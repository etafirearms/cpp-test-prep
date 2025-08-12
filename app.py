from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import json
import os
import requests
import stripe
import time
from functools import wraps

# -----------------------------------------------------------------------------
# App & Config
# -----------------------------------------------------------------------------
app = Flask(__name__)

# Required environment vars (fail fast if missing)
def require_env(name: str) -> str:
    val = os.environ.get(name)
    if not val:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return val

app.config['SECRET_KEY'] = require_env('SECRET_KEY')

# Database
app.config['SQLALCHEMY_DATABASE_URI'] = require_env('DATABASE_URL')
if app.config['SQLALCHEMY_DATABASE_URI'].startswith('postgres://'):
    app.config['SQLALCHEMY_DATABASE_URI'] = app.config['SQLALCHEMY_DATABASE_URI'].replace('postgres://', 'postgresql://')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# External APIs
OPENAI_API_KEY = require_env('OPENAI_API_KEY')
OPENAI_CHAT_MODEL = os.environ.get('OPENAI_CHAT_MODEL', 'gpt-3.5-turbo')
OPENAI_API_BASE = os.environ.get('OPENAI_API_BASE', 'https://api.openai.com/v1')

stripe.api_key = require_env('STRIPE_SECRET_KEY')
STRIPE_PUBLISHABLE_KEY = require_env('STRIPE_PUBLISHABLE_KEY')

# NOTE: make webhook secret OPTIONAL at startup so the app can boot without it.
STRIPE_WEBHOOK_SECRET = os.environ.get('STRIPE_WEBHOOK_SECRET')  # may be None

# Simple rate limiter for AI calls
last_api_call = None

# -----------------------------------------------------------------------------
# Database Models
# -----------------------------------------------------------------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    subscription_status = db.Column(db.String(20), default='trial')  # trial, active, past_due, expired
    subscription_plan = db.Column(db.String(20), default='trial')    # trial, 3month, 6month
    subscription_end_date = db.Column(db.DateTime)
    stripe_customer_id = db.Column(db.String(100))
    stripe_subscription_id = db.Column(db.String(100))
    discount_code_used = db.Column(db.String(50))
    study_time = db.Column(db.Integer, default=0)
    quiz_scores = db.Column(db.Text, default='[]')

class ChatHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    messages = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)

class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    activity = db.Column(db.String(100), nullable=False)
    details = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class QuizResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    quiz_type = db.Column(db.String(50), nullable=False)
    questions = db.Column(db.Text, nullable=False)
    answers = db.Column(db.Text, nullable=False)
    score = db.Column(db.Float, nullable=False)
    total_questions = db.Column(db.Integer, nullable=False)
    completed_at = db.Column(db.DateTime, default=datetime.utcnow)

class StudySession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    topic = db.Column(db.String(100))
    duration = db.Column(db.Integer)
    session_type = db.Column(db.String(50))
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    ended_at = db.Column(db.DateTime)

# Create tables (idempotent)
with app.app_context():
    try:
        db.create_all()
        print("Database tables created successfully!")
    except Exception as e:
        print(f"Database initialization error: {e}")

# -----------------------------------------------------------------------------
# Helpers & Decorators
# -----------------------------------------------------------------------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this feature.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def subscription_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if user.subscription_status == 'expired':
            flash('Your subscription has expired. Please renew to continue.', 'danger')
            return redirect(url_for('subscribe'))
        return f(*args, **kwargs)
    return decorated_function

def log_activity(user_id, activity, details=None):
    log = ActivityLog(user_id=user_id, activity=activity, details=details)
    db.session.add(log)
    db.session.commit()

def chat_with_ai(messages, user_id=None):
    """
    ASIS CPP (Certified Protection Professional) tutor:
    - Seven domains (Security Principles & Practices; Business Principles & Practices; Investigations;
      Personnel Security; Physical Security; Information Security; Crisis Management).
    - No proprietary ASIS content. No guarantees or claims of ASIS affiliation.
    - Encouraging, structured, scenario-driven when helpful.
    """
    global last_api_call
    try:
        # simple rate limiting (2 seconds)
        if last_api_call:
            delta = datetime.utcnow() - last_api_call
            if delta.total_seconds() < 2:
                time.sleep(2 - delta.total_seconds())

        system_message = {
            "role": "system",
            "content": (
                "You are a study tutor for the ASIS Certified Protection Professional (CPP) exam.\n"
                "- Focus on seven domains: Security Principles & Practices; Business Principles & Practices; "
                "Investigations; Personnel Security; Physical Security; Information Security; Crisis Management.\n"
                "- Use only general, publicly available concepts; do NOT reproduce proprietary ASIS content.\n"
                "- Provide explanations, original practice questions, study strategies, and scenario-based exercises.\n"
                "- Formatting for MCQs:\n"
                "**1. [Question]**\n\n"
                "A. [Option A]\nB. [Option B]\nC. [Option C]\nD. [Option D]\n\n"
                "- Keep answers accurate, encouraging, and domain-correct. Never guarantee passing."
            )
        }
        if not messages or messages[0].get('role') != 'system':
            messages.insert(0, system_message)

        headers = {
            'Authorization': f'Bearer {OPENAI_API_KEY}',
            'Content-Type': 'application/json'
        }

        data = {
            'model': OPENAI_CHAT_MODEL,
            'messages': messages,
            'max_tokens': 1000,
            'temperature': 0.7
        }

        last_api_call = datetime.utcnow()
        response = requests.post(
            f'{OPENAI_API_BASE}/chat/completions',
            headers=headers,
            json=data,
            timeout=40
        )

        print(f"OpenAI API Response Status: {response.status_code}")

        if response.status_code == 200:
            result = response.json()
            return result['choices'][0]['message']['content']
        elif response.status_code == 429:
            return "I’m getting a lot of questions right now. Please wait a few seconds and try again."
        elif response.status_code in (401, 403):
            return "Authentication issue with the AI service. Please contact support."
        else:
            print(f"API Error {response.status_code}: {response.text}")
            return "I’m experiencing technical difficulties. Please try again shortly."
    except requests.exceptions.Timeout:
        return "The AI service timed out. Please try again."
    except requests.exceptions.ConnectionError:
        return "I can’t connect to the AI service right now. Please try again."
    except Exception as e:
        print(f"AI Chat Error: {e}")
        return "Sorry, I’m experiencing technical difficulties. Please try again later."

def set_user_subscription_by_customer(customer_id: str, status: str, subscription_id: str | None = None):
    """Find user by Stripe customer and update subscription status."""
    if not customer_id:
        return
    user = User.query.filter_by(stripe_customer_id=customer_id).first()
    if not user:
        return
    user.subscription_status = status
    if subscription_id:
        user.stripe_subscription_id = subscription_id
    if status == 'active' and not user.subscription_end_date:
        user.subscription_end_date = datetime.utcnow() + timedelta(days=90)
    if status in ('canceled', 'expired'):
        user.subscription_status = 'expired'
    db.session.commit()
    log_activity(user.id, 'subscription_status_update', f'status={status}')

# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------
@app.get("/healthz")
def healthz():
    return {"ok": True}, 200

@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email'].lower().strip()
        password = request.form['password']
        first_name = request.form['first_name'].strip()
        last_name = request.form['last_name'].strip()

        if not email or not password or not first_name or not last_name:
            flash('All fields are required.', 'danger')
            return render_template('register.html')

        if User.query.filter_by(email=email).first():
            flash('Email already registered. Please log in.', 'warning')
            return redirect(url_for('login'))

        try:
            stripe_customer = stripe.Customer.create(
                email=email,
                name=f"{first_name} {last_name}"
            )
            user = User(
                email=email,
                password_hash=generate_password_hash(password),
                first_name=first_name,
                last_name=last_name,
                subscription_status='trial',
                subscription_end_date=datetime.utcnow() + timedelta(days=7),
                stripe_customer_id=stripe_customer.id
            )
            db.session.add(user)
            db.session.commit()

            log_activity(user.id, 'user_registered', f'New user: {first_name} {last_name}')
            session['user_id'] = user.id
            session['user_name'] = f"{first_name} {last_name}"
            flash(f'Welcome {first_name}! You have a 7-day free trial.', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            flash('Registration error. Please try again.', 'danger')
            print(f"Registration error: {e}")

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].lower().strip()
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

    # Security: early return on missing user/password rather than timing leaks
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['user_name'] = f"{user.first_name} {user.last_name}"
            log_activity(user.id, 'user_login', 'User logged in')
            flash(f'Welcome back, {user.first_name}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password.', 'danger')

    return render_template('login.html')

@app.route('/logout')
def logout():
    if 'user_id' in session:
        log_activity(session['user_id'], 'user_logout', 'User logged out')
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    user = User.query.get(session['user_id'])
    recent_activities = ActivityLog.query.filter_by(user_id=user.id).order_by(ActivityLog.timestamp.desc()).limit(10).all()
    recent_quizzes = QuizResult.query.filter_by(user_id=user.id).order_by(QuizResult.completed_at.desc()).limit(5).all()

    days_left = 0
    if user.subscription_end_date:
        days_left = max(0, (user.subscription_end_date - datetime.utcnow()).days)

    return render_template('dashboard.html',
                           user=user,
                           recent_activities=recent_activities,
                           recent_quizzes=recent_quizzes,
                           days_left=days_left)

@app.route('/study')
@subscription_required
def study():
    user = User.query.get(session['user_id'])
    chat_history = ChatHistory.query.filter_by(user_id=user.id).first()
    if not chat_history:
        chat_history = ChatHistory(user_id=user.id, messages='[]')
        db.session.add(chat_history)
        db.session.commit()

    messages = json.loads(chat_history.messages)
    session['study_start_time'] = datetime.utcnow().timestamp()
    return render_template('study.html', user=user, messages=messages)

@app.route('/chat', methods=['POST'])
@subscription_required
def chat():
    user_message = request.json.get('message', '').strip()
    if not user_message:
        return jsonify({'error': 'Empty message'}), 400

    user_id = session['user_id']
    chat_history = ChatHistory.query.filter_by(user_id=user_id).first()
    messages = json.loads(chat_history.messages) if chat_history.messages else []

    messages.append({
        'role': 'user',
        'content': user_message,
        'timestamp': datetime.utcnow().isoformat()
    })

    openai_messages = [{'role': m['role'], 'content': m['content']} for m in messages]
    ai_response = chat_with_ai(openai_messages, user_id)

    messages.append({
        'role': 'assistant',
        'content': ai_response,
        'timestamp': datetime.utcnow().isoformat()
    })

    chat_history.messages = json.dumps(messages)
    chat_history.updated_at = datetime.utcnow()
    db.session.commit()

    log_activity(user_id, 'chat_message', f'Asked: {user_message[:50]}...')

    return jsonify({
        'response': ai_response,
        'timestamp': datetime.utcnow().isoformat()
    })

@app.route('/quiz/<quiz_type>')
@subscription_required
def quiz(quiz_type):
    # CPP (Protection) quiz generator
    quiz_prompt = f"""Create a {quiz_type} multiple-choice quiz for the ASIS Certified Protection Professional (CPP) exam.
Return VALID JSON only with 10 challenging questions covering CPP security domains where appropriate:
- Security Principles & Practices (risk management, governance, ethics)
- Business Principles & Practices (budgeting, contracts, project mgmt)
- Investigations (planning, interviews, evidence, reporting)
- Personnel Security (screening, insider threat, workplace violence)
- Physical Security (CPTED, access control, locks, lighting, alarms)
- Information Security (policies, data protection, incident response)
- Crisis Management (BCP, DR, emergency response, comms)

JSON schema:
{{
  "title": "CPP {quiz_type.title()} Quiz",
  "questions": [
    {{
      "question": "Clear question text",
      "options": {{"A": "opt", "B": "opt", "C": "opt", "D": "opt"}},
      "correct": "A",
      "explanation": "Short, public, non-proprietary rationale"
    }}
  ]
}}"""
    ai_response = chat_with_ai([{'role': 'user', 'content': quiz_prompt}])

    try:
        import re
        json_match = re.search(r'\{.*\}\s*$', ai_response, re.DOTALL)
        if json_match:
            quiz_data = json.loads(json_match.group())
        else:
            raise ValueError("No JSON found")
    except Exception as _:
        quiz_data = {
            "title": f"CPP {quiz_type.title()} Practice Quiz",
            "questions": [
                {
                    "question": "Which step best follows a completed threat assessment in a risk management cycle?",
                    "options": {
                        "A": "Initiate random inspections only",
                        "B": "Select and implement appropriate risk treatments",
                        "C": "Archive the assessment for audit",
                        "D": "Defer to legal for approval only"
                    },
                    "correct": "B",
                    "explanation": "After assessing threats/risks, select proportionate controls and implement treatment plans."
                },
                {
                    "question": "Which CPTED principle focuses on increasing the likelihood improper behavior will be observed?",
                    "options": {
                        "A": "Territorial reinforcement",
                        "B": "Natural surveillance",
                        "C": "Access control",
                        "D": "Maintenance"
                    },
                    "correct": "B",
                    "explanation": "Natural surveillance increases visibility to deter misconduct."
                }
            ]
        }

    return render_template('quiz.html', quiz_data=quiz_data, quiz_type=quiz_type)

@app.route('/submit-quiz', methods=['POST'])
@subscription_required
def submit_quiz():
    data = request.json
    quiz_type = data.get('quiz_type')
    answers = data.get('answers')
    questions = data.get('questions')

    correct_count = 0
    total_questions = len(questions) if questions else 0

    for i, question in enumerate(questions or []):
        user_answer = answers.get(str(i))
        if user_answer == question['correct']:
            correct_count += 1

    score = (correct_count / total_questions) * 100 if total_questions else 0.0

    result = QuizResult(
        user_id=session['user_id'],
        quiz_type=quiz_type,
        questions=json.dumps(questions),
        answers=json.dumps(answers),
        score=score,
        total_questions=total_questions
    )
    db.session.add(result)

    user = User.query.get(session['user_id'])
    scores = json.loads(user.quiz_scores) if user.quiz_scores else []
    scores.append({'score': score, 'date': datetime.utcnow().isoformat(), 'type': quiz_type})
    user.quiz_scores = json.dumps(scores[-20:])

    db.session.commit()

    log_activity(session['user_id'], 'quiz_completed',
                f'{quiz_type} quiz: {correct_count}/{total_questions} ({score:.1f}%)')

    return jsonify({
        'score': score,
        'correct': correct_count,
        'total': total_questions,
        'results': [
            {
                'question': q['question'],
                'user_answer': answers.get(str(i), 'Not answered'),
                'correct_answer': q['correct'],
                'explanation': q.get('explanation', ''),
                'is_correct': answers.get(str(i)) == q['correct']
            }
            for i, q in enumerate(questions or [])
        ]
    })

@app.route('/flashcards')
@subscription_required
def flashcards():
    topic = request.args.get('topic', 'CPP core domains (security management)')
    prompt = f"""Create 10 flashcards for the ASIS CPP exam about: {topic}.
Use only public, non-proprietary information. Cover definitions, principles, and brief examples.
Return VALID JSON only:
{{
  "topic": "{topic}",
  "cards": [{{"front": "Term or scenario", "back": "Clear explanation with example"}}]
}}"""
    ai_response = chat_with_ai([{'role': 'user', 'content': prompt}])

    try:
        import re
        json_match = re.search(r'\{.*\}\s*$', ai_response, re.DOTALL)
        if json_match:
            flashcard_data = json.loads(json_match.group())
        else:
            raise ValueError("No JSON found")
    except Exception as _:
        flashcard_data = {
            "topic": topic,
            "cards": [
                {"front": "Risk treatment options", "back": "Avoid, Transfer, Mitigate, Accept—choose based on impact/likelihood and cost-benefit."},
                {"front": "CPTED pillars", "back": "Natural surveillance, Natural access control, Territorial reinforcement, Maintenance."},
                {"front": "Least privilege", "back": "Grant only the minimum access needed for a role; reduces insider risk."},
                {"front": "Business continuity vs. disaster recovery", "back": "BC keeps operations running; DR restores tech/services after disruption."},
                {"front": "Chain of custody", "back": "Documentation that preserves integrity of evidence from collection to presentation."}
            ]
        }

    log_activity(session['user_id'], 'flashcards_viewed', f'Topic: {topic}')
    return render_template('flashcards.html', flashcard_data=flashcard_data)

@app.route('/progress')
@login_required
def progress():
    user = User.query.get(session['user_id'])
    activities = ActivityLog.query.filter_by(user_id=user.id).order_by(ActivityLog.timestamp.desc()).all()
    quiz_results = QuizResult.query.filter_by(user_id=user.id).order_by(QuizResult.completed_at.desc()).all()

    total_sessions = len([a for a in activities if 'study' in a.activity.lower()])
    total_quizzes = len(quiz_results)
    avg_score = sum(q.score for q in quiz_results) / len(quiz_results) if quiz_results else 0

    study_sessions = StudySession.query.filter_by(user_id=user.id).all()
    total_study_time = sum(s.duration or 0 for s in study_sessions)

    return render_template('progress.html',
                           user=user,
                           activities=activities,
                           quiz_results=quiz_results,
                           total_sessions=total_sessions,
                           total_quizzes=total_quizzes,
                           avg_score=avg_score,
                           total_study_time=total_study_time)

@app.route('/subscribe')
@login_required
def subscribe():
    user = User.query.get(session['user_id'])
    return render_template('subscribe.html', user=user, stripe_key=STRIPE_PUBLISHABLE_KEY)

@app.route('/create-checkout-session', methods=['POST'])
@login_required
def create_checkout_session():
    """Create Stripe Checkout Session with subscription plans and optional discount codes"""
    try:
        user = User.query.get(session['user_id'])
        plan_type = request.form.get('plan_type')  # '3month' or '6month'
        discount_code = request.form.get('discount_code', '').strip().upper()

        plans = {
            '3month': {
                'amount': 8997,  # $89.97 total (example)
                'name': 'CPP Test Prep - 3 Month Plan',
                'interval': 'month',
                'interval_count': 3
            },
            '6month': {
                'amount': 9900,  # $99.00 total (example)
                'name': 'CPP Test Prep - 6 Month Plan',
                'interval': 'month',
                'interval_count': 6
            }
        }
        if plan_type not in plans:
            flash('Invalid subscription plan selected.', 'danger')
            return redirect(url_for('subscribe'))

        selected_plan = plans[plan_type]
        final_amount = selected_plan['amount']

        discount_applied = False
        if discount_code == 'LAUNCH50':
            final_amount = int(selected_plan['amount'] * 0.5)
            discount_applied = True

        price = stripe.Price.create(
            unit_amount=final_amount,
            currency='usd',
            recurring={'interval': selected_plan['interval'], 'interval_count': selected_plan['interval_count']},
            product_data={
                'name': selected_plan['name'] + (' (50% OFF LAUNCH SPECIAL)' if discount_applied else ''),
                'description': 'Access to AI tutor, practice quizzes, flashcards, and progress tracking'
            }
        )

        checkout_session = stripe.checkout.Session.create(
            customer=user.stripe_customer_id,
            payment_method_types=['card'],
            line_items=[{'price': price.id, 'quantity': 1}],
            mode='subscription',
            success_url=url_for('subscription_success', _external=True) + '?session_id={CHECKOUT_SESSION_ID}&plan=' + plan_type,
            cancel_url=url_for('subscribe', _external=True),
            metadata={
                'user_id': user.id,
                'plan_type': plan_type,
                'discount_code': discount_code if discount_applied else '',
                'original_amount': selected_plan['amount'],
                'final_amount': final_amount
            }
        )

        log_activity(user.id, 'subscription_attempt',
                     f'Plan: {plan_type}, Discount: {discount_code}, Amount: ${final_amount/100:.2f}')

        return redirect(checkout_session.url, code=303)
    except Exception as e:
        print(f"Stripe checkout error: {e}")
        flash('Payment processing error. Please try again.', 'danger')
        return redirect(url_for('subscribe'))

@app.route('/subscription-success')
@login_required
def subscription_success():
    """Handle successful subscription with plan tracking"""
    session_id = request.args.get('session_id')
    plan_type = request.args.get('plan', '3month')

    if session_id:
        try:
            checkout_session = stripe.checkout.Session.retrieve(session_id)
            if checkout_session.payment_status == 'paid':
                user = User.query.get(session['user_id'])
                user.subscription_status = 'active'
                if plan_type == '6month':
                    user.subscription_end_date = datetime.utcnow() + timedelta(days=180)
                else:
                    user.subscription_end_date = datetime.utcnow() + timedelta(days=90)
                user.stripe_subscription_id = checkout_session.subscription
                db.session.commit()

                metadata = checkout_session.metadata or {}
                log_activity(user.id, 'subscription_activated',
                             f'Plan: {plan_type}, Amount: ${metadata.get("final_amount", "0")}')
                flash(f'Subscription activated! Welcome to CPP Test Prep ({plan_type.upper()})!', 'success')
            else:
                flash('Payment verification failed. Please contact support.', 'danger')
        except Exception as e:
            print(f"Subscription verification error: {e}")
            flash('Subscription verification error. Please contact support.', 'danger')

    return redirect(url_for('dashboard'))

# --- Stripe Webhook (single definition; tolerates missing secret) -------------
@app.post("/webhook", endpoint="stripe_webhook_v1")
def stripe_webhook():
    # If not configured yet, acknowledge (prevents retry loops on Render)
    if not STRIPE_WEBHOOK_SECRET:
        return 'Webhook not configured', 200

    payload = request.get_data(as_text=True)
    sig_header = request.headers.get('Stripe-Signature')

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
    except ValueError:
        return 'Invalid payload', 400
    except stripe.error.SignatureVerificationError:
        return 'Invalid signature', 400

    etype = event.get('type')
    data_object = event.get('data', {}).get('object', {})

    customer_id = data_object.get('customer')
    subscription_id = data_object.get('subscription') or data_object.get('id')

    if etype == 'invoice.payment_succeeded':
        set_user_subscription_by_customer(customer_id, 'active', subscription_id)
    elif etype == 'invoice.payment_failed':
        set_user_subscription_by_customer(customer_id, 'past_due', subscription_id)
    elif etype in ('customer.subscription.created', 'customer.subscription.updated'):
        status = data_object.get('status', 'active')
        normalized = 'active' if status in ('active', 'trialing') else ('past_due' if status == 'past_due' else 'expired')
        set_user_subscription_by_customer(customer_id, normalized, subscription_id)
    elif etype == 'customer.subscription.deleted':
        set_user_subscription_by_customer(customer_id, 'expired', subscription_id)

    return 'Success', 200

@app.route('/end-study-session', methods=['POST'])
@login_required
def end_study_session():
    if 'study_start_time' in session:
        start_time = datetime.fromtimestamp(session['study_start_time'])
        duration = int((datetime.utcnow() - start_time).total_seconds() / 60)

        study_session = StudySession(
            user_id=session['user_id'],
            duration=duration,
            session_type='chat',
            started_at=start_time,
            ended_at=datetime.utcnow()
        )
        db.session.add(study_session)

        user = User.query.get(session['user_id'])
        user.study_time += duration
        db.session.commit()

        del session['study_start_time']
        log_activity(session['user_id'], 'study_session_completed', f'Duration: {duration} minutes')

    return jsonify({'success': True})

@app.route('/terms')
def terms():
    return render_template('terms.html')

@app.route('/privacy')
def privacy():
    return render_template('privacy.html')

# Local dev only; Render uses Gunicorn entry point "app:app"
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
