from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import json
import os
import requests
import stripe
from functools import wraps

app = Flask(__name__)

# Configuration for Production
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'cpp-prep-secret-key-2024')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///cpp_prep.db')
if app.config['SQLALCHEMY_DATABASE_URI'].startswith('postgres://'):
    app.config['SQLALCHEMY_DATABASE_URI'] = app.config['SQLALCHEMY_DATABASE_URI'].replace('postgres://', 'postgresql://')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
db = SQLAlchemy(app)

# API Configuration
OPENAI_API_KEY = os.environ.get('OPENAI_API_KEY', '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')
stripe.api_key = os.environ.get('STRIPE_SECRET_KEY', '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')
STRIPE_PUBLISHABLE_KEY = os.environ.get('STRIPE_PUBLISHABLE_KEY', 'pk_live_51Ouik4P74bHmavbxxshp1STvn79vdgvCZkDIVRt0f9adlJqyTx81m9ONgVDuAsChzHBv3chfDHR4Cg2UBnm9iRln006sA0QteW')

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    subscription_status = db.Column(db.String(20), default='trial')
    subscription_plan = db.Column(db.String(20), default='trial')  # trial, 3month, 6month
    subscription_end_date = db.Column(db.DateTime)
    stripe_customer_id = db.Column(db.String(100))
    stripe_subscription_id = db.Column(db.String(100))
    discount_code_used = db.Column(db.String(50))  # Track which discount was applied
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

# Create database tables automatically
with app.app_context():
    try:
        db.create_all()
        print("Database tables created successfully!")
    except Exception as e:
        print(f"Database initialization error: {e}")

# Helper Functions
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
    """Enhanced CPP-specific AI chat"""
    try:
        headers = {
            'Authorization': f'Bearer {OPENAI_API_KEY}',
            'Content-Type': 'application/json'
        }
        
        system_message = {
            "role": "system",
            "content": """You are a specialized CPP (Certified Payroll Professional) exam preparation tutor with expert knowledge in:

            - Federal and state payroll tax regulations
            - FLSA (Fair Labor Standards Act) requirements
            - Employee classification and wage/hour laws
            - Payroll calculations and deductions
            - Recordkeeping requirements
            - Workers' compensation and unemployment insurance
            - Benefits administration
            - Payroll systems and technology

            You help students by:
            1. Providing clear explanations with real-world examples
            2. Creating practice questions and quizzes
            3. Offering study strategies and exam tips
            4. Explaining complex regulations in simple terms
            5. Providing current information on payroll compliance

            Always be encouraging, accurate, and focused on helping students pass their CPP exam."""
        }
        
        if not messages or messages[0]['role'] != 'system':
            messages.insert(0, system_message)
        
        data = {
            'model': 'gpt-4',  # Using GPT-4 for better accuracy
            'messages': messages,
            'max_tokens': 1200,
            'temperature': 0.7
        }
        
        response = requests.post(
            'https://api.openai.com/v1/chat/completions',
            headers=headers,
            json=data,
            timeout=30
        )
        
        if response.status_code == 200:
            result = response.json()
            return result['choices'][0]['message']['content']
        else:
            return f"I'm having trouble connecting right now. Please try again. (Error: {response.status_code})"
    
    except Exception as e:
        print(f"AI Chat Error: {e}")
        return "Sorry, I'm experiencing technical difficulties. Please try again in a moment."

# Database Initialization Route
@app.route('/init-db')
def init_database():
    """Initialize database tables - backup method"""
    try:
        with app.app_context():
            db.create_all()
            print("Database tables created successfully!")
        return "<h1>Database tables created successfully!</h1><p><a href='/'>Go to Homepage</a></p>"
    except Exception as e:
        print(f"Database initialization error: {e}")
        return f"<h1>Error creating tables:</h1><p>{str(e)}</p>"

# Routes
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
        
        # Create Stripe customer
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
    
    recent_activities = ActivityLog.query.filter_by(user_id=user.id)\
        .order_by(ActivityLog.timestamp.desc()).limit(10).all()
    
    recent_quizzes = QuizResult.query.filter_by(user_id=user.id)\
        .order_by(QuizResult.completed_at.desc()).limit(5).all()
    
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
    quiz_prompt = f"""Create a comprehensive {quiz_type} quiz for CPP exam preparation with 10 challenging multiple choice questions. 
    Cover topics like payroll calculations, tax regulations, FLSA requirements, and compliance issues.
    
    Format your response as valid JSON:
    {{
        "title": "CPP {quiz_type.title()} Quiz",
        "questions": [
            {{
                "question": "Question text here",
                "options": {{"A": "option1", "B": "option2", "C": "option3", "D": "option4"}},
                "correct": "A",
                "explanation": "Detailed explanation of why this answer is correct"
            }}
        ]
    }}"""
    
    ai_response = chat_with_ai([{'role': 'user', 'content': quiz_prompt}])
    
    try:
        import re
        json_match = re.search(r'\{.*\}', ai_response, re.DOTALL)
        if json_match:
            quiz_data = json.loads(json_match.group())
        else:
            raise ValueError("No JSON found")
    except:
        quiz_data = {
            "title": f"CPP {quiz_type.title()} Practice Quiz",
            "questions": [
                {
                    "question": "What does CPP certification stand for?",
                    "options": {
                        "A": "Certified Payroll Professional",
                        "B": "Corporate Payroll Processor", 
                        "C": "Calculated Pay Program",
                        "D": "Central Processing Platform"
                    },
                    "correct": "A",
                    "explanation": "CPP stands for Certified Payroll Professional, the premier certification for payroll professionals."
                },
                {
                    "question": "Under FLSA, what is the standard workweek?",
                    "options": {
                        "A": "35 hours",
                        "B": "37.5 hours",
                        "C": "40 hours", 
                        "D": "42 hours"
                    },
                    "correct": "C",
                    "explanation": "FLSA defines a standard workweek as 40 hours, after which overtime must be paid to non-exempt employees."
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
    total_questions = len(questions)
    
    for i, question in enumerate(questions):
        user_answer = answers.get(str(i))
        if user_answer == question['correct']:
            correct_count += 1
    
    score = (correct_count / total_questions) * 100
    
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
            for i, q in enumerate(questions)
        ]
    })

@app.route('/flashcards')
@subscription_required
def flashcards():
    topic = request.args.get('topic', 'general CPP concepts')
    
    prompt = f"""Create 10 comprehensive flashcards for studying {topic} for the CPP exam.
    Include important definitions, formulas, regulations, and key concepts.
    
    Format as valid JSON:
    {{
        "topic": "{topic}",
        "cards": [
            {{"front": "Question or term", "back": "Detailed answer or definition"}},
            ...
        ]
    }}"""
    
    ai_response = chat_with_ai([{'role': 'user', 'content': prompt}])
    
    try:
        import re
        json_match = re.search(r'\{.*\}', ai_response, re.DOTALL)
        if json_match:
            flashcard_data = json.loads(json_match.group())
        else:
            raise ValueError("No JSON found")
    except:
        flashcard_data = {
            "topic": topic,
            "cards": [
                {"front": "What does FLSA stand for?", "back": "Fair Labor Standards Act - federal law establishing minimum wage, overtime pay, and child labor standards"},
                {"front": "Current federal minimum wage?", "back": "$7.25 per hour (as of 2024)"},
                {"front": "FICA tax rate for 2024?", "back": "7.65% (6.2% Social Security + 1.45% Medicare)"},
                {"front": "When is overtime required under FLSA?", "back": "After 40 hours in a workweek for non-exempt employees"},
                {"front": "What is the Social Security wage base for 2024?", "back": "$160,200 - wages above this amount are not subject to Social Security tax"}
            ]
        }
    
    log_activity(session['user_id'], 'flashcards_viewed', f'Topic: {topic}')
    
    return render_template('flashcards.html', flashcard_data=flashcard_data)

@app.route('/progress')
@login_required
def progress():
    user = User.query.get(session['user_id'])
    
    activities = ActivityLog.query.filter_by(user_id=user.id)\
        .order_by(ActivityLog.timestamp.desc()).all()
    
    quiz_results = QuizResult.query.filter_by(user_id=user.id)\
        .order_by(QuizResult.completed_at.desc()).all()
    
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
    """Create Stripe Checkout Session with subscription plans and discount codes"""
    try:
        user = User.query.get(session['user_id'])
        plan_type = request.form.get('plan_type')  # '3month' or '6month'
        discount_code = request.form.get('discount_code', '').strip().upper()
        
        # Define subscription plans
        plans = {
            '3month': {
                'amount': 8997,  # $89.97
                'name': 'CPP Test Prep - 3 Month Plan',
                'interval': 'month',
                'interval_count': 3
            },
            '6month': {
                'amount': 9900,  # $99.00
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
        
        # Apply discount code
        discount_applied = False
        if discount_code == 'LAUNCH50':
            final_amount = int(selected_plan['amount'] * 0.5)  # 50% off
            discount_applied = True
        
        # Create price object for Stripe
        price = stripe.Price.create(
            unit_amount=final_amount,
            currency='usd',
            recurring={
                'interval': selected_plan['interval'],
                'interval_count': selected_plan['interval_count']
            },
            product_data={
                'name': selected_plan['name'] + (' (50% OFF LAUNCH SPECIAL)' if discount_applied else ''),
                'description': 'Full access to AI tutor, practice quizzes, flashcards, and progress tracking'
            }
        )
        
        # Create checkout session
        checkout_session = stripe.checkout.Session.create(
            customer=user.stripe_customer_id,
            payment_method_types=['card'],
            line_items=[{
                'price': price.id,
                'quantity': 1,
            }],
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
        
        # Log the subscription attempt
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
            # Verify the checkout session
            checkout_session = stripe.checkout.Session.retrieve(session_id)
            
            if checkout_session.payment_status == 'paid':
                user = User.query.get(session['user_id'])
                user.subscription_status = 'active'
                
                # Set subscription end date based on plan
                if plan_type == '6month':
                    user.subscription_end_date = datetime.utcnow() + timedelta(days=180)  # 6 months
                else:
                    user.subscription_end_date = datetime.utcnow() + timedelta(days=90)   # 3 months
                
                user.stripe_subscription_id = checkout_session.subscription
                db.session.commit()
                
                # Log successful subscription with details
                metadata = checkout_session.metadata
                log_activity(user.id, 'subscription_activated', 
                           f'Plan: {plan_type}, Amount: ${metadata.get("final_amount", "0")}')
                
                flash(f'Subscription activated! Welcome to CPP Test Prep ({plan_type.upper()})!', 'success')
            else:
                flash('Payment verification failed. Please contact support.', 'danger')
                
        except Exception as e:
            print(f"Subscription verification error: {e}")
            flash('Subscription verification error. Please contact support.', 'danger')
    
    return redirect(url_for('dashboard'))

@app.route('/webhook', methods=['POST'])
def stripe_webhook():
    """Handle Stripe webhooks"""
    payload = request.get_data(as_text=True)
    sig_header = request.headers.get('Stripe-Signature')
    
    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, os.environ.get('STRIPE_WEBHOOK_SECRET')
        )
    except ValueError as e:
        return 'Invalid payload', 400
    except stripe.error.SignatureVerificationError as e:
        return 'Invalid signature', 400
    
    # Handle subscription events
    if event['type'] == 'invoice.payment_succeeded':
        subscription = event['data']['object']
        # Update user subscription status
        # Add your logic here
        
    elif event['type'] == 'invoice.payment_failed':
        subscription = event['data']['object']
        # Handle failed payment
        # Add your logic here
        
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
    """Terms of Service page"""
    return render_template('terms.html')

@app.route('/privacy')
def privacy():
    """Privacy Policy page"""
    return render_template('privacy.html')

# For production
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)