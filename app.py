# app.py - Clean Version with NO Triple-Quoted Strings
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, Response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from functools import wraps
import json
import os
import requests
import stripe
import time
import re

# -----------------------------------------------------------------------------
# App & Config
# -----------------------------------------------------------------------------
app = Flask(__name__)

def require_env(name: str) -> str:
    val = os.environ.get(name)
    if not val:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return val

# Required env vars
app.config['SECRET_KEY'] = require_env('SECRET_KEY')

# OpenAI config
OPENAI_API_KEY = require_env('OPENAI_API_KEY')
OPENAI_CHAT_MODEL = os.environ.get('OPENAI_CHAT_MODEL', 'gpt-4o-mini')
OPENAI_API_BASE = os.environ.get('OPENAI_API_BASE', 'https://api.openai.com/v1')

# Stripe config
stripe.api_key = require_env('STRIPE_SECRET_KEY')
STRIPE_PUBLISHABLE_KEY = require_env('STRIPE_PUBLISHABLE_KEY')
STRIPE_WEBHOOK_SECRET = os.environ.get('STRIPE_WEBHOOK_SECRET')

# Database config
database_url = require_env('DATABASE_URL')
if database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://')

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Simple rate limiter for AI calls
last_api_call = None

# Session configuration
app.config.update(
    SESSION_COOKIE_SECURE=True if os.environ.get('FLASK_ENV') == 'production' else False,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(days=30)
)

db = SQLAlchemy(app)

# -----------------------------------------------------------------------------
# Quiz Types Configuration
# -----------------------------------------------------------------------------
QUIZ_TYPES = {
    'practice': {
        'name': 'Practice Quiz',
        'description': 'General practice questions across all CPP domains',
        'questions': 10
    },
    'mock-exam': {
        'name': 'Mock Exam',
        'description': 'Progressive exam: 50 questions initially, 125 when ready',
        'questions': 50
    },
    'domain-specific': {
        'name': 'Domain-Specific Quiz',
        'description': 'Focus on specific CPP domains',
        'questions': 15
    },
    'quick-review': {
        'name': 'Quick Review',
        'description': 'Short 5-question review',
        'questions': 5
    }
}

CPP_DOMAINS = {
    'security-principles': {
        'name': 'Security Principles & Practices',
        'topics': ['Risk Management', 'Security Governance', 'Ethics', 'Standards & Regulations']
    },
    'business-principles': {
        'name': 'Business Principles & Practices',
        'topics': ['Budgeting', 'Contracts', 'Project Management', 'ROI Analysis']
    },
    'investigations': {
        'name': 'Investigations',
        'topics': ['Investigation Planning', 'Interviews', 'Evidence Collection', 'Report Writing']
    },
    'personnel-security': {
        'name': 'Personnel Security',
        'topics': ['Background Screening', 'Insider Threat', 'Workplace Violence', 'Security Awareness']
    },
    'physical-security': {
        'name': 'Physical Security',
        'topics': ['CPTED', 'Access Control', 'Perimeter Security', 'Security Technology']
    },
    'information-security': {
        'name': 'Information Security',
        'topics': ['Data Protection', 'Cybersecurity', 'Information Classification', 'Incident Response']
    },
    'crisis-management': {
        'name': 'Crisis Management',
        'topics': ['Business Continuity', 'Disaster Recovery', 'Emergency Response', 'Communications']
    }
}

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
    subscription_status = db.Column(db.String(20), default='trial')
    subscription_plan = db.Column(db.String(20), default='trial')
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
    domain = db.Column(db.String(50))
    questions = db.Column(db.Text, nullable=False)
    answers = db.Column(db.Text, nullable=False)
    score = db.Column(db.Float, nullable=False)
    total_questions = db.Column(db.Integer, nullable=False)
    time_taken = db.Column(db.Integer)
    completed_at = db.Column(db.DateTime, default=datetime.utcnow)

class StudySession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    topic = db.Column(db.String(100))
    duration = db.Column(db.Integer)
    session_type = db.Column(db.String(50))
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    ended_at = db.Column(db.DateTime)

class UserProgress(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    domain = db.Column(db.String(50), nullable=False)
    mastery_level = db.Column(db.String(20), default='needs_practice')
    average_score = db.Column(db.Float, default=0.0)
    question_count = db.Column(db.Integer, default=0)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow)
    consecutive_good_scores = db.Column(db.Integer, default=0)

# Database initialization
with app.app_context():
    try:
        db.create_all()
        print("Database initialization completed successfully")
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
        try:
            user = User.query.get(session['user_id'])
            if not user:
                session.clear()
                return redirect(url_for('login'))

            if user.subscription_status == 'expired':
                flash('Your subscription has expired. Please renew to continue.', 'danger')
                return redirect(url_for('subscribe'))

            if user.subscription_status == 'trial' and user.subscription_end_date:
                if datetime.utcnow() > user.subscription_end_date:
                    user.subscription_status = 'expired'
                    db.session.commit()
                    flash('Your trial has expired. Please subscribe to continue.', 'warning')
                    return redirect(url_for('subscribe'))
        except Exception as e:
            print(f"Subscription check error: {e}")
            flash('Authentication error. Please log in again.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def log_activity(user_id, activity, details=None):
    """Log user activity with proper error handling"""
    if not user_id:
        return
    
    try:
        activity_log = ActivityLog(
            user_id=user_id,
            activity=activity[:100],
            details=details[:500] if details else None,
            timestamp=datetime.utcnow()
        )
        db.session.add(activity_log)
        db.session.commit()
    except Exception as e:
        print(f"Activity logging error: {e}")
        # Don't raise - logging failures shouldn't break the main flow

def chat_with_ai(messages, user_id=None):
    global last_api_call
    try:
        if last_api_call:
            delta = datetime.utcnow() - last_api_call
            if delta.total_seconds() < 2:
                time.sleep(2 - delta.total_seconds())

        system_message = {
            "role": "system",
            "content": (
                "You are an expert tutor for the ASIS Certified Protection Professional (CPP) exam. "
                "Provide practical examples and clear explanations. "
                "Focus on the 7 CPP domains: Security Principles, Business Principles, "
                "Investigations, Personnel Security, Physical Security, Information Security, "
                "and Crisis Management."
            )
        }
        if not messages or messages[0].get('role') != 'system':
            messages.insert(0, system_message)
        else:
            messages[0] = system_message

        headers = {'Authorization': f'Bearer {OPENAI_API_KEY}', 'Content-Type': 'application/json'}
        data = {
            'model': OPENAI_CHAT_MODEL,
            'messages': messages,
            'max_tokens': 1500,
            'temperature': 0.7
        }
        last_api_call = datetime.utcnow()
        resp = requests.post(f'{OPENAI_API_BASE}/chat/completions', headers=headers, json=data, timeout=45)
        print(f"[OpenAI] status={resp.status_code} model={OPENAI_CHAT_MODEL}")

        if resp.status_code == 200:
            result = resp.json()
            content = result['choices'][0]['message']['content']
            return content

        if resp.status_code in (401, 403):
            return "I am having trouble connecting to my knowledge base. Please try again in a moment."
        elif resp.status_code == 429:
            return "I am receiving a lot of questions right now. Please wait a short time and try again."
        else:
            return "I encountered an unexpected issue. Please try rephrasing your question."
    except Exception as e:
        print(f"[OpenAI] Error: {e}")
        return "I encountered a technical issue. Please try again, or contact support if this continues."

def generate_enhanced_quiz(quiz_type, domain=None, difficulty='medium'):
    print(f"[QUIZ_GEN] Called with: quiz_type={quiz_type}, domain={domain}, difficulty={difficulty}")
    
    try:
        num_questions = QUIZ_TYPES.get(quiz_type, {}).get('questions', 10)
        print(f"[QUIZ_GEN] Number of questions determined: {num_questions}")
        
        quiz_data = generate_fallback_quiz(quiz_type, domain, difficulty, num_questions)
        print(f"[QUIZ_GEN] Quiz generated: {bool(quiz_data)}")
        
        return quiz_data
        
    except Exception as e:
        print(f"[QUIZ_GEN] ERROR: {e}")
        return generate_fallback_quiz(quiz_type, domain, difficulty, 10)

def generate_fallback_quiz(quiz_type, domain, difficulty, num_questions):
    print(f"[FALLBACK_QUIZ] Generating quiz: {quiz_type}, {domain}, {difficulty}, {num_questions}")
    
    try:
        base_questions = [
            {
                "question": "What is the primary purpose of a comprehensive security risk assessment?",
                "options": {
                    "A": "To identify all possible security threats",
                    "B": "To determine cost-effective risk mitigation strategies",
                    "C": "To eliminate all security risks completely",
                    "D": "To satisfy insurance requirements"
                },
                "correct": "B",
                "explanation": "Risk assessments help organizations identify risks and determine cost-effective mitigation strategies.",
                "domain": "security-principles"
            },
            {
                "question": "In CPTED principles, what does natural surveillance primarily accomplish?",
                "options": {
                    "A": "Reduces the need for security guards",
                    "B": "Increases the likelihood that criminal activity will be observed",
                    "C": "Eliminates blind spots in camera coverage",
                    "D": "Provides legal liability protection"
                },
                "correct": "B",
                "explanation": "Natural surveillance increases visibility and deters criminal activity through observation.",
                "domain": "physical-security"
            },
            {
                "question": "What is the key difference between a vulnerability and a threat?",
                "options": {
                    "A": "Vulnerabilities are external, threats are internal",
                    "B": "Threats are potential dangers, vulnerabilities are weaknesses",
                    "C": "Vulnerabilities cost money, threats do not",
                    "D": "There is no significant difference"
                },
                "correct": "B",
                "explanation": "Threats are potential dangers while vulnerabilities are weaknesses that could be exploited.",
                "domain": "general"
            },
            {
                "question": "In security management, what does defense in depth mean?",
                "options": {
                    "A": "Having the strongest possible perimeter security",
                    "B": "Multiple layers of security controls",
                    "C": "Deep background checks on all personnel",
                    "D": "Detailed incident response procedures"
                },
                "correct": "B",
                "explanation": "Defense in depth involves multiple layers of security controls for redundancy.",
                "domain": "general"
            },
            {
                "question": "What is the most critical first step in incident response?",
                "options": {
                    "A": "Notify law enforcement",
                    "B": "Document everything immediately",
                    "C": "Contain the incident to prevent further damage",
                    "D": "Identify the root cause"
                },
                "correct": "C",
                "explanation": "Containment prevents further damage and limits the scope of the incident.",
                "domain": "information-security"
            }
        ]

        questions = []
        question_index = 0
        
        while len(questions) < num_questions:
            if question_index >= len(base_questions):
                question_index = 0
            
            question_copy = base_questions[question_index].copy()
            questions.append(question_copy)
            question_index += 1

        quiz_data = {
            "title": f"CPP {quiz_type.title().replace('-', ' ')} Quiz",
            "quiz_type": quiz_type,
            "domain": domain or 'general',
            "difficulty": difficulty,
            "questions": questions[:num_questions]
        }
        
        print(f"[FALLBACK_QUIZ] Quiz created successfully with {len(quiz_data['questions'])} questions")
        return quiz_data
        
    except Exception as e:
        print(f"[FALLBACK_QUIZ] ERROR: {e}")
        return None

# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------
@app.route('/favicon.ico')
def favicon():
    return Response('', status=204, mimetype='image/x-icon')

@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            email = request.form.get('email', '').lower().strip()
            password = request.form.get('password', '')
            first_name = request.form.get('first_name', '').strip()
            last_name = request.form.get('last_name', '').strip()

            if not all([email, password, first_name, last_name]):
                flash('All fields are required.', 'danger')
                return render_template('register.html')

            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
            if not re.match(email_pattern, email):
                flash('Please enter a valid email address.', 'danger')
                return render_template('register.html')

            if len(password) < 8:
                flash('Password must be at least 8 characters long.', 'danger')
                return render_template('register.html')

            existing_user = User.query.filter_by(email=email).first()
            if existing_user:
                flash('Email already registered. Please log in.', 'warning')
                return redirect(url_for('login'))

            stripe_customer = stripe.Customer.create(
                email=email,
                name=f"{first_name} {last_name}",
                metadata={'source': 'cpp_test_prep'}
            )

            user = User(
                email=email,
                password_hash=generate_password_hash(password),
                first_name=first_name,
                last_name=last_name,
                subscription_status='trial',
                subscription_plan='trial',
                subscription_end_date=datetime.utcnow() + timedelta(days=7),
                stripe_customer_id=stripe_customer.id
            )
            
            db.session.add(user)
            db.session.commit()

            session['user_id'] = user.id
            session['user_name'] = f"{first_name} {last_name}"
            session.permanent = True

            log_activity(user.id, 'user_registered', f'New user: {first_name} {last_name}')
            flash(f'Welcome {first_name}! You have a 7-day free trial.', 'success')
            return redirect(url_for('dashboard'))

        except Exception as e:
            print(f"Registration error: {e}")
            flash('An error occurred during registration. Please try again.', 'danger')
            return render_template('register.html')

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].lower().strip()
        password = request.form['password']

        if not email or not password:
            flash('Please enter both email and password.', 'danger')
            return render_template('login.html')

        try:
            user = User.query.filter_by(email=email).first()
            if user and check_password_hash(user.password_hash, password):
                session['user_id'] = user.id
                session['user_name'] = f"{user.first_name} {user.last_name}"
                log_activity(user.id, 'user_login', 'User logged in')

                if user.subscription_status == 'trial' and user.subscription_end_date:
                    days_left = (user.subscription_end_date - datetime.utcnow()).days
                    if days_left <= 0:
                        user.subscription_status = 'expired'
                        db.session.commit()
                        flash(f'Welcome back, {user.first_name}. Your trial has expired.', 'warning')
                    else:
                        flash(f'Welcome back, {user.first_name}.', 'success')
                else:
                    flash(f'Welcome back, {user.first_name}.', 'success')

                return redirect(url_for('dashboard'))
            else:
                flash('Invalid email or password.', 'danger')
        except Exception as e:
            print(f"Login error: {e}")
            flash('Login error. Please try again.', 'danger')

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
    try:
        user = User.query.get(session['user_id'])
        if not user:
            session.clear()
            return redirect(url_for('login'))

        try:
            recent_activities = ActivityLog.query.filter_by(user_id=user.id).order_by(
                ActivityLog.timestamp.desc()
            ).limit(10).all()
        except Exception:
            recent_activities = []

        try:
            recent_quizzes = QuizResult.query.filter_by(user_id=user.id).order_by(
                QuizResult.completed_at.desc()
            ).limit(5).all()
        except Exception:
            recent_quizzes = []

        days_left = 0
        if user.subscription_end_date:
            days_left = max(0, (user.subscription_end_date - datetime.utcnow()).days)

        return render_template(
            'dashboard.html',
            user=user,
            recent_activities=recent_activities,
            recent_quizzes=recent_quizzes,
            days_left=days_left,
            quiz_types=QUIZ_TYPES,
            cpp_domains=CPP_DOMAINS
        )

    except Exception as e:
        print(f"Dashboard error: {e}")
        flash('Error loading dashboard. Please try again.', 'danger')
        return redirect(url_for('home'))

@app.route('/study')
@subscription_required
def study():
    try:
        user = User.query.get(session['user_id'])
        if not user:
            return redirect(url_for('login'))

        chat_history = ChatHistory.query.filter_by(user_id=user.id).first()
        if not chat_history:
            chat_history = ChatHistory(user_id=user.id, messages='[]')
            db.session.add(chat_history)
            db.session.commit()

        try:
            messages = json.loads(chat_history.messages)
        except (json.JSONDecodeError, TypeError):
            messages = []
            chat_history.messages = '[]'
            db.session.commit()

        session['study_start_time'] = datetime.utcnow().timestamp()

        return render_template(
            'study.html',
            user=user,
            messages=messages,
            current_time=datetime.utcnow().strftime('%H:%M'),
            cpp_domains=CPP_DOMAINS
        )

    except Exception as e:
        print(f"Study page error: {e}")
        flash('Error loading study page. Please try again.', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/chat', methods=['POST'])
@subscription_required
def chat():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        user_message = data.get('message', '').strip()
        if not user_message:
            return jsonify({'error': 'Empty message'}), 400

        if len(user_message) > 1000:
            return jsonify({'error': 'Message too long. Please keep it under 1000 characters.'}), 400

        user_id = session['user_id']

        chat_history = ChatHistory.query.filter_by(user_id=user_id).first()
        if not chat_history:
            chat_history = ChatHistory(user_id=user_id, messages='[]')
            db.session.add(chat_history)

        try:
            messages = json.loads(chat_history.messages) if chat_history.messages else []
        except json.JSONDecodeError:
            messages = []

        if len(messages) > 20:
            messages = messages[-20:]

        timestamp = datetime.utcnow().isoformat()
        messages.append({'role': 'user', 'content': user_message, 'timestamp': timestamp})

        openai_messages = [{'role': m['role'], 'content': m['content']} for m in messages]

        ai_response = chat_with_ai(openai_messages, user_id)

        messages.append({'role': 'assistant', 'content': ai_response, 'timestamp': datetime.utcnow().isoformat()})

        chat_history.messages = json.dumps(messages)
        chat_history.updated_at = datetime.utcnow()
        db.session.commit()

        log_activity(user_id, 'chat_message', f'Asked: {user_message[:50]}...')

        return jsonify({'response': ai_response, 'timestamp': datetime.utcnow().isoformat()})

    except Exception as e:
        print(f"Chat error: {e}")
        return jsonify({'error': 'Sorry, I encountered an error processing your message. Please try again.'}), 500

@app.route('/quiz-selector')
@subscription_required
def quiz_selector():
    try:
        return render_template(
            'quiz_selector.html',
            quiz_types=QUIZ_TYPES,
            cpp_domains=CPP_DOMAINS
        )
    except Exception as e:
        print(f"Quiz selector error: {e}")
        flash('Error loading quiz selector. Please try again.', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/quiz/<quiz_type>')
@subscription_required
def quiz(quiz_type):
    print(f"[QUIZ] Route called with quiz_type: {quiz_type}")
    
    if quiz_type not in QUIZ_TYPES:
        print(f"[QUIZ] Invalid quiz type: {quiz_type}")
        flash('Invalid quiz type selected.', 'danger')
        return redirect(url_for('quiz_selector'))
    
    try:
        domain = request.args.get('domain')
        difficulty = request.args.get('difficulty', 'medium')
        print(f"[QUIZ] Parameters - domain: {domain}, difficulty: {difficulty}")

        if domain and domain not in CPP_DOMAINS:
            print(f"[QUIZ] Invalid domain: {domain}")
            flash('Invalid domain selected.', 'warning')
            domain = None

        session['quiz_start_time'] = datetime.utcnow().timestamp()

        print(f"[QUIZ] Calling generate_enhanced_quiz...")
        quiz_data = generate_enhanced_quiz(quiz_type, domain, difficulty)
        print(f"[QUIZ] generate_enhanced_quiz returned: {type(quiz_data)}")
        
        if not quiz_data:
            print("[QUIZ] ERROR: quiz_data is None")
            flash('Error generating quiz. Please try again.', 'danger')
            return redirect(url_for('quiz_selector'))
            
        if not quiz_data.get('questions'):
            print(f"[QUIZ] ERROR: No questions in quiz_data")
            flash('Error: No questions generated. Please try again.', 'danger')
            return redirect(url_for('quiz_selector'))
            
        if len(quiz_data.get('questions', [])) == 0:
            print("[QUIZ] ERROR: Empty questions list")
            flash('Error: No questions available. Please try again.', 'danger')
            return redirect(url_for('quiz_selector'))

        print(f"[QUIZ] SUCCESS - Questions: {len(quiz_data.get('questions', []))}")

        log_activity(
            session['user_id'],
            'quiz_started',
            f'Type: {quiz_type}, Domain: {domain or "general"}, Questions: {len(quiz_data["questions"])}'
        )

        print(f"[QUIZ] Rendering template...")
        return render_template(
            'quiz.html', 
            quiz_data=quiz_data, 
            quiz_type=quiz_type,
            domain=domain,
            difficulty=difficulty
        )

    except Exception as e:
        print(f"[QUIZ] EXCEPTION: {e}")
        flash('Error starting quiz. Please try again.', 'danger')
        return redirect(url_for('quiz_selector'))

@app.route('/submit-quiz', methods=['POST'])
@subscription_required
def submit_quiz():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        quiz_type = data.get('quiz_type')
        answers = data.get('answers', {})
        questions = data.get('questions', [])
        domain = data.get('domain', 'general')

        if not quiz_type or not questions:
            return jsonify({'error': 'Invalid quiz data'}), 400

        time_taken = 0
        if 'quiz_start_time' in session:
            start_time = datetime.fromtimestamp(session['quiz_start_time'])
            time_taken = int((datetime.utcnow() - start_time).total_seconds() / 60)
            del session['quiz_start_time']

        correct_count = 0
        total_questions = len(questions)

        for i, question in enumerate(questions):
            user_answer = answers.get(str(i))
            is_correct = user_answer == question.get('correct')
            if is_correct:
                correct_count += 1

        score = (correct_count / total_questions) * 100 if total_questions else 0.0

        result = QuizResult(
            user_id=session['user_id'],
            quiz_type=quiz_type,
            domain=domain,
            questions=json.dumps(questions),
            answers=json.dumps(answers),
            score=score,
            total_questions=total_questions,
            time_taken=time_taken
        )
        db.session.add(result)
        db.session.commit()

        log_activity(
            session['user_id'],
            'quiz_completed',
            f'{quiz_type} quiz: {correct_count}/{total_questions} ({score:.1f}%) in {time_taken} min'
        )

        detailed_results = []
        for i, q in enumerate(questions):
            user_answer = answers.get(str(i), 'Not answered')
            is_correct = user_answer == q.get('correct')
            detailed_results.append({
                'question': q.get('question', ''),
                'user_answer': user_answer,
                'correct_answer': q.get('correct'),
                'explanation': q.get('explanation', ''),
                'is_correct': is_correct,
                'domain': q.get('domain', 'general'),
                'options': q.get('options', {})
            })

        return jsonify({
            'success': True,
            'score': round(score, 1),
            'correct': correct_count,
            'total': total_questions,
            'time_taken': time_taken,
            'results': detailed_results
        })

    except Exception as e:
        print(f"Submit quiz error: {e}")
        db.session.rollback()
        return jsonify({'error': 'Error processing quiz results. Please try again.'}), 500

@app.route('/subscribe')
@login_required
def subscribe():
    try:
        user = User.query.get(session['user_id'])
        trial_days_left = None
        if user and user.subscription_status == 'trial' and user.subscription_end_date:
            delta = (user.subscription_end_date - datetime.utcnow())
            trial_days_left = max(delta.days, 0)

        plans = [
            {"id": "monthly", "label": "Monthly", "amount": 3999, "pretty": "$39.99 / month"},
            {"id": "6month", "label": "6 Months", "amount": 9900, "pretty": "$99 / 6 months"},
        ]

        return render_template(
            'subscribe.html',
            user=user,
            trial_days_left=trial_days_left,
            plans=plans,
            STRIPE_PUBLISHABLE_KEY=STRIPE_PUBLISHABLE_KEY
        )
    except Exception as e:
        print(f"Subscribe page error: {e}")
        flash('Could not load the subscribe page. Please try again.', 'danger')
        return redirect(url_for('dashboard'))

# Debug routes
@app.route('/test-debug')
def test_debug():
    current_time = datetime.utcnow()
    return f"<h1>Debug Route Test</h1><p>Current time: {current_time}</p><a href='/dashboard'>Back</a>"

@app.route('/debug/quiz-test')
@login_required
def debug_quiz_test():
    try:
        quiz_data = generate_enhanced_quiz('practice', None, 'medium')
        
        if quiz_data:
            questions_count = len(quiz_data.get('questions', []))
            first_question = quiz_data.get('questions', [{}])[0].get('question', 'No question') if quiz_data.get('questions') else 'No questions'
            return f"<h1>Quiz Generation: SUCCESS</h1><p>Title: {quiz_data.get('title')}</p><p>Questions: {questions_count}</p><p>First question: {first_question}</p><a href='/dashboard'>Back</a>"
        else:
            return "<h1>Quiz Generation: FAILED</h1><a href='/dashboard'>Back</a>"
    except Exception as e:
        return f"<h1>Quiz Generation: ERROR</h1><p>{str(e)}</p><a href='/dashboard'>Back</a>"

@app.route('/debug/simple-quiz')
@login_required  
def debug_simple_quiz():
    quiz_data = {
        "title": "Debug Test Quiz",
        "quiz_type": "debug",
        "domain": "general", 
        "difficulty": "easy",
        "questions": [
            {
                "question": "What is 1 + 1?",
                "options": {"A": "1", "B": "2", "C": "3", "D": "4"},
                "correct": "B",
                "explanation": "1 + 1 = 2",
                "domain": "general"
            }
        ]
    }
    
    return render_template('quiz.html', quiz_data=quiz_data, quiz_type='debug')

@app.route('/flashcards')
@subscription_required
def flashcards():
    try:
        topic = request.args.get('topic', 'CPP core domains')
        difficulty = request.args.get('difficulty', 'medium')
        if len(topic) > 100:
            topic = topic[:100]

        fallback_cards = [
            {"front": "Risk Assessment", "back": "Systematic process to identify, analyze, and evaluate potential threats and vulnerabilities.", "category": "definitions"},
            {"front": "CPTED", "back": "Crime Prevention Through Environmental Design uses physical environment design to reduce crime opportunities.", "category": "concepts"},
            {"front": "Defense in Depth", "back": "Multiple layers of controls so if one fails others continue to provide protection.", "category": "concepts"},
            {"front": "Least Privilege", "back": "Grant only the minimum access rights needed to perform job functions.", "category": "definitions"}
        ]
        
        flashcard_data = {
            "topic": topic,
            "difficulty": difficulty,
            "total_cards": len(fallback_cards),
            "cards": fallback_cards
        }

        log_activity(
            session['user_id'],
            'flashcards_viewed',
            f'Topic: {topic}, Cards: {len(flashcard_data.get("cards", []))}'
        )

        return render_template('flashcards.html', flashcard_data=flashcard_data, cpp_domains=CPP_DOMAINS)

    except Exception as e:
        print(f"Flashcards error: {e}")
        flash('Error loading flashcards. Please try again.', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/progress')
@login_required
def progress():
    try:
        user = User.query.get(session['user_id'])
        if not user:
            return redirect(url_for('login'))

        try:
            activities = ActivityLog.query.filter_by(user_id=user.id).order_by(
                ActivityLog.timestamp.desc()
            ).limit(50).all()
        except Exception as e:
            print(f"Error fetching activities: {e}")
            activities = []

        try:
            quiz_results = QuizResult.query.filter_by(user_id=user.id).order_by(
                QuizResult.completed_at.desc()
            ).all()
        except Exception as e:
            print(f"Error fetching quiz results: {e}")
            quiz_results = []

        total_sessions = len([a for a in activities if 'study' in a.activity.lower()])
        total_quizzes = len(quiz_results)
        valid_scores = [q.score for q in quiz_results if q.score is not None]
        avg_score = sum(valid_scores) / len(valid_scores) if valid_scores else 0

        return render_template(
            'progress.html',
            user=user,
            activities=activities,
            quiz_results=quiz_results,
            total_sessions=total_sessions,
            total_quizzes=total_quizzes,
            avg_score=round(avg_score, 1)
        )

    except Exception as e:
        print(f"Progress page error: {e}")
        flash('Error loading progress page. Please try again.', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/privacy')
def privacy():
    return render_template('privacy.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

# Simple Error Handlers - NO TRIPLE QUOTES
@app.errorhandler(404)
def not_found_error(error):
    try:
        return render_template('404.html'), 404
    except Exception:
        return '<h1>404 - Page Not Found</h1><p><a href="/">Return Home</a></p>', 404

@app.errorhandler(500)
def internal_error(error):
    error_id = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    print(f"Error ID {error_id}: 500 Internal Server Error - {str(error)}")
    
    try:
        db.session.rollback()
    except:
        pass
    
    try:
        return render_template('500.html', error_id=error_id), 500
    except Exception:
        return f'<h1>500 - Server Error</h1><p>Error ID: {error_id}</p><p><a href="/">Return Home</a></p>', 500

@app.errorhandler(403)
def forbidden_error(error):
    try:
        return render_template('403.html'), 403
    except Exception:
        return '<h1>403 - Access Forbidden</h1><p><a href="/">Return Home</a></p>', 403

# Context processors
@app.context_processor
def inject_datetime_utils():
    def format_datetime(dt, format_type='default'):
        """Format datetime for templates"""
        if not dt:
            return 'Never'
        
        if isinstance(dt, str):
            try:
                dt = datetime.fromisoformat(dt.replace('Z', '+00:00'))
            except (ValueError, AttributeError):
                try:
                    dt = datetime.strptime(dt, '%Y-%m-%dT%H:%M:%S.%f')
                except ValueError:
                    try:
                        dt = datetime.strptime(dt, '%Y-%m-%d %H:%M:%S')
                    except ValueError:
                        return dt
        
        if not isinstance(dt, datetime):
            return str(dt)
        
        if format_type == 'time_ago':
            now = datetime.utcnow()
            diff = now - dt
            
            if diff.days > 0:
                return f"{diff.days} day{'s' if diff.days != 1 else ''} ago"
            elif diff.seconds > 3600:
                hours = diff.seconds // 3600
                return f"{hours} hour{'s' if hours != 1 else ''} ago"
            elif diff.seconds > 60:
                minutes = diff.seconds // 60
                return f"{minutes} minute{'s' if minutes != 1 else ''} ago"
            else:
                return "Just now"
        elif format_type == 'date':
            return dt.strftime('%Y-%m-%d')
        elif format_type == 'datetime':
            return dt.strftime('%Y-%m-%d %H:%M')
        else:
            return dt.strftime('%Y-%m-%d %H:%M:%S')
    
    return {
        'now': datetime.utcnow(),
        'format_datetime': format_datetime
    }

@app.context_processor
def inject_quiz_types():
    return {'quiz_types': QUIZ_TYPES, 'cpp_domains': CPP_DOMAINS}

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    print(f"Starting CPP Test Prep Application on port {port}")
    print(f"Debug mode: {debug}")
    app.run(host='0.0.0.0', port=port, debug=debug)
