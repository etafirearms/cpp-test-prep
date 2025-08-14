# app.py
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

app.config['SQLALCHEMY_DATABASE_URI'] = require_env('DATABASE_URL')
# Render sometimes provides postgres://; SQLAlchemy expects postgresql://
if app.config['SQLALCHEMY_DATABASE_URI'].startswith('postgres://'):
    app.config['SQLALCHEMY_DATABASE_URI'] = app.config['SQLALCHEMY_DATABASE_URI'].replace('postgres://', 'postgresql://')

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Enhanced engine options for better connection handling
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_recycle': 300,  # Recycle connections every 5 minutes
    'pool_size': 5,       # Limit connection pool size
    'max_overflow': 10,   # Allow up to 10 overflow connections
    'pool_timeout': 30,   # Timeout for getting connection from pool
    'connect_args': {
        'sslmode': 'require',
        'connect_timeout': 10,
        'application_name': 'cpp_test_prep',
        'options': '-c statement_timeout=30000'  # 30 second statement timeout
    }
}

db = SQLAlchemy(app)

# OpenAI config
OPENAI_API_KEY = require_env('OPENAI_API_KEY')
OPENAI_CHAT_MODEL = os.environ.get('OPENAI_CHAT_MODEL', 'gpt-4o-mini')
OPENAI_API_BASE = os.environ.get('OPENAI_API_BASE', 'https://api.openai.com/v1')

# Stripe config
# IMPORTANT: STRIPE_SECRET_KEY must be a secret key (starts with sk_live_ or sk_test_)
# STRIPE_PUBLISHABLE_KEY must be a publishable key (starts with pk_live_ or pk_test_)
stripe.api_key = require_env('STRIPE_SECRET_KEY')
STRIPE_PUBLISHABLE_KEY = require_env('STRIPE_PUBLISHABLE_KEY')
STRIPE_WEBHOOK_SECRET = os.environ.get('STRIPE_WEBHOOK_SECRET')

# Simple rate limiter for AI calls
last_api_call = None

# Session configuration for better reliability
app.config.update(
    SESSION_COOKIE_SECURE=True if os.environ.get('FLASK_ENV') == 'production' else False,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(days=30)
)

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
    },
    'difficult': {
        'name': 'Advanced Challenge',
        'description': 'Challenging questions for advanced preparation',
        'questions': 20
    },
    'scenario-based': {
        'name': 'Scenario-Based Quiz',
        'description': 'Real-world security scenarios and case studies',
        'questions': 12
    },
    'legal-compliance': {
        'name': 'Legal & Compliance Quiz',
        'description': 'Focus on legal aspects and compliance requirements',
        'questions': 15
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

class QuestionBank(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question_hash = db.Column(db.String(64), unique=True, nullable=False)
    question_text = db.Column(db.Text, nullable=False)
    domain = db.Column(db.String(50))
    difficulty = db.Column(db.String(20))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class UserProgress(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    domain = db.Column(db.String(50), nullable=False)
    mastery_level = db.Column(db.String(20), default='needs_practice')
    average_score = db.Column(db.Float, default=0.0)
    question_count = db.Column(db.Integer, default=0)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow)
    consecutive_good_scores = db.Column(db.Integer, default=0)

# Database initialization with proper error handling
def migrate_database_safe():
    """Safely add missing columns to existing tables with comprehensive error handling"""
    max_retries = 3
    for attempt in range(max_retries):
        try:
            with app.app_context():
                print(f"Database migration attempt {attempt + 1}")
                
                # Test database connection first
                with db.engine.connect() as conn:
                    result = conn.execute(db.text('SELECT 1 as test'))
                    print("Database connection test successful")
                
                # Create all tables
                db.create_all()
                print("Base tables created/verified")
                
                # Check for missing columns and add them
                inspector = db.inspect(db.engine)
                
                if 'quiz_result' in inspector.get_table_names():
                    columns = [column['name'] for column in inspector.get_columns('quiz_result')]
                    
                    with db.engine.connect() as conn:
                        transaction = conn.begin()
                        try:
                            if 'domain' not in columns:
                                conn.execute(db.text("ALTER TABLE quiz_result ADD COLUMN domain VARCHAR(50)"))
                                print("Added domain column to quiz_result")
                            
                            if 'time_taken' not in columns:
                                conn.execute(db.text("ALTER TABLE quiz_result ADD COLUMN time_taken INTEGER"))
                                print("Added time_taken column to quiz_result")
                            
                            transaction.commit()
                            print("Migration completed successfully")
                            return True
                            
                        except Exception as alter_error:
                            transaction.rollback()
                            print(f"Column alteration error (might be expected): {alter_error}")
                            # Continue anyway as columns might already exist
                            return True
                
                print("Database migration completed successfully")
                return True
                
        except Exception as e:
            print(f"Database migration attempt {attempt + 1} failed: {e}")
            if attempt == max_retries - 1:
                print("All migration attempts failed, trying fallback creation")
                try:
                    db.create_all()
                    print("Fallback: Created tables without migration")
                    return True
                except Exception as fallback_error:
                    print(f"Fallback creation also failed: {fallback_error}")
                    return False
            time.sleep(2 ** attempt)  # Exponential backoff
    
    return False

# Initialize database with proper error handling
with app.app_context():
    if not migrate_database_safe():
        print("WARNING: Database migration failed - application may not work correctly")
    else:
        print("Database initialization completed successfully")

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
    try:
        activity_log = ActivityLog(user_id=user_id, activity=activity, details=details)
        db.session.add(activity_log)
        db.session.commit()
    except Exception as e:
        print("Activity logging error: " + str(e))

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
                "You are an expert tutor for the ASIS Certified Protection Professional (CPP) exam.\n\n"
                "FOCUS AREAS:\n"
                "1. Security Principles & Practices\n"
                "2. Business Principles & Practices\n"
                "3. Investigations\n"
                "4. Personnel Security\n"
                "5. Physical Security\n"
                "6. Information Security\n"
                "7. Crisis Management\n\n"
                "GUIDELINES:\n"
                "- Use only public non-proprietary knowledge\n"
                "- Provide practical examples\n"
                "- Format MCQs clearly with explanations\n"
                "- Be supportive and never guarantee success\n"
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
            'temperature': 0.7,
            'presence_penalty': 0.1,
            'frequency_penalty': 0.1
        }
        last_api_call = datetime.utcnow()
        resp = requests.post(f'{OPENAI_API_BASE}/chat/completions', headers=headers, json=data, timeout=45)
        print("[OpenAI] status=" + str(resp.status_code) + " model=" + OPENAI_CHAT_MODEL)

        if resp.status_code == 200:
            result = resp.json()
            content = result['choices'][0]['message']['content']
            if 'usage' in result:
                print("[OpenAI] tokens used: " + str(result['usage'].get('total_tokens', 'unknown')))
            return content

        if resp.status_code in (401, 403):
            return "I am having trouble connecting to my knowledge base. Please try again in a moment."
        elif resp.status_code == 429:
            return "I am receiving a lot of questions right now. Please wait a short time and try again."
        elif resp.status_code >= 500:
            return "The AI service is temporarily experiencing technical difficulties. Please try again soon."
        else:
            print("[OpenAI] Unexpected status: " + str(resp.status_code))
            return "I encountered an unexpected issue. Please try rephrasing your question."
    except requests.exceptions.Timeout:
        return "My response is taking longer than usual. Please try again with a shorter question."
    except requests.exceptions.ConnectionError:
        return "I am having trouble connecting to my knowledge base. Please check your internet connection."
    except Exception as e:
        print("[OpenAI] Unexpected error: " + str(e))
        return "I encountered a technical issue. Please try again, or contact support if this continues."

def generate_enhanced_quiz(quiz_type, domain=None, difficulty='medium'):
    user_id = session.get('user_id')
    if quiz_type == 'mock-exam' and user_id:
        try:
            user_progress = UserProgress.query.filter_by(user_id=user_id).all()
            ready_for_full_exam = len(user_progress) > 0
            for progress in user_progress:
                if progress.consecutive_good_scores < 3 or progress.average_score < 75:
                    ready_for_full_exam = False
                    break
            if ready_for_full_exam:
                num_questions = 125
                flash('Full 125-question mock exam unlocked!', 'success')
            else:
                num_questions = 50
                flash('Starting with 50-question practice exam.', 'info')
        except Exception:
            num_questions = 50
    else:
        num_questions = QUIZ_TYPES.get(quiz_type, {}).get('questions', 10)
    return generate_fallback_quiz(quiz_type, domain, difficulty, num_questions)

def generate_fallback_quiz(quiz_type, domain, difficulty, num_questions):
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
            "domain": domain or "general"
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
            "domain": domain or "general"
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
    while len(questions) < num_questions:
        for q in base_questions:
            if len(questions) < num_questions:
                questions.append(q.copy())
    return {
        "title": f"CPP {quiz_type.title().replace('-', ' ')} Quiz",
        "quiz_type": quiz_type,
        "domain": domain or 'general',
        "difficulty": difficulty,
        "questions": questions[:num_questions]
    }

def update_user_progress(user_id, quiz_result):
    try:
        questions = json.loads(quiz_result.questions)
        answers = json.loads(quiz_result.answers)
        domain_results = {}
        for i, question in enumerate(questions):
            q_domain = question.get('domain', 'general')
            if q_domain == 'general':
                continue
            if q_domain not in domain_results:
                domain_results[q_domain] = {'correct': 0, 'total': 0}
            domain_results[q_domain]['total'] += 1
            user_answer = answers.get(str(i))
            if user_answer == question['correct']:
                domain_results[q_domain]['correct'] += 1

        for domain_key, results in domain_results.items():
            progress = UserProgress.query.filter_by(user_id=user_id, domain=domain_key).first()
            if not progress:
                progress = UserProgress(user_id=user_id, domain=domain_key)
                db.session.add(progress)
            domain_score = (results['correct'] / results['total']) * 100
            total_questions = progress.question_count + results['total']
            if progress.question_count > 0:
                progress.average_score = (
                    (progress.average_score * progress.question_count + domain_score * results['total'])
                    / total_questions
                )
            else:
                progress.average_score = domain_score
            progress.question_count = total_questions
            progress.last_updated = datetime.utcnow()
            if domain_score >= 75:
                progress.consecutive_good_scores += 1
            else:
                progress.consecutive_good_scores = 0
            if progress.average_score >= 90 and progress.consecutive_good_scores >= 3:
                progress.mastery_level = 'mastered'
            elif progress.average_score >= 75 and progress.consecutive_good_scores >= 2:
                progress.mastery_level = 'good'
            else:
                progress.mastery_level = 'needs_practice'
        db.session.commit()
    except Exception as e:
        print("Error updating user progress: " + str(e))
        db.session.rollback()

def get_domain_recommendation(progress):
    average_score = progress.average_score or 0
    consecutive_good_scores = progress.consecutive_good_scores or 0
    
    if average_score >= 90 and consecutive_good_scores >= 3:
        return {
            'level': 'mastered',
            'message': 'Excellent. You have mastered this domain.',
            'action': 'Review occasionally to maintain knowledge.',
            'color': 'success'
        }
    elif average_score >= 75 and consecutive_good_scores >= 2:
        return {
            'level': 'good',
            'message': 'Good progress. You understand the core concepts.',
            'action': 'Take advanced practice questions.',
            'color': 'warning'
        }
    else:
        return {
            'level': 'needs_practice',
            'message': 'This area needs more attention.',
            'action': 'Study fundamentals and take more quizzes.',
            'color': 'danger'
        }

def set_user_subscription_by_customer(customer_id, status, subscription_id=None):
    if not customer_id:
        return
    try:
        user = User.query.filter_by(stripe_customer_id=customer_id).first()
        if not user:
            print(f"No user found for Stripe customer: {customer_id}")
            return

        user.subscription_status = status
        if subscription_id:
            user.stripe_subscription_id = subscription_id

        # Keep a rough end date for UX; access is really gated by status
        if status == 'active' and not user.subscription_end_date:
            user.subscription_end_date = datetime.utcnow() + timedelta(days=30)
        elif status in ('canceled', 'expired'):
            user.subscription_status = 'expired'

        db.session.commit()
        log_activity(user.id, 'subscription_status_update', f'status={status}')
        print(f"Updated subscription for user {user.id}: {status}")
    except Exception as e:
        print(f"Error updating subscription: {e}")
        db.session.rollback()

def generate_fallback_flashcards(topic, difficulty):
    return [
        {"front": "Risk Assessment", "back": "Systematic process to identify, analyze, and evaluate potential threats and vulnerabilities.", "category": "definitions"},
        {"front": "CPTED", "back": "Crime Prevention Through Environmental Design uses physical environment design to reduce crime opportunities.", "category": "concepts"},
        {"front": "Defense in Depth", "back": "Multiple layers of controls so if one fails others continue to provide protection.", "category": "concepts"},
        {"front": "Least Privilege", "back": "Grant only the minimum access rights needed to perform job functions.", "category": "definitions"},
        {"front": "Business Continuity", "back": "Ability to maintain essential functions during and after a disruption.", "category": "definitions"},
        {"front": "Chain of Custody", "back": "Documentation that tracks evidence from collection through analysis to court presentation.", "category": "procedures"},
        {"front": "Vulnerability", "back": "Weakness that could be exploited by a threat.", "category": "definitions"},
        {"front": "Threat", "back": "Potential danger that could harm assets or operations.", "category": "definitions"},
        {"front": "Access Control", "back": "Measures that regulate who can view or use resources.", "category": "concepts"},
        {"front": "Incident Response", "back": "Preparation, detection, containment, eradication, recovery, and lessons learned.", "category": "procedures"},
        {"front": "Physical Security", "back": "Protection of people and assets from physical events.", "category": "definitions"},
        {"front": "Information Security", "back": "Protection of information through confidentiality, integrity, availability.", "category": "definitions"},
        {"front": "Security Governance", "back": "Framework that aligns security with business objectives.", "category": "concepts"},
        {"front": "Due Diligence", "back": "Investigation and assessment before decisions or agreements.", "category": "procedures"},
        {"front": "Insider Threat", "back": "Risk posed by people with authorized access.", "category": "concepts"},
        {"front": "Perimeter Security", "back": "Barriers and controls at boundaries to prevent unauthorized access.", "category": "concepts"},
        {"front": "Security Awareness", "back": "Education to keep personnel informed about policies and threats.", "category": "procedures"},
        {"front": "Crisis Management", "back": "Prepare for, respond to, and recover from emergencies.", "category": "concepts"},
        {"front": "Background Investigation", "back": "Verify history before granting access or employment.", "category": "procedures"},
        {"front": "Security Metrics", "back": "Indicators used to assess effectiveness of controls.", "category": "definitions"}
    ]

# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------
@app.route('/favicon.ico')
def favicon():
    try:
        return app.send_static_file('favicon.ico')
    except Exception:
        return Response('', status=204, mimetype='image/x-icon')

@app.get("/healthz")
def healthz():
    """Comprehensive health check endpoint"""
    health_status = {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "checks": {}
    }
    
    overall_healthy = True
    
    # Database check
    try:
        with db.engine.connect() as conn:
            conn.execute(db.text('SELECT 1'))
        health_status["checks"]["database"] = "healthy"
    except Exception as e:
        health_status["checks"]["database"] = f"unhealthy: {str(e)}"
        overall_healthy = False
    
    # Stripe check
    try:
        if stripe.api_key:
            stripe.Account.retrieve()
            health_status["checks"]["stripe"] = "healthy"
        else:
            health_status["checks"]["stripe"] = "not_configured"
    except Exception as e:
        health_status["checks"]["stripe"] = f"unhealthy: {str(e)}"
        overall_healthy = False
    
    # OpenAI check
    try:
        if OPENAI_API_KEY:
            health_status["checks"]["openai"] = "configured"
        else:
            health_status["checks"]["openai"] = "not_configured"
            overall_healthy = False
    except Exception as e:
        health_status["checks"]["openai"] = f"error: {str(e)}"
    
    if not overall_healthy:
        health_status["status"] = "unhealthy"
        return health_status, 503
    
    return health_status, 200

@app.get("/readiness")
def readiness():
    """Readiness probe for container orchestration"""
    try:
        # Quick database test
        db.session.execute(db.text('SELECT 1'))
        
        # Check if essential environment variables are set
        required_env_vars = ['SECRET_KEY', 'DATABASE_URL']
        missing_vars = [var for var in required_env_vars if not os.environ.get(var)]
        
        if missing_vars:
            return {
                "status": "not_ready", 
                "missing_env_vars": missing_vars
            }, 503
        
        return {"status": "ready", "timestamp": datetime.utcnow().isoformat()}, 200
    except Exception as e:
        return {"status": "not_ready", "error": str(e)}, 503

@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('home.html')

# -----------------------------
# Auth - Register
# -----------------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            # Input validation with detailed logging
            email = request.form.get('email', '').lower().strip()
            password = request.form.get('password', '')
            first_name = request.form.get('first_name', '').strip()
            last_name = request.form.get('last_name', '').strip()
            terms_accepted = request.form.get('terms_accepted')  # New field

            print(f"Registration attempt for email: {email}")

            # Validate required fields
            if not all([email, password, first_name, last_name]):
                print("Registration failed: Missing required fields")
                flash('All fields are required.', 'danger')
                return render_template('register.html')

            # Validate terms acceptance
            if not terms_accepted:
                print("Registration failed: Terms not accepted")
                flash('You must accept the Terms of Service and Privacy Policy to register.', 'danger')
                return render_template('register.html')

            # Validate email format
            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_pattern, email):
                print(f"Registration failed: Invalid email format for {email}")
                flash('Please enter a valid email address.', 'danger')
                return render_template('register.html')

            # Validate password strength
            if len(password) < 8:
                print("Registration failed: Password too short")
                flash('Password must be at least 8 characters long.', 'danger')
                return render_template('register.html')

            # Check if user already exists
            try:
                existing_user = User.query.filter_by(email=email).first()
                if existing_user:
                    print(f"Registration failed: Email {email} already registered")
                    flash('Email already registered. Please log in.', 'warning')
                    return redirect(url_for('login'))
            except Exception as db_error:
                print(f"Database error checking existing user: {db_error}")
                flash('Database error. Please try again.', 'danger')
                return render_template('register.html')

            # Create Stripe customer with retry logic
            stripe_customer = None
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    print(f"Creating Stripe customer (attempt {attempt + 1})")
                    stripe_customer = stripe.Customer.create(
                        email=email,
                        name=f"{first_name} {last_name}",
                        metadata={'source': 'cpp_test_prep'},
                        description=f"CPP Test Prep user: {first_name} {last_name}"
                    )
                    print(f"Stripe customer created successfully: {stripe_customer.id}")
                    break
                except stripe.error.RateLimitError as e:
                    print(f"Stripe rate limit error (attempt {attempt + 1}): {e}")
                    if attempt == max_retries - 1:
                        raise
                    time.sleep(2 ** attempt)  # Exponential backoff
                except stripe.error.StripeError as e:
                    print(f"Stripe error (attempt {attempt + 1}): {e}")
                    if attempt == max_retries - 1:
                        raise
                    time.sleep(1)

            if not stripe_customer:
                print("Failed to create Stripe customer after retries")
                flash('Registration error with payment system. Please try again.', 'danger')
                return render_template('register.html')

            # Create user record with transaction
            try:
                print("Creating user record in database")
                user = User(
                    email=email,
                    password_hash=generate_password_hash(password),
                    first_name=first_name,
                    last_name=last_name,
                    subscription_status='trial',
                    subscription_plan='trial',
                    subscription_end_date=datetime.utcnow() + timedelta(days=7),
                    stripe_customer_id=stripe_customer.id,
                    created_at=datetime.utcnow()
                )
                
                db.session.add(user)
                db.session.flush()  # Get the user ID without committing
                user_id = user.id
                
                # Create initial activity log
                log_activity(user_id, 'user_registered', f'New user: {first_name} {last_name}')
                
                # Commit the transaction
                db.session.commit()
                print(f"User created successfully with ID: {user_id}")

                # Set session variables
                session['user_id'] = user_id
                session['user_name'] = f"{first_name} {last_name}"
                session.permanent = True  # Make session permanent

                flash(f'Welcome {first_name}! You have a 7-day free trial.', 'success')
                return redirect(url_for('dashboard'))

            except Exception as db_error:
                print(f"Database error creating user: {db_error}")
                db.session.rollback()
                
                # Try to clean up Stripe customer if user creation failed
                try:
                    if stripe_customer:
                        stripe.Customer.delete(stripe_customer.id)
                        print("Cleaned up Stripe customer after database error")
                except Exception as cleanup_error:
                    print(f"Failed to cleanup Stripe customer: {cleanup_error}")
                
                flash('Registration error. Please try again.', 'danger')
                return render_template('register.html')

        except stripe.error.StripeError as e:
            print(f"Stripe error during registration: {e}")
            flash('Registration error with payment system. Please try again later.', 'danger')
            return render_template('register.html')
        except Exception as e:
            print(f"Unexpected registration error: {e}")
            import traceback
            traceback.print_exc()
            flash('An unexpected error occurred. Please try again.', 'danger')
            return render_template('register.html')

    # GET request - show registration form
    return render_template('register.html')

# -----------------------------
# Auth - Login
# -----------------------------
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
                    elif days_left <= 2:
                        flash(f'Welcome back, {user.first_name}. Your trial expires in {days_left} days.', 'warning')
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

# -----------------------------
# Dashboard
# -----------------------------
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
        except Exception as e:
            print("Error fetching activities: " + str(e))
            recent_activities = []

        try:
            recent_quizzes = QuizResult.query.filter_by(user_id=user.id).order_by(
                QuizResult.completed_at.desc()
            ).limit(5).all()
        except Exception as e:
            print("Error fetching quiz results: " + str(e))
            recent_quizzes = []

        days_left = 0
        if user.subscription_end_date:
            days_left = max(0, (user.subscription_end_date - datetime.utcnow()).days)

        quiz_stats = {
            'total_quizzes': 0,
            'avg_score': 0,
            'best_score': 0,
            'quiz_types_completed': [],
            'recent_trend': 'stable'
        }

        try:
            all_quiz_results = QuizResult.query.filter_by(user_id=user.id).all()
            if all_quiz_results:
                all_scores = [q.score for q in all_quiz_results if q.score is not None]
                if all_scores:
                    quiz_stats.update({
                        'total_quizzes': len(all_quiz_results),
                        'avg_score': sum(all_scores) / len(all_scores),
                        'best_score': max(all_scores),
                        'quiz_types_completed': list(set([q.quiz_type for q in all_quiz_results if q.quiz_type]))
                    })
                    if len(all_scores) >= 3:
                        recent_scores = all_scores[-3:]
                        if recent_scores[-1] > recent_scores[0]:
                            quiz_stats['recent_trend'] = 'improving'
                        elif recent_scores[-1] < recent_scores[0]:
                            quiz_stats['recent_trend'] = 'declining'
        except Exception as e:
            print("Error calculating quiz stats: " + str(e))

        total_study_time = 0
        try:
            study_sessions = StudySession.query.filter_by(user_id=user.id).all()
            total_study_time = sum(s.duration or 0 for s in study_sessions)
        except Exception as e:
            print("Error fetching study time: " + str(e))

        return render_template(
            'dashboard.html',
            user=user,
            recent_activities=recent_activities,
            recent_quizzes=recent_quizzes,
            days_left=days_left,
            quiz_stats=quiz_stats,
            total_study_time=total_study_time,
            quiz_types=QUIZ_TYPES,
            cpp_domains=CPP_DOMAINS
        )

    except Exception as e:
        print("Dashboard error: " + str(e))
        flash('Error loading dashboard. Please try again.', 'danger')
        return redirect(url_for('home'))

# -----------------------------
# Study and Chat
# -----------------------------
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

# -----------------------------
# Quizzes
# -----------------------------
@app.route('/quiz-selector')
@subscription_required
def quiz_selector():
    try:
        user_id = session['user_id']
        user_progress = {}
        try:
            progress_records = UserProgress.query.filter_by(user_id=user_id).all()
            for progress in progress_records:
                user_progress[progress.domain] = {
                    'mastery_level': progress.mastery_level,
                    'average_score': round(progress.average_score or 0, 1),
                    'consecutive_good_scores': progress.consecutive_good_scores
                }
        except Exception as e:
            print("Error fetching user progress: " + str(e))

        return render_template(
            'quiz_selector.html',
            quiz_types=QUIZ_TYPES,
            cpp_domains=CPP_DOMAINS,
            user_progress=user_progress
        )

    except Exception as e:
        print("Quiz selector error: " + str(e))
        flash('Error loading quiz selector. Please try again.', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/quiz/<quiz_type>')
@subscription_required
def quiz(quiz_type):
    if quiz_type not in QUIZ_TYPES:
        flash('Invalid quiz type selected.', 'danger')
        return redirect(url_for('quiz_selector'))
    try:
        domain = request.args.get('domain')
        difficulty = request.args.get('difficulty', 'medium')

        if domain and domain not in CPP_DOMAINS:
            flash('Invalid domain selected.', 'warning')
            domain = None

        session['quiz_start_time'] = datetime.utcnow().timestamp()

        quiz_data = generate_enhanced_quiz(quiz_type, domain, difficulty)
        if not quiz_data or not quiz_data.get('questions'):
            flash('Error generating quiz. Please try again.', 'danger')
            return redirect(url_for('quiz_selector'))

        log_activity(
            session['user_id'],
            'quiz_started',
            f'Type: {quiz_type}, Domain: {domain or "general"}, Difficulty: {difficulty}'
        )

        return render_template('quiz.html', quiz_data=quiz_data, quiz_type=quiz_type)

    except Exception as e:
        print(f"Quiz generation error: {e}")
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
        domain_scores = {}

        for i, question in enumerate(questions):
            user_answer = answers.get(str(i))
            is_correct = user_answer == question.get('correct')
            if is_correct:
                correct_count += 1
            q_domain = question.get('domain', 'general')
            if q_domain not in domain_scores:
                domain_scores[q_domain] = {'correct': 0, 'total': 0}
            domain_scores[q_domain]['total'] += 1
            if is_correct:
                domain_scores[q_domain]['correct'] += 1

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

        update_user_progress(session['user_id'], result)

        user = User.query.get(session['user_id'])
        try:
            scores = json.loads(user.quiz_scores) if user.quiz_scores else []
        except (json.JSONDecodeError, TypeError):
            scores = []
        scores.append({
            'score': score,
            'date': datetime.utcnow().isoformat(),
            'type': quiz_type,
            'domain': domain,
            'time_taken': time_taken
        })
        user.quiz_scores = json.dumps(scores[-50:])
        db.session.commit()

        performance_insights = []
        if score >= 90:
            performance_insights.append("Excellent performance. You are well-prepared for this topic.")
        elif score >= 80:
            performance_insights.append("Good job. Review missed questions to strengthen weak areas.")
        elif score >= 70:
            performance_insights.append("Fair performance. Focus on areas you missed.")
        else:
            performance_insights.append("Consider additional study time in this area before the exam.")

        if time_taken > 0 and total_questions > 0:
            avg_time_per_question = time_taken / total_questions
            if avg_time_per_question < 1:
                performance_insights.append("Good pace. You completed questions efficiently.")
            elif avg_time_per_question > 3:
                performance_insights.append("Consider practicing to improve speed.")

        for domain_key, domain_score in domain_scores.items():
            if domain_score['total'] > 2:
                domain_pct = (domain_score['correct'] / domain_score['total']) * 100
                if domain_pct < 70:
                    domain_name = CPP_DOMAINS.get(domain_key, {}).get('name', domain_key)
                    performance_insights.append(f"Focus more study time on {domain_name}")

        log_activity(
            session['user_id'],
            'quiz_completed',
            f'{quiz_type} quiz: {correct_count}/{total_questions} ({score:.1f} percent) in {time_taken} min'
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
            'domain_scores': domain_scores,
            'performance_insights': performance_insights,
            'results': detailed_results
        })

    except Exception as e:
        print(f"Submit quiz error: {e}")
        db.session.rollback()
        return jsonify({'error': 'Error processing quiz results. Please try again.'}), 500

# -----------------------------
# Flashcards
# -----------------------------
@app.route('/flashcards')
@subscription_required
def flashcards():
    try:
        topic = request.args.get('topic', 'CPP core domains')
        difficulty = request.args.get('difficulty', 'medium')
        if len(topic) > 100:
            topic = topic[:100]

        prompt = f"""Create 20 comprehensive flashcards for the ASIS CPP exam about: {topic}.
Difficulty level: {difficulty}

Return ONLY valid JSON:
{{
  "topic": "{topic}",
  "difficulty": "{difficulty}",
  "total_cards": 20,
  "cards": [
    {{"front": "Term or concept", "back": "Clear explanation with context", "category": "definitions|concepts|scenarios|procedures"}}
  ]
}}"""

        ai_response = chat_with_ai([{'role': 'user', 'content': prompt}])

        try:
            json_match = re.search(r'\{.*\}', ai_response, re.DOTALL)
            if json_match:
                flashcard_data = json.loads(json_match.group())
                if not flashcard_data.get('cards'):
                    raise ValueError("No cards in response")
            else:
                raise ValueError("No JSON found")
        except Exception as e:
            print(f"Flashcard generation error: {e}")
            fallback_cards = generate_fallback_flashcards(topic, difficulty)
            flashcard_data = {
                "topic": topic,
                "difficulty": difficulty,
                "total_cards": len(fallback_cards),
                "cards": fallback_cards
            }

        log_activity(
            session['user_id'],
            'flashcards_viewed',
            f'Topic: {topic}, Difficulty: {difficulty}, Cards: {len(flashcard_data.get("cards", []))}'
        )

        return render_template('flashcards.html', flashcard_data=flashcard_data, cpp_domains=CPP_DOMAINS)

    except Exception as e:
        print(f"Flashcards error: {e}")
        flash('Error loading flashcards. Please try again.', 'danger')
        return redirect(url_for('dashboard'))

# -----------------------------
# Performance Analysis
# -----------------------------
@app.route('/performance-analysis')
@login_required
def performance_analysis():
    try:
        user_id = session['user_id']
        domain_analysis = {}
        
        for domain_key, domain_info in CPP_DOMAINS.items():
            progress = UserProgress.query.filter_by(user_id=user_id, domain=domain_key).first()
            if not progress:
                progress = UserProgress(user_id=user_id, domain=domain_key)
                db.session.add(progress)
            
            avg_score = progress.average_score
            if avg_score is None:
                avg_score = 0
            
            last_updated_str = 'Never'
            if progress.last_updated:
                last_updated_str = progress.last_updated.strftime('%Y-%m-%d')
            
            domain_analysis[domain_key] = {
                'name': domain_info['name'],
                'topics': domain_info['topics'],
                'mastery_level': progress.mastery_level,
                'average_score': round(avg_score, 1),
                'question_count': progress.question_count,
                'consecutive_good_scores': progress.consecutive_good_scores,
                'recommendation': get_domain_recommendation(progress),
                'last_updated': last_updated_str
            }
        
        db.session.commit()

        needs_practice = []
        good_progress = []
        mastered = []
        
        for d in domain_analysis.values():
            if d['mastery_level'] == 'needs_practice':
                needs_practice.append(d)
            elif d['mastery_level'] == 'good':
                good_progress.append(d)
            elif d['mastery_level'] == 'mastered':
                mastered.append(d)

        overall_recommendations = []
        if needs_practice:
            needs_practice_domains = [d['name'] for d in needs_practice[:3]]
            overall_recommendations.append({
                'priority': 'high',
                'title': 'Focus Areas - High Priority',
                'domains': needs_practice_domains,
                'action': 'Spend 60 percent of study time on these domains',
                'color': 'danger'
            })
        
        if good_progress:
            good_progress_domains = [d['name'] for d in good_progress]
            overall_recommendations.append({
                'priority': 'medium',
                'title': 'Reinforcement Areas',
                'domains': good_progress_domains,
                'action': 'Take advanced quizzes and practice scenarios',
                'color': 'warning'
            })
        
        if mastered:
            mastered_domains = [d['name'] for d in mastered]
            overall_recommendations.append({
                'priority': 'low',
                'title': 'Mastered Areas',
                'domains': mastered_domains,
                'action': 'Light review to maintain knowledge',
                'color': 'success'
            })

        total_domains = len(CPP_DOMAINS)
        readiness_score = 0
        if total_domains > 0:
            readiness_score = (len(mastered) * 100 + len(good_progress) * 70) / total_domains

        return render_template(
            'performance_analysis.html',
            domain_analysis=domain_analysis,
            recommendations=overall_recommendations,
            readiness_score=round(readiness_score, 1),
            cpp_domains=CPP_DOMAINS
        )

    except Exception as e:
        print("Performance analysis error: " + str(e))
        flash('Error loading performance analysis. Please try again.', 'danger')
        return redirect(url_for('dashboard'))

# -----------------------------
# Progress
# -----------------------------
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

        try:
            study_sessions = StudySession.query.filter_by(user_id=user.id).all()
            total_study_time = sum(s.duration or 0 for s in study_sessions)
        except Exception as e:
            print(f"Error fetching study sessions: {e}")

