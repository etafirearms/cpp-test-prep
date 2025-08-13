from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import json
import os
import requests
import stripe
import time
import hashlib
from functools import wraps

# -----------------------------------------------------------------------------
# App & Config
# -----------------------------------------------------------------------------
app = Flask(__name__)

def require_env(name: str) -> str:
    val = os.environ.get(name)
    if not val:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return val

# Required env vars (set these in Render → Environment)
app.config['SECRET_KEY'] = require_env('SECRET_KEY')

app.config['SQLALCHEMY_DATABASE_URI'] = require_env('DATABASE_URL')
# Render sometimes provides postgres://; SQLAlchemy expects postgresql://
if app.config['SQLALCHEMY_DATABASE_URI'].startswith('postgres://'):
    app.config['SQLALCHEMY_DATABASE_URI'] = app.config['SQLALCHEMY_DATABASE_URI'].replace('postgres://', 'postgresql://')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_recycle': 300,
    'connect_args': {
        'sslmode': 'require',
        'connect_timeout': 10
    }
}
db = SQLAlchemy(app)

# OpenAI config
OPENAI_API_KEY = require_env('OPENAI_API_KEY')
OPENAI_CHAT_MODEL = os.environ.get('OPENAI_CHAT_MODEL', 'gpt-4o-mini')
OPENAI_API_BASE = os.environ.get('OPENAI_API_BASE', 'https://api.openai.com/v1')

# Stripe config
stripe.api_key = require_env('STRIPE_SECRET_KEY')
STRIPE_PUBLISHABLE_KEY = require_env('STRIPE_PUBLISHABLE_KEY')
STRIPE_WEBHOOK_SECRET = os.environ.get('STRIPE_WEBHOOK_SECRET')

# Simple rate limiter for AI calls
last_api_call = None

# -----------------------------------------------------------------------------
# Quiz Types Configuration (Enhanced)
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
        'questions': 50  # Will be dynamic based on user progress
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
    domain = db.Column(db.String(50))  # Fixed: Add missing column
    questions = db.Column(db.Text, nullable=False)
    answers = db.Column(db.Text, nullable=False)
    score = db.Column(db.Float, nullable=False)
    total_questions = db.Column(db.Integer, nullable=False)
    time_taken = db.Column(db.Integer)  # Fixed: Add missing column
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
    """Track all generated questions to prevent duplicates"""
    id = db.Column(db.Integer, primary_key=True)
    question_hash = db.Column(db.String(64), unique=True, nullable=False)
    question_text = db.Column(db.Text, nullable=False)
    domain = db.Column(db.String(50))
    difficulty = db.Column(db.String(20))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class UserProgress(db.Model):
    """Track user progress by domain and difficulty"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    domain = db.Column(db.String(50), nullable=False)
    mastery_level = db.Column(db.String(20), default='needs_practice')
    average_score = db.Column(db.Float, default=0.0)
    question_count = db.Column(db.Integer, default=0)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow)
    consecutive_good_scores = db.Column(db.Integer, default=0)

# Fixed: Database initialization with proper error handling
def migrate_database_safe():
    """Safely add missing columns to existing tables"""
    try:
        with app.app_context():
            # Check if tables exist and create them if they don't
            inspector = db.inspect(db.engine)
            
            if 'quiz_result' in inspector.get_table_names():
                columns = [column['name'] for column in inspector.get_columns('quiz_result')]
                
                # Add missing columns with raw SQL
                with db.engine.connect() as conn:
                    if 'domain' not in columns:
                        try:
                            conn.execute(db.text("ALTER TABLE quiz_result ADD COLUMN domain VARCHAR(50)"))
                            print("Added domain column to quiz_result")
                        except Exception as e:
                            print(f"Domain column might already exist: {e}")
                    
                    if 'time_taken' not in columns:
                        try:
                            conn.execute(db.text("ALTER TABLE quiz_result ADD COLUMN time_taken INTEGER"))
                            print("Added time_taken column to quiz_result")
                        except Exception as e:
                            print(f"Time_taken column might already exist: {e}")
                    
                    conn.commit()
            
            # Create all tables
            db.create_all()
            print("Database tables created/updated successfully!")
            
    except Exception as e:
        print(f"Database migration error: {e}")
        # Try to create tables anyway
        try:
            db.create_all()
            print("Fallback: Created tables without migration")
        except Exception as e2:
            print(f"Fallback creation failed: {e2}")

# Initialize database with migration
with app.app_context():
    migrate_database_safe()

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
                
            # Check subscription status
            if user.subscription_status == 'expired':
                flash('Your subscription has expired. Please renew to continue.', 'danger')
                return redirect(url_for('subscribe'))
            
            # Check trial expiry
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
    """Enhanced activity logging with error handling"""
    try:
        activity_log = ActivityLog(user_id=user_id, activity=activity, details=details)
        db.session.add(activity_log)
        db.session.commit()
    except Exception as e:
        print(f"Activity logging error: {e}")
        # Don't fail the main operation due to logging issues

def safe_db_operation(operation_func):
    """Decorator for safe database operations with retry"""
    @wraps(operation_func)
    def wrapper(*args, **kwargs):
        max_retries = 3
        for attempt in range(max_retries):
            try:
                return operation_func(*args, **kwargs)
            except Exception as e:
                print(f"Database operation failed (attempt {attempt + 1}): {e}")
                if attempt == max_retries - 1:
                    db.session.rollback()
                    raise e
                time.sleep(0.5)  # Brief delay before retry
    return wrapper

def chat_with_ai(messages, user_id=None):
    """Enhanced AI chat function with better error handling"""
    global last_api_call
    try:
        # Rate limiting
        if last_api_call:
            delta = datetime.utcnow() - last_api_call
            if delta.total_seconds() < 2:
                time.sleep(2 - delta.total_seconds())

        # Enhanced system message
        system_message = {
            "role": "system",
            "content": (
                "You are an expert tutor for the ASIS Certified Protection Professional (CPP) exam.\n\n"
                "FOCUS AREAS:\n"
                "1. Security Principles & Practices - Risk management, governance, ethics\n"
                "2. Business Principles & Practices - Budgeting, contracts, project management\n"
                "3. Investigations - Planning, interviews, evidence, reporting\n"
                "4. Personnel Security - Background screening, insider threats, workplace violence\n"
                "5. Physical Security - CPTED, access control, perimeter security\n"
                "6. Information Security - Data protection, cybersecurity, incident response\n"
                "7. Crisis Management - Business continuity, disaster recovery, emergency response\n\n"
                "GUIDELINES:\n"
                "- Use only public, non-proprietary knowledge\n"
                "- Provide practical, real-world examples\n"
                "- Format multiple-choice questions clearly\n"
                "- Give detailed explanations for answers\n"
                "- Be encouraging and supportive\n"
                "- Never guarantee exam success\n\n"
                "QUESTION FORMAT:\n"
                "**Question #. [Question text]**\n\n"
                "A. [Option A]\nB. [Option B]\nC. [Option C]\nD. [Option D]\n\n"
                "**Answer: [Letter]**\n"
                "**Explanation:** [Clear explanation]\n"
            )
        }
        
        # Ensure system message is first
        if not messages or messages[0].get('role') != 'system':
            messages.insert(0, system_message)
        else:
            messages[0] = system_message  # Update existing system message

        headers = {
            'Authorization': f'Bearer {OPENAI_API_KEY}',
            'Content-Type': 'application/json'
        }
        
        data = {
            'model': OPENAI_CHAT_MODEL,
            'messages': messages,
            'max_tokens': 1500,  # Increased for better responses
            'temperature': 0.7,
            'presence_penalty': 0.1,  # Encourage variety
            'frequency_penalty': 0.1   # Reduce repetition
        }

        last_api_call = datetime.utcnow()
        resp = requests.post(
            f'{OPENAI_API_BASE}/chat/completions', 
            headers=headers, 
            json=data, 
            timeout=45
        )

        print(f"[OpenAI] status={resp.status_code} model={OPENAI_CHAT_MODEL}")

        if resp.status_code == 200:
            result = resp.json()
            content = result['choices'][0]['message']['content']
            
            # Log usage for debugging
            if 'usage' in result:
                print(f"[OpenAI] tokens used: {result['usage'].get('total_tokens', 'unknown')}")
            
            return content

        # Enhanced error messages
        if resp.status_code in (401, 403):
            return (
                "I'm having trouble connecting to my knowledge base. This might be due to "
                "API authentication issues. Please try again in a moment, or contact support "
                "if the problem persists."
            )
        elif resp.status_code == 429:
            return (
                "I'm receiving a lot of questions right now and need a moment to catch up. "
                "Please wait 30 seconds and try your question again."
            )
        elif resp.status_code >= 500:
            return (
                "The AI service is temporarily experiencing technical difficulties. "
                "Please try again in a few minutes."
            )
        else:
            print(f"[OpenAI] Unexpected status: {resp.status_code}, body: {resp.text[:200]}")
            return "I encountered an unexpected issue. Please try rephrasing your question."

    except requests.exceptions.Timeout:
        return (
            "My response is taking longer than usual. Please try again with a shorter "
            "or more specific question."
        )
    except requests.exceptions.ConnectionError:
        return (
            "I'm having trouble connecting to my knowledge base. Please check your "
            "internet connection and try again."
        )
    except Exception as e:
        print(f"[OpenAI] Unexpected error: {e}")
        return (
            "I encountered a technical issue while processing your question. "
            "Please try again, or contact support if this continues."
        )

def generate_quiz_questions_with_uniqueness(quiz_type, domain, difficulty, num_questions, user_id):
    """Generate unique questions and store hashes to prevent duplicates"""
    
    domain_focus = ""
    if domain and domain in CPP_DOMAINS:
        domain_info = CPP_DOMAINS[domain]
        domain_focus = f"\nFocus specifically on {domain_info['name']} including: {', '.join(domain_info['topics'])}."
    
    # Enhanced prompt for better question generation
    prompt = f"""Create {num_questions} UNIQUE multiple-choice questions for the ASIS CPP exam.
{domain_focus}

REQUIREMENTS:
- Difficulty: {difficulty}
- Each question must be completely unique (no duplicates)
- Cover different aspects, scenarios, and applications
- Include practical, real-world scenarios
- Questions should test understanding, not just memorization
- Ensure answers are clearly distinguishable

QUESTION TYPES TO INCLUDE:
- Conceptual understanding (40%)
- Scenario-based applications (30%)
- Best practices and procedures (20%)
- Regulatory and compliance (10%)

Return ONLY valid JSON in this exact format:
{{
  "title": "CPP {quiz_type.title().replace('-', ' ')} Quiz",
  "questions": [
    {{
      "question": "Clear, specific question text",
      "options": {{"A": "option", "B": "option", "C": "option", "D": "option"}},
      "correct": "A",
      "explanation": "Detailed explanation with reasoning",
      "domain": "{domain or 'general'}"
    }}
  ]
}}

Ensure all {num_questions} questions are included in the response."""

    ai_response = chat_with_ai([{'role': 'user', 'content': prompt}])
    
    try:
        import re
        # Try to extract JSON from response
        json_match = re.search(r'\{.*\}', ai_response, re.DOTALL)
        if json_match:
            quiz_data = json.loads(json_match.group())
            
            # Validate structure
            if 'questions' not in quiz_data or not isinstance(quiz_data['questions'], list):
                raise ValueError("Invalid quiz structure")
            
            # Check for duplicates and store new questions
            unique_questions = []
            for question in quiz_data.get('questions', []):
                question_text = question.get('question', '')
                if not question_text:
                    continue
                    
                question_hash = hashlib.md5(question_text.encode()).hexdigest()
                
                # Check if question already exists
                try:
                    existing = QuestionBank.query.filter_by(question_hash=question_hash).first()
                    if not existing:
                        # Store new question
                        new_question = QuestionBank(
                            question_hash=question_hash,
                            question_text=question_text,
                            domain=question.get('domain', domain or 'general'),
                            difficulty=difficulty
                        )
                        db.session.add(new_question)
                        unique_questions.append(question)
                    else:
                        print(f"Duplicate question detected: {question_text[:50]}...")
                except Exception as e:
                    print(f"Database error checking duplicates: {e}")
                    # Include question anyway if DB check fails
                    unique_questions.append(question)
            
            # Accept if we have at least 70% unique questions
            if len(unique_questions) >= max(1, num_questions * 0.7):
                quiz_data['questions'] = unique_questions[:num_questions]
                try:
                    db.session.commit()
                except Exception as e:
                    print(f"Error saving questions to database: {e}")
                    db.session.rollback()
                return quiz_data
            else:
                print(f"Too many duplicates: {len(unique_questions)} unique out of {num_questions}")
                db.session.rollback()
                return None
                
    except json.JSONDecodeError as e:
        print(f"JSON parsing error: {e}")
        print(f"AI response preview: {ai_response[:500]}")
        return None
    except Exception as e:
        print(f"Quiz generation error: {e}")
        db.session.rollback()
        return None

def generate_fallback_quiz(quiz_type, domain, difficulty, num_questions):
    """Generate fallback quiz when AI generation fails"""
    
    # Domain-specific fallback questions
    domain_questions = {
        'security-principles': [
            {
                "question": "What is the primary purpose of a comprehensive security risk assessment?",
                "options": {
                    "A": "To identify all possible security threats",
                    "B": "To determine cost-effective risk mitigation strategies",
                    "C": "To eliminate all security risks completely",
                    "D": "To satisfy insurance and regulatory requirements"
                },
                "correct": "B",
                "explanation": "Risk assessments help organizations identify risks and determine the most cost-effective strategies to mitigate them, balancing security needs with business requirements.",
                "domain": "security-principles"
            },
            {
                "question": "Which principle is fundamental to effective security governance?",
                "options": {
                    "A": "Maximum security at minimum cost",
                    "B": "Security decisions made by IT department",
                    "C": "Alignment with business objectives",
                    "D": "Standardization across all departments"
                },
                "correct": "C",
                "explanation": "Security governance must align with business objectives to be effective and sustainable, ensuring security supports rather than hinders business goals.",
                "domain": "security-principles"
            }
        ],
        'physical-security': [
            {
                "question": "In CPTED principles, what does 'natural surveillance' primarily accomplish?",
                "options": {
                    "A": "Reduces the need for security guards",
                    "B": "Increases the likelihood that criminal activity will be observed",
                    "C": "Eliminates blind spots in camera coverage",
                    "D": "Provides legal liability protection"
                },
                "correct": "B",
                "explanation": "Natural surveillance increases visibility and the perception that criminal activity will be observed, which serves as a deterrent to potential offenders.",
                "domain": "physical-security"
            }
        ],
        'information-security': [
            {
                "question": "What is the most critical first step in incident response?",
                "options": {
                    "A": "Notify law enforcement",
                    "B": "Document everything immediately",
                    "C": "Contain the incident to prevent further damage",
                    "D": "Identify the root cause"
                },
                "correct": "C",
                "explanation": "Containment is critical to prevent further damage and limit the scope of the incident before other response activities can be effectively undertaken.",
                "domain": "information-security"
            }
        ]
    }
    
    # Get domain-specific questions or use general ones
    base_questions = domain_questions.get(domain, domain_questions['security-principles'])
    
    # Add more general questions to reach the required number
    general_questions = [
        {
            "question": "What is the key difference between a vulnerability and a threat?",
            "options": {
                "A": "Vulnerabilities are external, threats are internal",
                "B": "Threats are potential dangers, vulnerabilities are weaknesses",
                "C": "Vulnerabilities cost money, threats do not",
                "D": "There is no significant difference"
            },
            "correct": "B",
            "explanation": "Threats are potential dangers or adverse events, while vulnerabilities are weaknesses that could be exploited by threats.",
            "domain": domain or "general"
        },
        {
            "question": "In security management, what does 'defense in depth' mean?",
            "options": {
                "A": "Having the strongest possible perimeter security",
                "B": "Multiple layers of security controls",
                "C": "Deep background checks on all personnel",
                "D": "Detailed incident response procedures"
            },
            "correct": "B",
            "explanation": "Defense in depth involves implementing multiple layers of security controls so that if one layer fails, others continue to provide protection.",
            "domain": domain or "general"
        }
    ]
    
    # Combine and extend questions to meet requirements
    all_questions = base_questions + general_questions
    
    # Extend the list if we need more questions
    while len(all_questions) < num_questions:
        all_questions.extend(base_questions)
    
    return {
        "title": f"CPP {quiz_type.title().replace('-', ' ')} Quiz",
        "quiz_type": quiz_type,
        "domain": domain or 'general',
        "difficulty": difficulty,
        "questions": all_questions[:num_questions]
    }

@safe_db_operation
def generate_enhanced_quiz(quiz_type, domain=None, difficulty='medium'):
    """Generate enhanced quiz questions with duplicate prevention and progressive difficulty"""
    user_id = session.get('user_id')
    
    # Dynamic question count for mock exams
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
                flash('Full 125-question mock exam unlocked! This simulates the actual CPP exam.', 'success')
            else:
                num_questions = 50
                flash('Starting with 50-question practice exam. Score consistently above 75% to unlock the full exam.', 'info')
        except Exception as e:
            print(f"Error checking user progress: {e}")
            num_questions = 50
    else:
        num_questions = QUIZ_TYPES.get(quiz_type, {}).get('questions', 10)
    
    # Generate questions with uniqueness check
    max_attempts = 3
    for attempt in range(max_attempts):
        try:
            quiz_data = generate_quiz_questions_with_uniqueness(
                quiz_type, domain, difficulty, num_questions, user_id
            )
            if quiz_data and len(quiz_data.get('questions', [])) >= max(1, num_questions * 0.5):
                return quiz_data
        except Exception as e:
            print(f"Quiz generation attempt {attempt + 1} failed: {e}")
    
    # Fallback if all attempts fail
    print("Using fallback quiz generation")
    return generate_fallback_quiz(quiz_type, domain, difficulty, num_questions)

@safe_db_operation
def update_user_progress(user_id, quiz_result):
    """Update user progress based on quiz results"""
    try:
        questions = json.loads(quiz_result.questions)
        answers = json.loads(quiz_result.answers)
        
        # Group questions by domain
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
        
        # Update progress for each domain
        for domain, results in domain_results.items():
            progress = UserProgress.query.filter_by(user_id=user_id, domain=domain).first()
            if not progress:
                progress = UserProgress(user_id=user_id, domain=domain)
                db.session.add(progress)
            
            # Calculate domain score
            domain_score = (results['correct'] / results['total']) * 100
            
            # Update running average (weighted by question count)
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
            
            # Update consecutive good scores
            if domain_score >= 75:  # Raised threshold for "good" scores
                progress.consecutive_good_scores += 1
            else:
                progress.consecutive_good_scores = 0
            
            # Update mastery level
            if progress.average_score >= 90 and progress.consecutive_good_scores >= 3:
                progress.mastery_level = 'mastered'
            elif progress.average_score >= 75 and progress.consecutive_good_scores >= 2:
                progress.mastery_level = 'good'
            else:
                progress.mastery_level = 'needs_practice'
        
        db.session.commit()
    except Exception as e:
        print(f"Error updating user progress: {e}")
        db.session.rollback()

def get_domain_recommendation(progress):
    """Generate specific recommendations based on performance"""
    if progress.average_score >= 90 and progress.consecutive_good_scores >= 3:
        return {
            'level': 'mastered',
            'message': 'Excellent! You have mastered this domain.',
            'action': 'Review occasionally to maintain knowledge. Focus on other domains.',
            'color': 'success'
        }
    elif progress.average_score >= 75 and progress.consecutive_good_scores >= 2:
        return {
            'level': 'good',
            'message': 'Good progress! You understand the core concepts.',
            'action': 'Take advanced practice questions and focus on edge cases.',
            'color': 'warning'
        }
    else:
        return {
            'level': 'needs_practice',
            'message': 'This area needs more attention.',
            'action': 'Study fundamental concepts and take more practice quizzes.',
            'color': 'danger'
        }

def set_user_subscription_by_customer(customer_id, status, subscription_id=None):
    """Find user by Stripe customer and update subscription status."""
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
            
        if status == 'active' and not user.subscription_end_date:
            user.subscription_end_date = datetime.utcnow() + timedelta(days=90)
        elif status in ('canceled', 'expired'):
            user.subscription_status = 'expired'
            
        db.session.commit()
        log_activity(user.id, 'subscription_status_update', f'status={status}')
        print(f"Updated subscription for user {user.id}: {status}")
        
    except Exception as e:
        print(f"Error updating subscription: {e}")
        db.session.rollback()

# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------
@app.get("/healthz")
def healthz():
    """Health check endpoint"""
    try:
        # Test database connection
        db.session.execute(db.text('SELECT 1'))
        return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}, 200
    except Exception as e:
        return {"status": "unhealthy", "error": str(e)}, 500

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

        # Validation
        if not all([email, password, first_name, last_name]):
            flash('All fields are required.', 'danger')
            return render_template('register.html')

        if len(password) < 8:
            flash('Password must be at least 8 characters long.', 'danger')
            return render_template('register.html')

        if User.query.filter_by(email=email).first():
            flash('Email already registered. Please log in.', 'warning')
            return redirect(url_for('login'))

        try:
            # Create Stripe customer
            stripe_customer = stripe.Customer.create(
                email=email, 
                name=f"{first_name} {last_name}",
                metadata={'source': 'cpp_test_prep'}
            )
            
            # Create user
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

            # Log registration
            log_activity(user.id, 'user_registered', f'New user: {first_name} {last_name}')
            
            # Set session
            session['user_id'] = user.id
            session['user_name'] = f"{first_name} {last_name}"
            
            flash(f'Welcome {first_name}! You have a 7-day free trial.', 'success')
            return redirect(url_for('dashboard'))
            
        except stripe.error.StripeError as e:
            print(f"Stripe error during registration: {e}")
            flash('Registration error with payment system. Please try again.', 'danger')
        except Exception as e:
            print(f"Registration error: {e}")
            flash('Registration error. Please try again.', 'danger')
            db.session.rollback()

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
                
                # Check trial status
                if user.subscription_status == 'trial' and user.subscription_end_date:
                    days_left = (user.subscription_end_date - datetime.utcnow()).days
                    if days_left <= 0:
                        user.subscription_status = 'expired'
                        db.session.commit()
                        flash(f'Welcome back, {user.first_name}! Your trial has expired.', 'warning')
                    elif days_left <= 2:
                        flash(f'Welcome back, {user.first_name}! Your trial expires in {days_left} days.', 'warning')
                    else:
                        flash(f'Welcome back, {user.first_name}!', 'success')
                else:
                    flash(f'Welcome back, {user.first_name}!', 'success')
                    
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
            
        # Get recent activities with error handling
        try:
            recent_activities = ActivityLog.query.filter_by(user_id=user.id).order_by(
                ActivityLog.timestamp.desc()
            ).limit(10).all()
        except Exception as e:
            print(f"Error fetching activities: {e}")
            recent_activities = []

        # Get recent quizzes with error handling
        try:
            recent_quizzes = QuizResult.query.filter_by(user_id=user.id).order_by(
                QuizResult.completed_at.desc()
            ).limit(5).all()
        except Exception as e:
            print(f"Error fetching quiz results: {e}")
            recent_quizzes = []

        # Calculate days left in subscription
        days_left = 0
        if user.subscription_end_date:
            days_left = max(0, (user.subscription_end_date - datetime.utcnow()).days)

        # Enhanced quiz statistics with error handling
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
                all_scores = [q.score for q in all_quiz_results]
                quiz_stats.update({
                    'total_quizzes': len(all_quiz_results),
                    'avg_score': sum(all_scores) / len(all_scores),
                    'best_score': max(all_scores),
                    'quiz_types_completed': list(set([q.quiz_type for q in all_quiz_results]))
                })
                
                # Calculate trend
                if len(all_scores) >= 3:
                    recent_scores = all_scores[-3:]
                    if recent_scores[-1] > recent_scores[0]:
                        quiz_stats['recent_trend'] = 'improving'
                    elif recent_scores[-1] < recent_scores[0]:
                        quiz_stats['recent_trend'] = 'declining'
                        
        except Exception as e:
            print(f"Error calculating quiz stats: {e}")

        # Study time tracking
        total_study_time = 0
        try:
            study_sessions = StudySession.query.filter_by(user_id=user.id).all()
            total_study_time = sum(s.duration or 0 for s in study_sessions)
        except Exception as e:
            print(f"Error fetching study time: {e}")

        return render_template('dashboard.html',
                               user=user,
                               recent_activities=recent_activities,
                               recent_quizzes=recent_quizzes,
                               days_left=days_left,
                               quiz_stats=quiz_stats,
                               total_study_time=total_study_time,
                               quiz_types=QUIZ_TYPES,
                               cpp_domains=CPP_DOMAINS)
                               
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
            
        # Get or create chat history
        chat_history = ChatHistory.query.filter_by(user_id=user.id).first()
        if not chat_history:
            chat_history = ChatHistory(user_id=user.id, messages='[]')
            db.session.add(chat_history)
            db.session.commit()

        messages = []
        try:
            messages = json.loads(chat_history.messages)
        except (json.JSONDecodeError, TypeError):
            messages = []
            chat_history.messages = '[]'
            db.session.commit()

        # Track study session start
        session['study_start_time'] = datetime.utcnow().timestamp()
        
        return render_template('study.html', 
                             user=user, 
                             messages=messages,
                             current_time=datetime.utcnow().strftime('%H:%M'),
                             cpp_domains=CPP_DOMAINS)
                             
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
        
        # Get chat history
        chat_history = ChatHistory.query.filter_by(user_id=user_id).first()
        if not chat_history:
            chat_history = ChatHistory(user_id=user_id, messages='[]')
            db.session.add(chat_history)
        
        # Parse existing messages
        try:
            messages = json.loads(chat_history.messages) if chat_history.messages else []
        except json.JSONDecodeError:
            messages = []

        # Limit message history to prevent context overflow
        if len(messages) > 20:
            messages = messages[-20:]

        # Add user message
        timestamp = datetime.utcnow().isoformat()
        messages.append({
            'role': 'user', 
            'content': user_message, 
            'timestamp': timestamp
        })

        # Prepare messages for AI (remove timestamps for API call)
        openai_messages = [{'role': m['role'], 'content': m['content']} for m in messages]
        
        # Get AI response
        ai_response = chat_with_ai(openai_messages, user_id)
        
        # Add AI response to history
        messages.append({
            'role': 'assistant', 
            'content': ai_response, 
            'timestamp': datetime.utcnow().isoformat()
        })

        # Save updated chat history
        chat_history.messages = json.dumps(messages)
        chat_history.updated_at = datetime.utcnow()
        db.session.commit()

        # Log activity
        log_activity(user_id, 'chat_message', f'Asked: {user_message[:50]}...')
        
        return jsonify({
            'response': ai_response, 
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        print(f"Chat error: {e}")
        return jsonify({
            'error': 'Sorry, I encountered an error processing your message. Please try again.'
        }), 500

@app.route('/quiz-selector')
@subscription_required
def quiz_selector():
    """Enhanced quiz selection interface"""
    try:
        user_id = session['user_id']
        
        # Get user progress for recommendations
        user_progress = {}
        try:
            progress_records = UserProgress.query.filter_by(user_id=user_id).all()
            for progress in progress_records:
                user_progress[progress.domain] = {
                    'mastery_level': progress.mastery_level,
                    'average_score': progress.average_score,
                    'consecutive_good_scores': progress.consecutive_good_scores
                }
        except Exception as e:
            print(f"Error fetching user progress: {e}")
        
        return render_template('quiz_selector.html', 
                               quiz_types=QUIZ_TYPES, 
                               cpp_domains=CPP_DOMAINS,
                               user_progress=user_progress)
                               
    except Exception as e:
        print(f"Quiz selector error: {e}")
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
        
        # Validate domain
        if domain and domain not in CPP_DOMAINS:
            flash('Invalid domain selected.', 'warning')
            domain = None
        
        # Store quiz start time
        session['quiz_start_time'] = datetime.utcnow().timestamp()
        
        # Generate quiz with enhanced features
        quiz_data = generate_enhanced_quiz(quiz_type, domain, difficulty)
        
        if not quiz_data or not quiz_data.get('questions'):
            flash('Error generating quiz. Please try again.', 'danger')
            return redirect(url_for('quiz_selector'))
        
        log_activity(session['user_id'], 'quiz_started', 
                     f'Type: {quiz_type}, Domain: {domain or "general"}, Difficulty: {difficulty}')
        
        return render_template('quiz.html', 
                               quiz_data=quiz_data, 
                               quiz_type=quiz_type)
                               
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

        # Calculate time taken
        time_taken = 0
        if 'quiz_start_time' in session:
            start_time = datetime.fromtimestamp(session['quiz_start_time'])
            time_taken = int((datetime.utcnow() - start_time).total_seconds() / 60)
            del session['quiz_start_time']

        # Calculate scores
        correct_count = 0
        total_questions = len(questions)
        domain_scores = {}
        
        for i, question in enumerate(questions):
            user_answer = answers.get(str(i))
            is_correct = user_answer == question.get('correct')
            
            if is_correct:
                correct_count += 1
            
            # Track domain-specific performance
            q_domain = question.get('domain', 'general')
            if q_domain not in domain_scores:
                domain_scores[q_domain] = {'correct': 0, 'total': 0}
            domain_scores[q_domain]['total'] += 1
            if is_correct:
                domain_scores[q_domain]['correct'] += 1

        score = (correct_count / total_questions) * 100 if total_questions else 0.0

        # Save quiz result
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

        # Update user progress
        update_user_progress(session['user_id'], result)

        # Update user quiz scores
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
        user.quiz_scores = json.dumps(scores[-50:])  # Keep last 50 scores
        db.session.commit()

        # Generate performance insights
        performance_insights = []
        if score >= 90:
            performance_insights.append("🎉 Excellent performance! You're well-prepared for this topic.")
        elif score >= 80:
            performance_insights.append("👍 Good job! Review the missed questions to strengthen weak areas.")
        elif score >= 70:
            performance_insights.append("📚 Fair performance. Focus on studying the areas you missed.")
        else:
            performance_insights.append("📖 Consider additional study time in this area before the exam.")

        # Add time-based feedback
        if time_taken > 0:
            avg_time_per_question = time_taken / total_questions
            if avg_time_per_question < 1:
                performance_insights.append("⚡ Good pace! You completed questions efficiently.")
            elif avg_time_per_question > 3:
                performance_insights.append("🕒 Consider practicing to improve your speed.")

        # Domain-specific feedback
        for domain_key, domain_score in domain_scores.items():
            if domain_score['total'] > 2:  # Only for domains with sufficient questions
                domain_pct = (domain_score['correct'] / domain_score['total']) * 100
                if domain_pct < 70:
                    domain_name = CPP_DOMAINS.get(domain_key, {}).get('name', domain_key)
                    performance_insights.append(f"🎯 Focus more study time on {domain_name}")

        # Log completion
        log_activity(session['user_id'], 'quiz_completed', 
                     f'{quiz_type} quiz: {correct_count}/{total_questions} ({score:.1f}%) in {time_taken}min')
        
        # Prepare detailed results
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
        return jsonify({
            'error': 'Error processing quiz results. Please try again.'
        }), 500

@app.route('/flashcards')
@subscription_required
def flashcards():
    try:
        topic = request.args.get('topic', 'CPP core domains')
        difficulty = request.args.get('difficulty', 'medium')
        
        # Validate inputs
        if len(topic) > 100:
            topic = topic[:100]
        
        prompt = f"""Create 20 comprehensive flashcards for the ASIS CPP exam about: {topic}.
Difficulty level: {difficulty}

Create a diverse set covering:
- Key terminology and definitions (30%)
- Important concepts and principles (30%) 
- Practical scenarios and applications (25%)
- Best practices and procedures (15%)

Each card should be unique and valuable for exam preparation.

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
            import re
            json_match = re.search(r'\{.*\}', ai_response, re.DOTALL)
            if json_match:
                flashcard_data = json.loads(json_match.group())
                if not flashcard_data.get('cards'):
                    raise ValueError("No cards in response")
            else:
                raise ValueError("No JSON found")
        except Exception as e:
            print(f"Flashcard generation error: {e}")
            # Enhanced fallback with topic-specific content
            fallback_cards = generate_fallback_flashcards(topic, difficulty)
            flashcard_data = {
                "topic": topic,
                "difficulty": difficulty,
                "total_cards": len(fallback_cards),
                "cards": fallback_cards
            }

        log_activity(session['user_id'], 'flashcards_viewed', 
                     f'Topic: {topic}, Difficulty: {difficulty}, Cards: {len(flashcard_data.get("cards", []))}')
        
        return render_template('flashcards.html', 
                               flashcard_data=flashcard_data, 
                               cpp_domains=CPP_DOMAINS)
                               
    except Exception as e:
        print(f"Flashcards error: {e}")
        flash('Error loading flashcards. Please try again.', 'danger')
        return redirect(url_for('dashboard'))

def generate_fallback_flashcards(topic, difficulty):
    """Generate fallback flashcards when AI generation fails"""
    base_cards = [
        {"front": "Risk Assessment", "back": "Systematic process to identify, analyze, and evaluate potential threats and vulnerabilities to determine appropriate safeguards.", "category": "definitions"},
        {"front": "CPTED", "back": "Crime Prevention Through Environmental Design - uses physical environment design to reduce crime opportunities through natural surveillance, access control, and territoriality.", "category": "concepts"},
        {"front": "Defense in Depth", "back": "Security strategy using multiple layers of controls so if one fails, others continue to provide protection.", "category": "concepts"},
        {"front": "Least Privilege", "back": "Security principle of granting users only the minimum access rights needed to perform their job functions.", "category": "definitions"},
        {"front": "Business Continuity", "back": "Organization's ability to maintain essential functions during and after a disaster or disruption.", "category": "definitions"},
        {"front": "Chain of Custody", "back": "Documentation process that tracks evidence from collection through analysis to court presentation, maintaining its integrity.", "category": "procedures"},
        {"front": "Vulnerability", "back": "Weakness in a system, process, or control that could be exploited by a threat.", "category": "definitions"},
        {"front": "Threat", "back": "Potential danger or adverse event that could harm an organization's assets or operations.", "category": "definitions"},
        {"front": "Access Control", "back": "Security measures that regulate who can view or use resources in a computing environment.", "category": "concepts"},
        {"front": "Incident Response", "back": "Structured approach to addressing security breaches including preparation, detection, containment, eradication, recovery, and lessons learned.", "category": "procedures"},
        {"front": "Physical Security", "back": "Protection of personnel, hardware, software, networks and data from physical circumstances that could cause losses or damage.", "category": "definitions"},
        {"front": "Information Security", "back": "Practice of protecting information by mitigating information risks through confidentiality, integrity, and availability controls.", "category": "definitions"},
        {"front": "Security Governance", "back": "Framework for managing and directing security activities to align with business objectives.", "category": "concepts"},
        {"front": "Due Diligence", "back": "Investigation and assessment process undertaken before making security decisions or entering agreements.", "category": "procedures"},
        {"front": "Insider Threat", "back": "Security risk posed by people who have authorized access to an organization's assets.", "category": "concepts"},
        {"front": "Perimeter Security", "back": "Physical barriers and controls at the boundary of protected areas to prevent unauthorized access.", "category": "concepts"},
        {"front": "Security Awareness", "back": "Education program to keep personnel informed about security policies, procedures, and current threats.", "category": "procedures"},
        {"front": "Crisis Management", "back": "Process of preparing for, responding to, and recovering from emergency situations that threaten an organization.", "category": "concepts"},
        {"front": "Background Investigation", "back": "Process of verifying an individual's personal and professional history before granting access or employment.", "category": "procedures"},
        {"front": "Security Metrics", "back": "Measurable indicators used to assess the effectiveness and efficiency of security controls and programs.", "category": "definitions"}
    ]
    
    return base_cards

@app.route('/performance-analysis')
@login_required
def performance_analysis():
    """Detailed performance analysis by domain"""
    try:
        user_id = session['user_id']
        
        # Calculate performance by domain
        domain_analysis = {}
        for domain_key, domain_info in CPP_DOMAINS.items():
            progress = UserProgress.query.filter_by(user_id=user_id, domain=domain_key).first()
            if not progress:
                # Create new progress record
                progress = UserProgress(user_id=user_id, domain=domain_key)
                db.session.add(progress)
            
            domain_analysis[domain_key] = {
                'name': domain_info['name'],
                'topics': domain_info['topics'],
                'mastery_level': progress.mastery_level,
                'average_score': round(progress.average_score, 1),
                'question_count': progress.question_count,
                'consecutive_good_scores': progress.consecutive_good_scores,
                'recommendation': get_domain_recommendation(progress),
                'last_updated': progress.last_updated.strftime('%Y-%m-%d') if progress.last_updated else 'Never'
            }
        
        db.session.commit()
        
        # Generate overall recommendations
        needs_practice = [d for d in domain_analysis.values() if d['mastery_level'] == 'needs_practice']
        good_progress = [d for d in domain_analysis.values() if d['mastery_level'] == 'good']
        mastered = [d for d in domain_analysis.values() if d['mastery_level'] == 'mastered']
        
        overall_recommendations = []
        
        if needs_practice:
            overall_recommendations.append({
                'priority': 'high',
                'title': 'Focus Areas (High Priority)',
                'domains': [d['name'] for d in needs_practice[:3]],
                'action': 'Spend 60% of study time on these domains',
                'color': 'danger'
            })
        
        if good_progress:
            overall_recommendations.append({
                'priority': 'medium',
                'title': 'Reinforcement Areas',
                'domains': [d['name'] for d in good_progress],
                'action': 'Take advanced quizzes and practice scenarios',
                'color': 'warning'
            })
        
        if mastered:
            overall_recommendations.append({
                'priority': 'low',
                'title': 'Mastered Areas',
                'domains': [d['name'] for d in mastered],
                'action': 'Light review to maintain knowledge',
                'color': 'success'
            })
        
        # Calculate readiness score
        total_domains = len(CPP_DOMAINS)
        readiness_score = (len(mastered) * 100 + len(good_progress) * 70) / total_domains
        
        return render_template('performance_analysis.html',
                             domain_analysis=domain_analysis,
                             recommendations=overall_recommendations,
                             readiness_score=round(readiness_score, 1),
                             cpp_domains=CPP_DOMAINS)
                             
    except Exception as e:
        print(f"Performance analysis error: {e}")
        flash('Error loading performance analysis. Please try again.', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/progress')
@login_required
def progress():
    try:
        user = User.query.get(session['user_id'])
        if not user:
            return redirect(url_for('login'))
            
        # Get activities with error handling
        try:
            activities = ActivityLog.query.filter_by(user_id=user.id).order_by(
                ActivityLog.timestamp.desc()
            ).limit(50).all()
        except Exception as e:
            print(f"Error fetching activities: {e}")
            activities = []

        # Get quiz results with error handling
        try:
            quiz_results = QuizResult.query.filter_by(user_id=user.id).order_by(
                QuizResult.completed_at.desc()
            ).all()
        except Exception as e:
            print(f"Error fetching quiz results: {e}")
            quiz_results = []

        # Calculate statistics
        total_sessions = len([a for a in activities if 'study' in a.activity.lower()])
        total_quizzes = len(quiz_results)
        avg_score = sum(q.score for q in quiz_results) / len(quiz_results) if quiz_results else 0
        
        # Get study sessions
        try:
            study_sessions = StudySession.query.filter_by(user_id=user.id).all()
            total_study_time = sum(s.duration or 0 for s in study_sessions)
        except Exception as e:
            print(f"Error fetching study sessions: {e}")
            total_study_time = 0

        # Calculate trends
        score_trend = 'stable'
        if len(quiz_results) >= 5:
            recent_scores = [q.score for q in quiz_results[:5]]
            older_scores = [q.score for q in quiz_results[5:10]] if len(quiz_results) >= 10 else []
            
            if older_scores:
                recent_avg = sum(recent_scores) / len(recent_scores)
                older_avg = sum(older_scores) / len(older_scores)
                if recent_avg > older_avg + 5:
                    score_trend = 'improving'
                elif recent_avg < older_avg - 5:
                    score_trend = 'declining'

        return render_template('progress.html',
                               user=user,
                               activities=activities,
                               quiz_results=quiz_results,
                               total_sessions=total_sessions,
                               total_quizzes=total_quizzes,
                               avg_score=round(avg_score, 1),
                               total_study_time=total_study_time,
                               score_trend=score_trend)
                               
    except Exception as e:
        print(f"Progress page error: {e}")
        flash('Error loading progress page. Please try again.', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/subscribe')
@login_required
def subscribe():
    try:
        user = User.query.get(session['user_id'])
        if not user:
            return redirect(url_for('login'))
            
        return render_template('subscribe.html', 
                               user=user, 
                               stripe_key=STRIPE_PUBLISHABLE_KEY)
                               
    except Exception as e:
        print(f"Subscribe page error: {e}")
        flash('Error loading subscription page. Please try again.', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/create-checkout-session', methods=['POST'])
@login_required
def create_checkout_session():
    try:
        user = User.query.get(session['user_id'])
        if not user:
            return redirect(url_for('login'))
            
        plan_type = request.form.get('plan_type')
        discount_code = request.form.get('discount_code', '').strip().upper()

        # Define available plans
        plans = {
            '3month': {
                'amount': 8997, 
                'name': 'CPP Test Prep - 3 Month Plan', 
                'interval': 'month', 
                'interval_count': 3
            },
            '6month': {
                'amount': 9900, 
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
        
        # Apply discount codes
        if discount_code == 'LAUNCH50':
            final_amount = int(selected_plan['amount'] * 0.5)
            discount_applied = True
        elif discount_code == 'STUDENT20':
            final_amount = int(selected_plan['amount'] * 0.8)
            discount_applied = True

        # Create Stripe price
        price = stripe.Price.create(
            unit_amount=final_amount,
            currency='usd',
            recurring={
                'interval': selected_plan['interval'], 
                'interval_count': selected_plan['interval_count']
            },
            product_data={
                'name': selected_plan['name'] + (
                    f' ({discount_code} DISCOUNT)' if discount_applied else ''
                ),
                'description': 'AI tutor, practice quizzes, flashcards, progress tracking, and exam preparation'
            }
        )

        # Create checkout session
        checkout_session = stripe.checkout.Session.create(
            customer=user.stripe_customer_id,
            payment_method_types=['card'],
            line_items=[{'price': price.id, 'quantity': 1}],
            mode='subscription',
            success_url=url_for('subscription_success', _external=True) + 
                       '?session_id={CHECKOUT_SESSION_ID}&plan=' + plan_type,
            cancel_url=url_for('subscribe', _external=True),
            metadata={
                'user_id': user.id,
                'plan_type': plan_type,
                'discount_code': discount_code if discount_applied else '',
                'original_amount': selected_plan['amount'],
                'final_amount': final_amount
            },
            allow_promotion_codes=True
        )

        log_activity(user.id, 'subscription_attempt', 
                     f'Plan: {plan_type}, Discount: {discount_code}, Amount: ${final_amount/100:.2f}')
        
        return redirect(checkout_session.url, code=303)
        
    except stripe.error.StripeError as e:
        print(f"Stripe checkout error: {e}")
        flash('Payment processing error. Please try again or contact support.', 'danger')
        return redirect(url_for('subscribe'))
    except Exception as e:
        print(f"Checkout session error: {e}")
        flash('Error creating payment session. Please try again.', 'danger')
        return redirect(url_for('subscribe'))

@app.route('/subscription-success')
@login_required
def subscription_success():
    session_id = request.args.get('session_id')
    plan_type = request.args.get('plan', '3month')

    if session_id:
        try:
            checkout_session = stripe.checkout.Session.retrieve(session_id)
            if checkout_session.payment_status == 'paid':
                user = User.query.get(session['user_id'])
                user.subscription_status = 'active'
                
                # Set subscription end date based on plan
                days = 180 if plan_type == '6month' else 90
                user.subscription_end_date = datetime.utcnow() + timedelta(days=days)
                user.subscription_plan = plan_type
                user.stripe_subscription_id = checkout_session.subscription
                
                # Save discount code if used
                metadata = checkout_session.metadata or {}
                if metadata.get('discount_code'):
                    user.discount_code_used = metadata['discount_code']
                
                db.session.commit()

                log_activity(user.id, 'subscription_activated', 
                           f'Plan: {plan_type}, Amount: ${metadata.get("final_amount", "0")}')
                
                flash(f'🎉 Subscription activated! Welcome to CPP Test Prep ({plan_type.upper()})!', 'success')
            else:
                flash('Payment verification failed. Please contact support.', 'danger')
                
        except stripe.error.StripeError as e:
            print(f"Stripe verification error: {e}")
            flash('Payment verification error. Please contact support.', 'danger')
        except Exception as e:
            print(f"Subscription verification error: {e}")
            flash('Subscription verification error. Please contact support.', 'danger')

    return redirect(url_for('dashboard'))

@app.post("/webhook")
def stripe_webhook():
    """Handle Stripe webhook events"""
    if not STRIPE_WEBHOOK_SECRET:
        print("Webhook secret not configured")
        return 'Webhook not configured', 200

    payload = request.get_data(as_text=True)
    sig_header = request.headers.get('Stripe-Signature')

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
    except ValueError as e:
        print(f"Invalid payload: {e}")
        return 'Invalid payload', 400
    except stripe.error.SignatureVerificationError as e:
        print(f"Invalid signature: {e}")
        return 'Invalid signature', 400

    # Handle the event
    event_type = event.get('type')
    data_object = event.get('data', {}).get('object', {})

    customer_id = data_object.get('customer')
    subscription_id = data_object.get('subscription') or data_object.get('id')

    print(f"Processing webhook: {event_type} for customer {customer_id}")

    try:
        if event_type == 'invoice.payment_succeeded':
            set_user_subscription_by_customer(customer_id, 'active', subscription_id)
        elif event_type == 'invoice.payment_failed':
            set_user_subscription_by_customer(customer_id, 'past_due', subscription_id)
        elif event_type in ('customer.subscription.created', 'customer.subscription.updated'):
            status = data_object.get('status', 'active')
            if status in ('active', 'trialing'):
                normalized_status = 'active'
            elif status == 'past_due':
                normalized_status = 'past_due'
            else:
                normalized_status = 'expired'
            set_user_subscription_by_customer(customer_id, normalized_status, subscription_id)
        elif event_type == 'customer.subscription.deleted':
            set_user_subscription_by_customer(customer_id, 'expired', subscription_id)
            
    except Exception as e:
        print(f"Error processing webhook {event_type}: {e}")
        return 'Webhook processing error', 500

    return 'Success', 200

@app.route('/end-study-session', methods=['POST'])
@login_required
def end_study_session():
    """End study session and track time"""
    try:
        if 'study_start_time' in session:
            start_time = datetime.fromtimestamp(session['study_start_time'])
            duration = int((datetime.utcnow() - start_time).total_seconds() / 60)

            # Save study session
            study_session = StudySession(
                user_id=session['user_id'],
                duration=duration,
                session_type='chat',
                started_at=start_time,
                ended_at=datetime.utcnow()
            )
            db.session.add(study_session)
            
            # Update user total study time
            user = User.query.get(session['user_id'])
            if user:
                user.study_time = (user.study_time or 0) + duration
            
            db.session.commit()

            del session['study_start_time']
            log_activity(session['user_id'], 'study_session_completed', f'Duration: {duration} minutes')
            
            return jsonify({'success': True, 'duration': duration})
        else:
            return jsonify({'success': False, 'error': 'No active session'})
            
    except Exception as e:
        print(f"Error ending study session: {e}")
        return jsonify({'success': False, 'error': 'Session end error'})

@app.route('/clear-chat', methods=['POST'])
@login_required
def clear_chat():
    """Clear chat history for user"""
    try:
        user_id = session['user_id']
        chat_history = ChatHistory.query.filter_by(user_id=user_id).first()
        
        if chat_history:
            chat_history.messages = '[]'
            chat_history.updated_at = datetime.utcnow()
            db.session.commit()
            
        log_activity(user_id, 'chat_cleared', 'User cleared chat history')
        return jsonify({'success': True})
        
    except Exception as e:
        print(f"Error clearing chat: {e}")
        return jsonify({'success': False, 'error': 'Failed to clear chat'})

# Static pages
@app.route('/terms')
def terms():
    return render_template('terms.html')

@app.route('/privacy')
def privacy():
    return render_template('privacy.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

# Diagnostic endpoints
@app.get("/diag/openai")
def diag_openai():
    """Diagnostic endpoint for OpenAI API"""
    has_key = bool(os.environ.get("OPENAI_API_KEY"))
    model = os.environ.get("OPENAI_CHAT_MODEL", OPENAI_CHAT_MODEL)
    
    try:
        headers = {
            'Authorization': f'Bearer {os.environ.get("OPENAI_API_KEY","")}',
            'Content-Type': 'application/json'
        }
        data = {
            'model': model,
            'messages': [{"role":"user","content":"Say 'pong' if you can hear me."}],
            'max_tokens': 10,
            'temperature': 0
        }
        
        response = requests.post(
            f'{OPENAI_API_BASE}/chat/completions', 
            headers=headers, 
            json=data, 
            timeout=20
        )
        
        success = (response.status_code == 200)
        
        return jsonify({
            "has_key": has_key,
            "model": model,
            "status_code": response.status_code,
            "success": success,
            "response_preview": response.text[:300],
            "timestamp": datetime.utcnow().isoformat()
        }), (200 if success else 500)
        
    except Exception as e:
        return jsonify({
            "has_key": has_key, 
            "model": model, 
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }), 500

@app.get("/diag/database")
def diag_database():
    """Diagnostic endpoint for database connectivity"""
    try:
        # Test basic connection
        db.session.execute(db.text('SELECT 1'))
        
        # Test table access
        user_count = User.query.count()
        quiz_count = QuizResult.query.count()
        
        return jsonify({
            "status": "healthy",
            "user_count": user_count,
            "quiz_count": quiz_count,
            "timestamp": datetime.utcnow().isoformat()
        }), 200
        
    except Exception as e:
        return jsonify({
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }), 500

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500

@app.errorhandler(403)
def forbidden_error(error):
    return render_template('403.html'), 403

# Context processors for templates
@app.context_processor
def inject_now():
    return {'now': datetime.utcnow()}

@app.context_processor
def inject_quiz_types():
    return {'quiz_types': QUIZ_TYPES, 'cpp_domains': CPP_DOMAINS}

# Application factory pattern support
def create_app(config_name='default'):
    """Application factory for different configurations"""
    return app

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    
    print(f"Starting CPP Test Prep Application on port {port}")
    print(f"Debug mode: {debug}")
    print(f"Database URL configured: {bool(app.config.get('SQLALCHEMY_DATABASE_URI'))}")
    print(f"OpenAI API configured: {bool(OPENAI_API_KEY)}")
    print(f"Stripe configured: {bool(stripe.api_key)}")
    
    app.run(host='0.0.0.0', port=port, debug=debug)
