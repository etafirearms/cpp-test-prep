# app.py
from flask import Flask, request, redirect, url_for, flash, session, jsonify, Response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from string import Template
from functools import wraps
import json
import os
import requests
import stripe
import time
import hashlib
import random
import re
import math

from sqlalchemy import text, inspect, func

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
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_recycle': 300,
    'connect_args': {
        'sslmode': 'require',
        'connect_timeout': 10,
    }
}
FRONTEND_VERSION = os.environ.get('FRONTEND_VERSION', 'v-freeze-2025-08-16')
ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', '').lower().strip()

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
# Quiz Types & Domains
# -----------------------------------------------------------------------------
QUIZ_TYPES = {
    'practice': {'name': 'Practice Quiz', 'description': 'General practice questions', 'questions': 10},
    'mock-exam': {'name': 'Mock Exam', 'description': 'Full exam simulation', 'questions': 50},
    'domain-specific': {'name': 'Domain-Specific Quiz', 'description': 'Focus on specific domains', 'questions': 15},
    'quick-review': {'name': 'Quick Review', 'description': 'Short 5-question review', 'questions': 5},
    'difficult': {'name': 'Advanced Challenge', 'description': 'Challenging questions', 'questions': 20}
}

CPP_DOMAINS = {
    'security-principles': {'name': 'Security Principles & Practices', 'topics': ['Risk Management', 'Security Governance']},
    'business-principles': {'name': 'Business Principles & Practices', 'topics': ['Budgeting', 'Contracts']},
    'investigations': {'name': 'Investigations', 'topics': ['Investigation Planning', 'Evidence Collection']},
    'personnel-security': {'name': 'Personnel Security', 'topics': ['Background Screening', 'Insider Threat']},
    'physical-security': {'name': 'Physical Security', 'topics': ['CPTED', 'Access Control']},
    'information-security': {'name': 'Information Security', 'topics': ['Data Protection', 'Cybersecurity']},
    'crisis-management': {'name': 'Crisis Management', 'topics': ['Business Continuity', 'Emergency Response']},
}

DOMAIN_KEYS = list(CPP_DOMAINS.keys())

# -----------------------------------------------------------------------------
# Database Models
# -----------------------------------------------------------------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
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
    terms_accepted = db.Column(db.Boolean, default=False)
    terms_accepted_date = db.Column(db.DateTime)
    is_admin = db.Column(db.Boolean, default=False)

class ChatHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    messages = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)

class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    activity = db.Column(db.String(100), nullable=False)
    details = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)

class QuizResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    quiz_type = db.Column(db.String(50), nullable=False)
    domain = db.Column(db.String(50))
    questions = db.Column(db.Text, nullable=False)
    answers = db.Column(db.Text, nullable=False)
    score = db.Column(db.Float, nullable=False)
    total_questions = db.Column(db.Integer, nullable=False)
    time_taken = db.Column(db.Integer)
    completed_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

class StudySession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    topic = db.Column(db.String(100))
    duration = db.Column(db.Integer)
    session_type = db.Column(db.String(50))
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    ended_at = db.Column(db.DateTime)

class UserProgress(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    domain = db.Column(db.String(50), nullable=False, index=True)
    topic = db.Column(db.String(100), nullable=True, index=True)
    mastery_level = db.Column(db.String(20), default='needs_practice')
    average_score = db.Column(db.Float, default=0.0)
    question_count = db.Column(db.Integer, default=0)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow)
    consecutive_good_scores = db.Column(db.Integer, default=0)
    __table_args__ = (db.UniqueConstraint('user_id', 'domain', 'topic', name='uq_userprogress_user_domain_topic'),)

class QuestionEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    question_hash = db.Column(db.String(64), nullable=False, index=True)
    domain = db.Column(db.String(50), nullable=True, index=True)
    topic = db.Column(db.String(100), nullable=True, index=True)
    source = db.Column(db.String(20), nullable=False)  # quiz/mock/flashcard/tutor
    is_correct = db.Column(db.Boolean, nullable=True)
    response_time_s = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    __table_args__ = (db.Index('ix_question_event_user_created', 'user_id', 'created_at'),)

class QuestionBank(db.Model):
    __tablename__ = 'question_bank'
    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(50), nullable=False, index=True)
    difficulty = db.Column(db.String(20), default='medium', index=True)
    question = db.Column(db.Text, nullable=False)
    options_json = db.Column(db.Text, nullable=False)  # JSON dict of options
    correct = db.Column(db.String(5), nullable=False)  # 'A'/'B'/...
    explanation = db.Column(db.Text, default='')
    source_name = db.Column(db.String(120), default='')
    source_url = db.Column(db.String(300), default='')
    is_verified = db.Column(db.Boolean, default=True, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

# -----------------------------------------------------------------------------
# Database Initialization / Migrations (safe, idempotent)
# -----------------------------------------------------------------------------
def add_column_if_missing(table: str, coldef_sql: str):
    """coldef_sql example: 'ADD COLUMN domain VARCHAR(50)'"""
    try:
        db.session.execute(text(f'ALTER TABLE {table} {coldef_sql}'))
        db.session.commit()
    except Exception:
        db.session.rollback()

def init_database():
    try:
        db.create_all()
        insp = inspect(db.engine)

        # QuizResult ensure domain & time_taken
        if 'quiz_result' in insp.get_table_names():
            cols = {c['name'] for c in insp.get_columns('quiz_result')}
            if 'domain' not in cols:
                add_column_if_missing('quiz_result', 'ADD COLUMN domain VARCHAR(50)')
            if 'time_taken' not in cols:
                add_column_if_missing('quiz_result', 'ADD COLUMN time_taken INTEGER')

        # User ensure terms + is_admin
        if 'user' in insp.get_table_names():
            cols = {c['name'] for c in insp.get_columns('user')}
            if 'terms_accepted' not in cols:
                add_column_if_missing('"user"', 'ADD COLUMN terms_accepted BOOLEAN DEFAULT FALSE')
            if 'terms_accepted_date' not in cols:
                add_column_if_missing('"user"', 'ADD COLUMN terms_accepted_date TIMESTAMP')
            if 'is_admin' not in cols:
                add_column_if_missing('"user"', 'ADD COLUMN is_admin BOOLEAN DEFAULT FALSE')

        # QuestionBank table and columns
        if 'question_bank' not in insp.get_table_names():
            db.create_all()
        else:
            cols = {c['name'] for c in insp.get_columns('question_bank')}
            needed = {
                'domain': 'ADD COLUMN domain VARCHAR(50)',
                'difficulty': 'ADD COLUMN difficulty VARCHAR(20)',
                'question': 'ADD COLUMN question TEXT',
                'options_json': 'ADD COLUMN options_json TEXT',
                'correct': 'ADD COLUMN correct VARCHAR(5)',
                'explanation': 'ADD COLUMN explanation TEXT',
                'source_name': 'ADD COLUMN source_name VARCHAR(120)',
                'source_url': 'ADD COLUMN source_url VARCHAR(300)',
                'is_verified': 'ADD COLUMN is_verified BOOLEAN DEFAULT TRUE',
                'created_at': 'ADD COLUMN created_at TIMESTAMP',
            }
            for col, sqlfrag in needed.items():
                if col not in cols:
                    add_column_if_missing('question_bank', sqlfrag)

        # Make configured admin an admin (if exists)
        try:
            if ADMIN_EMAIL:
                admin_user = User.query.filter(func.lower(User.email) == ADMIN_EMAIL).first()
                if admin_user and not admin_user.is_admin:
                    admin_user.is_admin = True
                    db.session.commit()
        except Exception:
            db.session.rollback()

        print("Database initialized successfully")
    except Exception as e:
        print(f"Database initialization error: {e}")

with app.app_context():
    init_database()

# -----------------------------------------------------------------------------
# Helpers & Decorators
# -----------------------------------------------------------------------------
def login_required(f):
    @wraps(f)
    def inner(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this feature.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return inner

def subscription_required(f):
    @wraps(f)
    def inner(*args, **kwargs):
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
    return inner

def admin_required(f):
    @wraps(f)
    def inner(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        u = User.query.get(session['user_id'])
        if not u or not u.is_admin:
            flash('Admin access required.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return inner

def log_activity(user_id, activity, details=None):
    try:
        db.session.add(ActivityLog(user_id=user_id, activity=activity, details=details))
        db.session.commit()
    except Exception as e:
        print(f"Activity logging error: {e}")
        db.session.rollback()

def _hash_question_payload(question_obj: dict) -> str:
    q_text = (question_obj or {}).get('question', '') or ''
    opts = (question_obj or {}).get('options', {}) or {}
    parts = [q_text.strip()]
    for key in sorted(opts.keys()):
        parts.append(f"{key}:{str(opts.get(key, '')).strip()}")
    raw = "||".join(parts)
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()

def record_question_event(user_id: int, question_obj: dict, domain: str = None, topic: str = None,
                          is_correct: bool = None, response_time_s: int = None, source: str = 'quiz') -> None:
    try:
        qhash = _hash_question_payload(question_obj)
        evt = QuestionEvent(
            user_id=user_id, question_hash=qhash, domain=domain, topic=topic,
            source=source, is_correct=is_correct, response_time_s=response_time_s,
        )
        db.session.add(evt)
        db.session.commit()
    except Exception as e:
        print(f"record_question_event error: {e}")
        db.session.rollback()

def _mastery_from_stats(avg: float, streak: int) -> str:
    if (avg or 0) >= 90 and (streak or 0) >= 3:
        return 'mastered'
    if (avg or 0) >= 75 and (streak or 0) >= 2:
        return 'good'
    return 'needs_practice'

def update_user_progress_on_answer(user_id: int, domain: str, topic: str, is_correct: bool) -> None:
    try:
        if not domain:
            return
        row = UserProgress.query.filter_by(user_id=user_id, domain=domain, topic=topic).first()
        if not row:
            row = UserProgress(
                user_id=user_id, domain=domain, topic=topic, average_score=0.0,
                question_count=0, consecutive_good_scores=0, mastery_level='needs_practice'
            )
            db.session.add(row)

        earned = 100.0 if bool(is_correct) else 0.0
        old_count = row.question_count or 0
        new_count = old_count + 1
        row.average_score = ((row.average_score or 0.0) * old_count + earned) / new_count
        row.question_count = new_count
        row.consecutive_good_scores = (row.consecutive_good_scores or 0) + 1 if earned >= 75.0 else 0
        row.mastery_level = _mastery_from_stats(row.average_score, row.consecutive_good_scores)
        row.last_updated = datetime.utcnow()
        db.session.commit()
    except Exception as e:
        print(f"update_user_progress_on_answer error: {e}")
        db.session.rollback()

def get_seen_hashes(user_id: int, domain: str = None, topic: str = None, window_days: int = 30) -> set:
    try:
        cutoff = datetime.utcnow() - timedelta(days=window_days)
        q = QuestionEvent.query.filter(QuestionEvent.user_id == user_id, QuestionEvent.created_at >= cutoff)
        if domain:
            q = q.filter(QuestionEvent.domain == domain)
        if topic:
            q = q.filter(QuestionEvent.topic == topic)
        return {row.question_hash for row in q.with_entities(QuestionEvent.question_hash).all()}
    except Exception as e:
        print(f"get_seen_hashes error: {e}")
        return set()

# Clean prefixes like "A) " / "B. " at start of explanation/answer
PREFIX_RE = re.compile(r'^\s*[A-Za-z][\)\.\:]\s+')

def strip_answer_letter_prefix(text_in: str) -> str:
    if not text_in:
        return text_in
    return PREFIX_RE.sub('', text_in).strip()

# -----------------------------------------------------------------------------
# AI Chat
# -----------------------------------------------------------------------------
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
                "Focus on the seven CPP domains: Security Principles & Practices, Business Principles & Practices, "
                "Investigations, Personnel Security, Physical Security, Information Security, and Crisis Management. "
                "Provide clear explanations, practical examples, structured lists and short paragraphs, and do not claim affiliation with ASIS."
            )
        }
        if not messages or messages[0].get('role') != 'system':
            messages.insert(0, system_message)

        headers = {'Authorization': f'Bearer {OPENAI_API_KEY}', 'Content-Type': 'application/json'}
        data = {'model': OPENAI_CHAT_MODEL, 'messages': messages, 'max_tokens': 1200, 'temperature': 0.6}
        last_api_call = datetime.utcnow()
        resp = requests.post(f'{OPENAI_API_BASE}/chat/completions', headers=headers, json=data, timeout=45)
        if resp.status_code == 200:
            payload = resp.json()
            return payload['choices'][0]['message']['content']
        elif resp.status_code in (401, 403):
            return "I’m having trouble authenticating to my knowledge base right now. Please try again."
        elif resp.status_code == 429:
            return "I’m receiving a lot of requests at the moment. Please try again shortly."
        elif resp.status_code >= 500:
            return "The AI service is experiencing issues. Please try again in a bit."
        else:
            print(f"[OpenAI] Unexpected status: {resp.status_code} body={resp.text[:300]}")
            return "I hit an unexpected issue. Please rephrase and try again."
    except Exception as e:
        print(f"AI chat error: {e}")
        return "I encountered a technical issue. Please try again."

# -----------------------------------------------------------------------------
# Fallback Question Bank (used if DB is empty)
# -----------------------------------------------------------------------------
FALLBACK_QUESTIONS = [
    # Keep these varied across domains
    {
        "question": "What is the primary purpose of a security risk assessment?",
        "options": {"A": "Identify all threats", "B": "Determine cost-effective mitigation", "C": "Eliminate all risks", "D": "Satisfy compliance"},
        "correct": "B",
        "explanation": "Risk assessments help prioritize and select cost-effective mitigation strategies.",
        "domain": "security-principles",
        "difficulty": "medium"
    },
    {
        "question": "In CPTED, natural surveillance primarily accomplishes what?",
        "options": {"A": "Reduces guard costs", "B": "Increases observation likelihood", "C": "Eliminates cameras", "D": "Provides legal protection"},
        "correct": "B",
        "explanation": "Natural surveillance increases the chance that inappropriate behavior is observed.",
        "domain": "physical-security",
        "difficulty": "easy"
    },
    {
        "question": "Which concept applies multiple layers so if one fails others still protect?",
        "options": {"A": "Security by Obscurity", "B": "Defense in Depth", "C": "Zero Trust", "D": "Least Privilege"},
        "correct": "B",
        "explanation": "Defense in Depth uses layered controls to avoid single-point failure.",
        "domain": "security-principles",
        "difficulty": "easy"
    },
    {
        "question": "In incident response, what is usually the FIRST priority?",
        "options": {"A": "Notify law enforcement", "B": "Contain the incident", "C": "Eradicate malware", "D": "Perform lessons learned"},
        "correct": "B",
        "explanation": "Containment reduces ongoing impact before eradication and recovery.",
        "domain": "information-security",
        "difficulty": "medium"
    },
    {
        "question": "Background investigations primarily support which objective?",
        "options": {"A": "Regulatory compliance only", "B": "Improving marketing outcomes", "C": "Personnel security risk reduction", "D": "Disaster response coordination"},
        "correct": "C",
        "explanation": "They reduce insider threat and hiring risk.",
        "domain": "personnel-security",
        "difficulty": "easy"
    },
    {
        "question": "What is the best description of Business Continuity Planning (BCP)?",
        "options": {"A": "A plan to evacuate the building", "B": "Procedures to keep key operations running during disruptions", "C": "A marketing strategy", "D": "An insurance policy"},
        "correct": "B",
        "explanation": "BCP maintains critical functions during and after an incident.",
        "domain": "crisis-management",
        "difficulty": "medium"
    },
    {
        "question": "Which is the MOST effective deterrent for external intrusion at a data center perimeter?",
        "options": {"A": "Unlit fences", "B": "CCTV without recording", "C": "Layered fencing, lighting, and access control", "D": "Warning signs only"},
        "correct": "C",
        "explanation": "Layered controls with lighting and access control are more effective than single measures.",
        "domain": "physical-security",
        "difficulty": "medium"
    },
    {
        "question": "Chain of custody documentation ensures what in an investigation?",
        "options": {"A": "Evidence was expensive", "B": "Evidence was fun", "C": "Evidence integrity from collection through presentation", "D": "Evidence was collected at night"},
        "correct": "C",
        "explanation": "It records how evidence was handled to preserve admissibility.",
        "domain": "investigations",
        "difficulty": "medium"
    },
    {
        "question": "Which is the PRIMARY goal of access control?",
        "options": {"A": "Enhance aesthetics", "B": "Restrict entry to authorized individuals", "C": "Promote employee morale", "D": "Reduce cleaning costs"},
        "correct": "B",
        "explanation": "Access control enforces authorization at entry points.",
        "domain": "physical-security",
        "difficulty": "easy"
    },
    {
        "question": "What BEST describes least privilege?",
        "options": {"A": "Users get the most privileges", "B": "Users get no privileges", "C": "Users get only privileges required to perform tasks", "D": "Privileges are randomly assigned"},
        "correct": "C",
        "explanation": "Least privilege restricts access to the minimum necessary.",
        "domain": "information-security",
        "difficulty": "easy"
    },
]

# -----------------------------------------------------------------------------
# Question selection helpers
# -----------------------------------------------------------------------------
def question_bank_query(domain: str = None, difficulty: str = None, limit: int = 10):
    q = QuestionBank.query.filter(QuestionBank.is_verified.is_(True))
    if domain and domain != 'random':
        q = q.filter(QuestionBank.domain == domain)
    if difficulty:
        q = q.filter(QuestionBank.difficulty == difficulty)
    # Order by random
    q = q.order_by(func.random()).limit(limit)
    return q.all()

def select_questions(quiz_type: str, domain: str, difficulty: str, num_questions: int):
    selected = []

    # Try DB first
    try:
        rows = question_bank_query(domain=domain, difficulty=difficulty, limit=num_questions)
        for r in rows:
            try:
                opts = json.loads(r.options_json)
            except Exception:
                opts = {}
            selected.append({
                "question": r.question,
                "options": opts,
                "correct": r.correct,
                "explanation": r.explanation or "",
                "domain": r.domain
            })
    except Exception as e:
        print(f"DB question fetch error: {e}")

    # Fill with fallback if needed
    if len(selected) < num_questions:
        fb_pool = [q for q in FALLBACK_QUESTIONS if (domain in (None, 'random') or q['domain'] == domain)]
        if difficulty:
            # optional filtering; fallback small so keep soft
            pass
        random.shuffle(fb_pool)
        for q in fb_pool:
            if len(selected) >= num_questions:
                break
            selected.append({
                "question": q["question"],
                "options": q["options"].copy(),
                "correct": q["correct"],
                "explanation": q["explanation"],
                "domain": q["domain"]
            })

    random.shuffle(selected)
    return selected[:num_questions]

def build_quiz_payload(quiz_type: str, domain: str, difficulty: str, num_questions: int):
    return {
        "title": f"CPP {quiz_type.title().replace('-', ' ')}",
        "quiz_type": quiz_type,
        "domain": domain or 'general',
        "difficulty": difficulty or 'medium',
        "questions": select_questions(quiz_type, domain, difficulty, num_questions)
    }

# -----------------------------------------------------------------------------
# HTML Base Template (use string.Template to avoid f-string brace issues)
# -----------------------------------------------------------------------------
def render_base_template(title, content_html, user=None, extra_head_css="", extra_scripts=""):
    disclaimer = """
    <div class="bg-light border-top mt-4 py-3">
        <div class="container">
            <div class="row"><div class="col-12">
                <div class="alert alert-info mb-0">
                    <strong>Important Notice:</strong> This service is NOT affiliated with, endorsed by, or approved by ASIS International.
                    CPP® is a registered certification mark of ASIS International, Inc. This platform is an independent study aid.
                </div>
            </div></div>
        </div>
    </div>
    """

    nav_html = ""
    if user:
        nav_html = (
            '<nav class="navbar navbar-expand-lg navbar-dark bg-primary">'
            '  <div class="container">'
            '    <a class="navbar-brand" href="/dashboard">CPP Test Prep</a>'
            '    <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarsExample" aria-controls="navbarsExample" aria-expanded="false" aria-label="Toggle navigation">'
            '      <span class="navbar-toggler-icon"></span>'
            '    </button>'
            '    <div class="collapse navbar-collapse" id="navbarsExample">'
            '      <ul class="navbar-nav ms-auto mb-2 mb-lg-0">'
            '        <li class="nav-item"><a class="nav-link" href="/dashboard">Dashboard</a></li>'
            '        <li class="nav-item"><a class="nav-link" href="/study">Tutor</a></li>'
            '        <li class="nav-item"><a class="nav-link" href="/flashcards">Flashcards</a></li>'
            '        <li class="nav-item"><a class="nav-link" href="/quiz-selector">Quizzes</a></li>'
            '        <li class="nav-item"><a class="nav-link" href="/mock-exam">Mock Exam</a></li>'
            '        <li class="nav-item"><a class="nav-link" href="/progress">Progress</a></li>'
            '        <li class="nav-item"><a class="nav-link" href="/subscribe">Subscribe</a></li>'
            '        <li class="nav-item"><a class="nav-link" href="/logout">Logout</a></li>'
            '      </ul>'
            '    </div>'
            '  </div>'
            '</nav>'
        )

    page = Template("""\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>$title - CPP Test Prep</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css?v=$v" rel="stylesheet">
  <style>
    /* Dashboard/progress helpers */
    .chip { display:inline-block; padding:8px 12px; border-radius:999px; background:#0d6efd; color:#fff; margin:4px; cursor:pointer; user-select:none; }
    .chip-outline { background:#fff; color:#0d6efd; border:1px solid #0d6efd; }
    .card-35 { max-width: 640px; aspect-ratio: 1.6; }
    /* Flashcard 3x5 feel */
    .flashcard { background:#fffef8; border:1px solid #e9e2c6; border-radius:16px; box-shadow: 0 8px 24px rgba(0,0,0,0.08); }
    .flashcard .front, .flashcard .back { font-size:1.25rem; line-height:1.5; color:#1b1f24; }
    .fc-instructions { font-size:0.95rem; color:#495057; }
    .assistant-msg { white-space:pre-wrap; }
    /* Progress gauge container */
    .gauge-wrap { width: 320px; max-width: 100%; margin: 0 auto; }
  </style>
  $extra_head_css
  <script>window.__APP_VERSION="$v";</script>
</head>
<body>
  $nav
  <div class="container mt-4">
    $content
  </div>
  $disclaimer
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js?v=$v"></script>
  $extra_scripts
</body>
</html>
""")
    return page.substitute(
        title=title,
        nav=nav_html,
        content=content_html,
        disclaimer=disclaimer,
        extra_head_css=extra_head_css,
        extra_scripts=extra_scripts,
        v=FRONTEND_VERSION
    )

# -----------------------------------------------------------------------------
# Routes: Health & Favicon
# -----------------------------------------------------------------------------
@app.route('/favicon.ico')
def favicon():
    return Response('', status=204, mimetype='image/x-icon')

@app.get("/healthz")
def healthz():
    try:
        db.session.execute(text('SELECT 1'))
        return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}, 200
    except Exception as e:
        return {"status": "unhealthy", "error": str(e)}, 500

@app.get("/diag/smoke")
def diag_smoke():
    # Render core pages (server-side string assembly only)
    try:
        _ = render_base_template("Smoke", "<div>OK</div>")
        return {"ok": True, "ts": datetime.utcnow().isoformat()}, 200
    except Exception as e:
        return {"ok": False, "error": str(e)}, 500

# -----------------------------------------------------------------------------
# Home & Auth
# -----------------------------------------------------------------------------
@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    content = """
    <div class="row justify-content-center">
      <div class="col-md-8">
        <div class="text-center mb-5">
          <h1 class="display-5">CPP Test Prep</h1>
          <p class="lead">AI-powered study platform for the Certified Protection Professional exam</p>
        </div>
        <div class="row g-3">
          <div class="col-md-6">
            <div class="card h-100">
              <div class="card-body">
                <h5 class="card-title">🎯 Smart Quizzes</h5>
                <p class="card-text">Randomized practice with per-question feedback.</p>
              </div>
            </div>
          </div>
          <div class="col-md-6">
            <div class="card h-100">
              <div class="card-body">
                <h5 class="card-title">🤖 AI Tutor</h5>
                <p class="card-text">Readable explanations, scenarios, and study guidance.</p>
              </div>
            </div>
          </div>
        </div>
        <div class="text-center mt-4">
          <a href="/register" class="btn btn-primary btn-lg me-3">Start Free Trial</a>
          <a href="/login" class="btn btn-outline-primary btn-lg">Login</a>
        </div>
      </div>
    </div>
    """
    return render_base_template("Home", content)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email', '').lower().strip()
        password = request.form.get('password', '')
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        terms_accepted = (request.form.get('terms_accepted') == 'on')

        if not all([email, password, first_name, last_name]):
            flash('All fields are required.', 'danger')
            return redirect(url_for('register'))
        if len(password) < 8:
            flash('Password must be at least 8 characters long.', 'danger')
            return redirect(url_for('register'))
        if not terms_accepted:
            flash('You must accept the terms and conditions to register.', 'danger')
            return redirect(url_for('register'))
        if User.query.filter_by(email=email).first():
            flash('Email already registered. Please log in.', 'warning')
            return redirect(url_for('login'))

        try:
            stripe_customer = stripe.Customer.create(
                email=email, name=f"{first_name} {last_name}",
                metadata={'source': 'cpp_test_prep'}
            )

            user = User(
                email=email,
                password_hash=generate_password_hash(password),
                first_name=first_name,
                last_name=last_name,
                subscription_status='trial',
                subscription_plan='trial',
                subscription_end_date=datetime.utcnow() + timedelta(days=7),  # keep 7 until you approve change
                stripe_customer_id=stripe_customer.id,
                terms_accepted=True,
                terms_accepted_date=datetime.utcnow()
            )
            db.session.add(user)
            db.session.commit()

            log_activity(user.id, 'user_registered', f'New user: {first_name} {last_name}')
            session['user_id'] = user.id
            session['user_name'] = f"{first_name} {last_name}"
            flash(f'Welcome {first_name}! You have a 7-day free trial.', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            print(f"Registration error: {e}")
            db.session.rollback()
            flash('Registration error. Please try again.', 'danger')

    content = """
    <div class="row justify-content-center">
      <div class="col-md-6">
        <div class="card">
          <div class="card-header"><h3 class="mb-0">Create Account</h3></div>
          <div class="card-body">
            <form method="POST">
              <div class="mb-3"><label class="form-label">First Name</label><input type="text" class="form-control" name="first_name" required></div>
              <div class="mb-3"><label class="form-label">Last Name</label><input type="text" class="form-control" name="last_name" required></div>
              <div class="mb-3"><label class="form-label">Email</label><input type="email" class="form-control" name="email" required></div>
              <div class="mb-3"><label class="form-label">Password</label><input type="password" class="form-control" name="password" required><div class="form-text">At least 8 characters.</div></div>
              <div class="mb-3">
                <div class="card bg-light"><div class="card-body">
                  <h6 class="card-title">Terms and Conditions</h6>
                  <div style="max-height: 150px; overflow-y: auto; font-size: 0.9em;">
                    <p><strong>Service</strong> Study materials and practice tests for CPP exam preparation.</p>
                    <p><strong>Responsibilities</strong> Use for legitimate study purposes; keep your account secure.</p>
                    <p><strong>Payment</strong> Subscription fees and cancellation per checkout terms.</p>
                    <p><strong>IP</strong> Content is proprietary.</p>
                    <p><strong>Disclaimer</strong> No guarantee of exam success.</p>
                  </div>
                  <div class="form-check mt-2">
                    <input class="form-check-input" type="checkbox" id="terms_accepted" name="terms_accepted" required>
                    <label class="form-check-label" for="terms_accepted"><strong>I agree to the Terms and Conditions</strong></label>
                  </div>
                </div></div>
              </div>
              <button type="submit" class="btn btn-primary w-100">Create Account</button>
            </form>
            <div class="text-center mt-3">Already have an account? <a href="/login">Login</a></div>
          </div>
        </div>
      </div>
    </div>
    """
    return render_base_template("Register", content)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').lower().strip()
        password = request.form.get('password', '')
        try:
            user = User.query.filter_by(email=email).first()
            if user and check_password_hash(user.password_hash, password):
                session['user_id'] = user.id
                session['user_name'] = f"{user.first_name} {user.last_name}"
                log_activity(user.id, 'user_login', 'User logged in')
                flash(f'Welcome back, {user.first_name}!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid email or password.', 'danger')
        except Exception as e:
            print(f"Login error: {e}")
            flash('Login error. Please try again.', 'danger')

    content = """
    <div class="row justify-content-center">
      <div class="col-md-5">
        <div class="card">
          <div class="card-header"><h3 class="mb-0">Login</h3></div>
          <div class="card-body">
            <form method="POST">
              <div class="mb-3"><label class="form-label">Email</label><input type="email" class="form-control" name="email" required></div>
              <div class="mb-3"><label class="form-label">Password</label><input type="password" class="form-control" name="password" required></div>
              <button type="submit" class="btn btn-primary w-100">Login</button>
            </form>
            <div class="text-center mt-3">Don't have an account? <a href="/register">Register</a></div>
          </div>
        </div>
      </div>
    </div>
    """
    return render_base_template("Login", content)

@app.route('/logout')
def logout():
    if 'user_id' in session:
        log_activity(session['user_id'], 'user_logout', 'User logged out')
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

# -----------------------------------------------------------------------------
# Dashboard
# -----------------------------------------------------------------------------
@app.route('/dashboard')
@login_required
def dashboard():
    user = User.query.get(session['user_id'])
    days_left = 0
    if user.subscription_end_date:
        days_left = max(0, (user.subscription_end_date - datetime.utcnow()).days)

    # last visit / motivational blurb
    msg = random.choice([
        "Small steps daily beat cramming. You've got this!",
        "Consistency builds confidence. Let’s add 10 minutes today.",
        "Every question is progress. Keep going!"
    ])
    content = Template("""
    <div class="row">
      <div class="col-12 mb-3">
        <h1 class="h3 mb-1">Welcome back, $first_name!</h1>
        <div class="text-muted">Plan status: <strong>$days_left days left</strong>. $msg</div>
      </div>
    </div>

    <div class="row g-3">
      <div class="col-md-8">
        <div class="card">
          <div class="card-body d-flex align-items-center">
            <div class="flex-grow-1">
              <h5 class="mb-2">Tutor</h5>
              <p class="mb-0 text-muted">Ask anything; try a scenario; get structured, readable explanations.</p>
            </div>
            <a href="/study" class="btn btn-primary ms-3">Open Tutor</a>
          </div>
        </div>

        <div class="row g-3 mt-1">
          <div class="col-md-6">
            <div class="card h-100">
              <div class="card-body d-flex align-items-center">
                <div class="flex-grow-1">
                  <h5 class="mb-2">Flashcards</h5>
                  <p class="mb-0 text-muted">3x5 cards with Flip/Know/Don’t Know; keyboard J/K.</p>
                </div>
                <a href="/flashcards" class="btn btn-outline-primary ms-3">Open</a>
              </div>
            </div>
          </div>
          <div class="col-md-6">
            <div class="card h-100">
              <div class="card-body d-flex align-items-center">
                <div class="flex-grow-1">
                  <h5 class="mb-2">Quizzes</h5>
                  <p class="mb-0 text-muted">Pick domain & amount (5/10/15/20). Per-question feedback.</p>
                </div>
                <a href="/quiz-selector" class="btn btn-outline-success ms-3">Start</a>
              </div>
            </div>
          </div>
        </div>

        <div class="row g-3 mt-1">
          <div class="col-md-6">
            <div class="card h-100">
              <div class="card-body d-flex align-items-center">
                <div class="flex-grow-1">
                  <h5 class="mb-2">Mock Exam</h5>
                  <p class="mb-0 text-muted">All-domain random; choose 25/50/75/100; full review.</p>
                </div>
                <a href="/mock-exam" class="btn btn-outline-warning ms-3">Start</a>
              </div>
            </div>
          </div>
          <div class="col-md-6">
            <div class="card h-100">
              <div class="card-body d-flex align-items-center">
                <div class="flex-grow-1">
                  <h5 class="mb-2">Progress</h5>
                  <p class="mb-0 text-muted">See your needle gauge & domain mastery.</p>
                </div>
                <a href="/progress" class="btn btn-outline-secondary ms-3">View</a>
              </div>
            </div>
          </div>
        </div>

      </div>
      <div class="col-md-4">
        <div class="card h-100">
          <div class="card-header">Overall Progress</div>
          <div class="card-body">
            <div class="gauge-wrap">
              <svg id="gauge" viewBox="0 0 100 60">
                <!-- arc background -->
                <path d="M10 50 A40 40 0 0 1 90 50" fill="none" stroke="#e9ecef" stroke-width="10"/>
                <!-- color bands -->
                <path d="M10 50 A40 40 0 0 1 42 50" fill="none" stroke="#dc3545" stroke-width="10"/>
                <path d="M42 50 A40 40 0 0 1 74 50" fill="none" stroke="#fd7e14" stroke-width="10"/>
                <path d="M74 50 A40 40 0 0 1 90 50" fill="none" stroke="#28a745" stroke-width="10"/>
                <!-- needle -->
                <g id="needle" transform="translate(50,50) rotate(0)">
                  <rect x="-1" y="-37" width="2" height="37" fill="#343a40"></rect>
                  <circle cx="0" cy="0" r="3" fill="#343a40"></circle>
                </g>
                <!-- labels -->
                <text x="50" y="58" text-anchor="middle" font-size="8" fill="#495057" id="gaugeLabel">0%</text>
              </svg>
            </div>
            <div class="small text-muted mt-2">Target: sustain 80%+.</div>
          </div>
        </div>
      </div>
    </div>
    <script>
      (function(){
        const pct = $overall_pct;
        const angle = -90 + (pct * 180 / 100); // -90 to +90
        const needle = document.getElementById('needle');
        const lbl = document.getElementById('gaugeLabel');
        if (needle) needle.setAttribute('transform', 'translate(50,50) rotate(' + angle.toFixed(1) + ')');
        if (lbl) lbl.textContent = pct.toFixed(0) + '%';
      })();
    </script>
    """).substitute(
        first_name=user.first_name,
        days_left=days_left,
        msg=msg,
        overall_pct=int(_compute_overall_pct(user.id))
    )
    return render_base_template("Dashboard", content, user=user)

def _compute_overall_pct(user_id: int) -> float:
    # Prefer last 10 quiz averages
    try:
        rows = (QuizResult.query.filter_by(user_id=user_id)
                .order_by(QuizResult.completed_at.desc()).limit(10).all())
        if rows:
            return sum(r.score for r in rows) / len(rows)
        # else use domain progress average
        pr = UserProgress.query.filter_by(user_id=user_id).all()
        if pr:
            return sum((r.average_score or 0.0) for r in pr) / len(pr)
    except Exception as e:
        print(f"overall pct error: {e}")
    return 0.0

# -----------------------------------------------------------------------------
# Tutor (Study)
# -----------------------------------------------------------------------------
@app.route('/study')
@subscription_required
def study():
    user = User.query.get(session['user_id'])
    session['study_start_time'] = datetime.utcnow().timestamp()

    # Simple inline SVG avatar (neutral)
    avatar_svg = """data:image/svg+xml;utf8,
    <svg xmlns='http://www.w3.org/2000/svg' width='96' height='96' viewBox='0 0 24 24' fill='none' stroke='%230d6efd' stroke-width='1.5' stroke-linecap='round' stroke-linejoin='round'>
      <circle cx='12' cy='8' r='4' fill='%23e9f2ff'/>
      <path d='M4 20c0-4 3.5-7 8-7s8 3 8 7' fill='%23e9f2ff'/>
    </svg>"""

    content = Template("""
    <div class="row">
      <div class="col-lg-8">
        <div class="card">
          <div class="card-header d-flex align-items-center">
            <img src="$avatar" alt="Tutor" style="width:36px;height:36px;border-radius:50%;margin-right:8px;">
            <h4 class="mb-0">AI Tutor</h4>
          </div>
          <div class="card-body">
            <div id="chat" style="height: 420px; overflow-y: auto; border: 1px solid #eee; padding: 10px; margin-bottom: 12px; background:#fff;"></div>
            <div class="input-group">
              <input type="text" id="userInput" class="form-control" placeholder="Ask about any CPP topic..." />
              <button id="sendBtn" class="btn btn-primary">Send</button>
            </div>
            <div class="form-text mt-2">Tips: Ask “Explain Defense-in-Depth with examples” or click a suggestion. Use scenarios to practice applied thinking.</div>
          </div>
        </div>
      </div>
      <div class="col-lg-4">
        <div class="card mb-3">
          <div class="card-header d-flex justify-content-between align-items-center">
            <span>Suggestions</span>
            <div>
              <button class="btn btn-sm btn-outline-primary me-1" id="sugTab">Topics</button>
              <button class="btn btn-sm btn-outline-secondary" id="scnTab">Scenarios</button>
            </div>
          </div>
          <div class="card-body" id="suggestions"></div>
        </div>

        <div class="card">
          <div class="card-header">Domains</div>
          <div class="card-body">
            $chips
          </div>
        </div>
      </div>
    </div>
    <script>
      const chatDiv = document.getElementById('chat');
      const input = document.getElementById('userInput');
      const sendBtn = document.getElementById('sendBtn');
      function esc(s){return s.replace(/&/g,'&amp;').replace(/</g,'&lt;');}
      function asBullets(text){
        // simple bullets to <ul>
        const lines = text.split('\\n');
        let inList=false, out=[];
        for(const ln of lines){
          if(/^\\s*[-*]\\s+/.test(ln)){
            if(!inList){ out.push('<ul>'); inList = true; }
            out.push('<li>'+esc(ln.replace(/^\\s*[-*]\\s+/,''))+'</li>');
          } else {
            if(inList){ out.push('</ul>'); inList=false; }
            out.push('<p>'+esc(ln)+'</p>');
          }
        }
        if(inList) out.push('</ul>');
        return out.join('');
      }
      function append(role, text) {
        const el = document.createElement('div');
        el.className = role === 'user' ? 'text-end mb-2' : 'text-start mb-2';
        const body = role === 'user' ? esc(text) : asBullets(text);
        el.innerHTML =
          '<span class="badge bg-' + (role === 'user' ? 'primary' : 'secondary') + '">' +
          (role === 'user' ? 'You' : 'Tutor') + '</span>' +
          '<div class="mt-1 p-2 border rounded assistant-msg">' + body + '</div>';
        chatDiv.appendChild(el);
        chatDiv.scrollTop = chatDiv.scrollHeight;
      }
      async function send() {
        const q = input.value.trim();
        if (!q) return;
        append('user', q);
        input.value = '';
        try {
          const res = await fetch('/chat', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({message: q}) });
          const data = await res.json();
          if (data.response) append('assistant', data.response);
          else append('assistant', data.error || 'Sorry, something went wrong.');
        } catch (e) {
          append('assistant', 'Network error.');
        }
      }
      sendBtn.addEventListener('click', send);
      input.addEventListener('keydown', (e) => { if (e.key === 'Enter') send(); });

      // suggestions
      const topics = $topic_suggestions;
      const scenarios = $scenario_suggestions;
      const suggDiv = document.getElementById('suggestions');
      const sugTab = document.getElementById('sugTab');
      const scnTab = document.getElementById('scnTab');
      function renderChips(list){
        suggDiv.innerHTML = '';
        list.forEach(txt=>{
          const b = document.createElement('button');
          b.className='btn btn-sm btn-outline-secondary m-1';
          b.textContent = txt;
          b.onclick = ()=>{ input.value = txt; input.focus(); };
          suggDiv.appendChild(b);
        });
      }
      renderChips(topics);
      sugTab.onclick = ()=>renderChips(topics);
      scnTab.onclick = ()=>renderChips(scenarios);
    </script>
    """).substitute(
        avatar=avatar_svg,
        chips="".join([f'<span class="chip" onclick="document.getElementById(\'userInput\').value=\'Explain key topics in {CPP_DOMAINS[k][\"name\"]}\';document.getElementById(\'userInput\').focus();">{CPP_DOMAINS[k]["name"]}</span>' for k in DOMAIN_KEYS]),
        topic_suggestions=json.dumps([
            "Summarize Security Principles & Practices",
            "Explain Defense in Depth with examples",
            "How to structure an incident response plan?",
            "Common investigation pitfalls and how to avoid them",
            "Design a layered physical security perimeter",
            "What is least privilege vs. need-to-know?"
        ]),
        scenario_suggestions=json.dumps([
            "Scenario: Suspicious tailgating at a data center — how to respond?",
            "Scenario: Lost laptop with PHI — first 3 steps and containment",
            "Scenario: Background check reveals discrepancy — next actions?",
            "Scenario: Evidence chain broken — salvage admissibility?",
            "Scenario: Power outage during storm — BCP activation checklist"
        ])
    )
    return render_base_template("Tutor", content, user=user)

@app.route('/chat', methods=['POST'])
@subscription_required
def chat():
    try:
        data = request.get_json() or {}
        user_message = (data.get('message') or '').strip()
        if not user_message:
            return jsonify({'error': 'Empty message'}), 400

        user_id = session['user_id']

        ch = ChatHistory.query.filter_by(user_id=user_id).first()
        if not ch:
            ch = ChatHistory(user_id=user_id, messages='[]')
            db.session.add(ch)
            db.session.commit()

        try:
            messages = json.loads(ch.messages) if ch.messages else []
        except json.JSONDecodeError:
            messages = []

        if len(messages) > 20:
            messages = messages[-20:]

        messages.append({'role': 'user', 'content': user_message, 'timestamp': datetime.utcnow().isoformat()})
        openai_messages = [{'role': m['role'], 'content': m['content']} for m in messages]

        ai_response = chat_with_ai(openai_messages, user_id=user_id)
        messages.append({'role': 'assistant', 'content': ai_response, 'timestamp': datetime.utcnow().isoformat()})

        ch.messages = json.dumps(messages)
        ch.updated_at = datetime.utcnow()
        db.session.commit()

        log_activity(user_id, 'chat_message', f'Asked: {user_message[:50]}...')
        return jsonify({'response': ai_response, 'timestamp': datetime.utcnow().isoformat()})
    except Exception as e:
        print(f"Chat error: {e}")
        return jsonify({'error': 'Sorry, I encountered an error processing your message.'}), 500

# -----------------------------------------------------------------------------
# Flashcards
# -----------------------------------------------------------------------------
@app.route('/flashcards')
@subscription_required
def flashcards_page():
    user = User.query.get(session['user_id'])
    # domain chips
    chips = ''.join([f'<span class="chip" data-domain="{k}">{CPP_DOMAINS[k]["name"]}</span>' for k in DOMAIN_KEYS])
    chips = f'<span class="chip chip-outline" data-domain="random">Random</span>' + chips

    content = f"""
    <div class="row">
      <div class="col-lg-4 order-lg-1 order-2">
        <div class="card mb-3">
          <div class="card-header">Domains</div>
          <div class="card-body">
            <div id="domainChips">{chips}</div>
          </div>
        </div>
        <div class="card">
          <div class="card-header">How to use</div>
          <div class="card-body fc-instructions">
            <ul class="mb-2">
              <li><strong>Flip</strong> reveals the answer.</li>
              <li><strong>Know</strong> / <strong>Don’t know</strong> tracks your progress.</li>
              <li><strong>Next</strong> moves to the next card.</li>
              <li>Keyboard: <strong>J</strong>=Flip, <strong>K</strong>=Next.</li>
            </ul>
            <div class="text-muted small">Cards are unlimited; select a domain or choose Random.</div>
          </div>
        </div>
      </div>

      <div class="col-lg-8 order-lg-2 order-1">
        <div class="card mb-2">
          <div class="card-body">
            <div class="d-flex justify-content-between align-items-center">
              <div>Selected: <span id="selDomain">Random</span></div>
              <div>Cards in session: <span id="cardCount">0</span></div>
              <div>Known: <span id="knownCount">0</span> &nbsp; | &nbsp; Don’t know: <span id="dontCount">0</span></div>
            </div>
          </div>
        </div>

        <div class="d-flex justify-content-center">
          <div id="flashcard" class="flashcard card-35 w-100 p-4" style="cursor:pointer;">
            <div id="fcFront" class="front">Select a domain or click Random to begin. Tap or press J to flip.</div>
            <div id="fcBack" class="back d-none"></div>
          </div>
        </div>

        <div class="text-center mt-3">
          <button class="btn btn-secondary me-2" id="flipBtn">Flip (J)</button>
          <button class="btn btn-outline-danger me-2" id="dontBtn">Don’t know</button>
          <button class="btn btn-outline-success me-2" id="knowBtn">Know</button>
          <button class="btn btn-primary" id="nextBtn">Next (K)</button>
        </div>
      </div>
    </div>

    <script>
      let deck = [];
      let idx = -1;
      let showingBack = false;
      let domain = 'random';
      let known=0, dont=0;

      function setCounts(){ document.getElementById('cardCount').textContent = deck.length; document.getElementById('knownCount').textContent=known; document.getElementById('dontCount').textContent=dont; }
      function showCard(){
        const front = document.getElementById('fcFront');
        const back = document.getElementById('fcBack');
        if(idx < 0 || idx >= deck.length){ front.textContent = 'Out of cards. Click Next to fetch more.'; back.classList.add('d-none'); showingBack=false; return; }
        front.textContent = deck[idx].front;
        back.textContent  = deck[idx].back;
        if(showingBack){ back.classList.remove('d-none'); front.classList.add('d-none'); } else { back.classList.add('d-none'); front.classList.remove('d-none'); }
      }
      async function fetchMore(){
        const res = await fetch('/api/flashcards?domain=' + encodeURIComponent(domain) + '&count=50');
        const data = await res.json();
        deck = deck.concat(data);
        setCounts();
        if(idx<0 && deck.length>0){ idx=0; showingBack=false; showCard(); }
      }
      function nextCard(){
        idx++;
        if(idx >= deck.length){
          fetchMore().then(()=>{ if(deck.length>0){ if(idx>=deck.length) idx=deck.length-1; showingBack=false; showCard(); } });
        } else {
          showingBack=false; showCard();
        }
      }
      function flip(){ showingBack = !showingBack; showCard(); }
      document.getElementById('flashcard').onclick = flip;
      document.getElementById('flipBtn').onclick = flip;
      document.getElementById('nextBtn').onclick = nextCard;
      document.getElementById('knowBtn').onclick = function(){ known++; nextCard(); setCounts(); };
      document.getElementById('dontBtn').onclick = function(){ dont++; nextCard(); setCounts(); };
      document.addEventListener('keydown', (e)=>{ if(e.key.toLowerCase()==='j') flip(); if(e.key.toLowerCase()==='k') nextCard(); });

      // domain chips
      document.querySelectorAll('#domainChips .chip').forEach(ch=>{
        ch.addEventListener('click', ()=>{
          domain = ch.getAttribute('data-domain');
          document.getElementById('selDomain').textContent = ch.textContent;
          deck = []; idx=-1; showingBack=false; known=0; dont=0; setCounts();
          fetchMore();
        });
      });

      // initial load
      fetchMore();
    </script>
    """
    return render_base_template("Flashcards", content, user=user)

@app.get('/api/flashcards')
@subscription_required
def api_flashcards():
    domain = request.args.get('domain', 'random')
    try:
        count = int(request.args.get('count', 50))
    except ValueError:
        count = 50
    count = max(1, min(200, count))

    # Build from DB (question -> flashcard front/back)
    cards = []
    try:
        rows = question_bank_query(domain=None if domain == 'random' else domain, limit=count)
        for r in rows:
            try:
                opts = json.loads(r.options_json)
            except Exception:
                opts = {}
            correct_letter = (r.correct or '').strip()
            correct_text = (opts.get(correct_letter, '') if opts else '')
            back = strip_answer_letter_prefix(f"{correct_text}".strip())
            if r.explanation:
                back = (back + "\n\n" + r.explanation.strip()) if back else r.explanation.strip()
            cards.append({"front": r.question.strip(), "back": back, "domain": r.domain})
    except Exception as e:
        print(f"/api/flashcards DB error: {e}")

    # Fallback fill
    if len(cards) < count:
        fb = [q for q in FALLBACK_QUESTIONS if (domain == 'random' or q['domain'] == domain)]
        random.shuffle(fb)
        for q in fb:
            opts = q['options']
            correct_text = opts.get(q['correct'], '')
            back = strip_answer_letter_prefix(correct_text)
            if q.get('explanation'):
                back = (back + "\n\n" + q['explanation']) if back else q['explanation']
            cards.append({"front": q['question'], "back": back, "domain": q['domain']})
            if len(cards) >= count:
                break

    return jsonify(cards[:count])

# -----------------------------------------------------------------------------
# Quiz Builder + Quiz
# -----------------------------------------------------------------------------
@app.route('/quiz-selector')
@subscription_required
def quiz_selector():
    user = User.query.get(session['user_id'])
    # Domain chips
    chips = ''.join([f'<span class="chip" data-domain="{k}">{CPP_DOMAINS[k]["name"]}</span>' for k in DOMAIN_KEYS])
    chips = f'<span class="chip chip-outline" data-domain="random">All Domains</span>' + chips

    content = f"""
    <div class="row">
      <div class="col-lg-6">
        <div class="card">
          <div class="card-header"><h5 class="mb-0">Quiz Builder</h5></div>
          <div class="card-body">
            <div class="mb-2"><strong>Domain</strong></div>
            <div id="qbDomains">{chips}</div>

            <div class="mt-3"><strong>How many questions?</strong></div>
            <div>
              <span class="chip chip-outline" data-count="5">5</span>
              <span class="chip chip-outline" data-count="10">10</span>
              <span class="chip chip-outline" data-count="15">15</span>
              <span class="chip chip-outline" data-count="20">20</span>
            </div>

            <div class="mt-3"><strong>Difficulty</strong></div>
            <div>
              <span class="chip chip-outline" data-diff="easy">Easy</span>
              <span class="chip" data-diff="medium">Medium</span>
              <span class="chip chip-outline" data-diff="hard">Hard</span>
            </div>

            <div class="mt-4 text-end">
              <button id="startQuiz" class="btn btn-success">Start Quiz</button>
            </div>
          </div>
        </div>
      </div>

      <div class="col-lg-6">
        <div class="card h-100">
          <div class="card-header"><h5 class="mb-0">Mock Exam</h5></div>
          <div class="card-body">
            <p class="text-muted">All domains, randomized. Choose length:</p>
            <div>
              <a class="btn btn-outline-secondary me-2 mb-2" href="/mock-exam?count=25">25</a>
              <a class="btn btn-outline-secondary me-2 mb-2" href="/mock-exam?count=50">50</a>
              <a class="btn btn-outline-secondary me-2 mb-2" href="/mock-exam?count=75">75</a>
              <a class="btn btn-outline-secondary me-2 mb-2" href="/mock-exam?count=100">100</a>
            </div>
            <div class="small text-muted mt-2">You must answer all questions. Full review after submission.</div>
          </div>
        </div>
      </div>
    </div>

    <script>
      let selDomain='random', selCount=10, selDiff='medium';
      document.querySelectorAll('#qbDomains .chip').forEach(ch=>{
        ch.addEventListener('click', ()=>{
          document.querySelectorAll('#qbDomains .chip').forEach(x=>x.classList.add('chip-outline'));
          ch.classList.remove('chip-outline');
          selDomain = ch.getAttribute('data-domain');
        });
      });
      document.querySelectorAll('[data-count]').forEach(ch=>{
        ch.addEventListener('click', ()=>{
          document.querySelectorAll('[data-count]').forEach(x=>x.classList.add('chip-outline'));
          ch.classList.remove('chip-outline');
          selCount = parseInt(ch.getAttribute('data-count'));
        });
      });
      document.querySelectorAll('[data-diff]').forEach(ch=>{
        ch.addEventListener('click', ()=>{
          document.querySelectorAll('[data-diff]').forEach(x=>x.classList.add('chip-outline'));
          ch.classList.remove('chip-outline');
          selDiff = ch.getAttribute('data-diff');
        });
      });
      document.getElementById('startQuiz').onclick = function(){
        const url = '/quiz/run?quiz_type=practice&domain=' + encodeURIComponent(selDomain) +
                    '&count=' + selCount + '&difficulty=' + encodeURIComponent(selDiff);
        window.location.href = url;
      };
    </script>
    """
    return render_base_template("Quizzes", content, user=user)

@app.route('/quiz/run')
@subscription_required
def quiz_run():
    user = User.query.get(session['user_id'])
    quiz_type = request.args.get('quiz_type', 'practice')
    domain = request.args.get('domain', 'random')
    difficulty = request.args.get('difficulty', 'medium')
    try:
        num = int(request.args.get('count', '10'))
    except ValueError:
        num = 10
    num = max(5, min(50, num))

    # Start timer
    session['quiz_start_time'] = datetime.utcnow().timestamp()
    quiz_data = build_quiz_payload(quiz_type, None if domain == 'random' else domain, difficulty, num)
    quiz_json = json.dumps(quiz_data)

    # Build page with per-question rendering + bottom submit
    content = """
    <div class="row">
      <div class="col-md-10 mx-auto">
        <div class="card">
          <div class="card-header d-flex justify-content-between align-items-center">
            <h4 class="mb-0">""" + quiz_data['title'] + """</h4>
            <button id="submitTop" class="btn btn-success">Submit</button>
          </div>
          <div class="card-body" id="quizContainer"></div>
        </div>
        <div class="text-end mt-3"><button id="submitBottom" class="btn btn-success">Submit</button></div>
        <div class="mt-4" id="results"></div>
      </div>
    </div>
    <script>
      const QUIZ_DATA = %%QUIZ_JSON%%;

      function renderQuiz() {
        const container = document.getElementById('quizContainer');
        container.innerHTML = '';
        (QUIZ_DATA.questions || []).forEach((q, idx) => {
          const card = document.createElement('div');
          card.className = 'mb-3 p-3 border rounded';
          const title = document.createElement('h5');
          title.textContent = 'Q' + (idx + 1) + '. ' + q.question;
          card.appendChild(title);

          const options = q.options || {};
          for (const key of Object.keys(options)) {
            const optId = 'q' + idx + '_' + key;
            const div = document.createElement('div');
            div.className = 'form-check';
            const input = document.createElement('input');
            input.className = 'form-check-input';
            input.type = 'radio';
            input.name = 'q' + idx;
            input.id = optId;
            input.value = key;
            const label = document.createElement('label');
            label.className = 'form-check-label';
            label.htmlFor = optId;
            label.textContent = key + ') ' + options[key];
            div.appendChild(input);
            div.appendChild(label);
            card.appendChild(div);
          }
          container.appendChild(card);
        });
      }

      async function submitQuiz() {
        // check unanswered
        let unanswered = [];
        (QUIZ_DATA.questions || []).forEach((q, idx) => {
          const sel = document.querySelector('input[name="q' + idx + '"]:checked');
          if(!sel) unanswered.push(idx+1);
        });
        if(unanswered.length>0){
          alert('Please answer all questions before submitting. Unanswered: ' + unanswered.join(', '));
          return;
        }

        const answers = {};
        (QUIZ_DATA.questions || []).forEach((q, idx) => {
          const selected = document.querySelector('input[name="q' + idx + '"]:checked');
          answers[String(idx)] = selected ? selected.value : null;
        });
        const res = await fetch('/submit-quiz', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({
            quiz_type: QUIZ_DATA.quiz_type,
            domain: QUIZ_DATA.domain,
            questions: QUIZ_DATA.questions,
            answers: answers
          })
        });
        const data = await res.json();
        const resultsDiv = document.getElementById('results');
        if (data.error) {
          resultsDiv.innerHTML = '<div class="alert alert-danger">' + data.error + '</div>';
          return;
        }
        let html = '<div class="card"><div class="card-body">';
        html += '<h4>Score: ' + data.score.toFixed(1) + '% (' + data.correct + '/' + data.total + ')</h4>';
        html += '<p>Time taken: ' + (data.time_taken || 0) + ' min</p>';
        if (Array.isArray(data.performance_insights)) {
          html += '<ul>';
          data.performance_insights.forEach(p => { html += '<li>' + p + '</li>'; });
          html += '</ul>';
        }
        // Detailed review
        if (Array.isArray(data.results)) {
          html += '<hr><h5>Review</h5>';
          data.results.forEach((r, i) => {
            const ok = r.is_correct ? 'success' : 'danger';
            html += '<div class="mb-3 p-3 border border-' + ok + ' rounded">';
            html += '<div><strong>Q' + r.index + '.</strong> ' + r.question + '</div>';
            if (r.user_letter) {
              html += '<div class="mt-1 text-' + (r.is_correct ? 'success' : 'danger') + '">';
              html += 'Your answer: ' + r.user_letter + ') ' + (r.user_text || '') + '</div>';
            } else {
              html += '<div class="mt-1 text-danger">No answer selected.</div>';
            }
            html += '<div class="mt-1">Correct: <strong>' + r.correct_letter + ') ' + (r.correct_text || '') + '</strong></div>';
            if (r.explanation) {
              html += '<div class="mt-1 text-muted"><em>' + r.explanation + '</em></div>';
            }
            html += '</div>';
          });
        }
        html += '</div></div>';
        resultsDiv.innerHTML = html;
        window.scrollTo({ top: resultsDiv.offsetTop - 20, behavior: 'smooth' });
      }

      document.getElementById('submitTop').addEventListener('click', submitQuiz);
      document.getElementById('submitBottom').addEventListener('click', submitQuiz);
      renderQuiz();
    </script>
    """.replace("%%QUIZ_JSON%%", quiz_json)

    return render_base_template("Quiz", content, user=user)

# Back-compat route (still usable)
@app.route('/quiz/<quiz_type>')
@subscription_required
def quiz_compat(quiz_type):
    # Map to builder defaults
    return redirect(url_for('quiz_selector'))

# -----------------------------------------------------------------------------
# Mock Exam
# -----------------------------------------------------------------------------
@app.route('/mock-exam')
@subscription_required
def mock_exam():
    user = User.query.get(session['user_id'])
    try:
        requested = int(request.args.get('count', 50))
    except ValueError:
        requested = 50
    num_questions = max(25, min(100, requested))
    session['quiz_start_time'] = datetime.utcnow().timestamp()

    quiz_data = build_quiz_payload('mock-exam', None, 'medium', num_questions)
    quiz_json = json.dumps(quiz_data)

    content = """
    <div class="row">
      <div class="col-md-10 mx-auto">
        <div class="card">
          <div class="card-header d-flex justify-content-between align-items-center">
            <h4 class="mb-0">Mock Exam (""" + str(num_questions) + """ Q)</h4>
            <button id="submitTop" class="btn btn-success">Submit</button>
          </div>
          <div class="card-body" id="quizContainer"></div>
        </div>
        <div class="text-end mt-3"><button id="submitBottom" class="btn btn-success">Submit</button></div>
        <div class="mt-4" id="results"></div>
      </div>
    </div>
    <script>
      const QUIZ_DATA = %%QUIZ_JSON%%;

      function renderQuiz() {
        const container = document.getElementById('quizContainer');
        container.innerHTML = '';
        (QUIZ_DATA.questions || []).forEach((q, idx) => {
          const card = document.createElement('div');
          card.className = 'mb-3 p-3 border rounded';
          const title = document.createElement('h5');
          title.textContent = 'Q' + (idx + 1) + '. ' + q.question;
          card.appendChild(title);

          const options = q.options || {};
          for (const key of Object.keys(options)) {
            const optId = 'q' + idx + '_' + key;
            const div = document.createElement('div');
            div.className = 'form-check';
            const input = document.createElement('input');
            input.className = 'form-check-input';
            input.type = 'radio';
            input.name = 'q' + idx;
            input.id = optId;
            input.value = key;
            const label = document.createElement('label');
            label.className = 'form-check-label';
            label.htmlFor = optId;
            label.textContent = key + ') ' + options[key];
            div.appendChild(input);
            div.appendChild(label);
            card.appendChild(div);
          }
          container.appendChild(card);
        });
      }

      async function submitQuiz() {
        // must answer all
        let unanswered = [];
        (QUIZ_DATA.questions || []).forEach((q, idx) => {
          const sel = document.querySelector('input[name="q' + idx + '"]:checked');
          if(!sel) unanswered.push(idx+1);
        });
        if(unanswered.length>0){
          alert('Please answer all questions before submitting. Unanswered: ' + unanswered.join(', '));
          return;
        }

        const answers = {};
        (QUIZ_DATA.questions || []).forEach((q, idx) => {
          const selected = document.querySelector('input[name="q' + idx + '"]:checked');
          answers[String(idx)] = selected ? selected.value : null;
        });
        const res = await fetch('/submit-quiz', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({
            quiz_type: 'mock-exam',
            domain: 'general',
            questions: QUIZ_DATA.questions,
            answers: answers
          })
        });
        const data = await res.json();
        const resultsDiv = document.getElementById('results');
        if (data.error) {
          resultsDiv.innerHTML = '<div class="alert alert-danger">' + data.error + '</div>';
          return;
        }
        let html = '<div class="card"><div class="card-body">';
        html += '<h4>Score: ' + data.score.toFixed(1) + '% (' + data.correct + '/' + data.total + ')</h4>';
        html += '<p>Time taken: ' + (data.time_taken || 0) + ' min</p>';
        if (Array.isArray(data.performance_insights)) {
          html += '<ul>';
          data.performance_insights.forEach(p => { html += '<li>' + p + '</li>'; });
          html += '</ul>';
        }
        if (Array.isArray(data.results)) {
          html += '<hr><h5>Review</h5>';
          data.results.forEach((r, i) => {
            const ok = r.is_correct ? 'success' : 'danger';
            html += '<div class="mb-3 p-3 border border-' + ok + ' rounded">';
            html += '<div><strong>Q' + r.index + '.</strong> ' + r.question + '</div>';
            if (r.user_letter) {
              html += '<div class="mt-1 text-' + (r.is_correct ? 'success' : 'danger') + '">';
              html += 'Your answer: ' + r.user_letter + ') ' + (r.user_text || '') + '</div>';
            } else {
              html += '<div class="mt-1 text-danger">No answer selected.</div>';
            }
            html += '<div class="mt-1">Correct: <strong>' + r.correct_letter + ') ' + (r.correct_text || '') + '</strong></div>';
            if (r.explanation) {
              html += '<div class="mt-1 text-muted"><em>' + r.explanation + '</em></div>';
            }
            html += '</div>';
          });
        }
        html += '</div></div>';
        resultsDiv.innerHTML = html;
        window.scrollTo({ top: resultsDiv.offsetTop - 20, behavior: 'smooth' });
      }

      document.getElementById('submitTop').addEventListener('click', submitQuiz);
      document.getElementById('submitBottom').addEventListener('click', submitQuiz);
      renderQuiz();
    </script>
    """.replace("%%QUIZ_JSON%%", quiz_json)

    return render_base_template("Mock Exam", content, user=user)

# -----------------------------------------------------------------------------
# Submit Quiz (detailed review + tracking)
# -----------------------------------------------------------------------------
@app.route('/submit-quiz', methods=['POST'])
@subscription_required
def submit_quiz():
    try:
        data = request.get_json() or {}
        quiz_type = data.get('quiz_type')
        answers = data.get('answers', {})
        questions = data.get('questions', [])
        domain = data.get('domain', 'general')

        if not quiz_type or not questions:
            return jsonify({'error': 'Invalid quiz data'}), 400

        time_taken = 0
        if 'quiz_start_time' in session:
            start = datetime.fromtimestamp(session['quiz_start_time'])
            time_taken = int((datetime.utcnow() - start).total_seconds() / 60)
            session.pop('quiz_start_time', None)

        correct_count = 0
        total = len(questions)
        detailed_results = []

        for i, q in enumerate(questions):
            user_letter = answers.get(str(i))
            correct_letter = q.get('correct')
            options = q.get('options', {}) or {}
            is_correct = (user_letter == correct_letter)
            if is_correct:
                correct_count += 1

            detailed_results.append({
                'index': i + 1,
                'question': q.get('question', ''),
                'correct_letter': correct_letter,
                'correct_text': options.get(correct_letter, ''),
                'user_letter': user_letter,
                'user_text': options.get(user_letter, '') if user_letter else None,
                'explanation': q.get('explanation', ''),
                'is_correct': bool(is_correct),
                'domain': q.get('domain', 'general')
            })

            # Track learning events
            try:
                record_question_event(session['user_id'], q, domain=q.get('domain', domain),
                                      is_correct=is_correct, source=('mock' if quiz_type == 'mock-exam' else 'quiz'))
                update_user_progress_on_answer(session['user_id'], q.get('domain', domain), None, is_correct)
            except Exception as e:
                print(f"tracking error: {e}")

        score = (correct_count / total) * 100 if total else 0.0

        # Save result
        qr = QuizResult(
            user_id=session['user_id'],
            quiz_type=quiz_type,
            domain=domain,
            questions=json.dumps(questions),
            answers=json.dumps(answers),
            score=score,
            total_questions=total,
            time_taken=time_taken
        )
        db.session.add(qr)
        db.session.commit()

        # Update user quiz score history
        user = User.query.get(session['user_id'])
        try:
            scores = json.loads(user.quiz_scores) if user.quiz_scores else []
        except Exception:
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

        insights = []
        if score >= 90:
            insights.append("Excellent performance. You're well-prepared for this topic.")
        elif score >= 80:
            insights.append("Strong performance. Review missed questions to lock in knowledge.")
        elif score >= 70:
            insights.append("Fair performance. Focus on the areas you missed.")
        else:
            insights.append("Consider more practice on this domain before the exam.")
        if time_taken > 0 and total > 0:
            avg = time_taken / total
            if avg < 1:
                insights.append("Great pace. You answered efficiently.")
            elif avg > 3:
                insights.append("Consider practicing to improve your speed.")

        log_activity(session['user_id'], 'quiz_completed', f'{quiz_type}: {correct_count}/{total} in {time_taken} min')

        return jsonify({
            'success': True,
            'score': round(score, 1),
            'correct': correct_count,
            'total': total,
            'time_taken': time_taken,
            'performance_insights': insights,
            'results': detailed_results
        })
    except Exception as e:
        print(f"Submit quiz error: {e}")
        db.session.rollback()
        return jsonify({'error': 'Error processing quiz results.'}), 500

# -----------------------------------------------------------------------------
# Progress
# -----------------------------------------------------------------------------
@app.route('/progress')
@subscription_required
def progress_page():
    user = User.query.get(session['user_id'])
    # overall pct
    overall = int(_compute_overall_pct(user.id))

    # domain rows
    try:
        rows = (UserProgress.query
                .filter_by(user_id=user.id)
                .order_by(UserProgress.domain.asc()).all())
    except Exception as e:
        print(f"/progress error: {e}")
        rows = []

    def badge(score):
        try:
            s = float(score or 0)
        except Exception:
            s = 0
        color = 'danger' if s < 60 else ('warning' if s < 80 else 'success')
        label = 'Needs practice' if color == 'danger' else ('Good' if color == 'warning' else 'Strong')
        return f'<span class="badge bg-{color}">{label}</span>'

    tbody = ""
    for r in rows:
        dname = CPP_DOMAINS.get(r.domain, {"name": r.domain}).get("name", r.domain)
        tbody += "<tr>"
        tbody += f"<td>{dname}</td>"
        tbody += f"<td>{(r.average_score or 0):.0f}%</td>"
        tbody += f"<td>{r.question_count or 0}</td>"
        tbody += f"<td>{badge(r.average_score)}</td>"
        tbody += "</tr>"

    if not tbody:
        tbody = '<tr><td colspan="4" class="text-muted">Practice to populate your progress here.</td></tr>'

    content = Template("""
    <div class="row">
      <div class="col-md-4">
        <div class="card h-100">
          <div class="card-header">Overall Progress</div>
          <div class="card-body">
            <div class="gauge-wrap">
              <svg id="gauge" viewBox="0 0 100 60">
                <path d="M10 50 A40 40 0 0 1 90 50" fill="none" stroke="#e9ecef" stroke-width="10"/>
                <path d="M10 50 A40 40 0 0 1 42 50" fill="none" stroke="#dc3545" stroke-width="10"/>
                <path d="M42 50 A40 40 0 0 1 74 50" fill="none" stroke="#fd7e14" stroke-width="10"/>
                <path d="M74 50 A40 40 0 0 1 90 50" fill="none" stroke="#28a745" stroke-width="10"/>
                <g id="needle" transform="translate(50,50) rotate(0)">
                  <rect x="-1" y="-37" width="2" height="37" fill="#343a40"></rect>
                  <circle cx="0" cy="0" r="3" fill="#343a40"></circle>
                </g>
                <text x="50" y="58" text-anchor="middle" font-size="8" fill="#495057" id="gaugeLabel">0%</text>
              </svg>
            </div>
            <div class="small text-muted mt-2">Target: sustain 80%+ over time.</div>
          </div>
        </div>
      </div>
      <div class="col-md-8">
        <div class="card h-100">
          <div class="card-header">Domain Mastery</div>
          <div class="card-body">
            <div class="table-responsive">
              <table class="table align-middle">
                <thead><tr><th>Domain</th><th>Average</th><th>Questions</th><th>Status</th></tr></thead>
                <tbody>$tbody</tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    </div>
    <script>
      (function(){
        const pct = $overall;
        const angle = -90 + (pct * 180 / 100);
        const needle = document.getElementById('needle');
        const lbl = document.getElementById('gaugeLabel');
        if (needle) needle.setAttribute('transform', 'translate(50,50) rotate(' + angle.toFixed(1) + ')');
        if (lbl) lbl.textContent = pct.toFixed(0) + '%';
      })();
    </script>
    """).substitute(overall=overall, tbody=tbody)

    return render_base_template("Progress", content, user=user)

# -----------------------------------------------------------------------------
# Subscription & Stripe
# -----------------------------------------------------------------------------
@app.route('/subscribe')
@login_required
def subscribe():
    user = User.query.get(session['user_id'])
    trial_days_left = None
    if user and user.subscription_status == 'trial' and user.subscription_end_date:
        trial_days_left = max((user.subscription_end_date - datetime.utcnow()).days, 0)

    plans_html = """
    <div class="row">
      <div class="col-md-6">
        <div class="card h-100"><div class="card-body">
          <h4>Monthly</h4>
          <p>$39.99 / month</p>
          <form method="POST" action="/create-checkout-session">
            <input type="hidden" name="plan_type" value="monthly" />
            <div class="mb-2"><input type="text" class="form-control" name="discount_code" placeholder="Discount code (optional)"></div>
            <button class="btn btn-primary">Choose Monthly</button>
          </form>
        </div></div>
      </div>
      <div class="col-md-6">
        <div class="card h-100"><div class="card-body">
          <h4>6 Months</h4>
          <p>$99 / 6 months</p>
          <form method="POST" action="/create-checkout-session">
            <input type="hidden" name="plan_type" value="6month" />
            <div class="mb-2"><input type="text" class="form-control" name="discount_code" placeholder="Discount code (optional)"></div>
            <button class="btn btn-success">Choose 6 Months</button>
          </form>
        </div></div>
      </div>
    </div>
    """
    header = f'<div class="alert alert-info mb-3">Trial days left: {trial_days_left}</div>' if trial_days_left is not None else ''

    content = f"""
    <div class="row">
      <div class="col-12"><h2>Choose a Plan</h2></div>
      <div class="col-12">{header}</div>
      <div class="col-12">{plans_html}</div>
    </div>
    """
    return render_base_template("Subscribe", content, user=user)

@app.route('/create-checkout-session', methods=['POST'])
@login_required
def create_checkout_session():
    try:
        user = User.query.get(session['user_id'])
        plan_type = request.form.get('plan_type')
        discount_code = (request.form.get('discount_code') or '').strip().upper()

        plans = {
            'monthly': {'amount': 3999, 'name': 'CPP Test Prep - Monthly Plan', 'interval': 'month', 'interval_count': 1},
            '6month': {'amount': 9900, 'name': 'CPP Test Prep - 6 Month Plan', 'interval': 'month', 'interval_count': 6}
        }
        if plan_type not in plans:
            flash('Invalid plan selected.', 'danger')
            return redirect(url_for('subscribe'))

        selected = plans[plan_type]
        final_amount = selected['amount']
        discount_applied = False
        if discount_code == 'LAUNCH50':
            final_amount = int(selected['amount'] * 0.5)
            discount_applied = True
        elif discount_code == 'STUDENT20':
            final_amount = int(selected['amount'] * 0.8)
            discount_applied = True

        price = stripe.Price.create(
            unit_amount=final_amount,
            currency='usd',
            recurring={'interval': selected['interval'], 'interval_count': selected['interval_count']},
            product_data={'name': selected['name'] + (f' ({discount_code} DISCOUNT)' if discount_applied else ''), 'description': 'AI tutor, quizzes, and study tools'}
        )

        checkout_session = stripe.checkout.Session.create(
            customer=user.stripe_customer_id,
            payment_method_types=['card'],
            line_items=[{'price': price.id, 'quantity': 1}],
            mode='subscription',
            success_url=url_for('subscription_success', _external=True) + f'?session_id={{CHECKOUT_SESSION_ID}}&plan={plan_type}',
            cancel_url=url_for('subscribe', _external=True),
            metadata={
                'user_id': user.id,
                'plan_type': plan_type,
                'discount_code': discount_code if discount_applied else '',
                'original_amount': selected['amount'],
                'final_amount': final_amount
            },
            allow_promotion_codes=True
        )

        log_activity(user.id, 'subscription_attempt', f'Plan: {plan_type}, Discount: {discount_code}, Amount: ${final_amount/100:.2f}')
        return redirect(checkout_session.url, code=303)
    except Exception as e:
        print(f"Checkout session error: {e}")
        flash('Error creating payment session. Please try again.', 'danger')
        return redirect(url_for('subscribe'))

@app.route('/subscription-success')
@login_required
def subscription_success():
    session_id = request.args.get('session_id')
    plan_type = request.args.get('plan', 'monthly')
    if session_id:
        try:
            cs = stripe.checkout.Session.retrieve(session_id)
            if cs.payment_status == 'paid':
                user = User.query.get(session['user_id'])
                user.subscription_status = 'active'
                user.subscription_plan = plan_type
                user.stripe_subscription_id = cs.subscription
                if plan_type == '6month':
                    user.subscription_end_date = datetime.utcnow() + timedelta(days=180)
                else:
                    user.subscription_end_date = datetime.utcnow() + timedelta(days=30)
                meta = cs.metadata or {}
                if meta.get('discount_code'):
                    user.discount_code_used = meta['discount_code']
                db.session.commit()
                log_activity(user.id, 'subscription_activated', f'Plan: {plan_type}')
                flash('Subscription activated. Welcome!', 'success')
            else:
                flash('Payment verification failed.', 'danger')
        except Exception as e:
            print(f"Subscription verification error: {e}")
            flash('Subscription verification error. Please contact support.', 'danger')
    return redirect(url_for('dashboard'))

@app.post("/webhook")
def stripe_webhook():
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

    event_type = event.get('type')
    data_object = event.get('data', {}).get('object', {})
    customer_id = data_object.get('customer')
    subscription_id = data_object.get('subscription') or data_object.get('id')

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
            if status == 'active' and not user.subscription_end_date:
                user.subscription_end_date = datetime.utcnow() + timedelta(days=30)
            elif status in ('canceled', 'expired'):
                user.subscription_status = 'expired'
            db.session.commit()
            log_activity(user.id, 'subscription_status_update', f'status={status}')
        except Exception as e:
            print(f"Error updating subscription: {e}")
            db.session.rollback()

    try:
        if event_type == 'invoice.payment_succeeded':
            set_user_subscription_by_customer(customer_id, 'active', subscription_id)
        elif event_type == 'invoice.payment_failed':
            set_user_subscription_by_customer(customer_id, 'past_due', subscription_id)
        elif event_type in ('customer.subscription.created', 'customer.subscription.updated'):
            status = data_object.get('status', 'active')
            normalized = 'active' if status in ('active', 'trialing') else ('past_due' if status == 'past_due' else 'expired')
            set_user_subscription_by_customer(customer_id, normalized, subscription_id)
        elif event_type == 'customer.subscription.deleted':
            set_user_subscription_by_customer(customer_id, 'expired', subscription_id)
    except Exception as e:
        print(f"Webhook processing error for {event_type}: {e}")
        return 'Webhook processing error', 500

    return 'Success', 200

# -----------------------------------------------------------------------------
# Study Session Tracking
# -----------------------------------------------------------------------------
@app.route('/end-study-session', methods=['POST'])
@login_required
def end_study_session():
    try:
        if 'study_start_time' in session:
            start_time = datetime.fromtimestamp(session['study_start_time'])
            duration = int((datetime.utcnow() - start_time).total_seconds() / 60)
            db.session.add(StudySession(
                user_id=session['user_id'],
                duration=duration,
                session_type='chat',
                started_at=start_time,
                ended_at=datetime.utcnow()
            ))
            user = User.query.get(session['user_id'])
            if user:
                user.study_time = (user.study_time or 0) + duration
            db.session.commit()
            session.pop('study_start_time', None)
            log_activity(session['user_id'], 'study_session_completed', f'Duration: {duration} minutes')
            return jsonify({'success': True, 'duration': duration})
        return jsonify({'success': False, 'error': 'No active session'})
    except Exception as e:
        print(f"Error ending study session: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'error': 'Session end error'})

# -----------------------------------------------------------------------------
# Admin (MVP)
# -----------------------------------------------------------------------------
@app.route('/admin')
@admin_required
def admin_home():
    content = """
    <div class="row g-3">
      <div class="col-md-4"><a class="btn btn-primary w-100" href="/admin/users">Users</a></div>
      <div class="col-md-4"><a class="btn btn-secondary w-100" href="/admin/questions">Question Bank</a></div>
      <div class="col-md-4"><a class="btn btn-outline-success w-100" href="/admin/import">Import CSV/JSON</a></div>
    </div>
    """
    return render_base_template("Admin", content, user=User.query.get(session['user_id']))

@app.route('/admin/users')
@admin_required
def admin_users():
    q = request.args.get('q', '').strip().lower()
    users = User.query.order_by(User.created_at.desc()).all()
    rows = []
    for u in users:
        if q and q not in u.email.lower() and q not in (u.first_name.lower() + ' ' + u.last_name.lower()):
            continue
        rows.append(f"<tr><td>{u.id}</td><td>{u.first_name} {u.last_name}</td><td>{u.email}</td>"
                    f"<td>{u.subscription_status}</td><td>{u.subscription_plan}</td>"
                    f"<td>{(u.subscription_end_date or '')}</td><td>{'Yes' if u.is_admin else 'No'}</td></tr>")
    if not rows:
        rows = ['<tr><td colspan="7" class="text-muted">No users found.</td></tr>']
    content = f"""
    <div class="card">
      <div class="card-header d-flex justify-content-between align-items-center">
        <h5 class="mb-0">Users</h5>
        <form class="d-flex" method="GET">
          <input name="q" class="form-control form-control-sm me-2" type="search" placeholder="Search..." value="{q}">
          <button class="btn btn-sm btn-outline-secondary">Search</button>
        </form>
      </div>
      <div class="card-body">
        <div class="table-responsive">
          <table class="table table-sm">
            <thead><tr><th>ID</th><th>Name</th><th>Email</th><th>Status</th><th>Plan</th><th>End</th><th>Admin</th></tr></thead>
            <tbody>{''.join(rows)}</tbody>
          </table>
        </div>
      </div>
    </div>
    """
    return render_base_template("Admin • Users", content, user=User.query.get(session['user_id']))

@app.route('/admin/questions')
@admin_required
def admin_questions():
    domain = request.args.get('domain', 'all')
    q = QuestionBank.query
    if domain != 'all':
        q = q.filter_by(domain=domain)
    q = q.order_by(QuestionBank.created_at.desc()).limit(200)
    rows = []
    for r in q.all():
        rows.append(f"""
        <tr>
          <td>{r.id}</td>
          <td>{r.domain}</td>
          <td>{r.difficulty}</td>
          <td>{(r.question[:80] + '...') if len(r.question)>80 else r.question}</td>
          <td>{r.correct}</td>
          <td>{'Yes' if r.is_verified else 'No'}</td>
        </tr>
        """)
    if not rows:
        rows = ['<tr><td colspan="6" class="text-muted">No questions yet.</td></tr>']
    domain_options = '<option value="all">All</option>' + ''.join([f'<option value="{k}">{CPP_DOMAINS[k]["name"]}</option>' for k in DOMAIN_KEYS])
    content = f"""
    <div class="card">
      <div class="card-header d-flex justify-content-between align-items-center">
        <h5 class="mb-0">Question Bank</h5>
        <form method="GET" class="d-flex">
          <select name="domain" class="form-select form-select-sm me-2">{domain_options}</select>
          <button class="btn btn-sm btn-outline-secondary">Filter</button>
        </form>
      </div>
      <div class="card-body">
        <div class="table-responsive">
          <table class="table table-sm">
            <thead><tr><th>ID</th><th>Domain</th><th>Difficulty</th><th>Question</th><th>Correct</th><th>Verified</th></tr></thead>
            <tbody>{''.join(rows)}</tbody>
          </table>
        </div>
      </div>
    </div>
    """
    return render_base_template("Admin • Questions", content, user=User.query.get(session['user_id']))

@app.route('/admin/import', methods=['GET', 'POST'])
@admin_required
def admin_import():
    note = ""
    if request.method == 'POST':
        payload = request.form.get('payload', '').strip()
        fmt = request.form.get('format', 'json')
        domain_default = request.form.get('domain_default', '').strip() or None
        difficulty_default = request.form.get('difficulty_default', 'medium').strip() or 'medium'
        created = 0
        try:
            if fmt == 'json':
                data = json.loads(payload)
                if isinstance(data, dict):
                    data = data.get('items') or data.get('questions') or []
                for item in data:
                    domain = (item.get('domain') or domain_default or 'security-principles')
                    difficulty = (item.get('difficulty') or difficulty_default or 'medium')
                    question = item.get('question') or ''
                    options = item.get('options') or {}
                    correct = item.get('correct') or ''
                    explanation = item.get('explanation') or ''
                    if not question or not options or not correct:
                        continue
                    qb = QuestionBank(
                        domain=domain, difficulty=difficulty, question=question,
                        options_json=json.dumps(options), correct=correct, explanation=explanation,
                        source_name=item.get('source_name', ''), source_url=item.get('source_url', ''),
                        is_verified=bool(item.get('is_verified', True))
                    )
                    db.session.add(qb)
                    created += 1
                db.session.commit()
                note = f"Imported {created} questions (JSON)."
            else:
                # CSV: question, A, B, C, D, correct, explanation, domain, difficulty
                lines = [ln.strip() for ln in payload.splitlines() if ln.strip()]
                for ln in lines:
                    parts = [p.strip() for p in ln.split(',')]
                    if len(parts) < 7:
                        continue
                    question, A, B, C, D, correct, explanation = parts[:7]
                    domain = parts[7] if len(parts) > 7 and parts[7] else (domain_default or 'security-principles')
                    difficulty = parts[8] if len(parts) > 8 and parts[8] else difficulty_default
                    opts = {"A": A, "B": B, "C": C, "D": D}
                    qb = QuestionBank(
                        domain=domain, difficulty=difficulty, question=question,
                        options_json=json.dumps(opts), correct=correct, explanation=explanation,
                        is_verified=True
                    )
                    db.session.add(qb)
                    created += 1
                db.session.commit()
                note = f"Imported {created} questions (CSV)."
        except Exception as e:
            note = f"Import error: {str(e)}"
            db.session.rollback()

    content = f"""
    <div class="card">
      <div class="card-header"><h5 class="mb-0">Import Questions</h5></div>
      <div class="card-body">
        <form method="POST">
          <div class="row g-3">
            <div class="col-md-3">
              <label class="form-label">Format</label>
              <select name="format" class="form-select">
                <option value="json">JSON</option>
                <option value="csv">CSV</option>
              </select>
            </div>
            <div class="col-md-3">
              <label class="form-label">Default Domain (optional)</label>
              <input name="domain_default" class="form-control" placeholder="security-principles">
            </div>
            <div class="col-md-3">
              <label class="form-label">Default Difficulty</label>
              <select name="difficulty_default" class="form-select">
                <option value="easy">easy</option>
                <option value="medium" selected>medium</option>
                <option value="hard">hard</option>
              </select>
            </div>
          </div>
          <div class="mt-3">
            <label class="form-label">Paste Payload</label>
            <textarea name="payload" class="form-control" rows="10" placeholder='JSON example: {{"items":[{{"domain":"physical-security","difficulty":"medium","question":"...","options":{{"A":"...","B":"...","C":"...","D":"..."}}, "correct":"B","explanation":"..."}}]}} OR CSV: question,A,B,C,D,correct,explanation,domain,difficulty'></textarea>
          </div>
          <div class="mt-3 text-end">
            <button class="btn btn-success">Import</button>
          </div>
        </form>
        {"<div class='alert alert-info mt-3'>" + note + "</div>" if note else ""}
      </div>
    </div>
    """
    return render_base_template("Admin • Import", content, user=User.query.get(session['user_id']))

# -----------------------------------------------------------------------------
# Diagnostics
# -----------------------------------------------------------------------------
@app.get("/diag/openai")
def diag_openai():
    has_key = bool(os.environ.get("OPENAI_API_KEY"))
    model = os.environ.get("OPENAI_CHAT_MODEL", OPENAI_CHAT_MODEL)
    try:
        headers = {'Authorization': f'Bearer {os.environ.get("OPENAI_API_KEY","")}', 'Content-Type': 'application/json'}
        data = {'model': model, 'messages': [{"role": "user", "content": "Say 'pong' if you can hear me."}], 'max_tokens': 10, 'temperature': 0}
        response = requests.post(f'{OPENAI_API_BASE}/chat/completions', headers=headers, json=data, timeout=20)
        success = (response.status_code == 200)
        return jsonify({
            "has_key": has_key, "model": model, "status_code": response.status_code,
            "success": success, "response_preview": response.text[:300],
            "timestamp": datetime.utcnow().isoformat()
        }), (200 if success else 500)
    except Exception as e:
        return jsonify({"has_key": has_key, "model": model, "error": str(e), "timestamp": datetime.utcnow().isoformat()}), 500

@app.get("/diag/database")
def diag_database():
    try:
        db.session.execute(text('SELECT 1'))
        user_count = db.session.query(User).count()
        quiz_count = db.session.query(QuizResult).count()
        qb_count = db.session.query(QuestionBank).count()
        return jsonify({"status": "healthy", "user_count": user_count, "quiz_count": quiz_count, "question_bank": qb_count, "timestamp": datetime.utcnow().isoformat()}), 200
    except Exception as e:
        return jsonify({"status": "unhealthy", "error": str(e), "timestamp": datetime.utcnow().isoformat()}), 500

# -----------------------------------------------------------------------------
# App Factory / Run
# -----------------------------------------------------------------------------
def create_app(config_name='default'):
    return app

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    print(f"Starting CPP Test Prep on port {port}")
    print(f"Debug: {debug}")
    print(f"DB configured: {bool(app.config.get('SQLALCHEMY_DATABASE_URI'))}")
    print(f"OpenAI configured: {bool(OPENAI_API_KEY)}")
    print(f"Stripe configured: {bool(stripe.api_key))}")
    app.run(host='0.0.0.0', port=port, debug=debug)
