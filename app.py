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
    'crisis-management': {'name': 'Crisis Management', 'topics': ['Business Continuity', 'Emergency Response']}
}

# Domain theme colors (used on quiz pages)
DOMAIN_THEME = {
    "security-principles": "#0d6efd",
    "business-principles": "#6f42c1",
    "investigations": "#20c997",
    "personnel-security": "#198754",
    "physical-security": "#fd7e14",
    "information-security": "#0dcaf0",
    "crisis-management": "#dc3545",
    "general": "#0d6efd"
}

def domain_brand(domain: str) -> str:
    return DOMAIN_THEME.get(domain or 'general', "#0d6efd")

# -----------------------------------------------------------------------------
# FLASHCARD BANK (demo data)
# -----------------------------------------------------------------------------
# Each card: { "front": "...", "back": "...", "domain": "<key>" }
FLASHCARD_BANK = {
    "security-principles": [
        {"front": "Define Defense in Depth.", "back": "Layered security controls so if one fails, others protect.", "domain": "security-principles"},
        {"front": "Risk appetite vs risk tolerance?", "back": "Appetite: overall level willing to accept; Tolerance: acceptable deviation per objective.", "domain": "security-principles"},
        {"front": "What is least privilege?", "back": "Grant only the minimum access needed to perform a task.", "domain": "security-principles"},
        {"front": "Primary output of a risk assessment?", "back": "Prioritized mitigation strategies mapped to risks and costs.", "domain": "security-principles"},
    ],
    "business-principles": [
        {"front": "CapEx vs OpEx?", "back": "CapEx: long-term assets; OpEx: ongoing operating expenses.", "domain": "business-principles"},
        {"front": "Purpose of an SLA?", "back": "Defines service expectations and performance metrics between parties.", "domain": "business-principles"},
        {"front": "RFP purpose?", "back": "Solicit comparable vendor proposals using a standardized scope.", "domain": "business-principles"},
        {"front": "Key contract risk area?", "back": "Indemnification, limitation of liability, termination clauses.", "domain": "business-principles"},
    ],
    "investigations": [
        {"front": "Chain of custody definition.", "back": "Documentation tracking evidence handling to preserve integrity.", "domain": "investigations"},
        {"front": "Interview vs interrogation?", "back": "Interview: information-gathering; Interrogation: confrontational, suspect-focused.", "domain": "investigations"},
        {"front": "What is entrapment?", "back": "Inducing a person to commit a crime they otherwise wouldn’t commit.", "domain": "investigations"},
        {"front": "Open-source intelligence (OSINT)?", "back": "Publicly available info used to support investigations.", "domain": "investigations"},
    ],
    "personnel-security": [
        {"front": "Purpose of background screening?", "back": "Reduce insider threat and hiring risk.", "domain": "personnel-security"},
        {"front": "What is separation of duties?", "back": "Split tasks among individuals to reduce fraud/error risk.", "domain": "personnel-security"},
        {"front": "Insider threat indicator?", "back": "Unusual access requests, policy violations, disgruntlement.", "domain": "personnel-security"},
        {"front": "Pre-employment vs continuous vetting?", "back": "Pre: point-in-time screening; Continuous: ongoing monitoring.", "domain": "personnel-security"},
    ],
    "physical-security": [
        {"front": "CPTED natural surveillance?", "back": "Design that increases visibility to deter crime.", "domain": "physical-security"},
        {"front": "Mantrap purpose?", "back": "Two-door space to control and verify entry.", "domain": "physical-security"},
        {"front": "Perimeter layers?", "back": "Outer (fences), middle (gates), inner (doors, vaults).", "domain": "physical-security"},
        {"front": "Lighting foot-candle typical range?", "back": "Commonly ~2–5 fc depending on area/task.", "domain": "physical-security"},
    ],
    "information-security": [
        {"front": "CIA triad?", "back": "Confidentiality, Integrity, Availability.", "domain": "information-security"},
        {"front": "What is hashing?", "back": "One-way function producing a fixed-size digest for data.", "domain": "information-security"},
        {"front": "Phishing vs spear phishing?", "back": "Phishing: broad; Spear: targeted to an individual or org.", "domain": "information-security"},
        {"front": "Zero Trust?", "back": "Never trust, always verify, least privilege everywhere.", "domain": "information-security"},
    ],
    "crisis-management": [
        {"front": "BCP vs DRP?", "back": "BCP: continue business; DRP: restore IT/data.", "domain": "crisis-management"},
        {"front": "Incident Command System (ICS)?", "back": "Standardized hierarchy/roles for incident management.", "domain": "crisis-management"},
        {"front": "Tabletop exercise?", "back": "Discussion-based scenario practice for plans/roles.", "domain": "crisis-management"},
        {"front": "MOU vs MOA?", "back": "MOU: intent; MOA: more formal obligations.", "domain": "crisis-management"},
    ],
}

def _all_flashcards():
    out = []
    for d, items in FLASHCARD_BANK.items():
        out.extend(items)
    return out

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
    terms_accepted = db.Column(db.Boolean, default=False)
    terms_accepted_date = db.Column(db.DateTime)

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
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    domain = db.Column(db.String(50), nullable=False, index=True)
    topic = db.Column(db.String(100), nullable=True, index=True)
    mastery_level = db.Column(db.String(20), default='needs_practice')
    average_score = db.Column(db.Float, default=0.0)
    question_count = db.Column(db.Integer, default=0)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow)
    consecutive_good_scores = db.Column(db.Integer, default=0)
    __table_args__ = (
        db.UniqueConstraint('user_id', 'domain', 'topic', name='uq_userprogress_user_domain_topic'),
    )

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
    __table_args__ = (
        db.Index('ix_question_event_user_created', 'user_id', 'created_at'),
    )

class FlashcardProgress(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, index=True, nullable=False)
    card_hash = db.Column(db.String(64), index=True, nullable=False)
    domain = db.Column(db.String(50), index=True, nullable=True)
    efactor = db.Column(db.Float, default=2.5)
    reps = db.Column(db.Integer, default=0)
    interval = db.Column(db.Integer, default=0)  # days
    last_seen = db.Column(db.DateTime)
    next_due = db.Column(db.DateTime, index=True)
    __table_args__ = (db.UniqueConstraint('user_id', 'card_hash', name='uq_user_card'),)

# -----------------------------------------------------------------------------
# Database Initialization / Migrations (safe, idempotent)
# -----------------------------------------------------------------------------
def init_database():
    try:
        db.create_all()

        insp = inspect(db.engine)

        # Ensure QuizResult has 'domain' and 'time_taken'
        if 'quiz_result' in insp.get_table_names():
            existing_cols = {c['name'] for c in insp.get_columns('quiz_result')}
            if 'domain' not in existing_cols:
                try:
                    db.session.execute(text("ALTER TABLE quiz_result ADD COLUMN domain VARCHAR(50)"))
                    db.session.commit()
                except Exception:
                    db.session.rollback()
            if 'time_taken' not in existing_cols:
                try:
                    db.session.execute(text("ALTER TABLE quiz_result ADD COLUMN time_taken INTEGER"))
                    db.session.commit()
                except Exception:
                    db.session.rollback()

        # Ensure User has terms columns
        if 'user' in insp.get_table_names():
            existing_cols = {c['name'] for c in insp.get_columns('user')}
            if 'terms_accepted' not in existing_cols:
                try:
                    db.session.execute(text('ALTER TABLE "user" ADD COLUMN terms_accepted BOOLEAN DEFAULT FALSE'))
                    db.session.commit()
                except Exception:
                    db.session.rollback()
            if 'terms_accepted_date' not in existing_cols:
                try:
                    db.session.execute(text('ALTER TABLE "user" ADD COLUMN terms_accepted_date TIMESTAMP'))
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

def log_activity(user_id, activity, details=None):
    try:
        db.session.add(ActivityLog(user_id=user_id, activity=activity, details=details))
        db.session.commit()
    except Exception as e:
        print(f"Activity logging error: {e}")
        db.session.rollback()

# ---------- tracking helpers ----------
def _hash_question_payload(question_obj: dict) -> str:
    q_text = (question_obj or {}).get('question', '') or ''
    opts = (question_obj or {}).get('options', {}) or {}
    parts = [q_text.strip()]
    for key in sorted(opts.keys()):
        parts.append(f"{key}:{str(opts.get(key, '')).strip()}")
    raw = "||".join(parts)
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()

def _hash_card(front_text: str) -> str:
    return hashlib.sha256((front_text or '').strip().encode('utf-8')).hexdigest()

def record_question_event(
    user_id: int,
    question_obj: dict,
    domain: str = None,
    topic: str = None,
    is_correct: bool = None,
    response_time_s: int = None,
    source: str = 'quiz'
) -> None:
    try:
        qhash = _hash_question_payload(question_obj)
        evt = QuestionEvent(
            user_id=user_id,
            question_hash=qhash,
            domain=domain,
            topic=topic,
            source=source,
            is_correct=is_correct,
            response_time_s=response_time_s,
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

def update_user_progress_on_answer(
    user_id: int,
    domain: str,
    topic: str,
    is_correct: bool
) -> None:
    try:
        if not domain:
            return
        row = UserProgress.query.filter_by(user_id=user_id, domain=domain, topic=topic).first()
        if not row:
            row = UserProgress(
                user_id=user_id,
                domain=domain,
                topic=topic,
                average_score=0.0,
                question_count=0,
                consecutive_good_scores=0,
                mastery_level='needs_practice'
            )
            db.session.add(row)

        earned = 100.0 if bool(is_correct) else 0.0
        old_count = row.question_count or 0
        new_count = old_count + 1
        row.average_score = ((row.average_score or 0.0) * old_count + earned) / new_count
        row.question_count = new_count

        if earned >= 75.0:
            row.consecutive_good_scores = (row.consecutive_good_scores or 0) + 1
        else:
            row.consecutive_good_scores = 0

        row.mastery_level = _mastery_from_stats(row.average_score, row.consecutive_good_scores)
        row.last_updated = datetime.utcnow()

        db.session.commit()
    except Exception as e:
        print(f"update_user_progress_on_answer error: {e}")
        db.session.rollback()

def get_seen_hashes(user_id: int, domain: str = None, topic: str = None, window_days: int = 30) -> set:
    try:
        cutoff = datetime.utcnow() - timedelta(days=window_days)
        q = QuestionEvent.query.filter(
            QuestionEvent.user_id == user_id,
            QuestionEvent.created_at >= cutoff
        )
        if domain:
            q = q.filter(QuestionEvent.domain == domain)
        if topic:
            q = q.filter(QuestionEvent.topic == topic)
        return {row.question_hash for row in q.with_entities(QuestionEvent.question_hash).all()}
    except Exception as e:
        print(f"get_seen_hashes error: {e}")
        return set()

# ---------- SM-2 helpers for flashcards ----------
def sm2_update(efactor: float, reps: int, interval: int, q: int):
    # q in [0..5]; we'll use 4 for Know, 2 for Don't know
    ef = efactor + (0.1 - (5 - q) * (0.08 + (5 - q) * 0.02))
    ef = max(1.3, ef)
    if q < 3:
        reps_new = 0
        interval_new = 1
    else:
        reps_new = reps + 1
        if reps_new == 1:
            interval_new = 1
        elif reps_new == 2:
            interval_new = 6
        else:
            interval_new = int(round(interval * ef))
            if interval_new < 1:
                interval_new = 1
    return ef, reps_new, interval_new

def _get_bank_for_domain(domain: str):
    if not domain or domain == 'all' or domain == 'random' or domain == 'general':
        return _all_flashcards()
    return FLASHCARD_BANK.get(domain, [])

# -----------------------------------------------------------------------------
# AI chat
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
                "Provide clear explanations, practical examples, and do not claim affiliation with ASIS."
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
            'max_tokens': 1500,
            'temperature': 0.7
        }

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
# Static quiz generator (fallback)
# -----------------------------------------------------------------------------
def generate_fallback_quiz(quiz_type, domain, difficulty, num_questions):
    base_questions = [
        {
            "question": "What is the primary purpose of a security risk assessment?",
            "options": {"A": "Identify all threats","B": "Determine cost-effective mitigation","C": "Eliminate all risks","D": "Satisfy compliance"},
            "correct": "B",
            "explanation": "Risk assessments help determine cost-effective mitigation strategies.",
            "domain": "security-principles"
        },
        {
            "question": "In CPTED, natural surveillance primarily accomplishes what?",
            "options": {"A": "Reduces guard costs","B": "Increases observation likelihood","C": "Eliminates cameras","D": "Provides legal protection"},
            "correct": "B",
            "explanation": "Natural surveillance increases the likelihood that criminal activity will be observed.",
            "domain": "physical-security"
        },
        {
            "question": "Which concept means applying multiple security layers so if one fails others still protect?",
            "options": {"A": "Security by Obscurity","B": "Defense in Depth","C": "Zero Trust","D": "Least Privilege"},
            "correct": "B",
            "explanation": "Defense in Depth uses layered controls to maintain protection despite single-point failures.",
            "domain": "security-principles"
        },
        {
            "question": "In incident response, what is usually the FIRST priority?",
            "options": {"A": "Notify law enforcement","B": "Contain the incident","C": "Eradicate malware","D": "Perform lessons learned"},
            "correct": "B",
            "explanation": "Containment prevents further damage before eradication and recovery.",
            "domain": "information-security"
        },
        {
            "question": "Background investigations primarily support which objective?",
            "options": {"A": "Regulatory compliance only","B": "Improving marketing outcomes","C": "Personnel Security risk reduction","D": "Disaster response coordination"},
            "correct": "C",
            "explanation": "They help reduce personnel security risks such as insider threat.",
            "domain": "personnel-security"
        }
    ]
    # Build up to requested count by repetition (demo). In production replace with real bank or AI.
    questions = []
    while len(questions) < num_questions:
        for q in base_questions:
            if len(questions) < num_questions:
                questions.append(q.copy())
    # Shuffle for randomness
    random.shuffle(questions)
    return {
        "title": f"CPP {quiz_type.title().replace('-', ' ')} Quiz",
        "quiz_type": quiz_type,
        "domain": domain or 'general',
        "difficulty": difficulty,
        "questions": questions[:num_questions]
    }

def generate_quiz(quiz_type, domain=None, difficulty='medium'):
    config = QUIZ_TYPES.get(quiz_type, {'questions': 10})
    return generate_fallback_quiz(quiz_type, domain, difficulty, config['questions'])

# -----------------------------------------------------------------------------
# Base HTML Template with global CSS
# -----------------------------------------------------------------------------
def render_base_template(title, content_html, user=None):
    disclaimer = """
    <div class="bg-light border-top mt-4 py-3">
        <div class="container">
            <div class="row">
                <div class="col-12">
                    <div class="alert alert-info mb-0">
                        <strong>Important Notice:</strong> This service is NOT affiliated with, endorsed by, or approved by ASIS International.
                        CPP® (Certified Protection Professional) is a registered certification mark of ASIS International, Inc.
                        This platform is an independent study aid and does not guarantee exam success.
                    </div>
                </div>
            </div>
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
            '      <div class="navbar-nav ms-auto">'
            '        <a class="nav-link" href="/dashboard">Dashboard</a>'
            '        <a class="nav-link" href="/study">Tutor</a>'
            '        <a class="nav-link" href="/flashcards">Flashcards</a>'
            '        <a class="nav-link" href="/quiz-selector">Quizzes</a>'
            '        <a class="nav-link" href="/progress">Progress</a>'
            '        <a class="nav-link" href="/subscribe">Subscribe</a>'
            '        <a class="nav-link" href="/logout">Logout</a>'
            '      </div>'
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
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
  <style>
    :root{ --brand: #0d6efd; }
    .chip { display:inline-block; padding:8px 12px; border-radius:999px; background:#0d6efd; color:white; margin:4px; cursor:pointer; font-weight:600; }
    .chip-outline { background:#fff; border:1px solid #0d6efd; color:#0d6efd; }
    .chip.small { font-size: 0.85rem; padding:6px 10px; }

    /* FLASHCARDS */
    .card-flash { width:100%; max-width:800px; margin:auto; }
    .card-face { position: relative; width: 100%; aspect-ratio: 5 / 3; transition: transform 0.6s; transform-style: preserve-3d; }
    .card-face.flip { transform: rotateY(180deg); }
    .card-side { position: absolute; inset: 0; backface-visibility: hidden; border-radius: 16px; padding: 28px; box-shadow: 0 8px 24px rgba(0,0,0,0.08);
                 display:flex; align-items:center; justify-content:center; font-size: clamp(1.05rem, 2.3vw, 1.4rem); line-height:1.5; font-weight:600; }
    .card-front { background:#e8f2ff; color:#0b3d66; border:1px solid #cfe4ff; }
    .card-back  { background:#fff5cc; color:#5c4500; border:1px solid #ffe89a; transform: rotateY(180deg); }

    .kbd {border:1px solid #ccc;border-bottom-width:2px;padding:2px 6px;border-radius:6px;background:#f8f9fa;margin:0 4px;font-family:ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono","Courier New", monospace;}

    .dom-good { background:#28a745 !important; color:white !important; }
    .dom-ok   { background:#fd7e14 !important; color:white !important; }
    .dom-bad  { background:#dc3545 !important; color:white !important; }

    .dial { --p:0; width:120px; height:120px; border-radius:50%;
      background:conic-gradient(#0d6efd calc(var(--p)*1%), #e9ecef 0);
      display:flex; align-items:center; justify-content:center; font-weight:700; color:#0d6efd;
    }
    .dial > div { background:white; width:84px; height:84px; border-radius:50%; display:flex; align-items:center; justify-content:center; }

    .q-progress { height:8px; background:#e9ecef; border-radius:999px; overflow:hidden; }
    .q-progress > div { height:100%; width:0%; background:var(--brand); transition:width .2s ease; }

    /* Buttons themed by --brand, but keep Bootstrap classes for layout */
    .btn-brand { background: var(--brand); border-color: var(--brand); color:#fff; }
    .btn-brand:hover { filter: brightness(0.95); color:#fff; }
    .chip.brand { background:var(--brand); border-color:var(--brand); }
    .chip-outline.brand { color:var(--brand); border-color:var(--brand); }

    @media (max-width: 576px) {
      .card-side { padding: 18px; font-size: clamp(1rem, 4vw, 1.2rem); }
    }
  </style>
</head>
<body>
  $nav
  <div class="container mt-4">
    $content
  </div>
  $disclaimer
</body>
</html>
""")
    return page.substitute(title=title, nav=nav_html, content=content_html, disclaimer=disclaimer)

# -----------------------------------------------------------------------------
# Routes
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

@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    content = """
    <div class="row justify-content-center">
      <div class="col-md-8">
        <div class="text-center mb-5">
          <h1 class="display-4">CPP Test Prep</h1>
          <p class="lead">AI-powered study platform for the Certified Protection Professional exam</p>
        </div>
        <div class="row">
          <div class="col-md-6">
            <div class="card h-100">
              <div class="card-body">
                <h5 class="card-title">🎯 Smart Quizzes</h5>
                <p class="card-text">Practice with questions across all CPP domains</p>
              </div>
            </div>
          </div>
          <div class="col-md-6">
            <div class="card h-100">
              <div class="card-body">
                <h5 class="card-title">🤖 AI Tutor</h5>
                <p class="card-text">Get personalized explanations and study guidance</p>
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

# ----------------------------- Auth: Register/Login/Logout --------------------
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
              <div class="mb-3">
                <label for="first_name" class="form-label">First Name</label>
                <input type="text" class="form-control" id="first_name" name="first_name" required>
              </div>
              <div class="mb-3">
                <label for="last_name" class="form-label">Last Name</label>
                <input type="text" class="form-control" id="last_name" name="last_name" required>
              </div>
              <div class="mb-3">
                <label for="email" class="form-label">Email</label>
                <input type="email" class="form-control" id="email" name="email" required>
              </div>
              <div class="mb-3">
                <label for="password" class="form-label">Password</label>
                <input type="password" class="form-control" id="password" name="password" required>
                <div class="form-text">Must be at least 8 characters long.</div>
              </div>
              <div class="mb-3">
                <div class="card bg-light">
                  <div class="card-body">
                    <h6 class="card-title">Terms and Conditions</h6>
                    <div style="max-height: 200px; overflow-y: auto; font-size: 0.9em;">
                      <p><strong>1. Service Description</strong><br>
                      This platform provides study materials and practice tests for CPP exam preparation.</p>
                      <p><strong>2. User Responsibilities</strong><br>
                      Use this service for legitimate study purposes and keep your account secure.</p>
                      <p><strong>3. Payment Terms</strong><br>
                      Subscription fees and cancellation policies apply as stated during checkout.</p>
                      <p><strong>4. Intellectual Property</strong><br>
                      All content is proprietary and protected by copyright.</p>
                      <p><strong>5. Disclaimer</strong><br>
                      We do not guarantee exam success; results depend on individual preparation.</p>
                      <p><strong>6. Privacy</strong><br>
                      We protect personal information per our privacy policy.</p>
                    </div>
                    <div class="form-check mt-3">
                      <input class="form-check-input" type="checkbox" id="terms_accepted" name="terms_accepted" required>
                      <label class="form-check-label" for="terms_accepted"><strong>I agree to the Terms and Conditions</strong></label>
                    </div>
                  </div>
                </div>
              </div>
              <button type="submit" class="btn btn-primary w-100">Create Account</button>
            </form>
            <div class="text-center mt-3">
              <p>Already have an account? <a href="/login">Login here</a></p>
            </div>
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
              <div class="mb-3">
                <label for="email" class="form-label">Email</label>
                <input type="email" class="form-control" id="email" name="email" required>
              </div>
              <div class="mb-3">
                <label for="password" class="form-label">Password</label>
                <input type="password" class="form-control" id="password" name="password" required>
              </div>
              <button type="submit" class="btn btn-primary w-100">Login</button>
            </form>
            <div class="text-center mt-3">
              <p>Don't have an account? <a href="/register">Register here</a></p>
            </div>
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

# --------------------------------- Dashboard ----------------------------------
@app.route('/dashboard')
@login_required
def dashboard():
    user = User.query.get(session['user_id'])
    days_left = 0
    if user.subscription_end_date:
        days_left = max(0, (user.subscription_end_date - datetime.utcnow()).days)

    # Simple encouraging message
    messages = [
        "Small sessions add up—nice job showing up today!",
        "Consistency beats cramming. You’ve got this.",
        "Every question is a step closer to confident mastery.",
        "Keep going—future you will thank you!"
    ]
    motd = random.choice(messages)

    tmpl = Template("""
    <div class="row">
      <div class="col-12 d-flex justify-content-between align-items-start">
        <div>
          <h1 class="mb-1">Welcome back, $first_name!</h1>
          <div class="text-muted">Last visit: $last_visit</div>
        </div>
        <div class="text-end">
          <div class="small text-muted">Trial/Plan</div>
          <div class="badge bg-primary fs-6">$days_left days left</div>
        </div>
      </div>

      <div class="col-12 mt-3">
        <div class="alert alert-success mb-4">$motd</div>
      </div>

      <div class="col-md-12">
        <div class="row g-3">
          <div class="col-md-6">
            <div class="card h-100">
              <div class="card-body d-flex flex-column">
                <h4 class="mb-2">🤖 Study with AI Tutor</h4>
                <p class="text-muted">Ask questions and get explanations, with domain suggestions.</p>
                <div class="mt-auto">
                  <a href="/study" class="btn btn-primary me-2">Open AI Tutor</a>
                  <a href="/progress" class="btn btn-outline-primary">View Progress</a>
                </div>
              </div>
            </div>
          </div>

          <div class="col-md-6">
            <div class="card h-100">
              <div class="card-body d-flex flex-column">
                <h4 class="mb-2">🃏 Flashcards</h4>
                <p class="text-muted">Spaced-repetition (SM-2). Use J to flip, K to go next.</p>
                <div class="mt-auto">
                  <a href="/flashcards" class="btn btn-secondary me-2">Open Flashcards</a>
                  <a href="/quiz-selector" class="btn btn-success">Start a Quiz</a>
                </div>
              </div>
            </div>
          </div>

          <div class="col-md-3">
            <div class="card h-100">
              <div class="card-body text-center d-flex flex-column">
                <h5 class="mb-2">📝 Quizzes</h5>
                <p class="text-muted flex-grow-1">Domain-specific & practice quizzes.</p>
                <a href="/quiz-selector" class="btn btn-success mt-auto">Choose a Quiz</a>
              </div>
            </div>
          </div>

          <div class="col-md-3">
            <div class="card h-100">
              <div class="card-body text-center d-flex flex-column">
                <h5 class="mb-2">🏁 Mock Exam</h5>
                <p class="text-muted flex-grow-1">Up to 100 questions in one go.</p>
                <a href="/mock-exam" class="btn btn-warning mt-auto">Start Mock Exam</a>
              </div>
            </div>
          </div>

          <div class="col-md-3">
            <div class="card h-100">
              <div class="card-body text-center d-flex flex-column">
                <h5 class="mb-2">📈 Progress</h5>
                <p class="text-muted flex-grow-1">Track strengths and focus areas.</p>
                <a href="/progress" class="btn btn-outline-primary mt-auto">Open Progress</a>
              </div>
            </div>
          </div>

          <div class="col-md-3">
            <div class="card h-100">
              <div class="card-body text-center d-flex flex-column">
                <h5 class="mb-2">💳 Subscription</h5>
                <p class="text-muted flex-grow-1">Manage your plan.</p>
                <a href="/subscribe" class="btn btn-outline-secondary mt-auto">Manage</a>
              </div>
            </div>
          </div>

        </div>
      </div>
    </div>
    """)
    last_visit = user.created_at.strftime("%Y-%m-%d") if user.created_at else "n/a"
    content = tmpl.substitute(
        first_name=user.first_name,
        last_visit=last_visit,
        days_left=days_left,
        motd=motd
    )
    return render_base_template("Dashboard", content, user=user)

# --------------------------------- Study Chat ---------------------------------
@app.route('/study')
@subscription_required
def study():
    user = User.query.get(session['user_id'])
    session['study_start_time'] = datetime.utcnow().timestamp()

    # domain chips
    domain_html = []
    domain_html.append('<span class="chip chip-outline me-1" data-domain="general">General</span>')
    for key, meta in CPP_DOMAINS.items():
        domain_html.append(f'<span class="chip chip-outline me-1" data-domain="{key}">{meta["name"]}</span>')

    # Suggestions panel
    suggestions_html = """
      <div class="card mb-3">
        <div class="card-body">
          <h6 class="mb-2">Try asking:</h6>
          <ul id="tutorSuggestions" class="mb-0">
            <li><a href="#" class="link-primary sug">Summarize CPTED in plain language</a></li>
            <li><a href="#" class="link-primary sug">Create a study plan for Physical Security</a></li>
            <li><a href="#" class="link-primary sug">Compare risk appetite vs risk tolerance</a></li>
            <li><a href="#" class="link-primary sug">Explain chain of custody with an example</a></li>
          </ul>
        </div>
      </div>
    """

    content = Template("""
    <div class="row">
      <div class="col-lg-3 mb-3">
        <div class="card">
          <div class="card-body">
            <h6 class="mb-2">Domains</h6>
            $chips
          </div>
        </div>
        $suggestions
      </div>
      <div class="col-lg-9">
        <div class="card">
          <div class="card-header"><h4 class="mb-0">AI Tutor</h4></div>
          <div class="card-body">
            <div class="alert alert-info">
              <strong>General:</strong> Ask about any CPP domain. I can help you compare topics, plan your study path, or explain tricky concepts.<br/>
              <em>Choose a domain on the left for a quick intro, then ask your next question.</em>
            </div>
            <div id="domainIntro" class="mb-3"></div>
            <div id="chat" style="height: 360px; overflow-y: auto; border: 1px solid #eee; padding: 10px; margin-bottom: 12px;"></div>
            <div class="input-group">
              <input type="text" id="userInput" class="form-control" placeholder="Ask about any CPP topic..." />
              <button id="sendBtn" class="btn btn-primary">Send</button>
            </div>
          </div>
        </div>
      </div>
    </div>
    <script>
      const chatDiv = document.getElementById('chat');
      const input = document.getElementById('userInput');
      const sendBtn = document.getElementById('sendBtn');
      const chips = document.querySelectorAll('.chip');

      function append(role, text) {
        const el = document.createElement('div');
        el.className = role === 'user' ? 'text-end mb-2' : 'text-start mb-2';
        el.innerHTML = '<span class="badge bg-' + (role === 'user' ? 'primary' : 'secondary') + '">' + (role === 'user' ? 'You' : 'Tutor') + '</span> ' +
                       '<div class="mt-1 p-2 border rounded">' + text.replace(/</g,'&lt;') + '</div>';
        chatDiv.appendChild(el);
        chatDiv.scrollTop = chatDiv.scrollHeight;
      }

      async function send() {
        const q = input.value.trim();
        if (!q) return;
        append('user', q);
        input.value = '';
        try {
          const res = await fetch('/chat', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({message: q})
          });
          const data = await res.json();
          if (data.response) append('assistant', data.response);
          else append('assistant', data.error || 'Sorry, something went wrong.');
        } catch (e) {
          append('assistant', 'Network error.');
        }
      }

      function loadDomainIntro(domainKey, label) {
        if (!domainKey || domainKey === 'general') {
          document.getElementById('domainIntro').innerHTML = '';
          return;
        }
        const summaries = {
          'security-principles': 'Security governance, risk frameworks, and layered controls.',
          'business-principles': 'Contracts, budgeting, procurement, and metrics.',
          'investigations': 'Evidence handling, interviews, and reporting.',
          'personnel-security': 'Screening, insider threat, and roles/duties.',
          'physical-security': 'CPTED, perimeter design, locks, lighting, access.',
          'information-security': 'CIA triad, policies, and cyber threats.',
          'crisis-management': 'BCP/DRP, incident command, and exercises.'
        };
        const s = summaries[domainKey] || 'Overview coming soon.';
        document.getElementById('domainIntro').innerHTML = '<div class="alert alert-secondary"><strong>' + label + ':</strong> ' + s + ' <em>What would you like to learn next?</em></div>';
      }

      sendBtn.addEventListener('click', send);
      input.addEventListener('keydown', (e) => { if (e.key === 'Enter') send(); });

      // Suggestions click
      document.querySelectorAll('.sug').forEach(a => {
        a.addEventListener('click', (e) => {
          e.preventDefault();
          input.value = e.target.textContent;
          input.focus();
        });
      });

      // Domain chips
      chips.forEach(ch => {
        ch.addEventListener('click', () => {
          chips.forEach(c => c.classList.add('chip-outline'));
          chips.forEach(c => c.classList.remove('brand'));
          ch.classList.remove('chip-outline');
          ch.classList.add('brand');
          const key = ch.getAttribute('data-domain');
          const label = ch.textContent;
          loadDomainIntro(key, label);
          input.placeholder = 'Ask about ' + (label || 'any CPP topic') + '...';
        });
      });
    </script>
    """)
    chips_html = "".join(domain_html)
    content = content.substitute(chips=chips_html, suggestions=suggestions_html)
    return render_base_template("Study", content, user=user)

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

# -------------------------------- Flashcards (SM-2) ---------------------------
@app.route('/flashcards')
@subscription_required
def flashcards_page():
    user = User.query.get(session['user_id'])

    # Domain chips with counts placeholders (filled by JS)
    chips = ['<span class="chip chip-outline small me-1" data-domain="all">Random</span>']
    chips.append('<span class="chip chip-outline small me-1" data-domain="security-principles">Security Principles</span>')
    chips.append('<span class="chip chip-outline small me-1" data-domain="business-principles">Business Principles</span>')
    chips.append('<span class="chip chip-outline small me-1" data-domain="investigations">Investigations</span>')
    chips.append('<span class="chip chip-outline small me-1" data-domain="personnel-security">Personnel Security</span>')
    chips.append('<span class="chip chip-outline small me-1" data-domain="physical-security">Physical Security</span>')
    chips.append('<span class="chip chip-outline small me-1" data-domain="information-security">Information Security</span>')
    chips.append('<span class="chip chip-outline small me-1" data-domain="crisis-management">Crisis Management</span>')

    page = Template("""
    <div class="row">
      <div class="col-lg-3 mb-3">
        <div class="card">
          <div class="card-body">
            <h6 class="mb-2">Flashcard Domains</h6>
            <div id="fcDomains">$chips</div>
            <hr/>
            <div id="fcCounts" class="small text-muted"></div>
          </div>
        </div>
        <div class="card mt-3">
          <div class="card-body">
            <h6 class="mb-2">How to use</h6>
            <p class="mb-2">Click the card to <strong>flip</strong> between question and answer.</p>
            <p class="mb-2">Use buttons below or keyboard shortcuts:</p>
            <ul class="mb-2">
              <li><span class="kbd">J</span> Flip</li>
              <li><span class="kbd">K</span> Next</li>
            </ul>
            <p class="mb-0"><strong>Don’t know</strong>: we’ll show it again sooner. <strong>Know</strong>: we schedule it further out using spaced repetition.</p>
          </div>
        </div>
      </div>

      <div class="col-lg-9">
        <div class="card">
          <div class="card-header d-flex justify-content-between align-items-center">
            <h4 class="mb-0">Flashcards</h4>
            <div><span class="badge bg-primary" id="deckLabel">Random</span></div>
          </div>
          <div class="card-body">
            <div class="card-flash mb-3">
              <div id="fcFace" class="card-face">
                <div class="card-side card-front" id="fcFront"></div>
                <div class="card-side card-back" id="fcBack"></div>
              </div>
            </div>
            <div class="d-flex justify-content-center gap-2">
              <button id="btnFlip" class="btn btn-outline-secondary">Flip (J)</button>
              <button id="btnDontKnow" class="btn btn-danger">Don’t know</button>
              <button id="btnKnow" class="btn btn-success">Know</button>
              <button id="btnNext" class="btn btn-outline-primary">Next (K)</button>
            </div>
          </div>
        </div>
      </div>
    </div>

    <script>
      const deckLabel = document.getElementById('deckLabel');
      const fcFace = document.getElementById('fcFace');
      const fcFront = document.getElementById('fcFront');
      const fcBack = document.getElementById('fcBack');
      const btnFlip = document.getElementById('btnFlip');
      const btnKnow = document.getElementById('btnKnow');
      const btnDont = document.getElementById('btnDontKnow');
      const btnNext = document.getElementById('btnNext');
      const chips = document.querySelectorAll('#fcDomains .chip');

      let currentDomain = 'all';
      let currentCard = null;

      function setCountsHtml(counts) {
        const parts = [];
        for (const k in counts) {
          const c = counts[k];
          parts.push('<div class="mb-1"><strong>' + c.label + ':</strong> Due ' + c.due + ' | New ' + c.new + '</div>');
        }
        document.getElementById('fcCounts').innerHTML = parts.join('');
      }

      async function refreshCounts() {
        try {
          const res = await fetch('/api/flashcards/summary');
          const data = await res.json();
          setCountsHtml(data.counts || {});
        } catch(e) {
          // no-op
        }
      }

      function flip() {
        fcFace.classList.toggle('flip');
      }

      function clearCard(text) {
        fcFront.textContent = text || 'Loading card...';
        fcBack.textContent = '';
        fcFace.classList.remove('flip');
      }

      async function loadNext() {
        try {
          clearCard('Loading card...');
          const res = await fetch('/api/flashcards/next', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({domain: currentDomain})
          });
          const data = await res.json();
          if (data && data.card) {
            currentCard = data.card;
            fcFront.textContent = data.card.front;
            fcBack.textContent = data.card.back;
            fcFace.classList.remove('flip');
          } else {
            currentCard = null;
            fcFront.textContent = 'No cards available right now in this domain.';
            fcBack.textContent = 'Try another domain or Random.';
          }
          refreshCounts();
        } catch (e) {
          currentCard = null;
          fcFront.textContent = 'Network error loading card.';
          fcBack.textContent = '';
        }
      }

      async function grade(q) {
        if (!currentCard) { await loadNext(); return; }
        try {
          await fetch('/api/flashcards/grade', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ domain: currentDomain, card_hash: currentCard.card_hash, quality: q })
          });
        } catch (e) {}
        // Fast follow-up: show next card
        await loadNext();
      }

      // Buttons
      btnFlip.addEventListener('click', flip);
      btnKnow.addEventListener('click', () => grade(4));
      btnDont.addEventListener('click', () => grade(2));
      btnNext.addEventListener('click', loadNext);

      // Keyboard shortcuts
      document.addEventListener('keydown', (e) => {
        if (e.key.toLowerCase() === 'j') flip();
        if (e.key.toLowerCase() === 'k') loadNext();
      });

      // Domain selection
      chips.forEach(ch => {
        ch.addEventListener('click', () => {
          chips.forEach(c => c.classList.add('chip-outline'));
          ch.classList.remove('chip-outline');
          currentDomain = ch.getAttribute('data-domain') || 'all';
          deckLabel.textContent = ch.textContent.trim() || 'Random';
          loadNext();
        });
      });

      // Init
      (async () => {
        refreshCounts();
        loadNext();
      })();
    </script>
    """)
    content = page.substitute(chips="".join(chips))
    return render_base_template("Flashcards", content, user=user)

# ---- Flashcards API
@app.get('/api/flashcards/summary')
@subscription_required
def api_flashcards_summary():
    user_id = session['user_id']
    now = datetime.utcnow()

    def count_for_domain(dom_key, label):
        bank = _get_bank_for_domain(dom_key if dom_key != 'all' else 'all')
        bank_hashes = {_hash_card(c['front']) for c in bank}
        due = db.session.query(func.count(FlashcardProgress.id)).filter(
            FlashcardProgress.user_id == user_id,
            FlashcardProgress.next_due != None,
            FlashcardProgress.next_due <= now,
            (FlashcardProgress.domain == dom_key) | (dom_key == 'all')
        ).scalar() or 0

        seen_hashes = set(r[0] for r in db.session.query(FlashcardProgress.card_hash).filter(
            FlashcardProgress.user_id == user_id
        ).all())
        new_count = len([h for h in bank_hashes if h not in seen_hashes])
        return {"label": label, "due": int(due), "new": int(new_count)}

    counts = {
        "all": count_for_domain("all", "Random (All Domains)"),
        "security-principles": count_for_domain("security-principles", "Security Principles"),
        "business-principles": count_for_domain("business-principles", "Business Principles"),
        "investigations": count_for_domain("investigations", "Investigations"),
        "personnel-security": count_for_domain("personnel-security", "Personnel Security"),
        "physical-security": count_for_domain("physical-security", "Physical Security"),
        "information-security": count_for_domain("information-security", "Information Security"),
        "crisis-management": count_for_domain("crisis-management", "Crisis Management"),
    }
    return jsonify({"counts": counts})

@app.post('/api/flashcards/next')
@subscription_required
def api_flashcards_next():
    user_id = session['user_id']
    data = request.get_json() or {}
    dom = (data.get('domain') or 'all').strip()

    now = datetime.utcnow()

    # 1) Due card first
    q = FlashcardProgress.query.filter(
        FlashcardProgress.user_id == user_id,
        FlashcardProgress.next_due != None,
        FlashcardProgress.next_due <= now
    )
    if dom != 'all':
        q = q.filter(FlashcardProgress.domain == dom)
    due_row = q.order_by(FlashcardProgress.next_due.asc()).first()

    def format_card(front, back, domain_key):
        return {"front": front, "back": back, "domain": domain_key, "card_hash": _hash_card(front)}

    if due_row:
        # find original card (front/back) from bank by hash
        bank = _get_bank_for_domain(due_row.domain or 'general')
        for c in bank:
            if _hash_card(c['front']) == due_row.card_hash:
                return jsonify({"card": format_card(c['front'], c['back'], c['domain'])})

    # 2) New card from bank (not yet in progress)
    bank = _get_bank_for_domain(dom)
    if dom == 'all':
        random.shuffle(bank)
    seen_hashes = set(r[0] for r in db.session.query(FlashcardProgress.card_hash).filter(
        FlashcardProgress.user_id == user_id
    ).all())

    for c in bank:
        h = _hash_card(c['front'])
        if h not in seen_hashes:
            return jsonify({"card": format_card(c['front'], c['back'], c['domain'])})

    # 3) If nothing due and nothing new: return any card from bank (graceful fallback)
    if bank:
        c = random.choice(bank)
        return jsonify({"card": format_card(c['front'], c['back'], c['domain'])})

    return jsonify({"card": None})

@app.post('/api/flashcards/grade')
@subscription_required
def api_flashcards_grade():
    user_id = session['user_id']
    data = request.get_json() or {}
    dom = (data.get('domain') or 'all').strip()
    card_hash = data.get('card_hash')
    quality = int(data.get('quality', 2))  # 4=Know, 2=Don't know

    if not card_hash:
        return jsonify({"ok": False, "error": "Missing card_hash"}), 400

    # Find domain if 'all'
    if dom == 'all':
        # attempt to resolve domain by checking bank
        found_domain = None
        for d, items in FLASHCARD_BANK.items():
            for c in items:
                if _hash_card(c['front']) == card_hash:
                    found_domain = d
                    break
            if found_domain:
                break
        dom = found_domain or 'general'

    row = FlashcardProgress.query.filter_by(user_id=user_id, card_hash=card_hash).first()
    if not row:
        row = FlashcardProgress(
            user_id=user_id,
            card_hash=card_hash,
            domain=dom,
            efactor=2.5,
            reps=0,
            interval=0,
            last_seen=None,
            next_due=None
        )
        db.session.add(row)
        db.session.commit()

    new_ef, new_reps, new_interval = sm2_update(row.efactor or 2.5, row.reps or 0, row.interval or 0, quality)
    row.efactor = new_ef
    row.reps = new_reps
    row.interval = new_interval
    row.last_seen = datetime.utcnow()
    row.next_due = datetime.utcnow() + timedelta(days=new_interval)
    db.session.commit()

    # Record event + progress (use "is_correct" True for Know)
    is_correct = (quality >= 3)
    # For QuestionEvent, we don't have multiple-choice options; store hash only
    try:
        evt = QuestionEvent(
            user_id=user_id,
            question_hash=card_hash,
            domain=dom,
            topic=None,
            source='flashcard',
            is_correct=is_correct,
            response_time_s=None
        )
        db.session.add(evt)
        db.session.commit()
    except Exception as e:
        print(f"flashcard event error: {e}")
        db.session.rollback()

    try:
        update_user_progress_on_answer(user_id, dom, None, is_correct)
    except Exception as e:
        print(f"flashcard progress update error: {e}")

    return jsonify({"ok": True})

# ------------------------------ Quizzes ---------------------------------------
@app.route('/quiz-selector')
@subscription_required
def quiz_selector():
    user = User.query.get(session['user_id'])

    # Build a clean selector with domain chips and difficulty/size options
    domain_chips = ['<span class="chip chip-outline me-1" data-domain="general">All Domains</span>']
    for key, meta in CPP_DOMAINS.items():
        domain_chips.append(f'<span class="chip chip-outline me-1" data-domain="{key}">{meta["name"]}</span>')

    content = Template("""
    <div class="row">
      <div class="col-12"><h2>Select a Quiz</h2></div>
      <div class="col-12"><p>Pick a mode, a domain (optional), and how many questions. Then start!</p></div>
    </div>
    <div class="row g-3">
      <div class="col-lg-4">
        <div class="card h-100">
          <div class="card-body">
            <h6>Quiz Mode</h6>
            <select id="quizMode" class="form-select mb-3">
              <option value="practice">Practice</option>
              <option value="domain-specific">Domain-Specific</option>
              <option value="quick-review">Quick Review</option>
              <option value="difficult">Advanced Challenge</option>
            </select>
            <h6>Domain</h6>
            <div id="domainChips">$chips</div>
            <h6 class="mt-3">Difficulty</h6>
            <select id="difficulty" class="form-select">
              <option value="easy">Easy</option>
              <option value="medium" selected>Medium</option>
              <option value="hard">Hard</option>
            </select>
          </div>
        </div>
      </div>
      <div class="col-lg-8">
        <div class="card h-100">
          <div class="card-body d-flex flex-column">
            <h5 class="mb-3">How many questions?</h5>
            <div class="mb-3">
              <button class="btn btn-outline-primary me-2 qcount" data-n="5">5</button>
              <button class="btn btn-outline-primary me-2 qcount" data-n="10">10</button>
              <button class="btn btn-outline-primary me-2 qcount" data-n="15">15</button>
              <button class="btn btn-outline-primary me-2 qcount" data-n="20">20</button>
            </div>
            <div class="mt-auto">
              <button id="startQuiz" class="btn btn-success">Start Quiz</button>
            </div>
          </div>
        </div>
      </div>
    </div>

    <script>
      let domain = 'general';
      document.querySelectorAll('#domainChips .chip').forEach(ch => {
        ch.addEventListener('click', () => {
          document.querySelectorAll('#domainChips .chip').forEach(c => c.classList.add('chip-outline'));
          ch.classList.remove('chip-outline');
          domain = ch.getAttribute('data-domain') || 'general';
        });
      });

      let qcount = null;
      document.querySelectorAll('.qcount').forEach(b => b.addEventListener('click', () => {
        document.querySelectorAll('.qcount').forEach(x => x.classList.remove('btn-primary'));
        document.querySelectorAll('.qcount').forEach(x => x.classList.add('btn-outline-primary'));
        b.classList.remove('btn-outline-primary');
        b.classList.add('btn-primary');
        qcount = parseInt(b.getAttribute('data-n'), 10);
      }));

      document.getElementById('startQuiz').addEventListener('click', () => {
        const mode = document.getElementById('quizMode').value;
        const diff = document.getElementById('difficulty').value;
        let url = '/quiz/' + encodeURIComponent(mode) + '?difficulty=' + encodeURIComponent(diff);
        if (domain) url += '&domain=' + encodeURIComponent(domain);
        if (qcount) url += '&count=' + encodeURIComponent(qcount);
        window.location.href = url;
      });
    </script>
    """)
    content = content.substitute(chips="".join(domain_chips))
    return render_base_template("Quizzes", content, user=user)

@app.route('/quiz/<quiz_type>')
@subscription_required
def quiz(quiz_type):
    user = User.query.get(session['user_id'])
    if quiz_type not in QUIZ_TYPES:
        flash('Invalid quiz type.', 'danger')
        return redirect(url_for('quiz_selector'))

    domain = request.args.get('domain', 'general')
    difficulty = request.args.get('difficulty', 'medium')
    try:
        requested = int(request.args.get('count', QUIZ_TYPES[quiz_type]['questions']))
    except ValueError:
        requested = QUIZ_TYPES[quiz_type]['questions']

    session['quiz_start_time'] = datetime.utcnow().timestamp()

    # Generate quiz with requested count
    quiz_data = generate_fallback_quiz(quiz_type, domain, difficulty, max(1, min(100, requested)))
    random.shuffle(quiz_data["questions"])
    quiz_json = json.dumps(quiz_data)

    brand = domain_brand(domain)

    page = Template("""
    <style>:root{ --brand: $brand; }</style>
    <div class="row">
      <div class="col-md-10 mx-auto">
        <div class="card">
          <div class="card-header d-flex justify-content-between align-items-center">
            <h4 class="mb-0">$title</h4>
            <div class="d-flex gap-2">
              <button id="submitBtnTop" class="btn btn-brand">Submit</button>
            </div>
          </div>
          <div class="card-body" id="quizContainer"></div>
          <div class="card-footer d-flex justify-content-between align-items-center">
            <div class="q-progress w-100 me-3"><div id="qProg"></div></div>
            <button id="submitBtn" class="btn btn-brand">Submit</button>
          </div>
        </div>
        <div class="mt-4" id="results"></div>
      </div>
    </div>
    <script>
      const QUIZ_DATA = $quiz_json;

      function renderQuiz() {
        const container = document.getElementById('quizContainer');
        container.innerHTML = '';
        QUIZ_DATA.questions.forEach((q, idx) => {
          const card = document.createElement('div');
          card.className = 'mb-3 p-3 border rounded';
          const title = document.createElement('h5');
          title.textContent = 'Q' + (idx + 1) + '. ' + q.question;
          card.appendChild(title);

          const options = q.options || {};
          for (const key in options) {
            const optId = 'q' + idx + '_' + key;
            const div = document.createElement('div');
            div.className = 'form-check';
            const input = document.createElement('input');
            input.className = 'form-check-input';
            input.type = 'radio';
            input.name = 'q' + idx;
            input.id = optId;
            input.value = key;
            input.addEventListener('change', updateProgress);
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

      function updateProgress() {
        const total = (QUIZ_DATA.questions || []).length;
        let answered = 0;
        (QUIZ_DATA.questions || []).forEach((q, i) => {
          const sel = document.querySelector('input[name="q'+i+'"]:checked');
          if (sel) answered += 1;
        });
        const pct = Math.round((answered/total)*100);
        document.getElementById('qProg').style.width = pct + '%';
      }

      async function submitQuiz() {
        const answers = {};
        (QUIZ_DATA.questions || []).forEach((q, idx) => {
          const selected = document.querySelector('input[name="q' + idx + '"]:checked');
          answers[String(idx)] = selected ? selected.value : null;
        });
        try {
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
            html += '<hr/><h5>Review</h5>';
            data.results.forEach(r => {
              const klass = r.is_correct ? 'text-success' : 'text-danger';
              html += '<div class="mb-2"><strong>Q' + r.index + '.</strong> ' + r.question + '<br/>' +
                      '<span class="'+klass+'">Your answer: ' + (r.user_letter ? (r.user_letter + ') ' + (r.user_text||'')) : '—') + '</span><br/>' +
                      '<span class="text-success">Correct: ' + (r.correct_letter ? (r.correct_letter + ') ' + (r.correct_text||'')) : '') + '</span><br/>' +
                      (r.explanation ? ('<em>' + r.explanation + '</em>') : '') +
                      '</div>';
            });
          }
          html += '</div></div>';
          resultsDiv.innerHTML = html;
          window.scrollTo({ top: resultsDiv.offsetTop - 20, behavior: 'smooth' });
        } catch (e) {
          resultsDiv.innerHTML = '<div class="alert alert-danger">Submission failed.</div>';
        }
      }

      document.getElementById('submitBtn').addEventListener('click', submitQuiz);
      document.getElementById('submitBtnTop').addEventListener('click', submitQuiz);
      renderQuiz();
      updateProgress();
    </script>
    """)
    content = page.substitute(title=quiz_data['title'], quiz_json=quiz_json, brand=brand)
    return render_base_template("Quiz", content, user=user)

@app.route('/mock-exam')
@subscription_required
def mock_exam():
    try:
        requested = int(request.args.get('count', 100))
    except ValueError:
        requested = 100
    num_questions = max(25, min(100, requested))

    quiz_data = generate_fallback_quiz('mock-exam', domain=None, difficulty='medium', num_questions=num_questions)
    random.shuffle(quiz_data["questions"])
    quiz_json = json.dumps(quiz_data)

    page = Template("""
    <div class="row">
      <div class="col-md-10 mx-auto">
        <div class="card">
          <div class="card-header d-flex justify-content-between align-items-center">
            <h4 class="mb-0">Mock Exam ($num Q)</h4>
            <button id="submitBtnTop" class="btn btn-success">Submit</button>
          </div>
          <div class="card-body" id="quizContainer"></div>
          <div class="card-footer d-flex justify-content-end">
            <button id="submitBtn" class="btn btn-success">Submit</button>
          </div>
        </div>
        <div class="mt-4" id="results"></div>
      </div>
    </div>
    <script>
      const QUIZ_DATA = $quiz_json;

      function renderQuiz() {
        const container = document.getElementById('quizContainer');
        container.innerHTML = '';
        QUIZ_DATA.questions.forEach((q, idx) => {
          const card = document.createElement('div');
          card.className = 'mb-3 p-3 border rounded';
          const title = document.createElement('h5');
          title.textContent = 'Q' + (idx + 1) + '. ' + q.question;
          card.appendChild(title);

          const options = q.options || {};
          for (const key in options) {
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
        // Ensure no unanswered: scroll to first unanswered
        let firstUnanswered = null;
        (QUIZ_DATA.questions || []).forEach((q, idx) => {
          const selected = document.querySelector('input[name="q' + idx + '"]:checked');
          if (!selected && firstUnanswered === null) firstUnanswered = idx;
        });
        if (firstUnanswered !== null) {
          const target = document.querySelector('input[name="q' + firstUnanswered + '"]');
          if (target) {
            target.scrollIntoView({behavior: 'smooth', block: 'center'});
            target.parentElement.parentElement.classList.add('border','border-danger');
          }
          return;
        }

        const answers = {};
        (QUIZ_DATA.questions || []).forEach((q, idx) => {
          const selected = document.querySelector('input[name="q' + idx + '"]:checked');
          answers[String(idx)] = selected ? selected.value : null;
        });
        try {
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
            html += '<hr/><h5>Review</h5>';
            data.results.forEach(r => {
              const klass = r.is_correct ? 'text-success' : 'text-danger';
              html += '<div class="mb-2"><strong>Q' + r.index + '.</strong> ' + r.question + '<br/>' +
                      '<span class="'+klass+'">Your answer: ' + (r.user_letter ? (r.user_letter + ') ' + (r.user_text||'')) : '—') + '</span><br/>' +
                      '<span class="text-success">Correct: ' + (r.correct_letter ? (r.correct_letter + ') ' + (r.correct_text||'')) : '') + '</span><br/>' +
                      (r.explanation ? ('<em>' + r.explanation + '</em>') : '') +
                      '</div>';
            });
          }
          html += '</div></div>';
          resultsDiv.innerHTML = html;
          window.scrollTo({ top: resultsDiv.offsetTop - 20, behavior: 'smooth' });
        } catch (e) {
          resultsDiv.innerHTML = '<div class="alert alert-danger">Submission failed.</div>';
        }
      }

      document.getElementById('submitBtn').addEventListener('click', submitQuiz);
      document.getElementById('submitBtnTop').addEventListener('click', submitQuiz);
      renderQuiz();
    </script>
    """)
    content = page.substitute(num=num_questions, quiz_json=quiz_json)
    return render_base_template("Mock Exam", content, user=User.query.get(session['user_id']))

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

            # record QuestionEvent & update progress by domain in question (if provided)
            q_domain = q.get('domain', domain) or domain
            try:
                record_question_event(session['user_id'], q, domain=q_domain, topic=None, is_correct=is_correct, source='quiz')
                update_user_progress_on_answer(session['user_id'], q_domain, None, is_correct)
            except Exception as e:
                print(f"submit-quiz tracking error: {e}")

            detailed_results.append({
                'index': i + 1,
                'question': q.get('question', ''),
                'correct_letter': correct_letter,
                'correct_text': options.get(correct_letter, ''),
                'user_letter': user_letter,
                'user_text': options.get(user_letter, '') if user_letter else None,
                'explanation': q.get('explanation', ''),
                'is_correct': bool(is_correct),
                'domain': q_domain
            })

        score = (correct_count / total) * 100 if total else 0.0

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
            insights.append("Good job. Review missed questions to strengthen weak areas.")
        elif score >= 70:
            insights.append("Fair performance. Focus on the areas you missed.")
        else:
            insights.append("Consider more study time in this area before the exam.")
        if time_taken > 0 and total > 0:
            avg = time_taken / total
            if avg < 1:
                insights.append("Great pace. You answered efficiently.")
            elif avg > 3:
                insights.append("Consider practicing to improve your speed.")

        log_activity(session['user_id'], 'quiz_completed',
                     f'{quiz_type}: {correct_count}/{total} in {time_taken} min')

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

# ----------------------------- Progress Page ----------------------------------
@app.route('/progress')
@subscription_required
def progress_page():
    user_id = session['user_id']
    # Pull progress rows
    rows = UserProgress.query.filter_by(user_id=user_id).all()

    # Aggregate by domain
    by_domain = {}
    for r in rows:
        key = r.domain or 'general'
        if key not in by_domain:
            by_domain[key] = {"avg": 0.0, "count": 0, "level": 'needs_practice'}
        d = by_domain[key]
        d["avg"] = ((d["avg"] * d["count"]) + (r.average_score or 0.0)) / float((d["count"] + 1) or 1)
        d["count"] += r.question_count or 0
        # choose strongest level
        levels = ['needs_practice', 'good', 'mastered']
        best = max([r.mastery_level, d["level"]], key=lambda x: levels.index(x))
        d["level"] = best

    # Overall
    total_q = sum((v["count"] or 0) for v in by_domain.values())
    overall = 0.0
    if by_domain:
        overall = sum((v["avg"] or 0.0) for v in by_domain.values()) / len(by_domain)

    # Build tiles
    def level_class(level):
        if level == 'mastered': return 'dom-good'
        if level == 'good': return 'dom-ok'
        return 'dom-bad'

    tiles = []
    # Ensure deterministic order per CPP_DOMAINS
    order = list(CPP_DOMAINS.keys())
    order.insert(0, 'general')
    seen = set()
    for dk in order:
        if dk in seen: continue
        seen.add(dk)
        label = 'General' if dk == 'general' else CPP_DOMAINS.get(dk, {}).get('name', dk)
        v = by_domain.get(dk, {"avg": 0.0, "count": 0, "level": "needs_practice"})
        badge = level_class(v["level"])
        tiles.append(f"""
          <div class="col-md-6 col-lg-4">
            <div class="card mb-3">
              <div class="card-body">
                <div class="d-flex justify-content-between align-items-center mb-2">
                  <h6 class="mb-0">{label}</h6>
                  <span class="badge {badge}">{v["level"].replace('_',' ').title()}</span>
                </div>
                <div>Average score: <strong>{v["avg"]:.1f}%</strong></div>
                <div>Questions answered: <strong>{v["count"]}</strong></div>
              </div>
            </div>
          </div>
        """)

    page = Template("""
    <div class="row">
      <div class="col-8">
        <h2>Your Progress</h2>
        <p class="text-muted">Green = strong, Orange = good, Red = needs practice.</p>
      </div>
      <div class="col-4 d-flex justify-content-end align-items-start">
        <div class="dial" style="--p:$p;"><div>${overall}%</div></div>
      </div>
    </div>
    <div class="row mt-2">
      $tiles
    </div>
    """)
    content = page.substitute(
        p=int(round(overall)),
        overall=int(round(overall)),
        tiles="".join(tiles)
    )
    return render_base_template("Progress", content, user=User.query.get(user_id))

# ----------------------------- Subscription & Stripe --------------------------
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
        <div class="card h-100">
          <div class="card-body">
            <h4>Monthly</h4>
            <p>$39.99 / month</p>
            <form method="POST" action="/create-checkout-session">
              <input type="hidden" name="plan_type" value="monthly" />
              <div class="mb-2">
                <input type="text" class="form-control" name="discount_code" placeholder="Discount code (optional)">
              </div>
              <button class="btn btn-primary">Choose Monthly</button>
            </form>
          </div>
        </div>
      </div>
      <div class="col-md-6">
        <div class="card h-100">
          <div class="card-body">
            <h4>6 Months</h4>
            <p>$99 / 6 months</p>
            <form method="POST" action="/create-checkout-session">
              <input type="hidden" name="plan_type" value="6month" />
              <div class="mb-2">
                <input type="text" class="form-control" name="discount_code" placeholder="Discount code (optional)">
              </div>
              <button class="btn btn-success">Choose 6 Months</button>
            </form>
          </div>
        </div>
      </div>
    </div>
    """
    header = ""
    if trial_days_left is not None:
        header = f'<div class="alert alert-info mb-3">Trial days left: {trial_days_left}</div>'

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
            product_data={
                'name': selected['name'] + (f' ({discount_code} DISCOUNT)' if discount_applied else ''),
                'description': 'AI tutor, quizzes, and study tools'
            }
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

# ----------------------------- Study Session Tracking -------------------------
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

# --------------------------------- Diag ---------------------------------------
@app.get("/diag/openai")
def diag_openai():
    has_key = bool(os.environ.get("OPENAI_API_KEY"))
    model = os.environ.get("OPENAI_CHAT_MODEL", OPENAI_CHAT_MODEL)
    try:
        headers = {
            'Authorization': f'Bearer {os.environ.get("OPENAI_API_KEY","")}',
            'Content-Type': 'application/json'
        }
        data = {
            'model': model,
            'messages': [{"role": "user", "content": "Say 'pong' if you can hear me."}],
            'max_tokens': 10,
            'temperature': 0
        }
        response = requests.post(f'{OPENAI_API_BASE}/chat/completions', headers=headers, json=data, timeout=20)
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
    try:
        db.session.execute(text('SELECT 1'))
        user_count = db.session.query(User).count()
        quiz_count = db.session.query(QuizResult).count()
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

# ----------------------------- App Factory / Run ------------------------------
def create_app(config_name='default'):
    return app

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    print(f"Starting CPP Test Prep on port {port}")
    print(f"Debug: {debug}")
    print(f"DB configured: {bool(app.config.get('SQLALCHEMY_DATABASE_URI'))}")
    print(f"OpenAI configured: {bool(OPENAI_API_KEY)}")
    print(f"Stripe configured: {bool(stripe.api_key)}")
    app.run(host='0.0.0.0', port=port, debug=debug)
