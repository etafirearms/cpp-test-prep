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

# For SQL text/inspection helpers
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
    mastery_level = db.Column(db.String(20), default='needs_practice')  # needs_practice | good | mastered
    average_score = db.Column(db.Float, default=0.0)  # 0-100
    question_count = db.Column(db.Integer, default=0)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow)
    consecutive_good_scores = db.Column(db.Integer, default=0)

    __table_args__ = (
        db.UniqueConstraint('user_id', 'domain', 'topic', name='uq_userprogress_user_domain_topic'),
    )

class QuestionEvent(db.Model):
    """
    One row per answered card/question.
    source: 'quiz' | 'mock' | 'flashcard' | 'tutor'
    """
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    question_hash = db.Column(db.String(64), nullable=False, index=True)  # sha256 of content
    domain = db.Column(db.String(50), nullable=True, index=True)
    topic = db.Column(db.String(100), nullable=True, index=True)
    source = db.Column(db.String(20), nullable=False)  # quiz/mock/flashcard/tutor
    is_correct = db.Column(db.Boolean, nullable=True)  # flashcards can be Know/Don't Know
    response_time_s = db.Column(db.Integer)  # optional
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    __table_args__ = (
        db.Index('ix_question_event_user_created', 'user_id', 'created_at'),
    )

class QuestionBank(db.Model):
    """
    Optional seed bank for verified questions/flashcards.
    """
    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(50), index=True)
    difficulty = db.Column(db.String(20), index=True)
    question = db.Column(db.Text, nullable=False)
    options_json = db.Column(db.Text)         # JSON dict of options
    correct = db.Column(db.String(5))         # e.g., "B"
    explanation = db.Column(db.Text)
    source_name = db.Column(db.String(120))
    source_url = db.Column(db.Text)
    is_verified = db.Column(db.Boolean, default=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

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

# ---------- tracking helpers (hash, record event, update progress, seen) ----------
def _hash_question_payload(question_obj: dict) -> str:
    """
    Stable SHA256 hash for a question so we can detect repeats.
    Uses question text + sorted options.
    """
    q_text = (question_obj or {}).get('question', '') or ''
    opts = (question_obj or {}).get('options', {}) or {}
    parts = [q_text.strip()]
    for key in sorted(opts.keys()):
        parts.append(f"{key}:{str(opts.get(key, '')).strip()}")
    raw = "||".join(parts)
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()

def record_question_event(
    user_id: int,
    question_obj: dict,
    domain: str = None,
    topic: str = None,
    is_correct: bool = None,
    response_time_s: int = None,
    source: str = 'quiz'
) -> None:
    """Insert one QuestionEvent row safely."""
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
    """
    Mastery banding:
    - mastered: avg >= 90 and streak >= 3
    - good:     avg >= 75 and streak >= 2
    - needs_practice: otherwise
    """
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
    """
    Lightweight rolling update for UserProgress.
    Call this per answer (wired in /submit-quiz).
    """
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
    """
    Return a set of question_hash values the user has seen recently.
    (Use this for non-repeating flashcards later.)
    """
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

# -----------------------------------------------------------------------------
# AI chat wrapper
# -----------------------------------------------------------------------------
def chat_with_ai(messages, user_id=None):
    """Thin wrapper to OpenAI Chat Completions with basic rate limiting and robust error handling."""
    global last_api_call
    try:
        # Friendly rate limit
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
            return "I’m having trouble authenticating right now. Please try again."
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
# Quiz generation
# -----------------------------------------------------------------------------
BASE_QUESTIONS = [
    {
        "question": "What is the primary purpose of a security risk assessment?",
        "options": {
            "A": "Identify all threats",
            "B": "Determine cost-effective mitigation",
            "C": "Eliminate all risks",
            "D": "Satisfy compliance"
        },
        "correct": "B",
        "explanation": "Risk assessments help determine cost-effective mitigation strategies.",
        "domain": "security-principles",
        "difficulty": "medium"
    },
    {
        "question": "In CPTED, natural surveillance primarily accomplishes what?",
        "options": {
            "A": "Reduces guard costs",
            "B": "Increases observation likelihood",
            "C": "Eliminates cameras",
            "D": "Provides legal protection"
        },
        "correct": "B",
        "explanation": "Natural surveillance increases the likelihood that criminal activity will be observed.",
        "domain": "physical-security",
        "difficulty": "medium"
    },
    {
        "question": "Which concept means applying multiple security layers so if one fails others still protect?",
        "options": {
            "A": "Security by Obscurity",
            "B": "Defense in Depth",
            "C": "Zero Trust",
            "D": "Least Privilege"
        },
        "correct": "B",
        "explanation": "Defense in Depth uses layered controls to maintain protection despite single-point failures.",
        "domain": "security-principles",
        "difficulty": "medium"
    },
    {
        "question": "In incident response, what is usually the FIRST priority?",
        "options": {
            "A": "Notify law enforcement",
            "B": "Contain the incident",
            "C": "Eradicate malware",
            "D": "Perform lessons learned"
        },
        "correct": "B",
        "explanation": "Containment prevents further damage before eradication and recovery.",
        "domain": "information-security",
        "difficulty": "medium"
    },
    {
        "question": "Background investigations primarily support which objective?",
        "options": {
            "A": "Regulatory compliance only",
            "B": "Improving marketing outcomes",
            "C": "Personnel Security risk reduction",
            "D": "Disaster response coordination"
        },
        "correct": "C",
        "explanation": "They help reduce personnel security risks such as insider threat.",
        "domain": "personnel-security",
        "difficulty": "medium"
    }
]

def generate_fallback_quiz(quiz_type, domain, difficulty, num_questions):
    # Filter pool by domain if provided (and not random)
    if domain and domain not in ('general', 'random'):
        pool = [q for q in BASE_QUESTIONS if q.get('domain') == domain]
        if not pool:
            pool = BASE_QUESTIONS[:]
    else:
        pool = BASE_QUESTIONS[:]

    # Randomize and repeat to fill up
    questions = []
    while len(questions) < num_questions:
        batch = pool[:]
        random.shuffle(batch)
        for q in batch:
            if len(questions) >= num_questions:
                break
            questions.append(q.copy())

    return {
        "title": f"CPP {quiz_type.title().replace('-', ' ')}",
        "quiz_type": quiz_type,
        "domain": domain or 'general',
        "difficulty": difficulty,
        "questions": questions[:num_questions]
    }

def generate_quiz(quiz_type, domain=None, difficulty='medium', count=None):
    config = QUIZ_TYPES.get(quiz_type, {'questions': 10})
    n = count if isinstance(count, int) and count > 0 else config['questions']
    return generate_fallback_quiz(quiz_type, domain, difficulty, n)

# -----------------------------------------------------------------------------
# HTML Base Template
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
            '    <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navcol" aria-controls="navcol" aria-expanded="false" aria-label="Toggle navigation">'
            '      <span class="navbar-toggler-icon"></span>'
            '    </button>'
            '    <div class="collapse navbar-collapse" id="navcol">'
            '      <div class="navbar-nav ms-auto">'
            '        <a class="nav-link" href="/dashboard">Dashboard</a>'
            '        <a class="nav-link" href="/study">Tutor</a>'
            '        <a class="nav-link" href="/flashcards">Flashcards</a>'
            '        <a class="nav-link" href="/quiz-selector">Quizzes</a>'
            '        <a class="nav-link" href="/mock-exam">Mock Exam</a>'
            '        <a class="nav-link" href="/progress">Progress</a>'
            '        <a class="nav-link" href="/subscribe">Subscribe</a>'
            '        <a class="nav-link" href="/logout">Logout</a>'
            '      </div>'
            '    </div>'
            '  </div>'
            '</nav>'
        )

    # Small CSS helpers, incl. gauge and domain chips
    css = """
    <style>
      .gauge-wrap {
        --p: 0%;
        width: 120px; height: 120px;
        border-radius: 50%;
        background:
          radial-gradient(farthest-side, white 79%, transparent 80% 100%),
          conic-gradient(#0d6efd var(--p), #e9ecef 0);
        display:flex; align-items:center; justify-content:center;
        font-weight:700; font-size:1.1rem;
      }
      .domain-chip {
        display:inline-block; margin:4px 6px 4px 0; padding:6px 10px;
        border-radius:18px; background:#e9f2ff; color:#0d6efd; cursor:pointer; user-select:none;
        border:1px solid #b6d4fe;
      }
      .domain-chip.active {
        background:#0d6efd; color:#fff; border-color:#0d6efd;
      }
      /* Flashcard styling */
      .fc-container { max-width: 620px; margin: 0 auto; }
      .flashcard {
        width: 560px; max-width: 100%;
        height: 340px;
        border-radius: 16px;
        box-shadow: 0 6px 24px rgba(0,0,0,0.12);
        background: #fff;
        padding: 20px 24px;
        margin: 12px auto;
        display:flex; align-items:center; justify-content:center;
        text-align:center; font-size:1.15rem; line-height:1.4;
      }
      .flashcard .small-muted { color:#6c757d; font-size:0.9rem; }
      .kbd { border:1px solid #ced4da; padding:2px 6px; border-radius:4px; font-family:monospace; }
    </style>
    """

    page = Template("""\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>$title - CPP Test Prep</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
  $css
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
    return page.substitute(title=title, nav=nav_html, content=content_html, disclaimer=disclaimer, css=css)

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
          <h1 class="display-5">CPP Test Prep</h1>
          <p class="lead">AI-powered study platform for the Certified Protection Professional exam</p>
        </div>
        <div class="row g-3">
          <div class="col-md-6">
            <div class="card h-100"><div class="card-body">
              <h5 class="card-title">🎯 Smart Quizzes</h5>
              <p class="card-text">Practice with questions across all CPP domains.</p>
            </div></div>
          </div>
          <div class="col-md-6">
            <div class="card h-100"><div class="card-body">
              <h5 class="card-title">🤖 AI Tutor</h5>
              <p class="card-text">Get explanations, examples, and study guidance.</p>
            </div></div>
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
            # Create Stripe customer
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

    # GET form
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

    # Compute overall progress (simple average of domain averages)
    user_progress = UserProgress.query.filter_by(user_id=user.id).all()
    if user_progress:
        avg_sum = sum([(p.average_score or 0.0) for p in user_progress])
        overall_pct = int(round(avg_sum / len(user_progress)))
    else:
        overall_pct = 0

    tmpl = Template("""
    <div class="row">
      <div class="col-12"><h1>Welcome back, $first_name!</h1></div>
      <div class="col-12">
        <div class="row mt-4 g-3">
          <div class="col-md-3">
            <div class="card bg-primary text-white h-100"><div class="card-body">
              <h6 class="mb-1">Trial/Plan</h6>
              <h3 class="mb-0">$days_left days left</h3>
            </div></div>
          </div>
          <div class="col-md-3">
            <div class="card bg-success text-white h-100"><div class="card-body">
              <h6 class="mb-1">Study Time</h6>
              <h3 class="mb-0">$study_time mins</h3>
            </div></div>
          </div>
          <div class="col-md-3">
            <div class="card h-100 d-flex align-items-center justify-content-center">
              <div class="gauge-wrap" style="--p:$overall_pct%;">
                <span>$overall_pct%</span>
              </div>
              <div class="small text-muted mt-2">Overall progress (Goal: 80%+)</div>
            </div>
          </div>
        </div>

        <div class="row mt-4 g-3">
          <div class="col-md-6">
            <div class="card h-100">
              <div class="card-body d-flex flex-column">
                <h5 class="mb-2">🤖 Tutor</h5>
                <p class="text-muted">Ask anything across CPP domains, see suggestions, and get clear explanations.</p>
                <a href="/study" class="btn btn-primary mt-auto">Open Tutor</a>
              </div>
            </div>
          </div>
          <div class="col-md-6">
            <div class="card h-100">
              <div class="card-body d-flex flex-column">
                <h5 class="mb-2">🃏 Flashcards</h5>
                <p class="text-muted">Spaced practice with instant flip (<span class="kbd">J</span>) and next (<span class="kbd">K</span>). Unlimited per session.</p>
                <a href="/flashcards" class="btn btn-secondary mt-auto">Open Flashcards</a>
              </div>
            </div>
          </div>

          <div class="col-md-6">
            <div class="card h-100">
              <div class="card-body d-flex flex-column">
                <h5 class="mb-2">📝 Quizzes</h5>
                <p class="text-muted">Build a quiz: choose domain & number of questions.</p>
                <a href="/quiz-selector" class="btn btn-success mt-auto">Start a Quiz</a>
              </div>
            </div>
          </div>

          <div class="col-md-6">
            <div class="card h-100">
              <div class="card-body d-flex flex-column">
                <h5 class="mb-2">🏁 Mock Exam</h5>
                <p class="text-muted">25/50/75/100 random questions across domains.</p>
                <a href="/mock-exam" class="btn btn-warning mt-auto">Start Mock Exam</a>
              </div>
            </div>
          </div>
        </div>

      </div>
    </div>
    """)
    content = tmpl.substitute(
        first_name=user.first_name,
        days_left=days_left,
        study_time=(user.study_time or 0),
        overall_pct=overall_pct
    )
    return render_base_template("Dashboard", content, user=user)

# --------------------------------- Study Chat ---------------------------------
@app.route('/study')
@subscription_required
def study():
    user = User.query.get(session['user_id'])
    session['study_start_time'] = datetime.utcnow().timestamp()

    domain_chips_html = ''.join([
        f'<span class="domain-chip" data-domain="{k}">{v["name"]}</span>'
        for k, v in CPP_DOMAINS.items()
    ])

    content = Template("""
    <div class="row">
      <div class="col-md-8 mx-auto">
        <div class="card">
          <div class="card-header d-flex align-items-center gap-2">
            <img src="https://robohash.org/ai?set=set3&size=80x80" alt="AI Tutor" class="rounded-circle me-2" width="36" height="36" />
            <h4 class="mb-0">Tutor</h4>
          </div>
          <div class="card-body">
            <div class="mb-2">Select a domain to see a short intro, then ask a question:</div>
            <div class="mb-3">$chips</div>
            <div id="intro" class="alert alert-secondary" style="display:none;"></div>

            <div id="chat" style="height: 360px; overflow-y: auto; border: 1px solid #eee; padding: 10px; margin-bottom: 12px;"></div>

            <div class="row">
              <div class="col-md-9">
                <div class="input-group">
                  <input type="text" id="userInput" class="form-control" placeholder="Ask about any CPP topic..." />
                  <button id="sendBtn" class="btn btn-primary">Send</button>
                </div>
              </div>
              <div class="col-md-3">
                <div class="card">
                  <div class="card-body">
                    <div class="fw-bold mb-2">Suggestions</div>
                    <div id="sugs">
                      <div class="small text-muted">Click to fill the ask box</div>
                      <ul id="sugList" class="mt-2 mb-0" style="padding-left:18px;"></ul>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <div class="small text-muted mt-2">Tip: Start with “Explain like I’m new to the topic” for a gentle ramp.</div>
          </div>
        </div>
      </div>
    </div>
    <script>
      const chatDiv = document.getElementById('chat');
      const input = document.getElementById('userInput');
      const sendBtn = document.getElementById('sendBtn');
      const introDiv = document.getElementById('intro');
      const sugList = document.getElementById('sugList');

      const domainSnippets = {
        "security-principles": "Security Principles & Practices: governance, risk, defense-in-depth, and program management.",
        "business-principles": "Business Principles & Practices: budgeting, contracts, and aligning security with business goals.",
        "investigations": "Investigations: planning, evidence collection, interviews, and reporting.",
        "personnel-security": "Personnel Security: screening, onboarding, insider threat, and termination processes.",
        "physical-security": "Physical Security: CPTED, access control, barriers, lighting, and surveillance.",
        "information-security": "Information Security: data protection, incident response, and cyber hygiene.",
        "crisis-management": "Crisis Management: BCP/DR, emergency response, ICS, and communications."
      };

      const domainSuggestions = {
        "security-principles": ["What is defense in depth?", "How do I prioritize risks?", "What KPIs make sense for a security program?"],
        "business-principles": ["Build a basic security budget", "CapEx vs OpEx tradeoffs in security", "Vendor management essentials"],
        "investigations": ["Chain of custody best practices", "Interview vs interrogation: differences", "Open-source intel basics"],
        "personnel-security": ["Effective background checks", "Detecting insider threats", "Termination checklists"],
        "physical-security": ["Layers of physical protection", "CPTED quick wins", "Access control models"],
        "information-security": ["Incident response phases", "Password policies vs MFA", "Phishing awareness essentials"],
        "crisis-management": ["BCP vs DR differences", "Crisis communications playbook", "Tabletop exercise ideas"]
      };

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
      sendBtn.addEventListener('click', send);
      input.addEventListener('keydown', (e) => { if (e.key === 'Enter') send(); });

      document.querySelectorAll('.domain-chip').forEach(chip => {
        chip.addEventListener('click', () => {
          document.querySelectorAll('.domain-chip').forEach(c => c.classList.remove('active'));
          chip.classList.add('active');
          const dom = chip.getAttribute('data-domain');
          introDiv.style.display = 'block';
          introDiv.innerText = domainSnippets[dom] || 'General CPP domain overview.';
          const list = domainSuggestions[dom] || [];
          sugList.innerHTML = '';
          list.forEach(s => {
            const li = document.createElement('li');
            const a = document.createElement('a');
            a.href = '#'; a.textContent = s;
            a.addEventListener('click', (ev) => { ev.preventDefault(); input.value = s; input.focus(); });
            li.appendChild(a);
            sugList.appendChild(li);
          });
        });
      });
    </script>
    """)
    return render_base_template("Study", content.substitute(chips=domain_chips_html), user=user)

@app.route('/chat', methods=['POST'])
@subscription_required
def chat():
    try:
        data = request.get_json() or {}
        user_message = (data.get('message') or '').strip()
        if not user_message:
            return jsonify({'error': 'Empty message'}), 400

        user_id = session['user_id']

        # Load or create chat history
        ch = ChatHistory.query.filter_by(user_id=user_id).first()
        if not ch:
            ch = ChatHistory(user_id=user_id, messages='[]')
            db.session.add(ch)
            db.session.commit()

        try:
            messages = json.loads(ch.messages) if ch.messages else []
        except json.JSONDecodeError:
            messages = []

        # Trim history for safety
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

# --------------------------------- Flashcards ---------------------------------
@app.route('/flashcards')
@subscription_required
def flashcards_page():
    user = User.query.get(session['user_id'])
    # Domain sidebar (blue blocks)
    chips = ['<div class="domain-chip active" data-domain="random">Random (All)</div>'] + [
        f'<div class="domain-chip" data-domain="{k}">{v["name"]}</div>'
        for k, v in CPP_DOMAINS.items()
    ]
    chips_html = ''.join(chips)

    content = Template("""
    <div class="row">
      <div class="col-md-3">
        <div class="card mb-3">
          <div class="card-header"><strong>Domains</strong></div>
          <div class="card-body">
            $chips
          </div>
        </div>

        <div class="card">
          <div class="card-header"><strong>How it works</strong></div>
          <div class="card-body">
            <ul class="mb-2">
              <li>Click the card to flip (<span class="kbd">J</span>).</li>
              <li>Next card: <span class="kbd">K</span>.</li>
              <li>Mark <em>Know</em> or <em>Don't know</em> to fill the buckets.</li>
            </ul>
            <div class="small text-muted">“Know” helps the system dial down repeats over time.</div>
          </div>
        </div>
      </div>

      <div class="col-md-9">
        <div class="fc-container">
          <div id="fcCard" class="flashcard">
            <div id="fcText">Loading flashcards…</div>
          </div>
          <div class="d-flex justify-content-center gap-2 mb-3">
            <button id="btnDontKnow" class="btn btn-outline-danger">Don't know</button>
            <button id="btnKnow" class="btn btn-outline-success">Know</button>
          </div>
          <div class="d-flex justify-content-between">
            <div>Bucket — <span class="text-danger">Don't know:</span> <span id="cntDK">0</span> | <span class="text-success">Know:</span> <span id="cntK">0</span></div>
            <div class="small text-muted">Cards loaded: <span id="cntLoaded">0</span></div>
          </div>
        </div>
      </div>
    </div>

    <script>
      let domain = 'random';
      let cards = [];
      let idx = 0;
      let showingBack = false;
      let cntDK = 0, cntK = 0;

      function renderCard() {
        const el = document.getElementById('fcText');
        if (!cards.length) {
          el.innerHTML = 'No cards available for this domain yet. Try another domain.';
          return;
        }
        const c = cards[idx];
        el.innerHTML = '<div>' + (showingBack ? c.back.replace(/</g,'&lt;') : c.front.replace(/</g,'&lt;')) + '</div>' +
          '<div class="small-muted mt-2">' + (showingBack ? '(Back)' : '(Front — click to flip)') + '</div>';
        document.getElementById('cntLoaded').textContent = String(cards.length);
      }

      function nextCard() {
        showingBack = false;
        if (!cards.length) return;
        idx = (idx + 1) % cards.length;
        renderCard();
      }

      async function loadCards() {
        try {
          const res = await fetch('/api/flashcards?domain=' + encodeURIComponent(domain) + '&count=100');
          const data = await res.json();
          if (data.cards) {
            cards = data.cards;
            idx = 0; showingBack = false;
            renderCard();
          } else {
            cards = []; idx=0; showingBack=false; renderCard();
          }
        } catch (e) {
          cards = []; idx=0; showingBack=false; renderCard();
        }
      }

      document.getElementById('fcCard').addEventListener('click', () => {
        showingBack = !showingBack; renderCard();
      });

      document.getElementById('btnDontKnow').addEventListener('click', () => {
        cntDK += 1; document.getElementById('cntDK').textContent = String(cntDK);
        nextCard();
      });
      document.getElementById('btnKnow').addEventListener('click', () => {
        cntK += 1; document.getElementById('cntK').textContent = String(cntK);
        nextCard();
      });

      document.addEventListener('keydown', (e) => {
        if (e.key.toLowerCase() === 'j') { showingBack = !showingBack; renderCard(); }
        if (e.key.toLowerCase() === 'k') { nextCard(); }
      });

      document.querySelectorAll('.domain-chip').forEach(chip => {
        chip.addEventListener('click', () => {
          document.querySelectorAll('.domain-chip').forEach(c => c.classList.remove('active'));
          chip.classList.add('active');
          domain = chip.getAttribute('data-domain');
          loadCards();
        });
      });

      loadCards();
    </script>
    """)
    return render_base_template("Flashcards", content.substitute(chips=chips_html), user=user)

@app.get("/api/flashcards")
@subscription_required
def api_flashcards():
    """
    Returns flashcards with 'front' and 'back' text.
    Back text does NOT include letter prefixes.
    Accepts ?domain=<key|random>&count=50 (max 200).
    """
    try:
        domain = (request.args.get("domain") or "random").strip().lower()
        try:
            count = int(request.args.get("count", "50"))
        except ValueError:
            count = 50
        count = max(1, min(200, count))

        def build_from_pool(pool, desired_count):
            cards = []
            while len(cards) < desired_count:
                batch = pool[:]
                random.shuffle(batch)
                for b in batch:
                    if len(cards) >= desired_count:
                        break
                    opts = b.get("options", {}) or {}
                    correct_text = (opts.get(b.get("correct"), "") or "").strip()
                    back_lines = []
                    if correct_text:
                        back_lines.append(f"Correct: {correct_text}")
                    if b.get("explanation"):
                        back_lines.append(b["explanation"].strip())
                    cards.append({
                        "id": f"fb_{len(cards)+1}",
                        "front": (b.get("question") or "").strip(),
                        "back": "\n\n".join([x for x in back_lines if x]) or "Correct answer available.",
                        "domain": b.get("domain", "general"),
                        "difficulty": b.get("difficulty", "medium")
                    })
            return cards

        base_pool = BASE_QUESTIONS[:]

        # Try DB first (if table exists)
        cards = []
        try:
            rows = []
            if 'question_bank' in inspect(db.engine).get_table_names():
                q = QuestionBank.query.filter_by(is_verified=True)
                if domain not in ("random", "", None):
                    q = q.filter(QuestionBank.domain == domain)
                rows = q.order_by(func.random()).limit(count).all()
            if rows:
                for r in rows:
                    try:
                        opts = json.loads(r.options_json or "{}")
                        if not isinstance(opts, dict):
                            opts = {}
                    except Exception:
                        opts = {}
                    correct_text = (opts.get(r.correct, "") or "").strip()
                    back_lines = []
                    if correct_text:
                        back_lines.append(f"Correct: {correct_text}")
                    if r.explanation:
                        back_lines.append(r.explanation.strip())
                    back = "\n\n".join([x for x in back_lines if x])

                    cards.append({
                        "id": f"qb_{r.id}",
                        "front": (r.question or "").strip(),
                        "back": back if back else "Correct answer available.",
                        "domain": (r.domain or "general"),
                        "difficulty": (r.difficulty or "medium")
                    })
        except Exception as e:
            print(f"/api/flashcards DB error: {e}")

        # Fallback if DB empty
        if not cards:
            pool = base_pool if domain in ("random", "", None) else [b for b in base_pool if b.get("domain") == domain] or base_pool
            cards = build_from_pool(pool, count)

        return jsonify({"cards": cards, "domain": domain, "count": len(cards)}), 200
    except Exception as e:
        print(f"/api/flashcards error: {e}")
        return jsonify({"error": "Could not load flashcards."}), 500

# ------------------------------ Quizzes ---------------------------------------
@app.route('/quiz-selector')
@subscription_required
def quiz_selector():
    user = User.query.get(session['user_id'])

    chips = ['<span class="domain-chip active" data-domain="random">All / Random</span>'] + [
        f'<span class="domain-chip" data-domain="{k}">{v["name"]}</span>'
        for k, v in CPP_DOMAINS.items()
    ]
    chips_html = ''.join(chips)

    content = Template("""
    <div class="row">
      <div class="col-md-10 mx-auto">
        <div class="card">
          <div class="card-header">
            <h4 class="mb-0">Build Your Quiz</h4>
          </div>
          <div class="card-body">
            <div class="mb-2">Choose a domain:</div>
            <div class="mb-3">$chips</div>

            <div class="mb-3">
              <label class="form-label me-3">How many questions?</label>
              <div class="btn-group" role="group">
                <input type="radio" class="btn-check" name="qcount" id="qc5" autocomplete="off" value="5">
                <label class="btn btn-outline-secondary" for="qc5">5</label>
                <input type="radio" class="btn-check" name="qcount" id="qc10" autocomplete="off" value="10" checked>
                <label class="btn btn-outline-secondary" for="qc10">10</label>
                <input type="radio" class="btn-check" name="qcount" id="qc15" autocomplete="off" value="15">
                <label class="btn btn-outline-secondary" for="qc15">15</label>
                <input type="radio" class="btn-check" name="qcount" id="qc20" autocomplete="off" value="20">
                <label class="btn btn-outline-secondary" for="qc20">20</label>
              </div>
            </div>

            <div class="mb-3">
              <label class="form-label me-3">Difficulty</label>
              <select id="difficulty" class="form-select" style="max-width: 220px; display: inline-block;">
                <option value="easy">Easy</option>
                <option value="medium" selected>Medium</option>
                <option value="hard">Hard</option>
              </select>
            </div>

            <button id="startQuiz" class="btn btn-success">Start Quiz</button>
          </div>
        </div>
      </div>
    </div>
    <script>
      let domain = 'random';
      document.querySelectorAll('.domain-chip').forEach(chip => {
        chip.addEventListener('click', () => {
          document.querySelectorAll('.domain-chip').forEach(c => c.classList.remove('active'));
          chip.classList.add('active');
          domain = chip.getAttribute('data-domain');
        });
      });
      document.getElementById('startQuiz').addEventListener('click', () => {
        const count = document.querySelector('input[name="qcount"]:checked').value;
        const diff = document.getElementById('difficulty').value;
        window.location.href = '/quiz/practice?domain=' + encodeURIComponent(domain) + '&count=' + encodeURIComponent(count) + '&difficulty=' + encodeURIComponent(diff);
      });
    </script>
    """)
    return render_base_template("Quizzes", content.substitute(chips=chips_html), user=user)

@app.route('/quiz/<quiz_type>')
@subscription_required
def quiz(quiz_type):
    user = User.query.get(session['user_id'])
    if quiz_type not in QUIZ_TYPES:
        flash('Invalid quiz type.', 'danger')
        return redirect(url_for('quiz_selector'))

    domain = request.args.get('domain', 'random')
    difficulty = request.args.get('difficulty', 'medium')
    try:
        count = int(request.args.get('count', QUIZ_TYPES[quiz_type]['questions']))
    except Exception:
        count = QUIZ_TYPES[quiz_type]['questions']

    # Start quiz timer
    session['quiz_start_time'] = datetime.utcnow().timestamp()

    quiz_data = generate_quiz(quiz_type, domain, difficulty, count)
    quiz_json = json.dumps(quiz_data)

    page = Template("""
    <div class="row">
      <div class="col-md-10 mx-auto">
        <div class="card">
          <div class="card-header d-flex justify-content-between align-items-center">
            <h4 class="mb-0">$title</h4>
            <button id="submitBtnTop" class="btn btn-success">Submit</button>
          </div>
          <div class="card-body" id="quizContainer"></div>
          <div class="card-footer text-end">
            <button id="submitBtnBottom" class="btn btn-success">Submit</button>
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
        (QUIZ_DATA.questions || []).forEach((q, idx) => {
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
          html += '</div></div>';
          resultsDiv.innerHTML = html;
          window.scrollTo({ top: resultsDiv.offsetTop - 20, behavior: 'smooth' });
        } catch (e) {
          resultsDiv.innerHTML = '<div class="alert alert-danger">Submission failed.</div>';
        }
      }

      document.getElementById('submitBtnTop').addEventListener('click', submitQuiz);
      document.getElementById('submitBtnBottom').addEventListener('click', submitQuiz);
      renderQuiz();
    </script>
    """)
    content = page.substitute(title=quiz_data['title'], quiz_json=quiz_json)
    return render_base_template("Quiz", content, user=user)

@app.route('/mock-exam')
@subscription_required
def mock_exam():
    # Allow selection UI for count
    requested = request.args.get('count')
    count = None
    if requested:
        try:
            count = int(requested)
        except Exception:
            count = None

    if not count:
        # Selection UI
        content = """
        <div class="row">
          <div class="col-md-8 mx-auto">
            <div class="card">
              <div class="card-header"><h4 class="mb-0">Mock Exam</h4></div>
              <div class="card-body">
                <p class="mb-2">Choose the number of questions (random across all domains):</p>
                <div class="btn-group" role="group">
                  <a class="btn btn-outline-secondary" href="/mock-exam?count=25">25</a>
                  <a class="btn btn-outline-secondary" href="/mock-exam?count=50">50</a>
                  <a class="btn btn-outline-secondary" href="/mock-exam?count=75">75</a>
                  <a class="btn btn-outline-secondary" href="/mock-exam?count=100">100</a>
                </div>
              </div>
            </div>
          </div>
        </div>
        """
        return render_base_template("Mock Exam", content, user=User.query.get(session['user_id']))

    num_questions = max(25, min(100, count))  # sensible bounds

    # Start timer
    session['quiz_start_time'] = datetime.utcnow().timestamp()

    quiz_data = generate_fallback_quiz('mock-exam', domain='general', difficulty='medium', num_questions=num_questions)
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
          <div class="card-footer text-end">
            <button id="submitBtnBottom" class="btn btn-success">Submit</button>
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
        (QUIZ_DATA.questions || []).forEach((q, idx) => {
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

      function validateAllAnswered() {
        const total = (QUIZ_DATA.questions || []).length;
        for (let i = 0; i < total; i++) {
          const selected = document.querySelector('input[name="q' + i + '"]:checked');
          if (!selected) {
            const firstCard = document.querySelectorAll('#quizContainer .border.rounded')[i];
            if (firstCard) {
              firstCard.scrollIntoView({behavior:'smooth', block:'center'});
              firstCard.classList.add('border-danger');
              setTimeout(() => firstCard.classList.remove('border-danger'), 2000);
            }
            return false;
          }
        }
        return true;
      }

      async function submitQuiz() {
        if (!validateAllAnswered()) {
          alert('Please answer all questions before submitting.');
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
          html += '</div></div>';
          resultsDiv.innerHTML = html;
          window.scrollTo({ top: resultsDiv.offsetTop - 20, behavior: 'smooth' });
        } catch (e) {
          resultsDiv.innerHTML = '<div class="alert alert-danger">Submission failed.</div>';
        }
      }

      document.getElementById('submitBtnTop').addEventListener('click', submitQuiz);
      document.getElementById('submitBtnBottom').addEventListener('click', submitQuiz);
      renderQuiz();
    </script>
    """)
    content = page.substitute(num=num_questions, quiz_json=quiz_json)
    return render_base_template("Mock Exam", content, user=User.query.get(session['user_id']))

# ----------------- Submit quiz (records events & updates progress) ------------
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

        # Duration
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

            # Record event & update progress
            q_domain = q.get('domain', domain)
            record_question_event(session['user_id'], q, domain=q_domain, topic=None, is_correct=is_correct, source=('mock' if quiz_type == 'mock-exam' else 'quiz'))
            update_user_progress_on_answer(session['user_id'], q_domain, None, is_correct)

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

        # Simple insights
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

# ----------------------------- Progress ---------------------------------------
@app.route('/progress')
@subscription_required
def progress_page():
    user = User.query.get(session['user_id'])
    rows = UserProgress.query.filter_by(user_id=user.id, topic=None).all()

    def color_for(level: str) -> str:
        if level == 'mastered':
            return 'bg-success text-white'
        if level == 'good':
            return 'bg-warning text-dark'
        return 'bg-danger text-white'

    tr_html = []
    for r in rows:
        dmeta = CPP_DOMAINS.get(r.domain, {})
        dname = dmeta.get('name', r.domain)
        pct = int(round(r.average_score or 0))
        level = r.mastery_level or 'needs_practice'
        bar_class = 'bg-success' if level == 'mastered' else ('bg-warning' if level == 'good' else 'bg-danger')
        tr_html.append(
            '<tr>'
            f'<td>{dname}</td>'
            f'<td><div class="progress" style="height: 16px;"><div class="progress-bar {bar_class}" role="progressbar" style="width: {pct}%;" aria-valuenow="{pct}" aria-valuemin="0" aria-valuemax="100">{pct}%</div></div></td>'
            f'<td><span class="badge {color_for(level)}">{level.replace("_"," ").title()}</span></td>'
            f'<td>{r.question_count or 0}</td>'
            f'<td>{(r.last_updated or datetime.utcnow()).strftime("%Y-%m-%d")}</td>'
            '</tr>'
        )

    overall_pct = 0
    if rows:
        overall_pct = int(round(sum([(p.average_score or 0.0) for p in rows]) / len(rows)))

    content = Template("""
    <div class="row">
      <div class="col-md-8">
        <div class="card"><div class="card-header"><h4 class="mb-0">Progress by Domain</h4></div>
          <div class="card-body">
            <div class="table-responsive">
              <table class="table align-middle">
                <thead><tr><th>Domain</th><th>Average</th><th>Level</th><th>Questions</th><th>Updated</th></tr></thead>
                <tbody>$rows</tbody>
              </table>
            </div>
            <div class="small text-muted">
              Green = strong, Orange = good, Red = needs practice. Keep going — consistency wins!
            </div>
          </div>
        </div>
      </div>
      <div class="col-md-4 d-flex align-items-center justify-content-center">
        <div class="text-center">
          <div class="gauge-wrap" style="--p:$overall%;">
            <span>$overall%</span>
          </div>
          <div class="mt-2 small text-muted">Overall progress (Goal: 80%+)</div>
        </div>
      </div>
    </div>
    """)
    return render_base_template("Progress", content.substitute(rows=''.join(tr_html), overall=overall_pct), user=user)

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
                # Set a user-facing end date for the dashboard countdown
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
