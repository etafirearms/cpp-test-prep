# -*- coding: utf-8 -*-
"""
Complete CPP Test Prep Platform
A comprehensive Flask application for ASIS CPP exam preparation
with subscription billing, enhanced UI, and complete study modes
"""

import os
import re
import json
import time
import uuid
import hashlib
import random
import html
import logging
import math
import io
import difflib
import hmac
from datetime import datetime, timedelta
from typing import Any, Dict, List, Tuple, Optional
from urllib.parse import quote as _urlquote
import urllib.request as _urlreq
import urllib.error as _urlerr

from flask import (
    Flask, request, session, redirect, url_for, abort, jsonify, make_response, g
)
from flask import render_template_string
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix

# ====================================================================================================
# APPLICATION SETUP & CONFIGURATION
# ====================================================================================================

APP_VERSION = os.environ.get("APP_VERSION", "2.1.0")

def _env_bool(val: str | None, default: bool = False) -> bool:
    s = (val if val is not None else ("1" if default else "0")).strip().lower()
    return s in ("1", "true", "yes", "y", "on")

DEBUG = _env_bool(os.environ.get("DEBUG", "0"), default=False)

SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-change-me")
SESSION_COOKIE_SECURE_FLAG = _env_bool(os.environ.get("SESSION_COOKIE_SECURE", "1"), default=True)

if (SESSION_COOKIE_SECURE_FLAG or not DEBUG) and SECRET_KEY == "dev-secret-change-me":
    raise RuntimeError(
        "SECURITY: SECRET_KEY must be set to a non-default value when running with "
        "SESSION_COOKIE_SECURE=1 or when DEBUG is false."
    )

app = Flask(__name__)
app.secret_key = SECRET_KEY

app.config.update(
    SESSION_COOKIE_SECURE=SESSION_COOKIE_SECURE_FLAG,
    SESSION_COOKIE_SAMESITE="Lax",
    WTF_CSRF_TIME_LIMIT=None,
)

app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

# Logging setup
logger = logging.getLogger("cpp_prep")
handler = logging.StreamHandler()
fmt = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
handler.setFormatter(fmt)
logger.setLevel(logging.INFO)
logger.addHandler(handler)

# Paths & Data
DATA_DIR = os.environ.get("Data_Dir", os.path.join(os.getcwd(), "data"))
os.makedirs(DATA_DIR, exist_ok=True)

BANK_DIR = os.path.join(DATA_DIR, "bank")
os.makedirs(BANK_DIR, exist_ok=True)

# OpenAI Configuration
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
OPENAI_API_BASE = os.environ.get("OPENAI_API_BASE", "https://api.openai.com/v1")
OPENAI_CHAT_MODEL = os.environ.get("OPENAI_CHAT_MODEL", "gpt-4o-mini")
TUTOR_WEB_AWARE = _env_bool(os.environ.get("TUTOR_WEB_AWARE", "0"), default=False)

# Stripe Configuration
STRIPE_PUBLISHABLE_KEY = os.environ.get("STRIPE_PUBLISHABLE_KEY", "")
STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
STRIPE_MONTHLY_PRICE_ID = os.environ.get("STRIPE_MONTHLY_PRICE_ID", "")
STRIPE_SIXMONTH_PRICE_ID = os.environ.get("STRIPE_SIXMONTH_PRICE_ID", "")

# Admin Configuration
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")

# Import Stripe if available
STRIPE_ENABLED = False
try:
    import stripe
    if STRIPE_SECRET_KEY:
        stripe.api_key = STRIPE_SECRET_KEY
        STRIPE_ENABLED = True
except ImportError:
    logger.warning("Stripe not available - billing features disabled")

# CSRF Protection
try:
    from flask_wtf import CSRFProtect
    from flask_wtf.csrf import generate_csrf
    csrf = CSRFProtect(app)
    HAS_CSRF = True
except Exception:
    csrf = None
    HAS_CSRF = False
    def generate_csrf() -> str:
        return ""

def csrf_token() -> str:
    if HAS_CSRF:
        return generate_csrf()
    val = session.get("_csrf_token")
    if not val:
        val = uuid.uuid4().hex
        session["_csrf_token"] = val
    return val

def _csrf_ok() -> bool:
    if HAS_CSRF:
        return True
    return (request.form.get("csrf_token") == session.get("_csrf_token"))

# Rate limiting
_RATE = {}
def _rate_ok(key: str, per_sec: float = 1.0) -> bool:
    t = time.time()
    last = _RATE.get(key, 0.0)
    if (t - last) < (1.0 / per_sec):
        return False
    _RATE[key] = t
    return True

# Security Headers
CSP = (
    "default-src 'self' https:; "
    "img-src 'self' data: https:; "
    "style-src 'self' 'unsafe-inline' https:; "
    "script-src 'self' 'unsafe-inline' https:; "
    "font-src 'self' https: data:; "
    "connect-src 'self' https:; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "form-action 'self'"
)

@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer-when-downgrade"
    resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    resp.headers.setdefault("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
    resp.headers["Content-Security-Policy"] = CSP
    return resp

# Request logging
@app.before_request
def _reqlog_start():
    g._req_t0 = time.time()

@app.after_request
def _reqlog_end(resp):
    try:
        p = request.path or ""
        if p.startswith("/static") or p == "/favicon.ico":
            return resp
        dur_ms = int((time.time() - getattr(g, "_req_t0", time.time())) * 1000)
        rid = request.headers.get("X-Request-ID", "")
        rid_sfx = f" req_id={rid}" if rid else ""
        logger.info("REQ %s %s -> %s %dms%s", request.method, p, resp.status_code, dur_ms, rid_sfx)
    except Exception:
        pass
    return resp

# ====================================================================================================
# DATA LAYER & UTILITIES
# ====================================================================================================

def _path(name: str) -> str:
    return os.path.join(DATA_DIR, name)

def _load_json(name: str, default):
    p = _path(name)
    try:
        if not os.path.exists(p):
            return default
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.warning("load_json %s failed: %s", name, e)
        return default

def _save_json(name: str, data):
    p = _path(name)
    tmp = f"{p}.tmp"
    try:
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, p)
    except Exception as e:
        logger.warning("save_json %s failed: %s", name, e)
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except Exception:
            pass

def _atomic_write_bytes(path: str, data: bytes) -> None:
    d = os.path.dirname(path) or "."
    os.makedirs(d, exist_ok=True)
    tmp_path = path + ".tmp"
    with open(tmp_path, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_path, path)

def _atomic_write_text(path: str, text: str) -> None:
    _atomic_write_bytes(path, text.encode("utf-8"))

def _read_jsonl(path: str) -> List[Dict[str, Any]]:
    if not os.path.exists(path):
        return []
    out: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except Exception:
                continue
    return out

def _write_jsonl(path: str, rows: List[Dict[str, Any]]) -> None:
    buf = io.StringIO()
    for r in rows:
        buf.write(json.dumps(r, ensure_ascii=False))
        buf.write("\n")
    _atomic_write_text(path, buf.getvalue())

# ====================================================================================================
# USER MANAGEMENT & BILLING
# ====================================================================================================

def _users_all() -> List[dict]:
    return _load_json("users.json", [])

def _find_user(email: str) -> dict | None:
    email = (email or "").strip().lower()
    for u in _users_all():
        if (u.get("email") or "").lower() == email:
            return u
    return None

def _find_user_by_id(uid: str) -> dict | None:
    for u in _users_all():
        if u.get("id") == uid:
            return u
    return None

def _update_user(uid: str, patch: dict):
    users = _users_all()
    for u in users:
        if u.get("id") == uid:
            u.update(patch or {})
            break
    _save_json("users.json", users)

def _create_user(email: str, password: str, subscription_type: str = "trial") -> Tuple[bool, str]:
    email = (email or "").strip().lower()
    if not email or not password or len(password) < 8:
        return False, "Please provide a valid email and a password with at least 8 characters."
    if _find_user(email):
        return False, "User already exists."
    users = _users_all()
    uid = uuid.uuid4().hex
    users.append({
        "id": uid,
        "email": email,
        "password_hash": generate_password_hash(password),
        "subscription_type": subscription_type,
        "subscription_status": "trial",
        "stripe_customer_id": "",
        "stripe_subscription_id": "",
        "trial_ends_at": (datetime.utcnow() + timedelta(days=7)).isoformat(),
        "terms_accepted": True,
        "terms_accepted_at": datetime.utcnow().isoformat(),
        "created_at": datetime.utcnow().isoformat()
    })
    _save_json("users.json", users)
    return True, uid

def validate_password(pw: str) -> Tuple[bool, str]:
    if not pw or len(pw) < 8:
        return False, "Password must be at least 8 characters."
    if not re.search(r'[A-Z]', pw):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r'[a-z]', pw):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r'[0-9]', pw):
        return False, "Password must contain at least one number."
    return True, ""

def _user_id() -> str:
    return session.get("uid", "")

def _current_user() -> dict | None:
    uid = _user_id()
    return _find_user_by_id(uid) if uid else None

def _login_redirect_url(next_path: str | None = None) -> str:
    next_val = next_path or request.path or "/"
    return f"/login?next={_urlquote(next_val)}"

def login_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not _user_id():
            return redirect(_login_redirect_url(request.path))
        return fn(*args, **kwargs)
    return wrapper

def subscription_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = _current_user()
        if not user:
            return redirect(_login_redirect_url(request.path))
        
        # Check subscription status
        status = user.get("subscription_status", "trial")
        if status in ["active", "trial"]:
            # Check if trial expired
            if status == "trial":
                trial_end = user.get("trial_ends_at")
                if trial_end:
                    try:
                        trial_date = datetime.fromisoformat(trial_end.replace('Z', ''))
                        if trial_date < datetime.utcnow():
                            if STRIPE_ENABLED:
                                return redirect("/billing?expired=1")
                            else:
                                # If billing disabled, allow continued access
                                pass
                    except (ValueError, TypeError):
                        # Invalid date format, allow access
                        pass
            return fn(*args, **kwargs)
        else:
            if STRIPE_ENABLED:
                return redirect("/billing?expired=1")
            else:
                return fn(*args, **kwargs)
    return wrapper

def is_admin() -> bool:
    return bool(session.get("admin_ok"))

# ====================================================================================================
# CPP DOMAIN DEFINITIONS & CONTENT SYSTEM
# ====================================================================================================

# CPP Exam Domains with official weightings
CPP_DOMAINS = {
    "domain1": {"name": "Security Principles & Practices", "weight": 0.22, "code": "D1"},
    "domain2": {"name": "Business Principles & Practices", "weight": 0.15, "code": "D2"},
    "domain3": {"name": "Investigations", "weight": 0.09, "code": "D3"},
    "domain4": {"name": "Personnel Security", "weight": 0.11, "code": "D4"},
    "domain5": {"name": "Physical Security", "weight": 0.16, "code": "D5"},
    "domain6": {"name": "Information Security", "weight": 0.14, "code": "D6"},
    "domain7": {"name": "Crisis Management", "weight": 0.13, "code": "D7"}
}

# Question type distributions
QUESTION_TYPE_MIX = {
    "mc": 0.50,        # 50% Multiple Choice
    "tf": 0.25,        # 25% True/False  
    "scenario": 0.25,  # 25% Scenario
}

# File paths for content bank
_QUESTIONS_FILE = os.path.join(BANK_DIR, "questions.jsonl")
_FLASHCARDS_FILE = os.path.join(BANK_DIR, "flashcards.jsonl")
_WEIGHTS_FILE = os.path.join(BANK_DIR, "weights.json")

# Encouragement messages for rotating display
ENCOURAGEMENT_MESSAGES = [
    "Stay consistent! Just 30 minutes of daily study makes a huge difference.",
    "Break complex topics into smaller chunks - your brain will thank you!",
    "Practice questions are your best friend for exam success.",
    "Remember: the CPP exam tests applied knowledge, not just memorization.",
    "Take breaks every 45 minutes to maintain peak concentration.",
    "Review your weak domains more frequently - that's where growth happens.",
    "Simulate exam conditions during your mock tests for better preparation.",
    "Connect new concepts to real-world security scenarios you've experienced.",
    "Use the tutor to clarify any confusing topics - understanding beats memorizing.",
    "Progress isn't always linear - trust the process and keep moving forward!",
    "Study groups can provide new perspectives on challenging concepts.",
    "Focus on understanding 'why' behind correct answers, not just 'what'.",
    "Your dedication to security excellence shows in every study session.",
    "Mix up your study methods - flashcards, quizzes, and scenarios work together.",
    "Confidence comes from preparation - you're building it every day!",
    "Quality over quantity - better to understand 10 concepts than memorize 100 facts.",
    "Sleep is crucial for memory consolidation - don't sacrifice rest for study time.",
    "Teach someone else a concept to truly test your understanding.",
    "Create mental connections between domains - security is interconnected.",
    "Celebrate small wins - every correct answer builds toward your goal!"
]

def get_random_encouragement():
    """Get a random encouragement message"""
    return random.choice(ENCOURAGEMENT_MESSAGES)

# Basic content to avoid empty database
SEED_QUESTIONS = [
    {
        "id": "seed_q_1",
        "type": "mc",
        "domain": "Domain 1",
        "stem": "Which control type prevents incidents before they occur?",
        "choices": ["Detective", "Preventive", "Corrective", "Compensating"],
        "answer": 1,
        "explanation": "Preventive controls stop incidents before they happen.",
        "module": "Security Controls"
    },
    {
        "id": "seed_q_2",
        "type": "tf", 
        "domain": "Domain 1",
        "stem": "Risk can be completely eliminated.",
        "answer": False,
        "explanation": "Risk can only be reduced, transferred, or accepted - never completely eliminated.",
        "module": "Risk Management"
    }
]

SEED_FLASHCARDS = [
    {
        "id": "seed_fc_1",
        "domain": "Domain 1",
        "front": "What are the three types of security controls?",
        "back": "Administrative, Physical, and Technical controls",
        "tags": ["controls", "fundamentals"]
    }
]

# ====================================================================================================
# CONTENT BANK MANAGEMENT
# ====================================================================================================

def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"

def get_all_questions(domains: Optional[List[str]] = None,
                      types: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    rows = _read_jsonl(_QUESTIONS_FILE)
    if not rows:
        # Return seed questions if none exist
        return SEED_QUESTIONS
    if domains:
        dset = set([d.lower() for d in domains])
        rows = [r for r in rows if str(r.get("domain","")).lower() in dset]
    if types:
        tset = set([t.lower() for t in types])
        rows = [r for r in rows if str(r.get("type","")).lower() in tset]
    return rows

def get_all_flashcards(domains: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    rows = _read_jsonl(_FLASHCARDS_FILE)
    if not rows:
        # Return seed flashcards if none exist
        return SEED_FLASHCARDS
    if domains:
        dset = set([d.lower() for d in domains])
        rows = [r for r in rows if str(r.get("domain","")).lower() in dset]
    return rows

def calculate_user_progress(user_id: str) -> Dict[str, Any]:
    """Calculate comprehensive user progress for speedometer display"""
    attempts = _load_json("attempts.json", [])
    user_attempts = [a for a in attempts if a.get("user_id") == user_id]
    
    if not user_attempts:
        return {
            "overall_percentage": 0,
            "color": "red",
            "status": "Getting Started",
            "details": {
                "quiz_sessions": 0,
                "mock_sessions": 0,
                "tutor_sessions": 0,
                "flashcard_sessions": 0,
                "domains_covered": 0,
                "total_questions": 0,
                "correct_answers": 0,
                "accuracy": 0
            }
        }
    
    # Count different types of activities
    quiz_sessions = len([a for a in user_attempts if a.get("mode") == "quiz"])
    mock_sessions = len([a for a in user_attempts if a.get("mode") == "mock"])
    tutor_sessions = len([a for a in user_attempts if a.get("mode") == "tutor"])
    flashcard_sessions = len([a for a in user_attempts if a.get("mode") == "flashcards"])
    
    # Calculate accuracy
    question_attempts = [a for a in user_attempts if a.get("mode") in ["quiz", "mock"] and a.get("score") is not None]
    total_questions = len(question_attempts)
    correct_answers = sum(1 for a in question_attempts if a.get("score") == 1)
    accuracy = (correct_answers / total_questions * 100) if total_questions > 0 else 0
    
    # Count unique domains covered (safely handle None values)
    domain_set = set()
    for a in user_attempts:
        domain = a.get("domain")
        if domain and domain != "all":
            domain_set.add(domain)
    domains_covered = len(domain_set)
    
    # Calculate progress score based on multiple factors
    progress_score = 0
    
    # Activity diversity (30% of score)
    activity_score = min(30, (quiz_sessions * 2) + (mock_sessions * 5) + (tutor_sessions * 1) + (flashcard_sessions * 1))
    progress_score += activity_score
    
    # Domain coverage (25% of score)
    domain_score = (domains_covered / 7) * 25 if domains_covered > 0 else 0
    progress_score += domain_score
    
    # Accuracy bonus (25% of score)
    accuracy_score = (accuracy / 100) * 25 if accuracy > 0 else 0
    progress_score += accuracy_score
    
    # Consistency bonus (20% of score) - based on recent activity
    recent_attempts = user_attempts[-20:] if len(user_attempts) > 20 else user_attempts
    if len(recent_attempts) >= 15:
        progress_score += 20
    elif len(recent_attempts) >= 10:
        progress_score += 15
    elif len(recent_attempts) >= 5:
        progress_score += 10
    
    # Cap at 100%
    overall_percentage = min(100, int(progress_score))
    
    # Determine color and status
    if overall_percentage >= 80:
        color = "green"
        status = "Exam Ready"
    elif overall_percentage >= 40:
        color = "orange"
        status = "Making Progress"
    else:
        color = "red"
        status = "Building Foundation"
    
    return {
        "overall_percentage": overall_percentage,
        "color": color,
        "status": status,
        "details": {
            "quiz_sessions": quiz_sessions,
            "mock_sessions": mock_sessions,
            "tutor_sessions": tutor_sessions,
            "flashcard_sessions": flashcard_sessions,
            "domains_covered": domains_covered,
            "total_questions": total_questions,
            "correct_answers": correct_answers,
            "accuracy": round(accuracy, 1)
        }
    }

def select_questions(domains: List[str],
                     count: int,
                     mix: Optional[Dict[str, float]] = None,
                     user_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Core question selection engine"""
    questions = get_all_questions()
    
    # Simple selection for now
    if not questions:
        return SEED_QUESTIONS[:count]
    
    # Filter by domains if specified
    if domains and "all" not in domains:
        filtered = []
        for q in questions:
            if any(domain.lower() in str(q.get("domain", "")).lower() for domain in domains):
                filtered.append(q)
        questions = filtered if filtered else questions
    
    # Return random selection up to count
    if len(questions) <= count:
        return questions
    
    return random.sample(questions, count)

# ====================================================================================================
# AI TUTOR SYSTEM
# ====================================================================================================

def _ai_enabled() -> bool:
    return bool(OPENAI_API_KEY)

def _openai_chat_completion(user_prompt: str) -> Tuple[bool, str]:
    """Call OpenAI API for tutor responses"""
    if not _ai_enabled():
        return False, ("Tutor is currently in offline mode. "
                       "No API key configured. You can still study with flashcards, quizzes, and mock exams.")
    
    url = f"{OPENAI_API_BASE.rstrip('/')}/chat/completions"
    sys_prompt = (
        "You are an expert CPP (Certified Protection Professional) study tutor. "
        "Explain clearly, cite general best practices, and avoid proprietary or member-only ASIS content. "
        "Keep answers concise and actionable. When useful, give short bullet points or an example scenario. "
        "Never claim this platform is ASIS-approved. "
        "Focus on helping students understand concepts for exam success. "
        "Always include this disclaimer at the end: 'This program is not affiliated with or approved by ASIS International.'"
    )
    
    payload = {
        "model": OPENAI_CHAT_MODEL,
        "messages": [
            {"role": "system", "content": sys_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": 0.2,
        "max_tokens": 700,
    }
    
    data = json.dumps(payload).encode("utf-8")
    req = _urlreq.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {OPENAI_API_KEY}",
        },
        method="POST",
    )
    
    try:
        with _urlreq.urlopen(req, timeout=25) as resp:
            raw = resp.read().decode("utf-8", "ignore")
            obj = json.loads(raw)
            msg = (obj.get("choices") or [{}])[0].get("message", {}).get("content", "")
            if not msg:
                return False, "The Tutor did not return a response. Please try again."
            return True, msg.strip()
    except _urlerr.HTTPError as e:
        try:
            err_body = e.read().decode("utf-8", "ignore")
        except Exception:
            err_body = str(e)
        logger.warning("Tutor HTTPError: %s %s", e, err_body)
        return False, "Tutor request failed. Please try again."
    except Exception as e:
        logger.warning("Tutor error: %s", e)
        return False, "Tutor is temporarily unavailable. Please try again."

# ====================================================================================================
# EVENT LOGGING
# ====================================================================================================

def _log_event(uid: str, name: str, data: dict | None = None):
    evts = _load_json("events.json", [])
    evts.append({
        "ts": datetime.utcnow().isoformat() + "Z",
        "user_id": uid,
        "name": name,
        "data": data or {}
    })
    _save_json("events.json", evts)

def _append_attempt(uid: str, mode: str, score: int = None, total: int = None, 
                   domain: str = None, question: str = None, answer: str = None):
    rec = {
        "ts": datetime.utcnow().isoformat() + "Z",
        "user_id": uid,
        "mode": mode,
        "score": score,
        "total": total,
        "domain": domain,
        "question": question,
        "answer": answer
    }
    attempts = _load_json("attempts.json", [])
    attempts.append(rec)
    _save_json("attempts.json", attempts)

# ====================================================================================================
# UI HELPERS & BASE LAYOUT - MUST BE DEFINED BEFORE ROUTES
# ====================================================================================================

def _footer_html():
    """Standard footer with ASIS disclaimer"""
    return """
    <footer class="bg-light border-top mt-5 py-4">
      <div class="container">
        <div class="row">
          <div class="col-md-8">
            <p class="text-muted mb-1">
              <strong>Disclaimer:</strong> This program is not affiliated with or approved by ASIS International. 
              It uses only open-source and publicly available study materials. No ASIS-protected content is included.
            </p>
            <p class="text-muted small mb-0">
              Educational use only. No legal, safety, or professional advice. Use official sources to verify. 
              No guarantee of exam results. &copy; 2024 CPP-Exam-Prep
            </p>
          </div>
          <div class="col-md-4 text-md-end">
            <a href="/terms" class="text-decoration-none text-muted small">Terms &amp; Conditions</a>
          </div>
        </div>
      </div>
    </footer>
    """

def progress_meter_html(progress_data: Dict[str, Any]) -> str:
    """Generate progress meter HTML (speedometer style)"""
    percentage = progress_data.get("overall_percentage", 0)
    color = progress_data.get("color", "red")
    status = progress_data.get("status", "Getting Started")
    
    # Calculate rotation for needle (0% = -90deg, 100% = 90deg)
    rotation = max(-90, min(90, -90 + (percentage * 1.8)))
    
    color_map = {"red": "#dc3545", "orange": "#fd7e14", "green": "#198754"}
    needle_color = color_map.get(color, "#dc3545")
    
    return f"""
    <div class="progress-meter text-center mb-3">
      <div class="position-relative d-inline-block">
        <svg width="120" height="80" viewBox="0 0 120 80">
          <!-- Background arc -->
          <path d="M 20 60 A 40 40 0 0 1 100 60" stroke="#e9ecef" stroke-width="8" fill="none"/>
          
          <!-- Red zone (0-40%) -->
          <path d="M 20 60 A 40 40 0 0 0 60 20" stroke="#dc3545" stroke-width="6" fill="none"/>
          
          <!-- Orange zone (40-79%) -->
          <path d="M 60 20 A 40 40 0 0 0 88 44" stroke="#fd7e14" stroke-width="6" fill="none"/>
          
          <!-- Green zone (80-100%) -->
          <path d="M 88 44 A 40 40 0 0 0 100 60" stroke="#198754" stroke-width="6" fill="none"/>
          
          <!-- Needle -->
          <line x1="60" y1="60" x2="60" y2="25" stroke="{needle_color}" stroke-width="3" 
                transform="rotate({rotation} 60 60)"/>
          
          <!-- Center dot -->
          <circle cx="60" cy="60" r="4" fill="{needle_color}"/>
        </svg>
        
        <div class="position-absolute w-100" style="bottom: -10px;">
          <div class="fw-bold text-{color}">{percentage}%</div>
          <div class="small text-muted">{html.escape(status)}</div>
        </div>
      </div>
    </div>
    """

def base_layout(title: str, body_html: str, show_nav: bool = True) -> str:
    """Base layout with navigation and footer"""
    nav_html = ""
    if show_nav:
        user = _current_user()
        nav_html = """
        <nav class="navbar navbar-expand-lg navbar-light bg-light border-bottom">
          <div class="container">
            <a class="navbar-brand fw-bold" href="/">
              <i class="bi bi-shield-lock text-primary"></i> CPP Prep
            </a>
            
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navContent">
              <span class="navbar-toggler-icon"></span>
            </button>
            
            <div id="navContent" class="collapse navbar-collapse">
              <div class="ms-auto d-flex align-items-center gap-3">
        """
        
        if user:
            nav_html += """
                <a class="text-decoration-none" href="/tutor">Tutor</a>
                <a class="text-decoration-none" href="/quiz">Quiz</a>
                <a class="text-decoration-none" href="/dashboard">Dashboard</a>
                <a class="btn btn-outline-danger btn-sm" href="/logout">Logout</a>
            """
        else:
            nav_html += """
                <a class="btn btn-outline-primary btn-sm" href="/login">Login</a>
                <a class="btn btn-primary btn-sm" href="/register">Sign Up</a>
            """
        
        nav_html += """
              </div>
            </div>
          </div>
        </nav>
        """
    
    escaped_title = html.escape(title or "CPP Exam Prep")
    
    return f"""
    <!doctype html>
    <html lang="en">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>{escaped_title}</title>
      <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
      <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css" rel="stylesheet">
      <style>
        .progress-meter svg {{ max-width: 100%; height: auto; }}
        .tutor-chat {{ 
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
          border-radius: 15px;
        }}
        .tutor-message {{ 
          background: rgba(255,255,255,0.95); 
          border-radius: 15px; 
          padding: 1.5rem;
          box-shadow: 0 2px 10px rgba(0,0,0,0.1);
          line-height: 1.6;
        }}
        .user-message {{ 
          background: linear-gradient(45deg, #e3f2fd, #bbdefb); 
          border-radius: 15px; 
          padding: 1rem;
          border-left: 4px solid #2196F3;
        }}
        .correct-answer {{ 
          background-color: #d4edda; 
          border: 2px solid #28a745; 
          border-radius: 10px;
          animation: correctPulse 0.5s ease-in-out;
        }}
        .incorrect-answer {{ 
          background-color: #f8d7da; 
          border: 2px solid #dc3545; 
          border-radius: 10px;
          animation: incorrectShake 0.5s ease-in-out;
        }}
        .question-card {{ 
          transition: all 0.3s ease; 
          border-radius: 15px;
          overflow: hidden;
        }}
        .question-card:hover {{ 
          transform: translateY(-2px); 
          box-shadow: 0 8px 25px rgba(0,0,0,0.15); 
        }}
        .encouragement-message {{ 
          background: linear-gradient(45deg, #4CAF50, #2196F3);
          color: white;
          border-radius: 15px;
          padding: 1.5rem;
          animation: slideIn 0.5s ease-out;
          box-shadow: 0 4px 15px rgba(0,0,0,0.2);
        }}
        @keyframes slideIn {{
          from {{ opacity: 0; transform: translateY(-20px); }}
          to {{ opacity: 1; transform: translateY(0); }}
        }}
        @keyframes correctPulse {{
          0%, 100% {{ transform: scale(1); }}
          50% {{ transform: scale(1.02); }}
        }}
        @keyframes incorrectShake {{
          0%, 100% {{ transform: translateX(0); }}
          25% {{ transform: translateX(-5px); }}
          75% {{ transform: translateX(5px); }}
        }}
      </style>
    </head>
    <body class="d-flex flex-column min-vh-100">
      {nav_html}
      
      <main class="flex-grow-1 py-4">
        {body_html}
      </main>

      {_footer_html()}

      <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
    </body>
    </html>
    """

def _render_question_choices(q):
    """Helper to render question choices"""
    qtype = q.get("type", "")
    if qtype == "mc":
        choices_html = ""
        for i, choice in enumerate(q.get("choices", [])):
            choices_html += f"""
            <div class="border rounded p-3 mb-2">
              <div class="form-check">
                <input class="form-check-input" type="radio" name="answer" value="{i}" id="choice{i}" required>
                <label class="form-check-label w-100" for="choice{i}">
                  <strong>{chr(65+i)}.</strong> {html.escape(choice)}
                </label>
              </div>
            </div>
            """
        return choices_html
    elif qtype == "tf":
        return """
        <div class="border rounded p-3 mb-2">
          <div class="form-check">
            <input class="form-check-input" type="radio" name="answer" value="true" id="true" required>
            <label class="form-check-label w-100" for="true">
              <strong>True</strong>
            </label>
          </div>
        </div>
        <div class="border rounded p-3 mb-2">
          <div class="form-check">
            <input class="form-check-input" type="radio" name="answer" value="false" id="false" required>
            <label class="form-check-label w-100" for="false">
              <strong>False</strong>
            </label>
          </div>
        </div>
        """
    return "<p>Question type not supported</p>"

def _render_quiz_question(questions, current_idx):
    """Render a single quiz question"""
    q = questions[current_idx]
    total = len(questions)
    progress_percent = ((current_idx + 1) / total) * 100
    
    content = f"""
    <div class="container">
      <div class="row justify-content-center">
        <div class="col-md-10">
          <!-- Progress bar -->
          <div class="mb-4">
            <div class="d-flex justify-content-between align-items-center mb-2">
              <h5 class="mb-0">Question {current_idx + 1} of {total}</h5>
              <span class="badge bg-warning">{html.escape(q.get('domain', 'Unknown'))}</span>
            </div>
            <div class="progress">
              <div class="progress-bar bg-warning" style="width: {progress_percent}%"></div>
            </div>
          </div>
          
          <!-- Question card -->
          <div class="card shadow-sm question-card">
            <div class="card-header bg-light">
              <h6 class="mb-0 text-muted">
                <i class="bi bi-question-circle me-2"></i>
                {html.escape(q.get('type', '').upper())} Question
              </h6>
            </div>
            <div class="card-body">
              <h5 class="card-title mb-4">{html.escape(q.get('stem', ''))}</h5>
              
              <form method="post" action="/quiz/answer">
                <input type="hidden" name="csrf_token" value="{csrf_token()}"/>
                <input type="hidden" name="question_id" value="{html.escape(q.get('id', ''))}"/>
                
                {_render_question_choices(q)}
                
                <div class="d-grid gap-2 mt-4">
                  <button type="submit" class="btn btn-primary btn-lg">
                    <i class="bi bi-check-circle me-2"></i>Submit Answer
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      </div>
    </div>
    """
    return base_layout("Quiz", content)

def _show_quiz_results():
    """Display quiz results"""
    if "quiz_answers" not in session:
        return redirect("/quiz")
    
    answers = session["quiz_answers"]
    total_questions = len(answers)
    correct_count = sum(1 for a in answers if a.get("is_correct", False))
    score_percentage = (correct_count / total_questions * 100) if total_questions > 0 else 0
    
    # Determine performance level
    if score_percentage >= 80:
        performance_class = "success"
        performance_text = "Excellent"
        performance_icon = "bi-trophy-fill"
    elif score_percentage >= 70:
        performance_class = "info"
        performance_text = "Good"
        performance_icon = "bi-star-fill"
    elif score_percentage >= 60:
        performance_class = "warning"
        performance_text = "Fair"
        performance_icon = "bi-exclamation-triangle-fill"
    else:
        performance_class = "danger"
        performance_text = "Needs Improvement"
        performance_icon = "bi-arrow-repeat"
    
    # Clear session
    session.pop("quiz_questions", None)
    session.pop("quiz_current", None)
    session.pop("quiz_answers", None)
    
    content = f"""
    <div class="container">
      <div class="row justify-content-center">
        <div class="col-md-8">
          <!-- Results Header -->
          <div class="card shadow-sm mb-4">
            <div class="card-header bg-{performance_class} text-white text-center">
              <h4 class="mb-0">
                <i class="bi {performance_icon} me-2"></i>
                Quiz Complete - {performance_text}!
              </h4>
            </div>
            <div class="card-body text-center">
              <div class="row">
                <div class="col-md-4">
                  <h2 class="text-{performance_class}">{correct_count}/{total_questions}</h2>
                  <p class="text-muted mb-0">Correct Answers</p>
                </div>
                <div class="col-md-4">
                  <h2 class="text-{performance_class}">{score_percentage:.1f}%</h2>
                  <p class="text-muted mb-0">Overall Score</p>
                </div>
                <div class="col-md-4">
                  <h2 class="text-{performance_class}">{performance_text}</h2>
                  <p class="text-muted mb-0">Performance Level</p>
                </div>
              </div>
            </div>
          </div>
          
          <!-- Action Buttons -->
          <div class="text-center">
            <a href="/quiz" class="btn btn-primary btn-lg me-2">
              <i class="bi bi-arrow-repeat me-2"></i>Take Another Quiz
            </a>
            <a href="/tutor" class="btn btn-success btn-lg me-2">
              <i class="bi bi-chat-dots me-2"></i>Ask Tutor
            </a>
            <a href="/dashboard" class="btn btn-outline-secondary btn-lg">
              <i class="bi bi-house me-2"></i>Dashboard
            </a>
          </div>
        </div>
      </div>
    </div>
    """
    return base_layout("Quiz Results", content)

# ====================================================================================================
# HEALTH CHECK ROUTE (REQUIRED FOR RENDER) - MUST BE FIRST ROUTE
# ====================================================================================================

@app.route("/healthz")
def health_check():
    """Health check endpoint for deployment platform"""
    return jsonify({
        "status": "healthy",
        "version": APP_VERSION,
        "timestamp": datetime.utcnow().isoformat()
    })

# ====================================================================================================
# ROUTES - LANDING PAGE & AUTHENTICATION
# ====================================================================================================

@app.route("/")
def landing_page():
    """Landing page with subscription options"""
    if _current_user():
        return redirect("/dashboard")
    
    content = """
    <div class="hero-section bg-primary text-white py-5 mb-5">
      <div class="container">
        <div class="row align-items-center">
          <div class="col-lg-6">
            <h1 class="display-4 fw-bold mb-3">Master the CPP Exam</h1>
            <p class="lead mb-4">
              Comprehensive preparation for the ASIS Certified Protection Professional certification. 
              Study smarter with our adaptive learning platform featuring expert-designed content.
            </p>
            <div class="d-flex gap-3 flex-wrap">
              <a href="/register" class="btn btn-light btn-lg">Start Free Trial</a>
              <a href="/login" class="btn btn-outline-light btn-lg">Sign In</a>
            </div>
          </div>
          <div class="col-lg-6 text-center">
            <i class="bi bi-shield-check display-1 text-white-50"></i>
          </div>
        </div>
      </div>
    </div>
    
    <div class="container mb-5">
      <div class="alert alert-warning border-warning">
        <div class="d-flex align-items-center">
          <i class="bi bi-exclamation-triangle-fill me-2"></i>
          <div>
            <strong>Important Disclaimer:</strong> This program is not affiliated with or approved by ASIS International. 
            We use only open-source and publicly available study materials. No ASIS-protected content is included.
          </div>
        </div>
      </div>
      
      <div class="row mb-5">
        <div class="col-12">
          <h2 class="text-center mb-4">Study Features</h2>
        </div>
        <div class="col-md-6 text-center mb-4">
          <div class="card h-100 border-0 shadow-sm question-card">
            <div class="card-body">
              <div class="tutor-chat p-3 rounded-3 mb-3">
                <i class="bi bi-chat-dots display-4 text-white"></i>
              </div>
              <h5>AI Tutor</h5>
              <p class="text-muted">Get instant explanations and personalized guidance on complex CPP topics</p>
            </div>
          </div>
        </div>
        <div class="col-md-6 text-center mb-4">
          <div class="card h-100 border-0 shadow-sm question-card">
            <div class="card-body">
              <i class="bi bi-ui-checks-grid text-warning display-4 mb-3"></i>
              <h5>Practice Quizzes</h5>
              <p class="text-muted">Test your knowledge with realistic exam questions</p>
            </div>
          </div>
        </div>
      </div>
      
      <div class="text-center mb-4">
        <p class="text-muted">Ready to start your CPP preparation journey?</p>
        <a href="/register" class="btn btn-primary btn-lg">Get Started Free</a>
      </div>
    </div>
    """
    
    return base_layout("CPP Exam Prep - Master Your Certification", content, show_nav=False)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        next_url = request.args.get("next", "/dashboard")
        
        content = f"""
        <div class="container" style="max-width: 600px;">
          <div class="card shadow-sm">
            <div class="card-header text-center bg-primary text-white">
              <h4 class="mb-0">Create Your Account</h4>
              <p class="mb-0 text-light">Start your free trial today</p>
            </div>
            <div class="card-body">
              <form method="post">
                <input type="hidden" name="csrf_token" value="{csrf_token()}"/>
                <input type="hidden" name="next" value="{html.escape(next_url)}"/>
                
                <div class="mb-3">
                  <label class="form-label">Email Address</label>
                  <input type="email" name="email" class="form-control" required 
                         placeholder="your.email@example.com"/>
                </div>
                
                <div class="mb-3">
                  <label class="form-label">Password</label>
                  <input type="password" name="password" class="form-control" required 
                         minlength="8"/>
                  <div class="form-text">
                    Password must contain: uppercase, lowercase, number (minimum 8 characters)
                  </div>
                </div>
                
                <div class="mb-3">
                  <label class="form-label">Confirm Password</label>
                  <input type="password" name="confirm_password" class="form-control" required/>
                </div>
                
                <div class="mb-3">
                  <div class="form-check">
                    <input class="form-check-input" type="checkbox" name="accept_terms" 
                           id="accept_terms" required>
                    <label class="form-check-label" for="accept_terms">
                      I agree to the <a href="/terms" target="_blank">Terms &amp; Conditions</a>
                    </label>
                  </div>
                </div>
                
                <div class="d-grid gap-2">
                  <button type="submit" class="btn btn-primary btn-lg">
                    Create Account
                  </button>
                  <a href="/login" class="btn btn-outline-secondary">Already have an account? Sign in</a>
                </div>
              </form>
            </div>
          </div>
        </div>
        """
        return base_layout("Create Account", content, show_nav=False)
    
    # POST - process registration
    if not _csrf_ok():
        abort(403)
    
    email = (request.form.get("email") or "").strip().lower()
    password = request.form.get("password") or ""
    confirm_password = request.form.get("confirm_password") or ""
    next_url = request.form.get("next") or "/dashboard"
    accept_terms = request.form.get("accept_terms") == "on"
    
    # Validation
    if not accept_terms:
        content = """
        <div class="container" style="max-width: 480px;">
          <div class="alert alert-danger">
            You must accept the Terms & Conditions to continue.
          </div>
          <a href="/register" class="btn btn-primary">Back to Registration</a>
        </div>
        """
        return base_layout("Registration Failed", content, show_nav=False)
    
    if password != confirm_password:
        content = """
        <div class="container" style="max-width: 480px;">
          <div class="alert alert-danger">
            Passwords do not match.
          </div>
          <a href="/register" class="btn btn-primary">Try Again</a>
        </div>
        """
        return base_layout("Registration Failed", content, show_nav=False)
    
    valid, msg = validate_password(password)
    if not valid:
        content = f"""
        <div class="container" style="max-width: 480px;">
          <div class="alert alert-danger">
            {html.escape(msg)}
          </div>
          <a href="/register" class="btn btn-primary">Try Again</a>
        </div>
        """
        return base_layout("Registration Failed", content, show_nav=False)
    
    success, result = _create_user(email, password)
    if not success:
        content = f"""
        <div class="container" style="max-width: 480px;">
          <div class="alert alert-danger">
            {html.escape(result)}
          </div>
          <a href="/register" class="btn btn-primary">Try Again</a>
        </div>
        """
        return base_layout("Registration Failed", content, show_nav=False)
    
    # Success - auto login and redirect to dashboard
    session["uid"] = result
    session["email"] = email
    _log_event(result, "register.success")
    
    return redirect("/dashboard")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        next_url = request.args.get("next", "/dashboard")
        content = f"""
        <div class="container" style="max-width: 480px;">
          <div class="card shadow-sm">
            <div class="card-header text-center bg-primary text-white">
              <h4 class="mb-0">Welcome Back</h4>
              <p class="mb-0 text-light">Sign in to continue your CPP preparation</p>
            </div>
            <div class="card-body">
              <form method="post">
                <input type="hidden" name="csrf_token" value="{csrf_token()}"/>
                <input type="hidden" name="next" value="{html.escape(next_url)}"/>
                
                <div class="mb-3">
                  <label class="form-label">Email Address</label>
                  <input type="email" name="email" class="form-control" required
                         placeholder="your.email@example.com"/>
                </div>
                
                <div class="mb-3">
                  <label class="form-label">Password</label>
                  <input type="password" name="password" class="form-control" required/>
                </div>
                
                <div class="d-grid gap-2">
                  <button type="submit" class="btn btn-primary btn-lg">Sign In</button>
                  <a href="/register" class="btn btn-outline-secondary">Create New Account</a>
                </div>
              </form>
            </div>
          </div>
        </div>
        """
        return base_layout("Sign In", content, show_nav=False)
    
    # POST - process login
    if not _csrf_ok():
        abort(403)
    
    email = (request.form.get("email") or "").strip().lower()
    password = request.form.get("password") or ""
    next_url = request.form.get("next") or "/dashboard"
    
    user = _find_user(email)
    if not user or not check_password_hash(user.get("password_hash", ""), password):
        content = """
        <div class="container" style="max-width: 480px;">
          <div class="alert alert-danger">
            Invalid email or password. Please check your credentials and try again.
          </div>
          <a href="/login" class="btn btn-primary">Try Again</a>
        </div>
        """
        return base_layout("Sign In Failed", content, show_nav=False)
    
    # Success
    session["uid"] = user["id"]
    session["email"] = user["email"]
    _log_event(user["id"], "login.success")
    
    return redirect(next_url)

@app.route("/logout")
def logout():
    uid = _user_id()
    if uid:
        _log_event(uid, "logout")
    session.clear()
    return redirect("/")

@app.route("/dashboard")
@login_required
def dashboard():
    """Main dashboard with progress meter and encouragement"""
    user = _current_user()
    progress_data = calculate_user_progress(_user_id())
    encouragement = get_random_encouragement()
    
    user_name = user.get('email', '').split('@')[0] if user else 'Student'
    
    content = f"""
    <div class="container">
      <div class="row mb-4">
        <div class="col-md-8">
          <h1 class="h3 mb-2">Welcome back, {html.escape(user_name)}!</h1>
          <div class="encouragement-message mb-3">
            <i class="bi bi-lightbulb me-2"></i>
            {html.escape(encouragement)}
          </div>
        </div>
        <div class="col-md-4">
          {progress_meter_html(progress_data)}
        </div>
      </div>
      
      <div class="row g-4 mb-4">
        <div class="col-md-6">
          <div class="card h-100 shadow-sm question-card">
            <div class="card-body text-center">
              <div class="tutor-chat p-3 rounded-3 mb-3">
                <i class="bi bi-chat-dots display-4 text-white"></i>
              </div>
              <h5>AI Tutor</h5>
              <p class="text-muted mb-3">Get instant explanations and study guidance</p>
              <a href="/tutor" class="btn btn-primary">Ask Tutor</a>
            </div>
          </div>
        </div>
        
        <div class="col-md-6">
          <div class="card h-100 shadow-sm question-card">
            <div class="card-body text-center">
              <i class="bi bi-ui-checks-grid display-4 text-warning mb-3"></i>
              <h5>Practice Quiz</h5>
              <p class="text-muted mb-3">Test your knowledge with realistic exam questions</p>
              <a href="/quiz" class="btn btn-warning">Take Quiz</a>
            </div>
          </div>
        </div>
      </div>

      <div class="card">
        <div class="card-header">
          <h5 class="mb-0">CPP Exam Domains</h5>
        </div>
        <div class="card-body">
          <div class="row g-2">
            <div class="col-sm-6">
              <div class="border rounded p-2 small">
                <strong>Domain 1:</strong> Security Principles &amp; Practices (22%)
              </div>
            </div>
            <div class="col-sm-6">
              <div class="border rounded p-2 small">
                <strong>Domain 2:</strong> Business Principles &amp; Practices (15%)
              </div>
            </div>
            <div class="col-sm-6">
              <div class="border rounded p-2 small">
                <strong>Domain 3:</strong> Investigations (9%)
              </div>
            </div>
            <div class="col-sm-6">
              <div class="border rounded p-2 small">
                <strong>Domain 4:</strong> Personnel Security (11%)
              </div>
            </div>
            <div class="col-sm-6">
              <div class="border rounded p-2 small">
                <strong>Domain 5:</strong> Physical Security (16%)
              </div>
            </div>
            <div class="col-sm-6">
              <div class="border rounded p-2 small">
                <strong>Domain 6:</strong> Information Security (14%)
              </div>
            </div>
            <div class="col-sm-6">
              <div class="border rounded p-2 small">
                <strong>Domain 7:</strong> Crisis Management (13%)
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
    """
    
    return base_layout("Dashboard", content)

@app.route("/tutor", methods=["GET", "POST"])
@login_required
def tutor():
    if request.method == "GET":
        content = f"""
        <div class="container">
          <div class="tutor-chat p-4 mb-4">
            <div class="row">
              <div class="col-md-8">
                <h1 class="h4 text-white mb-2">
                  <i class="bi bi-chat-dots me-2"></i>AI Tutor
                </h1>
                <p class="text-white-50 mb-0">Ask questions about CPP exam topics and get expert explanations</p>
              </div>
              <div class="col-md-4">
                <div class="text-center">
                  <i class="bi bi-robot display-4 text-white-50"></i>
                </div>
              </div>
            </div>
          </div>
          
          <div class="card shadow-sm">
            <div class="card-header bg-light">
              <h5 class="mb-0">Ask Your Question</h5>
            </div>
            <div class="card-body">
              <form method="post">
                <input type="hidden" name="csrf_token" value="{csrf_token()}"/>
                <div class="mb-3">
                  <textarea name="question" class="form-control" rows="4" 
                           placeholder="e.g., 'Explain the difference between administrative, physical, and technical controls'" 
                           required></textarea>
                </div>
                <div class="d-flex justify-content-between align-items-center">
                  <small class="text-muted">
                    <i class="bi bi-lightbulb me-1"></i>
                    Tip: Be specific for better explanations
                  </small>
                  <button type="submit" class="btn btn-primary">
                    <i class="bi bi-send me-1"></i>Ask Tutor
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
        """
        return base_layout("AI Tutor", content)
    
    # POST - handle question
    if not _csrf_ok():
        abort(403)
    
    question = request.form.get("question", "").strip()
    if not question:
        return redirect("/tutor")
    
    # Rate limiting
    if not _rate_ok(f"tutor_{_user_id()}", 0.1):  # 1 request per 10 seconds
        content = """
        <div class="container">
          <div class="alert alert-warning">
            Please wait a moment before asking another question.
          </div>
          <a href="/tutor" class="btn btn-primary">Back to Tutor</a>
        </div>
        """
        return base_layout("Rate Limited", content)
    
    success, response = _openai_chat_completion(question)
    _append_attempt(_user_id(), "tutor", question=question, answer=response)
    
    # Enhanced response formatting
    formatted_response = response.replace('\n', '<br>').replace('**', '<strong>').replace('**', '</strong>')
    
    content = f"""
    <div class="container">
      <div class="tutor-chat p-4 mb-4">
        <h1 class="h4 text-white mb-0">
          <i class="bi bi-chat-dots me-2"></i>AI Tutor Response
        </h1>
      </div>
      
      <div class="row">
        <div class="col-md-6 mb-4">
          <div class="card shadow-sm">
            <div class="card-header bg-primary text-white">
              <i class="bi bi-person-fill me-2"></i>Your Question
            </div>
            <div class="card-body user-message">
              {html.escape(question)}
            </div>
          </div>
        </div>
        
        <div class="col-md-6 mb-4">
          <div class="card shadow-sm">
            <div class="card-header bg-success text-white">
              <i class="bi bi-robot me-2"></i>Tutor Response
            </div>
            <div class="card-body tutor-message">
              {formatted_response}
            </div>
          </div>
        </div>
      </div>
      
      <div class="text-center">
        <a href="/tutor" class="btn btn-primary btn-lg">
          <i class="bi bi-plus-circle me-2"></i>Ask Another Question
        </a>
        <a href="/dashboard" class="btn btn-outline-secondary btn-lg ms-2">
          <i class="bi bi-house me-2"></i>Back to Dashboard
        </a>
      </div>
    </div>
    """
    return base_layout("AI Tutor", content)

@app.route("/quiz", methods=["GET", "POST"])
@login_required
def quiz():
    if request.method == "GET":
        # Check if we're in the middle of a quiz
        if "quiz_questions" in session:
            current_q_idx = session.get("quiz_current", 0)
            questions = session["quiz_questions"]
            
            if current_q_idx < len(questions):
                return _render_quiz_question(questions, current_q_idx)
            else:
                # Quiz completed, show results
                return _show_quiz_results()
        
        # Show quiz setup
        content = f"""
        <div class="container">
          <div class="row justify-content-center">
            <div class="col-md-8">
              <div class="card shadow-sm">
                <div class="card-header bg-warning text-dark text-center">
                  <h4 class="mb-0">
                    <i class="bi bi-ui-checks-grid me-2"></i>Practice Quiz Setup
                  </h4>
                </div>
                <div class="card-body">
                  <form method="post">
                    <input type="hidden" name="csrf_token" value="{csrf_token()}"/>
                    
                    <div class="mb-4">
                      <label class="form-label fw-bold">Number of Questions</label>
                      <select name="count" class="form-select">
                        <option value="5">5 Questions (Quick Practice)</option>
                        <option value="10" selected>10 Questions (Standard)</option>
                        <option value="15">15 Questions (Extended)</option>
                      </select>
                    </div>
                    
                    <div class="alert alert-info">
                      <i class="bi bi-info-circle me-2"></i>
                      <strong>Quiz Format:</strong> You'll answer one question at a time with immediate feedback. 
                      Green indicates correct answers, red shows incorrect with explanations.
                    </div>
                    
                    <div class="d-grid gap-2">
                      <button type="submit" class="btn btn-warning btn-lg">
                        <i class="bi bi-play-circle me-2"></i>Start Quiz
                      </button>
                      <a href="/dashboard" class="btn btn-outline-secondary">Cancel</a>
                    </div>
                  </form>
                </div>
              </div>
            </div>
          </div>
        </div>
        """
        return base_layout("Quiz Setup", content)
    
    # POST - start quiz
    if not _csrf_ok():
        abort(403)
    
    count = int(request.form.get("count", 10))
    
    questions = select_questions([], count, user_id=_user_id())
    
    if not questions:
        content = """
        <div class="container">
          <div class="alert alert-warning">
            No questions available. Please try again later.
          </div>
          <a href="/quiz" class="btn btn-primary">Try Again</a>
        </div>
        """
        return base_layout("Quiz", content)
    
    # Store quiz in session
    session["quiz_questions"] = questions
    session["quiz_current"] = 0
    session["quiz_answers"] = []
    
    return _render_quiz_question(questions, 0)

@app.route("/quiz/answer", methods=["POST"])
@login_required
def quiz_answer():
    """Process quiz answer and show feedback"""
    if not _csrf_ok():
        abort(403)
    
    if "quiz_questions" not in session:
        return redirect("/quiz")
    
    questions = session["quiz_questions"]
    current_idx = session.get("quiz_current", 0)
    
    if current_idx >= len(questions):
        return redirect("/quiz")
    
    q = questions[current_idx]
    user_answer = request.form.get("answer", "")
    
    # Determine if answer is correct
    is_correct = False
    correct_answer = ""
    
    if q.get("type") == "mc":
        try:
            user_idx = int(user_answer)
            correct_idx = q.get("answer", 0)
            is_correct = (user_idx == correct_idx)
            correct_answer = q.get("choices", [])[correct_idx] if correct_idx < len(q.get("choices", [])) else ""
        except (ValueError, IndexError):
            pass
    elif q.get("type") == "tf":
        correct_bool = q.get("answer", False)
        user_bool = user_answer.lower() == "true"
        is_correct = (user_bool == correct_bool)
        correct_answer = str(correct_bool)
    
    # Store answer
    if "quiz_answers" not in session:
        session["quiz_answers"] = []
    
    session["quiz_answers"].append({
        "question": q.get("stem", ""),
        "user_answer": user_answer,
        "is_correct": is_correct,
        "explanation": q.get("explanation", ""),
        "domain": q.get("domain", "")
    })
    
    # Log attempt
    _append_attempt(_user_id(), "quiz", score=1 if is_correct else 0, total=1, 
                   domain=q.get("domain"), question=q.get("stem"), answer=user_answer)
    
    # Show feedback
    feedback_class = "correct-answer" if is_correct else "incorrect-answer"
    feedback_icon = "bi-check-circle-fill text-success" if is_correct else "bi-x-circle-fill text-danger"
    feedback_title = "Correct!" if is_correct else "Incorrect"
    
    explanation = q.get("explanation", "No explanation available.")
    
    next_btn_text = "Next Question" if current_idx + 1 < len(questions) else "View Results"
    next_url = f"/quiz/next" if current_idx + 1 < len(questions) else "/quiz/results"
    
    content = f"""
    <div class="container">
      <div class="row justify-content-center">
        <div class="col-md-10">
          <div class="card shadow-sm {feedback_class}">
            <div class="card-header text-center">
              <h4 class="mb-0">
                <i class="bi {feedback_icon} me-2"></i>
                {feedback_title}
              </h4>
            </div>
            <div class="card-body">
              <h6 class="text-muted mb-3">Question:</h6>
              <p class="mb-3">{html.escape(q.get('stem', ''))}</p>
              
              {f'<p><strong>Your Answer:</strong> {html.escape(user_answer)}</p>' if not is_correct else ''}
              {f'<p><strong>Correct Answer:</strong> {html.escape(correct_answer)}</p>' if not is_correct and correct_answer else ''}
              
              <div class="alert alert-{'success' if is_correct else 'info'}">
                <strong>Explanation:</strong> {html.escape(explanation)}
              </div>
              
              <div class="text-center">
                <a href="{next_url}" class="btn btn-primary btn-lg">
                  {next_btn_text} <i class="bi bi-arrow-right ms-2"></i>
                </a>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
    """
    return base_layout("Quiz Feedback", content)

@app.route("/quiz/next")
@login_required
def quiz_next():
    """Move to next question"""
    if "quiz_questions" not in session:
        return redirect("/quiz")
    
    current_idx = session.get("quiz_current", 0)
    session["quiz_current"] = current_idx + 1
    
    questions = session["quiz_questions"]
    if session["quiz_current"] >= len(questions):
        return redirect("/quiz/results")
    
    return _render_quiz_question(questions, session["quiz_current"])

@app.route("/quiz/results")
@login_required
def quiz_results():
    """Show quiz results"""
    return _show_quiz_results()

@app.route("/terms")
def terms():
    """Terms and conditions page"""
    content = """
    <div class="container" style="max-width: 800px;">
      <h1 class="mb-4">Terms & Conditions</h1>
      
      <div class="card">
        <div class="card-body">
          <h5>1. Acceptance of Terms</h5>
          <p>By using this CPP Exam Preparation service, you agree to these terms and conditions.</p>
          
          <h5>2. Service Description</h5>
          <p>This service provides study materials and practice questions for the ASIS Certified Protection Professional (CPP) exam. This program is not affiliated with or approved by ASIS International.</p>
          
          <h5>3. Disclaimer</h5>
          <p><strong>This program is not affiliated with or approved by ASIS International. It uses only open-source and publicly available study materials. No ASIS-protected content is included.</strong></p>
          
          <h5>4. Educational Use Only</h5>
          <p>All content is for educational purposes only. No legal, safety, or professional advice is provided. Users should verify information with official sources.</p>
          
          <h5>5. No Guarantee</h5>
          <p>We do not guarantee exam results or certification success. Individual results may vary.</p>
          
          <h5>6. Privacy</h5>
          <p>We collect minimal personal information and do not share user data with third parties except as required for payment processing.</p>
          
          <p class="text-muted mt-4">
            <small>Last updated: January 2024</small>
          </p>
        </div>
      </div>
      
      <div class="text-center mt-4">
        <a href="/" class="btn btn-primary">Back to Home</a>
      </div>
    </div>
    """
    return base_layout("Terms & Conditions", content, show_nav=False)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(
        host="0.0.0.0",
        port=port,
        debug=DEBUG
    )

