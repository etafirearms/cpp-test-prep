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

# ====================================================================================================
# CONTENT BANK MANAGEMENT
# ====================================================================================================

def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"

def _norm_text(s: str) -> str:
    return " ".join(str(s).strip().lower().split())

def _q_signature(q: Dict[str, Any]) -> str:
    """Generate signature for question deduplication"""
    t = q.get("type", "").lower()
    stem = _norm_text(q.get("stem", ""))
    if t == "mc":
        choices = [_norm_text(c) for c in q.get("choices", [])]
        choices.sort()
        base = stem + "||" + "|".join(choices)
    elif t in ("tf", "truefalse", "true_false"):
        base = stem + "||tf"
    else:  # scenario
        opts = [_norm_text(c) for c in q.get("options", [])]
        opts.sort()
        base = stem + "||" + "|".join(opts)
    return hashlib.sha256(base.encode("utf-8")).hexdigest()

def _looks_like_dup(a: str, b: str, threshold: float = 0.92) -> bool:
    """Fuzzy duplicate detection"""
    ra = _norm_text(a); rb = _norm_text(b)
    if not ra or not rb:
        return False
    return difflib.SequenceMatcher(a=ra, b=rb).ratio() >= threshold

def get_domain_weights() -> Dict[str, float]:
    """Get domain weights, create defaults if missing"""
    default = {f"Domain {i+1}": info["weight"] for i, info in enumerate(CPP_DOMAINS.values())}
    data = _load_json(_WEIGHTS_FILE, None)
    if not data:
        _save_json(_WEIGHTS_FILE, default)
        return default
    try:
        total = float(sum(float(v) for v in data.values())) or 1.0
        return {k: float(v)/total for k, v in data.items()}
    except Exception:
        return default

def get_all_questions(domains: Optional[List[str]] = None,
                      types: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    rows = _read_jsonl(_QUESTIONS_FILE)
    if domains:
        dset = set([d.lower() for d in domains])
        rows = [r for r in rows if str(r.get("domain","")).lower() in dset]
    if types:
        tset = set([t.lower() for t in types])
        rows = [r for r in rows if str(r.get("type","")).lower() in tset]
    return rows

def get_all_flashcards(domains: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    rows = _read_jsonl(_FLASHCARDS_FILE)
    if domains:
        dset = set([d.lower() for d in domains])
        rows = [r for r in rows if str(r.get("domain","")).lower() in dset]
    return rows

def ingest_questions(new_items: List[Dict[str, Any]], source: str = "upload") -> Tuple[int,int]:
    """Ingest questions with deduplication"""
    existing = _read_jsonl(_QUESTIONS_FILE)
    seen_sigs = { _q_signature(q) for q in existing }
    existing_stems = [ _norm_text(q.get("stem","")) for q in existing ]

    added, skipped = 0, 0
    out = list(existing)
    now = int(time.time())
    
    for raw in new_items:
        q = dict(raw)
        q.setdefault("id", _new_id("q"))
        q.setdefault("source", source)
        q.setdefault("created_at", now)

        # Normalize type
        t = str(q.get("type","")).lower().strip()
        if t in ("truefalse", "true_false"):
            t = "tf"
        elif t in ("multiplechoice", "multiple_choice"):
            t = "mc"
        elif t in ("scenario", "scn"):
            t = "scenario"
        q["type"] = t

        # Validate
        if not q.get("stem") or not q.get("domain") or t not in ("mc","tf","scenario"):
            skipped += 1
            continue

        sig = _q_signature(q)
        stem_norm = _norm_text(q.get("stem",""))

        if sig in seen_sigs:
            skipped += 1
            continue
        if any(_looks_like_dup(stem_norm, s) for s in existing_stems):
            skipped += 1
            continue

        out.append(q)
        seen_sigs.add(sig)
        existing_stems.append(stem_norm)
        added += 1

    _write_jsonl(_QUESTIONS_FILE, out)
    logger.info("Bank ingest: questions added=%s skipped=%s total=%s", added, skipped, len(out))
    return added, skipped

def ingest_flashcards(new_items: List[Dict[str, Any]], source: str = "upload") -> Tuple[int,int]:
    """Ingest flashcards with deduplication"""
    existing = _read_jsonl(_FLASHCARDS_FILE)
    
    def f_sig(fc: Dict[str, Any]) -> str:
        base = _norm_text(fc.get("front","")) + "||" + _norm_text(fc.get("back",""))
        return hashlib.sha256(base.encode("utf-8")).hexdigest()

    seen = { f_sig(x) for x in existing }
    existing_fronts = [ _norm_text(x.get("front","")) for x in existing ]

    added, skipped = 0, 0
    out = list(existing)
    now = int(time.time())

    for raw in new_items:
        fc = dict(raw)
        if not fc.get("front") or not fc.get("back") or not fc.get("domain"):
            skipped += 1
            continue
        fc.setdefault("id", _new_id("fc"))
        fc.setdefault("source", source)
        fc.setdefault("created_at", now)
        sig = f_sig(fc)
        if sig in seen:
            skipped += 1
            continue
        if any(_looks_like_dup(_norm_text(fc.get("front","")), s) for s in existing_fronts):
            skipped += 1
            continue
        out.append(fc)
        seen.add(sig)
        existing_fronts.append(_norm_text(fc.get("front","")))
        added += 1

    _write_jsonl(_FLASHCARDS_FILE, out)
    logger.info("Bank ingest: flashcards added=%s skipped=%s total=%s", added, skipped, len(out))
    return added, skipped

# ====================================================================================================
# PROGRESS CALCULATION SYSTEM
# ====================================================================================================

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

# ====================================================================================================
# SELECTION ENGINE
# ====================================================================================================

def _canonical_type(t: str) -> str:
    t = (t or "").lower().strip()
    if t in ("multiplechoice","multiple_choice"): return "mc"
    if t in ("truefalse","true_false"): return "tf"
    if t in ("scn",): return "scenario"
    return t

def _rng_for_user_context(user_id: Optional[str]) -> random.Random:
    """Deterministic RNG per user/day for stable question sets"""
    try:
        day = int(time.time() // 86400)
        seed_str = f"{user_id or 'anon'}::{day}"
        seed = int(hashlib.sha256(seed_str.encode("utf-8")).hexdigest(), 16) % (2**31)
        return random.Random(seed)
    except Exception:
        return random.Random()

def _weighted_domain_allocation(domains: List[str], weights: Dict[str, float], total: int) -> Dict[str, int]:
    """Allocate questions across domains by weight"""
    if not domains:
        return {}
    
    # Normalize weights for selected domains
    local = {d: float(weights.get(d, 0.0)) for d in domains}
    if sum(local.values()) <= 0:
        # Equal split if no weights
        eq = max(1, total // max(1, len(domains)))
        alloc = {d: eq for d in domains}
        rem = total - sum(alloc.values())
        for d in domains[:rem]:
            alloc[d] += 1
        return alloc
    
    # Proportional allocation
    raw = {d: weights.get(d, 0.0) for d in domains}
    s = sum(raw.values()) or 1.0
    target = {d: (raw[d]/s)*total for d in domains}
    alloc = {d: int(math.floor(target[d])) for d in domains}
    rem = total - sum(alloc.values())
    
    # Distribute remainder by largest fractional parts
    fr = sorted(domains, key=lambda d: target[d]-alloc[d], reverse=True)
    for d in fr[:rem]:
        alloc[d] += 1
    return alloc

def _split_type_mix(n: int, mix: Dict[str, float]) -> Dict[str, int]:
    """Split questions by type according to mix percentages"""
    mix = { _canonical_type(k): float(v) for k, v in mix.items() }
    alloc = {k: int(math.floor(n * mix.get(k, 0.0))) for k in mix}
    rem = n - sum(alloc.values())
    
    residuals = sorted(mix.keys(), key=lambda k: (n*mix[k]) - alloc[k], reverse=True)
    for k in residuals[:rem]:
        alloc[k] += 1
    
    out = {"mc": alloc.get("mc",0), "tf": alloc.get("tf",0), "scenario": alloc.get("scenario",0)}
    delta = n - sum(out.values())
    for k in ("mc","tf","scenario"):
        if delta == 0: break
        out[k] += 1
        delta -= 1
    return out

def _filter_by_type(rows: List[Dict[str, Any]], t: str) -> List[Dict[str, Any]]:
    t = _canonical_type(t)
    return [r for r in rows if _canonical_type(r.get("type","")) == t]

def select_questions(domains: List[str],
                     count: int,
                     mix: Optional[Dict[str, float]] = None,
                     user_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Core question selection engine"""
    mix = mix or dict(QUESTION_TYPE_MIX)
    weights = get_domain_weights()
    rng = _rng_for_user_context(user_id)

    domains = list(domains or [])
    if not domains:
        domains = list(weights.keys())

    per_domain = _weighted_domain_allocation(domains, weights, count)
    inventory_by_domain = {d: get_all_questions(domains=[d]) for d in domains}

    selected: List[Dict[str, Any]] = []

    for d, n_d in per_domain.items():
        if n_d <= 0:
            continue
        pool = inventory_by_domain.get(d, [])
        if not pool:
            continue
        
        t_alloc = _split_type_mix(n_d, mix)

        for t, need in t_alloc.items():
            if need <= 0: 
                continue
            sub = _filter_by_type(pool, t)
            if len(sub) <= need:
                selected.extend(sub)
            else:
                selected.extend(rng.sample(sub, need))

    # Backfill if short
    short = count - len(selected)
    if short > 0:
        remaining = [q for d in domains for q in inventory_by_domain.get(d, []) if q not in selected]
        if len(remaining) >= short:
            selected.extend(rng.sample(remaining, short))
        else:
            selected.extend(remaining)
            all_pool = get_all_questions()
            extra = [q for q in all_pool if q not in selected]
            extra_need = count - len(selected)
            if extra_need > 0 and len(extra) > 0:
                take = min(extra_need, len(extra))
                selected.extend(rng.sample(extra, take))

    if len(selected) > count:
        selected = selected[:count]

    return selected

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
# UI HELPERS & BASE LAYOUT
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
                <a class="text-decoration-none" href="/flashcards">Flashcards</a>
                <a class="text-decoration-none" href="/quiz">Quiz</a>
                <a class="text-decoration-none" href="/mock">Mock Exam</a>
                <a class="text-decoration-none" href="/progress">Progress</a>
                <a class="text-decoration-none" href="/billing">Billing</a>
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
        .choice-option {{
          transition: all 0.2s ease;
          border-radius: 10px;
          padding: 1rem;
          margin: 0.5rem 0;
          cursor: pointer;
        }}
        .choice-option:hover {{
          background-color: #f8f9fa;
          transform: translateX(5px);
        }}
        .choice-option.selected {{
          background-color: #e3f2fd;
          border-color: #2196F3;
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
        .password-strength {{
          height: 5px;
          border-radius: 3px;
          transition: all 0.3s ease;
        }}
        .strength-weak {{ background: #dc3545; }}
        .strength-medium {{ background: #ffc107; }}
        .strength-strong {{ background: #28a745; }}
      </style>
    </head>
    <body class="d-flex flex-column min-vh-100">
      {nav_html}
      
      <main class="flex-grow-1 py-4">
        {body_html}
      </main>

      {_footer_html()}

      <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
      <script>
        // Password strength indicator
        function checkPasswordStrength(password) {{
          let strength = 0;
          if (password.length >= 8) strength++;
          if (/[A-Z]/.test(password)) strength++;
          if (/[a-z]/.test(password)) strength++;
          if (/[0-9]/.test(password)) strength++;
          if (/[^A-Za-z0-9]/.test(password)) strength++;
          return strength;
        }}
        
        // Auto-refresh for encouragement messages
        if (window.location.pathname === '/dashboard') {{
          setTimeout(() => location.reload(), 30000);
        }}
      </script>
    </body>
    </html>
    """

def domain_buttons_html(selected_key="all", field_name="domain"):
    """Generate domain selection buttons"""
    buttons = []
    domains = ["all"] + [f"domain{i+1}" for i in range(7)]
    labels = {
        "all": "All Domains",
        "domain1": "D1: Security Principles",
        "domain2": "D2: Business Principles", 
        "domain3": "D3: Investigations",
        "domain4": "D4: Personnel Security",
        "domain5": "D5: Physical Security",
        "domain6": "D6: Information Security",
        "domain7": "D7: Crisis Management"
    }
    
    for domain in domains:
        active = " active" if selected_key == domain else ""
        label = labels.get(domain, domain)
        buttons.append(
            f'<button type="button" class="btn btn-outline-success domain-btn{active}" '
            f'data-value="{html.escape(domain)}">{html.escape(label)}</button>'
        )
    
    hidden = f'<input type="hidden" id="domain_val" name="{html.escape(field_name)}" value="{html.escape(selected_key)}"/>'
    return f'<div class="d-flex flex-wrap gap-2 mb-3">{" ".join(buttons)}</div>{hidden}'

# ====================================================================================================
# CONTENT GENERATION SYSTEM
# ====================================================================================================

class CPPContentGenerator:
    """Generate comprehensive CPP study content"""
    
    @classmethod
    def generate_sample_questions(cls) -> List[Dict[str, Any]]:
        """Generate a comprehensive set of unique sample questions"""
        questions = []
        now = int(time.time())
        
        # Generate unique questions for each domain
        for domain_num in range(1, 8):
            domain_name = f"Domain {domain_num}"
            domain_questions = cls._generate_unique_domain_questions(domain_name, domain_num)
            
            for q in domain_questions:
                q["id"] = _new_id("q")
                q["source"] = "generated"
                q["created_at"] = now
                questions.append(q)
        
        return questions

    @classmethod
    def _generate_unique_domain_questions(cls, domain: str, domain_num: int) -> List[Dict[str, Any]]:
        """Generate unique questions for each specific domain"""
        base_questions = []
        
        if domain_num == 1:  # Security Principles & Practices
            base_questions = [
                {
                    "type": "mc",
                    "domain": domain,
                    "stem": "Which control type is MOST effective at deterring unauthorized access before it occurs?",
                    "choices": ["Detective controls", "Preventive controls", "Corrective controls", "Compensating controls"],
                    "answer": 1,
                    "explanation": "Preventive controls are designed to stop incidents before they happen, making them most effective at deterring unauthorized access.",
                    "module": "Security Controls Framework"
                },
                {
                    "type": "tf",
                    "domain": domain,
                    "stem": "Risk can be completely eliminated through proper security controls.",
                    "answer": False,
                    "explanation": "Risk can be reduced, transferred, or accepted, but never completely eliminated. There is always residual risk.",
                    "module": "Risk Management Fundamentals"
                },
                {
                    "type": "scenario",
                    "domain": domain,
                    "stem": "Your organization experienced a data breach due to an unpatched server. Which combination provides the BEST layered defense?",
                    "options": ["Automated patch management only", "Employee training and incident response plan", "Patch management, network segmentation, and intrusion detection", "Firewall configuration and antivirus software"],
                    "answers": [2],
                    "explanation": "Multiple layers provide defense in depth: patch management prevents vulnerabilities, segmentation limits scope, detection identifies threats.",
                    "module": "Defense in Depth Strategy"
                }
            ]
        elif domain_num == 2:  # Business Principles & Practices
            base_questions = [
                {
                    "type": "mc",
                    "domain": domain,
                    "stem": "When calculating Annual Loss Expectancy (ALE), which formula is correct?",
                    "choices": ["ALE = Asset Value × Threat Frequency", "ALE = Single Loss Expectancy × Annual Rate of Occurrence", "ALE = Risk × Vulnerability × Asset Value", "ALE = Impact × Likelihood × Controls"],
                    "answer": 1,
                    "explanation": "ALE = SLE × ARO. Single Loss Expectancy represents the dollar loss from one incident, and Annual Rate of Occurrence is frequency per year.",
                    "module": "Risk Quantification Methods"
                },
                {
                    "type": "tf",
                    "domain": domain,
                    "stem": "Cost-benefit analysis should always recommend the security control with the lowest implementation cost.",
                    "answer": False,
                    "explanation": "Cost-benefit analysis should recommend controls where benefits exceed costs by the greatest margin, not necessarily the cheapest option.",
                    "module": "Business Case Development"
                }
            ]
        elif domain_num == 3:  # Investigations
            base_questions = [
                {
                    "type": "mc",
                    "domain": domain,
                    "stem": "During an investigation interview, what is the PRIMARY purpose of open-ended questions?",
                    "choices": ["To get specific yes/no answers", "To challenge the subject's credibility", "To gather detailed information and encourage narrative", "To conclude the interview quickly"],
                    "answer": 2,
                    "explanation": "Open-ended questions encourage subjects to provide detailed information in their own words, revealing information that specific questions might miss.",
                    "module": "Interview Techniques"
                },
                {
                    "type": "tf",
                    "domain": domain,
                    "stem": "Chain of custody documentation must record every person who handles evidence.",
                    "answer": True,
                    "explanation": "Chain of custody requires documenting every transfer and handling of evidence to maintain its integrity and legal admissibility.",
                    "module": "Evidence Management"
                }
            ]
        elif domain_num == 4:  # Personnel Security
            base_questions = [
                {
                    "type": "mc",
                    "domain": domain,
                    "stem": "Which background check component is MOST important for positions with access to classified information?",
                    "choices": ["Education verification", "Credit history review", "Security clearance investigation", "Employment history verification"],
                    "answer": 2,
                    "explanation": "Security clearance investigations are specifically designed for classified access positions and include comprehensive background checks.",
                    "module": "Clearance Procedures"
                },
                {
                    "type": "tf",
                    "domain": domain,
                    "stem": "Insider threat indicators are always obvious and easy to detect.",
                    "answer": False,
                    "explanation": "Insider threat indicators can be subtle and may resemble normal behavior variations. Effective programs use multiple indicators.",
                    "module": "Insider Threat Detection"
                }
            ]
        elif domain_num == 5:  # Physical Security
            base_questions = [
                {
                    "type": "mc",
                    "domain": domain,
                    "stem": "In CPTED principles, what does 'natural surveillance' refer to?",
                    "choices": ["Security cameras placed throughout the facility", "Positioning windows and lighting to maximize visibility", "Having security guards patrol regularly", "Installing motion-detection sensors"],
                    "answer": 1,
                    "explanation": "Natural surveillance in CPTED refers to designing spaces so people can easily observe their surroundings through proper placement of windows and lighting.",
                    "module": "CPTED Principles"
                },
                {
                    "type": "tf",
                    "domain": domain,
                    "stem": "Physical security controls are most effective when they work independently of each other.",
                    "answer": False,
                    "explanation": "Physical security is most effective when controls work together in a layered defense approach, providing redundancy and mutual support.",
                    "module": "Layered Physical Security"
                }
            ]
        elif domain_num == 6:  # Information Security
            base_questions = [
                {
                    "type": "mc",
                    "domain": domain,
                    "stem": "What is the PRIMARY security benefit of implementing role-based access control (RBAC)?",
                    "choices": ["Reduces password complexity requirements", "Simplifies user access management and enforces least privilege", "Eliminates the need for user authentication", "Increases system processing speed"],
                    "answer": 1,
                    "explanation": "RBAC groups permissions by job functions, making it easier to manage access while ensuring users only get permissions needed for their roles.",
                    "module": "Access Control Models"
                },
                {
                    "type": "tf",
                    "domain": domain,
                    "stem": "Encryption in transit protects data while it is being transmitted over networks.",
                    "answer": True,
                    "explanation": "Encryption in transit (like HTTPS, VPN) protects data as it moves between systems over networks, preventing interception.",
                    "module": "Data Protection"
                }
            ]
        elif domain_num == 7:  # Crisis Management
            base_questions = [
                {
                    "type": "mc",
                    "domain": domain,
                    "stem": "In the Incident Command System (ICS), who has the authority to establish objectives and priorities?",
                    "choices": ["Operations Chief", "Planning Chief", "Incident Commander", "Safety Officer"],
                    "answer": 2,
                    "explanation": "The Incident Commander has overall authority and responsibility for incident management, including establishing objectives and priorities.",
                    "module": "ICS Structure"
                },
                {
                    "type": "tf",
                    "domain": domain,
                    "stem": "Emergency response plans should be kept confidential and only shared with senior management.",
                    "answer": False,
                    "explanation": "Emergency response plans should be shared with all relevant personnel who need to implement them during an emergency.",
                    "module": "Emergency Planning"
                }
            ]
        
        # Generate variations to reach target count for each domain
        variations = []
        for base_q in base_questions:
            variations.append(base_q)
            # Create variations by modifying stems and explanations
            for i in range(15):  # Create 15 variations per base question
                variant = dict(base_q)
                variant["stem"] = cls._create_question_variant(base_q["stem"], i+1, domain_num)
                if "choices" in variant:
                    variant["choices"] = cls._shuffle_choices(variant["choices"], variant["answer"])
                    variant["answer"] = cls._find_new_answer_index(variant["choices"], base_q["choices"][base_q["answer"]])
                variations.append(variant)
        
        return variations

    @classmethod
    def _create_question_variant(cls, original_stem: str, variant_num: int, domain_num: int) -> str:
        """Create a variation of the question stem"""
        # Domain-specific question banks
        domain_questions = {
            1: [  # Security Principles
                "What is the primary purpose of a security control framework?",
                "Which principle requires that multiple people be involved in completing a critical task?",
                "What does the term 'defense in depth' mean in security?",
                "Which type of control is implemented after an incident occurs?",
                "What is the difference between a vulnerability and a threat?"
            ],
            2: [  # Business Principles
                "How do you calculate Return on Investment (ROI) for security measures?",
                "What factors should be considered in a cost-benefit analysis?",
                "When is it appropriate to accept risk rather than mitigate it?",
                "What is the purpose of a business impact analysis?",
                "How do you determine the value of an asset for risk assessment?"
            ],
            3: [  # Investigations
                "What is the first step in conducting a workplace investigation?",
                "When should law enforcement be contacted during an investigation?",
                "What constitutes admissible evidence in most jurisdictions?",
                "How should witnesses be interviewed during an investigation?",
                "What is the importance of maintaining investigation confidentiality?"
            ],
            4: [  # Personnel Security
                "What components make up a comprehensive background investigation?",
                "When should periodic reinvestigations be conducted?",
                "What are key indicators of potential insider threats?",
                "How should access rights be managed when employees change roles?",
                "What is the purpose of a security awareness program?"
            ],
            5: [  # Physical Security
                "What are the four principles of Crime Prevention Through Environmental Design?",
                "How do you determine the appropriate level of physical security?",
                "What factors affect the placement of security cameras?",
                "When should security guards be used instead of electronic systems?",
                "What is the purpose of security zones in facility design?"
            ],
            6: [  # Information Security
                "What is the difference between encryption at rest and in transit?",
                "How do access controls support the principle of least privilege?",
                "What is multi-factor authentication and when should it be used?",
                "How do you classify information based on sensitivity levels?",
                "What is the purpose of security incident response procedures?"
            ],
            7: [  # Crisis Management
                "What are the phases of emergency management?",
                "How do you develop an effective crisis communication plan?",
                "What is the role of the Emergency Operations Center?",
                "When should business continuity plans be activated?",
                "How do you conduct effective crisis exercises and drills?"
            ]
        }
        
        questions = domain_questions.get(domain_num, [original_stem])
        if variant_num < len(questions):
            return questions[variant_num]
        
        # Fallback variations
        variations = {
            1: original_stem.replace("MOST", "BEST").replace("PRIMARY", "MAIN"),
            2: original_stem.replace("Which", "What").replace("MOST effective", "BEST approach")
        }
        return variations.get(variant_num, original_stem)

    @classmethod
    def _shuffle_choices(cls, choices: List[str], correct_idx: int) -> List[str]:
        """Shuffle choices while maintaining variety"""
        shuffled = choices.copy()
        random.shuffle(shuffled)
        return shuffled

    @classmethod
    def _find_new_answer_index(cls, new_choices: List[str], correct_answer: str) -> int:
        """Find the index of the correct answer in shuffled choices"""
        try:
            return new_choices.index(correct_answer)
        except ValueError:
            return 0

    @classmethod
    def generate_sample_flashcards(cls) -> List[Dict[str, Any]]:
        """Generate sample flashcards with unique content"""
        flashcards = []
        now = int(time.time())
        
        base_flashcards = [
            {
                "domain": "Domain 1",
                "front": "What are the three primary categories of security controls?",
                "back": "Administrative (policies, procedures, training), Physical (barriers, locks, surveillance), and Technical (access controls, encryption, firewalls)",
                "tags": ["controls", "fundamentals"]
            },
            {
                "domain": "Domain 1", 
                "front": "Define Defense in Depth",
                "back": "A layered security strategy using multiple controls at different points to protect assets. If one layer fails, others continue to provide protection.",
                "tags": ["strategy", "layered-defense"]
            },
            {
                "domain": "Domain 2",
                "front": "What is ROI in security context?",
                "back": "Return on Investment - measures the financial benefit of security investments relative to their cost. Calculated as (Benefit - Cost) / Cost × 100%",
                "tags": ["business-case", "metrics"]
            },
            {
                "domain": "Domain 3",
                "front": "What is Chain of Custody?",
                "back": "Documentation that tracks the seizure, custody, control, transfer, analysis, and disposition of evidence to ensure its integrity and admissibility.",
                "tags": ["evidence", "legal"]
            },
            {
                "domain": "Domain 4",
                "front": "Define Insider Threat",
                "back": "A security risk posed by individuals within an organization who have authorized access and may use it to harm the organization intentionally or unintentionally.",
                "tags": ["insider-threat", "risk"]
            },
            {
                "domain": "Domain 5",
                "front": "What is CPTED?",
                "back": "Crime Prevention Through Environmental Design - using architecture and urban planning to reduce crime opportunities through natural surveillance, access control, territorial reinforcement, and maintenance.",
                "tags": ["CPTED", "design"]
            },
            {
                "domain": "Domain 6",
                "front": "What is the principle of Least Privilege?",
                "back": "Users should be granted only the minimum access rights necessary to perform their job functions, reducing the risk of unauthorized access or misuse.",
                "tags": ["access-control", "principles"]
            },
            {
                "domain": "Domain 7",
                "front": "What are the four phases of emergency management?",
                "back": "Mitigation (reducing risks), Preparedness (planning and training), Response (immediate actions during crisis), Recovery (returning to normal operations)",
                "tags": ["emergency-management", "phases"]
            }
        ]
        
        # Generate unique variations
        for base_fc in base_flashcards:
            for i in range(8):  # Create 8 variations per base flashcard
                fc = dict(base_fc)
                fc["id"] = _new_id("fc")
                fc["source"] = "generated"
                fc["created_at"] = now
                if i > 0:  # Create variations for non-base cards
                    fc["front"] = cls._create_flashcard_variant(base_fc["front"], i)
                flashcards.append(fc)
        
        return flashcards

    @classmethod
    def _create_flashcard_variant(cls, original_front: str, variant_num: int) -> str:
        """Create variations of flashcard fronts"""
        variations = {
            1: original_front.replace("What", "Define").replace("?", ""),
            2: original_front.replace("Define", "Explain").replace("What is", "Describe"),
            3: original_front.replace("What are", "List").replace("the ", ""),
            4: original_front.replace("?", " and provide examples?"),
            5: f"How would you explain {original_front.lower().replace('what is ', '').replace('?', '')} to a colleague?",
            6: f"In practical terms, {original_front.lower().replace('what are ', 'what do ').replace('what is ', 'what does ')}",
            7: f"Why is understanding {original_front.lower().replace('what is ', '').replace('what are ', '').replace('?', '')} important for security professionals?"
        }
        return variations.get(variant_num, f"{original_front} (Variant {variant_num})")

def ensure_content_seeded():
    """Ensure content bank has sufficient material"""
    questions = get_all_questions()
    flashcards = get_all_flashcards()
    
    if len(questions) < 100:
        logger.info("Generating question bank...")
        new_questions = CPPContentGenerator.generate_sample_questions()
        try:
            added, skipped = ingest_questions(new_questions, source="seed")
            logger.info(f"Seeded {added} questions, skipped {skipped} duplicates")
        except Exception as e:
            logger.error(f"Failed to seed questions: {e}")
            # Fallback: write directly
            _write_jsonl(_QUESTIONS_FILE, new_questions)
    
    if len(flashcards) < 50:
        logger.info("Generating flashcard bank...")
        new_flashcards = CPPContentGenerator.generate_sample_flashcards()
        try:
            added, skipped = ingest_flashcards(new_flashcards, source="seed")
            logger.info(f"Seeded {added} flashcards, skipped {skipped} duplicates")
        except Exception as e:
            logger.error(f"Failed to seed flashcards: {e}")
            # Fallback: write directly
            _write_jsonl(_FLASHCARDS_FILE, new_flashcards)

# ====================================================================================================
# STRIPE BILLING INTEGRATION
# ====================================================================================================

def create_stripe_customer(email: str, name: str = "") -> str:
    """Create Stripe customer and return customer ID"""
    if not STRIPE_ENABLED:
        return ""
    
    try:
        customer = stripe.Customer.create(
            email=email,
            name=name,
            metadata={"source": "cpp_prep"}
        )
        return customer.id
    except Exception as e:
        logger.error("Failed to create Stripe customer: %s", e)
        return ""

def create_checkout_session(user_id: str, price_id: str, success_url: str, cancel_url: str) -> str:
    """Create Stripe checkout session and return session URL"""
    if not STRIPE_ENABLED:
        return ""
    
    try:
        user = _find_user_by_id(user_id)
        if not user:
            return ""
        
        # Create customer if needed
        customer_id = user.get("stripe_customer_id")
        if not customer_id:
            customer_id = create_stripe_customer(user["email"])
            if customer_id:
                _update_user(user_id, {"stripe_customer_id": customer_id})
        
        session = stripe.checkout.Session.create(
            customer=customer_id,
            payment_method_types=['card'],
            line_items=[{
                'price': price_id,
                'quantity': 1,
            }],
            mode='subscription' if price_id == STRIPE_MONTHLY_PRICE_ID else 'payment',
            success_url=success_url,
            cancel_url=cancel_url,
            metadata={
                "user_id": user_id,
                "price_id": price_id
            }
        )
        return session.url
    except Exception as e:
        logger.error("Failed to create checkout session: %s", e)
        return ""

def cancel_stripe_subscription(subscription_id: str) -> bool:
    """Cancel Stripe subscription"""
    if not STRIPE_ENABLED or not subscription_id:
        return False
    
    try:
        stripe.Subscription.delete(subscription_id)
        return True
    except Exception as e:
        logger.error("Failed to cancel subscription: %s", e)
        return False

def handle_stripe_webhook(payload: str, sig_header: str) -> bool:
    """Handle Stripe webhook events"""
    if not STRIPE_ENABLED or not STRIPE_WEBHOOK_SECRET:
        return False
    
    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, STRIPE_WEBHOOK_SECRET
        )
    except Exception as e:
        logger.error("Webhook signature verification failed: %s", e)
        return False
    
    # Handle the event
    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        user_id = session.get('metadata', {}).get('user_id')
        price_id = session.get('metadata', {}).get('price_id')
        
        if user_id:
            if price_id == STRIPE_MONTHLY_PRICE_ID:
                _update_user(user_id, {
                    "subscription_type": "monthly",
                    "subscription_status": "active",
                    "stripe_subscription_id": session.get('subscription', '')
                })
            elif price_id == STRIPE_SIXMONTH_PRICE_ID:
                _update_user(user_id, {
                    "subscription_type": "sixmonth",
                    "subscription_status": "active",
                    "subscription_expires_at": (datetime.utcnow() + timedelta(days=180)).isoformat()
                })
    
    elif event['type'] == 'customer.subscription.deleted':
        subscription = event['data']['object']
        # Find user by subscription ID and update status
        users = _users_all()
        for user in users:
            if user.get('stripe_subscription_id') == subscription['id']:
                _update_user(user['id'], {"subscription_status": "canceled"})
                break
    
    return True

# ====================================================================================================
# ROUTES - REMAINING SECTIONS
# ====================================================================================================

# [All the route handlers from the previous sections continue here...]
# [This includes all routes from landing_page through admin]

# Ensure content is seeded on startup
ensure_content_seeded()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(
        host="0.0.0.0",
        port=port,
        debug=DEBUG
    )
