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
             Comprehensive AI-powered preparation for the ASIS Certified Protection Professional certification. 
             Study smarter with our adaptive learning platform featuring expert-designed content and personalized feedback.
           </p>
           <div class="d-flex gap-3 flex-wrap">
             <a href="/register" class="btn btn-light btn-lg">Start 7-Day Free Trial</a>
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
         <h2 class="text-center mb-4">Comprehensive Study Features</h2>
       </div>
       <div class="col-md-3 text-center mb-4">
         <div class="card h-100 border-0 shadow-sm question-card">
           <div class="card-body">
             <div class="tutor-chat p-3 rounded-3 mb-3">
               <i class="bi bi-chat-dots display-4 text-white"></i>
             </div>
             <h5>AI Tutor</h5>
             <p class="text-muted">Get instant explanations and personalized guidance on complex CPP topics with our intelligent tutoring system</p>
           </div>
         </div>
       </div>
       <div class="col-md-3 text-center mb-4">
         <div class="card h-100 border-0 shadow-sm question-card">
           <div class="card-body">
             <i class="bi bi-layers text-success display-4 mb-3"></i>
             <h5>Smart Flashcards</h5>
             <p class="text-muted">Master key concepts with spaced repetition and adaptive learning technology</p>
           </div>
         </div>
       </div>
       <div class="col-md-3 text-center mb-4">
         <div class="card h-100 border-0 shadow-sm question-card">
           <div class="card-body">
             <i class="bi bi-ui-checks-grid text-warning display-4 mb-3"></i>
             <h5>Practice Quizzes</h5>
             <p class="text-muted">Test your knowledge with realistic exam questions featuring detailed explanations</p>
           </div>
         </div>
       </div>
       <div class="col-md-3 text-center mb-4">
         <div class="card h-100 border-0 shadow-sm question-card">
           <div class="card-body">
             <i class="bi bi-journal-check text-info display-4 mb-3"></i>
             <h5>Mock Exams</h5>
             <p class="text-muted">Full-length practice exams with comprehensive performance analytics</p>
           </div>
         </div>
       </div>
     </div>
     
     <div class="row mb-5">
       <div class="col-12">
         <h2 class="text-center mb-4">Choose Your Plan</h2>
         <p class="text-center text-muted mb-4">All plans include 7-day free trial • No setup fees • Cancel anytime</p>
       </div>
       <div class="col-md-6 mb-4">
         <div class="card h-100 border-primary">
           <div class="card-header bg-primary text-white text-center">
             <h4 class="mb-0">Monthly Plan</h4>
             <small class="text-light">Most Flexible</small>
           </div>
           <div class="card-body text-center">
             <div class="display-4 text-primary mb-3">$39.99</div>
             <p class="text-muted mb-4">per month, renews automatically</p>
             <ul class="list-unstyled mb-4">
               <li class="mb-2"><i class="bi bi-check-circle text-success me-2"></i>Full access to all study features</li>
               <li class="mb-2"><i class="bi bi-check-circle text-success me-2"></i>AI Tutor with unlimited questions</li>
               <li class="mb-2"><i class="bi bi-check-circle text-success me-2"></i>Comprehensive progress tracking</li>
               <li class="mb-2"><i class="bi bi-check-circle text-success me-2"></i>Mobile-optimized interface</li>
               <li class="mb-2"><i class="bi bi-check-circle text-success me-2"></i>Cancel anytime, no penalties</li>
             </ul>
             <a href="/register?plan=monthly" class="btn btn-primary btn-lg w-100">Start Free Trial</a>
           </div>
         </div>
       </div>
       <div class="col-md-6 mb-4">
         <div class="card h-100 border-success position-relative">
           <div class="position-absolute top-0 start-50 translate-middle">
             <span class="badge bg-warning text-dark px-3 py-2">Best Value - Save $140</span>
           </div>
           <div class="card-header bg-success text-white text-center">
             <h4 class="mb-0">6-Month Package</h4>
             <small class="text-light">Most Popular</small>
           </div>
           <div class="card-body text-center">
             <div class="display-4 text-success mb-3">$99.00</div>
             <p class="text-muted mb-4">one-time payment, no renewals</p>
             <ul class="list-unstyled mb-4">
               <li class="mb-2"><i class="bi bi-check-circle text-success me-2"></i>Full access to all study features</li>
               <li class="mb-2"><i class="bi bi-check-circle text-success me-2"></i>AI Tutor with unlimited questions</li>
               <li class="mb-2"><i class="bi bi-check-circle text-success me-2"></i>Comprehensive progress tracking</li>
               <li class="mb-2"><i class="bi bi-check-circle text-success me-2"></i>Mobile-optimized interface</li>
               <li class="mb-2"><i class="bi bi-check-circle text-success me-2"></i>6 months of worry-free access</li>
             </ul>
             <a href="/register?plan=sixmonth" class="btn btn-success btn-lg w-100">Start Free Trial</a>
           </div>
         </div>
       </div>
     </div>
     
     <div class="text-center mb-4">
       <p class="text-muted">✓ 7-day free trial with full access ✓ No hidden fees ✓ Secure payment processing</p>
       <p class="text-muted">Already have an account? <a href="/login" class="text-decoration-none">Sign in here</a></p>
     </div>
   </div>
   """
   
   return base_layout("CPP Exam Prep - Master Your Certification", content, show_nav=False)

@app.route("/register", methods=["GET", "POST"])
def register():
   if request.method == "GET":
       plan = request.args.get("plan", "monthly")
       next_url = request.args.get("next", "/dashboard")
       
       plan_display = "Monthly ($39.99/month)" if plan == "monthly" else "6-Month Package ($99.00 one-time)"
       
       content = f"""
       <div class="container" style="max-width: 600px;">
         <div class="card shadow-sm">
           <div class="card-header text-center bg-primary text-white">
             <h4 class="mb-0">Create Your Account</h4>
             <p class="mb-0 text-light">Start your 7-day free trial today</p>
           </div>
           <div class="card-body">
             <form method="post" id="registerForm">
               <input type="hidden" name="csrf_token" value="{csrf_token()}"/>
               <input type="hidden" name="plan" value="{html.escape(plan)}"/>
               <input type="hidden" name="next" value="{html.escape(next_url)}"/>
               
               <div class="mb-3">
                 <label class="form-label">Email Address</label>
                 <input type="email" name="email" class="form-control" required 
                        placeholder="your.email@example.com"/>
               </div>
               
               <div class="mb-3">
                 <label class="form-label">Password</label>
                 <input type="password" name="password" class="form-control" required 
                        minlength="8" id="password" onkeyup="checkPasswordStrength()"/>
                 <div class="password-strength mt-1" id="strengthBar"></div>
                 <div class="form-text" id="strengthText">
                   Password must contain: uppercase, lowercase, number (minimum 8 characters)
                 </div>
               </div>
               
               <div class="mb-3">
                 <label class="form-label">Confirm Password</label>
                 <input type="password" name="confirm_password" class="form-control" required
                        id="confirmPassword" onkeyup="checkPasswordMatch()"/>
                 <div class="form-text" id="matchText"></div>
               </div>
               
               <div class="mb-3">
                 <div class="form-check">
                   <input class="form-check-input" type="checkbox" name="accept_terms" 
                          id="accept_terms" required>
                   <label class="form-check-label" for="accept_terms">
                     I have read and agree to the <a href="/terms" target="_blank" class="text-decoration-none">Terms &amp; Conditions</a>
                   </label>
                 </div>
               </div>
               
               <div class="alert alert-info small">
                 <strong>Your Plan:</strong> {plan_display}<br>
                 <strong>Free Trial:</strong> 7 days full access, no charges during trial period.<br>
                 <strong>After Trial:</strong> Billing begins automatically unless cancelled.
               </div>
               
               <div class="d-grid gap-2">
                 <button type="submit" class="btn btn-primary btn-lg" id="submitBtn" disabled>
                   Start Your Free Trial
                 </button>
                 <a href="/login" class="btn btn-outline-secondary">Already have an account? Sign in</a>
               </div>
             </form>
           </div>
         </div>
       </div>
       
       <script>
         function checkPasswordStrength() {{
           const password = document.getElementById('password').value;
           const strengthBar = document.getElementById('strengthBar');
           const strengthText = document.getElementById('strengthText');
           const strength = checkPasswordStrength(password);
           
           strengthBar.style.width = (strength * 20) + '%';
           if (strength < 3) {{
             strengthBar.className = 'password-strength strength-weak';
             strengthText.textContent = 'Weak password - add more complexity';
             strengthText.className = 'form-text text-danger';
           }} else if (strength < 4) {{
             strengthBar.className = 'password-strength strength-medium';
             strengthText.textContent = 'Good password strength';
             strengthText.className = 'form-text text-warning';
           }} else {{
             strengthBar.className = 'password-strength strength-strong';
             strengthText.textContent = 'Strong password';
             strengthText.className = 'form-text text-success';
           }}
           validateForm();
         }}
         
         function checkPasswordMatch() {{
           const password = document.getElementById('password').value;
           const confirm = document.getElementById('confirmPassword').value;
           const matchText = document.getElementById('matchText');
           
           if (confirm && password !== confirm) {{
             matchText.textContent = 'Passwords do not match';
             matchText.className = 'form-text text-danger';
           }} else if (confirm && password === confirm) {{
             matchText.textContent = 'Passwords match';
             matchText.className = 'form-text text-success';
           }} else {{
             matchText.textContent = '';
           }}
           validateForm();
         }}
         
         function validateForm() {{
           const password = document.getElementById('password').value;
           const confirm = document.getElementById('confirmPassword').value;
           const terms = document.getElementById('accept_terms').checked;
           const submitBtn = document.getElementById('submitBtn');
           
           const passwordStrong = checkPasswordStrength(password) >= 3;
           const passwordsMatch = password === confirm && password.length > 0;
           
           submitBtn.disabled = !(passwordStrong && passwordsMatch && terms);
         }}
         
         document.getElementById('accept_terms').addEventListener('change', validateForm);
       </script>
       """
       return base_layout("Create Account", content, show_nav=False)
   
   # POST - process registration
   if not _csrf_ok():
       abort(403)
   
   email = (request.form.get("email") or "").strip().lower()
   password = request.form.get("password") or ""
   confirm_password = request.form.get("confirm_password") or ""
   plan = request.form.get("plan", "monthly")
   next_url = request.form.get("next") or "/dashboard"
   accept_terms = request.form.get("accept_terms") == "on"
   
   # Validation
   if not accept_terms:
       content = """
       <div class="container" style="max-width: 480px;">
         <div class="alert alert-danger">
           <i class="bi bi-exclamation-triangle me-2"></i>
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
           <i class="bi bi-exclamation-triangle me-2"></i>
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
           <i class="bi bi-exclamation-triangle me-2"></i>
           {html.escape(msg)}
         </div>
         <a href="/register" class="btn btn-primary">Try Again</a>
       </div>
       """
       return base_layout("Registration Failed", content, show_nav=False)
   
   success, result = _create_user(email, password, plan)
   if not success:
       content = f"""
       <div class="container" style="max-width: 480px;">
         <div class="alert alert-danger">
           <i class="bi bi-exclamation-triangle me-2"></i>
           {html.escape(result)}
         </div>
         <a href="/register" class="btn btn-primary">Try Again</a>
       </div>
       """
       return base_layout("Registration Failed", content, show_nav=False)
   
   # Success - auto login and redirect to dashboard
   session["uid"] = result
   session["email"] = email
   _log_event(result, "register.success", {"plan": plan})
   
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
           <i class="bi bi-exclamation-triangle me-2"></i>
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
@subscription_required
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
       <div class="col-md-6 col-lg-3">
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
       
       <div class="col-md-6 col-lg-3">
         <div class="card h-100 shadow-sm question-card">
           <div class="card-body text-center">
             <i class="bi bi-layers display-4 text-success mb-3"></i>
             <h5>Flashcards</h5>
             <p class="text-muted mb-3">Master key concepts with interactive cards</p>
             <a href="/flashcards" class="btn btn-success">Study Cards</a>
           </div>
         </div>
       </div>
       
       <div class="col-md-6 col-lg-3">
         <div class="card h-100 shadow-sm question-card">
           <div class="card-body text-center">
             <i class="bi bi-ui-checks-grid display-4 text-warning mb-3"></i>
             <h5>Quiz</h5>
             <p class="text-muted mb-3">Practice with realistic exam questions</p>
             <a href="/quiz" class="btn btn-warning">Take Quiz</a>
           </div>
         </div>
       </div>
       
       <div class="col-md-6 col-lg-3">
         <div class="card h-100 shadow-sm question-card">
           <div class="card-body text-center">
             <i class="bi bi-journal-check display-4 text-info mb-3"></i>
             <h5>Mock Exam</h5>
             <p class="text-muted mb-3">Full-length practice exams</p>
             <a href="/mock" class="btn btn-info">Start Exam</a>
           </div>
         </div>
       </div>
     </div>

     <div class="row">
       <div class="col-md-8">
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
       
       <div class="col-md-4">
         <div class="card">
           <div class="card-header">
             <h5 class="mb-0">Quick Stats</h5>
           </div>
           <div class="card-body">
             <div class="mb-2">
               <strong>Quiz Sessions:</strong> {progress_data['details']['quiz_sessions']}
             </div>
             <div class="mb-2">
               <strong>Mock Exams:</strong> {progress_data['details']['mock_sessions']}
             </div>
             <div class="mb-2">
               <strong>Domains Covered:</strong> {progress_data['details']['domains_covered']}/7
             </div>
             <div class="mb-2">
               <strong>Accuracy:</strong> {progress_data['details']['accuracy']}%
             </div>
             <a href="/progress" class="btn btn-outline-primary btn-sm">View Details</a>
           </div>
         </div>
       </div>
     </div>
   </div>
   """
   
   return base_layout("Dashboard", content)

@app.route("/tutor", methods=["GET", "POST"])
@subscription_required
def tutor():
   if request.method == "GET":
       # Get recent conversations for context
       attempts = _load_json("attempts.json", [])
       recent_tutors = [a for a in attempts if a.get("user_id") == _user_id() and a.get("mode") == "tutor"][-5:]
       
       conversation_html = ""
       if recent_tutors:
           conversation_html = "<h5 class='text-white mb-3'>Recent Conversations</h5>"
           for conv in recent_tutors:
               question = html.escape(conv.get("question", "")[:100] + "..." if len(conv.get("question", "")) > 100 else conv.get("question", ""))
               conversation_html += f"""
               <div class="mb-2 p-2 rounded" style="background: rgba(255,255,255,0.1);">
                 <small class="text-white-50">You asked:</small><br>
                 <small class="text-white">{question}</small>
               </div>
               """
       
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
           
           {conversation_html}
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
                          placeholder="e.g., 'Explain the difference between administrative, physical, and technical controls' or 'What are the key principles of CPTED?'" 
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
         
         <div class="mt-4">
           <h6>Suggested Topics:</h6>
           <div class="d-flex flex-wrap gap-2">
             <button class="btn btn-outline-secondary btn-sm" onclick="fillQuestion('Risk Management')">Risk Management</button>
             <button class="btn btn-outline-secondary btn-sm" onclick="fillQuestion('CPTED')">CPTED Principles</button>
             <button class="btn btn-outline-secondary btn-sm" onclick="fillQuestion('Access Control')">Access Control</button>
             <button class="btn btn-outline-secondary btn-sm" onclick="fillQuestion('Emergency Management')">Emergency Management</button>
             <button class="btn btn-outline-secondary btn-sm" onclick="fillQuestion('Investigations')">Investigations</button>
           </div>
         </div>
       </div>
       
       <script>
         function fillQuestion(topic) {{
           const textarea = document.querySelector('textarea[name="question"]');
           const suggestions = {{
             'Risk Management': 'Explain the risk management process and how to calculate ALE (Annual Loss Expectancy)',
             'CPTED': 'What are the four principles of Crime Prevention Through Environmental Design (CPTED)?',
             'Access Control': 'Compare and contrast different access control models (DAC, MAC, RBAC)',
             'Emergency Management': 'Describe the four phases of emergency management and their key activities',
             'Investigations': 'What are the essential steps in conducting a workplace investigation?'
           }};
           textarea.value = suggestions[topic] || `Tell me about ${{topic}} in the context of the CPP exam`;
         }}
       </script>
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
           <i class="bi bi-clock me-2"></i>
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

@app.route("/flashcards")
@subscription_required  
def flashcards():
   domain = request.args.get("domain", "all")
   domains = None if domain == "all" else [domain]
   cards = get_all_flashcards(domains)
   
   if not cards:
       content = """
       <div class="container">
         <div class="alert alert-info">
           <i class="bi bi-info-circle me-2"></i>
           No flashcards available for the selected domain. Try selecting "All Domains" or check back soon for new content!
         </div>
         <a href="/dashboard" class="btn btn-primary">Back to Dashboard</a>
       </div>
       """
       return base_layout("Flashcards", content)
   
   # Get a random card
   card_index = request.args.get("index", "0")
   try:
       card_index = int(card_index) % len(cards)
   except (ValueError, TypeError):
       card_index = 0
   
   card = cards[card_index]
   next_index = (card_index + 1) % len(cards)
   prev_index = (card_index - 1) % len(cards)
   
   _append_attempt(_user_id(), "flashcards", domain=card.get('domain'))
   
   content = f"""
   <div class="container">
     <div class="row mb-4">
       <div class="col-md-8">
         <h1 class="h4 mb-2">
           <i class="bi bi-layers me-2"></i>Flashcards
         </h1>
         <p class="text-muted">Domain: {html.escape(card.get('domain', 'Unknown'))}</p>
       </div>
       <div class="col-md-4 text-end">
         <span class="badge bg-primary">Card {card_index + 1} of {len(cards)}</span>
       </div>
     </div>
     
     <div class="row justify-content-center mb-4">
       <div class="col-lg-8">
         <div class="card text-center shadow-lg" style="min-height: 400px;" id="flashcard">
           <div class="card-body d-flex align-items-center justify-content-center">
             <div>
               <div id="cardFront">
                 <h3 class="card-title mb-4 text-primary">{html.escape(card.get('front', ''))}</h3>
                 <button class="btn btn-success btn-lg" onclick="flipCard()">
                   <i class="bi bi-eye me-2"></i>Show Answer
                 </button>
               </div>
               <div id="cardBack" style="display:none;">
                 <h5 class="text-success mb-3">Answer:</h5>
                 <p class="lead">{html.escape(card.get('back', ''))}</p>
                 <hr>
                 <div class="d-flex justify-content-center gap-3">
                   <button class="btn btn-outline-danger" onclick="markDifficulty('hard')">
                     <i class="bi bi-x-circle me-1"></i>Hard
                   </button>
                   <button class="btn btn-outline-warning" onclick="markDifficulty('medium')">
                     <i class="bi bi-dash-circle me-1"></i>Medium
                   </button>
                   <button class="btn btn-outline-success" onclick="markDifficulty('easy')">
                     <i class="bi bi-check-circle me-1"></i>Easy
                   </button>
                 </div>
               </div>
             </div>
           </div>
         </div>
       </div>
     </div>
     
     <div class="row">
       <div class="col-md-4">
         <a href="/flashcards?domain={html.escape(domain)}&index={prev_index}" 
            class="btn btn-outline-primary w-100">
           <i class="bi bi-arrow-left me-2"></i>Previous Card
         </a>
       </div>
       <div class="col-md-4 text-center">
         {domain_buttons_html(domain, "domain")}
       </div>
       <div class="col-md-4">
         <a href="/flashcards?domain={html.escape(domain)}&index={next_index}" 
            class="btn btn-outline-primary w-100">
           Next Card<i class="bi bi-arrow-right ms-2"></i>
         </a>
       </div>
     </div>
     
     <div class="text-center mt-4">
       <a href="/dashboard" class="btn btn-secondary">Back to Dashboard</a>
     </div>
   </div>
   
   <script>
     function flipCard() {{
       document.getElementById('cardFront').style.display = 'none';
       document.getElementById('cardBack').style.display = 'block';
       document.getElementById('flashcard').classList.add('correct-answer');
     }}
     
     function markDifficulty(level) {{
       // Could send to backend to track difficulty
       console.log('Marked as:', level);
       setTimeout(() => {{
         window.location.href = '/flashcards?domain={html.escape(domain)}&index={next_index}';
       }}, 500);
     }}
     
     // Domain selection
     document.querySelectorAll('.domain-btn').forEach(btn => {{
       btn.addEventListener('click', function() {{
         window.location.href = '/flashcards?domain=' + this.dataset.value;
       }});
     }});
   </script>
   """
   return base_layout("Flashcards", content)

@app.route("/quiz", methods=["GET", "POST"])
@subscription_required
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
                     <label class="form-label fw-bold">Select Domain</label>
                     {domain_buttons_html()}
                   </div>
                   
                   <div class="mb-4">
                     <label class="form-label fw-bold">Number of Questions</label>
                     <select name="count" class="form-select">
                       <option value="10">10 Questions (Quick Practice)</option>
                       <option value="20" selected>20 Questions (Standard)</option>
                       <option value="30">30 Questions (Extended)</option>
                       <option value="50">50 Questions (Comprehensive)</option>
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
       
       <script>
       document.querySelectorAll('.domain-btn').forEach(btn => {{
         btn.addEventListener('click', function() {{
           document.querySelectorAll('.domain-btn').forEach(b => b.classList.remove('active'));
           this.classList.add('active');
           document.getElementById('domain_val').value = this.dataset.value;
         }});
       }});
       </script>
       """
       return base_layout("Quiz Setup", content)
   
   # POST - start quiz
   if not _csrf_ok():
       abort(403)
   
   domain = request.form.get("domain", "all")
   count = int(request.form.get("count", 20))
   
   domains = None if domain == "all" else [domain]
   questions = select_questions(domains or list(CPP_DOMAINS.keys()), count, user_id=_user_id())
   
   if not questions:
       content = """
       <div class="container">
         <div class="alert alert-warning">
           <i class="bi bi-exclamation-triangle me-2"></i>
           No questions available for selected criteria. Please try different settings.
         </div>
         <a href="/quiz" class="btn btn-primary">Try Again</a>
       </div>
       """
       return base_layout("Quiz", content)
   
   # Store quiz in session
   session["quiz_questions"] = questions
   session["quiz_current"] = 0
   session["quiz_answers"] = []
   session["quiz_domain"] = domain
   
   return _render_quiz_question(questions, 0)

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
   
   <script>
     // Make choice options interactive
     document.querySelectorAll('input[name="answer"]').forEach(input => {{
       input.addEventListener('change', function() {{
         document.querySelectorAll('.choice-option').forEach(opt => opt.classList.remove('selected'));
         this.closest('.choice-option').classList.add('selected');
       }});
     }});
   </script>
   """
   return base_layout("Quiz", content)

def _render_question_choices(q):
   """Helper to render question choices with enhanced styling"""
   qtype = q.get("type", "")
   if qtype == "mc":
       choices_html = ""
       for i, choice in enumerate(q.get("choices", [])):
           choices_html += f"""
           <div class="choice-option border rounded p-3 mb-2">
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
       <div class="choice-option border rounded p-3 mb-2">
         <div class="form-check">
           <input class="form-check-input" type="radio" name="answer" value="true" id="true" required>
           <label class="form-check-label w-100" for="true">
             <strong>True</strong>
           </label>
         </div>
       </div>
       <div class="choice-option border rounded p-3 mb-2">
         <div class="form-check">
           <input class="form-check-input" type="radio" name="answer" value="false" id="false" required>
           <label class="form-check-label w-100" for="false">
             <strong>False</strong>
           </label>
         </div>
       </div>
       """
   elif qtype == "scenario":
       choices_html = ""
       for i, option in enumerate(q.get("options", [])):
           choices_html += f"""
           <div class="choice-option border rounded p-3 mb-2">
             <div class="form-check">
               <input class="form-check-input" type="radio" name="answer" value="{i}" id="option{i}" required>
               <label class="form-check-label w-100" for="option{i}">
                 <strong>{chr(65+i)}.</strong> {html.escape(option)}
               </label>
             </div>
           </div>
           """
       return choices_html
   return "<p>Question type not supported</p>"

@app.route("/quiz/answer", methods=["POST"])
@subscription_required
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
   elif q.get("type") == "scenario":
       try:
           user_idx = int(user_answer)
           correct_indices = q.get("answers", [0])
           is_correct = user_idx in correct_indices
           correct_answer = q.get("options", [])[correct_indices[0]] if correct_indices and correct_indices[0] < len(q.get("options", [])) else ""
       except (ValueError, IndexError):
           pass
   
   # Store answer
   if "quiz_answers" not in session:
       session["quiz_answers"] = []
   
   session["quiz_answers"].append({
       "question": q.get("stem", ""),
       "user_answer": user_answer,
       "is_correct": is_correct,
       "explanation": q.get("explanation", ""),
       "module": q.get("module", ""),
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
   module_ref = f" (Module: {q.get('module', 'General')})" if q.get('module') else ""
   
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
             <h6 class="text-muted mb-
3">Question:</h6>
             <p class="mb-3">{html.escape(q.get('stem', ''))}</p>
             
             {f'<p><strong>Your Answer:</strong> {html.escape(user_answer)}</p>' if not is_correct else ''}
             {f'<p><strong>Correct Answer:</strong> {html.escape(correct_answer)}</p>' if not is_correct and correct_answer else ''}
             
             <div class="alert alert-{'success' if is_correct else 'info'}">
               <strong>Explanation:</strong> {html.escape(explanation)}{module_ref}
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
@subscription_required
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
@subscription_required
def quiz_results():
   """Show quiz results"""
   return _show_quiz_results()

def _show_quiz_results():
   """Display comprehensive quiz results"""
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
   
   # Domain breakdown
   domain_stats = {}
   for answer in answers:
       domain = answer.get("domain", "Unknown")
       if domain not in domain_stats:
           domain_stats[domain] = {"correct": 0, "total": 0}
       domain_stats[domain]["total"] += 1
       if answer.get("is_correct", False):
           domain_stats[domain]["correct"] += 1
   
   domain_breakdown = ""
   for domain, stats in domain_stats.items():
       percentage = (stats["correct"] / stats["total"] * 100) if stats["total"] > 0 else 0
       domain_breakdown += f"""
       <div class="col-md-6 mb-2">
         <div class="d-flex justify-content-between">
           <span>{html.escape(domain)}</span>
           <span class="badge bg-{'success' if percentage >= 70 else 'warning' if percentage >= 60 else 'danger'}">
             {stats['correct']}/{stats['total']} ({percentage:.0f}%)
           </span>
         </div>
       </div>
       """
   
   # Detailed review
   detailed_review = ""
   for i, answer in enumerate(answers):
       icon = "bi-check-circle-fill text-success" if answer.get("is_correct") else "bi-x-circle-fill text-danger"
       status = "Correct" if answer.get("is_correct") else "Incorrect"
       detailed_review += f"""
       <div class="card mb-2">
         <div class="card-body p-3">
           <div class="d-flex align-items-start">
             <i class="bi {icon} me-2 mt-1"></i>
             <div class="flex-grow-1">
               <h6 class="mb-1">Question {i+1}: {status}</h6>
               <p class="mb-1 small">{html.escape(answer.get('question', '')[:100])}...</p>
               {f'<small class="text-muted">{html.escape(answer.get("explanation", ""))}</small>' if not answer.get("is_correct") else ''}
             </div>
           </div>
         </div>
       </div>
       """
   
   # Clear session
   session.pop("quiz_questions", None)
   session.pop("quiz_current", None)
   session.pop("quiz_answers", None)
   session.pop("quiz_domain", None)
   
   content = f"""
   <div class="container">
     <div class="row justify-content-center">
       <div class="col-md-10">
         <!-- Results Header -->
         <div class="card shadow-sm mb-4">
           <div class="card-header bg-{performance_class} text-white text-center">
             <h4 class="mb-0">
               <i class="bi {performance_icon} me-2"></i>
               Quiz Complete - {performance_text} Performance!
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
         
         <!-- Domain Breakdown -->
         <div class="card shadow-sm mb-4">
           <div class="card-header">
             <h5 class="mb-0">Performance by Domain</h5>
           </div>
           <div class="card-body">
             <div class="row">
               {domain_breakdown}
             </div>
           </div>
         </div>
         
         <!-- Detailed Review -->
         <div class="card shadow-sm mb-4">
           <div class="card-header">
             <h5 class="mb-0">Question Review</h5>
           </div>
           <div class="card-body">
             {detailed_review}
           </div>
         </div>
         
         <!-- Action Buttons -->
         <div class="text-center">
           <a href="/quiz" class="btn btn-primary btn-lg me-2">
             <i class="bi bi-arrow-repeat me-2"></i>Take Another Quiz
           </a>
           <a href="/mock" class="btn btn-info btn-lg me-2">
             <i class="bi bi-journal-check me-2"></i>Try Mock Exam
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

@app.route("/mock", methods=["GET", "POST"])
@subscription_required
def mock():
   if request.method == "GET":
       # Check if we're in the middle of a mock exam
       if "mock_questions" in session:
           current_q_idx = session.get("mock_current", 0)
           questions = session["mock_questions"]
           
           if current_q_idx < len(questions):
               return _render_mock_question(questions, current_q_idx)
           else:
               # Mock exam completed, show results
               return _show_mock_results()
       
       # Show mock exam setup
       content = f"""
       <div class="container">
         <div class="row justify-content-center">
           <div class="col-md-8">
             <div class="card shadow-sm">
               <div class="card-header bg-info text-white text-center">
                 <h4 class="mb-0">
                   <i class="bi bi-journal-check me-2"></i>Mock Exam Setup
                 </h4>
                 <p class="mb-0 text-light">Simulate real CPP exam conditions</p>
               </div>
               <div class="card-body">
                 <form method="post">
                   <input type="hidden" name="csrf_token" value="{csrf_token()}"/>
                   
                   <div class="mb-4">
                     <label class="form-label fw-bold">Exam Length</label>
                     <select name="count" class="form-select">
                       <option value="25">25 Questions (Quick Assessment)</option>
                       <option value="50" selected>50 Questions (Standard Practice)</option>
                       <option value="75">75 Questions (Extended Practice)</option>
                       <option value="100">100 Questions (Full Simulation)</option>
                     </select>
                   </div>
                   
                   <div class="alert alert-warning">
                     <i class="bi bi-clock me-2"></i>
                     <strong>Exam Conditions:</strong> 
                     <ul class="mb-0 mt-2">
                       <li>Questions are weighted by official CPP domain percentages</li>
                       <li>No going back to previous questions (like the real exam)</li>
                       <li>Immediate feedback after each question</li>
                       <li>Comprehensive performance analysis at the end</li>
                     </ul>
                   </div>
                   
                   <div class="d-grid gap-2">
                     <button type="submit" class="btn btn-info btn-lg">
                       <i class="bi bi-play-circle me-2"></i>Begin Mock Exam
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
       return base_layout("Mock Exam Setup", content)
   
   # POST - start mock exam
   if not _csrf_ok():
       abort(403)
   
   count = int(request.form.get("count", 50))
   
   # Get questions weighted by domains
   all_domains = list(CPP_DOMAINS.keys())
   questions = select_questions(all_domains, count, user_id=_user_id())
   
   if not questions:
       content = """
       <div class="container">
         <div class="alert alert-warning">
           <i class="bi bi-exclamation-triangle me-2"></i>
           Insufficient questions available for mock exam. Please try again later.
         </div>
         <a href="/mock" class="btn btn-primary">Try Again</a>
       </div>
       """
       return base_layout("Mock Exam", content)
   
   # Store mock exam in session
   session["mock_questions"] = questions
   session["mock_current"] = 0
   session["mock_answers"] = []
   session["mock_start_time"] = time.time()
   
   return _render_mock_question(questions, 0)

def _render_mock_question(questions, current_idx):
   """Render a single mock exam question"""
   q = questions[current_idx]
   total = len(questions)
   progress_percent = ((current_idx + 1) / total) * 100
   
   # Calculate estimated time
   start_time = session.get("mock_start_time", time.time())
   elapsed_time = time.time() - start_time
   estimated_total = (elapsed_time / (current_idx + 1)) * total if current_idx > 0 else elapsed_time * total
   estimated_remaining = max(0, estimated_total - elapsed_time)
   
   time_display = f"{int(estimated_remaining // 60)}:{int(estimated_remaining % 60):02d} remaining"
   
   content = f"""
   <div class="container">
     <div class="row justify-content-center">
       <div class="col-md-10">
         <!-- Header with timer -->
         <div class="d-flex justify-content-between align-items-center mb-3 p-3 bg-info text-white rounded">
           <div>
             <h5 class="mb-0">Mock Exam - Question {current_idx + 1} of {total}</h5>
             <small>{html.escape(q.get('domain', 'Unknown'))}</small>
           </div>
           <div class="text-end">
             <div class="h6 mb-0">
               <i class="bi bi-clock me-1"></i>{time_display}
             </div>
             <div class="progress mt-1" style="width: 150px; height: 8px;">
               <div class="progress-bar bg-warning" style="width: {progress_percent}%"></div>
             </div>
           </div>
         </div>
         
         <!-- Question card -->
         <div class="card shadow-sm question-card">
           <div class="card-body">
             <h5 class="card-title mb-4">{html.escape(q.get('stem', ''))}</h5>
             
             <form method="post" action="/mock/answer">
               <input type="hidden" name="csrf_token" value="{csrf_token()}"/>
               <input type="hidden" name="question_id" value="{html.escape(q.get('id', ''))}"/>
               
               {_render_question_choices(q)}
               
               <div class="d-grid gap-2 mt-4">
                 <button type="submit" class="btn btn-info btn-lg">
                   <i class="bi bi-arrow-right me-2"></i>Submit & Continue
                 </button>
               </div>
             </form>
           </div>
         </div>
       </div>
     </div>
   </div>
   
   <script>
     // Auto-submit prevention for accidental clicks
     let submitted = false;
     document.querySelector('form').addEventListener('submit', function(e) {{
       if (submitted) {{
         e.preventDefault();
         return false;
       }}
       submitted = true;
     }});
     
     // Make choice options interactive
     document.querySelectorAll('input[name="answer"]').forEach(input => {{
       input.addEventListener('change', function() {{
         document.querySelectorAll('.choice-option').forEach(opt => opt.classList.remove('selected'));
         this.closest('.choice-option').classList.add('selected');
       }});
     }});
   </script>
   """
   return base_layout("Mock Exam", content)

@app.route("/mock/answer", methods=["POST"])
@subscription_required
def mock_answer():
   """Process mock exam answer and show feedback"""
   if not _csrf_ok():
       abort(403)
   
   if "mock_questions" not in session:
       return redirect("/mock")
   
   questions = session["mock_questions"]
   current_idx = session.get("mock_current", 0)
   
   if current_idx >= len(questions):
       return redirect("/mock")
   
   q = questions[current_idx]
   user_answer = request.form.get("answer", "")
   
   # Determine if answer is correct (same logic as quiz)
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
   elif q.get("type") == "scenario":
       try:
           user_idx = int(user_answer)
           correct_indices = q.get("answers", [0])
           is_correct = user_idx in correct_indices
           correct_answer = q.get("options", [])[correct_indices[0]] if correct_indices and correct_indices[0] < len(q.get("options", [])) else ""
       except (ValueError, IndexError):
           pass
   
   # Store answer
   if "mock_answers" not in session:
       session["mock_answers"] = []
   
   session["mock_answers"].append({
       "question": q.get("stem", ""),
       "user_answer": user_answer,
       "is_correct": is_correct,
       "explanation": q.get("explanation", ""),
       "module": q.get("module", ""),
       "domain": q.get("domain", ""),
       "type": q.get("type", "")
   })
   
   # Log attempt
   _append_attempt(_user_id(), "mock", score=1 if is_correct else 0, total=1, 
                  domain=q.get("domain"), question=q.get("stem"), answer=user_answer)
   
   # Move to next question or show results
   session["mock_current"] = current_idx + 1
   
   # Show brief feedback then auto-advance
   feedback_class = "correct-answer" if is_correct else "incorrect-answer"
   feedback_icon = "bi-check-circle-fill text-success" if is_correct else "bi-x-circle-fill text-danger"
   feedback_title = "Correct!" if is_correct else "Incorrect"
   
   next_url = "/mock/next" if current_idx + 1 < len(questions) else "/mock/results"
   
   content = f"""
   <div class="container">
     <div class="row justify-content-center">
       <div class="col-md-8">
         <div class="card shadow-sm {feedback_class}">
           <div class="card-body text-center">
             <h4 class="mb-3">
               <i class="bi {feedback_icon} me-2"></i>
               {feedback_title}
             </h4>
             
             <p class="mb-3">{html.escape(q.get('explanation', 'No explanation available.'))}</p>
             
             {f'<p class="small text-muted">Module: {html.escape(q.get("module", "General"))}</p>' if q.get('module') else ''}
             
             <a href="{next_url}" class="btn btn-primary btn-lg">
               {'Continue to Next Question' if current_idx + 1 < len(questions) else 'View Exam Results'}
               <i class="bi bi-arrow-right ms-2"></i>
             </a>
           </div>
         </div>
       </div>
     </div>
   </div>
   
   <script>
     // Auto-advance after 5 seconds
     setTimeout(function() {{
       window.location.href = '{next_url}';
     }}, 5000);
   </script>
   """
   return base_layout("Mock Exam Feedback", content)

@app.route("/mock/next")
@subscription_required
def mock_next():
   """Move to next mock exam question"""
   if "mock_questions" not in session:
       return redirect("/mock")
   
   current_idx = session.get("mock_current", 0)
   questions = session["mock_questions"]
   
   if current_idx >= len(questions):
       return redirect("/mock/results")
   
   return _render_mock_question(questions, current_idx)

@app.route("/mock/results")
@subscription_required
def mock_results():
   """Show mock exam results"""
   return _show_mock_results()

def _show_mock_results():
   """Display comprehensive mock exam results"""
   if "mock_answers" not in session:
       return redirect("/mock")
   
   answers = session["mock_answers"]
   total_questions = len(answers)
   correct_count = sum(1 for a in answers if a.get("is_correct", False))
   score_percentage = (correct_count / total_questions * 100) if total_questions > 0 else 0
   
   # Calculate exam time
   start_time = session.get("mock_start_time", time.time())
   total_time = time.time() - start_time
   time_per_question = total_time / total_questions if total_questions > 0 else 0
   
   # Performance analysis
   if score_percentage >= 80:
       performance_class = "success"
       performance_text = "Excellent - Ready for CPP Exam"
       performance_icon = "bi-trophy-fill"
       recommendation = "You're performing at exam-ready level! Continue reviewing weak areas and consider scheduling your CPP exam."
   elif score_percentage >= 70:
       performance_class = "info"
       performance_text = "Good - Nearly Ready"
       performance_icon = "bi-star-fill"
       recommendation = "Strong performance! Focus on improving weak domains and take more practice exams."
   elif score_percentage >= 60:
       performance_class = "warning"
       performance_text = "Fair - More Study Needed"
       performance_icon = "bi-exclamation-triangle-fill"
       recommendation = "You're making progress but need more study time. Focus on understanding concepts rather than memorization."
   else:
       performance_class = "danger"
       performance_text = "Needs Improvement"
       performance_icon = "bi-arrow-repeat"
       recommendation = "More comprehensive study is needed. Consider reviewing fundamentals and using the AI tutor for difficult concepts."
   
   # Domain breakdown with CPP weightings
   domain_stats = {}
   for answer in answers:
       domain = answer.get("domain", "Unknown")
       if domain not in domain_stats:
           domain_stats[domain] = {"correct": 0, "total": 0}
       domain_stats[domain]["total"] += 1
       if answer.get("is_correct", False):
           domain_stats[domain]["correct"] += 1
   
   domain_breakdown = ""
   for domain, stats in domain_stats.items():
       percentage = (stats["correct"] / stats["total"] * 100) if stats["total"] > 0 else 0
       weight = CPP_DOMAINS.get(domain.lower().replace(" ", ""), {}).get("weight", 0) * 100
       domain_breakdown += f"""
       <div class="row mb-2">
         <div class="col-6">
           <small>{html.escape(domain)}</small>
           <br><span class="text-muted small">Weight: {weight:.0f}%</span>
         </div>
         <div class="col-3 text-center">
           {stats['correct']}/{stats['total']}
         </div>
         <div class="col-3 text-end">
           <span class="badge bg-{'success' if percentage >= 70 else 'warning' if percentage >= 60 else 'danger'}">
             {percentage:.0f}%
           </span>
         </div>
       </div>
       """
   
   # Clear session
   session.pop("mock_questions", None)
   session.pop("mock_current", None)
   session.pop("mock_answers", None)
   session.pop("mock_start_time", None)
   
   content = f"""
   <div class="container">
     <div class="row justify-content-center">
       <div class="col-md-10">
         <!-- Results Header -->
         <div class="card shadow-sm mb-4">
           <div class="card-header bg-{performance_class} text-white text-center">
             <h4 class="mb-0">
               <i class="bi {performance_icon} me-2"></i>
               Mock Exam Complete
             </h4>
             <p class="mb-0">{performance_text}</p>
           </div>
           <div class="card-body text-center">
             <div class="row">
               <div class="col-md-3">
                 <h3 class="text-{performance_class}">{correct_count}/{total_questions}</h3>
                 <p class="text-muted mb-0">Correct</p>
               </div>
               <div class="col-md-3">
                 <h3 class="text-{performance_class}">{score_percentage:.1f}%</h3>
                 <p class="text-muted mb-0">Score</p>
               </div>
               <div class="col-md-3">
                 <h3 class="text-{performance_class}">{int(total_time // 60)}:{int(total_time % 60):02d}</h3>
                 <p class="text-muted mb-0">Total Time</p>
               </div>
               <div class="col-md-3">
                 <h3 class="text-{performance_class}">{time_per_question:.1f}s</h3>
                 <p class="text-muted mb-0">Per Question</p>
               </div>
             </div>
           </div>
         </div>
         
         <!-- Recommendation -->
         <div class="alert alert-{performance_class}">
           <h6 class="alert-heading">Recommendation:</h6>
           {recommendation}
         </div>
         
         <!-- Domain Performance -->
         <div class="card shadow-sm mb-4">
           <div class="card-header">
             <h5 class="mb-0">Domain Performance Analysis</h5>
           </div>
           <div class="card-body">
             <div class="row mb-2">
               <div class="col-6"><strong>Domain</strong></div>
               <div class="col-3 text-center"><strong>Correct</strong></div>
               <div class="col-3 text-end"><strong>Score</strong></div>
             </div>
             <hr>
             {domain_breakdown}
           </div>
         </div>
         
         <!-- Action Buttons -->
         <div class="text-center">
           <a href="/mock" class="btn btn-info btn-lg me-2">
             <i class="bi bi-arrow-repeat me-2"></i>Take Another Mock Exam
           </a>
           <a href="/quiz" class="btn btn-warning btn-lg me-2">
             <i class="bi bi-ui-checks-grid me-2"></i>Practice Quiz
           </a>
           <a href="/tutor" class="btn btn-primary btn-lg me-2">
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
   return base_layout("Mock Exam Results", content)

@app.route("/progress")
@subscription_required
def progress():
   """Detailed progress tracking page"""
   progress_data = calculate_user_progress(_user_id())
   
   # Get historical data
   attempts = _load_json("attempts.json", [])
   user_attempts = [a for a in attempts if a.get("user_id") == _user_id()]
   
   # Recent activity
   recent_activity = ""
   for attempt in user_attempts[-10:]:
       timestamp = attempt.get("ts", "")
       mode = attempt.get("mode", "")
       domain = attempt.get("domain", "")
       score = attempt.get("score")
       
       icon_map = {
           "quiz": "bi-ui-checks-grid text-warning",
           "mock": "bi-journal-check text-info", 
           "tutor": "bi-chat-dots text-primary",
           "flashcards": "bi-layers text-success"
       }
       
       icon = icon_map.get(mode, "bi-circle")
       score_text = f"({score}/1)" if score is not None else ""
       
       recent_activity += f"""
       <div class="d-flex align-items-center mb-2 p-2 rounded bg-light">
         <i class="bi {icon} me-3"></i>
         <div class="flex-grow-1">
           <strong>{mode.title()}</strong> - {domain} {score_text}
           <br><small class="text-muted">{timestamp}</small>
         </div>
       </div>
       """
   
   content = f"""
   <div class="container">
     <h1 class="h4 mb-4">
       <i class="bi bi-graph-up me-2"></i>Your Progress
     </h1>
     
     <div class="row mb-4">
       <div class="col-md-6">
         {progress_meter_html(progress_data)}
         <div class="text-center">
           <h5 class="text-{progress_data['color']}">
             {progress_data['overall_percentage']}% Complete
           </h5>
           <p class="text-muted">{html.escape(progress_data['status'])}</p>
         </div>
       </div>
       <div class="col-md-6">
         <div class="card">
           <div class="card-header">
             <h6 class="mb-0">Study Statistics</h6>
           </div>
           <div class="card-body">
             <div class="row text-center">
               <div class="col-6 mb-3">
                 <h4 class="text-warning">{progress_data['details']['quiz_sessions']}</h4>
                 <small class="text-muted">Quiz Sessions</small>
               </div>
               <div class="col-6 mb-3">
                 <h4 class="text-info">{progress_data['details']['mock_sessions']}</h4>
                 <small class="text-muted">Mock Exams</small>
               </div>
               <div class="col-6 mb-3">
                 <h4 class="text-primary">{progress_data['details']['tutor_sessions']}</h4>
                 <small class="text-muted">Tutor Questions</small>
               </div>
               <div class="col-6 mb-3">
                 <h4 class="text-success">{progress_data['details']['flashcard_sessions']}</h4>
                 <small class="text-muted">Flashcard Sessions</small>
               </div>
             </div>
             <hr>
             <div class="text-center">
               <h5 class="text-primary">{progress_data['details']['accuracy']}%</h5>
               <small class="text-muted">Overall Accuracy</small>
             </div>
           </div>
         </div>
       </div>
     </div>
     
     <div class="row">
       <div class="col-md-8">
         <div class="card">
           <div class="card-header">
             <h6 class="mb-0">Domain Coverage</h6>
           </div>
           <div class="card-body">
             <p class="mb-3">
               <strong>{progress_data['details']['domains_covered']}</strong> of 7 domains covered
             </p>
             
             <div class="row g-2">
               <div class="col-sm-6">
                 <div class="border rounded p-2 small">
                   <strong>Domain 1:</strong> Security Principles &amp; Practices
                 </div>
               </div>
               <div class="col-sm-6">
                 <div class="border rounded p-2 small">
                   <strong>Domain 2:</strong> Business Principles &amp; Practices
                 </div>
               </div>
               <div class="col-sm-6">
                 <div class="border rounded p-2 small">
                   <strong>Domain 3:</strong> Investigations
                 </div>
               </div>
               <div class="col-sm-6">
                 <div class="border rounded p-2 small">
                   <strong>Domain 4:</strong> Personnel Security
                 </div>
               </div>
               <div class="col-sm-6">
                 <div class="border rounded p-2 small">
                   <strong>Domain 5:</strong> Physical Security
                 </div>
               </div>
               <div class="col-sm-6">
                 <div class="border rounded p-2 small">
                   <strong>Domain 6:</strong> Information Security
                 </div>
               </div>
               <div class="col-sm-6">
                 <div class="border rounded p-2 small">
                   <strong>Domain 7:</strong> Crisis Management
                 </div>
               </div>
             </div>
           </div>
         </div>
       </div>
       
       <div class="col-md-4">
         <div class="card">
           <div class="card-header">
             <h6 class="mb-0">Recent Activity</h6>
           </div>
           <div class="card-body" style="max-height: 400px; overflow-y: auto;">
             {recent_activity if recent_activity else '<p class="text-muted">No recent activity</p>'}
           </div>
         </div>
       </div>
     </div>
     
     <div class="text-center mt-4">
       <a href="/dashboard" class="btn btn-primary">Back to Dashboard</a>
     </div>
   </div>
   """
   return base_layout("Progress", content)

@app.route("/billing")
@login_required
def billing():
   """Billing management page"""
   user = _current_user()
   expired = request.args.get("expired") == "1"
   
   subscription_info = ""
   if user.get("subscription_status") == "trial":
       trial_end = user.get("trial_ends_at")
       if trial_end:
           try:
               trial_date = datetime.fromisoformat(trial_end.replace('Z', ''))
               days_left = (trial_date - datetime.utcnow()).days
               subscription_info = f"""
               <div class="alert alert-info">
                 <i class="bi bi-info-circle me-2"></i>
                 <strong>Free Trial:</strong> {max(0, days_left)} days remaining
                 {"<br><strong>Choose a plan below to continue after your trial.</strong>" if days_left <= 3 else ""}
               </div>
               """
           except (ValueError, TypeError):
               subscription_info = """
               <div class="alert alert-info">
                 <i class="bi bi-info-circle me-2"></i>
                 <strong>Free Trial:</strong> Active
               </div>
               """
   elif user.get("subscription_status") == "active":
       if user.get("subscription_type") == "monthly":
           subscription_info = """
           <div class="alert alert-success">
             <i class="bi bi-check-circle me-2"></i>
             <strong>Monthly Subscription:</strong> Active - $39.99/month
             <br>Renews automatically. You can cancel anytime below.
           </div>
           """
       elif user.get("subscription_type") == "sixmonth":
           expires = user.get("subscription_expires_at")
           if expires:
               try:
                   expire_date = datetime.fromisoformat(expires.replace('Z', ''))
                   days_left = (expire_date - datetime.utcnow()).days
                   subscription_info = f"""
                   <div class="alert alert-success">
                     <i class="bi bi-check-circle me-2"></i>
                     <strong>6-Month Package:</strong> Active - {max(0, days_left)} days remaining
                     <br>One-time purchase, no automatic renewal.
                   </div>
                   """
               except (ValueError, TypeError):
                   subscription_info = """
                   <div class="alert alert-success">
                     <i class="bi bi-check-circle me-2"></i>
                     <strong>6-Month Package:</strong> Active
                   </div>
                   """
   
   if expired:
       subscription_info = """
       <div class="alert alert-warning">
         <i class="bi bi-exclamation-triangle me-2"></i>
         <strong>Subscription Expired:</strong> Please choose a plan below to continue studying.
       </div>
       """
   
   # Determine which buttons to show
   is_monthly_active = (user.get('subscription_type') == 'monthly' and 
                       user.get('subscription_status') == 'active')
   is_sixmonth_active = (user.get('subscription_type') == 'sixmonth' and 
                        user.get('subscription_status') == 'active')
   
   monthly_button = ('<button class="btn btn-outline-primary disabled w-100">Current Plan</button>' 
                    if is_monthly_active else 
                    '<a href="/billing/checkout?plan=monthly" class="btn btn-primary w-100">Select Monthly</a>')
   
   sixmonth_button = ('<button class="btn btn-outline-success disabled w-100">Current Plan</button>' 
                     if is_sixmonth_active else 
                     '<a href="/billing/checkout?plan=sixmonth" class="btn btn-success w-100">Select 6-Month</a>')
   
   cancel_section = ""
   if is_monthly_active and STRIPE_ENABLED:
       cancel_section = f"""
       <div class="card border-danger">
         <div class="card-header bg-danger text-white">
           <h5 class="mb-0">
             <i class="bi bi-exclamation-triangle me-2"></i>Cancel Subscription
           </h5>
         </div>
         <div class="card-body">
           <p class="text-muted">
             Cancelling will stop future billing. You'll retain access until your current billing period ends.
           </p>
           <form method="post" action="/billing/cancel" class="d-inline">
             <input type="hidden" name="csrf_token" value="{csrf_token()}"/>
             <button type="submit" class="btn btn-danger" onclick="return confirm('Are you sure you want to cancel your subscription?')">
               <i class="bi bi-x-circle me-2"></i>Cancel Monthly Subscription
             </button>
           </form>
         </div>
       </div>
       """
   
   content = f"""
   <div class="container" style="max-width: 900px;">
     <div class="d-flex justify-content-between align-items-center mb-4">
       <h1 class="h4 mb-0">
         <i class="bi bi-credit-card me-2"></i>Billing &amp; Subscription
       </h1>
       <a href="/dashboard" class="btn btn-outline-secondary">
         <i class="bi bi-arrow-left me-2"></i>Back to Dashboard
       </a>
     </div>
     
     {subscription_info}
     
     <div class="row mb-4">
       <div class="col-md-6 mb-3">
         <div class="card h-100 shadow-sm">
           <div class="card-header bg-primary text-white text-center">
             <h5 class="mb-1">Monthly Plan</h5>
             <small class="text-light">Most Flexible</small>
           </div>
           <div class="card-body text-center">
             <div class="h3 text-primary mb-3">$39.99<small class="text-muted">/month</small></div>
             <p class="text-muted mb-3">Renews automatically until cancelled</p>
             <ul class="list-unstyled small mb-4 text-start">
               <li class="mb-1"><i class="bi bi-check text-success me-2"></i>Full platform access</li>
               <li class="mb-1"><i class="bi bi-check text-success me-2"></i>Unlimited AI Tutor usage</li>
               <li class="mb-1"><i class="bi bi-check text-success me-2"></i>Comprehensive progress tracking</li>
               <li class="mb-1"><i class="bi bi-check text-success me-2"></i>Mobile-optimized interface</li>
               <li class="mb-1"><i class="bi bi-check text-success me-2"></i>Cancel anytime, no penalties</li>
             </ul>
             {monthly_button}
           </div>
         </div>
       </div>
       
       <div class="col-md-6 mb-3">
         <div class="card h-100 shadow-sm position-relative">
           <div class="position-absolute top-0 start-50 translate-middle">
             <span class="badge bg-warning text-dark px-3 py-1">Save $140</span>
           </div>
           <div class="card-header bg-success text-white text-center">
             <h5 class="mb-1">6-Month Package</h5>
             <small class="text-light">Best Value</small>
           </div>
           <div class="card-body text-center">
             <div class="h3 text-success mb-3">$99.00<small class="text-muted"> one-time</small></div>
             <p class="text-muted mb-3">No recurring charges or renewals</p>
             <ul class="list-unstyled small mb-4 text-start">
               <li class="mb-1"><i class="bi bi-check text-success me-2"></i>Full platform access</li>
               <li class="mb-1"><i class="bi bi-check text-success me-2"></i>Unlimited AI Tutor usage</li>
               <li class="mb-1"><i class="bi bi-check text-success me-2"></i>Comprehensive progress tracking</li>
               <li class="mb-1"><i class="bi bi-check text-success me-2"></i>Mobile-optimized interface</li>
               <li class="mb-1"><i class="bi bi-check text-success me-2"></i>6 months worry-free access</li>
             </ul>
             {sixmonth_button}
           </div>
         </div>
       </div>
     </div>
     
     {cancel_section}
     
     <div class="card bg-light">
       <div class="card-body">
         <h6 class="mb-3">
           <i class="bi bi-shield-check me-2"></i>Secure Payment Information
         </h6>
         <div class="row text-center">
           <div class="col-md-4 mb-2">
             <i class="bi bi-lock-fill text-success me-1"></i>
             <small>SSL Encrypted</small>
           </div>
           <div class="col-md-4 mb-2">
             <i class="bi bi-credit-card text-primary me-1"></i>
             <small>Stripe Powered</small>
           </div>
           <div class="col-md-4 mb-2">
             <i class="bi bi-arrow-repeat text-info me-1"></i>
             <small>Cancel Anytime</small>
           </div>
         </div>
       </div>
     </div>
   </div>
   """
   
   return base_layout("Billing", content)

@app.route("/billing/checkout")
@login_required
def billing_checkout():
   """Create Stripe checkout session"""
   plan = request.args.get("plan", "monthly")
   
   if not STRIPE_ENABLED:
       content = """
       <div class="container">
         <div class="alert alert-warning">
           <i class="bi bi-exclamation-triangle me-2"></i>
           Billing is not currently available. Please contact support.
         </div>
         <a href="/billing" class="btn btn-primary">Back to Billing</a>
       </div>
       """
       return base_layout("Checkout", content)
   
   price_id = STRIPE_MONTHLY_PRICE_ID if plan == "monthly" else STRIPE_SIXMONTH_PRICE_ID
   if not price_id:
       abort(400)
   
   success_url = request.url_root + "billing/success"
   cancel_url = request.url_root + "billing"
   
   checkout_url = create_checkout_session(_user_id(), price_id, success_url, cancel_url)
   
   if checkout_url:
       return redirect(checkout_url)
   else:
       content = """
       <div class="container">
         <div class="alert alert-danger">
           <i class="bi bi-exclamation-triangle me-2"></i>
           Unable to create checkout session. Please try again.
         </div>
         <a href="/billing" class="btn btn-primary">Back to Billing</a>
       </div>
       """
       return base_layout("Checkout Error", content)

@app.route("/billing/success")
@login_required
def billing_success():
   """Billing success page"""
   content = """
   <div class="container text-center">
     <div class="py-5">
       <i class="bi bi-check-circle-fill text-success display-1 mb-4"></i>
       <h1 class="h3 text-success mb-3">Payment Successful!</h1>
       <p class="lead mb-4">
         Your subscription is now active. You have full access to all CPP prep features and can begin studying immediately.
       </p>
       <div class="d-flex justify-content-center gap-3">
         <a href="/dashboard" class="btn btn-success btn-lg">
           <i class="bi bi-house me-2"></i>Go to Dashboard
         </a>
         <a href="/quiz" class="btn btn-outline-primary btn-lg">
           <i class="bi bi-ui-checks-grid me-2"></i>Start Studying
         </a>
       </div>
     </div>
   </div>
   """
   return base_layout("Payment Successful", content)

@app.route("/billing/cancel", methods=["POST"])
@login_required
def billing_cancel():
   """Cancel subscription"""
   if not _csrf_ok():
       abort(403)
   
   user = _current_user()
   subscription_id = user.get("stripe_subscription_id")
   
   if subscription_id and cancel_stripe_subscription(subscription_id):
       _update_user(_user_id(), {"subscription_status": "canceled"})
       _log_event(_user_id(), "subscription.canceled")
       
       content = """
       <div class="container text-center">
         <div class="py-5">
           <i class="bi bi-check-circle-fill text-success display-1 mb-4"></i>
           <h1 class="h3 mb-3">Subscription Cancelled</h1>
           <p class="lead mb-4">
             Your subscription has been cancelled successfully. You'll retain access until your current billing period ends.
           </p>
           <div class="alert alert-info">
             We're sorry to see you go! If you change your mind, you can always resubscribe at any time.
           </div>
           <a href="/billing" class="btn btn-primary btn-lg">Back to Billing</a>
         </div>
       </div>
       """
       return base_layout("Subscription Cancelled", content)
   else:
       content = """
       <div class="container">
         <div class="alert alert-danger">
           <i class="bi bi-exclamation-triangle me-2"></i>
           Unable to cancel subscription. Please contact support for assistance.
         </div>
         <a href="/billing" class="btn btn-primary">Back to Billing</a>
       </div>
       """
       return base_layout("Cancellation Error", content)

@app.route("/stripe/webhook", methods=["POST"])
def stripe_webhook():
   """Handle Stripe webhooks"""
   payload = request.get_data()
   sig_header = request.headers.get("Stripe-Signature")
   
   if handle_stripe_webhook(payload.decode('utf-8'), sig_header):
       return jsonify({"status": "success"})
   else:
       abort(400)

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
         
         <h5>3. Subscription and Billing</h5>
         <p>Monthly subscriptions renew automatically until cancelled. 6-month packages are one-time purchases with no automatic renewal.</p>
         
         <h5>4. Disclaimer</h5>
         <p><strong>This program is not affiliated with or approved by ASIS International. It uses only open-source and publicly available study materials. No ASIS-protected content is included.</strong></p>
         
         <h5>5. Educational Use Only</h5>
         <p>All content is for educational purposes only. No legal, safety, or professional advice is provided. Users should verify information with official sources.</p>
         
         <h5>6. No Guarantee</h5>
         <p>We do not guarantee exam results or certification success. Individual results may vary.</p>
         
         <h5>7. Privacy</h5>
         <p>We collect minimal personal information and do not share user data with third parties except as required for payment processing.</p>
         
         <h5>8. Cancellation</h5>
         <p>Monthly subscriptions can be cancelled at any time with no penalties. Refunds are not available for 6-month packages after purchase.</p>
         
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

@app.route("/admin", methods=["GET", "POST"])
def admin():
   """Admin panel for system management"""
   if request.method == "GET":
       if not is_admin():
           content = f"""
           <div class="container" style="max-width: 400px;">
             <div class="card shadow-sm">
               <div class="card-header text-center">
                 <h4 class="mb-0">Admin Access</h4>
               </div>
               <div class="card-body">
                 <form method="post">
                   <input type="hidden" name="csrf_token" value="{csrf_token()}"/>
                   <div class="mb-3">
                     <label class="form-label">Admin Password</label>
                     <input type="password" name="password" class="form-control" required/>
                   </div>
                   <button type="submit" class="btn btn-primary w-100">Access Admin Panel</button>
                 </form>
               </div>
             </div>
           </div>
           """
           return base_layout("Admin Access", content, show_nav=False)
       
       # Show admin panel
       users = _users_all()
       questions = get_all_questions()
       flashcards = get_all_flashcards()
       attempts = _load_json("attempts.json", [])
       
       content = f"""
       <div class="container">
         <h1 class="h4 mb-4">
           <i class="bi bi-gear me-2"></i>Admin Panel
         </h1>
         
         <div class="row mb-4">
           <div class="col-md-3">
             <div class="card text-center">
               <div class="card-body">
                 <h3 class="text-primary">{len(users)}</h3>
                 <p class="mb-0">Total Users</p>
               </div>
             </div>
           </div>
           <div class="col-md-3">
             <div class="card text-center">
               <div class="card-body">
                 <h3 class="text-success">{len(questions)}</h3>
                 <p class="mb-0">Questions</p>
               </div>
             </div>
           </div>
           <div class="col-md-3">
             <div class="card text-center">
               <div class="card-body">
                 <h3 class="text-warning">{len(flashcards)}</h3>
                 <p class="mb-0">Flashcards</p>
               </div>
             </div>
           </div>
           <div class="col-md-3">
             <div class="card text-center">
               <div class="card-body">
                 <h3 class="text-info">{len(attempts)}</h3>
                 <p class="mb-0">Study Sessions</p>
               </div>
             </div>
           </div>
         </div>
         
         <div class="card">
           <div class="card-header">
             <h5 class="mb-0">Recent Users</h5>
           </div>
           <div class="card-body">
             <div class="table-responsive">
               <table class="table table-sm">
                 <thead>
                   <tr>
                     <th>Email</th>
                     <th>Status</th>
                     <th>Type</th>
                     <th>Created</th>
                   </tr>
                 </thead>
                 <tbody>
       """
       
       for user in users[-10:]:
           status = user.get("subscription_status", "unknown")
           sub_type = user.get("subscription_type", "unknown")
           created = user.get("created_at", "")[:10]
           
           content += f"""
                   <tr>
                     <td>{html.escape(user.get('email', ''))}</td>
                     <td><span class="badge bg-{'success' if status == 'active' else 'warning' if status == 'trial' else 'secondary'}">{status}</span></td>
                     <td>{sub_type}</td>
                     <td>{created}</td>
                   </tr>
           """
       
       content += """
                 </tbody>
               </table>
             </div>
           </div>
         </div>
         
         <div class="mt-4">
           <a href="/dashboard" class="btn btn-primary">Back to Dashboard</a>
           <a href="/logout" class="btn btn-outline-secondary">Logout</a>
         </div>
       </div>
       """
       return base_layout("Admin Panel", content)
   
   # POST - verify admin password
   if not _csrf_ok():
       abort(403)
   
   password = request.form.get("password", "")
   if password == ADMIN_PASSWORD and ADMIN_PASSWORD:
       session["admin_ok"] = True
       return redirect("/admin")
   else:
       abort(403)

# Ensure content is seeded on startup
ensure_content_seeded()

if __name__ == "__main__":
   port = int(os.environ.get("PORT", 5000))
   app.run(
       host="0.0.0.0",
       port=port,
       debug=DEBUG
   )

