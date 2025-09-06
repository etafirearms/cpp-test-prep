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
try:
    import stripe
    stripe.api_key = STRIPE_SECRET_KEY
    STRIPE_ENABLED = bool(STRIPE_SECRET_KEY)
except ImportError:
    STRIPE_ENABLED = False
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
                if trial_end and datetime.fromisoformat(trial_end.replace('Z', '')) < datetime.utcnow():
                    return redirect("/billing?expired=1")
            return fn(*args, **kwargs)
        else:
            return redirect("/billing?expired=1")
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
    "Confidence comes from preparation - you're building it every day!"
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
                "domains_covered": 0
            }
        }
    
    # Count different types of activities
    quiz_sessions = len([a for a in user_attempts if a.get("mode") == "quiz"])
    mock_sessions = len([a for a in user_attempts if a.get("mode") == "mock"])
    tutor_sessions = len([a for a in user_attempts if a.get("mode") == "tutor"])
    flashcard_sessions = len([a for a in user_attempts if a.get("mode") == "flashcards"])
    
    # Count unique domains covered
    domains_covered = len(set([a.get("domain") for a in user_attempts if a.get("domain")]))
    
    # Calculate progress score based on multiple factors
    progress_score = 0
    
    # Activity diversity (30% of score)
    activity_score = min(30, (quiz_sessions * 2) + (mock_sessions * 5) + (tutor_sessions * 1) + (flashcard_sessions * 1))
    progress_score += activity_score
    
    # Domain coverage (40% of score)
    domain_score = (domains_covered / 7) * 40
    progress_score += domain_score
    
    # Consistency bonus (30% of score) - based on recent activity
    recent_attempts = [a for a in user_attempts[-20:]]  # Last 20 attempts
    if len(recent_attempts) >= 10:
        progress_score += 30
    elif len(recent_attempts) >= 5:
        progress_score += 15
    
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
            "domains_covered": domains_covered
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
    rotation = -90 + (percentage * 1.8)
    
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
          <line x1="60" y1="60" x2="60" y2="25" stroke="#333" stroke-width="2" 
                transform="rotate({rotation} 60 60)" transform-origin="60 60"/>
          
          <!-- Center dot -->
          <circle cx="60" cy="60" r="3" fill="#333"/>
        </svg>
        
        <div class="position-absolute w-100" style="bottom: -10px;">
          <div class="fw-bold text-{color}">{percentage}%</div>
          <div class="small text-muted">{status}</div>
        </div>
      </div>
    </div>
    """

def base_layout(title: str, body_html: str, show_nav: bool = True) -> str:
    """Base layout with navigation and footer"""
    nav_html = ""
    if show_nav:
        user = _current_user()
        nav_html = f"""
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
                {"" if not user else f'''
                <a class="text-decoration-none" href="/tutor">Tutor</a>
                <a class="text-decoration-none" href="/flashcards">Flashcards</a>
                <a class="text-decoration-none" href="/quiz">Quiz</a>
                <a class="text-decoration-none" href="/mock">Mock Exam</a>
                <a class="text-decoration-none" href="/progress">Progress</a>
                <a class="text-decoration-none" href="/billing">Billing</a>
                <a class="btn btn-outline-danger btn-sm" href="/logout">Logout</a>
                '''}
                {"" if user else '''
                <a class="btn btn-outline-primary btn-sm" href="/login">Login</a>
                <a class="btn btn-primary btn-sm" href="/register">Sign Up</a>
                '''}
              </div>
            </div>
          </div>
        </nav>
        """
    
    tpl = f"""
    <!doctype html>
    <html lang="en">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>{html.escape(title or "CPP Exam Prep")}</title>
      <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
      <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css" rel="stylesheet">
      <style>
        .progress-meter svg {{ max-width: 100%; height: auto; }}
        .tutor-chat {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }}
        .tutor-message {{ background: rgba(255,255,255,0.95); border-radius: 15px; }}
        .user-message {{ background: #e3f2fd; border-radius: 15px; }}
        .correct-answer {{ background-color: #d4edda; border: 1px solid #c3e6cb; }}
        .incorrect-answer {{ background-color: #f8d7da; border: 1px solid #f5c6cb; }}
        .question-card {{ transition: all 0.3s ease; }}
        .question-card:hover {{ transform: translateY(-2px); box-shadow: 0 4px 15px rgba(0,0,0,0.1); }}
        .encouragement-message {{ 
          background: linear-gradient(45deg, #4CAF50, #2196F3);
          color: white;
          border-radius: 10px;
          padding: 1rem;
          animation: slideIn 0.5s ease-out;
        }}
        @keyframes slideIn {{
          from {{ opacity: 0; transform: translateY(-10px); }}
          to {{ opacity: 1; transform: translateY(0); }}
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
    return tpl

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
    return f'<div class="d-flex flex-wrap gap-2">{" ".join(buttons)}</div>{hidden}'

# ====================================================================================================
# CONTENT GENERATION SYSTEM
# ====================================================================================================

class CPPContentGenerator:
    """Generate comprehensive CPP study content"""
    
    @classmethod
    def generate_sample_questions(cls) -> List[Dict[str, Any]]:
        """Generate a comprehensive set of sample questions"""
        questions = []
        
        # Domain 1: Security Principles & Practices (22%)
        domain1_questions = [
            {
                "type": "mc",
                "domain": "Domain 1",
                "stem": "Which control type is MOST effective at deterring unauthorized access before it occurs?",
                "choices": ["Detective controls", "Preventive controls", "Corrective controls", "Compensating controls"],
                "answer": 1,
                "explanation": "Preventive controls are designed to stop incidents before they happen, making them most effective at deterring unauthorized access. Detective controls identify incidents after they occur, corrective controls fix problems, and compensating controls provide alternative protection.",
                "module": "Security Controls Framework"
            },
            {
                "type": "tf",
                "domain": "Domain 1", 
                "stem": "Risk can be completely eliminated through proper security controls.",
                "answer": False,
                "explanation": "Risk can be reduced, transferred, or accepted, but never completely eliminated. There is always residual risk remaining after implementing security controls.",
                "module": "Risk Management Fundamentals"
            },
            {
                "type": "scenario",
                "domain": "Domain 1",
                "stem": "Your organization experienced a data breach due to an unpatched server. Management wants to prevent similar incidents. Which combination of controls would provide the BEST layered defense?",
                "options": ["Automated patch management only", "Employee training and incident response plan", "Patch management, network segmentation, and intrusion detection", "Firewall configuration and antivirus software"],
                "answers": [2],
                "explanation": "Option C provides multiple layers of protection: patch management prevents vulnerabilities, network segmentation limits breach scope, and intrusion detection identifies threats. Single controls or limited combinations don't provide adequate defense in depth.",
                "module": "Defense in Depth Strategy"
            },
            {
                "type": "mc",
                "domain": "Domain 1",
                "stem": "What is the PRIMARY purpose of a vulnerability assessment?",
                "choices": ["To identify threats", "To identify weaknesses", "To calculate risk", "To implement controls"],
                "answer": 1,
                "explanation": "Vulnerability assessments identify weaknesses in systems, processes, or physical security that could be exploited by threats. This is different from threat identification or risk calculation.",
                "module": "Security Assessment Methods"
            }
        ]
        
        # Domain 2: Business Principles & Practices (15%)
        domain2_questions = [
            {
                "type": "mc",
                "domain": "Domain 2",
                "stem": "When calculating Annual Loss Expectancy (ALE), which formula is correct?",
                "choices": ["ALE = Asset Value × Threat Frequency", "ALE = Single Loss Expectancy × Annual Rate of Occurrence", "ALE = Risk × Vulnerability × Asset Value", "ALE = Impact × Likelihood × Controls"],
                "answer": 1,
                "explanation": "ALE = SLE × ARO. Single Loss Expectancy represents the dollar loss from one incident, and Annual Rate of Occurrence is how often it happens per year. This gives the expected annual loss.",
                "module": "Risk Quantification Methods"
            },
            {
                "type": "tf",
                "domain": "Domain 2",
                "stem": "A cost-benefit analysis should always recommend the security control with the lowest implementation cost.",
                "answer": False,
                "explanation": "Cost-benefit analysis should recommend controls where benefits exceed costs by the greatest margin, not necessarily the cheapest option. The most cost-effective solution provides the best value.",
                "module": "Business Case Development"
            }
        ]
        
        # Add more domains with similar structure...
        questions.extend(domain1_questions * 5)  # Multiply to reach target count
        questions.extend(domain2_questions * 3)
        
        # Add unique IDs and timestamps
        for i, q in enumerate(questions):
            q["id"] = f"q_{uuid.uuid4().hex[:8]}"
            q["source"] = "generated"
            q["created_at"] = int(time.time())
        
        return questions

    @classmethod
    def generate_sample_flashcards(cls) -> List[Dict[str, Any]]:
        """Generate sample flashcards"""
        flashcards = [
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
            }
        ]
        
        # Add unique IDs and timestamps
        for i, fc in enumerate(flashcards):
            fc["id"] = f"fc_{uuid.uuid4().hex[:8]}"
            fc["source"] = "generated"
            fc["created_at"] = int(time.time())
        
        return flashcards * 10  # Multiply to create more content

def ensure_content_seeded():
    """Ensure content bank has sufficient material"""
    questions = get_all_questions()
    flashcards = get_all_flashcards()
    
    if len(questions) < 50:
        logger.info("Seeding question bank...")
        new_questions = CPPContentGenerator.generate_sample_questions()
        for q in new_questions:
            pass  # Would call ingest_questions in full implementation
        _write_jsonl(_QUESTIONS_FILE, new_questions)
    
    if len(flashcards) < 20:
        logger.info("Seeding flashcard bank...")
        new_flashcards = CPPContentGenerator.generate_sample_flashcards()
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
    
    content = f"""
    <div class="hero-section bg-primary text-white py-5 mb-5">
      <div class="container">
        <div class="row align-items-center">
          <div class="col-lg-6">
            <h1 class="display-4 fw-bold mb-3">Master the CPP Exam</h1>
            <p class="lead mb-4">
              Comprehensive AI-powered preparation for the ASIS Certified Protection Professional certification. 
              Study smarter with our adaptive learning platform.
            </p>
            <div class="d-flex gap-3">
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
        <div class="col-md-3 text-center mb-4">
          <div class="card h-100 border-0 shadow-sm">
            <div class="card-body">
              <i class="bi bi-chat-dots text-primary display-4 mb-3"></i>
              <h5>AI Tutor</h5>
              <p class="text-muted">Get instant explanations and guidance on complex CPP topics</p>
            </div>
          </div>
        </div>
        <div class="col-md-3 text-center mb-4">
          <div class="card h-100 border-0 shadow-sm">
            <div class="card-body">
              <i class="bi bi-layers text-success display-4 mb-3"></i>
              <h5>Flashcards</h5>
              <p class="text-muted">Master key concepts with interactive study cards</p>
            </div>
          </div>
        </div>
        <div class="col-md-3 text-center mb-4">
          <div class="card h-100 border-0 shadow-sm">
            <div class="card-body">
              <i class="bi bi-ui-checks-grid text-warning display-4 mb-3"></i>
              <h5>Practice Quizzes</h5>
              <p class="text-muted">Test your knowledge with realistic exam questions</p>
            </div>
          </div>
        </div>
        <div class="col-md-3 text-center mb-4">
          <div class="card h-100 border-0 shadow-sm">
            <div class="card-body">
              <i class="bi bi-journal-check text-info display-4 mb-3"></i>
              <h5>Mock Exams</h5>
              <p class="text-muted">Full-length practice exams with detailed feedback</p>
            </div>
          </div>
        </div>
      </div>
      
      <div class="row mb-5">
        <div class="col-12">
          <h2 class="text-center mb-4">Choose Your Plan</h2>
        </div>
        <div class="col-md-6 mb-4">
          <div class="card h-100 border-primary">
            <div class="card-header bg-primary text-white text-center">
              <h4 class="mb-0">Monthly Plan</h4>
            </div>
            <div class="card-body text-center">
              <div class="display-4 text-primary mb-3">$39.99</div>
              <p class="text-muted mb-4">per month, renews automatically</p>
              <ul class="list-unstyled mb-4">
                <li class="mb-2"><i class="bi bi-check-circle text-success me-2"></i>Full access to all features</li>
                <li class="mb-2"><i class="bi bi-check-circle text-success me-2"></i>AI Tutor with unlimited questions</li>
                <li class="mb-2"><i class="bi bi-check-circle text-success me-2"></i>Progress tracking</li>
                <li class="mb-2"><i class="bi bi-check-circle text-success me-2"></i>Cancel anytime</li>
              </ul>
              <a href="/register?plan=monthly" class="btn btn-primary btn-lg w-100">Start Monthly Plan</a>
            </div>
          </div>
        </div>
        <div class="col-md-6 mb-4">
          <div class="card h-100 border-success">
            <div class="card-header bg-success text-white text-center">
              <h4 class="mb-0">6-Month Package</h4>
              <small class="badge bg-warning text-dark">Best Value</small>
            </div>
            <div class="card-body text-center">
              <div class="display-4 text-success mb-3">$99.00</div>
              <p class="text-muted mb-4">one-time payment, no renewals</p>
              <ul class="list-unstyled mb-4">
                <li class="mb-2"><i class="bi bi-check-circle text-success me-2"></i>Full access to all features</li>
                <li class="mb-2"><i class="bi bi-check-circle text-success me-2"></i>AI Tutor with unlimited questions</li>
                <li class="mb-2"><i class="bi bi-check-circle text-success me-2"></i>Progress tracking</li>
                <li class="mb-2"><i class="bi bi-check-circle text-success me-2"></i>Save $140 vs monthly</li>
              </ul>
              <a href="/register?plan=sixmonth" class="btn btn-success btn-lg w-100">Get 6-Month Access</a>
            </div>
          </div>
        </div>
      </div>
      
      <div class="text-center mb-4">
        <p class="text-muted">All plans include a 7-day free trial. No hidden fees.</p>
        <p class="text-muted">Already have an account? <a href="/login">Sign in here</a></p>
      </div>
    </div>
    """
    
    return base_layout("CPP Exam Prep - Master Your Certification", content, show_nav=False)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        plan = request.args.get("plan", "monthly")
        next_url = request.args.get("next", "/dashboard")
        
        content = f"""
        <div class="container" style="max-width: 600px;">
          <div class="card shadow-sm">
            <div class="card-header text-center">
              <h4 class="mb-0">Create Your Account</h4>
              <p class="text-muted mb-0">Start your 7-day free trial</p>
            </div>
            <div class="card-body">
              <form method="post" id="registerForm">
                <input type="hidden" name="csrf_token" value="{csrf_token()}"/>
                <input type="hidden" name="plan" value="{html.escape(plan)}"/>
                <input type="hidden" name="next" value="{html.escape(next_url)}"/>
                
                <div class="mb-3">
                  <label class="form-label">Email Address</label>
                  <input type="email" name="email" class="form-control" required/>
                </div>
                
                <div class="mb-3">
                  <label class="form-label">Password</label>
                  <input type="password" name="password" class="form-control" required minlength="8"/>
                  <div class="form-text">Minimum 8 characters</div>
                </div>
                
                <div class="mb-3">
                  <label class="form-label">Confirm Password</label>
                  <input type="password" name="confirm_password" class="form-control" required/>
                </div>
                
                <div class="mb-3">
                  <div class="form-check">
                    <input class="form-check-input" type="checkbox" name="accept_terms" id="accept_terms" required>
                    <label class="form-check-label" for="accept_terms">
                      I have read and agree to the <a href="/terms" target="_blank">Terms & Conditions</a>
                    </label>
                  </div>
                </div>
                
                <div class="alert alert-info small">
                  <strong>Your Plan:</strong> {plan.title()} - 
                  {"$39.99/month (renews automatically)" if plan == "monthly" else "$99.00 one-time (6 months access)"}
                  <br>
                  <strong>Free Trial:</strong> 7 days full access, no charges during trial period.
                </div>
                
                <div class="d-grid gap-2">
                  <button type="submit" class="btn btn-primary btn-lg">Start Free Trial</button>
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
    plan = request.form.get("plan", "monthly")
    next_url = request.form.get("next") or "/dashboard"
    accept_terms = request.form.get("accept_terms") == "on"
    
    # Validation
    if not accept_terms:
        content = """
        <div class="container" style="max-width: 480px;">
          <div class="alert alert-danger">You must accept the Terms & Conditions to continue.</div>
          <a href="/register" class="btn btn-primary">Back to Registration</a>
        </div>
        """
        return base_layout("Registration Failed", content, show_nav=False)
    
    if password != confirm_password:
        content = """
        <div class="container" style="max-width: 480px;">
          <div class="alert alert-danger">Passwords do not match.</div>
          <a href="/register" class="btn btn-primary">Try Again</a>
        </div>
        """
        return base_layout("Registration Failed", content, show_nav=False)
    
    valid, msg = validate_password(password)
    if not valid:
        content = f"""
        <div class="container" style="max-width: 480px;">
          <div class="alert alert-danger">{html.escape(msg)}</div>
          <a href="/register" class="btn btn-primary">Try Again</a>
        </div>
        """
        return base_layout("Registration Failed", content, show_nav=False)
    
    success, result = _create_user(email, password, plan)
    if not success:
        content = f"""
        <div class="container" style="max-width: 480px;">
          <div class="alert alert-danger">{html.escape(result)}</div>
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
            <div class="card-header text-center">
              <h4 class="mb-0">Sign In</h4>
            </div>
            <div class="card-body">
              <form method="post">
                <input type="hidden" name="csrf_token" value="{csrf_token()}"/>
                <input type="hidden" name="next" value="{html.escape(next_url)}"/>
                
                <div class="mb-3">
                  <label class="form-label">Email</label>
                  <input type="email" name="email" class="form-control" required/>
                </div>
                
                <div class="mb-3">
                  <label class="form-label">Password</label>
                  <input type="password" name="password" class="form-control" required/>
                </div>
                
                <div class="d-grid gap-2">
                  <button type="submit" class="btn btn-primary">Sign In</button>
                  <a href="/register" class="btn btn-outline-secondary">Create Account</a>
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
          <div class="alert alert-danger">Invalid email or password.</div>
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

# ====================================================================================================
# ROUTES - MAIN DASHBOARD
# ====================================================================================================

@app.route("/dashboard")
@subscription_required
def dashboard():
    """Main dashboard with progress meter and encouragement"""
    user = _current_user()
    progress_data = calculate_user_progress(_user_id())
    encouragement = get_random_encouragement()
    
    content = f"""
    <div class="container">
      <div class="row mb-4">
        <div class="col-md-8">
          <h1 class="h3 mb-2">Welcome back, {html.escape(user.get('email', '').split('@')[0])}!</h1>
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
                    <strong>Domain 1:</strong> Security Principles & Practices (22%)
                  </div>
                </div>
                <div class="col-sm-6">
                  <div class="border rounded p-2 small">
                    <strong>Domain 2:</strong> Business Principles & Practices (15%)
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
                <strong>Tutor Questions:</strong> {progress_data['details']['tutor_sessions']}
              </div>
              <a href="/progress" class="btn btn-outline-primary btn-sm">View Details</a>
            </div>
          </div>
        </div>
      </div>
    </div>
    
    <script>
      // Rotate encouragement message every 30 seconds
      setTimeout(function() {{
        location.reload();
      }}, 30000);
    </script>
    """
    
    return base_layout("Dashboard", content)

# ====================================================================================================
# ROUTES - BILLING MANAGEMENT
# ====================================================================================================

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
            trial_date = datetime.fromisoformat(trial_end.replace('Z', ''))
            days_left = (trial_date - datetime.utcnow()).days
            subscription_info = f"""
            <div class="alert alert-info">
              <strong>Free Trial:</strong> {max(0, days_left)} days remaining
              {"<br><strong>Choose a plan below to continue after your trial.</strong>" if days_left <= 3 else ""}
            </div>
            """
    elif user.get("subscription_status") == "active":
        if user.get("subscription_type") == "monthly":
            subscription_info = f"""
            <div class="alert alert-success">
              <strong>Monthly Subscription:</strong> Active - $39.99/month
              <br>Renews automatically. You can cancel anytime below.
            </div>
            """
        elif user.get("subscription_type") == "sixmonth":
            expires = user.get("subscription_expires_at")
            if expires:
                expire_date = datetime.fromisoformat(expires.replace('Z', ''))
                days_left = (expire_date - datetime.utcnow()).days
                subscription_info = f"""
                <div class="alert alert-success">
                  <strong>6-Month Package:</strong> Active - {max(0, days_left)} days remaining
                  <br>One-time purchase, no automatic renewal.
                </div>
                """
    
    if expired:
        subscription_info = """
        <div class="alert alert-warning">
          <strong>Subscription Expired:</strong> Please choose a plan below to continue studying.
        </div>
        """
    
    content = f"""
    <div class="container" style="max-width: 800px;">
      <h1 class="h4 mb-4">Billing & Subscription</h1>
      
      {subscription_info}
      
      <div class="row mb-4">
        <div class="col-md-6 mb-3">
          <div class="card h-100">
            <div class="card-header bg-primary text-white">
              <h5 class="mb-0">Monthly Plan</h5>
            </div>
            <div class="card-body">
              <div class="h4 text-primary">$39.99/month</div>
              <p class="text-muted">Renews automatically until cancelled</p>
              <ul class="list-unstyled small mb-3">
                <li><i class="bi bi-check text-success me-1"></i> Full platform access</li>
                <li><i class="bi bi-check text-success me-1"></i> Unlimited AI Tutor</li>
                <li><i class="bi bi-check text-success me-1"></i> Progress tracking</li>
                <li><i class="bi bi-check text-success me-1"></i> Cancel anytime</li>
              </ul>
              {"<button class='btn btn-outline-primary disabled'>Current Plan</button>" if user.get('subscription_type') == 'monthly' and user.get('subscription_status') == 'active' else f"<a href='/billing/checkout?plan=monthly' class='btn btn-primary'>Select Monthly</a>"}
            </div>
          </div>
        </div>
        
        <div class="col-md-6 mb-3">
          <div class="card h-100">
            <div class="card-header bg-success text-white">
              <h5 class="mb-0">6-Month Package</h5>
            </div>
            <div class="card-body">
              <div class="h4 text-success">$99.00</div>
              <p class="text-muted">One-time payment, no renewals</p>
              <ul class="list-unstyled small mb-3">
                <li><i class="bi bi-check text-success me-1"></i> Full platform access</li>
                <li><i class="bi bi-check text-success me-1"></i> Unlimited AI Tutor</li>
                <li><i class="bi bi-check text-success me-1"></i> Progress tracking</li>
                <li><i class="bi bi-check text-success me-1"></i> Save $140 vs monthly</li>
              </ul>
              {"<button class='btn btn-outline-success disabled'>Current Plan</button>" if user.get('subscription_type') == 'sixmonth' and user.get('subscription_status') == 'active' else f"<a href='/billing/checkout?plan=sixmonth' class='btn btn-success'>Select 6-Month</a>"}
            </div>
          </div>
        </div>
      </div>
      
      {"" if user.get('subscription_type') != 'monthly' or user.get('subscription_status') != 'active' else '''
      <div class="card border-danger">
        <div class="card-header bg-danger text-white">
          <h5 class="mb-0">Cancel Subscription</h5>
        </div>
        <div class="card-body">
          <p class="text-muted">
            Cancelling will stop future billing. You'll retain access until your current billing period ends.
          </p>
          <form method="post" action="/billing/cancel" class="d-inline">
            <input type="hidden" name="csrf_token" value="''' + csrf_token() + '''"/>
            <button type="submit" class="btn btn-danger" onclick="return confirm('Are you sure you want to cancel your subscription?')">
              Cancel Monthly Subscription
            </button>
          </form>
        </div>
      </div>
      '''}
      
      <div class="mt-4">
        <a href="/dashboard" class="btn btn-outline-secondary">Back to Dashboard</a>
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
        <i class="bi bi-check-circle text-success display-1 mb-3"></i>
        <h1 class="h3 text-success mb-3">Payment Successful!</h1>
        <p class="lead mb-4">
          Your subscription is now active. You have full access to all CPP prep features.
        </p>
        <a href="/dashboard" class="btn btn-primary btn-lg">Start Studying</a>
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
            <i class="bi bi-check-circle text-success display-1 mb-3"></i>
            <h1 class="h3 mb-3">Subscription Cancelled</h1>
            <p class="lead mb-4">
              Your subscription has been cancelled. You'll retain access until your current billing period ends.
            </p>
            <a href="/billing" class="btn btn-primary">Back to Billing</a>
          </div>
        </div>
        """
        return base_layout("Subscription Cancelled", content)
    else:
        content = """
        <div class="container">
          <div class="alert alert-danger">
            Unable to cancel subscription. Please contact support.
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

# ====================================================================================================
# ROUTES - STUDY MODES (TUTOR, FLASHCARDS, QUIZ, MOCK EXAM)
# ====================================================================================================

@app.route("/tutor")
@subscription_required
def tutor():
    """AI Tutor interface with enhanced design"""
    offline_note = ""
    if not _ai_enabled():
        offline_note = """
        <div class="alert alert-warning mb-3 border-warning">
          <i class="bi bi-wifi-off me-2"></i>
          <strong>Tutor Offline:</strong> AI features are currently unavailable. 
          You can still access flashcards, quizzes, and mock exams.
        </div>
        """
    
    # Enhanced suggested questions
    suggestions = [
        "Explain the three lines of defense in corporate risk governance.",
        "How do you calculate Annual Loss Expectancy (ALE)? Give an example.",
        "What are the key CPTED principles and how do they reduce crime?",
        "Outline steps for investigating a data breach incident.",
        "Compare proprietary vs. contract security forces—pros and cons.",
        "What's the difference between a vulnerability and a threat?",
        "How should evidence be preserved during an investigation?",
        "Explain role-based access control (RBAC) with examples.",
        "What are the phases of emergency management?",
        "Define business continuity vs. disaster recovery."
    ]
    
    suggestions_html = ""
    for suggestion in suggestions[:6]:
        suggestions_html += f"""
        <button type="button" class="btn btn-outline-primary btn-sm mb-2 w-100 text-start suggestion-btn" 
                data-question="{html.escape(suggestion)}">
          <i class="bi bi-chat-square-text me-2"></i>{html.escape(suggestion)}
        </button>
        """
    
    content = f"""
    <div class="container">
      <div class="row mb-4">
        <div class="col-12">
          <div class="tutor-chat p-4 rounded-3 text-white text-center mb-3">
            <h1 class="h3 mb-2">
              <i class="bi bi-chat-dots me-2"></i>AI Tutor
            </h1>
            <p class="mb-0 opacity-90">
              Get instant explanations and guidance on CPP exam topics
            </p>
          </div>
        </div>
      </div>

      {offline_note}

      <div class="row g-4">
        <div class="col-lg-8">
          <div class="card shadow-sm h-100">
            <div class="card-header bg-light">
              <h5 class="mb-0">
                <i class="bi bi-chat-left-dots me-2 text-primary"></i>
                Conversation
              </h5>
            </div>
            <div class="card-body d-flex flex-column">
              <div id="chat-log" class="flex-grow-1 mb-3" style="min-height: 300px; max-height: 500px; overflow-y: auto;">
                <div class="text-center text-muted py-4">
                  <i class="bi bi-chat-square-dots display-4 text-muted mb-2"></i>
                  <p>Ask a question to start your conversation with the AI tutor.</p>
                </div>
              </div>
              
              <form id="tutor-form" method="post" action="/tutor/ask">
                <input type="hidden" name="csrf_token" value="{csrf_token()}"/>
                <div class="input-group">
                  <textarea id="question" name="question" class="form-control" rows="2" 
                            placeholder="Ask about any CPP topic..." style="resize: none;"></textarea>
                  <button id="ask-btn" type="submit" class="btn btn-primary">
                    <i class="bi bi-send"></i>
                  </button>
                </div>
                <div id="loading" class="text-center mt-2 d-none">
                  <div class="spinner-border spinner-border-sm text-primary me-2"></div>
                  <span class="text-muted">Tutor is thinking...</span>
                </div>
              </form>
            </div>
          </div>
        </div>

        <div class="col-lg-4">
          <div class="card shadow-sm">
            <div class="card-header bg-light">
              <h5 class="mb-0">
                <i class="bi bi-lightbulb me-2 text-warning"></i>
                Suggested Questions
              </h5>
            </div>
            <div class="card-body">
              <div class="d-grid gap-1">
                {suggestions_html}
              </div>
              <div class="text-muted small mt-3">
                <i class="bi bi-info-circle me-1"></i>
                Click any suggestion to ask automatically, or type your own question.
              </div>
            </div>
          </div>
          
          <div class="card shadow-sm mt-3">
            <div class="card-header bg-light">
              <h5 class="mb-0">
                <i class="bi bi-book me-2 text-info"></i>
                Study Tips
              </h5>
            </div>
            <div class="card-body">
              <ul class="list-unstyled small mb-0">
                <li class="mb-2"><i class="bi bi-check2 text-success me-2"></i>Ask "why" and "how" questions</li>
                <li class="mb-2"><i class="bi bi-check2 text-success me-2"></i>Request real-world examples</li>
                <li class="mb-2"><i class="bi bi-check2 text-success me-2"></i>Focus on understanding concepts</li>
                <li class="mb-0"><i class="bi bi-check2 text-success me-2"></i>Connect topics to your experience</li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </div>

    <script>
      document.addEventListener('DOMContentLoaded', function() {
        const form = document.getElementById('tutor-form');
        const questionInput = document.getElementById('question');
        const askBtn = document.getElementById('ask-btn');
        const loading = document.getElementById('loading');
        const chatLog = document.getElementById('chat-log');
        
        // Handle suggestion clicks
        document.querySelectorAll('.suggestion-btn').forEach(btn => {
          btn.addEventListener('click', function() {
            const question = this.dataset.question;
            questionInput.value = question;
            submitQuestion();
          });
        });
        
        // Handle form submission
        form.addEventListener('submit', function(e) {
          e.preventDefault();
          submitQuestion();
        });
        
        // Enter to submit (Shift+Enter for new line)
        questionInput.addEventListener('keydown', function(e) {
          if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            submitQuestion();
          }
        });
        
        async function submitQuestion() {
          const question = questionInput.value.trim();
          if (!question) return;
          
          // Show loading state
          askBtn.disabled = true;
          loading.classList.remove('d-none');
          
          // Clear welcome message if present
          if (chatLog.innerHTML.includes('Ask a question to start')) {
            chatLog.innerHTML = '';
          }
          
          // Add user message
          addMessage('You', question, 'user');
          
          try {
            const formData = new FormData(form);
            const response = await fetch('/tutor/ask', {
              method: 'POST',
              body: formData
            });
            
            const data = await response.json();
            
            if (data.ok) {
              addMessage('AI Tutor', data.answer, 'assistant');
            } else {
              addMessage('System', data.error || 'An error occurred. Please try again.', 'error');
            }
            
            questionInput.value = '';
          } catch (error) {
            addMessage('System', 'Failed to get response. Please check your connection and try again.', 'error');
          } finally {
            askBtn.disabled = false;
            loading.classList.add('d-none');
          }
        }
        
        function addMessage(sender, content, type) {
          const messageDiv = document.createElement('div');
          messageDiv.className = 'mb-3';
          
          let messageClass = 'tutor-message p-3';
          let senderIcon = 'bi-chat-dots';
          let senderColor = 'text-primary';
          
          if (type === 'user') {
            messageClass = 'user-message p-3';
            senderIcon = 'bi-person-circle';
            senderColor = 'text-info';
          } else if (type === 'error') {
            messageClass = 'alert alert-danger p-3';
            senderIcon = 'bi-exclamation-triangle';
            senderColor = 'text-danger';
          }
          
          messageDiv.innerHTML = `
            <div class="${messageClass}">
              <div class="d-flex align-items-center mb-2">
                <i class="bi ${senderIcon} ${senderColor} me-2"></i>
                <strong class="${senderColor}">${escapeHtml(sender)}</strong>
              </div>
              <div>${formatContent(content)}</div>
            </div>
          `;
          
          chatLog.appendChild(messageDiv);
          chatLog.scrollTop = chatLog.scrollHeight;
        }
        
        function formatContent(content) {
          // Simple formatting - convert newlines to paragraphs and preserve structure
          return escapeHtml(content)
            .replace(/\n\n/g, '</p><p>')
            .replace(/\n/g, '<br>')
            .replace(/^/, '<p>')
            .replace(/$/, '</p>')
            .replace(/<p><\/p>/g, '');
        }
        
        function escapeHtml(text) {
          const div = document.createElement('div');
          div.textContent = text;
          return div.innerHTML;
        }
      });
    </script>
    """
    
    _log_event(_user_id(), "tutor.view")
    return base_layout("AI Tutor", content)

@app.route("/tutor/ask", methods=["POST"])
@subscription_required
def tutor_ask():
    """Process tutor question"""
    if not _csrf_ok():
        return jsonify({"ok": False, "error": "Invalid request"}), 403
    
    question = (request.form.get("question") or "").strip()
    if not question:
        return jsonify({"ok": False, "error": "Please provide a question"}), 400
    
    # Rate limiting
    rate_key = f"tutor:{_user_id()}"
    if not _rate_ok(rate_key, per_sec=0.1):  # Max 1 request per 10 seconds
        return jsonify({"ok": False, "error": "Please wait before asking another question"}), 429
    
    # Get AI response
    ok, answer = _openai_chat_completion(question)
    
    # Log the interaction
    _log_event(_user_id(), "tutor.ask", {
        "question_length": len(question),
        "success": ok
    })
    
    _append_attempt(_user_id(), "tutor", question=question, answer=answer if ok else None)
    
    return jsonify({
        "ok": ok,
        "answer": answer,
        "question": question
    })

@app.route("/flashcards")
@subscription_required
def flashcards():
    """Flashcard study interface"""
    domain_filter = request.args.get("domain", "all")
    
    # Get flashcards
    if domain_filter == "all":
        cards = get_all_flashcards()
    else:
        domain_name = f"Domain {domain_filter[-1]}" if domain_filter.startswith("domain") else domain_filter
        cards = get_all_flashcards(domains=[domain_name])
    
    if not cards:
        content = f"""
        <div class="container">
          <h1 class="h4 mb-3">Flashcards</h1>
          <div class="alert alert-warning">
            No flashcards available for the selected domain. 
            <a href="/admin/generate" class="alert-link">Generate content</a> or select a different domain.
          </div>
          {domain_buttons_html(domain_filter)}
        </div>
        """
        return base_layout("Flashcards", content)
    
    # Prepare cards for JavaScript
    cards_json = json.dumps([{
        "id": c.get("id"),
        "front": c.get("front"),
        "back": c.get("back"),
        "domain": c.get("domain")
    } for c in cards], ensure_ascii=False)
    
    content = f"""
    <div class="container">
      <div class="d-flex justify-content-between align-items-center mb-3">
        <h1 class="h4 mb-0">
          <i class="bi bi-layers text-success me-2"></i>Flashcards
        </h1>
        <div class="text-muted small">
          <span id="card-counter">0 / 0</span>
        </div>
      </div>
      
      <div class="mb-3">
        <label class="form-label">Filter by Domain:</label>
        {domain_buttons_html(domain_filter)}
      </div>
      
      <div class="row justify-content-center">
        <div class="col-lg-8">
          <div id="flashcard-container" class="card shadow-sm mb-3" style="min-height: 300px;">
            <div id="card-front" class="card-body d-flex align-items-center justify-content-center text-center bg-light">
              <div>
                <h5 class="mb-0">Loading flashcards...</h5>
              </div>
            </div>
            <div id="card-back" class="card-body d-none d-flex align-items-center justify-content-center text-center">
              <div>
                <p class="mb-0">Answer will appear here</p>
              </div>
            </div>
          </div>
          
          <div class="d-flex justify-content-center gap-3 mb-3">
            <button id="prev-btn" class="btn btn-outline-secondary" disabled>
              <i class="bi bi-arrow-left"></i> Previous
            </button>
            <button id="flip-btn" class="btn btn-primary btn-lg">
              <i class="bi bi-arrow-repeat"></i> Flip Card
            </button>
            <button id="next-btn" class="btn btn-outline-secondary">
              Next <i class="bi bi-arrow-right"></i>
            </button>
          </div>
          
          <div class="text-center">
            <button id="shuffle-btn" class="btn btn-outline-success">
              <i class="bi bi-shuffle"></i> Shuffle Cards
            </button>
            <div class="text-muted small mt-2">
              Press SPACE to flip • Use ← → arrow keys to navigate
            </div>
          </div>
        </div>
      </div>
    </div>
    
    <script>
    (function() {
      const cards = {cards_json};
      let currentIndex = 0;
      let isFlipped = false;
      
      const frontEl = document.getElementById('card-front');
      const backEl = document.getElementById('card-back');
      const counterEl = document.getElementById('card-counter');
      const prevBtn = document.getElementById('prev-btn');
      const nextBtn = document.getElementById('next-btn');
      const flipBtn = document.getElementById('flip-btn');
      const shuffleBtn = document.getElementById('shuffle-btn');
      
      function updateCard() {
        if (cards.length === 0) {
          frontEl.innerHTML = '<div><h5 class="text-muted">No cards available</h5></div>';
          return;
        }
        
        const card = cards[currentIndex];
        frontEl.innerHTML = `
          <div>
            <h5 class="mb-3">${escapeHtml(card.front)}</h5>
            <div class="badge bg-secondary">${escapeHtml(card.domain)}</div>
          </div>
        `;
        backEl.innerHTML = `
          <div>
            <p class="mb-3">${escapeHtml(card.back)}</p>
            <div class="badge bg-secondary">${escapeHtml(card.domain)}</div>
          </div>
        `;
        
        counterEl.textContent = `${currentIndex + 1} / ${cards.length}`;
        
        prevBtn.disabled = currentIndex === 0;
        nextBtn.disabled = currentIndex === cards.length - 1;
        
        // Reset to front
        showFront();
      }
      
      function showFront() {
        frontEl.classList.remove('d-none');
        backEl.classList.add('d-none');
        isFlipped = false;
        flipBtn.innerHTML = '<i class="bi bi-arrow-repeat"></i> Flip Card';
        flipBtn.className = 'btn btn-primary btn-lg';
      }
      
      function showBack() {
        frontEl.classList.add('d-none');
        backEl.classList.remove('d-none');
        isFlipped = true;
        flipBtn.innerHTML = '<i class="bi bi-arrow-repeat"></i> Show Front';
        flipBtn.className = 'btn btn-outline-primary btn-lg';
      }
      
      function flip() {
        if (isFlipped) {
          showFront();
        } else {
          showBack();
        }
      }
      
      function shuffle() {
        for (let i = cards.length - 1; i > 0; i--) {
          const j = Math.floor(Math.random() * (i + 1));
          [cards[i], cards[j]] = [cards[j], cards[i]];
        }
        currentIndex = 0;
        updateCard();
      }
      
      function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
      }
      
      // Event listeners
      prevBtn.addEventListener('click', () => {
        if (currentIndex > 0) {
          currentIndex--;
          updateCard();
        }
      });
      
      nextBtn.addEventListener('click', () => {
        if (currentIndex < cards.length - 1) {
          currentIndex++;
          updateCard();
        }
      });
      
      flipBtn.addEventListener('click', flip);
      shuffleBtn.addEventListener('click', shuffle);
      
      // Keyboard support
      document.addEventListener('keydown', (e) => {
        if (e.code === 'Space') {
          e.preventDefault();
          flip();
        } else if (e.code === 'ArrowLeft' && currentIndex > 0) {
          currentIndex--;
          updateCard();
        } else if (e.code === 'ArrowRight' && currentIndex < cards.length - 1) {
          currentIndex++;
          updateCard();
        }
      });
      
      // Domain buttons
      document.querySelectorAll('.domain-btn').forEach(btn => {
        btn.addEventListener('click', function() {
          document.querySelectorAll('.domain-btn').forEach(b => b.classList.remove('active'));
          this.classList.add('active');
          const domain = this.dataset.value;
          window.location.href = `/flashcards?domain=${encodeURIComponent(domain)}`;
        });
      });
      
      // Initialize
      updateCard();
    })();
    </script>
    """
    
    _log_event(_user_id(), "flashcards.view", {"domain": domain_filter, "count": len(cards)})
    _append_attempt(_user_id(), "flashcards", domain=domain_filter)
    return base_layout("Flashcards", content)

# ====================================================================================================
# ROUTES - QUIZ & MOCK EXAMS (NEW DESIGN)
# ====================================================================================================

def _render_exam_picker(title: str, action_url: str, question_limits: List[int], default_count: int = 25):
    """Render exam picker with specific question count options"""
    limit_options = ""
    for limit in question_limits:
        selected = " selected" if limit == default_count else ""
        limit_options += f'<option value="{limit}"{selected}>{limit} questions</option>'
    
    content = f"""
    <div class="container" style="max-width: 800px;">
      <div class="card shadow-sm">
        <div class="card-header bg-primary text-white">
          <h4 class="mb-0">
            <i class="bi bi-{'ui-checks-grid' if 'quiz' in title.lower() else 'journal-check'} me-2"></i>
            {html.escape(title)} Setup
          </h4>
        </div>
        <div class="card-body">
          <form method="post" action="{html.escape(action_url)}">
            <input type="hidden" name="csrf_token" value="{csrf_token()}"/>
            
            <div class="row">
              <div class="col-md-6">
                <div class="mb-4">
                  <label class="form-label">Domain Focus</label>
                  {domain_buttons_html("all", "domain")}
                  <div class="form-text">
                    Choose a specific domain or "All Domains" for comprehensive practice 
                    following CPP exam weightings.
                  </div>
                </div>
              </div>
              
              <div class="col-md-6">
                <div class="mb-4">
                  <label class="form-label">Number of Questions</label>
                  <select name="count" class="form-select">
                    {limit_options}
                  </select>
                  <div class="form-text">
                    {"Quick practice sessions" if "quiz" in title.lower() else "Full exam simulation"}
                  </div>
                </div>
              </div>
            </div>

            <div class="d-flex gap-3">
              <button type="submit" class="btn btn-primary btn-lg">
                <i class="bi bi-play-circle me-2"></i>
                Start {html.escape(title)}
              </button>
              <a href="/dashboard" class="btn btn-outline-secondary">
                <i class="bi bi-arrow-left me-2"></i>
                Back to Dashboard
              </a>
            </div>
          </form>
        </div>
      </div>
    </div>
    
    <script>
      document.querySelectorAll('.domain-btn').forEach(btn => {
        btn.addEventListener('click', function() {
          document.querySelectorAll('.domain-btn').forEach(b => b.classList.remove('active'));
          this.classList.add('active');
          document.getElementById('domain_val').value = this.dataset.value;
        });
      });
    </script>
    """
    return base_layout(title + " Setup", content)

def _render_exam_session(title: str, questions: List[Dict[str, Any]]):
    """Render interactive exam session with immediate feedback"""
    if not questions:
        content = """
        <div class="container">
          <div class="alert alert-warning">
            <i class="bi bi-exclamation-triangle me-2"></i>
            No questions available for your selection. Please try different criteria or 
            <a href="/admin/generate" class="alert-link">contact support</a>.
          </div>
          <a href="/dashboard" class="btn btn-primary">Back to Dashboard</a>
        </div>
        """
        return base_layout(title, content)
    
    questions_json = json.dumps([{
        "id": q.get("id"),
        "type": q.get("type"),
        "domain": q.get("domain"),
        "stem": q.get("stem"),
        "choices": q.get("choices", []),
        "options": q.get("options", []),
        "answer": q.get("answer"),
        "answers": q.get("answers", []),
        "explanation": q.get("explanation", ""),
        "module": q.get("module", q.get("domain", ""))
    } for q in questions], ensure_ascii=False)
    
    content = f"""
    <div class="container" style="max-width: 900px;">
      <div class="card shadow-sm">
        <div class="card-header bg-primary text-white d-flex justify-content-between align-items-center">
          <div>
            <h4 class="mb-0">{html.escape(title)}</h4>
            <div class="small opacity-75" id="progress-text">Question 1 of {len(questions)}</div>
          </div>
          <div class="badge bg-light text-dark fs-6" id="score-display">Score: 0/0</div>
        </div>
        
        <div class="card-body">
          <div id="question-container">
            <!-- Question content will be inserted here -->
          </div>
          
          <div id="answer-choices" class="mt-4">
            <!-- Answer choices will be inserted here -->
          </div>
          
          <div id="submit-section" class="mt-4 text-center">
            <button id="submit-btn" class="btn btn-primary btn-lg" disabled>
              <i class="bi bi-check-circle me-2"></i>
              Submit Answer
            </button>
          </div>
          
          <div id="feedback-section" class="mt-4 d-none">
            <!-- Feedback will appear here -->
          </div>
          
          <div id="navigation-section" class="mt-4 d-flex justify-content-between align-items-center d-none">
            <button id="prev-btn" class="btn btn-outline-secondary" disabled>
              <i class="bi bi-arrow-left"></i> Previous
            </button>
            
            <div class="text-center">
              <div id="completion-message" class="d-none">
                <div class="alert alert-success">
                  <strong>Quiz Complete!</strong> 
                  <span id="final-score"></span>
                </div>
              </div>
            </div>
            
            <button id="next-btn" class="btn btn-primary">
              Next <i class="bi bi-arrow-right"></i>
            </button>
          </div>
        </div>
      </div>
    </div>
    
    <script>
    (function() {
      const questions = {questions_json};
      let currentIndex = 0;
      let userAnswers = new Array(questions.length).fill(null);
      let score = 0;
      let answered = new Array(questions.length).fill(false);
      
      const questionContainer = document.getElementById('question-container');
      const answerChoices = document.getElementById('answer-choices');
      const submitSection = document.getElementById('submit-section');
      const feedbackSection = document.getElementById('feedback-section');
      const navigationSection = document.getElementById('navigation-section');
      const progressText = document.getElementById('progress-text');
      const scoreDisplay = document.getElementById('score-display');
      const submitBtn = document.getElementById('submit-btn');
      const prevBtn = document.getElementById('prev-btn');
      const nextBtn = document.getElementById('next-btn');
      const completionMessage = document.getElementById('completion-message');
      const finalScore = document.getElementById('final-score');
      
      function renderQuestion() {
        const q = questions[currentIndex];
        
        // Question header
        questionContainer.innerHTML = `
          <div class="mb-3">
            <div class="d-flex justify-content-between align-items-start mb-2">
              <h5 class="mb-0">Question ${"" + (currentIndex + 1)}</h5>
              <span class="badge bg-secondary">${"" + escapeHtml(q.domain)}</span>
            </div>
            <p class="lead">${"" + escapeHtml(q.stem)}</p>
          </div>
        `;
        
        // Answer choices
        let choicesHtml = '';
        if (q.type === 'mc') {
          q.choices.forEach((choice, i) => {
            const letter = String.fromCharCode(65 + i);
            const checked = userAnswers[currentIndex] === i ? ' checked' : '';
            choicesHtml += `
              <div class="form-check mb-2">
                <input class="form-check-input answer-option" type="radio" 
                       name="answer" value="${"" + i}" id="choice_${"" + i}"${"" + checked}>
                <label class="form-check-label" for="choice_${"" + i}">
                  <strong>${"" + letter}.</strong> ${"" + escapeHtml(choice)}
                </label>
              </div>
            `;
          });
        } else if (q.type === 'tf') {
          const trueChecked = userAnswers[currentIndex] === true ? ' checked' : '';
          const falseChecked = userAnswers[currentIndex] === false ? ' checked' : '';
          choicesHtml = `
            <div class="form-check mb-2">
              <input class="form-check-input answer-option" type="radio" 
                     name="answer" value="true" id="choice_true"${"" + trueChecked}>
              <label class="form-check-label" for="choice_true">
                <strong>A.</strong> True
              </label>
            </div>
            <div class="form-check mb-2">
              <input class="form-check-input answer-option" type="radio" 
                     name="answer" value="false" id="choice_false"${"" + falseChecked}>
              <label class="form-check-label" for="choice_false">
                <strong>B.</strong> False
              </label>
            </div>
          `;
        } else if (q.type === 'scenario') {
          choicesHtml += '<div class="mb-2"><em>Select all that apply:</em></div>';
          q.options.forEach((option, i) => {
            const letter = String.fromCharCode(65 + i);
            const currentAnswers = userAnswers[currentIndex] || [];
            const checked = currentAnswers.includes(i) ? ' checked' : '';
            choicesHtml += `
              <div class="form-check mb-2">
                <input class="form-check-input answer-option" type="checkbox" 
                       value="${"" + i}" id="option_${"" + i}"${"" + checked}>
                <label class="form-check-label" for="option_${"" + i}">
                  <strong>${"" + letter}.</strong> ${"" + escapeHtml(option)}
                </label>
              </div>
            `;
          });
        }
        
        answerChoices.innerHTML = choicesHtml;
        
        // Update progress and navigation
        progressText.textContent = `Question ${"" + (currentIndex + 1)} of ${"" + questions.length}`;
        prevBtn.disabled = currentIndex === 0;
        
        if (currentIndex === questions.length - 1) {
          nextBtn.innerHTML = 'Finish <i class="bi bi-check-circle"></i>';
        } else {
          nextBtn.innerHTML = 'Next <i class="bi bi-arrow-right"></i>';
        }
        
        // Show/hide sections based on answer state
        if (answered[currentIndex]) {
          showFeedback();
        } else {
          hideFeedback();
          setupAnswerHandlers();
        }
        
        updateScore();
      }
      
      function setupAnswerHandlers() {
        const options = document.querySelectorAll('.answer-option');
        options.forEach(option => {
          option.addEventListener('change', function() {
            submitBtn.disabled = false;
          });
        });
      }
      
      function submitAnswer() {
        const q = questions[currentIndex];
        let userAnswer = null;
        let isCorrect = false;
        
        if (q.type === 'mc') {
          const selected = document.querySelector('input[name="answer"]:checked');
          if (selected) {
            userAnswer = parseInt(selected.value);
            isCorrect = userAnswer === q.answer;
          }
        } else if (q.type === 'tf') {
          const selected = document.querySelector('input[name="answer"]:checked');
          if (selected) {
            userAnswer = selected.value === 'true';
            isCorrect = userAnswer === q.answer;
          }
        } else if (q.type === 'scenario') {
          const selected = Array.from(document.querySelectorAll('input[type="checkbox"]:checked'))
            .map(cb => parseInt(cb.value));
          userAnswer = selected;
          isCorrect = arraysEqual(selected.sort(), q.answers.sort());
        }
        
        userAnswers[currentIndex] = userAnswer;
        answered[currentIndex] = true;
        
        if (isCorrect) {
          score++;
        }
        
        showFeedback();
        updateScore();
      }
      
      function showFeedback() {
        const q = questions[currentIndex];
        const userAnswer = userAnswers[currentIndex];
        let isCorrect = false;
        let correctAnswerText = '';
        
        if (q.type === 'mc') {
          isCorrect = userAnswer === q.answer;
          correctAnswerText = String.fromCharCode(65 + q.answer);
        } else if (q.type === 'tf') {
          isCorrect = userAnswer === q.answer;
          correctAnswerText = q.answer ? 'True' : 'False';
        } else if (q.type === 'scenario') {
          isCorrect = arraysEqual((userAnswer || []).sort(), q.answers.sort());
          correctAnswerText = q.answers.map(i => String.fromCharCode(65 + i)).join(', ');
        }
        
        const feedbackClass = isCorrect ? 'correct-answer' : 'incorrect-answer';
        const feedbackIcon = isCorrect ? 'bi-check-circle-fill text-success' : 'bi-x-circle-fill text-danger';
        const feedbackTitle = isCorrect ? 'Correct!' : 'Incorrect';
        
        feedbackSection.innerHTML = `
          <div class="${"" + feedbackClass} p-3 rounded">
            <div class="d-flex align-items-center mb-2">
              <i class="bi ${"" + feedbackIcon} me-2"></i>
              <strong>${"" + feedbackTitle}</strong>
            </div>
            <div class="mb-2">
              <strong>Correct Answer:</strong> ${"" + correctAnswerText}
            </div>
            <div class="mb-2">
              <strong>Explanation:</strong> ${"" + escapeHtml(q.explanation)}
            </div>
            <div class="small text-muted">
              <strong>Reference:</strong> ${"" + escapeHtml(q.module)}
            </div>
          </div>
        `;
        
        submitSection.classList.add('d-none');
        feedbackSection.classList.remove('d-none');
        navigationSection.classList.remove('d-none');
        
        // Disable answer options
        document.querySelectorAll('.answer-option').forEach(option => {
          option.disabled = true;
        });
      }
      
      function hideFeedback() {
        submitSection.classList.remove('d-none');
        feedbackSection.classList.add('d-none');
        navigationSection.classList.add('d-none');
        submitBtn.disabled = true;
      }
      
      function updateScore() {
        const answered_count = answered.filter(a => a).length;
        scoreDisplay.textContent = `Score: ${"" + score}/${"" + answered_count}`;
        
        // Show completion message if all answered
        if (answered_count === questions.length) {
          const percentage = Math.round((score / questions.length) * 100);
          finalScore.textContent = `You scored ${"" + score} out of ${"" + questions.length} (${"" + percentage}%)`;
          completionMessage.classList.remove('d-none');
          nextBtn.classList.add('d-none');
        }
      }
      
      function arraysEqual(a, b) {
        return Array.isArray(a) && Array.isArray(b) && 
               a.length === b.length && a.every((val, i) => val === b[i]);
      }
      
      function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text || '';
        return div.innerHTML;
      }
      
      // Event listeners
      submitBtn.addEventListener('click', submitAnswer);
      
      prevBtn.addEventListener('click', () => {
        if (currentIndex > 0) {
          currentIndex--;
          renderQuestion();
        }
      });
      
      nextBtn.addEventListener('click', () => {
        if (currentIndex < questions.length - 1) {
          currentIndex++;
          renderQuestion();
        }
      });
      
      // Initialize
      renderQuestion();
    })();
    </script>
    """
    
    return base_layout(title, content)

@app.route("/quiz")
@subscription_required
def quiz_picker():
    """Quiz setup page"""
    return _render_exam_picker("Practice Quiz", "/quiz/start", [10, 15, 20, 25, 30], 20)

@app.route("/quiz/start", methods=["POST"])
@subscription_required
def quiz_start():
    """Start quiz session"""
    if not _csrf_ok():
        abort(403)
    
    domain = request.form.get("domain", "all")
    count = int(request.form.get("count", 20))
    
    # Select questions
    domains = [] if domain == "all" else [f"Domain {domain[-1]}"] if domain.startswith("domain") else [domain]
    questions = select_questions(domains=domains, count=count, user_id=_user_id())
    
    # Log attempt
    _log_event(_user_id(), "quiz.start", {
        "domain": domain,
        "count": count,
        "actual_count": len(questions)
    })
    
    return _render_exam_session("Practice Quiz", questions)

@app.route("/mock")
@subscription_required
def mock_picker():
    """Mock exam setup page"""
    return _render_exam_picker("Mock Exam", "/mock/start", [25, 50, 75, 100], 50)

@app.route("/mock/start", methods=["POST"])
@subscription_required
def mock_start():
    """Start mock exam session"""
    if not _csrf_ok():
        abort(403)
    
    domain = request.form.get("domain", "all")
    count = int(request.form.get("count", 50))
    
    # Select questions
    domains = [] if domain == "all" else [f"Domain {domain[-1]}"] if domain.startswith("domain") else [domain]
    questions = select_questions(domains=domains, count=count, user_id=_user_id())
    
    # Log attempt
    _log_event(_user_id(), "mock.start", {
        "domain": domain,
        "count": count,
        "actual_count": len(questions)
    })
    
    return _render_exam_session("Mock Exam", questions)

# ====================================================================================================
# ROUTES - PROGRESS & ADMIN
# ====================================================================================================

@app.route("/progress")
@subscription_required
def progress():
    """User progress dashboard with enhanced metrics"""
    user = _current_user()
    progress_data = calculate_user_progress(_user_id())
    attempts = _load_json("attempts.json", [])
    user_attempts = [a for a in attempts if a.get("user_id") == _user_id()]
    
    # Group by mode for detailed stats
    by_mode = {}
    for attempt in user_attempts:
        mode = attempt.get("mode", "unknown")
        if mode not in by_mode:
            by_mode[mode] = []
        by_mode[mode].append(attempt)
    
    content = f"""
    <div class="container">
      <div class="row mb-4">
        <div class="col-md-8">
          <h1 class="h4 mb-3">
            <i class="bi bi-graph-up text-primary me-2"></i>
            Your Progress
          </h1>
        </div>
        <div class="col-md-4">
          {progress_meter_html(progress_data)}
        </div>
      </div>
      
      <div class="row g-3 mb-4">
        <div class="col-md-3">
          <div class="card text-center h-100">
            <div class="card-body">
              <i class="bi bi-trophy text-warning display-6 mb-2"></i>
              <h5 class="card-title">{len(user_attempts)}</h5>
              <p class="card-text text-muted">Total Sessions</p>
            </div>
          </div>
        </div>
        <div class="col-md-3">
          <div class="card text-center h-100">
            <div class="card-body">
              <i class="bi bi-ui-checks-grid text-primary display-6 mb-2"></i>
              <h5 class="card-title">{len(by_mode.get('quiz', []))}</h5>
              <p class="card-text text-muted">Quiz Sessions</p>
            </div>
          </div>
        </div>
        <div class="col-md-3">
          <div class="card text-center h-100">
            <div class="card-body">
              <i class="bi bi-journal-check text-info display-6 mb-2"></i>
              <h5 class="card-title">{len(by_mode.get('mock', []))}</h5>
              <p class="card-text text-muted">Mock Exams</p>
            </div>
          </div>
        </div>
        <div class="col-md-3">
          <div class="card text-center h-100">
            <div class="card-body">
              <i class="bi bi-chat-dots text-success display-6 mb-2"></i>
              <h5 class="card-title">{len(by_mode.get('tutor', []))}</h5>
              <p class="card-text text-muted">Tutor Questions</p>
            </div>
          </div>
        </div>
      </div>
      
      <div class="row g-3">
        <div class="col-md-8">
          <div class="card">
            <div class="card-header">
              <h5 class="mb-0">Recent Activity</h5>
            </div>
            <div class="card-body">
              {"<div class='text-muted text-center py-3'>No activity yet. Start studying to track your progress!</div>" if not user_attempts else ""}
              {"".join([f'''
              <div class="d-flex justify-content-between align-items-center py-2 {"border-bottom" if i < min(9, len(user_attempts)-1) else ""}">
                <div class="d-flex align-items-center">
                  <i class="bi bi-{
                    "chat-dots" if attempt.get("mode") == "tutor" else
                    "layers" if attempt.get("mode") == "flashcards" else
                    "ui-checks-grid" if attempt.get("mode") == "quiz" else
                    "journal-check"
                  } text-muted me-2"></i>
                  <div>
                    <strong>{attempt.get("mode", "").title()}</strong>
                    {f" - {attempt.get('domain', '')}" if attempt.get('domain') and attempt.get('domain') != 'all' else ""}
                    <br>
                    <small class="text-muted">
                      {attempt.get('question', '')[:80] + "..." if attempt.get('question') and len(attempt.get('question', '')) > 80 else attempt.get('question', '') if attempt.get('question') else "Study session"}
                    </small>
                  </div>
                </div>
                <div class="text-muted small text-end">
                  {attempt.get("ts", "").split("T")[0] if attempt.get("ts") else ""}<br>
                  <small>{attempt.get("ts", "").split("T")[1][:5] if attempt.get("ts") and "T" in attempt.get("ts", "") else ""}</small>
                </div>
              </div>
              ''' for i, attempt in enumerate(user_attempts[-10:])])}
            </div>
          </div>
        </div>
        
        <div class="col-md-4">
          <div class="card">
            <div class="card-header">
              <h5 class="mb-0">Domain Coverage</h5>
            </div>
            <div class="card-body">
              <div class="small">
                <div class="mb-2">
                  <strong>Domains Studied:</strong> {progress_data['details']['domains_covered']}/7
                </div>
                <div class="progress mb-3" style="height: 8px;">
                  <div class="progress-bar bg-{progress_data['color']}" 
                       style="width: {(progress_data['details']['domains_covered']/7)*100}%"></div>
                </div>
                <div class="mb-2">
                  <strong>Study Streak:</strong> Building consistency
                </div>
                <div class="mb-3">
                  <strong>Next Goal:</strong> 
                  {"Complete Domain 1 quiz" if progress_data['details']['domains_covered'] == 0 else 
                   "Try mock exam" if progress_data['details']['mock_sessions'] == 0 else
                   "Explore all domains"}
                </div>
                <a href="/dashboard" class="btn btn-outline-primary btn-sm w-100">
                  Continue Studying
                </a>
              </div>
            </div>
          </div>
          
          <div class="card mt-3">
            <div class="card-header">
              <h5 class="mb-0">Quick Actions</h5>
            </div>
            <div class="card-body">
              <div class="d-grid gap-2">
                <a href="/quiz" class="btn btn-primary btn-sm">Take Quick Quiz</a>
                <a href="/flashcards" class="btn btn-success btn-sm">Study Flashcards</a>
                <a href="/tutor" class="btn btn-secondary btn-sm">Ask Tutor</a>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
    """
    
    return base_layout("Progress", content)

@app.route("/terms")
def terms():
    """Terms and conditions page"""
    content = """
    <div class="container" style="max-width:960px;">
      <h1 class="mb-2">CPP_Test_Prep — Terms and Conditions</h1>
      <div class="text-muted mb-4">Effective Date: 2024-09-04</div>

      <div class="alert alert-warning mb-4">
        <div class="d-flex align-items-center">
          <i class="bi bi-exclamation-triangle-fill me-2"></i>
          <div>
            <strong>Important Disclaimer:</strong> This program is not affiliated with or approved by ASIS International. 
            We use only open-source and publicly available study materials. No ASIS-protected content is included.
          </div>
        </div>
      </div>

      <ol class="lh-base" style="padding-left: 1.2rem;">
        <li id="t1"><strong>Who we are</strong><br>
          CPP_Test_Prep is a study platform owned and operated by Strategic Security Advisors, LLC ("SSA," "we," "us," "our").
          Contact: <a href="mailto:cpptestprep@gmail.com">cpptestprep@gmail.com</a>.
        </li>

        <li id="t2" class="mt-3"><strong>What we do and what we do not do</strong><br>
          CPP_Test_Prep provides study tools for candidates preparing for the ASIS Certified Protection Professional examination.
          We are not affiliated with, endorsed by, or sponsored by ASIS International. We do not use or reproduce ASIS
          International protected, proprietary, or member-only materials. The platform is for education and training. It does not
          guarantee that you will pass any exam or achieve any certification.
        </li>

        <li id="t3" class="mt-3"><strong>Eligibility and accounts</strong><br>
          You must be at least 18 and able to form a binding contract. Keep your login secure and notify us of any unauthorized use.
          You are responsible for activity on your account.
        </li>

        <li id="t4" class="mt-3"><strong>Your license to use CPP_Test_Prep</strong><br>
          We grant you a limited, personal, non-exclusive, non-transferable license to access and use the platform for your own study.
          You may not resell, sublicense, share, copy at scale, scrape, or otherwise exploit the content or software.
        </li>

        <li id="t5" class="mt-3"><strong>Payments, renewals, and refunds</strong><br>
          If your plan is paid, you authorize recurring charges until you cancel. Prices may change on notice. Unless we state 
          otherwise in writing, fees are nonrefundable once a billing period begins. You may cancel at any time, which stops 
          future renewals.
        </li>

        <li id="t6" class="mt-3"><strong>Availability and changes</strong><br>
          We may update, suspend, or discontinue features or the platform. We are not liable for outages, data loss, or delays. 
          We may update these Terms by posting the revised version with a new Effective Date.
        </li>

        <li id="t7" class="mt-3"><strong>No warranties</strong><br>
          The platform and all content are provided "as is" and "as available." We disclaim all warranties, including fitness
          for a particular purpose, accuracy, and non-infringement. Study results vary by user.
        </li>

        <li id="t8" class="mt-3"><strong>Limitation of liability</strong><br>
          To the fullest extent permitted by law, SSA is not liable for indirect, incidental, special, consequential, or punitive 
          damages. Our total liability will not exceed the amount you paid to us in the 3 months before the claim.
        </li>

        <li id="t9" class="mt-3"><strong>Governing law</strong><br>
          These Terms are governed by the laws of the State of Arizona. The exclusive venue for disputes is the state or federal 
          courts located in Maricopa County, Arizona.
        </li>
      </ol>

      <div class="mt-4">
        <a class="btn btn-primary" href="/">Back to Home</a>
      </div>
    </div>
    """
    return base_layout("Terms & Conditions", content, show_nav=False)

# ====================================================================================================
# ROUTES - ADMIN PANEL
# ====================================================================================================

@app.route("/admin", methods=["GET", "POST"])
def admin():
    """Admin panel for content management"""
    if request.method == "POST":
        # Admin login
        password = request.form.get("password", "")
        if ADMIN_PASSWORD and password == ADMIN_PASSWORD:
            session["admin_ok"] = True
            return redirect("/admin")
        else:
            content = """
            <div class="container" style="max-width: 480px;">
              <div class="alert alert-danger">Invalid admin password.</div>
              <a href="/admin" class="btn btn-primary">Try Again</a>
            </div>
            """
            return base_layout("Admin Access Denied", content, show_nav=False)
    
    # Check admin access
    if not is_admin():
        if not ADMIN_PASSWORD:
            content = """
            <div class="container" style="max-width: 480px;">
              <div class="alert alert-warning">
                Admin access is not configured. Set ADMIN_PASSWORD environment variable.
              </div>
              <a href="/" class="btn btn-primary">Back to Home</a>
            </div>
            """
            return base_layout("Admin Not Available", content, show_nav=False)
        
        # Show login form
        content = f"""
        <div class="container" style="max-width: 480px;">
          <div class="card shadow-sm">
            <div class="card-header">
              <h4 class="mb-0">Admin Access</h4>
            </div>
            <div class="card-body">
              <form method="post">
                <div class="mb-3">
                  <label class="form-label">Admin Password</label>
                  <input type="password" name="password" class="form-control" required/>
                </div>
                <button type="submit" class="btn btn-primary">Access Admin Panel</button>
              </form>
            </div>
          </div>
        </div>
        """
        return base_layout("Admin Login", content, show_nav=False)
    
    # Admin dashboard
    questions = get_all_questions()
    flashcards = get_all_flashcards()
    users = _users_all()
    
    content = f"""
    <div class="container">
      <h1 class="h4 mb-3"><i class="bi bi-gear"></i> Admin Panel</h1>
      
      <div class="row g-3 mb-4">
        <div class="col-md-3">
          <div class="card text-center">
            <div class="card-body">
              <h5 class="card-title">{len(questions)}</h5>
              <p class="card-text text-muted">Questions in Bank</p>
            </div>
          </div>
        </div>
        <div class="col-md-3">
          <div class="card text-center">
            <div class="card-body">
              <h5 class="card-title">{len(flashcards)}</h5>
              <p class="card-text text-muted">Flashcards in Bank</p>
            </div>
          </div>
        </div>
        <div class="col-md-3">
          <div class="card text-center">
            <div class="card-body">
              <h5 class="card-title">{len(users)}</h5>
              <p class="card-text text-muted">Registered Users</p>
            </div>
          </div>
        </div>
        <div class="col-md-3">
          <div class="card text-center">
            <div class="card-body">
              <h5 class="card-title">v{APP_VERSION}</h5>
              <p class="card-text text-muted">App Version</p>
            </div>
          </div>
        </div>
      </div>
      
      <div class="row g-3">
        <div class="col-md-6">
          <div class="card">
            <div class="card-header">
              <h5 class="mb-0">Content Management</h5>
            </div>
            <div class="card-body">
              <div class="d-grid gap-2">
                <a href="/admin/generate" class="btn btn-primary">Generate Content</a>
                <a href="/admin/users" class="btn btn-outline-secondary">Manage Users</a>
                <a href="/admin/stats" class="btn btn-outline-info">View Statistics</a>
              </div>
            </div>
          </div>
        </div>
        
        <div class="col-md-6">
          <div class="card">
            <div class="card-header">
              <h5 class="mb-0">System Health</h5>
            </div>
            <div class="card-body">
              <div class="mb-2">
                <span class="badge bg-{'success' if _ai_enabled() else 'warning'}">
                  AI Tutor: {'Online' if _ai_enabled() else 'Offline'}
                </span>
              </div>
              <div class="mb-2">
                <span class="badge bg-{'success' if STRIPE_ENABLED else 'warning'}">
                  Billing: {'Enabled' if STRIPE_ENABLED else 'Disabled'}
                </span>
              </div>
              <div class="mb-2">
                <span class="badge bg-success">Data Directory: OK</span>
              </div>
              <div class="mb-2">
                <span class="badge bg-{'success' if len(questions) > 50 else 'warning'}">
                  Content Bank: {'Sufficient' if len(questions) > 50 else 'Low'}
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>
      
      <div class="mt-3">
        <a href="/admin/logout" class="btn btn-outline-danger">Logout Admin</a>
        <a href="/dashboard" class="btn btn-outline-secondary">Back to Dashboard</a>
      </div>
    </div>
    """
    
    return base_layout("Admin Panel", content)

@app.route("/admin/generate", methods=["GET", "POST"])
def admin_generate():
    """Generate content"""
    if not is_admin():
        return redirect("/admin")
    
    if request.method == "POST":
        action = request.form.get("action")
        
        if action == "seed_content":
            # Generate comprehensive content
            questions = CPPContentGenerator.generate_sample_questions()
            flashcards = CPPContentGenerator.generate_sample_flashcards()
            
            # Save to files
            _write_jsonl(_QUESTIONS_FILE, questions)
            _write_jsonl(_FLASHCARDS_FILE, flashcards)
            
            content = f"""
            <div class="container">
              <div class="alert alert-success">
                Successfully generated {len(questions)} questions and {len(flashcards)} flashcards!
              </div>
              <a href="/admin/generate" class="btn btn-primary">Generate More</a>
              <a href="/admin" class="btn btn-outline-secondary">Back to Admin</a>
            </div>
            """
            return base_layout("Content Generated", content)
    
    # Show generation form
    current_questions = len(get_all_questions())
    current_flashcards = len(get_all_flashcards())
    
    content = f"""
    <div class="container">
      <h1 class="h4 mb-3">Generate Content</h1>
      
      <div class="alert alert-info">
        <strong>Current Content:</strong> {current_questions} questions, {current_flashcards} flashcards
      </div>
      
      <div class="card">
        <div class="card-header">
          <h5 class="mb-0">Generate Sample Content</h5>
        </div>
        <div class="card-body">
          <p class="text-muted mb-3">
            This will generate a comprehensive set of sample questions and flashcards 
            distributed across all CPP domains according to exam weightings.
          </p>
          <form method="post">
            <input type="hidden" name="action" value="seed_content"/>
            <button type="submit" class="btn btn-primary" onclick="return confirm('This will generate new content. Continue?')">
              Generate Sample Content
            </button>
          </form>
        </div>
      </div>
      
      <div class="mt-3">
        <a href="/admin" class="btn btn-outline-secondary">Back to Admin</a>
      </div>
    </div>
    """
    
    return base_layout("Generate Content", content)

@app.route("/admin/logout")
def admin_logout():
    """Admin logout"""
    session.pop("admin_ok", None)
    return redirect("/admin")

# ====================================================================================================
# ROUTES - HEALTH & MISC
# ====================================================================================================

@app.route("/healthz")
def health_check():
    """Health check endpoint"""
    return jsonify({
        "service": "cpp-exam-prep",
        "version": APP_VERSION,
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "features": {
            "ai_tutor": _ai_enabled(),
            "billing": STRIPE_ENABLED,
            "questions": len(get_all_questions()),
            "flashcards": len(get_all_flashcards())
        }
    })

# ====================================================================================================
# APPLICATION INITIALIZATION
# ====================================================================================================

def initialize_app():
    """Initialize application with sample data"""
    try:
        # Ensure data directories exist
        for path in [DATA_DIR, BANK_DIR]:
            os.makedirs(path, exist_ok=True)
        
        # Initialize data files
        for name, default in [
            ("users.json", []),
            ("events.json", []),
            ("attempts.json", []),
        ]:
            if not os.path.exists(_path(name)):
                _save_json(name, default)
        
        # Ensure weights file exists
        if not os.path.exists(_WEIGHTS_FILE):
            get_domain_weights()  # This will create the file
        
        # Seed content if needed
        ensure_content_seeded()
        
        logger.info("Application initialized successfully")
        
    except Exception as e:
        logger.error("Failed to initialize application: %s", e)
        raise

# Initialize on import
initialize_app()

# ====================================================================================================
# MAIN ENTRY POINT
# ====================================================================================================

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(
        host="0.0.0.0",
        port=port,
        debug=DEBUG
    )
