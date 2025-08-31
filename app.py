# =========================
# SECTION 1/8: Imports, Config, Data IO, Security, Base Data
# =========================

# ----- Imports & Basic Config -----
from flask import (
    Flask, request, jsonify, session, redirect, url_for, Response, abort
)
# NOTE: routes that serve files (favicon, etc.) will be added later; the above import set
# intentionally mirrors your current codebase for compatibility.

from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from functools import wraps
from datetime import datetime, timedelta
from typing import Dict, Any

import os, json, random, requests, html, uuid, logging, time, hashlib, re, base64

import sqlite3
import stripe

# CSRF imports (robust: provide safe fallbacks)
try:
    from flask_wtf.csrf import CSRFProtect, validate_csrf, generate_csrf
    HAS_CSRF = True
except Exception:
    HAS_CSRF = False
    CSRFProtect = None
    validate_csrf = None
    def generate_csrf() -> str:
        return ""

# fcntl for safe file writes (best-effort)
try:
    import fcntl  # noqa: F401
    HAS_FCNTL = True
except ImportError:
    HAS_FCNTL = False

# ----- Logging -----
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("cpp-app")

# ----- Flask App -----
app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)
app.secret_key = os.environ.get("SECRET_KEY") or os.urandom(24)

if HAS_CSRF and CSRFProtect:
    csrf = CSRFProtect(app)
else:
    csrf = None

# ----- Environment / Providers -----
OPENAI_API_KEY    = os.environ.get("OPENAI_API_KEY", "").strip()
OPENAI_CHAT_MODEL = os.environ.get("OPENAI_CHAT_MODEL", "gpt-4o-mini").strip()
OPENAI_API_BASE   = os.environ.get("OPENAI_API_BASE", "https://api.openai.com/v1").rstrip("/")

stripe.api_key            = os.environ.get('STRIPE_SECRET_KEY', '').strip()
STRIPE_WEBHOOK_SECRET     = os.environ.get('STRIPE_WEBHOOK_SECRET', '').strip()
STRIPE_MONTHLY_PRICE_ID   = os.environ.get('STRIPE_MONTHLY_PRICE_ID', '').strip()
STRIPE_SIXMONTH_PRICE_ID  = os.environ.get('STRIPE_SIXMONTH_PRICE_ID', '').strip()
STRIPE_PUBLISHABLE_KEY    = os.environ.get('STRIPE_PUBLISHABLE_KEY', '').strip()
ADMIN_PASSWORD            = os.environ.get("ADMIN_PASSWORD", "").strip()

APP_VERSION = os.environ.get("APP_VERSION", "1.0.0")
IS_STAGING  = os.environ.get("RENDER_SERVICE_NAME", "").endswith("-staging")
DEBUG       = os.environ.get("FLASK_DEBUG", "0") == "1"

# ---- NEW: Legal/T&C versioning (used for hard gate later) ----
TERMS_VERSION = os.environ.get("TERMS_VERSION", "2025-09-01").strip()

# ---- NEW: Site polish resources (served in Section 8) ----
# 1x1 transparent PNG (valid for /favicon.ico to stop 404 noise)
FAVICON_PNG_B64 = (
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9Y1n8y8AAAAASUVORK5CYII="
)
ROBOTS_TXT = "User-agent: *\nDisallow:\n"

# ---- NEW: Footer text bits (Welcome/Disclaimer references in later sections) ----
DISCLAIMER_SHORT = (
    "Independent study tool; not affiliated with ASIS International. "
    "CPP® is a mark of ASIS International, Inc. No refunds after access is granted."
)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=(os.environ.get("SESSION_COOKIE_SECURE", "1") == "1"),
)

# ----- Data Storage (JSON + optional SQLite stub) -----
DATA_DIR = os.environ.get("DATA_DIR", "data")
os.makedirs(DATA_DIR, exist_ok=True)
DATABASE_PATH = os.path.join(DATA_DIR, "app.db")

def _load_json(name, default):
    """
    name: relative to DATA_DIR. e.g., 'users.json' or 'bank/cpp_questions_v1.json'
    """
    path = os.path.join(DATA_DIR, name)
    if not os.path.exists(path):
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.warning("Failed to load %s: %s", name, e)
        return default

def _save_json(name, data):
    """
    Atomic JSON save into DATA_DIR/name.
    """
    path = os.path.join(DATA_DIR, name)
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp_path = f"{path}.tmp.{os.getpid()}.{uuid.uuid4().hex}"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
    except Exception as e:
        # Fallback non-atomic
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception as e2:
            logger.error("Save failed for %s: %s (fallback error: %s)", name, e, e2)

# Legacy loads (kept for compatibility)
QUESTIONS  = _load_json("questions.json", [])
FLASHCARDS = _load_json("flashcards.json", [])
USERS      = _load_json("users.json", [])

# Optional SQLite init (not required)
def init_database():
    with sqlite3.connect(DATABASE_PATH) as conn:
        conn.row_factory = sqlite3.Row
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            subscription TEXT DEFAULT 'inactive',
            subscription_expires_at TEXT,
            discount_code TEXT,
            stripe_customer_id TEXT,
            created_at TEXT DEFAULT (datetime('now', 'utc')),
            updated_at TEXT DEFAULT (datetime('now', 'utc'))
        );
        """)
        conn.commit()
if os.environ.get('USE_DATABASE') == '1':
    init_database()

# ----- Security Headers & Simple Rate Limiting -----
_RATE_BUCKETS: Dict[Any, Any] = {}

@app.after_request
def add_security_headers(resp):
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    resp.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    csp = (
        "default-src 'self' https: data: blob:; "
        "img-src 'self' https: data:; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://js.stripe.com; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "font-src 'self' https: data:; "
        "connect-src 'self' https://api.openai.com https://js.stripe.com https://api.stripe.com; "
        "frame-src https://js.stripe.com; "
        "frame-ancestors 'none'"
    )
    resp.headers["Content-Security-Policy"] = csp
    return resp

def _client_token():
    el = (session.get("email") or "").strip().lower()
    ip = request.remote_addr or "unknown"
    return f"{el}|{ip}"

def _rate_limited(route: str, limit: int = 10, per_seconds: int = 60) -> bool:
    global _RATE_BUCKETS
    now = time.time()
    key = (route, _client_token())
    window = [t for t in _RATE_BUCKETS.get(key, []) if now - t < per_seconds]
    if len(window) >= limit:
        _RATE_BUCKETS[key] = window
        return True
    window.append(now)
    _RATE_BUCKETS[key] = window
    # occasional cleanup
    if len(_RATE_BUCKETS) > 1000:
        cutoff = now - (per_seconds * 2)
        _RATE_BUCKETS = {
            k: [t for t in v if t > cutoff]
            for k, v in _RATE_BUCKETS.items()
            if any(t > cutoff for t in v)
        }
    return False

# ----- JSON helpers -----
def safe_json_response(data, status_code=200):
    try:
        return jsonify(data), status_code
    except Exception as e:
        logger.error(f"JSON serialization error: {e}")
        return jsonify({"error": "Internal server error"}), 500

# ----- Time/ISO helpers -----
def _now_iso(seconds: bool = True) -> str:
    return datetime.utcnow().isoformat(timespec="seconds" if seconds else "milliseconds") + "Z"

# ----- Auth helpers -----
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            nxt = request.path if request.path.startswith("/") and not request.path.startswith("//") else "/"
            return redirect(url_for('login_page', next=nxt))
        return f(*args, **kwargs)
    return decorated_function

def is_admin():
    return session.get("admin_ok") is True

def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def _is_safe_next(n: str | None) -> bool:
    return bool(n) and n.startswith("/") and not n.startswith("//")

# ----- Users (file-backed) -----
def _load_users():
    return _load_json("users.json", [])

def _save_users(users):
    _save_json("users.json", users)

def _find_user(email: str):
    if not email:
        return None
    el = email.strip().lower()
    users = _load_users()
    for u in users:
        if (u.get("email","").strip().lower() == el):
            return u
    return None

def _find_user_by_id(user_id: str):
    users = _load_users()
    for u in users:
        if u.get("id") == user_id:
            return u
    return None

def _update_user(user_id: str, updates: Dict[str, Any]) -> bool:
    users = _load_users()
    for i, u in enumerate(users):
        if u.get("id") == user_id:
            users[i] = {**u, **(updates or {})}
            _save_users(users)
            return True
    return False

def validate_password(pw: str) -> tuple[bool, str]:
    if not pw or len(pw) < 8:
        return False, "Password must be at least 8 characters."
    return True, ""

# ----- NEW: T&C acceptance helpers (used by signup/login flows later) -----
def _terms_up_to_date(user: dict | None) -> bool:
    """
    Returns True if the given user dict has accepted the current TERMS_VERSION.
    """
    if not user:
        return False
    v = (user.get("terms_accept_version") or "").strip()
    return bool(v and v == TERMS_VERSION)

def _mark_terms_accepted(user_id: str) -> bool:
    """
    Set current TERMS_VERSION and timestamp on the user record.
    """
    try:
        return _update_user(user_id, {
            "terms_accept_version": TERMS_VERSION,
            "terms_accept_ts": _now_iso()
        })
    except Exception as _e:
        return False

# ----- Usage Management (plan limits) -----
def check_usage_limit(user, action_type):
    if not user:
        return False, "Please log in to continue"

    subscription = user.get('subscription', 'inactive')
    expires_at = user.get('subscription_expires_at')

    if subscription == 'sixmonth' and expires_at:
        try:
            expires_dt = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
            if expires_dt.replace(tzinfo=None) < datetime.utcnow():
                user['subscription'] = 'inactive'
                user.pop('subscription_expires_at', None)
                subscription = 'inactive'
        except Exception:
            pass

    limits = {
        'monthly':   {'quizzes': -1, 'questions': -1, 'tutor_msgs': -1, 'flashcards': -1},
        'sixmonth':  {'quizzes': -1, 'questions': -1, 'tutor_msgs': -1, 'flashcards': -1},
        'inactive':  {'quizzes': 0,  'questions': 0,  'tutor_msgs': 0,  'flashcards': 0},
    }

    today = datetime.utcnow()
    month_key = today.strftime('%Y-%m')

    usage = user.setdefault('usage', {})
    monthly_usage = usage.setdefault('monthly', {}).get(month_key, {})

    user_limits = limits.get(subscription, limits['inactive'])
    limit = user_limits.get(action_type, 0)
    used = monthly_usage.get(action_type, 0)

    if limit == -1:
        return True, ""
    if used >= limit:
        return False, "Your current plan has reached its limit. Please purchase a plan for unlimited access."
    return True, ""

def increment_usage(user_email, action_type, count=1):
    if not user_email:
        return
    users = _load_users()
    el = user_email.strip().lower()
    for i, u in enumerate(users):
        if (u.get("email","").strip().lower() == el):
            today = datetime.utcnow()
            month_key = today.strftime('%Y-%m')
            usage = u.setdefault('usage', {})
            monthly = usage.setdefault('monthly', {})
            month_usage = monthly.setdefault(month_key, {})
            month_usage[action_type] = month_usage.get(action_type, 0) + count
            usage['last_active'] = today.isoformat(timespec="seconds") + "Z"
            users[i] = u
            _save_json("users.json", users)
            return

# ----- Base Questions & Domains (starter content) -----
BASE_QUESTIONS = [
    {
        "question": "What is the primary purpose of a security risk assessment?",
        "options": {"A": "Identify all threats", "B": "Determine cost-effective mitigation", "C": "Eliminate all risks", "D": "Satisfy compliance"},
        "correct": "B",
        "explanation": "Risk assessments balance risk, cost, and operational impact to choose practical controls.",
        "domain": "security-principles", "difficulty": "medium"
    },
    {
        "question": "In CPTED, natural surveillance primarily accomplishes what?",
        "options": {"A": "Reduces guard costs", "B": "Increases observation likelihood", "C": "Eliminates cameras", "D": "Provides legal protection"},
        "correct": "B",
        "explanation": "Design that increases visibility makes misconduct more likely to be observed and deterred.",
        "domain": "physical-security", "difficulty": "medium"
    },
    {
        "question": "Which concept applies multiple layers so if one fails others still protect?",
        "options": {"A": "Security by Obscurity", "B": "Defense in Depth", "C": "Zero Trust", "D": "Least Privilege"},
        "correct": "B",
        "explanation": "Layered controls maintain protection despite single-point failures.",
        "domain": "security-principles", "difficulty": "medium"
    },
    {
        "question": "In incident response, what is usually the FIRST priority?",
        "options": {"A": "Notify law enforcement", "B": "Contain the incident", "C": "Eradicate malware", "D": "Lessons learned"},
        "correct": "B",
        "explanation": "Containment stops the bleeding before eradication and recovery.",
        "domain": "information-security", "difficulty": "medium"
    },
    {
        "question": "Background investigations primarily support which objective?",
        "options": {"A": "Regulatory compliance only", "B": "Marketing outcomes", "C": "Reduce insider risk", "D": "Disaster response"},
        "correct": "C",
        "explanation": "They help verify suitability and reduce personnel security risks.",
        "domain": "personnel-security", "difficulty": "medium"
    },
    {
        "question": "What is the primary goal of business continuity planning?",
        "options": {"A": "Prevent all disasters", "B": "Maintain critical operations during disruption", "C": "Reduce insurance costs", "D": "Only satisfy regulators"},
        "correct": "B",
        "explanation": "BCP ensures critical functions continue during and after a disruption.",
        "domain": "crisis-management", "difficulty": "medium"
    },
    {
        "question": "What establishes legal admissibility of evidence in investigations?",
        "options": {"A": "Chain of custody", "B": "Digital timestamps", "C": "Witness statements only", "D": "Management approval"},
        "correct": "A",
        "explanation": "Chain of custody proves integrity of evidence handling.",
        "domain": "investigations", "difficulty": "medium"
    },
    {
        "question": "Best approach to security budgeting?",
        "options": {"A": "Historical spend", "B": "Risk-based allocation", "C": "Industry averages", "D": "Spend remaining funds"},
        "correct": "B",
        "explanation": "Direct funds to the highest-impact, risk-reducing controls.",
        "domain": "business-principles", "difficulty": "medium"
    },
]

# --- FIX: define labels for domain buttons (prevents 500s) ---
DOMAINS = {
    "security-principles":  "Security Principles",
    "business-principles":  "Business Principles",
    "investigations":       "Investigations",
    "personnel-security":   "Personnel Security",
    "physical-security":    "Physical Security",
    "information-security": "Information Security",
    "crisis-management":    "Crisis & Continuity",
}

# Simple color tags for domain buttons
DOMAIN_STYLES = {
    "security-principles":  "primary",
    "business-principles":  "secondary",
    "investigations":       "info",
    "personnel-security":   "success",
    "physical-security":    "warning",
    "information-security": "dark",
    "crisis-management":    "danger",
}

def domain_buttons_html(selected_key: str = "random", field_name: str = "domain") -> str:
    """
    Returns a block of colored buttons (including 'Random') + a hidden input.
    Clicking a button sets the hidden input and toggles the active style.
    """
    def _btn(key, label, color):
        active = " active" if key == (selected_key or "random") else ""
        return (
            f'<button type="button" class="btn domain-btn btn-{color}{active}" '
            f' data-value="{html.escape(key)}">{html.escape(label)}</button>'
        )

    parts = []
    parts.append(_btn("random", "Random (all domains)", "outline-secondary"))

    for key, label in DOMAINS.items():
        color = DOMAIN_STYLES.get(key, "outline-primary")
        parts.append(_btn(key, label, color))

    hidden = (
        f'<input type="hidden" name="{html.escape(field_name)}" '
        f'id="{html.escape(field_name)}_val" value="{html.escape(selected_key or "random")}">'
    )
    return f'<div class="d-flex flex-wrap gap-2">{"".join(parts)}</div>{hidden}'

# ----- Suggested Tutor Questions (randomized helper for sidebar) -----
SUGGESTED_QUESTION_BANK = {
    "security-principles": [
        "Explain defense-in-depth with a simple example.",
        "What is risk appetite vs. risk tolerance?",
        "Qualitative vs quantitative risk assessment — when to use each?",
        "How does least privilege reduce attack surface?"
    ],
    "business-principles": [
        "How do you build a risk-based security budget?",
        "What KPIs matter most for a security program?",
        "CapEx vs OpEx tradeoffs in security investments?",
        "Make a short security business case outline."
    ],
    "investigations": [
        "Walk through chain-of-custody best practices.",
        "What is the difference between interview and interrogation?",
        "How to preserve a digital scene first?",
        "Administrative vs. criminal investigation — key differences?"
    ],
    "personnel-security": [
        "What background checks are most effective & why?",
        "Steps for handling insider threat indicators?",
        "Progressive discipline vs. immediate termination?",
        "How to design an employee reporting mechanism?"
    ],
    "physical-security": [
        "CPTED: give examples of natural surveillance.",
        "Pros/cons: mantraps vs turnstiles?",
        "Perimeter layers: deter, detect, delay — examples?",
        "How to choose a lock by risk level?"
    ],
    "information-security": [
        "First steps in incident containment for ransomware?",
        "What is zero trust in plain terms?",
        "Security awareness topics that really work?",
        "How to prioritize patching across assets?"
    ],
    "crisis-management": [
        "BCP vs DRP — what’s the difference?",
        "Simple RTO/RPO explanation with examples.",
        "ICS roles to know for private sector?",
        "How to run a table-top exercise effectively?"
    ],
}

def get_suggested_questions(domain_key: str | None, n: int = 4) -> list[str]:
    """
    Returns up to n randomized suggestions for the given domain.
    If domain_key is 'random' or None, sample across all domains.
    """
    try:
        n = max(1, min(int(n), 8))
    except Exception:
        n = 4
    if not domain_key or domain_key == "random":
        pool = []
        for items in SUGGESTED_QUESTION_BANK.values():
            pool.extend(items)
        random.shuffle(pool)
        return pool[:n]
    dk = str(domain_key).strip().lower()
    pool = SUGGESTED_QUESTION_BANK.get(dk, [])
    pool = pool[:]  # copy
    random.shuffle(pool)
    return pool[:n]

# ----- Question normalization/merge for legacy + base -----
def _normalize_question_legacy(q: dict):
    if not q or not q.get("question"):
        return None
    nq = {
        "question": q.get("question", "").strip(),
        "explanation": q.get("explanation", "").strip(),
        "domain": q.get("domain", "security-principles"),
        "difficulty": q.get("difficulty", "medium"),
    }
    opts = q.get("options")
    correct_letter = q.get("correct")
    if isinstance(opts, dict):
        letters = ["A", "B", "C", "D"]
        clean = {}
        for L in letters:
            if L in opts:
                clean[L] = str(opts[L])
        if len(clean) != 4:
            return None
        nq["options"] = clean
        if correct_letter and isinstance(correct_letter, str) and correct_letter.upper() in ("A","B","C","D"):
            nq["correct"] = correct_letter.upper()
        else:
            return None
    else:
        return None
    if nq.get("correct") not in ("A","B","C","D"):
        return None
    return nq

def _build_all_questions():
    merged = []
    seen = set()
    def add_many(src):
        for q in src:
            nq = _normalize_question_legacy(q)
            if not nq:
                continue
            key = (nq["question"], nq["domain"], nq["correct"])
            if key in seen:
                continue
            seen.add(key)
            merged.append(nq)
    add_many(QUESTIONS or [])
    add_many(BASE_QUESTIONS or [])
    return merged

ALL_QUESTIONS = _build_all_questions()

# ----- Misc utils -----
def _percent(num, den):
    if not den:
        return 0.0
    return round(100.0 * float(num) / float(den), 1)

def _user_id():
    return (session.get("user_id") or session.get("email") or "unknown")
# =========================
# SECTION 2/8: Layout, CSRF, Health, Auth (Login/Signup/Logout)
# =========================

# ---- Terms & Conditions (T&C) versioning ----
TERMS_VERSION = os.environ.get("TERMS_VERSION", "2025-08-30").strip()

def _user_terms_accepted(user: dict | None) -> bool:
    if not user:
        return False
    return str(user.get("terms_accept_version", "")).strip() == TERMS_VERSION

def _require_terms_gate(user_email: str) -> bool:
    """Return True if user MUST (re)accept T&C (missing or outdated)."""
    return not _user_terms_accepted(_find_user(user_email))

def _mark_terms_accepted(user_id: str):
    ts = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    _update_user(user_id, {"terms_accept_version": TERMS_VERSION, "terms_accept_ts": ts})


# ---- CSRF helpers (uniform, no false 403s) ----
def _csrf_ok() -> bool:
    if not HAS_CSRF:
        return True
    try:
        # validate_csrf was imported in Section 1 when available
        from flask_wtf.csrf import validate_csrf  # safe import even if already loaded
        validate_csrf(request.form.get("csrf_token") or "")
        return True
    except Exception:
        return False

@app.template_global()
def csrf_token():
    if HAS_CSRF:
        try:
            from flask_wtf.csrf import generate_csrf
            return generate_csrf()
        except Exception:
            return ""
    return ""

def _plan_badge_text(sub):
    return {"monthly": "Monthly", "sixmonth": "6-Month"}.get(sub, "Inactive")

def base_layout(title: str, body_html: str) -> str:
    user_name = session.get('name', '')
    user_email = session.get('email', '')
    is_logged_in = 'user_id' in session
    csrf_value = csrf_token()

    if is_logged_in:
        user = _find_user(user_email)
        subscription = user.get('subscription', 'inactive') if user else 'inactive'
        badge_text = _plan_badge_text(subscription)
        plan_badge = f'<span class="badge plan-{subscription}">{badge_text}</span>'
        user_menu = f"""
        <li class="nav-item dropdown">
          <a class="nav-link dropdown-toggle" href="#" id="userDropdown" role="button" data-bs-toggle="dropdown">
            {html.escape(user_name or user_email)} {plan_badge}
          </a>
          <ul class="dropdown-menu" aria-labelledby="userDropdown">
            <li><a class="dropdown-item" href="/usage">Usage Dashboard</a></li>
            <li><a class="dropdown-item" href="/billing">Billing</a></li>
            <li><a class="dropdown-item" href="/settings">Settings</a></li>
            <li><hr class="dropdown-divider"></li>
            <li>
              <form method="POST" action="/logout" class="d-inline">
                <input type="hidden" name="csrf_token" value="{csrf_value}"/>
                <button type="submit" class="dropdown-item">Logout</button>
              </form>
            </li>
          </ul>
        </li>
        """
    else:
        user_menu = """
        <li class="nav-item"><a class="nav-link" href="/login">Login</a></li>
        <li class="nav-item"><a class="nav-link btn btn-outline-primary ms-2" href="/signup">Create Account</a></li>
        """

    nav = f"""
    <nav class="navbar navbar-expand-lg navbar-light bg-gradient-primary sticky-top shadow-sm">
      <div class="container">
        <a class="navbar-brand fw-bold text-white" href="/"><i class="bi bi-shield-check text-warning"></i> CPP Test Prep</a>
        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
          <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="navbarNav">
          <ul class="navbar-nav me-auto">
            {'<li class="nav-item"><a class="nav-link text-white-75" href="/study"><i class="bi bi-robot me-1"></i>Tutor</a></li>' if is_logged_in else ''}
            {'<li class="nav-item"><a class="nav-link text-white-75" href="/flashcards"><i class="bi bi-card-list me-1"></i>Flashcards</a></li>' if is_logged_in else ''}
            {'<li class="nav-item"><a class="nav-link text-white-75" href="/quiz"><i class="bi bi-card-text me-1"></i>Quiz</a></li>' if is_logged_in else ''}
            {'<li class="nav-item"><a class="nav-link text-white-75" href="/mock-exam"><i class="bi bi-clipboard-check me-1"></i>Mock Exam</a></li>' if is_logged_in else ''}
            {'<li class="nav-item"><a class="nav-link text-white-75" href="/progress"><i class="bi bi-graph-up me-1"></i>Progress</a></li>' if is_logged_in else ''}
          </ul>
          <ul class="navbar-nav">{user_menu}</ul>
        </div>
      </div>
    </nav>
    """

    disclaimer = f"""
    <footer class="bg-light py-4 mt-5 border-top">
      <div class="container">
        <div class="row align-items-center">
          <div class="col-md-7">
            <small class="text-muted">
              <strong>Notice:</strong> This platform is independent and not affiliated with ASIS International.
              CPP&reg; is a mark of ASIS International, Inc.
              &nbsp;•&nbsp;<a href="/legal/terms" class="text-decoration-none">Terms &amp; Conditions</a>
            </small>
          </div>
          <div class="col-md-3 text-md-end mt-2 mt-md-0">
            <a href="#" id="report-issue" class="small text-muted text-decoration-none"><i class="bi bi-flag me-1"></i>Report an issue</a>
          </div>
          <div class="col-md-2 text-md-end mt-2 mt-md-0">
            <small class="text-muted">Version {APP_VERSION}</small>
          </div>
        </div>
      </div>
    </footer>
    """
    stage_banner = ("""
      <div class="alert alert-warning alert-dismissible fade show m-0" role="alert">
        <div class="container text-center">
          <strong>STAGING ENVIRONMENT</strong> - Not for production use.
          <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
      </div>
    """ if IS_STAGING else "")

    style_css = """
    <style>
      :root {
        --primary-blue:#2563eb; --success-green:#059669; --warning-orange:#d97706;
        --danger-red:#dc2626; --purple-accent:#7c3aed; --soft-gray:#f8fafc;
        --warm-white:#fefefe; --text-dark:#1f2937; --text-light:#6b7280;
      }
      body{font-family:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',systemui,sans-serif;
           background:linear-gradient(135deg,#f8fafc 0%,#e2e8f0 100%);color:var(--text-dark);line-height:1.6;}
      .bg-gradient-primary{background:linear-gradient(135deg,var(--primary-blue) 0%,var(--purple-accent) 100%)!important;}
      .text-white-75{color:rgba(255,255,255,.85)!important}.text-white-75:hover{color:#fff!important}
      .card{box-shadow:0 4px 12px rgba(0,0,0,.08);border:none;border-radius:16px;background:var(--warm-white);
            transition:all .3s ease;overflow:hidden}
      .card:hover{transform:translateY(-2px);box-shadow:0 8px 24px rgba(0,0,0,.12)}
      .btn{border-radius:12px;font-weight:600;letter-spacing:.025em;padding:.75rem 1.5rem;transition:all .2s ease}
      .domain-btn{border-radius:999px;padding:.4rem .9rem}.domain-btn.active{outline:3px solid rgba(0,0,0,.1);
        box-shadow:0 0 0 3px rgba(37,99,235,.15) inset}
      .btn-primary{background:linear-gradient(135deg,var(--primary-blue),var(--purple-accent));border:none;
        box-shadow:0 4px 12px rgba(37,99,235,.25)}
      .btn-primary:hover{transform:translateY(-1px);box-shadow:0 6px 20px rgba(37,99,235,.35)}
      .plan-monthly{background:linear-gradient(45deg,var(--primary-blue),var(--purple-accent));color:#fff}
      .plan-sixmonth{background:linear-gradient(45deg,var(--purple-accent),#8b5cf6);color:#fff}
      .plan-inactive{background:#6b7280;color:#fff}
      .alert{border-radius:12px;border:none;padding:1.25rem}
      .alert-success{background:linear-gradient(135deg,#d1fae5,#a7f3d0);color:#065f46;border-left:4px solid var(--success-green)}
      .alert-info{background:linear-gradient(135deg,#dbeafe,#bfdbfe);color:#1e3a8a;border-left:4px solid var(--primary-blue)}
      .alert-warning{background:linear-gradient(135deg,#fef3c7,#fed7aa);color:#92400e;border-left:4px solid var(--warning-orange)}
      .form-control,.form-select{border-radius:10px;border:2px solid #e5e7eb;padding:.75rem 1rem;transition:all .2s ease}
      .form-control:focus,.form-select:focus{border-color:var(--primary-blue);box-shadow:0 0 0 3px rgba(37,99,235,.1)}
      .navbar-brand{font-size:1.5rem;font-weight:700}
      .text-success{color:var(--success-green)!important;fill:var(--success-green)}
      .text-warning{color:var(--warning-orange)!important;fill:var(--warning-orange)}
      .text-danger{color:var(--danger-red)!important;fill:var(--danger-red)}
      @media (max-width:768px){.container{padding:0 20px}.card{margin-bottom:1.5rem;border-radius:12px}.btn{padding:.6rem 1.2rem}}
    </style>
    """

    # Replace Jinja literal if present in inline templates
    body_html = body_html.replace('{{ csrf_token() }}', csrf_value)

    return f"""<!DOCTYPE html>
    <html lang="en"><head>
      <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
      <meta name="csrf-token" content="{csrf_value}">
      <title>{html.escape(title)} - CPP Test Prep</title>
      <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
      <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css" rel="stylesheet">
      <link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
      <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
      {style_css}
    </head>
    <body class="d-flex flex-column min-vh-100">
      {nav}{stage_banner}
      <main class="flex-grow-1 py-4">{body_html}</main>
      {disclaimer}
      <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
      <script>
        (function(){{
          var a = document.getElementById('report-issue');
          if (a) {{
            a.addEventListener('click', function(e) {{
              e.preventDefault();
              try {{
                if (navigator.sendBeacon) navigator.sendBeacon('/events/report', new Blob([], {{type:'text/plain'}}));
              }} catch(_e) {{}}
              alert('Thanks for the heads up! Issue ping sent.');
            }});
          }}
        }})();
      </script>
    </body></html>"""

# ---- Health ----
@app.get("/healthz")
def healthz():
    ok = {"status": "healthy", "timestamp": datetime.utcnow().isoformat() + "Z", "version": APP_VERSION}
    return ok

# ---- Legal: Terms (static) & Accept gate ----
@app.get("/legal/terms")
def legal_terms_page():
    body = """
    <div class="container">
      <div class="row justify-content-center"><div class="col-lg-9">
        <div class="card">
          <div class="card-header bg-dark text-white">
            <h3 class="mb-0"><i class="bi bi-journal-text me-2"></i>Terms &amp; Conditions</h3>
          </div>
          <div class="card-body">
            <p class="text-muted">
              This platform is an independent study aid and is not affiliated with ASIS International.
              No refunds. Access is granted per the plan selected. Use at your own discretion.
            </p>
            <hr>
            <h5>1. Access &amp; Use</h5>
            <p class="small text-muted">You agree to use the service for personal study. Unauthorized sharing is prohibited.</p>
            <h5>2. Payment &amp; Renewals</h5>
            <p class="small text-muted">Subscriptions and one-time plans are processed by Stripe. No refunds.</p>
            <h5>3. Content</h5>
            <p class="small text-muted">Study materials are provided “as is” without warranty. Always consult official sources.</p>
            <h5>4. Limitation of Liability</h5>
            <p class="small text-muted">We are not liable for any damages arising from use of the service.</p>
            <h5>5. Changes</h5>
            <p class="small text-muted">Terms may change; you’ll be prompted to re-accept when material changes occur.</p>
            <div class="mt-3">
              <a class="btn btn-outline-secondary" href="/"><i class="bi bi-arrow-left me-1"></i>Back</a>
            </div>
          </div>
        </div>
      </div></div>
    </div>
    """
    return base_layout("Terms & Conditions", body)

@app.route("/legal/accept", methods=["GET", "POST"])
@login_required
def legal_accept_page():
    user = _find_user(session.get("email",""))
    if not user:
        return redirect(url_for("login_page"))
    nxt = request.args.get("next") or url_for("home")

    if request.method == "POST":
        if not _csrf_ok():
            abort(403)
        if request.form.get("agree") == "on":
            _mark_terms_accepted(user["id"])
            return redirect(nxt)

    csrf_val = csrf_token()
    body = f"""
    <div class="container"><div class="row justify-content-center"><div class="col-md-8">
      <div class="card">
        <div class="card-header bg-warning text-dark">
          <h3 class="mb-0"><i class="bi bi-shield-lock me-2"></i>Accept Terms &amp; Conditions</h3>
        </div>
        <div class="card-body">
          <p class="text-muted">
            To continue, please review our <a href="/legal/terms" target="_blank" rel="noopener">Terms &amp; Conditions</a> and confirm your acceptance.
          </p>
          <form method="POST">
            <input type="hidden" name="csrf_token" value="{csrf_val}"/>
            <div class="form-check mb-3">
              <input class="form-check-input" type="checkbox" id="agree" name="agree" required>
              <label class="form-check-label" for="agree">
                I have read and agree to the <a href="/legal/terms" target="_blank" rel="noopener">Terms &amp; Conditions</a>.
              </label>
            </div>
            <button type="submit" class="btn btn-primary">Accept & Continue</button>
            <a href="/" class="btn btn-outline-secondary ms-2">Cancel</a>
          </form>
        </div>
      </div>
    </div></div></div>
    """
    return base_layout("Accept Terms", body)

# ---- Auth: Login / Signup / Logout ----
@app.get("/login")
def login_page():
    if 'user_id' in session:
        return redirect(url_for('home'))
    body = """
    <div class="container">
      <div class="row justify-content-center"><div class="col-md-6 col-lg-4">
        <div class="card shadow-lg"><div class="card-body p-4">
          <div class="text-center mb-4">
            <i class="bi bi-shield-check text-primary display-4 mb-3"></i>
            <h2 class="card-title fw-bold text-primary">Welcome Back</h2>
            <p class="text-muted">Sign in to continue your CPP journey</p>
          </div>
          <form method="POST" action="/login">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
            <div class="mb-3"><label class="form-label fw-semibold">Email</label>
              <input type="email" class="form-control" name="email" required placeholder="your.email@example.com">
            </div>
            <div class="mb-4"><label class="form-label fw-semibold">Password</label>
              <input type="password" class="form-control" name="password" required placeholder="Enter your password">
            </div>
            <button type="submit" class="btn btn-primary w-100 mb-3">Sign In</button>
          </form>
          <div class="text-center">
            <p class="text-muted mb-2">Don't have an account?</p>
            <a href="/signup" class="btn btn-outline-primary">Create Account</a>
          </div>
        </div></div>
      </div></div>
    </div>
    """
    return base_layout("Sign In", body)

@app.post("/login")
def login_post():
    if _rate_limited("login", limit=5, per_seconds=300):
        return redirect(url_for('login_page'))
    if not _csrf_ok():
        abort(403)

    email = request.form.get('email', '').strip().lower()
    password = request.form.get('password', '')

    if not email or not password:
        return redirect(url_for('login_page'))

    user = _find_user(email)
    if user and check_password_hash(user.get('password_hash', ''), password):
        try:
            session.regenerate()  # Flask 3.x; guard below keeps compatibility
        except AttributeError:
            session.clear()
            session.permanent = True
        session['user_id'] = user['id']
        session['email'] = user['email']
        session['name'] = user.get('name', '')
        logger.info(f"User logged in: {email}")
        # T&C gate: force accept if missing/outdated
        if _require_terms_gate(email):
            return redirect(url_for("legal_accept_page", next=url_for("home")))
        return redirect(url_for('home'))

    logger.warning(f"Failed login attempt: {email}")
    return redirect(url_for('login_page'))

@app.get("/signup")
def signup_page():
    body = """
    <div class="container">
      <div class="row justify-content-center"><div class="col-lg-10">
        <div class="text-center mb-5">
          <i class="bi bi-mortarboard text-primary display-4 mb-3"></i>
          <h1 class="display-5 fw-bold text-primary">Start Your CPP Journey</h1>
          <p class="lead text-muted">Choose your path to certification success</p>
        </div>
        <div class="row mb-5">
          <div class="col-md-6 mb-4">
            <div class="card h-100 border-primary">
              <div class="card-header bg-primary text-white text-center"><h4 class="mb-0">Monthly Plan</h4></div>
              <div class="card-body text-center p-4">
                <div class="mb-3"><span class="display-4 fw-bold text-primary">$39.99</span><span class="text-muted fs-5">/month</span></div>
                <p class="text-muted mb-4">Perfect for focused study periods</p>
                <ul class="list-unstyled mb-4">
                  <li class="mb-2"><i class="bi bi-check-circle-fill text-success me-2"></i>Unlimited practice quizzes</li>
                  <li class="mb-2"><i class="bi bi-check-circle-fill text-success me-2"></i>AI tutor with instant help</li>
                  <li class="mb-2"><i class="bi bi-check-circle-fill text-success me-2"></i>Progress tracking & analytics</li>
                  <li class="mb-2"><i class="bi bi-check-circle-fill text-success me-2"></i>Mobile-friendly study</li>
                  <li class="mb-2"><i class="bi bi-check-circle-fill text-success me-2"></i>Cancel anytime</li>
                </ul>
                <button class="btn btn-primary btn-lg w-100" onclick="selectPlan('monthly')">Choose Monthly</button>
              </div>
            </div>
          </div>
          <div class="col-md-6 mb-4">
            <div class="card h-100 border-success position-relative">
              <div class="badge bg-warning text-dark position-absolute top-0 start-50 translate-middle px-3 py-2 fw-bold">
                <i class="bi bi-star-fill me-1"></i>Best Value
              </div>
              <div class="card-header bg-success text-white text-center pt-4"><h4 class="mb-0">6-Month Plan</h4></div>
              <div class="card-body text-center p-4">
                <div class="mb-3"><div class="display-4 fw-bold text-success mb-1">$99.00</div><span class="text-muted fs-6">One-time payment</span></div>
                <p class="text-muted mb-4">Complete preparation program</p>
                <ul class="list-unstyled mb-4">
                  <li class="mb-2"><i class="bi bi-check-circle-fill text-success me-2"></i>Everything in Monthly</li>
                  <li class="mb-2"><i class="bi bi-check-circle-fill text-success me-2"></i>6 full months of access</li>
                  <li class="mb-2"><i class="bi bi-check-circle-fill text-success me-2"></i>No auto-renewal</li>
                  <li class="mb-2"><i class="bi bi-check-circle-fill text-success me-2"></i>Save $140+ vs monthly</li>
                  <li class="mb-2"><i class="bi bi-check-circle-fill text-success me-2"></i>Extended study time</li>
                </ul>
                <button class="btn btn-success btn-lg w-100" onclick="selectPlan('sixmonth')">Choose 6-Month</button>
              </div>
            </div>
          </div>
        </div>

        <div class="card shadow-lg"><div class="card-body p-4">
          <h3 class="card-title text-center mb-4">Create Your Account</h3>
          <form method="POST" action="/signup" id="signupForm">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
            <input type="hidden" name="plan" id="selectedPlan" value="monthly">
            <div class="row">
              <div class="col-md-6 mb-3"><label class="form-label fw-semibold">Full Name</label>
                <input type="text" class="form-control" name="name" required placeholder="John Doe"></div>
              <div class="col-md-6 mb-3"><label class="form-label fw-semibold">Email</label>
                <input type="email" class="form-control" name="email" required placeholder="john@example.com"></div>
            </div>
            <div class="mb-3"><label class="form-label fw-semibold">Password</label>
              <input type="password" class="form-control" name="password" required minlength="8" placeholder="At least 8 characters">
              <div class="form-text">Choose a strong password with at least 8 characters</div>
            </div>
            <div class="form-check mb-4">
              <input class="form-check-input" type="checkbox" id="agree" name="agree" required>
              <label class="form-check-label" for="agree">
                I agree to the <a href="/legal/terms" target="_blank" rel="noopener">Terms &amp; Conditions</a>.
              </label>
            </div>
            <button type="submit" class="btn btn-success btn-lg w-100">
              <i class="bi bi-rocket-takeoff me-2"></i>Create Account & Continue
            </button>
          </form>
        </div></div>
      </div></div>
    </div>
    <script>
      var selectedPlanType = 'monthly';
      function selectPlan(plan) {
        selectedPlanType = plan;
        var el = document.getElementById('selectedPlan'); if (el) el.value = plan;
        var cards = document.querySelectorAll('.card.h-100');
        cards.forEach(function(c){ c.style.transform='none'; c.classList.remove('shadow-lg'); });
        var btn = document.querySelector('[onclick="selectPlan(\\''+plan+'\\')"]');
        if (btn) { var card = btn.closest('.card'); if (card) { card.classList.add('shadow-lg'); card.style.transform='translateY(-6px)'; } }
      }
      selectPlan('monthly');
    </script>
    """
    return base_layout("Create Account", body)

@app.post("/signup")
def signup_post():
    if not _csrf_ok():
        abort(403)

    name = request.form.get('name', '').strip()
    email = request.form.get('email', '').strip().lower()
    password = request.form.get('password', '')
    plan = (request.form.get('plan') or 'monthly').strip()
    agree = (request.form.get('agree') == 'on')

    if not name or not email or not password or not agree:
        return redirect(url_for('signup_page'))
    if not validate_email(email):
        return redirect(url_for('signup_page'))
    ok_pw, _msg = validate_password(password)
    if not ok_pw:
        return redirect(url_for('signup_page'))
    if _find_user(email):
        return redirect(url_for('signup_page'))

    user = {
        "id": str(uuid.uuid4()), "name": name, "email": email,
        "password_hash": generate_password_hash(password),
        "subscription": "inactive",
        "usage": {"monthly": {}, "last_active": ""},
        "created_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "history": [],
        "terms_accept_version": TERMS_VERSION,
        "terms_accept_ts": datetime.utcnow().isoformat(timespec="seconds") + "Z"
    }
    USERS.append(user); _save_json("users.json", USERS)

    try:
        session.regenerate()
    except AttributeError:
        session.clear(); session.permanent = True
    session['user_id'] = user['id']; session['email'] = user['email']; session['name'] = user['name']
    # Persist plan preference (optional): we can carry to /billing UI
    session['preferred_plan'] = plan

    # Per policy: no discount code handling here; purchasing happens on /billing
    return redirect(url_for('billing_page'))

@app.post("/logout")
def logout():
    if not _csrf_ok():
        abort(403)
    session.clear()
    return redirect(url_for('login_page'))
# =========================
# SECTION 3/8: Home, Study Alias, Tutor (AI), Minimal Analytics
# =========================

# Provide DOMAINS mapping if not already defined (used by domain buttons)
if 'DOMAINS' not in globals():
    DOMAINS = {
        "security-principles":  "Security Principles",
        "business-principles":  "Business Principles",
        "investigations":       "Investigations",
        "personnel-security":   "Personnel Security",
        "physical-security":    "Physical Security",
        "information-security": "Information Security",
        "crisis-management":    "Crisis & Continuity",
    }

# ---------- Home / Dashboard ----------
@app.get("/")
def home():
    if 'user_id' not in session:
        # Public welcome + disclaimer with T&C link (non-destructive to existing UX)
        body = """
        <div class="container text-center">
          <div class="mb-5">
            <i class="bi bi-mortarboard text-primary display-1 mb-4"></i>
            <h1 class="display-4 fw-bold">Master the CPP Exam</h1>
            <p class="lead text-muted">AI tutor, practice quizzes, flashcards, and progress tracking.</p>
          </div>

          <div class="alert alert-warning text-start mx-auto" style="max-width:860px;">
            <div class="d-flex">
              <i class="bi bi-exclamation-triangle-fill me-3 fs-4"></i>
              <div>
                <strong>Disclaimer.</strong> This platform is independent and not affiliated with ASIS International. CPP&reg; is a mark of ASIS International, Inc.
                Use of this site constitutes acceptance of our <a class="fw-semibold" href="/legal/terms" target="_blank" rel="noopener">Terms &amp; Conditions</a>.
                All sales are final.
              </div>
            </div>
          </div>

          <div class="d-flex justify-content-center gap-3 mb-4">
            <a href="/signup" class="btn btn-primary btn-lg px-4"><i class="bi bi-rocket-takeoff me-2"></i>Start Learning</a>
            <a href="/login" class="btn btn-outline-primary btn-lg px-4"><i class="bi bi-box-arrow-in-right me-2"></i>Sign In</a>
          </div>
          <div class="row g-3 mt-4">
            <div class="col-md-4">
              <div class="card h-100"><div class="card-body text-center p-4">
                <i class="bi bi-robot display-6 text-primary mb-3"></i>
                <h5>AI Study Tutor</h5><p class="text-muted small mb-0">Clear answers and references.</p>
              </div></div>
            </div>
            <div class="col-md-4">
              <div class="card h-100"><div class="card-body text-center p-4">
                <i class="bi bi-card-text display-6 text-success mb-3"></i>
                <h5>Practice & Mock</h5><p class="text-muted small mb-0">Realistic questions by domain.</p>
              </div></div>
            </div>
            <div class="col-md-4">
              <div class="card h-100"><div class="card-body text-center p-4">
                <i class="bi bi-graph-up display-6 text-warning mb-3"></i>
                <h5>Progress Tracking</h5><p class="text-muted small mb-0">See strengths and gaps.</p>
              </div></div>
            </div>
          </div>
        </div>
        """
        return base_layout("CPP Test Prep", body)

    first_name = (session.get('name') or '').split(' ')[0] or 'there'
    body = f"""
    <div class="container">
      <div class="row g-3">
        <div class="col-12">
          <div class="card"><div class="card-body p-4 d-flex align-items-center">
            <i class="bi bi-person-check text-primary fs-1 me-3"></i>
            <div>
              <h3 class="mb-1">Welcome back, {html.escape(first_name)}!</h3>
              <div class="text-muted">Pick a study mode to continue.</div>
            </div>
          </div></div>
        </div>

        <div class="col-md-3"><a class="text-decoration-none" href="/study">
          <div class="card h-100"><div class="card-body text-center p-4">
            <i class="bi bi-robot display-6 text-primary mb-2"></i>
            <h6 class="mb-0">Tutor</h6>
          </div></div></a>
        </div>

        <div class="col-md-3"><a class="text-decoration-none" href="/flashcards">
          <div class="card h-100"><div class="card-body text-center p-4">
            <i class="bi bi-card-list display-6 text-info mb-2"></i>
            <h6 class="mb-0">Flashcards</h6>
          </div></div></a>
        </div>

        <div class="col-md-3"><a class="text-decoration-none" href="/quiz">
          <div class="card h-100"><div class="card-body text-center p-4">
            <i class="bi bi-card-text display-6 text-success mb-2"></i>
            <h6 class="mb-0">Quiz</h6>
          </div></div></a>
        </div>

        <div class="col-md-3"><a class="text-decoration-none" href="/mock-exam">
          <div class="card h-100"><div class="card-body text-center p-4">
            <i class="bi bi-clipboard-check display-6 text-warning mb-2"></i>
            <h6 class="mb-0">Mock Exam</h6>
          </div></div></a>
        </div>
      </div>
    </div>
    """
    return base_layout("Dashboard", body)

# ---------- Study alias -> Tutor ----------
@app.get("/study", strict_slashes=False)
@login_required
def study_page():
    return redirect(url_for("tutor_page"))

# ---------- Minimal analytics utilities ----------
def _log_event(user_id, event_type, payload):
    try:
        data = _load_json("events.json", [])
        data.append({
            "id": str(uuid.uuid4()),
            "ts": datetime.utcnow().isoformat() + "Z",
            "user_id": user_id,
            "type": event_type,
            "payload": payload
        })
        _save_json("events.json", data)
    except Exception as e:
        logger.warning("log_event failed: %s", e)

def _append_user_history(user_id, channel, item):
    try:
        key = f"history_{channel}_{user_id}.json"
        history = _load_json(key, [])
        history.append(item)
        history = history[-20:]
        _save_json(key, history)
    except Exception as e:
        logger.warning("append_user_history failed: %s", e)

def _get_user_history(user_id, channel, limit=5):
    try:
        key = f"history_{channel}_{user_id}.json"
        hist = _load_json(key, [])
        return hist[-limit:]
    except Exception:
        return []

@app.before_request
def _track_page_views():
    try:
        uid = session.get("user_id") or session.get("email") or "anon"
        _log_event(uid, "page.view", {"path": request.path, "method": request.method})
    except Exception:
        pass

# ---------- Tutor (AI) ----------
def _call_tutor_agent(user_query, meta=None):
    """
    Baseline agent caller. This function is intentionally simple here and
    will be *extended/overridden* in Section 7 to support web-aware citations.
    """
    meta = meta or {}
    timeout_s = float(os.environ.get("TUTOR_TIMEOUT", "45"))
    temperature = float(os.environ.get("TUTOR_TEMP", "0.3"))
    max_tokens = int(os.environ.get("TUTOR_MAX_TOKENS", "800"))
    system_msg = os.environ.get("TUTOR_SYSTEM_PROMPT",
        "You are a calm, expert CPP/PSP study tutor. Explain clearly, step-by-step."
    )

    if not OPENAI_API_KEY:
        return False, "Tutor is not configured: missing OPENAI_API_KEY.", {}

    url = f"{OPENAI_API_BASE}/chat/completions"
    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "Content-Type": "application/json",
    }
    org = os.environ.get("OPENAI_ORG", "").strip()
    if org:
        headers["OpenAI-Organization"] = org
    payload = {
        "model": OPENAI_CHAT_MODEL,
        "messages": [
            {"role": "system", "content": system_msg},
            {"role": "user", "content": user_query}
        ],
        "temperature": temperature,
        "max_tokens": max_tokens
    }

    backoffs = [0, 1.5, 3.0]
    last_err = None
    for wait_s in backoffs:
        if wait_s:
            time.sleep(wait_s)
        try:
            resp = requests.post(url, headers=headers, data=json.dumps(payload), timeout=timeout_s)
            if resp.status_code in (429, 500, 502, 503, 504):
                last_err = f"{resp.status_code} {resp.text[:300]}"
                continue
            if resp.status_code >= 400:
                try:
                    j = resp.json()
                    msg = (j.get("error") or {}).get("message") or resp.text[:300]
                except Exception:
                    msg = resp.text[:300]
                return False, f"Agent error {resp.status_code}: {msg}", {"status": resp.status_code}
            data = resp.json()
            answer = (data.get("choices") or [{}])[0].get("message", {}).get("content", "")
            usage = data.get("usage", {})
            return True, answer, {"usage": usage, "model": OPENAI_CHAT_MODEL}
        except Exception as e:
            last_err = str(e)
            continue
    return False, f"Network/agent error: {last_err or 'unknown'}", {}

# --- NEW: Randomized suggested questions helper (Option B) ---
def _suggested_questions_for_domain(domain_key: str | None, k: int = 4):
    """
    Return up to k suggested question dicts [{"text":..., "domain":...}] for the given domain.
    - If domain_key is 'random' or falsy, pick from ALL domains.
    - Always shuffle and de-duplicate by text.
    """
    try:
        # Prefer curated bank if available; otherwise fall back to SUGGESTED_QUESTION_BANK (Section 1)
        pool = []
        try:
            # These helpers are defined later in Section 4; runtime-safe as we only call when the route executes.
            pool = _all_normalized_questions()
            pool = _filter_by_domain(pool, domain_key or "random")
            pool = [{"text": q.get("text","").strip(), "domain": q.get("domain") or "Unspecified"} for q in pool if q.get("text")]
        except Exception:
            # Fallback to static suggestions
            if not domain_key or domain_key == "random":
                for items in SUGGESTED_QUESTION_BANK.values():
                    for t in items:
                        pool.append({"text": t, "domain": "Mixed"})
            else:
                for t in SUGGESTED_QUESTION_BANK.get(domain_key, []):
                    pool.append({"text": t, "domain": domain_key})

        random.shuffle(pool)
        out, seen = [], set()
        for q in pool:
            t = (q.get("text") or "").strip()
            if not t or t in seen:
                continue
            seen.add(t)
            out.append({"text": t, "domain": (q.get("domain") or "Unspecified")})
            if len(out) >= max(1, min(int(k or 4), 8)):
                break
        return out
    except Exception as e:
        logger.warning("suggested questions error: %s", e)
        return []

@app.route("/tutor", methods=["GET", "POST"], strict_slashes=False)
@app.route("/tutor/", methods=["GET", "POST"], strict_slashes=False)
@login_required
def tutor_page():
    user = _find_user(session.get("email","")) or {}
    user_id = user.get("id") or session.get("email") or "unknown"

    tutor_error = ""
    tutor_answer = ""
    user_query = (request.form.get("query") or "").strip() if request.method == "POST" else ""
    selected_domain = (request.form.get("domain") or "random").strip().lower()

    if request.method == "POST":
        if not _csrf_ok():
            abort(403)

        # Plan/usage gate for tutor messages
        ok_limit, msg_limit = check_usage_limit(user, "tutor_msgs")
        if not ok_limit:
            tutor_error = msg_limit
        elif not user_query:
            tutor_error = "Please enter a question."
        else:
            # Inject domain cue for the agent when selected
            if selected_domain and selected_domain != "random":
                domain_label = DOMAINS.get(selected_domain, selected_domain)
                user_query = f"[Domain: {domain_label}] {user_query}"

            ok, answer, meta = _call_tutor_agent(user_query, meta={"user_id": user_id, "domain": selected_domain})
            if ok:
                tutor_answer = answer
                item = {"ts": datetime.utcnow().isoformat() + "Z", "q": user_query, "a": tutor_answer, "meta": meta}
                _append_user_history(user_id, "tutor", item)
                _log_event(user_id, "tutor.ask", {"q_len": len(user_query), "ok": True, "model": meta.get("model")})
                try:
                    increment_usage(user.get("email") or session.get("email",""), "tutor_msgs", 1)
                except Exception as _e:
                    logger.warning("usage increment (tutor) failed: %s", _e)
            else:
                tutor_error = answer
                _log_event(user_id, "tutor.ask", {"q_len": len(user_query), "ok": False})

    recent = _get_user_history(user_id, "tutor", limit=5)

    csrf_val = csrf_token()
    def _fmt(txt): return html.escape(txt).replace("\n","<br>")
    history_html = ""
    if recent:
        rows = []
        for it in recent:
            rows.append(
                f"<div class='mb-3'><div class='small text-muted'>{html.escape(it.get('ts',''))}</div>"
                f"<div class='fw-semibold'>You</div><div class='mb-2'>{_fmt(it.get('q',''))}</div>"
                f"<div class='fw-semibold'>Tutor</div><div>{_fmt(it.get('a',''))}</div></div>"
            )
        history_html = "".join(rows)
    else:
        history_html = "<div class='text-muted'>No history yet.</div>"

    # Domain button block
    domain_buttons = domain_buttons_html(selected_key=selected_domain, field_name="domain")

    # NEW: randomized suggested questions (4) based on selected domain (or mixed when random)
    suggestions = _suggested_questions_for_domain(selected_domain, k=4)
    def _suggest_btn(s):
        dom_key = (s.get("domain") or "Unspecified")
        dom_label = DOMAINS.get(str(dom_key).lower(), dom_key)
        return (
            "<button type='button' class='btn btn-outline-secondary w-100 text-start mb-2 suggested-q' "
            f"data-q=\"{html.escape(s.get('text',''))}\">"
            f"<span class='badge bg-light text-dark me-2'>{html.escape(str(dom_label))}</span>"
            f"{html.escape(s.get('text',''))}</button>"
        )
    suggestions_html = "".join(_suggest_btn(s) for s in suggestions) or "<div class='text-muted'>No suggestions yet.</div>"

    content = f"""
    <div class="container">
      <div class="row g-3 justify-content-center">
        <div class="col-lg-8">
          <div class="card">
            <div class="card-header bg-primary text-white">
              <h3 class="mb-0"><i class="bi bi-mortarboard me-2"></i>Tutor</h3>
            </div>
            <div class="card-body">
              <form id="tutorForm" method="POST" class="mb-3">
                <input type="hidden" name="csrf_token" value="{csrf_val}"/>
                <label class="form-label fw-semibold">Select a domain (optional)</label>
                {domain_buttons}
                <label class="form-label fw-semibold mt-3">Ask the Tutor</label>
                <textarea name="query" class="form-control" rows="3" placeholder="Ask about CPP/PSP topics...">{html.escape(user_query)}</textarea>
                <div class="d-flex gap-2 mt-3">
                  <button type="submit" class="btn btn-primary"><i class="bi bi-send me-1"></i>Ask</button>
                  <a href="/tutor" class="btn btn-outline-secondary">Clear</a>
                </div>
              </form>

              {"<div class='alert alert-danger'>" + html.escape(tutor_error) + "</div>" if tutor_error else ""}
              {"<div class='alert alert-success'><div class='fw-semibold mb-1'>Tutor:</div>" + _fmt(tutor_answer) + "</div>" if tutor_answer else ""}

              <div class="border-top pt-3">
                <div class="fw-semibold mb-2"><i class="bi bi-clock-history me-1"></i>Recent (last 5)</div>
                {history_html}
              </div>
              <a href="/" class="btn btn-outline-secondary mt-3"><i class="bi bi-arrow-left me-1"></i>Back</a>
            </div>
          </div>
        </div>

        <!-- NEW: Suggestions sidebar -->
        <div class="col-lg-4">
          <div class="card h-100">
            <div class="card-header bg-light">
              <h5 class="mb-0"><i class="bi bi-stars me-1"></i>Suggested prompts</h5>
              <div class="small text-muted">
                {("Mix of all domains" if selected_domain == "random" else "Based on " + html.escape(DOMAINS.get(selected_domain, selected_domain)))}
              </div>
            </div>
            <div class="card-body">
              {suggestions_html}
              <div class="small text-muted mt-2">Click a suggestion to auto-send.</div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <script>
      // Make the domain buttons click set the hidden input + toggle active
      (function(){{
        var container = document.currentScript.closest('body').querySelector('.card-body');
        if (!container) return;
        var hidden = document.getElementById('domain_val');
        document.querySelectorAll('.domain-btn').forEach(function(btn){{
          btn.addEventListener('click', function(){{
            document.querySelectorAll('.domain-btn').forEach(function(b){{ b.classList.remove('active'); }});
            btn.classList.add('active');
            if (hidden) hidden.value = btn.getAttribute('data-value');
          }});
        }});
      }})();
      // Auto-submit when clicking a suggested question
      (function(){{
        var form = document.getElementById('tutorForm');
        if (!form) return;
        var ta = form.querySelector('textarea[name="query"]');
        document.querySelectorAll('.suggested-q').forEach(function(btn){{
          btn.addEventListener('click', function(){{
            var q = btn.getAttribute('data-q') || '';
            if (ta) ta.value = q;
            form.submit();
          }});
        }});
      }})();
    </script>
    """
    return base_layout("Tutor", content)

@app.get("/tutor/ping")
@login_required
def tutor_ping():
    ok, answer, meta = _call_tutor_agent("Reply 'pong' only.", meta={"ping": True})
    return jsonify({"ok": bool(ok), "answer_preview": (answer or "")[:200], "meta": meta}), (200 if ok else 502)
# =========================
# SECTION 4/8: Quiz & Mock Exam (domain & count pickers, safe handling)
# =========================

# ---------- Normalize questions for runtime engine ----------
def _normalize_question_runtime(q, idx=None):
    """
    Converts a legacy/base/bank question into a uniform runtime dict:
    {
      "id": str,
      "text": "...",
      "domain": "...",
      "choices": [{"key":"A","text":"..."}, ...],  # supports 2 (T/F) or 4 choices
      "correct_key": "A",
      "type": "mcq" | "tf" | "scenario"
    }
    Notes:
      - True/False questions are represented as 2-choice MCQ (A=True, B=False) in the bank.
      - Scenario questions are plain MCQ where the stem may begin with "Scenario:".
    """
    if not q:
        return None

    qid = str(q.get("id") or idx or uuid.uuid4())
    text = (q.get("question") or q.get("q") or q.get("stem") or q.get("text") or "").strip()
    if not text:
        return None

    domain = (q.get("domain") or q.get("category") or q.get("section") or "Unspecified")

    # Gather options; support dict (preferred) or list
    raw_opts = q.get("options") or q.get("choices") or {}
    opts_dict = {}
    if isinstance(raw_opts, dict):
        # Accept either 2-choice (A,B) or 4-choice (A..D)
        for L in ["A", "B", "C", "D"]:
            if L in raw_opts:
                opts_dict[L] = str(raw_opts[L])
        # If only two keys are present and they are A,B -> treat as T/F
        if set(opts_dict.keys()) not in ({"A", "B"}, {"A", "B", "C", "D"}):
            # try lowercase keys
            lowered = {k.upper(): v for k, v in raw_opts.items() if k and isinstance(k, str)}
            opts_dict = {}
            for L in ["A", "B", "C", "D"]:
                if L in lowered:
                    opts_dict[L] = str(lowered[L])
    elif isinstance(raw_opts, list):
        # Allow list with length 2 or >=4; map to A.. letters
        letters = ["A", "B", "C", "D"]
        if len(raw_opts) >= 4:
            for i, L in enumerate(letters):
                v = raw_opts[i]
                opts_dict[L] = (v.get("text") if isinstance(v, dict) else str(v))
        elif len(raw_opts) == 2:
            for i, L in enumerate(["A", "B"]):
                v = raw_opts[i]
                opts_dict[L] = (v.get("text") if isinstance(v, dict) else str(v))
    else:
        return None

    if not opts_dict or (len(opts_dict) not in (2, 4)):
        return None

    # Correct key
    correct = q.get("correct") or q.get("answer") or q.get("correct_key")
    if isinstance(correct, str):
        ck = correct.strip().upper()
        if ck in opts_dict:
            correct_key = ck
        else:
            # allow 1-based index strings "1".."4"
            try:
                idx_num = int(ck)
                letters = list(opts_dict.keys())
                letters.sort()  # ensure deterministic A..D order
                correct_key = letters[idx_num - 1]
            except Exception:
                return None
    else:
        return None

    # Build choices array in A.. order (or A,B for TF)
    letters_order = sorted(list(opts_dict.keys()))
    choices = [{"key": L, "text": str(opts_dict[L])} for L in letters_order]

    # Determine type (for internal analytics only; UI unchanged)
    qtype = "mcq"
    if len(choices) == 2:
        qtype = "tf"
    elif text.lower().startswith("scenario:"):
        qtype = "scenario"

    return {
        "id": qid,
        "text": text,
        "domain": domain,
        "choices": choices,
        "correct_key": correct_key,
        "type": qtype
    }

def _all_normalized_questions():
    """
    Merge base/legacy ALL_QUESTIONS with bank questions (data/bank/cpp_questions_v1.json)
    into normalized runtime items. De-dup by (text, domain, correct_key).
    """
    out = []
    seen = set()

    # From legacy/base merged set built earlier
    for i, q in enumerate(ALL_QUESTIONS or []):
        nq = _normalize_question_runtime(q, idx=f"base-{i}")
        if nq:
            key = (nq["text"], nq["domain"], nq["correct_key"])
            if key not in seen:
                seen.add(key)
                out.append(nq)

    # From bank file
    bank = _load_json("bank/cpp_questions_v1.json", [])
    for i, q in enumerate(bank or []):
        nq = _normalize_question_runtime(q, idx=f"bank-{i}")
        if nq:
            key = (nq["text"], nq["domain"], nq["correct_key"])
            if key not in seen:
                seen.add(key)
                out.append(nq)

    return out

# ---------- Filters & picks ----------
def _filter_by_domain(pool, domain_key: str | None):
    if not domain_key or domain_key == "random":
        return pool[:]
    dk = str(domain_key).strip().lower()
    return [q for q in pool if str(q.get("domain") or "").strip().lower() == dk]

def _pick_questions(count: int, domain: str | None):
    pool = _all_normalized_questions()
    pool = _filter_by_domain(pool, domain)
    random.shuffle(pool)
    return pool[:max(0, min(count, len(pool)))]

# ---------- Run persistence ----------
def _run_key(mode, user_id):
    return f"{mode}_run_{user_id}.json"

def _load_run(mode, user_id):
    return _load_json(_run_key(mode, user_id), {})

def _save_run(mode, user_id, run):
    _save_json(_run_key(mode, user_id), run)

def _finish_run(mode, user_id):
    try:
        os.remove(os.path.join(DATA_DIR, _run_key(mode, user_id)))
    except Exception:
        pass

# ---------- Grading & analytics ----------
def _grade(run):
    answers = run.get("answers", {})
    qset = run.get("qset", [])
    total = len(qset)
    correct = 0
    details = {}
    domain_stats = {}
    for q in qset:
        qid = q["id"]
        user_key = answers.get(qid)
        is_ok = (q.get("correct_key") and user_key == q["correct_key"])
        if is_ok:
            correct += 1
        dname = q.get("domain") or "Unspecified"
        ds = domain_stats.setdefault(dname, {"correct": 0, "total": 0})
        ds["total"] += 1
        if is_ok:
            ds["correct"] += 1
        details[qid] = {
            "user_key": user_key,
            "correct_key": q.get("correct_key"),
            "is_correct": bool(is_ok),
            "domain": dname
        }
    return correct, total, details, domain_stats

def _record_attempt(user_id, mode, run, results):
    try:
        attempts = _load_json("attempts.json", [])
        correct, total, _details, domain_stats = results
        attempts.append({
            "id": str(uuid.uuid4()),
            "ts": datetime.utcnow().isoformat() + "Z",
            "user_id": user_id,
            "mode": mode,
            "count": total,
            "correct": correct,
            "score_pct": _percent(correct, total),
            "domains": domain_stats
        })
        _save_json("attempts.json", attempts)
    except Exception as e:
        logger.warning("record_attempt failed: %s", e)

# ---------- Shared rendering ----------
def _render_picker_page(title, route, counts, include_domain=True):
    # Domain buttons
    domain_buttons = domain_buttons_html(selected_key="random", field_name="domain") if include_domain else ""

    count_buttons = []
    for c in counts:
        count_buttons.append(f"""
          <button type="submit" name="count" value="{c}" class="btn btn-outline-primary">{c}</button>
        """)
    buttons_html = "".join(count_buttons)

    csrf_val = csrf_token()
    content = f"""
    <div class="container">
      <div class="row justify-content-center"><div class="col-lg-8 col-xl-7">
        <div class="card">
          <div class="card-header bg-warning text-dark">
            <h3 class="mb-0"><i class="bi bi-ui-checks-grid me-2"></i>{html.escape(title)}</h3>
          </div>
          <div class="card-body">
            <form method="POST" class="mb-3">
              <input type="hidden" name="csrf_token" value="{csrf_val}"/>
              {"<label class='form-label fw-semibold'>Domain</label>" if include_domain else ""}
              {domain_buttons}
              <div class="mt-3 mb-2 fw-semibold">How many questions?</div>
              <div class="d-flex flex-wrap gap-2">
                {buttons_html}
              </div>
            </form>
            <div class="text-muted small">Tip: Choose a domain to focus, or keep Random.</div>
          </div>
        </div>
      </div></div>
    </div>

    <script>
      (function(){{
        var container = document.currentScript.closest('.card').querySelector('.card-body');
        var hidden = container.querySelector('#domain_val');
        container.querySelectorAll('.domain-btn').forEach(function(btn){{
          btn.addEventListener('click', function(){{
            container.querySelectorAll('.domain-btn').forEach(function(b){{ b.classList.remove('active'); }});
            btn.classList.add('active');
            if (hidden) hidden.value = btn.getAttribute('data-value');
          }});
        }});
      }})();
    </script>
    """
    return base_layout(title, content)

def _render_question_card(title, route, run, index, error_msg=""):
    qset = run.get("qset", []) or []
    total = len(qset)

    if total == 0:
        msg = f"""
        <div class="container">
          <div class="row justify-content-center"><div class="col-lg-8">
            <div class="card">
              <div class="card-header bg-warning text-dark">
                <h3 class="mb-0"><i class="bi bi-ui-checks-grid me-2"></i>{html.escape(title)}</h3>
              </div>
              <div class="card-body">
                <div class="alert alert-info">
                  No questions are available yet. Please add your bank files in <code>data/bank</code> or <code>questions.json</code>, then try again.
                </div>
                <a href="/" class="btn btn-outline-secondary"><i class="bi bi-house me-1"></i>Home</a>
              </div>
            </div>
          </div></div>
        </div>
        """
        return base_layout(title, msg)

    i = max(0, min(index, total - 1))
    q = qset[i]
    qnum = i + 1
    prev_disabled = "disabled" if i == 0 else ""
    next_label = "Finish" if i == total - 1 else "Next"
    chosen = (run.get("answers", {}) or {}).get(q["id"])

    radios_html = []
    for c in q["choices"]:
        checked = "checked" if chosen == c["key"] else ""
        radios_html.append(
            f"""
            <div class="form-check mb-2">
              <input class="form-check-input" type="radio" name="choice" id="c_{q['id']}_{c['key']}" value="{html.escape(c['key'])}" {checked}>
              <label class="form-check-label" for="c_{q['id']}_{c['key']}"><span class="fw-semibold">{html.escape(c['key'])}.</span> {html.escape(c['text'])}</label>
            </div>
            """
        )
    choices_html = "".join(radios_html)

    csrf_val = csrf_token()
    content = f"""
    <div class="container">
      <div class="row justify-content-center"><div class="col-lg-10 col-xl-8">
        <div class="card">
          <div class="card-header bg-warning text-dark">
            <div class="d-flex justify-content-between align-items-center">
              <h3 class="mb-0"><i class="bi bi-ui-checks-grid me-2"></i>{html.escape(title)}</h3>
              <div class="small text-muted">Question {qnum} of {total}</div>
            </div>
          </div>
          <div class="card-body">
            {"<div class='alert alert-danger'>" + html.escape(error_msg) + "</div>" if error_msg else ""}

            <div class="mb-3">
              <div class="fw-semibold mb-1">Question</div>
              <div>{html.escape(q['text'])}</div>
              {"<div class='text-muted small mt-1'>Domain: " + html.escape(str(q.get('domain') or 'Unspecified')) + "</div>"}
            </div>

            <form method="POST" class="mt-3">
              <input type="hidden" name="csrf_token" value="{csrf_val}"/>
              <input type="hidden" name="index" value="{i}"/>
              <div class="mb-3">
                <div class="fw-semibold mb-2">Select one:</div>
                {choices_html}
              </div>
              <div class="d-flex gap-2">
                <button name="nav" value="prev" class="btn btn-outline-secondary" {prev_disabled}>
                  <i class="bi bi-arrow-left me-1"></i>Prev
                </button>
                <button name="nav" value="next" class="btn btn-primary">
                  {next_label} <i class="bi bi-arrow-right ms-1"></i>
                </button>
              </div>
            </form>

            <div class="mt-3">
              <a href="{route}?reset=1" class="btn btn-outline-danger"><i class="bi bi-arrow-counterclockwise me-1"></i>Reset</a>
              <a href="/" class="btn btn-outline-secondary ms-2"><i class="bi bi-house me-1"></i>Home</a>
            </div>
          </div>
        </div>
      </div></div>
    </div>
    """
    return base_layout(title, content)

def _render_results_card(title, route, run, results):
    correct, total, details, domain_stats = results
    pct = _percent(correct, total)

    qrows = []
    for q in run.get("qset", []):
        qid = q["id"]
        d = details.get(qid, {})
        is_ok = d.get("is_correct")
        badge = "<span class='badge bg-success'>Correct</span>" if is_ok else "<span class='badge bg-danger'>Wrong</span>"
        user_k = d.get("user_key") or "—"
        corr_k = d.get("correct_key") or "—"
        qrows.append(f"""
          <tr>
            <td class="text-nowrap">{html.escape(d.get('domain','Unspecified'))}</td>
            <td>{html.escape(q['text'])}</td>
            <td class="text-center">{html.escape(user_k)}</td>
            <td class="text-center">{html.escape(corr_k)}</td>
            <td class="text-center">{badge}</td>
          </tr>
        """)
    qtable = "".join(qrows) or "<tr><td colspan='5' class='text-center text-muted'>No items.</td></tr>"

    drows = []
    for dname, stats in sorted(domain_stats.items(), key=lambda x: x[0]):
        c = stats["correct"]; t = stats["total"]
        drows.append(f"""
          <tr>
            <td>{html.escape(str(dname))}</td>
            <td class="text-center">{c}/{t}</td>
            <td class="text-center">{_percent(c,t)}%</td>
          </tr>
        """)
    dtable = "".join(drows) or "<tr><td colspan='3' class='text-center text-muted'>No domain data.</td></tr>"

    content = f"""
    <div class="container">
      <div class="row justify-content-center"><div class="col-xl-10">
        <div class="card">
          <div class="card-header bg-info text-white">
            <h3 class="mb-0"><i class="bi bi-graph-up-arrow me-2"></i>{html.escape(title)} — Results</h3>
          </div>
          <div class="card-body">
            <div class="row g-3">
              <div class="col-md-4">
                <div class="p-3 border rounded-3">
                  <div class="fw-semibold">Score</div>
                  <div class="display-6">{correct}/{total}</div>
                  <div class="text-muted">{pct}%</div>
                </div>
              </div>
              <div class="col-md-8">
                <div class="p-3 border rounded-3">
                  <div class="fw-semibold mb-2">By Domain</div>
                  <div class="table-responsive">
                    <table class="table table-sm align-middle">
                      <thead><tr><th>Domain</th><th class="text-center">Correct</th><th class="text-center">%</th></tr></thead>
                      <tbody>{dtable}</tbody>
                    </table>
                  </div>
                </div>
              </div>
            </div>

            <div class="mt-4">
              <div class="fw-semibold mb-2">Question Review</div>
              <div class="table-responsive">
                <table class="table table-sm align-middle">
                  <thead>
                    <tr>
                      <th>Domain</th>
                      <th>Question</th>
                      <th class="text-center">Your</th>
                      <th class="text-center">Correct</th>
                      <th class="text-center">Result</th>
                    </tr>
                  </thead>
                  <tbody>{qtable}</tbody>
                </table>
              </div>
            </div>

            <div class="mt-3 d-flex gap-2">
              <a href="{route}?new=1" class="btn btn-primary"><i class="bi bi-arrow-repeat me-1"></i>New {html.escape(title)}</a>
              <a href="/" class="btn btn-outline-secondary"><i class="bi bi-house me-1"></i>Home</a>
            </div>
          </div>
        </div>
      </div></div>
    </div>
    """
    return base_layout(f"{title} Results", content)

# ---------- QUIZ ----------
@app.route("/quiz", methods=["GET", "POST"])
@login_required
def quiz_page():
    user_id = _user_id()
    user = _find_user(session.get("email",""))

    # Handle resets / new run
    if request.method == "GET":
        if request.args.get("reset") == "1":
            _finish_run("quiz", user_id)
            return redirect(url_for("quiz_page"))
        if request.args.get("new") == "1":
            _finish_run("quiz", user_id)

    run = _load_run("quiz", user_id)

    # If no active run: show picker or start from POST
    if not run:
        if request.method == "POST":
            if not _csrf_ok():
                abort(403)
            # plan/usage gate (one quiz per attempt)
            ok_limit, msg_limit = check_usage_limit(user, "quizzes")
            if not ok_limit:
                # Friendly soft-block
                content = f"""
                <div class="container">
                  <div class="row justify-content-center"><div class="col-lg-8">
                    <div class="card">
                      <div class="card-header bg-warning text-dark"><h3 class="mb-0"><i class="bi bi-ui-checks-grid me-2"></i>Quiz</h3></div>
                      <div class="card-body">
                        <div class="alert alert-warning">{html.escape(msg_limit)}</div>
                        <a class="btn btn-primary" href="/billing"><i class="bi bi-credit-card me-1"></i>Upgrade Plan</a>
                        <a class="btn btn-outline-secondary ms-2" href="/"><i class="bi bi-house me-1"></i>Home</a>
                      </div>
                    </div>
                  </div></div>
                </div>
                """
                return base_layout("Quiz", content)

            try:
                count = int(request.form.get("count") or 10)
            except Exception:
                count = 10
            if count not in (5, 10, 15, 20):
                count = 10
            domain = request.form.get("domain") or "random"
        else:
            # show picker
            return _render_picker_page("Quiz", "/quiz", counts=[5,10,15,20], include_domain=True)

        qset = _pick_questions(count, domain=domain)
        if not qset:
            # Safe empty state
            msg = """
            <div class="container">
              <div class="row justify-content-center"><div class="col-lg-8">
                <div class="card">
                  <div class="card-header bg-warning text-dark">
                    <h3 class="mb-0"><i class="bi bi-ui-checks-grid me-2"></i>Quiz</h3>
                  </div>
                  <div class="card-body">
                    <div class="alert alert-info">
                      No questions available to build a quiz. Please add items to <code>data/bank</code> or <code>questions.json</code>, and try again.
                    </div>
                    <a href="/" class="btn btn-outline-secondary"><i class="bi bi-house me-1"></i>Home</a>
                  </div>
                </div>
              </div></div>
            </div>
            """
            return base_layout("Quiz", msg)

        run = {
            "mode": "quiz",
            "created": datetime.utcnow().isoformat() + "Z",
            "user_id": user_id,
            "qset": qset,
            "answers": {},
            "index": 0,
            "finished": False
        }
        _save_run("quiz", user_id, run)

    # Progress existing run
    error_msg = ""
    if request.method == "POST" and run:
        if not _csrf_ok():
            abort(403)
        qset = run.get("qset") or []
        if not qset:
            _finish_run("quiz", user_id)
            return redirect(url_for("quiz_page"))

        try:
            idx = int(request.form.get("index") or run.get("index", 0))
        except Exception:
            idx = run.get("index", 0)
        idx = max(0, min(idx, len(qset) - 1))

        choice = (request.form.get("choice") or "").strip()
        nav = (request.form.get("nav") or "next").strip()
        qid = qset[idx]["id"]

        if nav == "prev":
            if choice:
                run["answers"][qid] = choice
            run["index"] = max(0, idx - 1)
        else:
            if not choice and qid not in run["answers"]:
                error_msg = "Please select an answer to continue."
            else:
                if choice:
                    run["answers"][qid] = choice
                if idx == len(qset) - 1:
                    run["finished"] = True
                else:
                    run["index"] = idx + 1

        _save_run("quiz", user_id, run)
        _log_event(user_id, "quiz.answer", {"idx": idx, "chosen": choice or run["answers"].get(qid)})

    if run.get("finished"):
        results = _grade(run)
        _record_attempt(user_id, "quiz", run, results)
        # usage increments after completion (1 quiz + N questions)
        email = session.get("email","")
        if email:
            try:
                increment_usage(email, "quizzes", 1)
                qcount = len(run.get("qset") or [])
                if qcount:
                    increment_usage(email, "questions", qcount)
            except Exception as _e:
                logger.warning("usage increment failed: %s", _e)
        _finish_run("quiz", user_id)
        return _render_results_card("Quiz", "/quiz", run, results)

    curr_idx = int(run.get("index", 0))
    return _render_question_card("Quiz", "/quiz", run, curr_idx, error_msg)

# ---------- MOCK EXAM ----------
@app.route("/mock-exam", methods=["GET", "POST"])
@app.route("/mock", methods=["GET", "POST"])
@login_required
def mock_exam_page():
    user_id = _user_id()
    user = _find_user(session.get("email",""))

    if request.method == "GET":
        if request.args.get("reset") == "1":
            _finish_run("mock", user_id)
            return redirect(url_for("mock_exam_page"))
        if request.args.get("new") == "1":
            _finish_run("mock", user_id)

    run = _load_run("mock", user_id)

    if not run:
        if request.method == "POST":
            if not _csrf_ok():
                abort(403)
            # usage/plan gate
            ok_limit, msg_limit = check_usage_limit(user, "quizzes")
            if not ok_limit:
                content = f"""
                <div class="container">
                  <div class="row justify-content-center"><div class="col-lg-8">
                    <div class="card">
                      <div class="card-header bg-warning text-dark"><h3 class="mb-0"><i class="bi bi-clipboard-check me-2"></i>Mock Exam</h3></div>
                      <div class="card-body">
                        <div class="alert alert-warning">{html.escape(msg_limit)}</div>
                        <a class="btn btn-primary" href="/billing"><i class="bi bi-credit-card me-1"></i>Upgrade Plan</a>
                        <a class="btn btn-outline-secondary ms-2" href="/"><i class="bi bi-house me-1"></i>Home</a>
                      </div>
                    </div>
                  </div></div>
                </div>
                """
                return base_layout("Mock Exam", content)

            try:
                count = int(request.form.get("count") or 50)
            except Exception:
                count = 50
            if count not in (25, 50, 75, 100):
                count = 50
            domain = request.form.get("domain") or "random"
        else:
            return _render_picker_page("Mock Exam", "/mock-exam", counts=[25,50,75,100], include_domain=True)

        qset = _pick_questions(count, domain=domain)
        if not qset:
            msg = """
            <div class="container">
              <div class="row justify-content-center"><div class="col-lg-8">
                <div class="card">
                  <div class="card-header bg-warning text-dark">
                    <h3 class="mb-0"><i class="bi bi-clipboard-check me-2"></i>Mock Exam</h3>
                  </div>
                  <div class="card-body">
                    <div class="alert alert-info">
                      No questions available to build a mock exam. Please add items to <code>data/bank</code> or <code>questions.json</code>, then try again.
                    </div>
                    <a href="/" class="btn btn-outline-secondary"><i class="bi bi-house me-1"></i>Home</a>
                  </div>
                </div>
              </div></div>
            </div>
            """
            return base_layout("Mock Exam", msg)

        run = {
            "mode": "mock",
            "created": datetime.utcnow().isoformat() + "Z",
            "user_id": user_id,
            "qset": qset,
            "answers": {},
            "index": 0,
            "finished": False
        }
        _save_run("mock", user_id, run)

    error_msg = ""
    if request.method == "POST" and run:
        if not _csrf_ok():
            abort(403)

        qset = run.get("qset") or []
        if not qset:
            _finish_run("mock", user_id)
            return redirect(url_for("mock_exam_page"))

        try:
            idx = int(request.form.get("index") or run.get("index", 0))
        except Exception:
            idx = run.get("index", 0)
        idx = max(0, min(idx, len(qset) - 1))

        choice = (request.form.get("choice") or "").strip()
        nav = (request.form.get("nav") or "next").strip()
        qid = qset[idx]["id"]

        if nav == "prev":
            if choice:
                run["answers"][qid] = choice
            run["index"] = max(0, idx - 1)
        else:
            if not choice and qid not in run["answers"]:
                error_msg = "Please select an answer to continue."
            else:
                if choice:
                    run["answers"][qid] = choice
                if idx == len(qset) - 1:
                    run["finished"] = True
                else:
                    run["index"] = idx + 1

        _save_run("mock", user_id, run)
        _log_event(user_id, "mock.answer", {"idx": idx, "chosen": choice or run["answers"].get(qid)})

    if run.get("finished"):
        results = _grade(run)
        _record_attempt(user_id, "mock", run, results)
        # usage increments after completion
        email = session.get("email","")
        if email:
            try:
                increment_usage(email, "quizzes", 1)
                qcount = len(run.get("qset") or [])
                if qcount:
                    increment_usage(email, "questions", qcount)
            except Exception as _e:
                logger.warning("usage increment failed: %s", _e)
        _finish_run("mock", user_id)
        return _render_results_card("Mock Exam", "/mock-exam", run, results)

    curr_idx = int(run.get("index", 0))
    return _render_question_card("Mock Exam", "/mock-exam", run, curr_idx, error_msg)
# =========================
# SECTION 5/8: Flashcards, Progress, Billing/Stripe (+ debug) + Admin ingest/check-bank
# =========================

# ---------- FLASHCARDS ----------
def _normalize_flashcard(item):
    """
    Accepts shapes like:
      {"front": "...", "back":"...", "domain":"...", "sources":[{"title": "...", "url":"..."}]}
    or {"q":"...", "a":"..."} etc.
    Returns normalized:
      {"id": "...", "front":"...", "back":"...", "domain":"...", "sources":[...]}
    """
    if not item:
        return None
    front = (item.get("front") or item.get("q") or item.get("term") or "").strip()
    back  = (item.get("back") or item.get("a") or item.get("definition") or "").strip()
    if not front or not back:
        return None
    domain = (item.get("domain") or item.get("category") or "Unspecified").strip()
    sources = item.get("sources") or []
    cleaned_sources = []
    for s in sources[:3]:
        t = (s.get("title") or "").strip()
        u = (s.get("url") or "").strip()
        if t and u:
            cleaned_sources.append({"title": t, "url": u})
    return {
        "id": item.get("id") or str(uuid.uuid4()),
        "front": front, "back": back, "domain": domain,
        "sources": cleaned_sources
    }

def _all_flashcards():
    """
    Merge legacy FLASHCARDS + optional bank file data/bank/cpp_flashcards_v1.json
    into normalized flashcards; de-dup by (front, back, domain).
    """
    out, seen = [], set()
    for fc in (FLASHCARDS or []):
        n = _normalize_flashcard(fc)
        if not n:
            continue
        key = (n["front"], n["back"], n["domain"])
        if key in seen:
            continue
        seen.add(key)
        out.append(n)

    bank = _load_json("bank/cpp_flashcards_v1.json", [])
    for fc in (bank or []):
        n = _normalize_flashcard(fc)
        if not n:
            continue
        key = (n["front"], n["back"], n["domain"])
        if key in seen:
            continue
        seen.add(key)
        out.append(n)
    return out

def _filter_flashcards_domain(cards, domain_key: str | None):
    if not domain_key or domain_key == "random":
        return cards[:]
    dk = str(domain_key).strip().lower()
    return [c for c in cards if str(c.get("domain","")).strip().lower() == dk]

@app.route("/flashcards", methods=["GET", "POST"])
@login_required
def flashcards_page():
    # Gate access by plan
    u = _find_user(session.get("email",""))
    ok_limit, msg_limit = check_usage_limit(u, "flashcards")
    if not ok_limit:
        content = f"""
        <div class="container">
          <div class="row justify-content-center"><div class="col-lg-8">
            <div class="card">
              <div class="card-header bg-success text-white"><h3 class="mb-0"><i class="bi bi-layers me-2"></i>Flashcards</h3></div>
              <div class="card-body">
                <div class="alert alert-warning">{html.escape(msg_limit)}</div>
                <a class="btn btn-primary" href="/billing"><i class="bi bi-credit-card me-1"></i>Upgrade Plan</a>
                <a class="btn btn-outline-secondary ms-2" href="/"><i class="bi bi-house me-1"></i>Home</a>
              </div>
            </div>
          </div></div>
        </div>
        """
        return base_layout("Flashcards", content)

    # GET -> picker (domain buttons + count buttons)
    if request.method == "GET":
        csrf_val = csrf_token()
        domain_buttons = domain_buttons_html(selected_key="random", field_name="domain")

        content = f"""
        <div class="container">
          <div class="row justify-content-center"><div class="col-lg-8 col-xl-7">
            <div class="card">
              <div class="card-header bg-success text-white">
                <h3 class="mb-0"><i class="bi bi-layers me-2"></i>Flashcards</h3>
              </div>
              <div class="card-body">
                <form method="POST" class="mb-3">
                  <input type="hidden" name="csrf_token" value="{csrf_val}"/>
                  <label class="form-label fw-semibold">Domain</label>
                  {domain_buttons}
                  <div class="mt-3 mb-2 fw-semibold">How many cards?</div>
                  <div class="d-flex flex-wrap gap-2">
                    <button class="btn btn-outline-success" name="count" value="10">10</button>
                    <button class="btn btn-outline-success" name="count" value="20">20</button>
                    <button class="btn btn-outline-success" name="count" value="30">30</button>
                  </div>
                </form>
                <div class="text-muted small">Tip: Choose a domain to focus, or Random to mix all.</div>
              </div>
            </div>
          </div></div>
        </div>

        <script>
          (function(){{
            var card = document.currentScript.closest('.card');
            if (!card) return;
            var container = card.querySelector('.card-body');
            var hidden = container.querySelector('#domain_val');
            container.querySelectorAll('.domain-btn').forEach(function(btn){{
              btn.addEventListener('click', function(){{
                container.querySelectorAll('.domain-btn').forEach(function(b){{ b.classList.remove('active'); }});
                btn.classList.add('active');
                if (hidden) hidden.value = btn.getAttribute('data-value');
              }});
            }});
          }})();
        </script>
        """
        return base_layout("Flashcards", content)

    # POST -> render a client-side session (no server state)
    if not _csrf_ok():
        abort(403)

    try:
        count = int(request.form.get("count") or 20)
    except Exception:
        count = 20
    if count not in (10, 20, 30):
        count = 20
    domain = request.form.get("domain") or "random"

    all_cards = _all_flashcards()
    pool = _filter_flashcards_domain(all_cards, domain)
    random.shuffle(pool)
    cards = pool[:max(0, min(count, len(pool)))]

    def _card_div(c):
        src_bits = ""
        if c.get("sources"):
            links = []
            for s in c["sources"]:
                title = html.escape(s["title"])
                url = html.escape(s["url"])
                links.append(f'<li><a href="{url}" target="_blank" rel="noopener">{title}</a></li>')
            src_bits = f'<div class="small mt-2"><span class="text-muted">Sources:</span><ul class="small mb-0 ps-3">{"".join(links)}</ul></div>'
        return f"""
        <div class="fc-card" data-id="{html.escape(c['id'])}" data-domain="{html.escape(c.get('domain','Unspecified'))}">
          <div class="front">{html.escape(c['front'])}</div>
          <div class="back d-none">{html.escape(c['back'])}{src_bits}</div>
        </div>
        """

    cards_html = "".join(_card_div(c) for c in cards) or "<div class='text-muted'>No flashcards found. Add content in <code>data/bank/cpp_flashcards_v1.json</code>.</div>"
    content = f"""
    <div class="container">
      <div class="row justify-content-center"><div class="col-lg-8 col-xl-7">
        <div class="card">
          <div class="card-header bg-success text-white d-flex justify-content-between align-items-center">
            <h3 class="mb-0"><i class="bi bi-layers me-2"></i>Flashcards</h3>
            <a href="/flashcards" class="btn btn-outline-light btn-sm">New Session</a>
          </div>
          <div class="card-body">
            <div class="mb-2 small text-muted">Domain: <strong>{html.escape(DOMAINS.get(domain, 'Mixed')) if domain!='random' else 'Random (all)'}</strong> • Cards: {len(cards)}</div>
            <div id="fc-container">{cards_html}</div>

            <div class="d-flex align-items-center gap-2 mt-3">
              <button class="btn btn-outline-secondary" id="prevBtn"><i class="bi bi-arrow-left"></i></button>
              <button class="btn btn-primary" id="flipBtn"><i class="bi bi-arrow-repeat me-1"></i>Flip</button>
              <button class="btn btn-outline-secondary" id="nextBtn"><i class="bi bi-arrow-right"></i></button>
              <div class="ms-auto small"><span id="idx">0</span>/<span id="total">{len(cards)}</span></div>
            </div>
          </div>
        </div>
      </div></div>
    </div>

    <script>
    (function() {{
      var cards = Array.prototype.slice.call(document.querySelectorAll('#fc-container .fc-card'));
      var i = 0, total = cards.length;
      function show(idx) {{
        cards.forEach(function(el, j) {{
          el.style.display = (j===idx) ? '' : 'none';
          if (j===idx) {{
            el.querySelector('.front').classList.remove('d-none');
            el.querySelector('.back').classList.add('d-none');
          }}
        }});
        var idxEl = document.getElementById('idx');
        if (idxEl) idxEl.textContent = (total ? idx+1 : 0);
      }}
      function flip() {{
        if (!total) return;
        var cur = cards[i];
        var front = cur.querySelector('.front');
        var back  = cur.querySelector('.back');
        front.classList.toggle('d-none');
        back.classList.toggle('d-none');
      }}
      function next() {{ if (!total) return; i = Math.min(total-1, i+1); show(i); }}
      function prev() {{ if (!total) return; i = Math.max(0, i-1); show(i); }}
      var f = document.getElementById('flipBtn');
      var n = document.getElementById('nextBtn');
      var p = document.getElementById('prevBtn');
      if (f) f.addEventListener('click', flip);
      if (n) n.addEventListener('click', next);
      if (p) p.addEventListener('click', prev);
      show(i);
    }})();
    </script>
    """
    # Log and increment usage (count = number of cards shown)
    _log_event(_user_id(), "flashcards.start", {"count": len(cards), "domain": domain})
    try:
        increment_usage(session.get("email",""), "flashcards", max(1, len(cards)))
    except Exception as _e:
        logger.warning("flashcards usage increment failed: %s", _e)
    return base_layout("Flashcards", content)


# ---------- PROGRESS ----------
@app.get("/progress")
@login_required
def progress_page():
    uid = _user_id()
    attempts = [a for a in _load_json("attempts.json", []) if a.get("user_id") == uid]
    attempts.sort(key=lambda x: x.get("ts",""), reverse=True)

    total_q  = sum(a.get("count", 0) for a in attempts)
    total_ok = sum(a.get("correct", 0) for a in attempts)
    best = max([a.get("score_pct", 0.0) for a in attempts], default=0.0)
    avg  = round(sum([a.get("score_pct", 0.0) for a in attempts]) / len(attempts), 1) if attempts else 0.0

    dom = {}
    for a in attempts:
        for dname, stats in (a.get("domains") or {}).items():
            dd = dom.setdefault(dname, {"correct": 0, "total": 0})
            dd["correct"] += int(stats.get("correct", 0))
            dd["total"]   += int(stats.get("total", 0))

    def pct(c, t): return f"{(100.0*c/t):.1f}%" if t else "0.0%"

    rows = []
    for a in attempts[:100]:
        rows.append(f"""
          <tr>
            <td class="text-nowrap">{html.escape(a.get('ts',''))}</td>
            <td>{html.escape(a.get('mode',''))}</td>
            <td class="text-end">{a.get('correct',0)}/{a.get('count',0)}</td>
            <td class="text-end">{a.get('score_pct',0)}%</td>
          </tr>
        """)
    attempts_html = "".join(rows) or "<tr><td colspan='4' class='text-center text-muted'>No attempts yet.</td></tr>"

    drows = []
    for dname in sorted(dom.keys()):
        c = dom[dname]["correct"]; t = dom[dname]["total"]
        drows.append(f"""
          <tr>
            <td>{html.escape(dname)}</td>
            <td class="text-end">{c}/{t}</td>
            <td class="text-end">{pct(c,t)}</td>
          </tr>
        """)
    domain_html = "".join(drows) or "<tr><td colspan='3' class='text-center text-muted'>No data.</td></tr>"

    content = f"""
    <div class="container">
      <div class="row justify-content-center"><div class="col-xl-10">
        <div class="card">
          <div class="card-header bg-info text-white"><h3 class="mb-0"><i class="bi bi-graph-up-arrow me-2"></i>Progress</h3></div>
          <div class="card-body">
            <div class="row g-3 mb-3">
              <div class="col-md-3"><div class="p-3 border rounded-3">
                <div class="small text-muted">Attempts</div><div class="h4 mb-0">{len(attempts)}</div>
              </div></div>
              <div class="col-md-3"><div class="p-3 border rounded-3">
                <div class="small text-muted">Questions</div><div class="h4 mb-0">{total_q}</div>
              </div></div>
              <div class="col-md-3"><div class="p-3 border rounded-3">
                <div class="small text-muted">Average</div><div class="h4 mb-0">{avg}%</div>
              </div></div>
              <div class="col-md-3"><div class="p-3 border rounded-3">
                <div class="small text-muted">Best</div><div class="h4 mb-0">{best:.1f}%</div>
              </div></div>
            </div>

            <div class="row g-3">
              <div class="col-lg-6">
                <div class="p-3 border rounded-3">
                  <div class="fw-semibold mb-2">By Domain</div>
                  <div class="table-responsive">
                    <table class="table table-sm align-middle">
                      <thead><tr><th>Domain</th><th class="text-end">Correct</th><th class="text-end">%</th></tr></thead>
                      <tbody>{domain_html}</tbody>
                    </table>
                  </div>
                </div>
              </div>
              <div class="col-lg-6">
                <div class="p-3 border rounded-3">
                  <div class="fw-semibold mb-2">Recent Attempts</div>
                  <div class="table-responsive">
                    <table class="table table-sm align-middle">
                      <thead><tr><th>When</th><th>Mode</th><th class="text-end">Score</th><th class="text-end">%</th></tr></thead>
                      <tbody>{attempts_html}</tbody>
                    </table>
                  </div>
                </div>
              </div>
            </div>

            <a href="/" class="btn btn-outline-secondary mt-3"><i class="bi bi-house me-1"></i>Home</a>
          </div>
        </div>
      </div></div>
    </div>
    """
    return base_layout("Progress", content)


# ---------- USAGE DASHBOARD (nav link helper) ----------
@app.get("/usage")
@login_required
def usage_dashboard():
    email = session.get("email","")
    u = _find_user(email) or {}
    usage = (u.get("usage") or {}).get("monthly", {})
    rows = []
    for month, items in sorted(usage.items()):
        quizzes = int(items.get("quizzes", 0))
        questions = int(items.get("questions", 0))
        tutor = int(items.get("tutor_msgs", 0))
        flashcards = int(items.get("flashcards", 0))
        rows.append(f"""
          <tr>
            <td>{html.escape(month)}</td>
            <td class="text-end">{quizzes}</td>
            <td class="text-end">{questions}</td>
            <td class="text-end">{tutor}</td>
            <td class="text-end">{flashcards}</td>
          </tr>
        """)
    tbl = "".join(rows) or "<tr><td colspan='5' class='text-center text-muted'>No usage yet.</td></tr>"
    body = f"""
    <div class="container"><div class="row justify-content-center"><div class="col-lg-8">
      <div class="card">
        <div class="card-header bg-primary text-white"><h3 class="mb-0"><i class="bi bi-speedometer2 me-2"></i>Usage Dashboard</h3></div>
        <div class="card-body">
          <div class="table-responsive">
            <table class="table table-sm align-middle">
              <thead><tr><th>Month</th><th class="text-end">Quizzes</th><th class="text-end">Questions</th><th class="text-end">Tutor Msgs</th><th class="text-end">Flashcards</th></tr></thead>
              <tbody>{tbl}</tbody>
            </table>
          </div>
          <a class="btn btn-outline-secondary" href="/"><i class="bi bi-house me-1"></i>Home</a>
        </div>
      </div>
    </div></div></div>
    """
    return base_layout("Usage", body)


# ---------- BILLING (Stripe) ----------
def create_stripe_checkout_session(user_email: str, plan: str = "monthly", discount_code: str | None = None):
    """
    Creates a Stripe Checkout Session for either a subscription (monthly) or a one-time payment (sixmonth).
    If a discount_code is provided, we look up an active Promotion Code in Stripe and apply it.
    We also enable allow_promotion_codes=True so users can enter codes on the Stripe page if needed.
    """
    try:
        # Try to resolve a Stripe Promotion Code (promo_...) from the human-readable code
        discounts_param = None
        if discount_code:
            try:
                pc = stripe.PromotionCode.list(code=discount_code.strip(), active=True, limit=1)
                if pc and pc.get("data"):
                    promo_id = pc["data"][0]["id"]  # e.g., 'promo_...'
                    discounts_param = [{"promotion_code": promo_id}]
                else:
                    logger.warning("No active Promotion Code found for %r", discount_code)
            except Exception as e:
                logger.warning("Promotion code lookup failed for %r: %s", discount_code, e)

        root = request.url_root.rstrip('/')

        if plan == "monthly":
            if not STRIPE_MONTHLY_PRICE_ID:
                logger.error("Monthly price ID not configured")
                return None
            sess = stripe.checkout.Session.create(
                payment_method_types=["card"],
                mode="subscription",
                line_items=[{"price": STRIPE_MONTHLY_PRICE_ID, "quantity": 1}],
                customer_email=user_email,
                success_url=f"{root}/billing/success?session_id={{CHECKOUT_SESSION_ID}}&plan=monthly",
                cancel_url=f"{root}/billing",
                allow_promotion_codes=True,
                discounts=discounts_param,  # may be None
                metadata={
                    "user_email": user_email,
                    "plan": "monthly",
                    "discount_code": (discount_code or "")
                },
            )
            return sess.url

        elif plan == "sixmonth":
            if not STRIPE_SIXMONTH_PRICE_ID:
                logger.error("Six-month price ID not configured")
                return None
            sess = stripe.checkout.Session.create(
                payment_method_types=["card"],
                mode="payment",
                line_items=[{"price": STRIPE_SIXMONTH_PRICE_ID, "quantity": 1}],
                customer_email=user_email,
                success_url=f"{root}/billing/success?session_id={{CHECKOUT_SESSION_ID}}&plan=sixmonth",
                cancel_url=f"{root}/billing",
                allow_promotion_codes=True,
                discounts=discounts_param,  # may be None
                metadata={
                    "user_email": user_email,
                    "plan": "sixmonth",
                    "duration_days": 180,
                    "discount_code": (discount_code or "")
                },
            )
            return sess.url

        else:
            logger.warning("Unknown plan %r", plan)
            return None

    except Exception as e:
        logger.error("Stripe session creation failed: %s", e)
        return None

@app.get("/billing")
@login_required
def billing_page():
    user = _find_user(session.get("email",""))
    sub = user.get("subscription","inactive") if user else "inactive"
    names = {"monthly":"Monthly Plan","sixmonth":"6-Month Plan","inactive":"Free Plan"}

    if sub == 'inactive':
        # Discount code UI lives *only* on Billing page; we append it to checkout links via JS
        plans_html = """
          <div class="row g-3">
            <div class="col-md-6">
              <div class="card border-primary">
                <div class="card-header bg-primary text-white text-center"><h5 class="mb-0">Monthly Plan</h5></div>
                <div class="card-body text-center">
                  <h3 class="text-primary">$39.99/month</h3><p class="text-muted">Unlimited access</p>
                  <a href="/billing/checkout?plan=monthly" class="btn btn-primary upgrade-btn" data-plan="monthly">Upgrade</a>
                </div>
              </div>
            </div>
            <div class="col-md-6">
              <div class="card border-success">
                <div class="card-header bg-success text-white text-center"><h5 class="mb-0">6-Month Plan</h5></div>
                <div class="card-body text-center">
                  <h3 class="text-success">$99.00</h3><p class="text-muted">One-time payment</p>
                  <a href="/billing/checkout?plan=sixmonth" class="btn btn-success upgrade-btn" data-plan="sixmonth">Upgrade</a>
                </div>
              </div>
            </div>
          </div>

          <div class="mt-3">
            <label class="form-label fw-semibold">Discount code (optional)</label>
            <div class="input-group">
              <input type="text" id="discount_code" class="form-control" placeholder="Enter a valid code (if you have one)">
              <button id="apply_code" class="btn btn-outline-secondary" type="button">Apply at Checkout</button>
            </div>
            <div class="form-text">Codes can also be entered on the Stripe checkout page.</div>
          </div>

          <script>
            (function(){{
              function goWithCode(href) {{
                var codeEl = document.getElementById('discount_code');
                var code = codeEl ? codeEl.value.trim() : '';
                if (code) {{
                  var url = new URL(href, window.location.origin);
                  url.searchParams.set('code', code);
                  return url.toString();
                }}
                return href;
              }}
              document.querySelectorAll('.upgrade-btn').forEach(function(btn){{
                btn.addEventListener('click', function(e){{
                  e.preventDefault();
                  window.location.href = goWithCode(btn.getAttribute('href'));
                }});
              }});
              var apply = document.getElementById('apply_code');
              if (apply) {{
                apply.addEventListener('click', function(){{
                  // No-op: user needs to select a plan; this keeps the code field value
                }});
              }}
            }})();
          </script>
        """
    else:
        plans_html = """
          <div class="alert alert-info border-0">
            <i class="bi bi-info-circle me-2"></i>Your subscription is active. Use support to manage changes.
          </div>
        """

    body = f"""
    <div class="container"><div class="row justify-content-center"><div class="col-lg-8">
      <div class="card"><div class="card-header bg-warning text-dark">
        <h3 class="mb-0"><i class="bi bi-credit-card me-2"></i>Billing & Subscription</h3>
      </div>
      <div class="card-body">
        <div class="alert {'alert-success' if sub!='inactive' else 'alert-info'} border-0 mb-4">
          <div class="d-flex align-items-center">
            <i class="bi bi-{'check-circle' if sub!='inactive' else 'info-circle'} fs-4 me-3"></i>
            <div><h6 class="alert-heading mb-1">Current Plan: {names.get(sub,'Unknown')}</h6>
              <p class="mb-0">{'You have unlimited access to all features.' if sub!='inactive' else 'Limited access — upgrade for unlimited features.'}</p>
            </div>
          </div>
        </div>

        {plans_html}
      </div></div>
    </div></div></div>
    """
    return base_layout("Billing", body)

@app.get("/billing/checkout")
@login_required
def billing_checkout():
    plan = request.args.get("plan","monthly")
    user_email = session.get("email","")
    if not user_email:
        return redirect(url_for("login_page"))

    # read promo only from query; no suggestions anywhere else
    discount_code = (request.args.get("code") or "").strip()

    url = create_stripe_checkout_session(user_email, plan=plan, discount_code=discount_code)
    if url:
        return redirect(url)
    return redirect(url_for("billing_page"))

@app.get("/billing/success")
@login_required
def billing_success():
    session_id = request.args.get("session_id")
    plan = request.args.get("plan","monthly")
    if session_id:
        try:
            cs = stripe.checkout.Session.retrieve(session_id, expand=["customer","subscription"])
            meta = cs.get("metadata", {}) if isinstance(cs, dict) else getattr(cs, "metadata", {}) or {}
            email = meta.get("user_email") or session.get("email")
            u = _find_user(email or "")
            if u:
                updates: Dict[str, Any] = {}
                if plan == "monthly":
                    updates["subscription"] = "monthly"
                    cid = (cs.get("customer") if isinstance(cs, dict) else getattr(cs,"customer", None)) or u.get("stripe_customer_id")
                    updates["stripe_customer_id"] = cid
                elif plan == "sixmonth":
                    updates["subscription"] = "sixmonth"
                    expiry = datetime.utcnow() + timedelta(days=int(meta.get("duration_days", 180) or 180))
                    updates["subscription_expires_at"] = expiry.isoformat() + "Z"
                    cid = (cs.get("customer") if isinstance(cs, dict) else getattr(cs,"customer", None)) or u.get("stripe_customer_id")
                    updates["stripe_customer_id"] = cid
                if updates:
                    _update_user(u["id"], updates)
        except Exception as e:
            logger.warning("Could not finalize success update from session: %s", e)

    content = f"""
    <div class="container"><div class="row justify-content-center"><div class="col-md-6">
      <div class="card text-center"><div class="card-body p-5">
        <i class="bi bi-check-circle-fill text-success display-1 mb-4"></i>
        <h2 class="text-success mb-3">Payment Successful!</h2>
        <p class="text-muted mb-4">Your {('Monthly' if plan=='monthly' else '6-Month')} subscription is now active.</p>
        <a href="/" class="btn btn-primary">Start Learning</a>
      </div></div>
    </div></div></div>"""
    return base_layout("Payment Success", content)

# Stripe Webhook — authoritative subscription updates
@app.post("/stripe/webhook")
def stripe_webhook():
    payload = request.data
    sig = request.headers.get("Stripe-Signature", "")
    try:
        event = stripe.Webhook.construct_event(payload=payload, sig_header=sig, secret=STRIPE_WEBHOOK_SECRET)
    except Exception as e:
        logger.error("Stripe webhook signature verification failed: %s", e)
        return "", 400

    if event.get("type") == "checkout.session.completed":
        cs = event["data"]["object"]
        meta = cs.get("metadata", {}) or {}
        email = meta.get("user_email")
        plan  = meta.get("plan", "")
        customer_id = cs.get("customer")

        if email:
            u = _find_user(email)
            if u:
                updates: Dict[str, Any] = {"stripe_customer_id": customer_id}
                if plan == "monthly":
                    updates["subscription"] = "monthly"
                elif plan == "sixmonth":
                    updates["subscription"] = "sixmonth"
                    duration = int(meta.get("duration_days", 180) or 180)
                    expiry = datetime.utcnow() + timedelta(days=duration)
                    updates["subscription_expires_at"] = expiry.isoformat() + "Z"
                _update_user(u["id"], updates)
                logger.info("Updated subscription via webhook: %s -> %s", email, plan)

    return "", 200


# ---------- BILLING DEBUG (admin-only; no secrets) ----------
@app.get("/billing/debug")
@login_required
def billing_debug():
    if not is_admin():
        return redirect(url_for("admin_login_page", next=request.path))

    data = {
        "STRIPE_PUBLISHABLE_KEY_present": bool(STRIPE_PUBLISHABLE_KEY),
        "STRIPE_MONTHLY_PRICE_ID_present": bool(STRIPE_MONTHLY_PRICE_ID),
        "STRIPE_SIXMONTH_PRICE_ID_present": bool(STRIPE_SIXMONTH_PRICE_ID),
        "OPENAI_CHAT_MODEL": OPENAI_CHAT_MODEL,
        "DATA_DIR": DATA_DIR,
    }
    rows = []
    for k, v in data.items():
        val = html.escape(str(v if not isinstance(v, bool) else ("yes" if v else "no")))
        rows.append(f"<tr><td class='fw-semibold'>{html.escape(k)}</td><td>{val}</td></tr>")
    tbl = "".join(rows)

    content = f"""
    <div class="container"><div class="row justify-content-center"><div class="col-lg-7">
      <div class="card">
        <div class="card-header bg-dark text-white"><h3 class="mb-0"><i class="bi bi-bug me-2"></i>Billing/Config Debug</h3></div>
        <div class="card-body">
          <div class="table-responsive">
            <table class="table table-sm align-middle">
              <tbody>{tbl}</tbody>
            </table>
          </div>
          <a href="/billing" class="btn btn-outline-secondary"><i class="bi bi-arrow-left me-1"></i>Back</a>
        </div>
      </div>
    </div></div></div>
    """
    return base_layout("Billing Debug", content)


# ---------- ADMIN LOGIN & PASSWORD RESET ----------
@app.get("/admin/login")
def admin_login_page():
    nxt = request.args.get("next") or "/"
    body = f"""
    <div class="container"><div class="row justify-content-center"><div class="col-md-5">
      <div class="card">
        <div class="card-header bg-secondary text-white"><h3 class="mb-0"><i class="bi bi-shield-lock me-2"></i>Admin Login</h3></div>
        <div class="card-body">
          <form method="POST" action="/admin/login">
            <input type="hidden" name="csrf_token" value="{csrf_token()}"/>
            <input type="hidden" name="next" value="{html.escape(nxt)}"/>
            <div class="mb-3">
              <label class="form-label">Admin Password</label>
              <input type="password" class="form-control" name="pw" required>
            </div>
            <button class="btn btn-primary" type="submit">Enter</button>
          </form>
        </div>
      </div>
    </div></div></div>
    """
    return base_layout("Admin Login", body)

@app.post("/admin/login")
def admin_login_post():
    # If CSRFProtect is active, it will enforce validity.
    # Fallback manual check when CSRF is not enabled.
    if not HAS_CSRF:
        if request.form.get("csrf_token") != csrf_token():
            abort(403)

    nxt = request.form.get("next") or "/"
    pw = (request.form.get("pw") or "").strip()
    if ADMIN_PASSWORD and pw == ADMIN_PASSWORD:
        session["admin_ok"] = True
        return redirect(nxt)
    return redirect(url_for("admin_login_page", next=nxt))

@app.route("/admin/reset-password", methods=["GET","POST"])
@login_required
def admin_reset_password():
    if not is_admin():
        return redirect(url_for("admin_login_page", next=request.path))

    msg = ""
    if request.method == "POST":
        if not HAS_CSRF:
            if request.form.get("csrf_token") != csrf_token():
                abort(403)
        email = (request.form.get("email") or "").strip().lower()
        new_pw = request.form.get("password") or ""
        ok, err = validate_password(new_pw)
        if not email or not ok:
            msg = err or "Please provide a valid email and a password with at least 8 characters."
        else:
            u = _find_user(email)
            if not u:
                msg = "No user found with that email."
            else:
                _update_user(u["id"], {"password_hash": generate_password_hash(new_pw)})
                msg = "Password updated successfully."

    csrf_val = csrf_token()
    body = f"""
    <div class="container"><div class="row justify-content-center"><div class="col-md-6">
      <div class="card">
        <div class="card-header bg-secondary text-white"><h3 class="mb-0"><i class="bi bi-key me-2"></i>Admin: Reset User Password</h3></div>
        <div class="card-body">
          {"<div class='alert alert-info'>" + html.escape(msg) + "</div>" if msg else ""}
          <form method="POST">
            <input type="hidden" name="csrf_token" value="{csrf_val}"/>
            <div class="mb-3">
              <label class="form-label">User Email</label>
              <input type="email" class="form-control" name="email" placeholder="user@example.com" required>
            </div>
            <div class="mb-3">
              <label class="form-label">New Password</label>
              <input type="password" class="form-control" name="password" minlength="8" required>
            </div>
            <button class="btn btn-primary" type="submit">Update Password</button>
            <a class="btn btn-outline-secondary ms-2" href="/"><i class="bi bi-house me-1"></i>Home</a>
          </form>
        </div>
      </div>
    </div></div></div>
    """
    return base_layout("Admin Reset Password", body)


# ---------- ADMIN CONTENT INGESTION (JSON API) ----------
# NOTE: This endpoint expects application/json and is admin-gated. If CSRF is enabled,
# we exempt AFTER definition to avoid 403s for JSON posts.
@app.post("/api/dev/ingest")
@login_required
def api_dev_ingest():
    if not is_admin():
        return jsonify({"ok": False, "error": "admin-required"}), 403

    if not request.is_json:
        return jsonify({"ok": False, "error": "application/json required",
                        "hint": "Use Content-Type: application/json"}), 415

    data = request.get_json(silent=True) or {}
    in_flash = data.get("flashcards") or []
    in_questions = data.get("questions") or []

    # Load current bank & index
    bank_fc = _bank_read_flashcards()
    bank_q  = _bank_read_questions()
    idx = _load_content_index()  # {hash: {...}}

    # Build quick hash sets for existing
    existing_fc_hashes = set()
    for fc in bank_fc:
        h = _item_hash_flashcard(fc.get("front",""), fc.get("back",""),
                                 fc.get("domain","Unspecified"), fc.get("sources") or [])
        existing_fc_hashes.add(h)
        idx.setdefault(h, {"type":"fc",
                           "added": idx.get(h,{}).get("added") or datetime.utcnow().isoformat()+"Z"})

    existing_q_hashes = set()
    for q in bank_q:
        h = _item_hash_question(q.get("question",""), q.get("options") or {},
                                q.get("correct",""), q.get("domain","Unspecified"),
                                q.get("sources") or [])
        existing_q_hashes.add(h)
        idx.setdefault(h, {"type":"q",
                           "added": idx.get(h,{}).get("added") or datetime.utcnow().isoformat()+"Z"})

    # Process incoming flashcards
    added_fc = 0
    rejected_fc = []
    for raw in in_flash:
        norm, msg = _norm_bank_flashcard(raw)
        if not norm:
            rejected_fc.append({"item": raw, "error": msg}); continue
        h = _item_hash_flashcard(norm["front"], norm["back"], norm["domain"], norm["sources"])
        if h in existing_fc_hashes:
            continue
        bank_fc.append(norm)
        existing_fc_hashes.add(h)
        idx[h] = {"type": "fc", "added": datetime.utcnow().isoformat()+"Z"}
        added_fc += 1

    # Process incoming questions
    added_q = 0
    rejected_q = []
    for raw in in_questions:
        norm, msg = _norm_bank_question(raw)
        if not norm:
            rejected_q.append({"item": raw, "error": msg}); continue
        h = _item_hash_question(norm["question"], norm["options"], norm["correct"],
                                norm["domain"], norm["sources"])
        if h in existing_q_hashes:
            continue
        bank_q.append(norm)
        existing_q_hashes.add(h)
        idx[h] = {"type": "q", "added": datetime.utcnow().isoformat()+"Z"}
        added_q += 1

    # Save files atomically
    _bank_write_flashcards(bank_fc)
    _bank_write_questions(bank_q)
    _save_content_index(idx)

    return jsonify({
        "ok": True,
        "summary": {
            "flashcards_added": added_fc,
            "questions_added": added_q,
            "flashcards_total": len(bank_fc),
            "questions_total": len(bank_q),
            "flashcards_rejected": len(rejected_fc),
            "questions_rejected": len(rejected_q),
        },
        "rejected": {
            "flashcards": rejected_fc[:50],  # cap to keep payload light
            "questions": rejected_q[:50]
        }
    })

# If CSRF is enabled, exempt the JSON ingestion endpoint (post-definition).
if HAS_CSRF:
    try:
        api_dev_ingest = csrf.exempt(api_dev_ingest)  # type: ignore
    except Exception:
        logger.warning("Could not CSRF-exempt /api/dev/ingest; continuing without exemption.")

# ---------- ADMIN: Acceptance checker (bank validator) ----------
@app.get("/admin/check-bank")
@login_required
def admin_check_bank():
    if not is_admin():
        return redirect(url_for("admin_login_page", next=request.path))

    bank_fc = _bank_read_flashcards()
    bank_q  = _bank_read_questions()

    # Validate flashcards
    fc_errors = []
    seen_fc = set()
    for i, fc in enumerate(bank_fc):
        if not isinstance(fc, dict):
            fc_errors.append(f"FC[{i}]: not an object"); continue
        f = (fc.get("front","")).strip(); b = (fc.get("back","")).strip()
        if not f or not b:
            fc_errors.append(f"FC[{i}]: missing front/back")
        ok, msg = _validate_sources(fc.get("sources") or [])
        if not ok:
            fc_errors.append(f"FC[{i}]: {msg}")
        h = _item_hash_flashcard(f, b, (fc.get('domain') or 'Unspecified'), fc.get('sources') or [])
        if h in seen_fc:
            fc_errors.append(f"FC[{i}]: duplicate hash")
        seen_fc.add(h)

    # Validate questions
    q_errors = []
    seen_q = set()
    for i, q in enumerate(bank_q):
        if not isinstance(q, dict):
            q_errors.append(f"Q[{i}]: not an object"); continue
        question = (q.get("question","")).strip()
        opts = q.get("options") or {}
        correct = (q.get("correct","")).strip().upper()
        if not question:
            q_errors.append(f"Q[{i}]: empty question")
        # options must be A..D and all non-empty (scenario & TF supported downstream; ingestion prefers 4 choices)
        for L in ["A","B","C","D"]:
            if not (isinstance(opts, dict) and opts.get(L)):
                q_errors.append(f"Q[{i}]: missing option {L}")
        if correct not in ("A","B","C","D"):
            q_errors.append(f"Q[{i}]: invalid correct {correct}")
        ok, msg = _validate_sources(q.get("sources") or [])
        if not ok:
            q_errors.append(f"Q[{i}]: {msg}")
        h = _item_hash_question(question, opts, correct, (q.get("domain") or "Unspecified"), q.get("sources") or [])
        if h in seen_q:
            q_errors.append(f"Q[{i}]: duplicate hash")
        seen_q.add(h)

    # Domain counts to help balancing
    def _count_by_domain(items, key="domain"):
        d = {}
        for it in items:
            dn = (it.get(key) or "Unspecified")
            d[dn] = d.get(dn, 0) + 1
        return d

    fc_by_dom = _count_by_domain(bank_fc)
    q_by_dom  = _count_by_domain(bank_q)

    def _tbl_dict(dct):
        rows = []
        for k in sorted(dct.keys()):
            rows.append(f"<tr><td>{html.escape(str(k))}</td><td class='text-end'>{int(dct[k])}</td></tr>")
        return "".join(rows) or "<tr><td colspan='2' class='text-center text-muted'>None</td></tr>"

    fc_err_html = "".join(f"<li>{html.escape(e)}</li>" for e in fc_errors) or "<li class='text-muted'>None</li>"
    q_err_html  = "".join(f"<li>{html.escape(e)}</li>" for e in q_errors)  or "<li class='text-muted'>None</li>"

    content = f"""
    <div class="container">
      <div class="row justify-content-center"><div class="col-xl-10">
        <div class="card">
          <div class="card-header bg-dark text-white"><h3 class="mb-0"><i class="bi bi-clipboard-check me-2"></i>Bank Acceptance Check</h3></div>
          <div class="card-body">
            <div class="row g-4">
              <div class="col-md-6">
                <div class="p-3 border rounded-3">
                  <div class="fw-semibold mb-2">Flashcards</div>
                  <div class="small text-muted mb-2">Total: {len(bank_fc)}</div>
                  <div class="table-responsive">
                    <table class="table table-sm align-middle">
                      <thead><tr><th>Domain</th><th class="text-end">Count</th></tr></thead>
                      <tbody>{_tbl_dict(fc_by_dom)}</tbody>
                    </table>
                  </div>
                  <div class="mt-2">
                    <div class="fw-semibold">Issues</div>
                    <ul class="small">{fc_err_html}</ul>
                  </div>
                </div>
              </div>
              <div class="col-md-6">
                <div class="p-3 border rounded-3">
                  <div class="fw-semibold mb-2">Questions</div>
                  <div class="small text-muted mb-2">Total: {len(bank_q)}</div>
                  <div class="table-responsive">
                    <table class="table table-sm align-middle">
                      <thead><tr><th>Domain</th><th class="text-end">Count</th></tr></thead>
                      <tbody>{_tbl_dict(q_by_dom)}</tbody>
                    </table>
                  </div>
                  <div class="mt-2">
                    <div class="fw-semibold">Issues</div>
                    <ul class="small">{q_err_html}</ul>
                  </div>
                </div>
              </div>
            </div>
            <div class="mt-3 d-flex gap-2">
              <a class="btn btn-outline-secondary" href="/"><i class="bi bi-house me-1"></i>Home</a>
              <a class="btn btn-outline-primary" href="/admin/content-balance"><i class="bi bi-bar-chart-line me-1"></i>Content Balance</a>
              <a class="btn btn-outline-primary" href="/billing/debug"><i class="bi bi-bug me-1"></i>Config Debug</a>
            </div>
          </div>
        </div>
      </div></div>
    </div>
    """
    return base_layout("Bank Checker", content)


# ---------- ADMIN: Content Balance (targets & progress) ----------
# Target allocation (total 900): 50% MCQ, 25% T/F, 25% Scenario
CONTENT_TARGETS = {
    "security-principles":  {"total": 198, "mcq": 99, "tf": 50, "scenario": 50},
    "business-principles":  {"total": 198, "mcq": 99, "tf": 50, "scenario": 50},
    "investigations":       {"total": 108, "mcq": 54, "tf": 27, "scenario": 27},
    "personnel-security":   {"total":  90, "mcq": 45, "tf": 22, "scenario": 22},
    "physical-security":    {"total": 180, "mcq": 90, "tf": 45, "scenario": 45},
    "information-security": {"total":  54, "mcq": 27, "tf": 14, "scenario": 14},
    "crisis-management":    {"total":  72, "mcq": 36, "tf": 18, "scenario": 18},
}

def _classify_question_type(q: dict) -> str:
    """
    Heuristic classification:
      - If stem starts with 'Scenario:' (case-insensitive) -> 'scenario'
      - Else if it appears to be True/False (options contain True/False keywords OR only A/B are present) -> 'tf'
      - Else -> 'mcq'
    """
    stem = (q.get("question") or "").strip()
    if re.match(r"^\s*scenario\s*[:\-]", stem, flags=re.IGNORECASE):
        return "scenario"
    opts = q.get("options") or {}
    keys_present = [k for k in ["A","B","C","D"] if (opts.get(k) and str(opts.get(k)).strip())]
    text_join = " ".join([str(opts.get(k,"")).lower() for k in ["A","B","C","D"]])
    if ("true" in text_join or "false" in text_join) or len(keys_present) <= 2:
        return "tf"
    return "mcq"

def _progress_bar_html(cur: int, tgt: int) -> str:
    pct = 0 if not tgt else min(100, round(cur*100.0/tgt))
    cls = "bg-success" if pct >= 100 else ("bg-info" if pct >= 50 else "bg-warning")
    return f"""
      <div class="progress" role="progressbar" aria-valuenow="{pct}" aria-valuemin="0" aria-valuemax="100">
        <div class="progress-bar {cls}" style="width:{pct}%">{pct}%</div>
      </div>
    """

@app.get("/admin/content-balance")
@login_required
def admin_content_balance():
    if not is_admin():
        return redirect(url_for("admin_login_page", next=request.path))

    bank_q = _bank_read_questions()

    # Build counts by domain & type
    counts: Dict[str, Dict[str, int]] = {k: {"total": 0, "mcq": 0, "tf": 0, "scenario": 0} for k in DOMAINS.keys()}
    for q in bank_q:
        dom = (q.get("domain") or "Unspecified").strip().lower()
        if dom not in counts:
            counts[dom] = {"total": 0, "mcq": 0, "tf": 0, "scenario": 0}
        qtype = _classify_question_type(q)
        counts[dom]["total"] += 1
        if qtype in ("mcq","tf","scenario"):
            counts[dom][qtype] += 1

    # Build table rows comparing to targets
    def row_for_domain(dkey: str) -> str:
        label = DOMAINS.get(dkey, dkey)
        tgt = CONTENT_TARGETS.get(dkey, {"total":0,"mcq":0,"tf":0,"scenario":0})
        cur = counts.get(dkey, {"total":0,"mcq":0,"tf":0,"scenario":0})
        total_row = f"""
          <tr class="table-light">
            <td class="fw-semibold">{html.escape(label)}</td>
            <td class="text-end">{cur['total']}</td>
            <td class="text-end">{tgt['total']}</td>
            <td colspan="3">{_progress_bar_html(cur['total'], tgt['total'])}</td>
          </tr>
        """
        types_row = f"""
          <tr>
            <td class="text-muted small ps-4">Breakdown</td>
            <td class="text-end">{cur['mcq']}/{tgt['mcq']} MCQ</td>
            <td class="text-end">{cur['tf']}/{tgt['tf']} T/F</td>
            <td class="text-end">{cur['scenario']}/{tgt['scenario']} Scenario</td>
            <td colspan="2">
              <div class="d-flex gap-2">
                <div class="flex-grow-1">{_progress_bar_html(cur['mcq'], tgt['mcq'])}</div>
                <div class="flex-grow-1">{_progress_bar_html(cur['tf'], tgt['tf'])}</div>
                <div class="flex-grow-1">{_progress_bar_html(cur['scenario'], tgt['scenario'])}</div>
              </div>
            </td>
          </tr>
        """
        return total_row + types_row

    rows_html = "".join(row_for_domain(k) for k in DOMAINS.keys()) or "<tr><td colspan='6' class='text-center text-muted'>No data.</td></tr>"

    content = f"""
    <div class="container">
      <div class="row justify-content-center"><div class="col-xl-10">
        <div class="card">
          <div class="card-header bg-primary text-white">
            <h3 class="mb-0"><i class="bi bi-bar-chart-line me-2"></i>Content Balance — Targets vs Current</h3>
          </div>
          <div class="card-body">
            <p class="text-muted">Targets reflect the 900-question goal with domain weights and a 50/25/25 (MCQ/T-F/Scenario) split.</p>
            <div class="table-responsive">
              <table class="table table-sm align-middle">
                <thead>
                  <tr>
                    <th>Domain</th>
                    <th class="text-end">Current</th>
                    <th class="text-end">Target</th>
                    <th class="text-end">T/F</th>
                    <th class="text-end">Scenario</th>
                    <th>Progress</th>
                  </tr>
                </thead>
                <tbody>{rows_html}</tbody>
              </table>
            </div>
            <div class="mt-3 d-flex gap-2">
              <a class="btn btn-outline-secondary" href="/"><i class="bi bi-house me-1"></i>Home</a>
              <a class="btn btn-outline-primary" href="/admin/check-bank"><i class="bi bi-clipboard-check me-1"></i>Bank Checker</a>
            </div>
          </div>
        </div>
      </div></div>
    </div>
    """
    return base_layout("Content Balance", content)
# =========================
# SECTION 6/8: Content ingestion (+ whitelist, hashing, acceptance checker)
# =========================

# NOTE ON DUPLICATION:
# Per requirements, canonical admin ingestion endpoints and source validation/hashing
# helpers live in Section 5/8. To avoid duplicate route/function definitions, this
# section ONLY adds auxiliary utilities and a new "Content Balance" admin view to
# track progress toward the 900-question target split by domain and type.

# ---------- Question Typing & Targets (for balance tracking) ----------

# Supported logical types for questions
QUESTION_TYPES = ["mcq", "tf", "scenario"]

# Exact target allocation provided (total = 900; split 50% MCQ, 25% T/F, 25% Scenario)
TARGET_COUNTS = {
    # domain_key: {"mcq": int, "tf": int, "scenario": int, "total": int}
    "security-principles":  {"mcq": 99, "tf": 50, "scenario": 50, "total": 198},
    "business-principles":  {"mcq": 99, "tf": 50, "scenario": 50, "total": 198},
    "investigations":       {"mcq": 54, "tf": 27, "scenario": 27, "total": 108},
    "personnel-security":   {"mcq": 45, "tf": 22, "scenario": 22, "total": 90},
    "physical-security":    {"mcq": 90, "tf": 45, "scenario": 45, "total": 180},
    "information-security": {"mcq": 27, "tf": 14, "scenario": 14, "total": 54},
    "crisis-management":    {"mcq": 36, "tf": 18, "scenario": 18, "total": 72},
}

def _infer_q_type(q: dict) -> str:
    """
    Infer a question's logical type for balance tracking.

    Priority:
      1) Respect explicit q["type"] if present and valid ('mcq'|'tf'|'scenario').
      2) If stem starts with/contains 'Scenario:' (case-insensitive near start) -> 'scenario'.
      3) If options suggest True/False (A/B exactly True/False or T/F) -> 'tf'.
      4) Otherwise -> 'mcq'.

    NOTE: Rendering remains generic MCQ; this type is used for ingestion metrics only.
    """
    try:
        t = (q.get("type") or "").strip().lower()
        if t in QUESTION_TYPES:
            return t
    except Exception:
        pass

    stem = (q.get("question") or q.get("q") or q.get("stem") or "").strip()
    if re.search(r"^\s*scenario\s*:", stem, flags=re.IGNORECASE):
        return "scenario"

    opts = q.get("options") or {}
    a = str(opts.get("A", "")).strip().lower()
    b = str(opts.get("B", "")).strip().lower()
    tf_set = {"true", "false", "t", "f"}
    if a in tf_set and b in tf_set:
        return "tf"

    return "mcq"


def _compute_content_balance(bank_questions: list[dict]) -> dict:
    """
    Returns nested counts by domain and type:
      {
        "<domain>": {"mcq": X, "tf": Y, "scenario": Z, "total": N},
        ...
        "_totals": {"mcq": ..., "tf": ..., "scenario": ..., "total": ...}
      }
    """
    counts: dict[str, dict[str, int]] = {}
    totals = {"mcq": 0, "tf": 0, "scenario": 0, "total": 0}

    for q in (bank_questions or []):
        dom = (q.get("domain") or "Unspecified").strip()
        qt = _infer_q_type(q)
        bucket = counts.setdefault(dom, {"mcq": 0, "tf": 0, "scenario": 0, "total": 0})
        if qt not in QUESTION_TYPES:
            qt = "mcq"
        bucket[qt] += 1
        bucket["total"] += 1
        totals[qt] += 1
        totals["total"] += 1

    counts["_totals"] = totals
    return counts


def _progress_bar_html(current: int, target: int, label: str = "") -> str:
    pct = 0
    if target > 0:
        pct = int(round((current / target) * 100))
        pct = max(0, min(100, pct))
    bar_class = "bg-success" if pct >= 100 else ("bg-info" if pct >= 50 else "bg-warning")
    return f"""
      <div class="progress" style="height: 14px;">
        <div class="progress-bar {bar_class}" role="progressbar" style="width: {pct}%;" aria-valuenow="{pct}" aria-valuemin="0" aria-valuemax="100">
          <span class="small">{pct}%</span>
        </div>
      </div>
      <div class="small text-muted mt-1">{html.escape(label)} {current}/{target}</div>
    """


def _domain_label(dom_key: str) -> str:
    try:
        return DOMAINS.get(dom_key, dom_key)
    except Exception:
        return dom_key


# ---------- Admin: Content Balance (new) ----------
@app.get("/admin/content-balance")
@login_required
def admin_content_balance():
    if not is_admin():
        return redirect(url_for("admin_login_page", next=request.path))

    bank_q = _bank_read_questions() if " _bank_read_questions" or True else _load_json("bank/cpp_questions_v1.json", [])
    counts = _compute_content_balance(bank_q)

    # Build table rows per domain (using configured targets when present)
    rows = []
    # Sort domains: known first in DOMAINS order, then others alphabetically
    known_order = list(DOMAINS.keys())
    domains_sorted = sorted(set([d for d in counts.keys() if d != "_totals"]),
                            key=lambda d: (known_order.index(d) if d in known_order else 999, d))

    for dom in domains_sorted:
        c = counts.get(dom, {"mcq": 0, "tf": 0, "scenario": 0, "total": 0})
        tgt = TARGET_COUNTS.get(dom, {"mcq": 0, "tf": 0, "scenario": 0, "total": 0})

        mcq_bar = _progress_bar_html(c["mcq"], tgt.get("mcq", 0), "MCQ")
        tf_bar = _progress_bar_html(c["tf"], tgt.get("tf", 0), "True/False")
        sc_bar = _progress_bar_html(c["scenario"], tgt.get("scenario", 0), "Scenario")
        tot_bar = _progress_bar_html(c["total"], tgt.get("total", 0), "Total")

        rows.append(f"""
          <tr>
            <td class="text-nowrap">{html.escape(_domain_label(dom))}</td>
            <td style="min-width:180px;">{mcq_bar}</td>
            <td style="min-width:180px;">{tf_bar}</td>
            <td style="min-width:180px;">{sc_bar}</td>
            <td style="min-width:180px;">{tot_bar}</td>
          </tr>
        """)

    body_rows = "".join(rows) or "<tr><td colspan='5' class='text-center text-muted'>No questions ingested yet.</td></tr>"

    # Totals vs global targets
    tot_counts = counts.get("_totals", {"mcq": 0, "tf": 0, "scenario": 0, "total": 0})
    tgt_totals = {
        "mcq": sum(TARGET_COUNTS[d]["mcq"] for d in TARGET_COUNTS),
        "tf": sum(TARGET_COUNTS[d]["tf"] for d in TARGET_COUNTS),
        "scenario": sum(TARGET_COUNTS[d]["scenario"] for d in TARGET_COUNTS),
        "total": sum(TARGET_COUNTS[d]["total"] for d in TARGET_COUNTS),
    }

    totals_html = f"""
      <div class="row g-3">
        <div class="col-md-3">
          <div class="p-3 border rounded-3">
            <div class="fw-semibold mb-1">MCQ</div>
            {_progress_bar_html(tot_counts.get("mcq",0), tgt_totals["mcq"], "MCQ total")}
          </div>
        </div>
        <div class="col-md-3">
          <div class="p-3 border rounded-3">
            <div class="fw-semibold mb-1">True/False</div>
            {_progress_bar_html(tot_counts.get("tf",0), tgt_totals["tf"], "T/F total")}
          </div>
        </div>
        <div class="col-md-3">
          <div class="p-3 border rounded-3">
            <div class="fw-semibold mb-1">Scenario</div>
            {_progress_bar_html(tot_counts.get("scenario",0), tgt_totals["scenario"], "Scenario total")}
          </div>
        </div>
        <div class="col-md-3">
          <div class="p-3 border rounded-3">
            <div class="fw-semibold mb-1">All Questions</div>
            {_progress_bar_html(tot_counts.get("total",0), tgt_totals["total"], "Grand total")}
          </div>
        </div>
      </div>
    """

    content = f"""
    <div class="container"><div class="row justify-content-center"><div class="col-xl-10">
      <div class="card">
        <div class="card-header bg-secondary text-white">
          <h3 class="mb-0"><i class="bi bi-diagram-3 me-2"></i>Content Balance (Targets vs Current)</h3>
        </div>
        <div class="card-body">
          <div class="alert alert-info border-0">
            <i class="bi bi-info-circle me-2"></i>
            Tracking progress toward the 900-question goal with the requested 50% MCQ / 25% T/F / 25% Scenario split.
            Use the <code>/api/dev/ingest</code> JSON endpoint to add content in batches.
          </div>

          {totals_html}

          <div class="table-responsive mt-4">
            <table class="table table-sm align-middle">
              <thead>
                <tr>
                  <th>Domain</th>
                  <th>MCQ</th>
                  <th>True/False</th>
                  <th>Scenario</th>
                  <th>Total</th>
                </tr>
              </thead>
              <tbody>{body_rows}</tbody>
            </table>
          </div>

          <div class="mt-3 d-flex gap-2">
            <a class="btn btn-outline-secondary" href="/"><i class="bi bi-house me-1"></i>Home</a>
            <a class="btn btn-outline-primary" href="/admin/check-bank"><i class="bi bi-clipboard-check me-1"></i>Bank Check</a>
          </div>
        </div>
      </div>
    </div></div></div>
    """
    return base_layout("Content Balance", content)


@app.get("/admin/content-balance.json")
@login_required
def admin_content_balance_json():
    if not is_admin():
        return jsonify({"ok": False, "error": "admin-required"}), 403

    bank_q = _bank_read_questions()
    counts = _compute_content_balance(bank_q)
    targets = TARGET_COUNTS
    totals_target = {
        "mcq": sum(targets[d]["mcq"] for d in targets),
        "tf": sum(targets[d]["tf"] for d in targets),
        "scenario": sum(targets[d]["scenario"] for d in targets),
        "total": sum(targets[d]["total"] for d in targets),
    }
    return jsonify({
        "ok": True,
        "counts": counts,
        "targets": targets,
        "targets_totals": totals_target
    })
# =========================
# SECTION 7/8: Tutor (web-aware citations override) + settings UI
# =========================

# NOTE: This section overrides _call_tutor_agent from Section 3 to add optional
# "web-aware" grounding that ONLY cites *ingested* sources (no live web).

def _format_citations_for_prompt(cites: list[dict]) -> str:
    if not cites:
        return ""
    lines = []
    for i, c in enumerate(cites, 1):
        title = (c.get("title") or "").strip()
        url = (c.get("url") or "").strip()
        dom = (c.get("domain") or "").strip()
        lines.append(f"[{i}] {title} — {dom}\n{url}")
    return "\n".join(lines)

def _call_tutor_agent(user_query, meta=None):
    """
    Override of the baseline agent (Section 3):
    - If web-aware is OFF, behave exactly like the original.
    - If web-aware is ON, include up to 3 best-matching *ingested bank* sources (no live web),
      instruct the model to align with these sources, and append a compact References list.
    """
    meta = meta or {}
    timeout_s = float(os.environ.get("TUTOR_TIMEOUT", "45"))
    temperature = float(os.environ.get("TUTOR_TEMP", "0.3"))
    max_tokens = int(os.environ.get("TUTOR_MAX_TOKENS", "900"))
    base_system = os.environ.get(
        "TUTOR_SYSTEM_PROMPT",
        "You are a calm, expert CPP/PSP study tutor. Explain clearly, step-by-step."
    )

    if not OPENAI_API_KEY:
        return False, "Tutor is not configured: missing OPENAI_API_KEY.", {}

    web_on = _tutor_web_enabled()
    sources = []
    sys_msg = base_system
    user_content = user_query

    if web_on:
        try:
            sources = _find_bank_citations(user_query, max_n=3)
        except Exception as _e:
            sources = []

        sys_msg = (
            base_system
            + "\n\nGROUNDING:\n"
              "- You are provided a small list of relevant, vetted sources (government/standards/AAR style).\n"
              "- Answer using your expertise and *align with* these sources. If something is uncertain, say so.\n"
              "- Keep the answer concise and exam-focused; show steps when helpful."
        )

        cites_block = _format_citations_for_prompt(sources)
        if cites_block:
            user_content = (
                f"{user_query}\n\n"
                f"Candidate reference material (use when helpful):\n{cites_block}"
            )

    url = f"{OPENAI_API_BASE}/chat/completions"
    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "Content-Type": "application/json",
    }
    org = os.environ.get("OPENAI_ORG", "").strip()
    if org:
        headers["OpenAI-Organization"] = org

    payload = {
        "model": OPENAI_CHAT_MODEL,
        "messages": [
            {"role": "system", "content": sys_msg},
            {"role": "user", "content": user_content}
        ],
        "temperature": temperature,
        "max_tokens": max_tokens
    }

    backoffs = [0, 1.5, 3.0]
    last_err = None
    for wait_s in backoffs:
        if wait_s:
            time.sleep(wait_s)
        try:
            resp = requests.post(url, headers=headers, data=json.dumps(payload), timeout=timeout_s)
            if resp.status_code in (429, 500, 502, 503, 504):
                last_err = f"{resp.status_code} {resp.text[:300]}"
                continue
            if resp.status_code >= 400:
                try:
                    j = resp.json()
                    msg = (j.get("error") or {}).get("message") or resp.text[:300]
                except Exception:
                    msg = resp.text[:300]
                return False, f"Agent error {resp.status_code}: {msg}", {"status": resp.status_code}

            data = resp.json()
            answer = (data.get("choices") or [{}])[0].get("message", {}).get("content", "")
            usage = data.get("usage", {})

            if web_on and sources and answer:
                refs_lines = []
                for i, s in enumerate(sources, 1):
                    t = (s.get("title") or "").strip()
                    u = (s.get("url") or "").strip()
                    refs_lines.append(f"[{i}] {t} — {u}")
                answer = f"{answer}\n\nReferences:\n" + "\n".join(refs_lines)

            return True, answer, {"usage": usage, "model": OPENAI_CHAT_MODEL, "web_aware": web_on}
        except Exception as e:
            last_err = str(e)
            continue
    return False, f"Network/agent error: {last_err or 'unknown'}", {"web_aware": web_on}

# -------- Tutor settings UI (admin) --------
@app.route("/admin/tutor-settings", methods=["GET", "POST"])
@login_required
def admin_tutor_settings():
    if not is_admin():
        return redirect(url_for("admin_login_page", next=request.path))

    msg = ""
    cfg = _load_tutor_settings()
    if request.method == "POST":
        if not HAS_CSRF:
            if request.form.get("csrf_token") != csrf_token():
                abort(403)
        web_aware = (request.form.get("web_aware") == "on")
        cfg["web_aware"] = bool(web_aware)
        _save_tutor_settings(cfg)
        msg = "Tutor settings updated."

    csrf_val = csrf_token()
    checked = "checked" if cfg.get("web_aware") else ""
    body = f"""
    <div class="container"><div class="row justify-content-center"><div class="col-lg-7">
      <div class="card">
        <div class="card-header bg-dark text-white">
          <h3 class="mb-0"><i class="bi bi-gear-wide-connected me-2"></i>Tutor Settings</h3>
        </div>
        <div class="card-body">
          {"<div class='alert alert-success'>" + html.escape(msg) + "</div>" if msg else ""}
          <form method="POST">
            <input type="hidden" name="csrf_token" value="{csrf_val}"/>
            <div class="form-check form-switch mb-3">
              <input class="form-check-input" type="checkbox" id="webAware" name="web_aware" {checked}>
              <label class="form-check-label" for="webAware">
                Enable web-aware mode (use *ingested* sources for citations)
              </label>
            </div>
            <button class="btn btn-primary" type="submit"><i class="bi bi-save me-1"></i>Save</button>
            <a class="btn btn-outline-secondary ms-2" href="/"><i class="bi bi-house me-1"></i>Home</a>
          </form>
          <hr>
          <div class="small text-muted">
            When enabled, the Tutor will ground answers to sources you ingested under <code>data/bank</code>.
            It never fetches the live internet; it only cites your vetted, whitelisted materials.
          </div>
        </div>
      </div>
    </div></div></div>
    """
    return base_layout("Tutor Settings", body)

# -------- Admin Content Balance (domain × type progress toward 900) --------

CONTENT_TARGETS = {
    # Domain keys follow app slugs
    "security-principles":  {"mcq": 99, "tf": 50, "scenario": 50},   # 198
    "business-principles":  {"mcq": 99, "tf": 50, "scenario": 50},   # 198
    "investigations":       {"mcq": 54, "tf": 27, "scenario": 27},   # 108
    "personnel-security":   {"mcq": 45, "tf": 22, "scenario": 22},   # 90
    "physical-security":    {"mcq": 90, "tf": 45, "scenario": 45},   # 180
    "information-security": {"mcq": 27, "tf": 14, "scenario": 14},   # 54
    "crisis-management":    {"mcq": 36, "tf": 18, "scenario": 18},   # 72
}

_TF_TOKENS_TRUE = {"true", "t", "yes", "y"}
_TF_TOKENS_FALSE = {"false", "f", "no", "n"}

def _classify_question_type(q: dict) -> str:
    """Heuristic classification: 'tf' if options include both True/False;
    'scenario' if question starts with 'Scenario:' (case-insensitive); else 'mcq'."""
    # Optional explicit hint
    qtype = (q.get("type") or "").strip().lower()
    if qtype in ("tf", "truefalse", "true_false"):
        return "tf"
    if qtype in ("scenario", "case", "case-study"):
        return "scenario"

    stem = (q.get("question") or "").strip()
    if stem.lower().startswith("scenario:"):
        return "scenario"

    opts = q.get("options") or {}
    vals = [str(opts.get(k, "")).strip().lower() for k in ("A", "B", "C", "D")]
    tokens = {re.sub(r"[^a-z]", "", v) for v in vals if v}
    has_true = any(tok in _TF_TOKENS_TRUE for tok in tokens)
    has_false = any(tok in _TF_TOKENS_FALSE for tok in tokens)
    if has_true and has_false:
        return "tf"
    return "mcq"

@app.get("/admin/content-balance")
@login_required
def admin_content_balance():
    if not is_admin():
        return redirect(url_for("admin_login_page", next=request.path))

    bank_q = _bank_read_questions()
    # Build counts
    counts = {}
    total_counts = {"mcq": 0, "tf": 0, "scenario": 0}
    for q in bank_q:
        d = (q.get("domain") or "Unspecified").strip().lower()
        d = d if d in CONTENT_TARGETS else d  # allow unknown, will show as-is
        qt = _classify_question_type(q)
        dct = counts.setdefault(d, {"mcq": 0, "tf": 0, "scenario": 0})
        dct[qt] = dct.get(qt, 0) + 1
        total_counts[qt] += 1

    # Render table rows
    def _progbar(val, target):
        pct = 0 if not target else min(100, int((val / target) * 100))
        return f"""
        <div class="progress" style="height:14px;">
          <div class="progress-bar" role="progressbar" style="width: {pct}%;" aria-valuenow="{pct}" aria-valuemin="0" aria-valuemax="{target}">{val}/{target}</div>
        </div>
        """

    rows = []
    # Ensure domains show in canonical order first
    ordered_domains = list(CONTENT_TARGETS.keys()) + [d for d in counts.keys() if d not in CONTENT_TARGETS]
    seen_d = set()
    for d in ordered_domains:
        if d in seen_d:
            continue
        seen_d.add(d)
        targ = CONTENT_TARGETS.get(d, {"mcq": 0, "tf": 0, "scenario": 0})
        have = counts.get(d, {"mcq": 0, "tf": 0, "scenario": 0})
        label = DOMAINS.get(d, d.title())
        rows.append(f"""
        <tr>
          <td class="text-nowrap">{html.escape(label)}</td>
          <td style="min-width:180px;">{_progbar(have.get('mcq',0), targ.get('mcq',0))}</td>
          <td style="min-width:180px;">{_progbar(have.get('tf',0), targ.get('tf',0))}</td>
          <td style="min-width:180px;">{_progbar(have.get('scenario',0), targ.get('scenario',0))}</td>
        </tr>
        """)

    rows_html = "".join(rows) or "<tr><td colspan='4' class='text-center text-muted'>No questions ingested yet.</td></tr>"

    totals_row = f"""
    <tr class="table-light">
      <td><strong>Totals</strong></td>
      <td>{total_counts['mcq']}</td>
      <td>{total_counts['tf']}</td>
      <td>{total_counts['scenario']}</td>
    </tr>
    """

    content = f"""
    <div class="container">
      <div class="row justify-content-center"><div class="col-xl-10">
        <div class="card">
          <div class="card-header bg-secondary text-white">
            <h3 class="mb-0"><i class="bi bi-bullseye me-2"></i>Content Balance (Domain × Type)</h3>
          </div>
          <div class="card-body">
            <p class="text-muted">
              Targets reflect 900 total questions with 50% MCQ / 25% True-False / 25% Scenario, distributed by CPP domain weights.
            </p>
            <div class="table-responsive">
              <table class="table align-middle">
                <thead>
                  <tr>
                    <th>Domain</th>
                    <th>MCQ</th>
                    <th>True/False</th>
                    <th>Scenario</th>
                  </tr>
                </thead>
                <tbody>
                  {rows_html}
                  {totals_row}
                </tbody>
              </table>
            </div>
            <div class="mt-3 d-flex gap-2">
              <a class="btn btn-outline-secondary" href="/"><i class="bi bi-house me-1"></i>Home</a>
              <a class="btn btn-outline-primary" href="/admin/check-bank"><i class="bi bi-clipboard-check me-1"></i>Bank Validator</a>
            </div>
          </div>
        </div>
      </div></div>
    </div>
    """
    return base_layout("Content Balance", content)


# =========================
# SECTION 8/8: Startup, health, error pages, and __main__
# =========================

# ---- Legal / Terms & Conditions ----
TERMS_VERSION = os.environ.get("TERMS_VERSION", "2025-09-01")

@app.get("/legal/terms")
def legal_terms_page():
    body = """
    <div class="container">
      <div class="row justify-content-center"><div class="col-lg-9">
        <div class="card">
          <div class="card-header bg-dark text-white">
            <h3 class="mb-0"><i class="bi bi-file-text me-2"></i>Terms & Conditions</h3>
          </div>
          <div class="card-body">
            <div class="alert alert-warning">
              <strong>Disclaimer:</strong> This independent study platform is not affiliated with ASIS International.
              CPP&reg; is a mark of ASIS International, Inc. No refunds once access is granted.
            </div>
            <h5>1. Service</h5>
            <p>This site provides study tools (practice questions, flashcards, and an AI tutor) for individual use.</p>
            <h5>2. No Affiliation</h5>
            <p>We are not endorsed by or affiliated with ASIS International. Use at your own discretion.</p>
            <h5>3. No Refunds</h5>
            <p>All sales are final. If you have issues, contact support and we will make reasonable efforts to help.</p>
            <h5>4. Acceptable Use</h5>
            <p>Do not share accounts or redistribute content without permission.</p>
            <h5>5. Privacy</h5>
            <p>We store minimal account and usage data necessary to operate the service.</p>
            <h5>6. Changes</h5>
            <p>Terms may be updated; you may be asked to re-accept updated terms to continue using the service.</p>
            <hr>
            <div class="d-flex gap-2">
              <a href="/" class="btn btn-outline-secondary"><i class="bi bi-house me-1"></i>Home</a>
              <a href="/signup" class="btn btn-primary"><i class="bi bi-person-plus me-1"></i>Create Account</a>
            </div>
          </div>
        </div>
      </div></div>
    </div>
    """
    return base_layout("Terms & Conditions", body)

@app.route("/legal/accept", methods=["GET", "POST"])
def legal_accept_page():
    # Accepting terms can be reached (1) after login if outdated, or (2) from a pre-login flow
    msg = ""
    if request.method == "POST":
        if not HAS_CSRF:
            if request.form.get("csrf_token") != csrf_token():
                abort(403)
        agreed = (request.form.get("agree") == "on")
        # determine which user we are updating:
        # - if already logged in, use session['email']
        # - else if pending (after login credential check), use session['pending_terms_email']
        email = session.get("email") or session.get("pending_terms_email") or ""
        user = _find_user(email)
        if not user:
            msg = "No user context found. Please sign in first."
        elif not agreed:
            msg = "You must agree to the Terms & Conditions to proceed."
        else:
            _update_user(user["id"], {
                "terms_accept_version": TERMS_VERSION,
                "terms_accept_ts": datetime.utcnow().isoformat() + "Z"
            })
            # If we came from a pending state (pre-session), finalize login session now
            if "pending_terms_user_id" in session and "user_id" not in session:
                session["user_id"] = user["id"]
                session["email"] = user["email"]
                session["name"] = user.get("name", "")
                session.pop("pending_terms_user_id", None)
                session.pop("pending_terms_email", None)
            return redirect(url_for("home"))

    csrf_val = csrf_token()
    body = f"""
    <div class="container">
      <div class="row justify-content-center"><div class="col-lg-8 col-xl-7">
        <div class="card">
          <div class="card-header bg-dark text-white">
            <h3 class="mb-0"><i class="bi bi-shield-lock me-2"></i>Accept Terms & Conditions</h3>
          </div>
          <div class="card-body">
            {"<div class='alert alert-warning'>" + html.escape(msg) + "</div>" if msg else ""}
            <p class="text-muted">To continue, please review and accept the latest Terms & Conditions.</p>
            <p><a href="/legal/terms" target="_blank" rel="noopener">Open the full Terms & Conditions</a></p>
            <form method="POST">
              <input type="hidden" name="csrf_token" value="{csrf_val}">
              <div class="form-check mb-3">
                <input class="form-check-input" type="checkbox" name="agree" id="agreeBox">
                <label class="form-check-label" for="agreeBox">
                  I have read and agree to the full Terms & Conditions (version {html.escape(TERMS_VERSION)}).
                </label>
              </div>
              <button class="btn btn-primary" type="submit"><i class="bi bi-check2-circle me-1"></i>Accept & Continue</button>
              <a class="btn btn-outline-secondary ms-2" href="/"><i class="bi bi-x-circle me-1"></i>Cancel</a>
            </form>
          </div>
        </div>
      </div></div>
    </div>
    """
    return base_layout("Accept Terms", body)

# ---- Anonymous "report issue" (adds an event; no PII) ----
@app.post("/report-issue")
def report_issue():
    try:
        payload = {
            "path": request.form.get("path") or request.headers.get("Referer") or "",
            "note": (request.form.get("note") or "")[:500],
            "ua": request.headers.get("User-Agent", "")[:200]
        }
        _log_event(session.get("user_id") or "anon", "user.report_issue", payload)
    except Exception as e:
        logger.warning("report_issue failed: %s", e)
    return "", 204

# ---- Robots.txt & Favicon ----
@app.get("/robots.txt")
def robots_txt():
    return Response("User-agent: *\nDisallow:\n", mimetype="text/plain")

@app.get("/favicon.ico")
def favicon_ico():
    # Tiny inline SVG as favicon (served as SVG)
    svg = (
        "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'>"
        "<rect width='64' height='64' rx='8' fill='#2563eb'/>"
        "<path d='M16 36l8 8 24-24' stroke='#fff' stroke-width='6' fill='none'/>"
        "</svg>"
    )
    return Response(svg, mimetype="image/svg+xml")

# ---- Friendly 404 page ----
@app.errorhandler(404)
def not_found(e):
    content = """
    <div class="container">
      <div class="row justify-content-center"><div class="col-md-8">
        <div class="card">
          <div class="card-header bg-warning text-dark">
            <h3 class="mb-0"><i class="bi bi-signpost-2 me-2"></i>Page not found</h3>
          </div>
          <div class="card-body">
            <p class="text-muted mb-3">We couldn't find that page. Try the home page or another section.</p>
            <a class="btn btn-primary" href="/"><i class="bi bi-house me-1"></i>Home</a>
          </div>
        </div>
      </div></div>
    </div>
    """
    return base_layout("Not Found", content), 404

# ---- 500 error page (friendly, no stack traces) ----
@app.errorhandler(500)
def server_error(e):
    content = """
    <div class="container">
      <div class="row justify-content-center"><div class="col-md-8">
        <div class="card">
          <div class="card-header bg-danger text-white">
            <h3 class="mb-0"><i class="bi bi-bug me-2"></i>Something went wrong</h3>
          </div>
          <div class="card-body">
            <p class="text-muted mb-3">An unexpected error occurred. Please try again.</p>
            <a class="btn btn-primary" href="/"><i class="bi bi-arrow-repeat me-1"></i>Retry</a>
          </div>
        </div>
      </div></div>
    </div>
    """
    return base_layout("Server Error", content), 500

# ---- Data bootstrapping ----
def init_sample_data():
    """
    Ensure required folders/files exist so the app never 500s on first boot.
    Non-destructive: only creates files if missing.
    """
    try:
        os.makedirs(DATA_DIR, exist_ok=True)

        bank_dir = os.path.join(DATA_DIR, "bank")
        os.makedirs(bank_dir, exist_ok=True)

        core_defaults = [
            ("users.json", []),
            ("questions.json", []),      # legacy optional
            ("flashcards.json", []),     # legacy optional
            ("attempts.json", []),
            ("events.json", []),
        ]
        for name, default in core_defaults:
            path = os.path.join(DATA_DIR, name)
            if not os.path.exists(path):
                _save_json(name, default)

        if not os.path.exists(os.path.join(bank_dir, "cpp_flashcards_v1.json")):
            _save_json("bank/cpp_flashcards_v1.json", [])
        if not os.path.exists(os.path.join(bank_dir, "cpp_questions_v1.json")):
            _save_json("bank/cpp_questions_v1.json", [])
        if not os.path.exists(os.path.join(bank_dir, "content_index.json")):
            _save_json("bank/content_index.json", {})

        tutor_path = os.path.join(DATA_DIR, "tutor_settings.json")
        if not os.path.exists(tutor_path):
            _save_json("tutor_settings.json", {"web_aware": os.environ.get("TUTOR_WEB_AWARE", "0") == "1"})
    except Exception as e:
        logger.warning("init_sample_data encountered an issue: %s", e)

# ---- App factory (for gunicorn / WSGI servers) ----
def create_app():
    init_sample_data()
    logger.info("CPP Test Prep v%s starting up", APP_VERSION)
    logger.info("Debug mode: %s", DEBUG)
    logger.info("Staging mode: %s", IS_STAGING)
    logger.info("CSRF protection: %s", "enabled" if HAS_CSRF else "disabled")
    logger.info("Stripe monthly ID present: %s", bool(STRIPE_MONTHLY_PRICE_ID))
    logger.info("Stripe 6-month ID present: %s", bool(STRIPE_SIXMONTH_PRICE_ID))
    logger.info("Stripe webhook secret present: %s", bool(STRIPE_WEBHOOK_SECRET))
    logger.info("OpenAI key present: %s", bool(OPENAI_API_KEY))
    return app

# ---- Local runner (Render uses gunicorn `app:app`) ----
if __name__ == "__main__":
    init_sample_data()
    port = int(os.environ.get("PORT", "5000"))
    logger.info("Running app on port %s", port)
    app.run(host="0.0.0.0", port=port, debug=DEBUG)
