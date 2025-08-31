# =========================
# SECTION 1/8: Imports, Config, Data IO, Security, Base Data
# =========================

# ----- Imports & Basic Config -----
from __future__ import annotations

from flask import (
    Flask, request, jsonify, session, redirect, url_for, Response, abort
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from functools import wraps
from datetime import datetime, timedelta
from typing import Dict, Any

import os, json, random, requests, html, uuid, logging, time, hashlib, re
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

# fcntl for safe file writes (best-effort, Linux only)
try:
    import fcntl  # noqa: F401
    HAS_FCNTL = True
except Exception:
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

# --- Legal / T&C gate config ---
LEGAL_TOS_VERSION = os.environ.get("LEGAL_TOS_VERSION", "2025-08-31")
LEGAL_TOS_ROUTE   = "/legal/terms"

# ----- App config -----
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=(os.environ.get("SESSION_COOKIE_SECURE", "1") == "1"),
)

# ----- Data Storage (JSON + optional SQLite stub) -----
DATA_DIR = os.environ.get("DATA_DIR", "data")
os.makedirs(DATA_DIR, exist_ok=True)
DATABASE_PATH = os.path.join(DATA_DIR, "app.db")

def _load_json(name: str, default):
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

def _save_json(name: str, data):
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
            try:
                os.fsync(f.fileno())
            except Exception:
                pass
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
    ip = request.headers.get("CF-Connecting-IP") or request.remote_addr or "unknown"
    ua = request.headers.get("User-Agent", "")
    return f"{el}|{ip}|{hashlib.sha256(ua.encode('utf-8')).hexdigest()[:10]}"

def _rate_limited(route: str, limit: int = 10, per_seconds: int = 60) -> bool:
    """
    Token-bucket per (route, client token).
    """
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
    if len(_RATE_BUCKETS) > 2000:
        cutoff = now - (per_seconds * 3)
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

# ----- Usage & Login Attempt Management -----
def _now_iso():
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"

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
            usage['last_active'] = _now_iso()
            users[i] = u
            _save_json("users.json", users)
            return

def _track_login_attempt(email: str, ok: bool):
    """
    Persist lightweight login attempt metrics on the user record and events.json.
    """
    if not email:
        return
    users = _load_users()
    el = email.strip().lower()
    for i, u in enumerate(users):
        if (u.get("email","").strip().lower() == el):
            sec = u.setdefault("security", {})
            la = sec.setdefault("login_attempts", {})
            if ok:
                la["last_success_ts"] = _now_iso()
                la["last_success_ip"] = request.headers.get("CF-Connecting-IP") or request.remote_addr or ""
                la["failed_count"] = 0
            else:
                la["failed_count"] = int(la.get("failed_count", 0)) + 1
                la["last_failed_ts"] = _now_iso()
                la["last_failed_ip"] = request.headers.get("CF-Connecting-IP") or request.remote_addr or ""
            users[i] = u
            _save_users(users)
            break
    # Append to events (ring buffer last 200)
    try:
        events = _load_json("events.json", [])
        events.append({
            "id": str(uuid.uuid4()),
            "ts": _now_iso(),
            "type": "auth.login" if ok else "auth.login_failed",
            "user_email": el,
            "ip": request.headers.get("CF-Connecting-IP") or request.remote_addr or "",
            "ua": request.headers.get("User-Agent","")[:120],
        })
        events = events[-200:]
        _save_json("events.json", events)
    except Exception as e:
        logger.warning("login attempt event log failed: %s", e)

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

# --- Domain constants (labels & styles) ---
DOMAINS = {
    "security-principles":  "Security Principles",
    "business-principles":  "Business Principles",
    "investigations":       "Investigations",
    "personnel-security":   "Personnel Security",
    "physical-security":    "Physical Security",
    "information-security": "Information Security",
    "crisis-management":    "Crisis & Continuity",
}

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
    try:
        return round(100.0 * float(num) / float(den), 1)
    except Exception:
        return 0.0

def _user_id():
    return (session.get("user_id") or session.get("email") or "unknown")

# ----- Base Layout (adds concise, universal footer disclaimer) -----
def _plan_badge_text(sub):
    return {"monthly": "Monthly", "sixmonth": "6-Month"}.get(sub, "Inactive")

@app.template_global()
def csrf_token():
    if HAS_CSRF:
        try:
            from flask_wtf.csrf import generate_csrf
            return generate_csrf()
        except Exception:
            return ""
    return ""

def base_layout(title: str, body_html: str) -> str:
    """
    Universal page wrapper with nav + footer disclaimer.
    Footer disclaimer (short, explicit, always present):
      - Not affiliated with ASIS. Educational use only. No professional advice. No refunds. See Terms.
    """
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
          <ul class="navbar-nav">
            <li class="nav-item"><a class="nav-link text-white-75" href="{LEGAL_TOS_ROUTE}">Terms</a></li>
            {user_menu}
          </ul>
        </div>
      </div>
    </nav>
    """

    # concise, always-on legal disclaimer in footer
    footer_disclaimer = (
        "Not affiliated with ASIS. Educational use only. No professional advice. "
        "No refunds. See Terms."
    )

    disclaimer = f"""
    <footer class="bg-light py-4 mt-5 border-top">
      <div class="container">
        <div class="row align-items-center">
          <div class="col-md-8">
            <small class="text-muted">
              <strong>Notice:</strong> This platform is independent and not affiliated with ASIS International.
              CPP&reg; is a mark of ASIS International, Inc.
            </small>
            <br>
            <small class="text-muted">{html.escape(footer_disclaimer)}</small>
          </div>
          <div class="col-md-4 text-end">
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
    </body></html>"""

# ---- Health (simple) ----
@app.get("/healthz")
def healthz():
    ok = {"status": "healthy", "timestamp": datetime.utcnow().isoformat() + "Z", "version": APP_VERSION}
    return ok
# =========================
# SECTION 2/8: Layout, CSRF, Health, Auth (Login/Signup/Logout) + Legal/T&C Gate
# =========================

# ---- CSRF helpers (uniform, no false 403s) ----
def _csrf_ok() -> bool:
    """
    Centralized POST form CSRF check.
    If Flask-WTF is enabled, validate; otherwise allow (safe default for server-side forms).
    """
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
    """
    Jinja helper for embedding a CSRF value into forms.
    """
    if HAS_CSRF:
        try:
            from flask_wtf.csrf import generate_csrf
            return generate_csrf()
        except Exception:
            return ""
    return ""

# ---- Terms & Conditions (T&C) gate ----
TERMS_VERSION = os.environ.get("TERMS_VERSION", "2025-09-01")  # bump when Terms text is updated

def _terms_accepted(user: dict | None) -> bool:
    """
    Returns True if the given user has accepted the latest TERMS_VERSION.
    """
    if not user:
        return False
    return (user.get("terms_accept_version") == TERMS_VERSION)

def _mark_terms_accepted(user_id: str):
    """
    Persist the acceptance for a user (version + timestamp).
    """
    try:
        _update_user(user_id, {
            "terms_accept_version": TERMS_VERSION,
            "terms_accept_ts": datetime.utcnow().isoformat(timespec="seconds") + "Z"
        })
    except Exception as e:
        logger.warning("Failed to persist terms acceptance: %s", e)

def _current_user() -> dict | None:
    """
    Convenience accessor for the currently logged-in user record.
    """
    email = session.get("email", "")
    return _find_user(email) if email else None

def _redirect_if_terms_needed(next_url: str = "/") -> Response | None:
    """
    If user is logged in but hasn't accepted the latest terms, force the /legal/accept step.
    Returns a redirect Response or None (if OK).
    """
    u = _current_user()
    if not u:
        return None
    if not _terms_accepted(u):
        # send to accept page; after acceptance, user returns to 'next_url'
        return redirect(url_for("legal_accept_page", next=next_url))
    return None

# ---- Plan badge labeling (used in navbar) ----
def _plan_badge_text(sub):
    return {"monthly": "Monthly", "sixmonth": "6-Month"}.get(sub, "Inactive")

# ---- Base layout (navbar + footer disclaimer) ----
def base_layout(title: str, body_html: str) -> str:
    """
    Shared layout wrapper with a top navbar and a global footer.
    Adds a short, clear liability disclaimer site-wide (per legal guidance).
    """
    user_name = session.get('name', '')
    user_email = session.get('email', '')
    is_logged_in = 'user_id' in session
    csrf_value = csrf_token()

    # Logged-in menu (with plan badge)
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

    # Staging banner (optional)
    stage_banner = ("""
      <div class="alert alert-warning alert-dismissible fade show m-0" role="alert">
        <div class="container text-center">
          <strong>STAGING ENVIRONMENT</strong> - Not for production use.
          <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
      </div>
    """ if IS_STAGING else "")

    # Global, concise legal disclaimer footer (appears on every page)
    footer_disclaimer = f"""
    <footer class="bg-light py-4 mt-5 border-top">
      <div class="container">
        <div class="row align-items-center gy-2">
          <div class="col-md-8">
            <small class="text-muted">
              <strong>Disclaimer:</strong> Education use only; not legal/professional advice. Not affiliated with ASIS.
              No refunds once purchased. See <a class="text-decoration-underline" href="/legal/terms">Terms</a>.
            </small>
          </div>
          <div class="col-md-4 text-md-end">
            <small class="text-muted">Version {html.escape(APP_VERSION)}</small>
          </div>
        </div>
      </div>
    </footer>
    """

    # Quick page styles
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
      {footer_disclaimer}
      <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
    </body></html>"""

# ---- Health ----
@app.get("/healthz")
def healthz():
    ok = {"status": "healthy", "timestamp": datetime.utcnow().isoformat() + "Z", "version": APP_VERSION}
    return ok

# ---- Legal: Full Terms page (static text rendered server-side) ----
@app.get("/legal/terms")
def legal_terms_page():
    """
    Renders the full Terms & Conditions (content text stored separately or inline).
    This endpoint name MUST be unique and defined only once across the codebase.
    """
    # Minimal placeholder; you can replace with a file read/render if desired.
    # Title and body convey the legal text that was provided separately.
    body = """
    <div class="container">
      <div class="row justify-content-center"><div class="col-lg-10">
        <div class="card">
          <div class="card-header bg-dark text-white">
            <h3 class="mb-0"><i class="bi bi-journal-text me-2"></i>Terms &amp; Conditions</h3>
          </div>
          <div class="card-body">
            <p class="text-muted small mb-3">Last updated: {date}</p>
            <div class="mb-3">
              <p>Welcome to CPP-Exam-Prep. These Terms &amp; Conditions are a binding agreement between you and CPP-Exam-Prep...</p>
              <p class="mb-0">For the complete text, please refer to the official Terms content maintained by the site owner.</p>
            </div>
            <a href="/" class="btn btn-outline-secondary"><i class="bi bi-house me-1"></i>Home</a>
          </div>
        </div>
      </div></div>
    </div>
    """.format(date=datetime.utcnow().date().isoformat())
    return base_layout("Terms & Conditions", body)

# ---- Legal: Acceptance step (hard gate after login if needed) ----
@app.route("/legal/accept", methods=["GET", "POST"])
@login_required
def legal_accept_page():
    """
    One-time acceptance step shown after login if the user hasn't accepted latest TERMS_VERSION.
    """
    nxt = request.args.get("next") or request.form.get("next") or "/"
    user = _current_user()
    if not user:
        # If somehow no user, go to login
        return redirect(url_for("login_page", next=nxt))

    # If already accepted current version, go to next
    if _terms_accepted(user):
        return redirect(nxt)

    msg = ""
    if request.method == "POST":
        if not _csrf_ok():
            abort(403)
        agree = request.form.get("agree") == "on"
        if not agree:
            msg = "You must agree to the Terms & Conditions to continue."
        else:
            _mark_terms_accepted(user.get("id"))
            return redirect(nxt)

    csrf_val = csrf_token()
    body = f"""
    <div class="container"><div class="row justify-content-center"><div class="col-lg-7">
      <div class="card">
        <div class="card-header bg-warning text-dark">
          <h3 class="mb-0"><i class="bi bi-shield-lock me-2"></i>Accept Terms &amp; Conditions</h3>
        </div>
        <div class="card-body">
          {"<div class='alert alert-danger'>" + html.escape(msg) + "</div>" if msg else ""}
          <p class="mb-2">
            Please review our <a href="/legal/terms" target="_blank" rel="noopener">Terms &amp; Conditions</a>.
            To continue using your account, you must accept the current terms (version {html.escape(TERMS_VERSION)}).
          </p>
          <form method="POST">
            <input type="hidden" name="csrf_token" value="{csrf_val}"/>
            <input type="hidden" name="next" value="{html.escape(nxt)}"/>
            <div class="form-check mb-3">
              <input class="form-check-input" type="checkbox" id="agreeBox" name="agree">
              <label class="form-check-label" for="agreeBox">
                I have read and agree to the Terms &amp; Conditions.
              </label>
            </div>
            <button class="btn btn-primary" type="submit"><i class="bi bi-check2-circle me-1"></i>Accept &amp; Continue</button>
            <a class="btn btn-outline-secondary ms-2" href="/logout"><i class="bi bi-box-arrow-right me-1"></i>Logout</a>
          </form>
        </div>
      </div>
    </div></div></div>
    """
    return base_layout("Accept Terms", body)

# ---- Auth: Login / Signup / Logout ----
@app.get("/login")
def login_page():
    # If already logged in, ensure terms or redirect to accept, else go home
    if 'user_id' in session:
        redir = _redirect_if_terms_needed(next_url=url_for('home'))
        return redir or redirect(url_for('home'))

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

    email = (request.form.get('email') or '').strip().lower()
    password = request.form.get('password') or ''

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

        # Hard T&C gate: if not accepted latest version, force one-time accept
        if not _terms_accepted(user):
            nxt = request.args.get("next") or url_for('home')
            return redirect(url_for('legal_accept_page', next=nxt))

        logger.info(f"User logged in: {email}")
        return redirect(url_for('home'))

    logger.warning(f"Failed login attempt: {email}")
    return redirect(url_for('login_page'))

@app.get("/signup")
def signup_page():
    # Hard gate appears on signup form as a required checkbox (server-validated).
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
            <div class="mb-3">
              <label class="form-label fw-semibold">Discount Code (optional)</label>
              <input type="text" class="form-control" name="discount_code" placeholder="betatester2025 or cppclass2025">
              <div class="form-text">If you have a promo code, enter it here.</div>
            </div>
            <div class="form-check mb-4">
              <input class="form-check-input" type="checkbox" id="agreeTerms" name="agree_terms" required>
              <label class="form-check-label" for="agreeTerms">
                I agree to the <a href="/legal/terms" target="_blank" rel="noopener">Terms &amp; Conditions</a>.
              </label>
            </div>
            <button type="submit" class="btn btn-success btn-lg w-100">
              <i class="bi bi-rocket-takeoff me-2"></i>Create Account & Start Learning
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

    name = (request.form.get('name') or '').strip()
    email = (request.form.get('email') or '').strip().lower()
    password = request.form.get('password') or ''
    plan = (request.form.get('plan') or 'monthly').strip()
    discount_code = (request.form.get('discount_code') or '').strip()
    agreed = (request.form.get('agree_terms') == 'on')

    if not name or not email or not password:
        return redirect(url_for('signup_page'))
    if not validate_email(email):
        return redirect(url_for('signup_page'))
    if len(password) < 8:
        return redirect(url_for('signup_page'))
    if not agreed:
        # Must agree to Terms to create account
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
        # record T&C acceptance at sign-up
        "terms_accept_version": TERMS_VERSION,
        "terms_accept_ts": datetime.utcnow().isoformat(timespec="seconds") + "Z",
    }
    USERS.append(user)
    _save_json("users.json", USERS)

    try:
        session.regenerate()
    except AttributeError:
        session.clear(); session.permanent = True
    session['user_id'] = user['id']; session['email'] = user['email']; session['name'] = user['name']

    # Proceed to Stripe Checkout (discount code handled there)
    checkout_url = create_stripe_checkout_session(user_email=email, plan=plan, discount_code=discount_code)
    if checkout_url:
        return redirect(checkout_url)
    # fallback: go through checkout route (preserves code via query)
    return redirect(url_for('billing_checkout', plan=plan, code=discount_code))

@app.post("/logout")
def logout():
    if not _csrf_ok():
        abort(403)
    session.clear()
    return redirect(url_for('login_page'))
# =========================
# SECTION 3/8: Home, Study Alias, Tutor (AI), Minimal Analytics
# =========================

# NOTE:
# - Section 2 defines auth, csrf_token(), base_layout(), login_required, is_admin, etc.
# - Section 4 defines quiz/mock engines and _all_normalized_questions() used by the tutor suggestions here.
# - Section 7 will override _call_tutor_agent() to add web-aware grounding & citations. This section provides
#   the baseline, safe implementation that is fully functional even without the override.

# ---------- Domain labels (defensive: only define if missing) ----------
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

# ---------- Minimal analytics & recent history utilities ----------
def _log_event(user_id: str, event_type: str, payload: dict):
    """Append a small analytics record to data/events.json. Best-effort; never raises."""
    try:
        data = _load_json("events.json", [])
        data.append({
            "id": str(uuid.uuid4()),
            "ts": datetime.utcnow().isoformat() + "Z",
            "user_id": user_id,
            "type": event_type,
            "payload": payload or {}
        })
        _save_json("events.json", data)
    except Exception as e:
        logger.warning("log_event failed: %s", e)

def _append_user_history(user_id: str, channel: str, item: dict, keep_last: int = 20):
    """Per-user short history (e.g., last tutor Q/A) in data/history_{channel}_{user}.json."""
    try:
        key = f"history_{channel}_{user_id}.json"
        history = _load_json(key, [])
        history.append(item or {})
        history = history[-int(keep_last):]
        _save_json(key, history)
    except Exception as e:
        logger.warning("append_user_history failed: %s", e)

def _get_user_history(user_id: str, channel: str, limit: int = 5) -> list[dict]:
    try:
        key = f"history_{channel}_{user_id}.json"
        hist = _load_json(key, [])
        if limit and isinstance(limit, int):
            return hist[-limit:]
        return hist
    except Exception:
        return []

@app.before_request
def _track_page_views():
    """Very light page view tracking (path/method)."""
    try:
        uid = session.get("user_id") or session.get("email") or "anon"
        _log_event(uid, "page.view", {"path": request.path, "method": request.method})
    except Exception:
        pass

# ---------- Tutor agent (baseline). Section 7 provides an override w/ grounding ----------
def _call_tutor_agent(user_query: str, meta: dict | None = None) -> tuple[bool, str, dict]:
    """
    Baseline agent caller. This function is intentionally simple here and
    will be *overridden* in Section 7 to support bank-grounded citations.

    Returns: (ok: bool, answer: str, meta: dict)
    """
    meta = meta or {}
    timeout_s = float(os.environ.get("TUTOR_TIMEOUT", "45"))
    temperature = float(os.environ.get("TUTOR_TEMP", "0.3"))
    max_tokens = int(os.environ.get("TUTOR_MAX_TOKENS", "800"))
    system_msg = os.environ.get(
        "TUTOR_SYSTEM_PROMPT",
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

# ---------- Suggested Tutor Questions (sidebar helpers) ----------
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
    pool = (SUGGESTED_QUESTION_BANK.get(dk, []) or [])[:]
    random.shuffle(pool)
    return pool[:n]

def _suggested_questions_for_domain(domain_key: str | None, k: int = 4) -> list[dict]:
    """
    Advanced suggestions that pull from normalized questions (Section 4 provides _all_normalized_questions()).
    Fallback to static SUGGESTED_QUESTION_BANK when insufficient content.
    """
    try:
        k = max(1, min(int(k), 8))
    except Exception:
        k = 4

    out, seen = [], set()
    try:
        # Prefer actual question stems to mirror bank content
        pool = _all_normalized_questions()  # defined in Section 4
        if domain_key and domain_key != "random":
            dk = str(domain_key).strip().lower()
            pool = [q for q in pool if str(q.get("domain") or "").strip().lower() == dk]
        random.shuffle(pool)
        for q in pool:
            t = (q.get("text") or "").strip()
            if not t or t in seen:
                continue
            seen.add(t)
            out.append({"text": t, "domain": (q.get("domain") or "Unspecified")})
            if len(out) >= k:
                break
    except Exception:
        out = []

    # Top up from static prompts if needed
    if len(out) < k:
        picks = get_suggested_questions(domain_key, n=(k - len(out)))
        for p in picks:
            if p in seen:
                continue
            seen.add(p)
            out.append({"text": p, "domain": domain_key or "Unspecified"})
    return out

# ---------- Route: Home / Dashboard ----------
@app.get("/")
def home():
    """
    For visitors (logged-out): show the Welcome/Disclaimer hero with clear CTA.
    For logged-in users: show a simple dashboard of study modes.
    NOTE: Terms acceptance gating is enforced in Section 2 during signup/login and /legal/accept flow.
    """
    if 'user_id' not in session:
        body = """
        <div class="container text-center">
          <div class="mb-5">
            <i class="bi bi-mortarboard text-primary display-1 mb-4"></i>
            <h1 class="display-4 fw-bold">Master the CPP Exam</h1>
            <p class="lead text-muted">Independent study tools: AI tutor, quizzes, flashcards, and progress tracking.</p>
          </div>
          <div class="alert alert-warning text-start mx-auto" style="max-width:860px">
            <div class="fw-semibold mb-1">Disclaimer</div>
            <div class="small">
              This platform is independent and not affiliated with ASIS International. We don’t distribute proprietary ASIS content.
              Content is educational only and may be incomplete or inaccurate. Use official sources to verify.
              <a href="/legal/terms" class="fw-semibold">Read Terms &amp; Conditions</a>.
            </div>
          </div>
          <div class="d-flex justify-content-center gap-3 mb-4">
            <a href="/signup" class="btn btn-primary btn-lg px-4"><i class="bi bi-rocket-takeoff me-2"></i>Start Learning</a>
            <a href="/login" class="btn btn-outline-primary btn-lg px-4"><i class="bi bi-box-arrow-in-right me-2"></i>Sign In</a>
          </div>
          <div class="row g-3 mt-2">
            <div class="col-md-4">
              <div class="card h-100"><div class="card-body text-center p-4">
                <i class="bi bi-robot display-6 text-primary mb-3"></i>
                <h5>AI Study Tutor</h5><p class="text-muted small mb-0">Clear explanations with references.</p>
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

    # Logged-in dashboard
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

# ---------- Tutor page ----------
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
        if not user_query:
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
            else:
                tutor_error = answer
                _log_event(user_id, "tutor.ask", {"q_len": len(user_query), "ok": False})

    recent = _get_user_history(user_id, "tutor", limit=5)
    csrf_val = csrf_token()

    def _fmt(txt: str) -> str:
        return html.escape(txt or "").replace("\n","<br>")

    # History render
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

    # Domain button block (Section 1 defines domain_buttons_html)
    domain_buttons = domain_buttons_html(selected_key=selected_domain, field_name="domain")

    # Randomized suggestions for sidebar
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

        <!-- Suggestions sidebar -->
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
      // Domain buttons toggle
      (function(){{
        var hidden = document.getElementById('domain_val');
        document.querySelectorAll('.domain-btn').forEach(function(btn){{
          btn.addEventListener('click', function(){{
            document.querySelectorAll('.domain-btn').forEach(function(b){{ b.classList.remove('active'); }});
            btn.classList.add('active');
            if (hidden) hidden.value = btn.getAttribute('data-value');
          }});
        }});
      }})();
      // Auto-submit suggestion
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

# ---------- Tutor connectivity test ----------
@app.get("/tutor/ping")
@login_required
def tutor_ping():
    ok, answer, meta = _call_tutor_agent("Reply 'pong' only.", meta={"ping": True})
    return jsonify({"ok": bool(ok), "answer_preview": (answer or "")[:200], "meta": meta}), (200 if ok else 502)
# =========================
# SECTION 4/8: Quiz & Mock Exam (domain & count pickers, safe handling)
# =========================

# ---------- Runtime normalization & helpers ----------
def _infer_qtype(text: str, options: dict) -> str:
    """
    Heuristic to classify question type for analytics/labels:
    - 'scenario' if stem begins with 'Scenario:' (case-insensitive)
    - 'tf' if the set of choices maps clearly to True/False (any order)
    - else 'mcq'
    """
    stem = (text or "").strip().lower()
    if stem.startswith("scenario:"):
        return "scenario"
    # Check for T/F-like options (robust to minor formatting)
    vals = {str((options or {}).get(k, "")).strip().lower() for k in ("A", "B", "C", "D")}
    tf_syn = {"true", "false", "t", "f", "yes", "no"}
    # If both a 'true/yes' and a 'false/no' appear and no other non-empty distractors, treat as tf
    has_true = any(v in {"true", "t", "yes"} for v in vals)
    has_false = any(v in {"false", "f", "no"} for v in vals)
    if has_true and has_false and (len({v for v in vals if v}) <= 4):
        # Still prefer MCQ unless it's clearly T/F: require at least 2 of the 4 to be empty or 'n/a'
        na_like = {"", "n/a", "not applicable", "none", "—", "-", "na"}
        empties = sum(1 for v in vals if v in na_like)
        if empties >= 2:
            return "tf"
    return "mcq"


def _normalize_question_runtime(q, idx=None):
    """
    Converts a legacy/base/bank question into a uniform runtime dict:
    {
      "id": str,
      "text": "...",
      "domain": "...",
      "choices": [{"key":"A","text":"..."}, ...],
      "correct_key": "A",
      "qtype": "mcq" | "tf" | "scenario"
    }
    """
    if not q:
        return None

    qid = str(q.get("id") or idx or uuid.uuid4())
    text = (q.get("question") or q.get("q") or q.get("stem") or q.get("text") or "").strip()
    if not text:
        return None

    domain = (q.get("domain") or q.get("category") or q.get("section") or "Unspecified")

    opts = q.get("options") or q.get("choices") or {}
    if not isinstance(opts, dict):
        return None

    letters = ["A", "B", "C", "D"]
    # All four letters must exist; keep exactly A..D to stay consistent with grader/UI
    for L in letters:
        if L not in opts:
            return None

    choices = [{"key": L, "text": str(opts[L])} for L in letters]

    correct = q.get("correct") or q.get("answer") or q.get("correct_key")
    if isinstance(correct, str) and correct.upper() in letters:
        correct_key = correct.upper()
    else:
        return None

    qtype = _infer_qtype(text, opts)

    return {
        "id": qid,
        "text": text,
        "domain": domain,
        "choices": choices,
        "correct_key": correct_key,
        "qtype": qtype
    }


def _all_normalized_questions():
    """
    Merge legacy QUESTIONS + BASE_QUESTIONS into normalized runtime items.
    BASE_QUESTIONS comes from Section 1 starter content; bank content is added/merged upstream.
    """
    src = (ALL_QUESTIONS or [])
    out = []
    for i, q in enumerate(src):
        nq = _normalize_question_runtime(q, idx=i)
        if nq:
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

    # per-domain stats
    domain_stats = {}
    # per-type stats (mcq/tf/scenario)
    type_stats = {"mcq": {"correct": 0, "total": 0},
                  "tf": {"correct": 0, "total": 0},
                  "scenario": {"correct": 0, "total": 0}}

    for q in qset:
        qid = q["id"]
        user_key = answers.get(qid)
        is_ok = (q.get("correct_key") and user_key == q["correct_key"])
        if is_ok:
            correct += 1

        dname = q.get("domain") or "Unspecified"
        qtype = q.get("qtype") or "mcq"

        ds = domain_stats.setdefault(dname, {"correct": 0, "total": 0})
        ds["total"] += 1
        if is_ok:
            ds["correct"] += 1

        ts = type_stats.setdefault(qtype, {"correct": 0, "total": 0})
        ts["total"] += 1
        if is_ok:
            ts["correct"] += 1

        details[qid] = {
            "user_key": user_key,
            "correct_key": q.get("correct_key"),
            "is_correct": bool(is_ok),
            "domain": dname,
            "qtype": qtype
        }
    return correct, total, details, domain_stats, type_stats


def _record_attempt(user_id, mode, run, results):
    try:
        attempts = _load_json("attempts.json", [])
        correct, total, _details, domain_stats, type_stats = results
        attempts.append({
            "id": str(uuid.uuid4()),
            "ts": datetime.utcnow().isoformat() + "Z",
            "user_id": user_id,
            "mode": mode,
            "count": total,
            "correct": correct,
            "score_pct": _percent(correct, total),
            "domains": domain_stats,
            "types": type_stats
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

    # Labels
    qtype_badge = {
        "mcq": "<span class='badge bg-primary'>MCQ</span>",
        "tf": "<span class='badge bg-secondary'>True/False</span>",
        "scenario": "<span class='badge bg-info text-dark'>Scenario</span>"
    }.get(q.get("qtype"), "<span class='badge bg-primary'>MCQ</span>")

    domain_label = html.escape(str(q.get("domain") or 'Unspecified'))

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
              <div class="mb-1">{html.escape(q['text'])}</div>
              <div class='text-muted small mt-1 d-flex align-items-center gap-2'>
                <span>Domain: <strong>{domain_label}</strong></span>
                <span>•</span>
                {qtype_badge}
              </div>
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
    correct, total, details, domain_stats, type_stats = results
    pct = _percent(correct, total)

    # Question review rows
    qrows = []
    for q in run.get("qset", []):
        qid = q["id"]
        d = details.get(qid, {})
        is_ok = d.get("is_correct")
        badge = "<span class='badge bg-success'>Correct</span>" if is_ok else "<span class='badge bg-danger'>Wrong</span>"
        user_k = d.get("user_key") or "—"
        corr_k = d.get("correct_key") or "—"
        qtype = (d.get("qtype") or "mcq").upper()
        qrows.append(f"""
          <tr>
            <td class="text-nowrap">{html.escape(d.get('domain','Unspecified'))}</td>
            <td>{html.escape(q['text'])}</td>
            <td class="text-center">{html.escape(qtype)}</td>
            <td class="text-center">{html.escape(user_k)}</td>
            <td class="text-center">{html.escape(corr_k)}</td>
            <td class="text-center">{badge}</td>
          </tr>
        """)
    qtable = "".join(qrows) or "<tr><td colspan='6' class='text-center text-muted'>No items.</td></tr>"

    # Domain table
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

    # Type table
    type_names = {"mcq": "Multiple Choice", "tf": "True/False", "scenario": "Scenario"}
    trows = []
    for key in ("mcq", "tf", "scenario"):
        stats = type_stats.get(key, {"correct": 0, "total": 0})
        c, t = stats.get("correct", 0), stats.get("total", 0)
        trows.append(f"""
          <tr>
            <td>{html.escape(type_names[key])}</td>
            <td class="text-center">{c}/{t}</td>
            <td class="text-center">{_percent(c,t)}%</td>
          </tr>
        """)
    ttable = "".join(trows)

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

            <div class="row g-3 mt-2">
              <div class="col-md-6">
                <div class="p-3 border rounded-3">
                  <div class="fw-semibold mb-2">By Question Type</div>
                  <div class="table-responsive">
                    <table class="table table-sm align-middle">
                      <thead><tr><th>Type</th><th class="text-center">Correct</th><th class="text-center">%</th></tr></thead>
                      <tbody>{ttable}</tbody>
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
                      <th class="text-center">Type</th>
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
    user = _find_user(session.get("email", ""))

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
            return _render_picker_page("Quiz", "/quiz", counts=[5, 10, 15, 20], include_domain=True)

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
        email = session.get("email", "")
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
    user = _find_user(session.get("email", ""))

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
            return _render_picker_page("Mock Exam", "/mock-exam", counts=[25, 50, 75, 100], include_domain=True)

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
        email = session.get("email", "")
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
# SECTION 5/8: Flashcards, Progress, Usage, Billing/Stripe (+ debug), Admin auth tools
# =========================

# ---------- FLASHCARDS ----------
def _normalize_flashcard(item):
    """
    Accepts shapes like:
      {"front":"...", "back":"...", "domain":"...", "sources":[{"title": "...", "url":"..."}]}
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

    # legacy file
    for fc in (FLASHCARDS or []):
        n = _normalize_flashcard(fc)
        if not n:
            continue
        key = (n["front"], n["back"], n["domain"])
        if key in seen:
            continue
        seen.add(key)
        out.append(n)

    # bank file (preferred)
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
    return [c for c in cards if str(c.get("domain", "")).strip().lower() == dk]

@app.route("/flashcards", methods=["GET", "POST"])
@login_required
def flashcards_page():
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
        document.getElementById('idx').textContent = (total ? idx+1 : 0);
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
      document.getElementById('flipBtn').addEventListener('click', flip);
      document.getElementById('nextBtn').addEventListener('click', next);
      document.getElementById('prevBtn').addEventListener('click', prev);
      show(i);
    }})();
    </script>
    """
    try:
        _log_event(_user_id(), "flashcards.start", {"count": len(cards), "domain": domain})
        # Usage tracking: count session as 1
        increment_usage(session.get("email",""), "flashcards", 1)
    except Exception:
        pass
    return base_layout("Flashcards", content)


# ---------- PROGRESS ----------
@app.get("/progress")
@login_required
def progress_page():
    uid = _user_id()
    attempts = [a for a in _load_json("attempts.json", []) if a.get("user_id") == uid]
    attempts.sort(key=lambda x: x.get("ts", ""), reverse=True)

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


# ---------- USAGE DASHBOARD ----------
@app.get("/usage")
@login_required
def usage_dashboard():
    email = session.get("email", "")
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
    If a discount_code is provided, look up an active Promotion Code in Stripe and apply it.
    """
    try:
        # Optional: resolve a Promotion Code (promo_...) from a human-readable code
        discounts_param = None
        if discount_code:
            try:
                pc = stripe.PromotionCode.list(code=discount_code.strip(), active=True, limit=1)
                if pc and pc.get("data"):
                    promo_id = pc["data"][0]["id"]
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
                discounts=discounts_param,
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
                discounts=discounts_param,
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
    user = _find_user(session.get("email", ""))
    sub = user.get("subscription", "inactive") if user else "inactive"
    names = {"monthly": "Monthly Plan", "sixmonth": "6-Month Plan", "inactive": "Free Plan"}

    if sub == 'inactive':
        # Discount code UI lives only on Billing page; appended to checkout links via JS
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
                var code = (document.getElementById('discount_code')||{{value:''}}).value.trim();
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
                  // NOP: user still needs to click a plan button; this just keeps the code in the field
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
    plan = request.args.get("plan", "monthly")
    user_email = session.get("email", "")
    if not user_email:
        return redirect(url_for("login_page"))

    discount_code = (request.args.get("code") or "").strip()
    url = create_stripe_checkout_session(user_email, plan=plan, discount_code=discount_code)
    if url:
        return redirect(url)
    return redirect(url_for("billing_page"))

@app.get("/billing/success")
@login_required
def billing_success():
    session_id = request.args.get("session_id")
    plan = request.args.get("plan", "monthly")
    if session_id:
        try:
            cs = stripe.checkout.Session.retrieve(session_id, expand=["customer", "subscription"])
            meta = cs.get("metadata", {}) if isinstance(cs, dict) else getattr(cs, "metadata", {}) or {}
            email = meta.get("user_email") or session.get("email")
            u = _find_user(email or "")
            if u:
                updates: Dict[str, Any] = {}
                if plan == "monthly":
                    updates["subscription"] = "monthly"
                    cid = (cs.get("customer") if isinstance(cs, dict) else getattr(cs, "customer", None)) or u.get("stripe_customer_id")
                    updates["stripe_customer_id"] = cid
                elif plan == "sixmonth":
                    updates["subscription"] = "sixmonth"
                    expiry = datetime.utcnow() + timedelta(days=int(meta.get("duration_days", 180) or 180))
                    updates["subscription_expires_at"] = expiry.isoformat() + "Z"
                    cid = (cs.get("customer") if isinstance(cs, dict) else getattr(cs, "customer", None)) or u.get("stripe_customer_id")
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
        "STRIPE_WEBHOOK_SECRET_present": bool(STRIPE_WEBHOOK_SECRET),
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

@app.route("/admin/reset-password", methods=["GET", "POST"])
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

# NOTE:
# The admin content ingestion API and the bank acceptance checker UI
# live in SECTION 6/8 to avoid duplicate endpoint definitions.
# =========================
# SECTION 6/8: Content ingestion helpers, whitelists, hashing, normalization,
#              question typing, targets, and bank citation utilities
# =========================

from urllib.parse import urlparse

# -------- Source whitelist (public/government/standards; no proprietary ASIS) --------
ALLOWED_SOURCE_DOMAINS = {
    # Government & standards (non-proprietary)
    "nist.gov", "cisa.gov", "fema.gov", "osha.gov", "gao.gov",
    # Research & practice
    "popcenter.asu.edu",      # POP Center
    "ncpc.org",               # National Crime Prevention Council
    "fbi.gov",
    "rand.org",
    "hsdl.org",               # Homeland Security Digital Library
    "nfpa.org",               # summaries allowed (no paywalled text)
    "iso.org",                # summaries only
    # Public After-Action / official city/state sites
    "ca.gov", "ny.gov", "tx.gov", "wa.gov", "mass.gov", "phila.gov", "denvergov.org",
    "boston.gov", "chicago.gov", "seattle.gov", "sandiego.gov", "lacounty.gov",
    "ready.gov"               # FEMA/ICS public summaries & guidance
}
# NOTE: Wikipedia intentionally NOT allowed.

def _url_domain_ok(url: str) -> bool:
    """
    Return True if URL domain is in the allowed whitelist.
    """
    try:
        d = urlparse((url or "").strip()).netloc.lower()
        if not d:
            return False
        return any(d == dom or d.endswith("." + dom) for dom in ALLOWED_SOURCE_DOMAINS)
    except Exception:
        return False

def _validate_sources(sources: list) -> tuple[bool, str]:
    """
    Enforce 1–3 sources; each must have title + URL; URL domain must be whitelisted.
    """
    if not isinstance(sources, list) or not (1 <= len(sources) <= 3):
        return False, "Each item must include 1–3 sources."
    for s in sources:
        if not isinstance(s, dict):
            return False, "Source entries must be objects with title and url."
        t = (s.get("title") or "").strip()
        u = (s.get("url") or "").strip()
        if not t or not u:
            return False, "Source requires non-empty title and url."
        if not _url_domain_ok(u):
            return False, f"URL domain not allowed: {u}"
    return True, ""

# -------- Hashing & de-dup index helpers --------
def _item_hash_flashcard(front: str, back: str, domain: str, sources: list) -> str:
    """
    Deterministic hash for a flashcard.
    """
    blob = json.dumps({
        "k": "fc",
        "front": (front or "").strip().lower(),
        "back": (back or "").strip().lower(),
        "domain": (domain or "Unspecified").strip().lower(),
        "srcs": [{"t": (s.get("title","").strip().lower()),
                  "u": (s.get("url","").strip().lower())} for s in (sources or [])]
    }, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()

def _item_hash_question(question: str, options: dict, correct: str, domain: str, sources: list) -> str:
    """
    Deterministic hash for a question (4-choice MCQ schema).
    """
    ordered = {k: str((options or {}).get(k,"")).strip().lower() for k in ["A","B","C","D"]}
    blob = json.dumps({
        "k": "q",
        "q": (question or "").strip().lower(),
        "opts": ordered,
        "correct": (correct or "").strip().upper(),
        "domain": (domain or "Unspecified").strip().lower(),
        "srcs": [{"t": (s.get("title","").strip().lower()),
                  "u": (s.get("url","").strip().lower())} for s in (sources or [])]
    }, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()

def _load_content_index():
    return _load_json("bank/content_index.json", {})

def _save_content_index(idx: dict):
    _save_json("bank/content_index.json", idx or {})

# -------- Bank file read/write helpers --------
def _bank_read_flashcards() -> list:
    return _load_json("bank/cpp_flashcards_v1.json", [])

def _bank_read_questions() -> list:
    return _load_json("bank/cpp_questions_v1.json", [])

def _bank_write_flashcards(items: list):
    _save_json("bank/cpp_flashcards_v1.json", items or [])

def _bank_write_questions(items: list):
    _save_json("bank/cpp_questions_v1.json", items or [])

# -------- Normalize incoming shapes to bank schema --------
def _norm_bank_flashcard(fc_in: dict) -> tuple[dict | None, str]:
    """
    Input flexible keys -> output bank schema:
      { "front": str, "back": str, "domain": str, "sources": [{title,url},..] }
    """
    if not isinstance(fc_in, dict):
        return None, "Flashcard must be an object."
    front = (fc_in.get("front") or fc_in.get("q") or fc_in.get("term") or "").strip()
    back  = (fc_in.get("back") or fc_in.get("a") or fc_in.get("definition") or "").strip()
    domain = (fc_in.get("domain") or fc_in.get("category") or "Unspecified").strip()
    sources = fc_in.get("sources") or []
    if not front or not back:
        return None, "Flashcard needs front/back text."
    ok, msg = _validate_sources(sources)
    if not ok:
        return None, msg
    out = {"front": front, "back": back, "domain": domain, "sources": sources}
    return out, ""

def _norm_bank_question(q_in: dict) -> tuple[dict | None, str]:
    """
    Input flexible keys -> bank schema (4-choice MCQ):
    {
      "question": str,
      "options": {"A": "...","B": "...","C": "...","D": "..."},
      "correct": "A"|"B"|"C"|"D",
      "domain": str,
      "sources": [{title,url}]
    }

    True/False questions are represented as:
      options: {"A": "True", "B": "False", "C": "", "D": ""}
      correct: "A" or "B"

    Scenario questions are standard MCQs whose stem begins with "Scenario:" or similar.
    """
    if not isinstance(q_in, dict):
        return None, "Question must be an object."

    question = (q_in.get("question") or q_in.get("q") or q_in.get("stem") or "").strip()
    domain   = (q_in.get("domain") or q_in.get("category") or "Unspecified").strip()
    sources  = q_in.get("sources") or []

    # Options: accept dict or list
    raw_opts = q_in.get("options") or q_in.get("choices") or q_in.get("answers")
    opts: dict[str, str] = {}
    if isinstance(raw_opts, dict):
        for L in ["A","B","C","D"]:
            v = raw_opts.get(L) or raw_opts.get(L.lower())
            if v is None:
                return None, f"Missing option {L}"
            opts[L] = str(v)
    elif isinstance(raw_opts, list) and len(raw_opts) >= 4:
        letters = ["A","B","C","D"]
        for i, L in enumerate(letters):
            v = raw_opts[i]
            if isinstance(v, dict):
                opts[L] = str(v.get("text") or v.get("label") or v.get("value") or "")
            else:
                opts[L] = str(v)
    else:
        return None, "Options must provide 4 choices."

    # Correct can be a letter or a 1-based index
    correct = q_in.get("correct") or q_in.get("answer") or q_in.get("correct_key")
    if isinstance(correct, str) and correct.strip().upper() in ("A","B","C","D"):
        correct = correct.strip().upper()
    else:
        try:
            idx = int(correct)
            correct = ["A","B","C","D"][idx - 1]
        except Exception:
            return None, "Correct must be A/B/C/D or 1..4."

    ok, msg = _validate_sources(sources)
    if not ok:
        return None, msg
    if not question:
        return None, "Question text required."

    return {
        "question": question,
        "options": opts,
        "correct": correct,
        "domain": domain,
        "sources": sources
    }, ""

# -------- Question typing & targets (for Content Balance dashboards) --------
QUESTION_TYPES = ("MCQ", "TF", "SCENARIO")

def _classify_question_type(q: dict) -> str:
    """
    Heuristic classification:
      - TF: options look like True/False pair (C/D empty or duplicates)
      - SCENARIO: stem starts with "scenario:" or contains "what should ... do first"
      - default: MCQ
    """
    try:
        stem = (q.get("question") or "").strip().lower()
        opts = q.get("options") or {}
        a = (opts.get("A") or "").strip().lower()
        b = (opts.get("B") or "").strip().lower()
        c = (opts.get("C") or "").strip().lower()
        d = (opts.get("D") or "").strip().lower()

        # True/False patterns
        tf_words = {"true", "false", "t", "f"}
        if ((a in tf_words and b in tf_words) and (not c or c == a or c == b) and (not d or d == a or d == b)):
            return "TF"

        # Scenario patterns
        if stem.startswith("scenario:") or "what should the" in stem and "do first" in stem:
            return "SCENARIO"
        if stem.startswith("case:") or stem.startswith("incident:"):
            return "SCENARIO"
    except Exception:
        pass
    return "MCQ"

# Exact targets (total = 900; 50/25/25 split) — from the agreed blueprint
QUESTION_TARGETS = {
    "security-principles":  {"MCQ": 99, "TF": 50, "SCENARIO": 50},   # total 198
    "business-principles":  {"MCQ": 99, "TF": 50, "SCENARIO": 50},   # total 198
    "investigations":       {"MCQ": 54, "TF": 27, "SCENARIO": 27},   # total 108
    "personnel-security":   {"MCQ": 45, "TF": 22, "SCENARIO": 22},   # total  90
    "physical-security":    {"MCQ": 90, "TF": 45, "SCENARIO": 45},   # total 180
    "information-security": {"MCQ": 27, "TF": 14, "SCENARIO": 14},   # total  54
    "crisis-management":    {"MCQ": 36, "TF": 18, "SCENARIO": 18},   # total  72
}

def _count_bank_by_domain_and_type() -> dict:
    """
    Returns:
      {
        "<domain>": {"MCQ": n, "TF": n, "SCENARIO": n, "TOTAL": n},
        ...
      }
    """
    counts: dict[str, dict] = {}
    bank_q = _bank_read_questions()
    for q in bank_q:
        dom = (q.get("domain") or "Unspecified").strip().lower()
        qtype = _classify_question_type(q)
        dd = counts.setdefault(dom, {"MCQ": 0, "TF": 0, "SCENARIO": 0, "TOTAL": 0})
        if qtype not in dd:
            dd[qtype] = 0
        dd[qtype] += 1
        dd["TOTAL"] += 1
    return counts

# -------- Tutor settings (persisted file; ENV can override) --------
def _load_tutor_settings():
    """
    Returns {"web_aware": bool}. Default is taken from ENV TUTOR_WEB_AWARE if present,
    otherwise the value stored in data/tutor_settings.json (default False).
    """
    return _load_json(
        "tutor_settings.json",
        {"web_aware": os.environ.get("TUTOR_WEB_AWARE", "0") == "1"}
    )

def _save_tutor_settings(cfg: dict):
    _save_json("tutor_settings.json", cfg or {})

def _tutor_web_enabled() -> bool:
    env = os.environ.get("TUTOR_WEB_AWARE")
    if env in ("0", "1"):
        return env == "1"
    return bool(_load_tutor_settings().get("web_aware", False))

# -------- Bank-source citation finder (uses only your ingested sources) --------
def _bank_all_sources():
    """
    Yields unique source dicts from bank files:
      {"title":..., "url":..., "domain":..., "from":"flashcard|question"}
    Only returns URLs whose domain is whitelisted by ALLOWED_SOURCE_DOMAINS.
    """
    seen = set()

    # From flashcards
    for fc in _bank_read_flashcards():
        for s in (fc.get("sources") or []):
            t = (s.get("title") or "").strip()
            u = (s.get("url") or "").strip()
            if not t or not u:
                continue
            if not _url_domain_ok(u):
                continue
            key = (t, u)
            if key in seen:
                continue
            seen.add(key)
            yield {"title": t, "url": u, "domain": urlparse(u).netloc.lower(), "from": "flashcard"}

    # From questions
    for q in _bank_read_questions():
        for s in (q.get("sources") or []):
            t = (s.get("title") or "").strip()
            u = (s.get("url") or "").strip()
            if not t or not u:
                continue
            if not _url_domain_ok(u):
                continue
            key = (t, u)
            if key in seen:
                continue
            seen.add(key)
            yield {"title": t, "url": u, "domain": urlparse(u).netloc.lower(), "from": "question"}

def _extract_keywords(text: str) -> set[str]:
    words = re.findall(r"[A-Za-z]{3,}", (text or "").lower())
    stop = {"the","and","for","with","from","this","that","into","over","under",
            "your","about","have","what","when","where","which"}
    return {w for w in words if w not in stop}

def _score_source(src, kw: set[str]) -> int:
    """
    Score by keyword overlap in title; small boost for .gov standards.
    """
    score = 0
    title_words = set(re.findall(r"[A-Za-z]{3,}", src["title"].lower()))
    score += len(title_words & kw) * 3
    if any(src["domain"].endswith(d) for d in ("nist.gov","cisa.gov","fema.gov","gao.gov","osha.gov")):
        score += 2
    return score

def _find_bank_citations(query: str, max_n: int = 3) -> list[dict]:
    """
    Returns up to `max_n` relevant sources from the ingested bank (flashcards/questions).
    Uses a simple keyword overlap scoring on titles with a small boost for .gov/standards.
    Output item shape: {"title": str, "url": str, "domain": str, "from": "flashcard"|"question"}
    """
    try:
        kw = _extract_keywords(query)
        candidates = []
        for src in _bank_all_sources():
            sc = _score_source(src, kw)
            if sc > 0:
                candidates.append((sc, src))

        # If nothing scored > 0, fall back to top N unique sources
        if not candidates:
            uniq = []
            seen = set()
            for src in _bank_all_sources():
                k = (src["title"], src["url"])
                if k in seen:
                    continue
                seen.add(k)
                uniq.append(src)
                if len(uniq) >= max_n:
                    break
            return uniq

        candidates.sort(key=lambda t: t[0], reverse=True)
        top = []
        seen_k = set()
        for _, src in candidates:
            k = (src["title"], src["url"])
            if k in seen_k:
                continue
            seen_k.add(k)
            top.append(src)
            if len(top) >= max_n:
                break
        return top
    except Exception as e:
        logger.warning("find_bank_citations failed: %s", e)
        return []
# =========================
# SECTION 7/8: Tutor (web-aware citations override) + settings UI
# =========================

def _format_citations_for_prompt(cites: list[dict]) -> str:
    """
    Turn a list of {"title","url","domain"} into a small text block we can show the model.
    """
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
    Override of the baseline agent:
      - If web-aware is OFF, behave like the base version (Section 3).
      - If web-aware is ON, include up to 3 best-matching ingested/whitelisted sources
        (no live web), instruct the model to align to those sources, and append
        a compact "References" section.
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
    sources: list[dict] = []
    sys_msg = base_system
    user_content = user_query

    if web_on:
        # Reuse the bank-only citation finder from Section 6
        try:
            sources = _find_bank_citations(user_query, max_n=3)
        except Exception:
            sources = []

        sys_msg = (
            base_system
            + "\n\nGROUNDING:\n"
              "- You are provided a short list of vetted sources (gov/standards/AAR style).\n"
              "- Answer using your expertise and align with these sources.\n"
              "- Keep answers concise and exam-focused."
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


@app.route("/admin/tutor-settings", methods=["GET", "POST"])
@login_required
def admin_tutor_settings_page():
    """
    Admin UI to toggle the Tutor's web-aware (bank-citations) mode.
    """
    if not is_admin():
        return redirect(url_for("admin_login_page", next=request.path))

    msg = ""
    cfg = _load_tutor_settings()
    if request.method == "POST":
        # CSRF: Flask-WTF will enforce when enabled; fallback minimal check when disabled
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
                Enable web-aware mode (use ingested sources for citations)
              </label>
            </div>
            <button class="btn btn-primary" type="submit"><i class="bi bi-save me-1"></i>Save</button>
            <a class="btn btn-outline-secondary ms-2" href="/"><i class="bi bi-house me-1"></i>Home</a>
          </form>
          <hr>
          <div class="small text-muted">
            When enabled, the Tutor grounds answers to sources ingested under <code>data/bank</code>.
            It never fetches the live internet; it only cites your vetted, whitelisted materials.
          </div>
        </div>
      </div>
    </div></div></div>
    """
    return base_layout("Tutor Settings", body)
# =========================
# SECTION 8/8: Startup, legal pages, polish (favicon/robots/404), health & __main__
# =========================

# ---- Legal: Terms & acceptance gate ----
TERMS_VERSION = globals().get("TERMS_VERSION", "2025-09-01")

@app.get("/legal/terms")
def legal_terms_page():
    """
    Render the Terms & Conditions page.
    NOTE: Keep this single definition to avoid duplicate endpoint errors.
    """
    # You can author full T&C content in a separate template/file if desired.
    # Here we provide a minimal shell; actual long-form text can be injected later.
    today_str = datetime.utcnow().strftime("%Y-%m-%d")
    body = f"""
    <div class="container">
      <div class="row justify-content-center"><div class="col-xl-10 col-lg-11">
        <div class="card">
          <div class="card-header bg-secondary text-white">
            <h3 class="mb-0"><i class="bi bi-file-text me-2"></i>Terms &amp; Conditions</h3>
          </div>
          <div class="card-body">
            <div class="text-muted mb-3">Last updated: {html.escape(TERMS_VERSION)} (viewed {html.escape(today_str)})</div>
            <p>Please review these Terms &amp; Conditions carefully. By creating an account,
            accessing, or using the Service, you agree to these Terms.</p>

            <hr>
            <p class="small text-muted mb-0">
              For questions, contact support at <a href="mailto:cpptestprep@gmail.com">cpptestprep@gmail.com</a>.
            </p>
          </div>
        </div>
        <div class="mt-3 text-center">
          <a href="/" class="btn btn-outline-secondary"><i class="bi bi-house me-1"></i>Home</a>
        </div>
      </div></div>
    </div>
    """
    return base_layout("Terms & Conditions", body)


@app.route("/legal/accept", methods=["GET", "POST"])
@login_required
def legal_accept_page():
    """
    One-time gate to record that the user accepted the latest TERMS_VERSION.
    If user is already at latest version, redirect to home.
    """
    user = _find_user(session.get("email", "")) or {}
    current_v = (user.get("terms_accept_version") or "").strip()
    if current_v == TERMS_VERSION:
        return redirect(url_for("home"))

    msg = ""
    if request.method == "POST":
        if not _csrf_ok():
            abort(403)
        agree = request.form.get("agree") == "on"
        if not agree:
            msg = "You must agree to continue."
        else:
            _update_user(user.get("id"), {
                "terms_accept_version": TERMS_VERSION,
                "terms_accept_ts": datetime.utcnow().isoformat(timespec="seconds") + "Z"
            })
            return redirect(url_for("home"))

    csrf_val = csrf_token()
    body = f"""
    <div class="container"><div class="row justify-content-center"><div class="col-lg-8">
      <div class="card">
        <div class="card-header bg-warning text-dark">
          <h3 class="mb-0"><i class="bi bi-shield-lock me-2"></i>Accept Terms &amp; Conditions</h3>
        </div>
        <div class="card-body">
          {"<div class='alert alert-danger'>" + html.escape(msg) + "</div>" if msg else ""}
          <p class="mb-3">To continue, please review and accept the latest Terms &amp; Conditions.</p>
          <p><a href="/legal/terms" target="_blank" rel="noopener">Open Terms &amp; Conditions in a new tab</a></p>
          <form method="POST">
            <input type="hidden" name="csrf_token" value="{csrf_val}"/>
            <div class="form-check mb-3">
              <input class="form-check-input" type="checkbox" id="agree" name="agree">
              <label class="form-check-label" for="agree">I have read and agree to the Terms &amp; Conditions</label>
            </div>
            <button class="btn btn-primary" type="submit"><i class="bi bi-check2-circle me-1"></i>Accept &amp; Continue</button>
            <a class="btn btn-outline-secondary ms-2" href="/logout">Cancel</a>
          </form>
        </div>
      </div>
    </div></div></div>
    """
    return base_layout("Accept Terms", body)


# ---- Favicon & robots.txt (polish) ----
# A tiny 16x16 ICO (single-color) to stop 404 noise; bytes generated once and embedded.
_FAVICON_BYTES = bytes.fromhex(
    "0000010001001010000001002000680400001600000028000000100000002000000001002000"
    "0000000040040000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    "FFFFFFFF"
)

@app.get("/favicon.ico")
def favicon():
    return Response(_FAVICON_BYTES, mimetype="image/x-icon")


@app.get("/robots.txt")
def robots_txt():
    body = "User-agent: *\nDisallow:\n"
    return Response(body, mimetype="text/plain")


# ---- 404 and 500 error pages ----
@app.errorhandler(404)
def not_found(e):
    content = """
    <div class="container">
      <div class="row justify-content-center"><div class="col-md-8">
        <div class="card">
          <div class="card-header bg-secondary text-white">
            <h3 class="mb-0"><i class="bi bi-question-circle me-2"></i>Page Not Found</h3>
          </div>
          <div class="card-body">
            <p class="text-muted mb-3">We couldn't find that page. Please check the address or go back home.</p>
            <a class="btn btn-primary" href="/"><i class="bi bi-house me-1"></i>Home</a>
          </div>
        </div>
      </div></div>
    </div>
    """
    return base_layout("Not Found", content), 404


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


# ---- App init, health, and entry point ----
def init_sample_data():
    """
    Ensure required folders/files exist so the app never 500s on first boot.
    Non-destructive: only creates files if missing.
    """
    try:
        # Base data dir
        os.makedirs(DATA_DIR, exist_ok=True)

        # Bank dir
        bank_dir = os.path.join(DATA_DIR, "bank")
        os.makedirs(bank_dir, exist_ok=True)

        # Core JSON stores (create if missing)
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

        # Bank files (create empty arrays if missing)
        if not os.path.exists(os.path.join(bank_dir, "cpp_flashcards_v1.json")):
            _save_json("bank/cpp_flashcards_v1.json", [])
        if not os.path.exists(os.path.join(bank_dir, "cpp_questions_v1.json")):
            _save_json("bank/cpp_questions_v1.json", [])
        if not os.path.exists(os.path.join(bank_dir, "content_index.json")):
            _save_json("bank/content_index.json", {})

        # Tutor settings (default OFF unless env overrides)
        tutor_path = os.path.join(DATA_DIR, "tutor_settings.json")
        if not os.path.exists(tutor_path):
            _save_json("tutor_settings.json", {"web_aware": os.environ.get("TUTOR_WEB_AWARE", "0") == "1"})

    except Exception as e:
        logger.warning("init_sample_data encountered an issue: %s", e)


@app.get("/healthz")
def healthz():
    ok = {"status": "healthy", "timestamp": datetime.utcnow().isoformat() + "Z", "version": APP_VERSION}
    return ok


def create_app():
    init_sample_data()
    logger.info("CPP Test Prep v%s starting up", APP_VERSION)
    logger.info("Debug mode: %s", DEBUG)
    logger.info("Staging mode: %s", IS_STAGING)
    logger.info("CSRF protection: %s", "enabled" if HAS_CSRF else "disabled")
    # quick config sanity in logs (no secrets)
    logger.info("Stripe monthly ID present: %s", bool(STRIPE_MONTHLY_PRICE_ID))
    logger.info("Stripe 6-month ID present: %s", bool(STRIPE_SIXMONTH_PRICE_ID))
    logger.info("Stripe webhook secret present: %s", bool(STRIPE_WEBHOOK_SECRET))
    logger.info("OpenAI key present: %s", bool(OPENAI_API_KEY))
    return app


if __name__ == "__main__":
    init_sample_data()
    port = int(os.environ.get("PORT", "5000"))
    logger.info("Running app on port %s", port)
    app.run(host="0.0.0.0", port=port, debug=DEBUG)
