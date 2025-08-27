# =========================
# CPP Test Prep - app.py
# SECTION 1/8: Imports, Config, Data IO, Security, Base Data
# =========================

# ----- Imports & Basic Config -----
from flask import (
    Flask, request, jsonify, session, redirect, url_for, Response, abort
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from functools import wraps
from datetime import datetime, timedelta
from contextlib import contextmanager
from typing import Dict, Any

import os, json, random, requests, html, uuid, logging, time, hashlib, re
import sqlite3
import stripe

# Optional CSRF import
try:
    from flask_wtf.csrf import CSRFProtect
    HAS_CSRF = True
except ImportError:
    HAS_CSRF = False

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

if HAS_CSRF:
    csrf = CSRFProtect(app)

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

# ----- Auth helpers -----
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated_function

def is_admin():
    return session.get("admin_ok") is True

def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

# ----- Users (file-backed) -----
def _find_user(email: str):
    if not email:
        return None
    el = email.strip().lower()
    for u in USERS:
        if (u.get("email","").strip().lower() == el):
            return u
    return None

def _find_user_by_id(user_id: str):
    for u in USERS:
        if u.get("id") == user_id:
            return u
    return None

def _update_user(user_id: str, updates: Dict[str, Any]) -> bool:
    for i, u in enumerate(USERS):
        if u.get("id") == user_id:
            USERS[i].update(updates)
            _save_json("users.json", USERS)
            return True
    return False

def validate_password(pw: str) -> tuple[bool, str]:
    if not pw or len(pw) < 8:
        return False, "Password must be at least 8 characters."
    return True, ""

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
                _save_json("users.json", USERS)
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
    user = _find_user(user_email)
    if not user:
        return
    today = datetime.utcnow()
    month_key = today.strftime('%Y-%m')
    usage = user.setdefault('usage', {})
    monthly = usage.setdefault('monthly', {})
    month_usage = monthly.setdefault(month_key, {})
    month_usage[action_type] = month_usage.get(action_type, 0) + count
    usage['last_active'] = today.isoformat(timespec="seconds") + "Z"
    _save_json("users.json", USERS)

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

DOMAINS = {
    "security-principles": "Security Principles & Practices",
    "business-principles": "Business Principles & Practices",
    "investigations": "Investigations",
    "personnel-security": "Personnel Security",
    "physical-security": "Physical Security",
    "information-security": "Information Security",
    "crisis-management": "Crisis Management",
}

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

def init_sample_data():
    # Placeholder to match create_app() call
    return
# =========================
# SECTION 2/8: Layout, CSRF, Health, Auth (Login/Signup/Logout)
# =========================

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
    if sub == 'monthly':
        return 'Monthly'
    if sub == 'sixmonth':
        return '6-Month'
    return 'Inactive'

def base_layout(title: str, body_html: str) -> str:
    user_name = session.get('name', '')
    user_email = session.get('email', '')
    is_logged_in = 'user_id' in session

    # fresh CSRF value for forms
    csrf_value = csrf_token()

    # top-right user menu
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
        <li class="nav-item">
          <a class="nav-link" href="/login">Login</a>
        </li>
        <li class="nav-item">
          <a class="nav-link btn btn-outline-primary ms-2" href="/signup">Create Account</a>
        </li>
        """

    # main navbar
    nav = f"""
    <nav class="navbar navbar-expand-lg navbar-light bg-gradient-primary sticky-top shadow-sm">
      <div class="container">
        <a class="navbar-brand fw-bold text-white" href="/">
          <i class="bi bi-shield-check text-warning"></i> CPP Test Prep
        </a>
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
            {user_menu}
          </ul>
        </div>
      </div>
    </nav>
    """

    # footer & staging banner
    disclaimer = f"""
    <footer class="bg-light py-4 mt-5 border-top">
      <div class="container">
        <div class="row">
          <div class="col-md-8">
            <small class="text-muted">
              <strong>Notice:</strong> This platform is independent and not affiliated with ASIS International.
              CPP&reg; is a mark of ASIS International, Inc.
            </small>
          </div>
          <div class="col-md-4 text-end">
            <small class="text-muted">Version {APP_VERSION}</small>
          </div>
        </div>
      </div>
    </footer>
    """
    stage_banner = (
        """
        <div class="alert alert-warning alert-dismissible fade show m-0" role="alert">
          <div class="container text-center">
            <strong>STAGING ENVIRONMENT</strong> - Not for production use.
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
          </div>
        </div>
        """ if IS_STAGING else ""
    )

    # styles
    style_css = """
    <style>
      :root {
        --primary-blue: #2563eb;
        --success-green: #059669;
        --warning-orange: #d97706;
        --danger-red: #dc2626;
        --purple-accent: #7c3aed;
        --soft-gray: #f8fafc;
        --warm-white: #fefefe;
        --text-dark: #1f2937;
        --text-light: #6b7280;
      }
      body {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
        background: linear-gradient(135deg, #f8fafc 0%, #e2e8f0 100%);
        color: var(--text-dark);
        line-height: 1.6;
      }
      .bg-gradient-primary { background: linear-gradient(135deg, var(--primary-blue) 0%, var(--purple-accent) 100%) !important; }
      .text-white-75 { color: rgba(255, 255, 255, 0.85) !important; }
      .text-white-75:hover { color: white !important; }
      .card {
        box-shadow: 0 4px 12px rgba(0,0,0,0.08);
        border: none;
        border-radius: 16px;
        background: var(--warm-white);
        transition: all 0.3s ease;
        overflow: hidden;
      }
      .card:hover { transform: translateY(-2px); box-shadow: 0 8px 24px rgba(0,0,0,0.12); }
      .btn { border-radius: 12px; font-weight: 600; letter-spacing: 0.025em; padding: 0.75rem 1.5rem; transition: all 0.2s ease; }
      .btn-primary { background: linear-gradient(135deg, var(--primary-blue), var(--purple-accent)); border: none; box-shadow: 0 4px 12px rgba(37, 99, 235, 0.25); }
      .btn-primary:hover { transform: translateY(-1px); box-shadow: 0 6px 20px rgba(37, 99, 235, 0.35); }
      .plan-monthly { background: linear-gradient(45deg, var(--primary-blue), var(--purple-accent)); color: white; }
      .plan-sixmonth { background: linear-gradient(45deg, var(--purple-accent), #8b5cf6); color: white; }
      .plan-inactive { background: #6b7280; color: white; }
      .alert { border-radius: 12px; border: none; padding: 1.25rem; }
      .alert-success { background: linear-gradient(135deg, #d1fae5, #a7f3d0); color: #065f46; border-left: 4px solid var(--success-green); }
      .alert-info { background: linear-gradient(135deg, #dbeafe, #bfdbfe); color: #1e3a8a; border-left: 4px solid var(--primary-blue); }
      .alert-warning { background: linear-gradient(135deg, #fef3c7, #fed7aa); color: #92400e; border-left: 4px solid var(--warning-orange); }
      .form-control, .form-select { border-radius: 10px; border: 2px solid #e5e7eb; padding: 0.75rem 1rem; transition: all 0.2s ease; }
      .form-control:focus, .form-select:focus { border-color: var(--primary-blue); box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.1); }
      .navbar-brand { font-size: 1.5rem; font-weight: 700; }
      .text-success { color: var(--success-green) !important; fill: var(--success-green); }
      .text-warning { color: var(--warning-orange) !important; fill: var(--warning-orange); }
      .text-danger  { color: var(--danger-red) !important; fill: var(--danger-red); }
      @media (max-width: 768px) {
        .container { padding: 0 20px; }
        .card { margin-bottom: 1.5rem; border-radius: 12px; }
        .btn { padding: 0.6rem 1.2rem; }
      }
    </style>
    """

    # inject CSRF in body templates if {{ csrf_token() }} literal appears
    body_html = body_html.replace('{{ csrf_token() }}', csrf_value)

    return f"""<!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <meta name="csrf-token" content="{csrf_value}">
      <title>{html.escape(title)} - CPP Test Prep</title>
      <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
      <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css" rel="stylesheet">
      <link rel="preconnect" href="https://fonts.googleapis.com">
      <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
      <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
      {style_css}
    </head>
    <body class="d-flex flex-column min-vh-100">
      {nav}
      {stage_banner}
      <main class="flex-grow-1 py-4">
        {body_html}
      </main>
      {disclaimer}
      <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
    </body>
    </html>"""

# ----- Health -----
@app.get("/healthz")
def healthz():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat(), "version": APP_VERSION}

# ----- Auth: Login/Signup/Logout -----
@app.get("/login")
def login_page():
    if 'user_id' in session:
        return redirect(url_for('home'))
    body = """
    <div class="container">
      <div class="row justify-content-center">
        <div class="col-md-6 col-lg-4">
          <div class="card shadow-lg">
            <div class="card-body p-4">
              <div class="text-center mb-4">
                <i class="bi bi-shield-check text-primary display-4 mb-3"></i>
                <h2 class="card-title fw-bold text-primary">Welcome Back</h2>
                <p class="text-muted">Sign in to continue your CPP journey</p>
              </div>
              <form method="POST" action="/login">
                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
                <div class="mb-3">
                  <label class="form-label fw-semibold">Email</label>
                  <input type="email" class="form-control" name="email" required placeholder="your.email@example.com">
                </div>
                <div class="mb-4">
                  <label class="form-label fw-semibold">Password</label>
                  <input type="password" class="form-control" name="password" required placeholder="Enter your password">
                </div>
                <button type="submit" class="btn btn-primary w-100 mb-3">Sign In</button>
              </form>
              <div class="text-center">
                <p class="text-muted mb-2">Don't have an account?</p>
                <a href="/signup" class="btn btn-outline-primary">Create Account</a>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
    """
    return base_layout("Sign In", body)

@app.post("/login")
def login_post():
    if _rate_limited("login", limit=5, per_seconds=300):
        return redirect(url_for('login_page'))

    email = request.form.get('email', '').strip().lower()
    password = request.form.get('password', '')

    if not email or not password:
        return redirect(url_for('login_page'))

    user = _find_user(email)
    if user and check_password_hash(user.get('password_hash', ''), password):
        try:
            session.regenerate()
        except AttributeError:
            session.clear()
            session.permanent = True
        session['user_id'] = user['id']
        session['email'] = user['email']
        session['name'] = user.get('name', '')
        logger.info(f"User logged in: {email}")
        return redirect(url_for('home'))

    logger.warning(f"Failed login attempt: {email}")
    return redirect(url_for('login_page'))

@app.get("/signup")
def signup_page():
    body = """
    <div class="container">
      <div class="row justify-content-center">
        <div class="col-lg-10">
          <div class="text-center mb-5">
            <i class="bi bi-mortarboard text-primary display-4 mb-3"></i>
            <h1 class="display-5 fw-bold text-primary">Start Your CPP Journey</h1>
            <p class="lead text-muted">Choose your path to certification success</p>
          </div>

          <div class="row mb-5">
            <div class="col-md-6 mb-4">
              <div class="card h-100 border-primary position-relative">
                <div class="card-header bg-primary text-white text-center">
                  <h4 class="mb-0">Monthly Plan</h4>
                </div>
                <div class="card-body text-center p-4">
                  <div class="mb-3">
                    <span class="display-4 fw-bold text-primary">$39.99</span>
                    <span class="text-muted fs-5">/month</span>
                  </div>
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
                <div class="card-header bg-success text-white text-center pt-4">
                  <h4 class="mb-0">6-Month Plan</h4>
                </div>
                <div class="card-body text-center p-4">
                  <div class="mb-3">
                    <div class="display-4 fw-bold text-success mb-1">$99.00</div>
                    <span class="text-muted fs-6">One-time payment</span>
                  </div>
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

          <div class="card shadow-lg">
            <div class="card-body p-4">
              <h3 class="card-title text-center mb-4">Create Your Account</h3>
              <form method="POST" action="/signup" id="signupForm">
                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
                <input type="hidden" name="plan" id="selectedPlan" value="monthly">
                <div class="row">
                  <div class="col-md-6 mb-3">
                    <label class="form-label fw-semibold">Full Name</label>
                    <input type="text" class="form-control" name="name" required placeholder="John Doe">
                  </div>
                  <div class="col-md-6 mb-3">
                    <label class="form-label fw-semibold">Email</label>
                    <input type="email" class="form-control" name="email" required placeholder="john@example.com">
                  </div>
                </div>
                <div class="mb-4">
                  <label class="form-label fw-semibold">Password</label>
                  <input type="password" class="form-control" name="password" required minlength="8" placeholder="At least 8 characters">
                  <div class="form-text">Choose a strong password with at least 8 characters</div>
                </div>
                <button type="submit" class="btn btn-success btn-lg w-100">
                  <i class="bi bi-rocket-takeoff me-2"></i>Create Account & Start Learning
                </button>
              </form>
            </div>
          </div>
        </div>
      </div>
    </div>

    <script>
      var selectedPlanType = 'monthly';
      function selectPlan(plan) {
        selectedPlanType = plan;
        var el = document.getElementById('selectedPlan');
        if (el) { el.value = plan; }
        var cards = document.querySelectorAll('.card.h-100');
        for (var i = 0; i < cards.length; i++) {
          cards[i].style.transform = 'none';
          cards[i].classList.remove('shadow-lg');
        }
        var selector = '[onclick="selectPlan(\\'' + plan + '\\')"]';
        var btn = document.querySelector(selector);
        if (btn) {
          var card = btn.closest('.card');
          if (card) {
            card.classList.add('shadow-lg');
            card.style.transform = 'translateY(-6px)';
          }
        }
      }
      selectPlan('monthly');
    </script>
    """
    return base_layout("Create Account", body)

@app.post("/signup")
def signup_post():
    name = request.form.get('name', '').strip()
    email = request.form.get('email', '').strip().lower()
    password = request.form.get('password', '')
    plan = (request.form.get('plan') or 'monthly').strip()

    if not name or not email or not password:
        return redirect(url_for('signup_page'))
    if not validate_email(email):
        return redirect(url_for('signup_page'))
    if len(password) < 8:
        return redirect(url_for('signup_page'))
    if _find_user(email):
        return redirect(url_for('signup_page'))

    user = {
        "id": str(uuid.uuid4()),
        "name": name,
        "email": email,
        "password_hash": generate_password_hash(password),
        "subscription": "inactive",
        "usage": {"monthly": {}, "last_active": ""},
        "created_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "history": []
    }
    USERS.append(user)
    _save_json("users.json", USERS)

    try:
        session.regenerate()
    except AttributeError:
        session.clear()
        session.permanent = True

    session['user_id'] = user['id']
    session['email'] = user['email']
    session['name'] = user['name']

    # This function is defined later in the Billing section (safe to call here).
    checkout_url = create_stripe_checkout_session(user_email=email, plan=plan) if 'create_stripe_checkout_session' in globals() else None
    if checkout_url:
        return redirect(checkout_url)
    return redirect(url_for('billing_checkout', plan=plan))

@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for('login_page'))
# =========================
# SECTION 3/8: Home, Study Alias, Tutor (AI), Minimal Analytics
# =========================

# ---------- Home / Dashboard ----------
@app.get("/")
def home():
    if 'user_id' not in session:
        # Public landing (concise but keeps your design tone)
        body = """
        <div class="container text-center">
          <div class="mb-5">
            <i class="bi bi-mortarboard text-primary display-1 mb-4"></i>
            <h1 class="display-4 fw-bold">Master the CPP Exam</h1>
            <p class="lead text-muted">AI tutor, practice quizzes, flashcards, and progress tracking.</p>
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

    # Minimal logged-in dashboard
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
    Calls your AI provider using env config.
    - OpenAI-compatible: OPENAI_API_KEY, OPENAI_API_BASE, OPENAI_CHAT_MODEL
    - Azure OpenAI: AZURE_OPENAI_ENDPOINT, AZURE_OPENAI_API_KEY, AZURE_OPENAI_DEPLOYMENT
    Returns: (ok: bool, answer: str, meta: dict)
    """
    meta = meta or {}
    timeout_s = float(os.environ.get("TUTOR_TIMEOUT", "45"))
    temperature = float(os.environ.get("TUTOR_TEMP", "0.3"))
    max_tokens = int(os.environ.get("TUTOR_MAX_TOKENS", "800"))
    system_msg = os.environ.get("TUTOR_SYSTEM_PROMPT",
        "You are a calm, expert CPP/PSP study tutor. Explain clearly, step-by-step, "
        "and include 1–3 citations (title + URL) from allowed public sources when relevant."
    )

    azure_endpoint = os.environ.get("AZURE_OPENAI_ENDPOINT", "").rstrip("/")
    azure_key = os.environ.get("AZURE_OPENAI_API_KEY", "").strip()
    azure_deploy = os.environ.get("AZURE_OPENAI_DEPLOYMENT", "").strip()

    if azure_endpoint and azure_key and azure_deploy:
        url = f"{azure_endpoint}/openai/deployments/{azure_deploy}/chat/completions?api-version=2024-06-01"
        headers = {"api-key": azure_key, "Content-Type": "application/json"}
        payload = {
            "messages": [
                {"role": "system", "content": system_msg},
                {"role": "user", "content": user_query}
            ],
            "temperature": temperature,
            "max_tokens": max_tokens
        }
    else:
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
            meta_out = {"usage": usage}
            meta_out.update({"provider": "azure" if azure_endpoint else "openai"})
            if not azure_endpoint:
                meta_out["model"] = payload.get("model")
            return True, answer, meta_out
        except Exception as e:
            last_err = str(e)
            continue
    return False, f"Network/agent error: {last_err or 'unknown'}", {}

@app.route("/tutor", methods=["GET", "POST"], strict_slashes=False)
@app.route("/tutor/", methods=["GET", "POST"], strict_slashes=False)
@login_required
def tutor_page():
    user = _find_user(session.get("email","")) or {}
    user_id = user.get("id") or session.get("email") or "unknown"

    tutor_error = ""
    tutor_answer = ""
    user_query = (request.form.get("query") or "").strip() if request.method == "POST" else ""

    if request.method == "POST":
        if HAS_CSRF and request.form.get("csrf_token") != csrf_token():
            abort(403)
        if not user_query:
            tutor_error = "Please enter a question."
        else:
            ok, answer, meta = _call_tutor_agent(user_query, meta={"user_id": user_id})
            if ok:
                tutor_answer = answer
                item = {"ts": datetime.utcnow().isoformat() + "Z", "q": user_query, "a": tutor_answer, "meta": meta}
                _append_user_history(user_id, "tutor", item)
                _log_event(user_id, "tutor.ask", {"q_len": len(user_query), "ok": True, "model": meta.get("model")})
            else:
                tutor_error = answer
                _log_event(user_id, "tutor.ask", {"q_len": len(user_query), "ok": False})

    recent = _get_user_history(user_id, "tutor", limit=5)

    # Render
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

    content = f"""
    <div class="container">
      <div class="row justify-content-center"><div class="col-lg-8">
        <div class="card">
          <div class="card-header bg-primary text-white"><h3 class="mb-0"><i class="bi bi-mortarboard me-2"></i>Tutor</h3></div>
          <div class="card-body">
            <form method="POST" class="mb-3">
              <input type="hidden" name="csrf_token" value="{csrf_val}"/>
              <label class="form-label fw-semibold">Ask the Tutor</label>
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
      </div></div>
    </div>
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
    Converts a legacy/base question into a uniform runtime dict:
    {
      "id": str,
      "text": "...",
      "domain": "...",
      "choices": [{"key":"A","text":"..."}, ...],
      "correct_key": "A"
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
    letters = ["A","B","C","D"]
    choices = []
    for L in letters:
        if L not in opts:
            return None
        choices.append({"key": L, "text": str(opts[L])})
    correct = q.get("correct") or q.get("answer") or q.get("correct_key")
    if isinstance(correct, str) and correct.upper() in letters:
        correct_key = correct.upper()
    else:
        return None
    return {
        "id": qid,
        "text": text,
        "domain": domain,
        "choices": choices,
        "correct_key": correct_key
    }

def _all_normalized_questions():
    """Merge legacy QUESTIONS + BASE_QUESTIONS into normalized runtime items."""
    src = (ALL_QUESTIONS or [])  # ALL_QUESTIONS is built in Section 1
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
    # Build domain dropdown (Random + known keys)
    domain_opts = ['<option value="random">Random (all domains)</option>']
    # Use keys from DOMAINS dict (Section 1) for explicit domain picking
    for key, label in DOMAINS.items():
        domain_opts.append(f'<option value="{html.escape(key)}">{html.escape(label)}</option>')
    domain_select = f"""
      <div class="mb-3">
        <label class="form-label fw-semibold">Domain</label>
        <select class="form-select" name="domain">
          {"".join(domain_opts)}
        </select>
      </div>
    """ if include_domain else ""

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
              {domain_select}
              <div class="mb-2 fw-semibold">How many questions?</div>
              <div class="d-flex flex-wrap gap-2">
                {buttons_html}
              </div>
            </form>
            <div class="text-muted small">Tip: You can change domain to focus on a single area, or keep it Random.</div>
          </div>
        </div>
      </div></div>
    </div>
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
            if HAS_CSRF and request.form.get("csrf_token") != csrf_token():
                abort(403)
            try:
                count = int(request.form.get("count") or 10)
            except Exception:
                count = 10
            # Allowed quiz sizes
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
        if HAS_CSRF and request.form.get("csrf_token") != csrf_token():
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

    if request.method == "GET":
        if request.args.get("reset") == "1":
            _finish_run("mock", user_id)
            return redirect(url_for("mock_exam_page"))
        if request.args.get("new") == "1":
            _finish_run("mock", user_id)

    run = _load_run("mock", user_id)

    if not run:
        if request.method == "POST":
            if HAS_CSRF and request.form.get("csrf_token") != csrf_token():
                abort(403)
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
        if HAS_CSRF and request.form.get("csrf_token") != csrf_token():
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
        _finish_run("mock", user_id)
        return _render_results_card("Mock Exam", "/mock-exam", run, results)

    curr_idx = int(run.get("index", 0))
    return _render_question_card("Mock Exam", "/mock-exam", run, curr_idx, error_msg)
# =========================
# SECTION 5/8: Flashcards, Progress, Billing/Stripe (+ debug)
# =========================

# ---------- FLASHCARDS ----------
def _normalize_flashcard(item):
    """
    Accepts shapes like:
      {"front": "...", "back":"...", "domain":"...", "sources":[{"title": "...", "url":"..."}]}
    or {"q":"...", "a":"..."} etc.
    Returns:
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
    # keep 0-3 structured sources
    cleaned_sources = []
    for s in sources[:3]:
        t = (s.get("title") or "").strip()
        u = (s.get("url") or "").strip()
        if t and u:
            cleaned_sources.append({"title": t, "url": u})
    return {
        "id": item.get("id") or str(uuid.uuid4()),
        "front": front,
        "back": back,
        "domain": domain,
        "sources": cleaned_sources
    }

def _all_flashcards():
    """
    Merge legacy FLASHCARDS + optional bank file data/bank/cpp_flashcards_v1.json
    into normalized flashcards.
    """
    out = []
    seen = set()
    # 1) legacy top-level
    for fc in (FLASHCARDS or []):
        n = _normalize_flashcard(fc)
        if not n:
            continue
        key = (n["front"], n["back"], n["domain"])
        if key in seen:
            continue
        seen.add(key)
        out.append(n)
    # 2) bank file (if present)
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
    # Picker (count + domain)
    if request.method == "GET":
        # build domain select
        domain_opts = ['<option value="random">Random (all domains)</option>']
        for key, label in DOMAINS.items():
            domain_opts.append(f'<option value="{html.escape(key)}">{html.escape(label)}</option>')
        domain_select = "".join(domain_opts)

        csrf_val = csrf_token()
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
                  <div class="mb-3">
                    <label class="form-label fw-semibold">Domain</label>
                    <select class="form-select" name="domain">{domain_select}</select>
                  </div>
                  <div class="mb-2 fw-semibold">How many cards?</div>
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
        """
        return base_layout("Flashcards", content)

    # POST -> start session client-side (no server state needed)
    if HAS_CSRF and request.form.get("csrf_token") != csrf_token():
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

    # Render with a tiny JS controller (flip/next/prev, progress)
    # (No secrets; all in-page)
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
          // always start on front when changing card
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
    _log_event(_user_id(), "flashcards.start", {"count": len(cards), "domain": domain})
    return base_layout("Flashcards", content)

# ---------- PROGRESS ----------
@app.get("/progress")
@login_required
def progress_page():
    uid = _user_id()
    attempts = [a for a in _load_json("attempts.json", []) if a.get("user_id") == uid]
    attempts.sort(key=lambda x: x.get("ts",""), reverse=True)

    # Overall aggregates
    total_q = sum(a.get("count", 0) for a in attempts)
    total_ok = sum(a.get("correct", 0) for a in attempts)
    best = max([a.get("score_pct", 0.0) for a in attempts], default=0.0)
    avg = round(sum([a.get("score_pct", 0.0) for a in attempts]) / len(attempts), 1) if attempts else 0.0

    # By domain
    dom = {}
    for a in attempts:
        for dname, stats in (a.get("domains") or {}).items():
            dd = dom.setdefault(dname, {"correct": 0, "total": 0})
            dd["correct"] += int(stats.get("correct", 0))
            dd["total"] += int(stats.get("total", 0))

    def pct(c, t): return f"{(100.0*c/t):.1f}%" if t else "0.0%"

    # attempts table
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

    # domain table
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

# ---------- BILLING (Stripe) ----------
def create_stripe_checkout_session(user_email: str, plan: str = "monthly"):
    try:
        if plan == "monthly":
            if not STRIPE_MONTHLY_PRICE_ID:
                logger.error("Monthly price ID not configured")
                return None
            sess = stripe.checkout.Session.create(
                payment_method_types=["card"],
                mode="subscription",
                line_items=[{"price": STRIPE_MONTHLY_PRICE_ID, "quantity": 1}],
                customer_email=user_email,
                success_url=request.url_root.rstrip('/') + "/billing/success?session_id={CHECKOUT_SESSION_ID}&plan=monthly",
                cancel_url=request.url_root.rstrip('/') + "/billing",
                metadata={"user_email": user_email, "plan": "monthly"},
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
                success_url=request.url_root.rstrip('/') + "/billing/success?session_id={CHECKOUT_SESSION_ID}&plan=sixmonth",
                cancel_url=request.url_root.rstrip('/') + "/billing",
                metadata={"user_email": user_email, "plan": "sixmonth", "duration_days": 180},
            )
            return sess.url
        else:
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
        plans_html = """
          <div class="row g-3">
            <div class="col-md-6">
              <div class="card border-primary">
                <div class="card-header bg-primary text-white text-center"><h5 class="mb-0">Monthly Plan</h5></div>
                <div class="card-body text-center">
                  <h3 class="text-primary">$39.99/month</h3><p class="text-muted">Unlimited access</p>
                  <a href="/billing/checkout?plan=monthly" class="btn btn-primary">Upgrade</a>
                </div>
              </div>
            </div>
            <div class="col-md-6">
              <div class="card border-success">
                <div class="card-header bg-success text-white text-center"><h5 class="mb-0">6-Month Plan</h5></div>
                <div class="card-body text-center">
                  <h3 class="text-success">$99.00</h3><p class="text-muted">One-time payment</p>
                  <a href="/billing/checkout?plan=sixmonth" class="btn btn-success">Upgrade</a>
                </div>
              </div>
            </div>
          </div>
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
    url = create_stripe_checkout_session(user_email, plan=plan)
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
        # Simple admin gate: visit /admin/login?pw=... once per session
        return redirect(url_for("admin_login_page", next=request.path))

    data = {
        "STRIPE_PUBLISHABLE_KEY_present": bool(STRIPE_PUBLISHABLE_KEY),
        "STRIPE_MONTHLY_PRICE_ID_present": bool(STRIPE_MONTHLY_PRICE_ID),
        "STRIPE_SIXMONTH_PRICE_ID_present": bool(STRIPE_SIXMONTH_PRICE_ID),
        "OPENAI_CHAT_MODEL": OPENAI_CHAT_MODEL,
        "DATA_DIR": DATA_DIR,
    }
    # NOTE: do NOT display secrets; only booleans/ids
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

# Simple admin login to flip session.admin_ok True
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
    if HAS_CSRF and request.form.get("csrf_token") != csrf_token():
        abort(403)
    nxt = request.form.get("next") or "/"
    pw = (request.form.get("pw") or "").strip()
    if ADMIN_PASSWORD and pw == ADMIN_PASSWORD:
        session["admin_ok"] = True
        return redirect(nxt)
    return redirect(url_for("admin_login_page", next=nxt))
# =========================
# SECTION 6/8: Content ingestion (+ whitelist, hashing, acceptance checker)
# =========================

# -------- Source whitelist (edit anytime) --------
ALLOWED_SOURCE_DOMAINS = {
    # Government & standards (non-proprietary)
    "nist.gov", "cisa.gov", "fema.gov", "osha.gov", "gao.gov",
    # Research & practice
    "popcenter.asu.edu",  # POP Center
    "ncpc.org",           # National Crime Prevention Council
    "fbi.gov",
    "rand.org",
    "hsdl.org",           # Homeland Security Digital Library
    "nfpa.org",           # view-only summaries allowed
    "iso.org",            # summaries only
    # After Action Reports (public/official postings)
    "ca.gov", "ny.gov", "tx.gov", "wa.gov", "mass.gov", "phila.gov", "denvergov.org",
    "boston.gov", "chicago.gov", "seattle.gov", "sandiego.gov", "lacounty.gov",
    "ready.gov"  # FEMA/ICS public summaries & guidance
}
# NOTE: Wikipedia intentionally NOT allowed.

from urllib.parse import urlparse

def _url_domain_ok(url: str) -> bool:
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

# -------- Hash & de-dup index --------
def _item_hash_flashcard(front: str, back: str, domain: str, sources: list) -> str:
    # Canonical string for deterministic hashing
    blob = json.dumps({
        "k": "fc",
        "front": front.strip().lower(),
        "back": back.strip().lower(),
        "domain": (domain or "Unspecified").strip().lower(),
        "srcs": [{"t": (s.get("title","").strip().lower()), "u": (s.get("url","").strip().lower())} for s in (sources or [])]
    }, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()

def _item_hash_question(question: str, options: dict, correct: str, domain: str, sources: list) -> str:
    # Keep options in A..D order for stable hashing
    ordered = {k: str(options.get(k,"")).strip().lower() for k in ["A","B","C","D"]}
    blob = json.dumps({
        "k": "q",
        "q": (question or "").strip().lower(),
        "opts": ordered,
        "correct": (correct or "").strip().upper(),
        "domain": (domain or "Unspecified").strip().lower(),
        "srcs": [{"t": (s.get("title","").strip().lower()), "u": (s.get("url","").strip().lower())} for s in (sources or [])]
    }, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()

def _load_content_index():
    return _load_json("bank/content_index.json", {})

def _save_content_index(idx: dict):
    _save_json("bank/content_index.json", idx)

# -------- Bank file helpers --------
def _bank_read_flashcards():
    return _load_json("bank/cpp_flashcards_v1.json", [])

def _bank_read_questions():
    return _load_json("bank/cpp_questions_v1.json", [])

def _bank_write_flashcards(items: list):
    _save_json("bank/cpp_flashcards_v1.json", items)

def _bank_write_questions(items: list):
    _save_json("bank/cpp_questions_v1.json", items)

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
    """
    if not isinstance(q_in, dict):
        return None, "Question must be an object."
    question = (q_in.get("question") or q_in.get("q") or q_in.get("stem") or "").strip()
    domain   = (q_in.get("domain") or q_in.get("category") or "Unspecified").strip()
    sources  = q_in.get("sources") or []
    # Options can come as dict or list
    raw_opts = q_in.get("options") or q_in.get("choices") or q_in.get("answers")
    opts = {}
    if isinstance(raw_opts, dict):
        for L in ["A","B","C","D"]:
            v = raw_opts.get(L) or raw_opts.get(L.lower())
            if not v: return None, f"Missing option {L}"
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
    # Correct can be letter or 1-based index
    correct = q_in.get("correct") or q_in.get("answer") or q_in.get("correct_key")
    if isinstance(correct, str) and correct.strip().upper() in ("A","B","C","D"):
        correct = correct.strip().upper()
    else:
        try:
            idx = int(correct)
            correct = ["A","B","C","D"][idx - 1]
        except Exception:
            return None, "Correct must be A/B/C/D or 1..4."
    # Sources validate
    ok, msg = _validate_sources(sources)
    if not ok:
        return None, msg
    if not question:
        return None, "Question text required."
    return {"question": question, "options": opts, "correct": correct, "domain": domain, "sources": sources}, ""

# -------- Ingestion (admin-only) --------
@app.post("/api/dev/ingest")
@login_required
def api_dev_ingest():
    if not is_admin():
        return jsonify({"ok": False, "error": "admin-required"}), 403

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
        h = _item_hash_flashcard(fc.get("front",""), fc.get("back",""), fc.get("domain","Unspecified"), fc.get("sources") or [])
        existing_fc_hashes.add(h)
        idx.setdefault(h, {"type":"fc","added": idx.get(h,{}).get("added") or datetime.utcnow().isoformat()+"Z"})

    existing_q_hashes = set()
    for q in bank_q:
        h = _item_hash_question(q.get("question",""), q.get("options") or {}, q.get("correct",""), q.get("domain","Unspecified"), q.get("sources") or [])
        existing_q_hashes.add(h)
        idx.setdefault(h, {"type":"q","added": idx.get(h,{}).get("added") or datetime.utcnow().isoformat()+"Z"})

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
        h = _item_hash_question(norm["question"], norm["options"], norm["correct"], norm["domain"], norm["sources"])
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

# -------- Acceptance checker (admin-only UI) --------
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
        # options must be A..D and all non-empty
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

    # Domain counts (simple) to help balancing
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
              <a class="btn btn-outline-primary" href="/billing/debug"><i class="bi bi-bug me-1"></i>Config Debug</a>
            </div>
          </div>
        </div>
      </div></div>
    </div>
    """
    return base_layout("Bank Checker", content)
# =========================
# SECTION 7/8: Tutor — web-aware citations (+ admin toggles)
# =========================

# ---- Settings loader for Tutor "web-aware" mode (persisted; override by ENV) ----
def _load_tutor_settings():
    return _load_json("tutor_settings.json", {"web_aware": os.environ.get("TUTOR_WEB_AWARE", "0") == "1"})

def _save_tutor_settings(cfg: dict):
    _save_json("tutor_settings.json", cfg or {})

def _tutor_web_enabled() -> bool:
    # ENV overrides file if set explicitly
    if os.environ.get("TUTOR_WEB_AWARE") in ("0", "1"):
        return os.environ.get("TUTOR_WEB_AWARE") == "1"
    return bool(_load_tutor_settings().get("web_aware", False))

# ---- Bank-source citation finder (uses your uploaded/ingested sources only) ----
def _bank_all_sources():
    """
    Yields deduped source dicts from bank files:
      {"title":..., "url":..., "domain":..., "from":"flashcard|question"}
    Only returns URLs whose domain is in ALLOWED_SOURCE_DOMAINS.
    """
    seen = set()
    for fc in _load_json("bank/cpp_flashcards_v1.json", []):
        for s in (fc.get("sources") or []):
            u = (s.get("url") or "").strip()
            t = (s.get("title") or "").strip()
            if not u or not t:
                continue
            if not _url_domain_ok(u):
                continue
            key = (t, u)
            if key in seen:
                continue
            seen.add(key)
            yield {"title": t, "url": u, "domain": urlparse(u).netloc.lower(), "from": "flashcard"}
    for q in _load_json("bank/cpp_questions_v1.json", []):
        for s in (q.get("sources") or []):
            u = (s.get("url") or "").strip()
            t = (s.get("title") or "").strip()
            if not u or not t:
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
    # simple stoplist
    stop = {"the","and","for","with","from","this","that","into","over","under","your","about","into","have","what","when","where","which"}
    return {w for w in words if w not in stop}

def _score_source(src, kw: set[str]) -> int:
    score = 0
    title_words = set(re.findall(r"[A-Za-z]{3,}", src["title"].lower()))
    score += len(title_words & kw) * 3
    domain_words = set(re.findall(r"[A-Za-z]{3,}", src["domain"].split(":")[0]))
    score += len(domain_words & kw)
    # prefer government standards & official guidance slightly
    if any(src["domain"].endswith(d) for d in ("nist.gov","cisa.gov","fema.gov","gao.gov","osha.gov")):
        score += 2
    return score

def _find_bank_citations(query: str, max_n: int = 3) -> list[dict]:
    kw = _extract_keywords(query)
    pool = list(_bank_all_sources())
    if not pool:
        return []
    scored = sorted(pool, key=lambda s: _score_source(s, kw), reverse=True)
    out = []
    seen_urls = set()
    for s in scored:
        if s["url"] in seen_urls:
            continue
        out.append(s)
        seen_urls.add(s["url"])
        if len(out) >= max_n:
            break
    return out

# ---- Replaces/extends prior _call_tutor_agent to inject citations when enabled ----
def _call_tutor_agent(user_query, meta=None):
    """
    Web-aware mode: when enabled, we pass 1–3 bank-sourced citations to the model
    and instruct it to include a short 'Citations' section with Title + URL.
    """
    meta = meta or {}
    timeout_s   = float(os.environ.get("TUTOR_TIMEOUT", "45"))
    temperature = float(os.environ.get("TUTOR_TEMP", "0.3"))
    max_tokens  = int(os.environ.get("TUTOR_MAX_TOKENS", "800"))
    model       = os.environ.get("MODEL_TUTOR", "gpt-4o-mini").strip()
    base_url    = os.environ.get("OPENAI_API_BASE", "https://api.openai.com/v1").rstrip("/")
    api_key     = os.environ.get("OPENAI_API_KEY","").strip()
    org_id      = os.environ.get("OPENAI_ORG","").strip()

    if not api_key:
        return False, "Tutor is not configured: missing API key.", {}

    web_on = _tutor_web_enabled()
    cites  = _find_bank_citations(user_query, max_n=3) if web_on else []
    cites_lines = "\n".join([f"- {c['title']} — {c['url']}" for c in cites])

    system_msg = (
        "You are a calm, expert CPP/PSP study tutor. Be concise, structured, and practical. "
        "If a question maps to CPP domains, mention the domain at the end of the relevant bullet. "
        "If supporting_sources are provided, incorporate their facts and add a short 'Citations' "
        "section at the end listing Title and URL (1–3 items). If sources are absent, answer normally."
    )

    messages = [{"role":"system","content": system_msg}]
    if cites:
        messages.append({"role":"system","content": "Supporting_sources:\n"+cites_lines})
    messages.append({"role":"user","content": user_query})

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    if org_id:
        headers["OpenAI-Organization"] = org_id

    payload = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }

    backoffs = [0, 1.5, 3.0]
    last_err = None
    for wait_s in backoffs:
        if wait_s: time.sleep(wait_s)
        try:
            resp = requests.post(f"{base_url}/chat/completions", headers=headers, data=json.dumps(payload), timeout=timeout_s)
            if resp.status_code in (429, 500, 502, 503, 504):
                last_err = f"{resp.status_code} {resp.text[:300]}"; continue
            if resp.status_code >= 400:
                try:
                    j = resp.json(); msg = (j.get("error") or {}).get("message") or resp.text[:300]
                except Exception:
                    msg = resp.text[:300]
                return False, f"Agent error {resp.status_code}: {msg}", {"status": resp.status_code}
            data = resp.json()
            answer = (data.get("choices") or [{}])[0].get("message", {}).get("content", "")
            usage  = data.get("usage", {})
            meta_out = {"usage": usage, "provider": "openai", "model": model, "web_aware": web_on, "citations_used": cites}
            return True, answer, meta_out
        except Exception as e:
            last_err = str(e)
            continue

    return False, f"Network/agent error: {last_err or 'unknown'}", {}

# ---- Admin UI to toggle web-aware mode & preview citations ----
@app.route("/admin/tutor-mode", methods=["GET","POST"])
@login_required
def admin_tutor_mode():
    if not is_admin():
        return redirect(url_for("admin_login_page", next=request.path))

    cfg = _load_tutor_settings()
    msg = ""
    if request.method == "POST":
        if HAS_CSRF and request.form.get("csrf_token") != csrf_token():
            abort(403)
        enabled = (request.form.get("web_aware") == "1")
        cfg["web_aware"] = enabled
        _save_tutor_settings(cfg)
        msg = "Saved. Web-aware Tutor is now " + ("ON" if enabled else "OFF")

    # quick preview if a query is provided
    preview_query = (request.args.get("q") or "").strip()
    preview_list = _find_bank_citations(preview_query, 3) if preview_query else []
    prev_html = ""
    if preview_query:
        if preview_list:
            items = "".join([f'<li><a href="{html.escape(x["url"])}" target="_blank" rel="noopener">{html.escape(x["title"])}</a> <span class="text-muted small">({html.escape(x["domain"])})</span></li>' for x in preview_list])
            prev_html = f"<div class='mt-3'><div class='fw-semibold'>Preview citations for: <em>{html.escape(preview_query)}</em></div><ul class='small'>{items}</ul></div>"
        else:
            prev_html = f"<div class='mt-3 text-muted small'>No matching sources found in your bank for: <em>{html.escape(preview_query)}</em></div>"

    content = f"""
    <div class="container"><div class="row justify-content-center"><div class="col-lg-7">
      <div class="card">
        <div class="card-header bg-secondary text-white"><h3 class="mb-0"><i class="bi bi-robot me-2"></i>Tutor Mode</h3></div>
        <div class="card-body">
          {"<div class='alert alert-success'>"+html.escape(msg)+"</div>" if msg else ""}
          <form method="POST" class="mb-3">
            <input type="hidden" name="csrf_token" value="{csrf_token()}"/>
            <div class="form-check form-switch">
              <input class="form-check-input" type="checkbox" id="webAware" name="web_aware" value="1" {"checked" if cfg.get("web_aware") else ""}>
              <label class="form-check-label" for="webAware">Enable web-aware Tutor (uses citations from your content bank)</label>
            </div>
            <button class="btn btn-primary mt-3" type="submit">Save</button>
            <a class="btn btn-outline-secondary mt-3 ms-2" href="/tutor">Go to Tutor</a>
          </form>

          <form method="GET" class="row g-2 align-items-end">
            <div class="col-9">
              <label class="form-label fw-semibold">Preview citations for a sample question</label>
              <input type="text" class="form-control" name="q" placeholder="e.g., physical access control for data centers" value="{html.escape(preview_query)}">
            </div>
            <div class="col-3">
              <button class="btn btn-outline-primary w-100">Preview</button>
            </div>
          </form>
          {prev_html}
        </div>
      </div>
    </div></div></div>
    """
    return base_layout("Tutor Mode", content)

# ---- Diagnostic endpoint to verify citations path (no overlap with existing /tutor/ping) ----
@app.get("/tutor/ping-web")
@login_required
def tutor_ping_web():
    q = request.args.get("q") or "Explain incident command system basics for private sector security roles."
    cites = _find_bank_citations(q, 3) if _tutor_web_enabled() else []
    return jsonify({
        "web_aware": _tutor_web_enabled(),
        "query": q,
        "citations": cites
    })
# =========================
# SECTION 8/8: Startup, health, error pages, and __main__
# =========================

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
        for name, default in [
            ("users.json", []),
            ("questions.json", []),      # legacy optional
            ("flashcards.json", []),     # legacy optional
            ("attempts.json", []),
            ("events.json", []),
        ]:
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
        if not os.path.exists(os.path.join(DATA_DIR, "tutor_settings.json")):
            _save_json("tutor_settings.json", {"web_aware": os.environ.get("TUTOR_WEB_AWARE", "0") == "1"})

    except Exception as e:
        logger.warning("init_sample_data encountered an issue: %s", e)

# ---- Health endpoint (idempotent: defined only if not already) ----
if "healthz" not in app.view_functions:
    @app.get("/healthz")
    def healthz():
        return {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "version": APP_VERSION,
            "web_aware_tutor": _tutor_web_enabled() if " _tutor_web_enabled" in globals() else False
        }

# ---- Friendly error pages (do not leak stack traces) ----
@app.errorhandler(404)
def not_found(e):
    content = """
    <div class="container">
      <div class="row justify-content-center"><div class="col-md-8">
        <div class="card">
          <div class="card-header bg-danger text-white">
            <h3 class="mb-0"><i class="bi bi-exclamation-triangle me-2"></i>Page Not Found</h3>
          </div>
          <div class="card-body">
            <p class="text-muted mb-3">We couldn’t find that page. Check the URL or use the navigation above.</p>
            <a class="btn btn-primary" href="/"><i class="bi bi-house me-1"></i>Go Home</a>
          </div>
        </div>
      </div></div>
    </div>
    """
    return base_layout("404 Not Found", content), 404

@app.errorhandler(500)
def server_error(e):
    # Keep message generic; details are in logs
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

# ---- App factory (for gunicorn) ----
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

# ---- Local runner (Render uses gunicorn `app:app`) ----
if __name__ == "__main__":
    init_sample_data()
    port = int(os.environ.get("PORT", "5000"))
    logger.info("Running app on port %s", port)
    app.run(host="0.0.0.0", port=port, debug=DEBUG)


