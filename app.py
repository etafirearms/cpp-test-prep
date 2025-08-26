# app.py

# ====== Imports & Basic Config ======
from flask import Flask, request, jsonify, session, redirect, url_for, Response
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from functools import wraps
from datetime import datetime, timedelta
from contextlib import contextmanager
from typing import Dict, Any

import os, json, random, requests, html, csv, uuid, logging, time, hashlib, re
import sqlite3
import stripe

# Optional CSRF import - only if available
try:
    from flask_wtf.csrf import CSRFProtect
    HAS_CSRF = True
except ImportError:
    HAS_CSRF = False

# fcntl for safe file writes (best-effort)
try:
    import fcntl
    HAS_FCNTL = True
except ImportError:
    HAS_FCNTL = False

# ====== Logging ======
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ====== Flask App ======
app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)
app.secret_key = os.environ.get("SECRET_KEY") or os.urandom(24)

if HAS_CSRF:
    csrf = CSRFProtect(app)

OPENAI_API_KEY    = os.environ.get("OPENAI_API_KEY", "")
OPENAI_CHAT_MODEL = os.environ.get("OPENAI_CHAT_MODEL", "gpt-4o-mini")
OPENAI_API_BASE   = os.environ.get("OPENAI_API_BASE", "https://api.openai.com/v1")

stripe.api_key            = os.environ.get('STRIPE_SECRET_KEY', '')
STRIPE_WEBHOOK_SECRET     = os.environ.get('STRIPE_WEBHOOK_SECRET', '')
STRIPE_MONTHLY_PRICE_ID   = os.environ.get('STRIPE_MONTHLY_PRICE_ID', '')
STRIPE_SIXMONTH_PRICE_ID  = os.environ.get('STRIPE_SIXMONTH_PRICE_ID', '')
ADMIN_PASSWORD            = os.environ.get("ADMIN_PASSWORD", "").strip()

APP_VERSION = os.environ.get("APP_VERSION", "1.0.0")
IS_STAGING  = os.environ.get("RENDER_SERVICE_NAME", "").endswith("-staging")
DEBUG       = os.environ.get("FLASK_DEBUG", "0") == "1"

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=(os.environ.get("SESSION_COOKIE_SECURE", "1") == "1"),
    MESSAGE_FLASHING=True
)

# ====== Data Storage (JSON + optional SQLite stub) ======
DATA_DIR = os.environ.get("DATA_DIR", "data")
os.makedirs(DATA_DIR, exist_ok=True)
DATABASE_PATH = os.path.join(DATA_DIR, "app.db")

def _load_json(name, default):
    path = os.path.join(DATA_DIR, name)
    if not os.path.exists(path):
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default

def _save_json(name, data):
    """
    Robust, atomic JSON save:
    - Writes to a unique temp file per process (avoids collisions across workers)
    - fsyncs and then os.replace(...) to be atomic on POSIX
    - Falls back to simple write if something unexpected happens
    """
    path = os.path.join(DATA_DIR, name)
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp_path = f"{path}.tmp.{os.getpid()}.{uuid.uuid4().hex}"

        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())

        # Atomic replace
        os.replace(tmp_path, path)
    except Exception as e:
        # Clean up stray temp (best effort)
        try:
            if 'tmp_path' in locals() and os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            pass
        logger.warning("Atomic _save_json failed for %s: %s; attempting simple write", name, e)
        # Fallback: non-atomic write (last writer wins)
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception as e2:
            logger.error("Fallback _save_json failed for %s: %s", name, e2)

QUESTIONS  = _load_json("questions.json", [])
FLASHCARDS = _load_json("flashcards.json", [])
USERS      = _load_json("users.json", [])

@contextmanager
def get_db_connection():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

def init_database():
    with get_db_connection() as conn:
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

# ====== Security Headers & Simple Rate Limiting ======
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
        "script-src 'self' https://cdn.jsdelivr.net https://js.stripe.com; "
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
    if len(_RATE_BUCKETS) > 1000:
        cutoff = now - (per_seconds * 2)
        _RATE_BUCKETS = {k: [t for t in v if t > cutoff]
                         for k, v in _RATE_BUCKETS.items()
                         if any(t > cutoff for t in v)}
    return False

def _submission_sig(payload: dict) -> str:
    try:
        blob = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    except Exception:
        blob = str(payload)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()

# ====== Auth Helpers ======
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

# ====== User helpers (replace prior data_store calls) ======
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

# ====== Usage Management ======
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
# ====== Questions & Domains ======
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

def _normalize_question(q: dict):
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
        for i, L in enumerate(letters):
            if L in opts:
                clean[L] = str(opts[L])
            elif str(i+1) in opts:
                clean[L] = str(opts[str(i+1)])
        if len(clean) != 4:
            return None
        nq["options"] = clean
        if correct_letter and isinstance(correct_letter, str) and correct_letter.upper() in ("A","B","C","D"):
            nq["correct"] = correct_letter.upper()
        else:
            try:
                idx = int(correct_letter)
                nq["correct"] = ["A","B","C","D"][idx-1]
            except Exception:
                return None
    elif isinstance(opts, list) and q.get("answer"):
        letters = ["A", "B", "C", "D"]
        if len(opts) < 4:
            return None
        nq["options"] = {letters[i]: str(opts[i]) for i in range(4)}
        try:
            ans_idx = int(q.get("answer"))
            nq["correct"] = letters[ans_idx - 1]
        except Exception:
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
            nq = _normalize_question(q)
            if not nq:
                continue
            key = (nq["question"], nq["domain"], nq["correct"])
            if key in seen:
                continue
            seen.add(key)
            merged.append(nq)
    add_many(QUESTIONS)
    add_many(BASE_QUESTIONS)
    return merged

ALL_QUESTIONS = _build_all_questions()

# ====== Misc Helpers ======
def safe_json_response(data, status_code=200):
    try:
        return jsonify(data), status_code
    except Exception as e:
        logger.error(f"JSON serialization error: {e}")
        return jsonify({"error": "Internal server error"}), 500

def filter_questions(domain_key: str | None):
    pool = ALL_QUESTIONS
    if not domain_key or domain_key == "random":
        return pool[:]
    return [q for q in pool if q.get("domain") == domain_key]

def build_quiz(num: int, domain_key: str | None):
    pool = filter_questions(domain_key)
    out = []
    if not pool:
        pool = ALL_QUESTIONS[:]
    while len(out) < num:
        random.shuffle(pool)
        for q in pool:
            if len(out) >= num:
                break
            out.append(q.copy())
    title = f"Practice ({num} questions)"
    return {"title": title, "domain": domain_key or "random", "questions": out[:num]}

def chat_with_ai(msgs: list[str]) -> str:
    try:
        if not OPENAI_API_KEY:
            return "OpenAI key is not configured. Please set OPENAI_API_KEY."
        payload = {
            "model": OPENAI_CHAT_MODEL,
            "messages": [{"role": "system", "content": "You are a helpful CPP exam tutor. Format your answers for easy reading with short sections and bullet points where helpful."}]
                        + [{"role": "user", "content": m} for m in msgs][-10:],
            "temperature": 0.7,
            "max_tokens": 500,
        }
        r = requests.post(
            f"{OPENAI_API_BASE}/chat/completions",
            headers={"Authorization": f"Bearer {OPENAI_API_KEY}", "Content-Type": "application/json"},
            json=payload,
            timeout=30,
        )
        if r.status_code != 200:
            logger.error(f"OpenAI API error {r.status_code}: {r.text[:200]}")
            return f"AI error ({r.status_code}). Please try again."
        data = r.json()
        return data["choices"][0]["message"]["content"]
    except Exception as e:
        return f"AI request failed: {e}"

def _plan_badge_text(sub):
    if sub == 'monthly':
        return 'Monthly'
    if sub == 'sixmonth':
        return '6-Month'
    return 'Inactive'
# ====== Base Layout ======
def base_layout(title: str, body_html: str) -> str:
    user_name = session.get('name', '')
    user_email = session.get('email', '')
    is_logged_in = 'user_id' in session

    # CSRF token value (string) for meta + forms
    if HAS_CSRF:
        try:
            from flask_wtf.csrf import generate_csrf
            csrf_token_value = generate_csrf()
        except Exception:
            csrf_token_value = ""
    else:
        csrf_token_value = ""

    # user menu
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
                <input type="hidden" name="csrf_token" value="{csrf_token_value}"/>
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

    # Precompute staging banner to avoid f-string traps
    stage_banner = (
        """
        <div class="alert alert-warning alert-dismissible fade show m-0" role="alert">
          <div class="container text-center">
            <strong>STAGING ENVIRONMENT</strong> - Not for production use.
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
          </div>
        </div>
        """
        if IS_STAGING else ""
    )

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
      .btn-success { background: linear-gradient(135deg, var(--success-green), #10b981); border: none; box-shadow: 0 4px 12px rgba(5, 150, 105, 0.25); }
      .btn-warning { background: linear-gradient(135deg, var(--warning-orange), #f59e0b); border: none; box-shadow: 0 4px 12px rgba(217, 119, 6, 0.25); }
      .progress { height: 12px; border-radius: 8px; background: #e5e7eb; overflow: hidden; }
      .progress-bar { border-radius: 8px; transition: width 0.6s ease; }
      .bg-success { background: linear-gradient(90deg, var(--success-green), #10b981) !important; }
      .bg-warning { background: linear-gradient(90deg, var(--warning-orange), #f59e0b) !important; }
      .bg-danger  { background: linear-gradient(90deg, var(--danger-red), #ef4444) !important; }
      .badge { font-size: 0.8em; padding: 0.5em 0.8em; border-radius: 8px; font-weight: 600; }
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
      @media (max-width: 768px) {
        .container { padding: 0 20px; }
        .card { margin-bottom: 1.5rem; border-radius: 12px; }
        .btn { padding: 0.6rem 1.2rem; }
      }
      .text-success { color: var(--success-green) !important; fill: var(--success-green); }
      .text-warning { color: var(--warning-orange) !important; fill: var(--warning-orange); }
      .text-danger  { color: var(--danger-red) !important; fill: var(--danger-red); }
    </style>
    """

    # Replace literal Jinja token in body_html
    body_html = body_html.replace('{{ csrf_token() }}', csrf_token_value)

    # Final HTML
    return f"""<!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <meta name="csrf-token" content="{csrf_token_value}">
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

@app.template_global()
def csrf_token():
    if HAS_CSRF:
        from flask_wtf.csrf import generate_csrf
        return generate_csrf()
    return ""
# ====== Health ======
@app.get("/healthz")
def healthz():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat(), "version": APP_VERSION}

# ====== Auth (Login/Signup/Logout) ======
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
                  <label for="email" class="form-label fw-semibold">Email</label>
                  <input type="email" class="form-control" name="email" required placeholder="your.email@example.com">
                </div>
                <div class="mb-4">
                  <label for="password" class="form-label fw-semibold">Password</label>
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
        // simple visual feedback
        var cards = document.querySelectorAll('.card.h-100');
        for (var i = 0; i < cards.length; i++) {
          cards[i].style.transform = 'none';
          cards[i].classList.remove('shadow-lg');
        }
        // find the clicked button by selector using normal strings (no backticks)
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
      // Pre-select monthly plan
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

    checkout_url = create_stripe_checkout_session(user_email=email, plan=plan)
    if checkout_url:
        return redirect(checkout_url)
    return redirect(url_for('billing_checkout', plan=plan))

@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for('login_page'))

# ====== Home / Dashboard ======
@app.get("/")
def home():
    if 'user_id' not in session:
        body = """
        <div class="container">
          <div class="row justify-content-center text-center">
            <div class="col-lg-10">
              <div class="mb-5">
                <i class="bi bi-mortarboard text-primary display-1 mb-4"></i>
                <h1 class="display-3 fw-bold mb-4">Master the CPP Exam</h1>
                <p class="lead fs-4 text-muted mb-5">
                  Transform your security career with AI-powered learning,
                  comprehensive practice tests, and personalized progress tracking.
                </p>
              </div>

              <div class="row mb-5 g-4">
                <div class="col-md-4">
                  <div class="card border-0 h-100">
                    <div class="card-body text-center p-4">
                      <i class="bi bi-robot display-4 text-primary mb-3"></i>
                      <h4 class="fw-bold">AI Study Tutor</h4>
                      <p class="text-muted">Get instant explanations, clarifications, and study guidance tailored to your learning style.</p>
                    </div>
                  </div>
                </div>
                <div class="col-md-4">
                  <div class="card border-0 h-100">
                    <div class="card-body text-center p-4">
                      <i class="bi bi-card-text display-4 text-success mb-3"></i>
                      <h4 class="fw-bold">Practice Quizzes</h4>
                      <p class="text-muted">Test your knowledge across all CPP domains with unlimited practice questions and detailed explanations.</p>
                    </div>
                  </div>
                </div>
                <div class="col-md-4">
                  <div class="card border-0 h-100">
                    <div class="card-body text-center p-4">
                      <i class="bi bi-graph-up display-4 text-warning mb-3"></i>
                      <h4 class="fw-bold">Smart Analytics</h4>
                      <p class="text-muted">Track your progress, identify weak areas, and focus your study time where it matters most.</p>
                    </div>
                  </div>
                </div>
              </div>

              <div class="mb-5">
                <a href="/signup" class="btn btn-primary btn-lg me-3 px-5 py-3">
                  <i class="bi bi-rocket-takeoff me-2"></i>Start Learning Now
                </a>
                <a href="/login" class="btn btn-outline-primary btn-lg px-5 py-3">
                  <i class="bi bi-box-arrow-in-right me-2"></i>Sign In
                </a>
              </div>

              <div class="row text-start g-4">
                <div class="col-md-6">
                  <div class="d-flex">
                    <i class="bi bi-check-circle-fill text-success fs-4 me-3 mt-1"></i>
                    <div>
                      <h5 class="fw-bold">Exam-Ready Content</h5>
                      <p class="text-muted mb-0">Questions designed to mirror the real CPP certification exam format and difficulty.</p>
                    </div>
                  </div>
                </div>
                <div class="col-md-6">
                  <div class="d-flex">
                    <i class="bi bi-check-circle-fill text-success fs-4 me-3 mt-1"></i>
                    <div>
                      <h5 class="fw-bold">Flexible Learning</h5>
                      <p class="text-muted mb-0">Study at your own pace with mobile-friendly access anywhere, anytime.</p>
                    </div>
                  </div>
                </div>
                <div class="col-md-6">
                  <div class="d-flex">
                    <i class="bi bi-check-circle-fill text-success fs-4 me-3 mt-1"></i>
                    <div>
                      <h5 class="fw-bold">Proven Methods</h5>
                      <p class="text-muted mb-0">Built on adult learning principles and spaced repetition for maximum retention.</p>
                    </div>
                  </div>
                </div>
                <div class="col-md-6">
                  <div class="d-flex">
                    <i class="bi bi-check-circle-fill text-success fs-4 me-3 mt-1"></i>
                    <div>
                      <h5 class="fw-bold">Instant Feedback</h5>
                      <p class="text-muted mb-0">Learn from mistakes immediately with detailed explanations for every question.</p>
                    </div>
                  </div>
                </div>
              </div>

            </div>
          </div>
        </div>
        """
        return base_layout("CPP Test Prep - Master Your Certification", body)

    # Logged-in dashboard
    user_name = session.get('name', '').split(' ')[0] or 'there'
    hist = session.get("quiz_history", [])
    avg = round(sum(h.get("score", 0.0) for h in hist) / len(hist), 1) if hist else 0.0

    if avg >= 80:
        dial_color = "success"
        dial_bg = "#059669"
    elif avg >= 60:
        dial_color = "warning"
        dial_bg = "#d97706"
    else:
        dial_color = "danger"
        dial_bg = "#dc2626"

    tips = [
        "Small wins build momentum — try a focused 15-minute session today.",
        "Active recall beats passive reading — quiz yourself regularly.",
        "Mix different topics to strengthen long-term memory connections.",
        "Practice under time pressure to build exam-day confidence.",
        "Teach concepts out loud — if you can explain it, you truly know it.",
        "Celebrate progress, not just perfection — every question counts.",
        "Take breaks between study sessions for better information processing."
    ]
    tip = random.choice(tips)

    body = f"""
    <div class="container">
      <div class="row">
        <div class="col-lg-8">
          <div class="card mb-4 border-0 shadow-sm">
            <div class="card-body p-4">
              <div class="d-flex align-items-center mb-3">
                <div class="me-3">
                  <div class="rounded-circle bg-primary bg-opacity-10 p-3">
                    <i class="bi bi-person-check text-primary fs-3"></i>
                  </div>
                </div>
                <div>
                  <h1 class="h3 mb-1">Welcome back, {html.escape(user_name)}!</h1>
                  <p class="text-muted mb-0">Ready to advance your CPP preparation?</p>
                </div>
              </div>
            </div>
          </div>

          <div class="card mb-4 border-0 bg-gradient-primary text-white">
            <div class="card-body p-4">
              <div class="d-flex align-items-start">
                <i class="bi bi-lightbulb text-warning fs-2 me-3 mt-1"></i>
                <div>
                  <h5 class="card-title text-white mb-2">Today's Learning Tip</h5>
                  <p class="card-text opacity-90 mb-0">{html.escape(tip)}</p>
                </div>
              </div>
            </div>
          </div>

          <div class="row g-3">
            <div class="col-md-6">
              <a href="/study" class="text-decoration-none">
                <div class="card h-100 border-0 shadow-sm study-card">
                  <div class="card-body text-center p-4">
                    <i class="bi bi-robot text-primary display-6 mb-3"></i>
                    <h5 class="card-title">AI Study Tutor</h5>
                    <p class="text-muted small">Get instant help and explanations</p>
                  </div>
                </div>
              </a>
            </div>
            <div class="col-md-6">
              <a href="/quiz" class="text-decoration-none">
                <div class="card h-100 border-0 shadow-sm study-card">
                  <div class="card-body text-center p-4">
                    <i class="bi bi-card-text text-success display-6 mb-3"></i>
                    <h5 class="card-title">Practice Quiz</h5>
                    <p class="text-muted small">Test your knowledge</p>
                  </div>
                </div>
              </a>
            </div>
            <div class="col-md-6">
              <a href="/flashcards" class="text-decoration-none">
                <div class="card h-100 border-0 shadow-sm study-card">
                  <div class="card-body text-center p-4">
                    <i class="bi bi-card-list text-info display-6 mb-3"></i>
                    <h5 class="card-title">Flashcards</h5>
                    <p class="text-muted small">Quick review sessions</p>
                  </div>
                </div>
              </a>
            </div>
            <div class="col-md-6">
              <a href="/mock-exam" class="text-decoration-none">
                <div class="card h-100 border-0 shadow-sm study-card">
                  <div class="card-body text-center p-4">
                    <i class="bi bi-clipboard-check text-warning display-6 mb-3"></i>
                    <h5 class="card-title">Mock Exam</h5>
                    <p class="text-muted small">Simulate exam conditions</p>
                  </div>
                </div>
              </a>
            </div>
          </div>
        </div>

        <div class="col-lg-4">
          <div class="card border-0 shadow-sm">
            <div class="card-body text-center p-4">
              <h5 class="card-title mb-4">Your Progress</h5>
              <div class="progress-dial-container mb-3">
                <svg width="180" height="180" viewBox="0 0 180 180" class="progress-dial">
                  <defs>
                    <linearGradient id="dialGrad" x1="0%" y1="0%" x2="100%" y2="0%">
                      <stop offset="0%" style="stop-color:{dial_bg};stop-opacity:0.3" />
                      <stop offset="100%" style="stop-color:{dial_bg};stop-opacity:1" />
                    </linearGradient>
                  </defs>
                  <path d="M 30 90 A 60 60 0 1 1 150 90" fill="none" stroke="#e9ecef" stroke-width="8" stroke-linecap="round"/>
                  <path d="M 30 90 A 60 60 0 {1 if avg > 50 else 0} 1 {30 + (120 * avg / 100)} {90 - (60 * (1 - abs(((avg / 100) * 2) - 1)))}"
                        fill="none" stroke="url(#dialGrad)" stroke-width="8" stroke-linecap="round"
                        class="progress-arc" data-score="{avg}"/>
                  <text x="90" y="85" text-anchor="middle" class="dial-score text-{dial_color}" font-size="28" font-weight="bold">{avg}%</text>
                  <text x="90" y="105" text-anchor="middle" class="dial-label" font-size="14" fill="#6c757d">Average Score</text>
                </svg>
              </div>
              <div class="row g-2 text-center">
                <div class="col-6">
                  <div class="small text-muted">Attempts</div>
                  <div class="fw-bold text-primary">{len(hist)}</div>
                </div>
                <div class="col-6">
                  <div class="small text-muted">Best Score</div>
                  <div class="fw-bold text-success">{max([h.get('score', 0) for h in hist], default=0):.0f}%</div>
                </div>
              </div>
              <a href="/progress" class="btn btn-outline-primary btn-sm mt-3">View Details</a>
            </div>
          </div>
        </div>
      </div>
    </div>

    <style>
      .study-card {{
        transition: all 0.3s ease;
        border: 2px solid transparent;
      }}
      .study-card:hover {{
        transform: translateY(-4px);
        border-color: var(--primary-blue);
        box-shadow: 0 8px 25px rgba(37, 99, 235, 0.15) !important;
      }}
      .text-decoration-none:hover {{
        text-decoration: none !important;
      }}
    </style>
    """
    return base_layout("Dashboard", body)
# ====== Billing & Stripe ======
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

    # Build the plans section OUTSIDE the f-string to avoid f-string parser issues
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
# ====== Settings ======
@app.route("/settings", methods=["GET","POST"])
@login_required
def settings_page():
    user = _find_user(session.get("email",""))
    if not user:
        return redirect(url_for("login_page"))

    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        password = (request.form.get("password") or "").strip()
        updates = {}
        if name and name != user.get("name"):
            updates["name"] = name
            session["name"] = name
        if password:
            ok, _msg = validate_password(password)
            if ok:
                updates["password_hash"] = generate_password_hash(password)
        if updates:
            _update_user(user["id"], updates)
        return redirect(url_for("settings_page"))

    content = f"""
    <div class="container">
      <div class="row justify-content-center"><div class="col-lg-6">
        <div class="card"><div class="card-header bg-secondary text-white"><h3 class="mb-0"><i class="bi bi-gear me-2"></i>Account Settings</h3></div>
          <div class="card-body">
            <form method="POST">
              <input type="hidden" name="csrf_token" value="{csrf_token()}"/>
              <div class="mb-3">
                <label class="form-label fw-semibold">Name</label>
                <input type="text" class="form-control" name="name" value="{html.escape(user.get('name',''))}" required>
              </div>
              <div class="mb-3">
                <label class="form-label fw-semibold">Email</label>
                <input type="email" class="form-control" value="{html.escape(user.get('email',''))}" readonly>
                <div class="form-text">Email cannot be changed</div>
              </div>
              <div class="mb-4">
                <label class="form-label fw-semibold">New Password</label>
                <input type="password" class="form-control" name="password" minlength="8" placeholder="Leave blank to keep current password">
              </div>
              <button type="submit" class="btn btn-primary">Update Settings</button>
            </form>
          </div>
        </div>
      </div></div>
    </div>"""
    return base_layout("Account Settings", content)

# ====== Error Handlers ======
@app.errorhandler(403)
def forbidden(e):
    return base_layout("Access Denied", """
    <div class="container"><div class="row justify-content-center"><div class="col-md-6 text-center">
      <div class="mb-4"><i class="bi bi-shield-x text-danger display-1"></i></div>
      <h1 class="display-4 text-muted mb-3">403</h1><h3 class="mb-3">Access Denied</h3>
      <p class="text-muted mb-4">You don't have permission to access this resource.</p>
      <a href="/" class="btn btn-primary"><i class="bi bi-house me-1"></i>Go Home</a>
    </div></div></div>
    """), 403

@app.errorhandler(404)
def not_found(e):
    return base_layout("Not Found", """
    <div class="container"><div class="row justify-content-center"><div class="col-md-6 text-center">
      <div class="mb-4"><i class="bi bi-compass text-warning display-1"></i></div>
      <h1 class="display-4 text-muted mb-3">404</h1><h3 class="mb-3">Page Not Found</h3>
      <p class="text-muted mb-4">The page you're looking for doesn't exist or has been moved.</p>
      <a href="/" class="btn btn-primary"><i class="bi bi-house me-1"></i>Go Home</a>
    </div></div></div>
    """), 404

@app.errorhandler(413)
def request_too_large(e):
    return base_layout("Request Too Large", """
    <div class="container"><div class="row justify-content-center"><div class="col-md-6 text-center">
      <div class="mb-4"><i class="bi bi-file-earmark-x text-warning display-1"></i></div>
      <h1 class="display-4 text-muted mb-3">413</h1><h3 class="mb-3">Request Too Large</h3>
      <p class="text-muted mb-4">The request is too large to process.</p>
      <a href="/" class="btn btn-primary"><i class="bi bi-house me-1"></i>Go Home</a>
    </div></div></div>
    """), 413

@app.errorhandler(500)
def server_error(e):
    logger.error("Server error: %s", e, exc_info=True)
    return base_layout("Server Error", """
    <div class="container"><div class="row justify-content-center"><div class="col-md-6 text-center">
      <div class="mb-4"><i class="bi bi-exclamation-triangle text-danger display-1"></i></div>
      <h1 class="display-4 text-muted mb-3">500</h1><h3 class="mb-3">Something Went Wrong</h3>
      <p class="text-muted mb-4">We're working to fix this issue. Please try again later.</p>
      <a href="/" class="btn btn-primary"><i class="bi bi-house me-1"></i>Go Home</a>
    </div></div></div>
    """), 500

# ====== Sample Data Init ======
def init_sample_data():
    try:
        logger.info("Sample data initialized (questions loaded: %d)", len(ALL_QUESTIONS))
    except Exception as e:
        logger.error("Failed to initialize sample data: %s", e)
# ====== Core Feature Routes (placeholders, no layout changes) ======

# ====== Tutor Routes (fixes 404; integrates AI; no layout changes) ======
# IMPORTANT: Ensure this is the ONLY Tutor block in the file.
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
                item = {
                    "ts": datetime.utcnow().isoformat() + "Z",
                    "q": user_query,
                    "a": tutor_answer,
                    "meta": meta
                }
                _append_user_history(user_id, "tutor", item)
                _log_event(user_id, "tutor.ask", {
                    "q_len": len(user_query),
                    "ok": True,
                    "model": meta.get("model")
                })
            else:
                tutor_error = answer
                _log_event(user_id, "tutor.ask", {"q_len": len(user_query), "ok": False})

    recent = _get_user_history(user_id, "tutor", limit=5)

    # --- Pre-format HTML to avoid backslashes inside f-string expressions ---
    tutor_block = ""
    if tutor_answer:
        safe_answer = html.escape(tutor_answer).replace("\n", "<br>")
        tutor_block = (
            "<div class='alert alert-success'>"
            "<div class='fw-semibold mb-1'>Tutor:</div>"
            + safe_answer +
            "</div>"
        )

    error_block = ""
    if tutor_error:
        error_block = "<div class='alert alert-danger'>" + html.escape(tutor_error) + "</div>"

    if recent:
        pieces = []
        for item in recent:
            ts = html.escape(item.get("ts",""))
            q_html = html.escape(item.get("q","")).replace("\n","<br>")
            a_html = html.escape(item.get("a","")).replace("\n","<br>")
            pieces.append(
                "<div class='mb-3'>"
                "<div class='small text-muted'>" + ts + "</div>"
                "<div class='fw-semibold'>You</div>"
                "<div class='mb-2'>" + q_html + "</div>"
                "<div class='fw-semibold'>Tutor</div>"
                "<div>" + a_html + "</div>"
                "</div>"
            )
        history_html = "".join(pieces)
    else:
        history_html = "<div class='text-muted'>No history yet.</div>"

    content = f"""
    <div class="container">
      <div class="row justify-content-center"><div class="col-lg-8">
        <div class="card">
          <div class="card-header bg-primary text-white">
            <h3 class="mb-0"><i class="bi bi-mortarboard me-2"></i>Tutor</h3>
          </div>
          <div class="card-body">
            <form method="POST" class="mb-4">
              <input type="hidden" name="csrf_token" value="{csrf_token()}"/>
              <label class="form-label fw-semibold">Ask the Tutor</label>
              <textarea name="query" class="form-control" rows="3" placeholder="Ask about CPP/PSP topics...">{html.escape(user_query)}</textarea>
              <div class="d-flex gap-2 mt-3">
                <button type="submit" class="btn btn-primary"><i class="bi bi-send me-1"></i>Ask</button>
                <a href="/tutor" class="btn btn-outline-secondary">Clear</a>
              </div>
            </form>
            {error_block}
            {tutor_block}
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
# ====== Quiz / Mock Exam Engine (file-backed; preserves layout) ======

# ---------- Helpers ----------
def _user_id():
    return (session.get("user_id")
            or session.get("email")
            or "unknown")

def _normalize_question(q, idx=None):
    """
    Normalize heterogeneous question shapes into a common structure:

    Returns:
      {
        "id": str,
        "text": "Question text",
        "domain": "Domain string or None",
        "choices": [{"key":"A","text":"..."}, ...],
        "correct_key": "A" (optional; stored server-side only)
      }
    """
    if q is None:
        return None
    qid = str(q.get("id") or idx or uuid.uuid4())
    text = (q.get("question") or q.get("q") or q.get("stem") or q.get("text") or "").strip()
    domain = (q.get("domain") or q.get("category") or q.get("section") or None)

    raw_choices = (q.get("choices") or q.get("options") or q.get("answers") or [])
    if isinstance(raw_choices, dict):
        items = sorted(list(raw_choices.items()), key=lambda x: x[0])
        choices = [{"key": k.strip(), "text": str(v)} for k, v in items]
    else:
        choices = []
        letters = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
        for i, c in enumerate(raw_choices):
            if isinstance(c, dict):
                k = str(c.get("key") or letters[i])
                t = str(c.get("text") or c.get("label") or c.get("value") or "")
            else:
                k = letters[i]
                t = str(c)
            choices.append({"key": k.strip(), "text": t})

    correct = q.get("correct") or q.get("answer") or q.get("correct_key")
    correct_key = None
    if isinstance(correct, (int, float)):
        idx = int(correct)
        if 0 <= idx < len(choices):
            correct_key = choices[idx]["key"]
    elif isinstance(correct, str):
        c_str = correct.strip()
        keyset = {c["key"] for c in choices}
        if c_str in keyset:
            correct_key = c_str
        else:
            for c in choices:
                if c_str.lower() == c["text"].strip().lower():
                    correct_key = c["key"]
                    break

    return {
        "id": qid,
        "text": text,
        "domain": domain,
        "choices": choices,
        "correct_key": correct_key
    }

def _all_normalized_questions():
    try:
        qs = ALL_QUESTIONS  # must exist in your app
    except Exception:
        qs = []
    out = []
    for i, q in enumerate(qs):
        nq = _normalize_question(q, idx=i)
        if nq and nq.get("text") and nq.get("choices"):
            out.append(nq)
    return out

def _pick_questions(count, domain=None):
    pool = _all_normalized_questions()
    if domain:
        pool = [q for q in pool if str(q.get("domain") or "").lower() == str(domain).lower()]
    random.shuffle(pool)
    return pool[:max(1, min(count, len(pool)))]

def _run_key(mode, user_id):
    # mode in {"quiz","mock"}
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

def _grade(run):
    """
    run = {
      "mode": "quiz"/"mock",
      "qset": [{"id","text","domain","choices","correct_key"}...],
      "answers": {"qid":"A"...}
    }
    Returns (score, total, details_by_qid, domain_breakdown)
    """
    answers = run.get("answers", {})
    qset = run.get("qset", [])
    total = len(qset)
    correct = 0
    details = {}
    domain_stats = {}  # {domain: {"correct":n,"total":n}}
    for q in qset:
        qid = q["id"]
        user_key = answers.get(qid)
        corr = (q.get("correct_key") and user_key == q["correct_key"])
        if corr:
            correct += 1
        d = (q.get("domain") or "Unspecified")
        ds = domain_stats.setdefault(d, {"correct": 0, "total": 0})
        ds["total"] += 1
        if corr:
            ds["correct"] += 1
        details[qid] = {
            "user_key": user_key,
            "correct_key": q.get("correct_key"),
            "is_correct": bool(corr),
            "domain": d
        }
    return correct, total, details, domain_stats

def _percent(num, den):
    if not den:
        return 0.0
    return round(100.0 * float(num) / float(den), 1)

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

# ---------- Shared rendering (no backslashes inside f-string expressions) ----------
def _render_question_card(title, route, run, index, error_msg=""):
    qset = run.get("qset", [])
    total = len(qset)
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
              <input type="hidden" name="csrf_token" value="{csrf_token()}"/>
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

    if request.method == "GET":
        if request.args.get("reset") == "1":
            _finish_run("quiz", user_id)
            return redirect(url_for("quiz_page"))
        if request.args.get("new") == "1":
            _finish_run("quiz", user_id)

    run = _load_run("quiz", user_id)

    if not run:
        try:
            count = int(request.args.get("count") or 10)
        except Exception:
            count = 10
        count = max(5, min(count, 50))
        domain = request.args.get("domain")
        qset = _pick_questions(count, domain=domain)
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

    error_msg = ""
    if request.method == "POST":
        if HAS_CSRF and request.form.get("csrf_token") != csrf_token():
            abort(403)
        try:
            idx = int(request.form.get("index") or run.get("index", 0))
        except Exception:
            idx = run.get("index", 0)
        idx = max(0, min(idx, len(run["qset"]) - 1))

        choice = (request.form.get("choice") or "").strip()
        nav = (request.form.get("nav") or "next").strip()
        qid = run["qset"][idx]["id"]

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
                if idx == len(run["qset"]) - 1:
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
        try:
            count = int(request.args.get("count") or 50)
        except Exception:
            count = 50
        count = max(25, min(count, 150))
        domain = request.args.get("domain")
        qset = _pick_questions(count, domain=domain)
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
    if request.method == "POST":
        if HAS_CSRF and request.form.get("csrf_token") != csrf_token():
            abort(403)
        try:
            idx = int(request.form.get("index") or run.get("index", 0))
        except Exception:
            idx = run.get("index", 0)
        idx = max(0, min(idx, len(run["qset"]) - 1))

        choice = (request.form.get("choice") or "").strip()
        nav = (request.form.get("nav") or "next").strip()
        qid = run["qset"][idx]["id"]

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
                if idx == len(run["qset"]) - 1:
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

@app.route("/flashcards", methods=["GET", "POST"])
@login_required
def flashcards_page():
    content = """
    <div class="container">
      <div class="row justify-content-center"><div class="col-lg-8">
        <div class="card">
          <div class="card-header bg-success text-white">
            <h3 class="mb-0"><i class="bi bi-layers me-2"></i>Flashcards</h3>
          </div>
          <div class="card-body">
            <p class="text-muted">Flashcards are enabled at this route. Content hooks will be added next.</p>
            <a href="/" class="btn btn-outline-secondary"><i class="bi bi-arrow-left me-1"></i>Back</a>
          </div>
        </div>
      </div></div>
    </div>
    """
    return base_layout("Flashcards", content)


@app.route("/progress", methods=["GET"])
@login_required
def progress_page():
    content = """
    <div class="container">
      <div class="row justify-content-center"><div class="col-lg-8">
        <div class="card">
          <div class="card-header bg-info text-white">
            <h3 class="mb-0"><i class="bi bi-graph-up-arrow me-2"></i>Progress</h3>
          </div>
          <div class="card-body">
            <p class="text-muted">Your progress dashboard will render here (scores, domains, streaks).</p>
            <a href="/" class="btn btn-outline-secondary"><i class="bi bi-arrow-left me-1"></i>Back</a>
          </div>
        </div>
      </div></div>
    </div>
    """
    return base_layout("Progress", content)
# ====== Tracking Utils (non-breaking, file-backed) ======
def _log_event(user_id, event_type, payload):
    """Append an event for analytics/progress. Non-fatal on error."""
    try:
        data = _load_json("events.json", [])
        data.append({
            "id": str(uuid.uuid4()),
            "ts": datetime.utcnow().isoformat() + "Z",
            "user_id": user_id,
            "type": event_type,   # e.g., 'tutor.ask', 'page.view'
            "payload": payload    # dict
        })
        _save_json("events.json", data)
    except Exception as e:
        logger.warning("log_event failed: %s", e)

def _append_user_history(user_id, channel, item):
    """Store a small rolling history per user/channel (e.g., tutor)."""
    try:
        key = f"history_{channel}_{user_id}.json"
        history = _load_json(key, [])
        history.append(item)
        # Keep last 20 entries to avoid unbounded growth
        history = history[-20:]
        _save_json(key, history)
    except Exception as e:
        logger.warning("append_user_history failed: %s", e)

def _get_user_history(user_id, channel, limit=10):
    try:
        key = f"history_{channel}_{user_id}.json"
        hist = _load_json(key, [])
        return hist[-limit:]
    except Exception:
        return []


# ====== AI Client (uses your existing env keys) ======
def _call_tutor_agent(user_query, meta=None):
    """
    Calls your AI agent using environment configuration.
    Supports either:
      - OPENAI_API_KEY + MODEL_TUTOR (chat.completions)
      - Or a custom base via OPENAI_API_BASE (compatible with OpenAI spec)
    """
    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    base_url = os.environ.get("OPENAI_API_BASE", "https://api.openai.com/v1").rstrip("/")
    model = os.environ.get("MODEL_TUTOR", "gpt-4o-mini")

    if not api_key:
        return False, "Tutor is not configured: missing OPENAI_API_KEY.", {}

    # Chat Completions (widely compatible)
    url = f"{base_url}/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    system_msg = os.environ.get("TUTOR_SYSTEM_PROMPT",
        "You are a calm, expert CPP/PSP study tutor. Explain clearly, step-by-step, "
        "cite domain numbers when relevant, and ask a short follow-up check for understanding."
    )

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_msg},
            {"role": "user", "content": user_query}
        ],
        "temperature": float(os.environ.get("TUTOR_TEMP", "0.3")),
        "max_tokens": int(os.environ.get("TUTOR_MAX_TOKENS", "800")),
    }

    try:
        resp = requests.post(url, headers=headers, data=json.dumps(payload), timeout=60)
        if resp.status_code >= 400:
            return False, f"Agent error {resp.status_code}: {resp.text[:300]}", {"status": resp.status_code}
        data = resp.json()
        # OpenAI-format extraction
        answer = (data.get("choices") or [{}])[0].get("message", {}).get("content", "")
        usage = data.get("usage", {})
        return True, answer, {"usage": usage, "model": model}
    except Exception as e:
        logger.error("Tutor agent call failed: %s", e, exc_info=True)
        return False, "Network error talking to the tutor agent.", {}


# ====== Page Views Tracking (no UI change) ======
@app.before_request
def _track_page_views():
    try:
        uid = session.get("user_id") or session.get("email") or "anon"
        _log_event(uid, "page.view", {"path": request.path, "method": request.method})
    except Exception:
        pass


# ====== Analytics Hooks ======
@app.route("/api/track", methods=["POST"])
@login_required
def api_track():
    try:
        if HAS_CSRF and request.form.get("csrf_token") != csrf_token():
            abort(403)
        event_type = (request.form.get("type") or "").strip()
        payload_raw = request.form.get("payload") or "{}"
        payload = json.loads(payload_raw) if isinstance(payload_raw, str) else {}
        uid = session.get("user_id") or session.get("email") or "unknown"
        if not event_type:
            return jsonify({"ok": False, "error": "Missing type"}), 400
        _log_event(uid, event_type, payload)
        return jsonify({"ok": True})
    except Exception as e:
        logger.error("api/track failed: %s", e, exc_info=True)
        return jsonify({"ok": False, "error": "server-error"}), 500

# ====== App Factory & Main ======
def create_app():
    init_sample_data()
    logger.info("CPP Test Prep v%s starting up", APP_VERSION)
    logger.info("Debug mode: %s", DEBUG)
    logger.info("Staging mode: %s", IS_STAGING)
    logger.info("CSRF protection: %s", "enabled" if HAS_CSRF else "disabled")
    return app

# ====== Entrypoint ======
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    logger.info("Running app on port %s", port)
    app.run(host="0.0.0.0", port=port, debug=DEBUG)







