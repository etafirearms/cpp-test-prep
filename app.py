from flask import Flask, request, jsonify, session, redirect, url_for, Response, flash
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime
import os, json, random, textwrap, requests, html, csv, uuid, logging, time, hashlib, re
import stripe
import sqlite3
from contextlib import contextmanager

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Configuration ---
app = Flask(__name__)
from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)
app.secret_key = os.environ.get("SECRET_KEY") or os.urandom(24)

# Environment variables - replace with your actual values
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
OPENAI_CHAT_MODEL = os.environ.get("OPENAI_CHAT_MODEL", "gpt-4o-mini")
OPENAI_API_BASE = os.environ.get("OPENAI_API_BASE", "https://api.openai.com/v1")
stripe.api_key = os.environ.get('STRIPE_SECRET_KEY', '')
STRIPE_WEBHOOK_SECRET = os.environ.get('STRIPE_WEBHOOK_SECRET', '')
STRIPE_PREMIUM_PRICE_ID = os.environ.get('STRIPE_PREMIUM_PRICE_ID', '')
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "").strip()

# App metadata
APP_VERSION = os.environ.get("APP_VERSION", "1.0.0")
IS_STAGING = os.environ.get("RENDER_SERVICE_NAME", "").endswith("-staging")
DEBUG = os.environ.get("FLASK_DEBUG", "0") == "1"

# Flask config
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=(os.environ.get("SESSION_COOKIE_SECURE", "1") == "1"),
    MESSAGE_FLASHING=True
)

# --- Data Storage ---
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
    path = os.path.join(DATA_DIR, name)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)

# Load data
QUESTIONS = _load_json("questions.json", [])
FLASHCARDS = _load_json("flashcards.json", [])
USERS = _load_json("users.json", [])

# --- Database Functions ---
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
            subscription TEXT DEFAULT 'free',
            discount_code TEXT,
            stripe_customer_id TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        
        CREATE TABLE IF NOT EXISTS usage_stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            month TEXT NOT NULL,
            action_type TEXT NOT NULL,
            count INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users (id),
            UNIQUE(user_id, month, action_type)
        );
        
        CREATE TABLE IF NOT EXISTS quiz_history (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            quiz_type TEXT NOT NULL,
            domain TEXT NOT NULL,
            score REAL NOT NULL,
            total_questions INTEGER NOT NULL,
            correct_answers INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        );
        """)
        conn.commit()

# Initialize database if using database mode
if os.environ.get('USE_DATABASE') == '1':
    init_database()

# --- Security & Rate Limiting ---
_RATE_BUCKETS = {}

@app.after_request
def add_security_headers(resp):
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    
    csp = (
        "default-src 'self' https: data: blob:; "
        "img-src 'self' https: data:; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://js.stripe.com; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "font-src 'self' https: data:; "
        "connect-src 'self' https:; "
        "frame-src https://js.stripe.com; "
        "frame-ancestors 'none'"
    )
    resp.headers["Content-Security-Policy"] = csp
    return resp

def _client_token():
    el = (session.get("email") or "").strip().lower()
    xff = (request.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
    ip = xff or (request.remote_addr or "")
    return f"{el}|{ip}"

def _rate_limited(route: str, limit: int = 10, per_seconds: int = 60) -> bool:
    now = time.time()
    key = (route, _client_token())
    window = _RATE_BUCKETS.get(key, [])
    window = [t for t in window if now - t < per_seconds]
    if len(window) >= limit:
        _RATE_BUCKETS[key] = window
        return True
    window.append(now)
    _RATE_BUCKETS[key] = window
    return False

def _submission_sig(payload: dict) -> str:
    try:
        blob = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    except Exception:
        blob = str(payload)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()

# --- Authentication & Authorization ---
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

def _find_user(email: str):
    if not email:
        return None
    el = email.strip().lower()
    for u in USERS:
        if (u.get("email","").strip().lower() == el):
            return u
    return None

def _get_or_create_user(email: str):
    if not email:
        return None
    u = _find_user(email)
    if u:
        return u
    u = {
        "id": str(uuid.uuid4()),
        "name": session.get("name",""),
        "email": email.strip().lower(),
        "subscription": "free",
        "password_hash": generate_password_hash("changeme123"),
        "usage": {"quizzes": 0, "questions": 0, "last_active": ""},
        "created_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "history": []
    }
    USERS.append(u)
    _save_json("users.json", USERS)
    return u

# --- Usage Management ---
def check_usage_limit(user, action_type):
    if not user:
        return False, "Please log in to continue"
    
    subscription = user.get('subscription', 'free')
    usage = user.get('usage', {})
    
    today = datetime.utcnow()
    month_key = today.strftime('%Y-%m')
    monthly_usage = usage.get('monthly', {}).get(month_key, {})
    
    limits = {
        'free': {'quizzes': 5, 'questions': 50, 'tutor_msgs': 10, 'flashcards': 25},
        'premium': {'quizzes': -1, 'questions': -1, 'tutor_msgs': -1, 'flashcards': -1},
        'trial': {'quizzes': 20, 'questions': 200, 'tutor_msgs': 50, 'flashcards': 100}
    }
    
    user_limits = limits.get(subscription, limits['free'])
    current_usage = monthly_usage.get(action_type, 0)
    limit = user_limits.get(action_type, 0)
    
    if limit == -1:  # unlimited
        return True, ""
    
    if current_usage >= limit:
        return False, f"Monthly {action_type} limit reached. Upgrade to Premium for unlimited access."
    
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

def _append_user_history(email: str, entry: dict, cap: int = 200):
    if not email:
        return
    u = _get_or_create_user(email)
    if not u:
        return
    hist = u.setdefault("history", [])
    hist.append(entry)
    if len(hist) > cap:
        del hist[:-cap]
    _save_json("users.json", USERS)

# --- Question Management ---
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

def _normalize_question(q: dict) -> dict | None:
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

def _build_all_questions() -> list[dict]:
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

# --- Helper Functions ---
def safe_json_response(data, status_code=200):
    try:
        return jsonify(data), status_code
    except Exception as e:
        logger.error(f"JSON serialization error: {e}")
        return jsonify({"error": "Internal server error"}), 500

def validate_quiz_submission(data):
    errors = []
    if not data:
        errors.append("No data received")
        return errors
    
    questions = data.get('questions', [])
    if not questions:
        errors.append("No questions provided")
    if len(questions) > 100:
        errors.append("Too many questions (max 100)")
    
    for i, q in enumerate(questions):
        if not q.get('question'):
            errors.append(f"Question {i+1} missing question text")
        options = q.get('options', {})
        if not all(options.get(letter) for letter in ['A', 'B', 'C', 'D']):
            errors.append(f"Question {i+1} missing options")
        if q.get('correct') not in ['A', 'B', 'C', 'D']:
            errors.append(f"Question {i+1} has invalid correct answer")
    
    return errors

def filter_questions(domain_key: str | None) -> list[dict]:
    pool = ALL_QUESTIONS
    if not domain_key or domain_key == "random":
        return pool[:]
    return [q for q in pool if q.get("domain") == domain_key]

def build_quiz(num: int, domain_key: str | None) -> dict:
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
            "max_tokens": 700,
        }
        r = requests.post(
            f"{OPENAI_API_BASE}/chat/completions",
            headers={"Authorization": f"Bearer {OPENAI_API_KEY}", "Content-Type": "application/json"},
            json=payload,
            timeout=30,
        )
        if r.status_code != 200:
            return f"AI error ({r.status_code}). Please try again."
        data = r.json()
        return data["choices"][0]["message"]["content"]
    except Exception as e:
        return f"AI request failed: {e}"

def base_layout(title: str, body_html: str) -> str:
    user_name = session.get('name', '')
    user_email = session.get('email', '')
    is_logged_in = 'user_id' in session
    
    user_menu = ""
    if is_logged_in:
        user = _find_user(user_email)
        subscription = user.get('subscription', 'free') if user else 'free'
        plan_badge = f'<span class="badge plan-{subscription}">{subscription.title()}</span>'
        
        user_menu = f"""
        <li class="nav-item dropdown">
          <a class="nav-link dropdown-toggle" href="#" id="userDropdown" role="button" data-bs-toggle="dropdown">
            {user_name or user_email} {plan_badge}
          </a>
          <ul class="dropdown-menu" aria-labelledby="userDropdown">
            <li><a class="dropdown-item" href="/usage">Usage Dashboard</a></li>
            <li><a class="dropdown-item" href="/billing">Billing</a></li>
            <li><a class="dropdown-item" href="/settings">Settings</a></li>
            <li><hr class="dropdown-divider"></li>
            <li>
              <form method="POST" action="/logout" class="d-inline">
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
          <a class="nav-link btn btn-outline-primary ms-2" href="/signup">Sign Up</a>
        </li>
        """

    nav = f"""
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark sticky-top">
      <div class="container">
        <a class="navbar-brand fw-bold" href="/">
          <i class="bi bi-shield-check"></i> CPP Test Prep
        </a>
        
        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
          <span class="navbar-toggler-icon"></span>
        </button>
        
        <div class="collapse navbar-collapse" id="navbarNav">
          <ul class="navbar-nav me-auto">
            {'<li class="nav-item"><a class="nav-link" href="/study">Tutor</a></li>' if is_logged_in else ''}
            {'<li class="nav-item"><a class="nav-link" href="/flashcards">Flashcards</a></li>' if is_logged_in else ''}
            {'<li class="nav-item"><a class="nav-link" href="/quiz">Quiz</a></li>' if is_logged_in else ''}
            {'<li class="nav-item"><a class="nav-link" href="/mock-exam">Mock Exam</a></li>' if is_logged_in else ''}
            {'<li class="nav-item"><a class="nav-link" href="/progress">Progress</a></li>' if is_logged_in else ''}
          </ul>
          
          <ul class="navbar-nav">
            {user_menu}
          </ul>
        </div>
      </div>
    </nav>
    """
    
    disclaimer = f"""
    <footer class="bg-light py-3 mt-5">
      <div class="container">
        <div class="row">
          <div class="col-md-8">
            <small class="text-muted">
              <strong>Notice:</strong> This platform is independent and not affiliated with ASIS International. 
              CPP® is a mark of ASIS International, Inc.
            </small>
          </div>
          <div class="col-md-4 text-end">
            <small class="text-muted">Version {APP_VERSION}</small>
          </div>
        </div>
      </div>
    </footer>
    """
    
    stage_banner = ("""
    <div class="alert alert-warning alert-dismissible fade show" role="alert">
      <div class="container text-center">
        <strong>STAGING ENVIRONMENT</strong> — Not for production use.
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
      </div>
    </div>
    """ if IS_STAGING else "")

    style_css = """
    <style>
      .card { box-shadow: 0 2px 4px rgba(0,0,0,0.1); border: none; }
      .btn-primary { background: linear-gradient(45deg, #007bff, #0056b3); border: none; }
      .progress { height: 8px; }
      .navbar-brand i { color: #28a745; }
      .alert-success { border-left: 4px solid #28a745; }
      .alert-warning { border-left: 4px solid #ffc107; }
      .alert-danger { border-left: 4px solid #dc3545; }
      .badge { font-size: 0.8em; }
      .usage-warning { background: linear-gradient(45deg, #fff3cd, #ffeaa7); }
      .usage-critical { background: linear-gradient(45deg, #f8d7da, #fdcae1); }
      .plan-free { background: #6c757d; }
      .plan-premium { background: linear-gradient(45deg, #007bff, #0056b3); }
      .plan-trial { background: #28a745; }
      @media (max-width: 768px) {
        .container { padding: 0 15px; }
        .card { margin-bottom: 1rem; }
      }
    </style>
    """

    return f"""<!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>{title} - CPP Test Prep</title>
      <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
      <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.7.2/font/bootstrap-icons.css" rel="stylesheet">
      {style_css}
    </head>
    <body class="d-flex flex-column min-vh-100">
      {nav}
      {stage_banner}
      
      <main class="flex-grow-1">
        {body_html}
      </main>
      
      {disclaimer}
      
      <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    </body>
    </html>"""

# --- Stripe Integration ---
def create_stripe_checkout_session(user_email, plan='premium'):
    try:
        if not STRIPE_PREMIUM_PRICE_ID:
            logger.error("Stripe price ID not configured")
            return None
            
            checkout_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{'price': STRIPE_PREMIUM_PRICE_ID, 'quantity': 1}],
            mode='subscription',
            customer_email=user_email,
            success_url=request.url_root + 'billing/success',
            cancel_url=request.url_root + 'billing',
            metadata={'user_email': user_email, 'plan': plan}
        )
        return checkout_session.url
    except Exception as e:
        logger.error(f"Stripe session creation failed: {e}")
        return None

# --- Routes ---

# Health check
@app.get("/healthz")
def healthz():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}

# Authentication routes
@app.get("/login")
def login_page():
    if 'user_id' in session:
        return redirect(url_for('home'))
    
    body = """
    <div class="container mt-5">
      <div class="row justify-content-center">
        <div class="col-md-6">
          <div class="card">
            <div class="card-body">
              <h2 class="card-title text-center mb-4">Sign In</h2>
              
              <form method="POST" action="/login">
                <div class="mb-3">
                  <label for="email" class="form-label">Email</label>
                  <input type="email" class="form-control" name="email" required>
                </div>
                <div class="mb-3">
                  <label for="password" class="form-label">Password</label>
                  <input type="password" class="form-control" name="password" required>
                </div>
                <button type="submit" class="btn btn-primary w-100">Sign In</button>
              </form>
              
              <div class="text-center mt-3">
                <a href="/signup">Don't have an account? Sign up</a>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
    """
    return base_layout("Login", body)

@app.post("/login")
def login_post():
    email = request.form.get('email', '').strip().lower()
    password = request.form.get('password', '')
    
    if not email or not password:
        return redirect(url_for('login_page'))
    
    user = _find_user(email)
    if user and check_password_hash(user.get('password_hash', ''), password):
        session['user_id'] = user['id']
        session['email'] = user['email']
        session['name'] = user['name']
        return redirect(url_for('home'))
    
    return redirect(url_for('login_page'))

@app.get("/signup")
def signup_page():
    body = """
    <div class="container mt-5">
      <div class="row justify-content-center">
        <div class="col-md-8">
          <h2 class="text-center mb-4">Choose Your Plan</h2>
          
          <div class="row mb-4">
            <div class="col-md-6">
              <div class="card h-100">
                <div class="card-body text-center">
                  <h4 class="card-title">Free Plan</h4>
                  <h2 class="text-primary">$0<small class="text-muted">/month</small></h2>
                  <ul class="list-unstyled">
                    <li>✓ 5 quizzes per month</li>
                    <li>✓ Basic flashcards</li>
                    <li>✓ Limited AI tutor</li>
                  </ul>
                  <button class="btn btn-outline-primary" onclick="selectPlan('free')">Select Free</button>
                </div>
              </div>
            </div>
            <div class="col-md-6">
              <div class="card h-100 border-primary">
                <div class="card-body text-center">
                  <h4 class="card-title">Premium Plan</h4>
                  <h2 class="text-primary">$29<small class="text-muted">/month</small></h2>
                  <ul class="list-unstyled">
                    <li>✓ Unlimited quizzes</li>
                    <li>✓ All flashcards</li>
                    <li>✓ Full AI tutor access</li>
                    <li>✓ Progress analytics</li>
                  </ul>
                  <button class="btn btn-primary" onclick="selectPlan('premium')">Select Premium</button>
                </div>
              </div>
            </div>
          </div>
          
          <div class="card">
            <div class="card-body">
              <h3 class="card-title">Create Account</h3>
              
              <form method="POST" action="/signup" id="signupForm">
                <input type="hidden" name="plan" id="selectedPlan" value="free">
                
                <div class="mb-3">
                  <label for="name" class="form-label">Full Name</label>
                  <input type="text" class="form-control" name="name" required>
                </div>
                
                <div class="mb-3">
                  <label for="email" class="form-label">Email</label>
                  <input type="email" class="form-control" name="email" required>
                </div>
                
                <div class="mb-3">
                  <label for="password" class="form-label">Password</label>
                  <input type="password" class="form-control" name="password" required minlength="8">
                  <small class="text-muted">At least 8 characters</small>
                </div>
                
                <div class="mb-3">
                  <label for="discount_code" class="form-label">Discount Code (Optional)</label>
                  <input type="text" class="form-control" name="discount_code" placeholder="Enter code">
                </div>
                
                <button type="submit" class="btn btn-success w-100">Create Account</button>
              </form>
              
              <div class="text-center mt-3">
                <a href="/login">Already have an account? Sign in</a>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
    
    <script>
      function selectPlan(plan) {
        document.getElementById('selectedPlan').value = plan;
        document.querySelectorAll('.card').forEach(card => {
          card.classList.remove('border-success');
        });
        event.target.closest('.card').classList.add('border-success');
      }
    </script>
    """
    return base_layout("Sign Up", body)

@app.post("/signup")
def signup_post():
    name = request.form.get('name', '').strip()
    email = request.form.get('email', '').strip().lower()
    password = request.form.get('password', '')
    plan = request.form.get('plan', 'free')
    discount_code = request.form.get('discount_code', '').strip()
    
    if not name or not email or not password:
        return redirect(url_for('signup_page'))
    
    if not validate_email(email):
        return redirect(url_for('signup_page'))
    
    if len(password) < 8:
        return redirect(url_for('signup_page'))
    
    if _find_user(email):
        return redirect(url_for('signup_page'))
    
    final_plan = plan
    if discount_code:
        valid_codes = {
            'STUDENT50': {'discount': 50, 'plan_upgrade': None},
            'PREMIUM30': {'discount': 30, 'plan_upgrade': 'premium'},
            'TRIAL': {'discount': 0, 'plan_upgrade': 'trial'}
        }
        if discount_code.upper() in valid_codes:
            code_info = valid_codes[discount_code.upper()]
            if code_info['plan_upgrade']:
                final_plan = code_info['plan_upgrade']
    
    user = {
        "id": str(uuid.uuid4()),
        "name": name,
        "email": email,
        "password_hash": generate_password_hash(password),
        "subscription": final_plan,
        "discount_code": discount_code,
        "usage": {"quizzes": 0, "questions": 0, "tutor_msgs": 0, "flashcards": 0, "last_active": ""},
        "created_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "history": []
    }
    
    USERS.append(user)
    _save_json("users.json", USERS)
    
    session['user_id'] = user['id']
    session['email'] = user['email']
    session['name'] = user['name']
    
    if final_plan == 'premium':
        return redirect(url_for('billing_page'))
    
    return redirect(url_for('home'))

@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for('login_page'))

# Home page
@app.get("/")
def home():
    if 'user_id' not in session:
        # Landing page for non-authenticated users
        body = """
        <div class="container mt-5">
          <div class="row justify-content-center">
            <div class="col-lg-8 text-center">
              <h1 class="display-4 fw-bold mb-4">Master the CPP Exam</h1>
              <p class="lead mb-4">Comprehensive test preparation with AI tutoring, practice quizzes, and progress tracking.</p>
              
              <div class="row mb-5">
                <div class="col-md-4">
                  <i class="bi bi-robot display-6 text-primary mb-3"></i>
                  <h4>AI Tutor</h4>
                  <p>Get personalized explanations and study guidance</p>
                </div>
                <div class="col-md-4">
                  <i class="bi bi-card-text display-6 text-primary mb-3"></i>
                  <h4>Practice Quizzes</h4>
                  <p>Hundreds of questions across all CPP domains</p>
                </div>
                <div class="col-md-4">
                  <i class="bi bi-graph-up display-6 text-primary mb-3"></i>
                  <h4>Progress Tracking</h4>
                  <p>Monitor your improvement and identify weak areas</p>
                </div>
              </div>
              
              <div class="mb-4">
                <a href="/signup" class="btn btn-primary btn-lg me-3">Start Free Trial</a>
                <a href="/login" class="btn btn-outline-primary btn-lg">Sign In</a>
              </div>
            </div>
          </div>
        </div>
        """
        return base_layout("CPP Test Prep", body)
    
    # Authenticated user dashboard
    user_name = session.get('name', '').split(' ')[0] or 'there'
    hist = session.get("quiz_history", [])
    avg = round(sum(h.get("score", 0.0) for h in hist) / len(hist), 1) if hist else 0.0

    tips = [
        "Small wins add up — try a focused 15-minute session.",
        "Active recall beats rereading — test yourself often.",
        "Mix topics. Switching domains improves long-term memory.",
        "Practice under time pressure to build exam stamina.",
        "Teach a concept aloud — if you can explain it, you know it.",
    ]
    tip = random.choice(tips)

    body = f"""
    <div class="container mt-4">
      <div class="row">
        <div class="col-lg-8">
          <div class="card mb-4">
            <div class="card-body">
              <h1 class="h3">Welcome back, {user_name}!</h1>
              <p class="text-muted">Ready to continue your CPP exam preparation?</p>
            </div>
          </div>
          
          <div class="card mb-4">
            <div class="card-body">
              <h5 class="card-title">💡 Today's tip</h5>
              <p class="card-text">{tip}</p>
            </div>
          </div>
          
          <div class="row">
            <div class="col-md-6 mb-3">
              <a href="/study" class="btn btn-outline-primary btn-lg w-100">
                <i class="bi bi-robot"></i> Open Tutor
              </a>
            </div>
            <div class="col-md-6 mb-3">
              <a href="/quiz" class="btn btn-primary btn-lg w-100">
                <i class="bi bi-card-text"></i> Practice Quiz
              </a>
            </div>
            <div class="col-md-6 mb-3">
              <a href="/flashcards" class="btn btn-outline-secondary btn-lg w-100">
                <i class="bi bi-card-list"></i> Flashcards
              </a>
            </div>
            <div class="col-md-6 mb-3">
              <a href="/mock-exam" class="btn btn-warning btn-lg w-100">
                <i class="bi bi-clipboard-check"></i> Mock Exam
              </a>
            </div>
          </div>
        </div>
        
        <div class="col-lg-4">
          <div class="card">
            <div class="card-body text-center">
              <h5>Your Progress</h5>
              <div class="display-4 text-primary">{avg}%</div>
              <p class="text-muted">Average quiz score</p>
              <a href="/progress" class="btn btn-sm btn-outline-primary">View Details</a>
            </div>
          </div>
        </div>
      </div>
    </div>
    """
    return base_layout("Dashboard", body)

# Study/Tutor page
@app.get("/study")
@login_required
def study_page():
    chips = ['<span class="badge bg-secondary me-2 mb-2 domain-chip" data-domain="random">Random</span>']
    chips.extend([f'<span class="badge bg-primary me-2 mb-2 domain-chip" data-domain="{k}">{v}</span>' for k, v in DOMAINS.items()])

    SUGGESTIONS = {
        "security-principles": [
            "Explain defense in depth with an example",
            "Risk assessment steps and quick scenario",
            "Least privilege vs. zero trust — differences",
            "Common control categories (prevent/detect/correct)"
        ],
        "business-principles": [
            "Risk-based budgeting in security",
            "Build a business case for CCTV upgrade",
            "ROI vs. risk reduction — how to explain",
            "KPIs for a security program"
        ],
        "investigations": [
            "Chain of custody — quick checklist",
            "Interview vs. interrogation — differences",
            "Evidence handling for digital media",
            "Scene preservation basics"
        ],
        "personnel-security": [
            "Termination checklist — access + property",
            "Pre-employment screening best practices",
            "Insider threat indicators",
            "Visitor/contractor controls"
        ],
        "physical-security": [
            "CPTED quick wins for offices",
            "Perimeter vs. internal controls",
            "Locks and key control basics",
            "Access control levels overview"
        ],
        "information-security": [
            "Incident response phases",
            "Phishing controls: people + tech",
            "Backups: 3-2-1 rule",
            "Security awareness ideas"
        ],
        "crisis-management": [
            "BCP vs. DR — differences",
            "Crisis comms checklist",
            "Tabletop exercise outline",
            "Critical function identification"
        ]
    }
    sugg_json = json.dumps(SUGGESTIONS)

    body = f"""
    <div class="container mt-4">
      <div class="row justify-content-center">
        <div class="col-lg-8">
          <div class="card">
            <div class="card-body">
              <h2><i class="bi bi-robot"></i> AI Tutor</h2>
              
              <div class="mb-3">
                <label class="form-label">Pick a domain:</label>
                <div>{''.join(chips)}</div>
              </div>
              
              <div class="chat-container">
                <div class="input-group mb-3">
                  <input type="text" class="form-control" id="chatInput" placeholder="Ask your question...">
                  <button class="btn btn-primary" type="button" id="sendBtn">Send</button>
                </div>
                
                <div class="alert alert-info">
                  <small><strong>Tip:</strong> "Explain risk assessment steps with a quick example."</small>
                </div>
                
                <div class="mb-3">
                  <strong>How to use Tutor:</strong><br>
                  <small>1) Pick a domain or keep Random. 2) Click a suggested topic or type your question.
                  3) The reply appears formatted for easy reading. 4) Ask follow-ups to go deeper.</small>
                </div>
                
                <div id="chatHistory"></div>
                <div id="suggestions" class="mt-3">
                  <h6>Suggested topics</h6>
                  <div id="suggestionList"></div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
    
    <script>
      const suggestions = {sugg_json};
      let currentDomain = 'random';
      
      function updateSuggestions(domain) {{
        const list = document.getElementById('suggestionList');
        const domainSuggestions = suggestions[domain] || suggestions['security-principles'];
        list.innerHTML = domainSuggestions.map(s => 
          `<span class="badge bg-light text-dark me-2 mb-2" style="cursor:pointer" onclick="askQuestion('${{s}}')">${{s}}</span>`
        ).join('');
      }}
      
      function askQuestion(question) {{
        document.getElementById('chatInput').value = question;
        sendMessage();
      }}
      
      function sendMessage() {{
        const input = document.getElementById('chatInput');
        const message = input.value.trim();
        if (!message) return;
        
        const chatHistory = document.getElementById('chatHistory');
        chatHistory.innerHTML += `<div class="mb-2"><strong>You:</strong> ${{message}}</div>`;
        chatHistory.innerHTML += `<div class="mb-2 text-muted">AI is thinking...</div>`;
        
        input.value = '';
        
        fetch('/api/chat', {{
          method: 'POST',
          headers: {{'Content-Type': 'application/json'}},
          body: JSON.stringify({{message: message, domain: currentDomain}})
        }})
        .then(r => r.json())
        .then(data => {{
          chatHistory.lastElementChild.outerHTML = `<div class="mb-3"><strong>AI Tutor:</strong><br>${{data.response.replace(/\\n/g, '<br>')}}</div>`;
          chatHistory.scrollTop = chatHistory.scrollHeight;
        }})
        .catch(err => {{
          chatHistory.lastElementChild.outerHTML = `<div class="mb-3 text-danger">Error: Please try again</div>`;
        }});
      }}
      
      document.querySelectorAll('.domain-chip').forEach(chip => {{
        chip.addEventListener('click', function() {{
          document.querySelectorAll('.domain-chip').forEach(c => c.className = c.className.replace('bg-success', 'bg-primary').replace('bg-secondary', 'bg-secondary'));
          this.className = this.className.replace('bg-primary', 'bg-success').replace('bg-secondary', 'bg-success');
          currentDomain = this.dataset.domain;
          updateSuggestions(currentDomain);
        }});
      }});
      
      document.getElementById('sendBtn').addEventListener('click', sendMessage);
      document.getElementById('chatInput').addEventListener('keypress', function(e) {{
        if (e.key === 'Enter') sendMessage();
      }});
      
      updateSuggestions('random');
    </script>
    """
    return base_layout("AI Tutor", body)

@app.post("/api/chat")
@login_required
def api_chat():
    user = _find_user(session.get('email', ''))
    can_chat, error_msg = check_usage_limit(user, 'tutor_msgs')
    
    if not can_chat:
        return safe_json_response({"error": error_msg, "upgrade_required": True}, 403)

    if _rate_limited("chat", limit=10, per_seconds=60):
        return safe_json_response({"error": "Too many requests. Please wait a moment."}, 429)

    data = request.get_json() or {}
    user_msg = (data.get("message") or "").strip()
    dom = data.get("domain")
    
    if not user_msg:
        return safe_json_response({"error": "Empty message"}, 400)

    prefix = ""
    if dom and dom in DOMAINS:
        prefix = f"Focus on the domain: {DOMAINS[dom]}.\n"

    reply = chat_with_ai([prefix + user_msg])
    increment_usage(user['email'], 'tutor_msgs')
    
    return safe_json_response({"response": reply, "timestamp": datetime.utcnow().isoformat()})

# Quiz page
@app.get("/quiz")
@login_required
def quiz_page():
    chips = ['<span class="badge bg-secondary me-2 mb-2 domain-chip" data-domain="random">Random</span>']
    chips.extend([f'<span class="badge bg-primary me-2 mb-2 domain-chip" data-domain="{k}">{v}</span>' for k, v in DOMAINS.items()])
    
    q = build_quiz(10, "random")
    q_json = json.dumps(q)
    
    body = f"""
    <div class="container mt-4">
      <div class="card">
        <div class="card-body">
          <div class="row">
            <div class="col-md-8">
              <h2><i class="bi bi-card-text"></i> Practice Quiz</h2>
              <p id="quizInfo">10 questions • Domain: Random</p>
            </div>
            <div class="col-md-4 text-end">
              <div class="btn-group">
                <select class="form-select" id="questionCount">
                  <option value="5">5</option>
                  <option value="10" selected>10</option>
                  <option value="15">15</option>
                  <option value="20">20</option>
                </select>
                <button class="btn btn-outline-secondary" id="buildQuiz">Build Quiz</button>
              </div>
            </div>
          </div>
          
          <div class="mb-3">
            {''.join(chips)}
          </div>
          
          <div id="quizContainer">
            <div id="quizQuestions"></div>
            <button class="btn btn-success btn-lg" id="submitQuiz" style="display:none">Submit Quiz</button>
          </div>
          
          <div id="resultsModal" class="modal" tabindex="-1">
            <div class="modal-dialog modal-lg">
              <div class="modal-content">
                <div class="modal-header">
                  <h5 class="modal-title">Quiz Results</h5>
                  <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body" id="resultsContent"></div>
                <div class="modal-footer">
                  <button type="button" class="btn btn-primary" data-bs-dismiss="modal">Close</button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
    
    <script>
      let currentQuiz = {q_json};
      let currentDomain = 'random';
      let userAnswers = {{}};
      
      function renderQuiz() {{
        const container = document.getElementById('quizQuestions');
        const questions = currentQuiz.questions || [];
        
        container.innerHTML = questions.map((q, i) => `
          <div class="card mb-3">
            <div class="card-body">
              <h6>Question ${{i + 1}} of ${{questions.length}}</h6>
              <p>${{q.question}}</p>
              ${{Object.entries(q.options).map(([letter, text]) => `
                <div class="form-check">
                  <input class="form-check-input" type="radio" name="q${{i}}" value="${{letter}}" id="q${{i}}${{letter}}">
                  <label class="form-check-label" for="q${{i}}${{letter}}">
                    ${{letter}}) ${{text}}
                  </label>
                </div>
              `).join('')}}
            </div>
          </div>
        `).join('');
        
        document.getElementById('submitQuiz').style.display = questions.length > 0 ? 'block' : 'none';
        
        // Add change listeners
        container.querySelectorAll('input[type="radio"]').forEach(input => {{
          input.addEventListener('change', function() {{
            const questionIndex = this.name.replace('q', '');
            userAnswers[questionIndex] = this.value;
          }});
        }});
      }}
      
      function buildQuiz() {{
        const count = document.getElementById('questionCount').value;
        fetch('/api/build-quiz', {{
          method: 'POST',
          headers: {{'Content-Type': 'application/json'}},
          body: JSON.stringify({{domain: currentDomain, count: parseInt(count)}})
        }})
        .then(r => r.json())
        .then(data => {{
          currentQuiz = data;
          userAnswers = {{}};
          document.getElementById('quizInfo').textContent = `${{count}} questions • Domain: ${{currentDomain === 'random' ? 'Random' : currentDomain}}`;
          renderQuiz();
        }});
      }}
      
      function submitQuiz() {{
        const questions = currentQuiz.questions || [];
        if (Object.keys(userAnswers).length < questions.length) {{
          alert('Please answer all questions before submitting.');
          return;
        }}
        
        fetch('/api/submit-quiz', {{
          method: 'POST',
          headers: {{'Content-Type': 'application/json'}},
          body: JSON.stringify({{
            quiz_type: 'practice',
            domain: currentDomain,
            questions: questions,
            answers: userAnswers
          }})
        }})
        .then(r => r.json())
        .then(data => {{
          if (data.success) {{
            showResults(data);
          }} else {{
            alert(data.error || 'Submission failed');
          }}
        }});
      }}
      
      function showResults(data) {{
        const content = document.getElementById('resultsContent');
        const insights = data.performance_insights.join('<br>');
        
        content.innerHTML = `
          <div class="text-center mb-4">
            <h3 class="display-4 text-${{data.score >= 70 ? 'success' : 'warning'}}">${{data.score}}%</h3>
            <p>You got ${{data.correct}} out of ${{data.total}} questions correct</p>
            <div class="alert alert-info">${{insights}}</div>
          </div>
          
          <h5>Detailed Results</h5>
          ${{data.detailed_results.map((result, i) => `
            <div class="card mb-2 ${{result.is_correct ? 'border-success' : 'border-danger'}}">
              <div class="card-body">
                <div class="d-flex justify-content-between">
                  <strong>Question ${{result.index}}</strong>
                  <span class="badge bg-${{result.is_correct ? 'success' : 'danger'}}">
                    ${{result.is_correct ? 'Correct' : 'Incorrect'}}
                  </span>
                </div>
                <p class="mt-2">${{result.question}}</p>
                <div class="row">
                  <div class="col-md-6">
                    <small><strong>Your answer:</strong> ${{result.user_letter || 'None'}} ${{result.user_text || ''}}</small>
                  </div>
                  <div class="col-md-6">
                    <small><strong>Correct answer:</strong> ${{result.correct_letter}} ${{result.correct_text}}</small>
                  </div>
                </div>
                ${{result.explanation ? `<div class="alert alert-light mt-2"><small>${{result.explanation}}</small></div>` : ''}}
              </div>
            </div>
          `).join('')}}
        `;
        
        new bootstrap.Modal(document.getElementById('resultsModal')).show();
      }}
      
      // Domain selection
      document.querySelectorAll('.domain-chip').forEach(chip => {{
        chip.addEventListener('click', function() {{
          document.querySelectorAll('.domain-chip').forEach(c => {{
            c.className = c.className.replace('bg-success', 'bg-primary').replace('bg-secondary', 'bg-secondary');
          }});
          this.className = this.className.replace('bg-primary', 'bg-success').replace('bg-secondary', 'bg-success');
          currentDomain = this.dataset.domain;
        }});
      }});
      
      document.getElementById('buildQuiz').addEventListener('click', buildQuiz);
      document.getElementById('submitQuiz').addEventListener('click', submitQuiz);
      
      renderQuiz();
    </script>
    """
    return base_layout("Practice Quiz", body)

@app.post("/api/build-quiz")
@login_required
def api_build_quiz():
    data = request.get_json() or {}
       domain = data.get("domain") or "random"
    if domain not in DOMAINS and domain != "random":
        domain = "random"
    count = int(data.get("count") or 10)
    count = max(1, min(count, 100))
    return safe_json_response(build_quiz(count, domain))

@app.post("/api/submit-quiz")
@login_required
def submit_quiz_api():
    try:
        if _rate_limited("submit-quiz", limit=10, per_seconds=60):
            return safe_json_response({"error": "Too many submissions. Please wait a moment."}, 429)
        
        user = _find_user(session.get('email', ''))
        can_submit, error_msg = check_usage_limit(user, 'quizzes')
        
        if not can_submit:
            return safe_json_response({"error": error_msg, "upgrade_required": True}, 403)
        
        data = request.get_json()
        if not data:
            return safe_json_response({"error": "Invalid JSON data"}, 400)
        
        validation_errors = validate_quiz_submission(data)
        if validation_errors:
            return safe_json_response({"error": "Invalid quiz data", "details": validation_errors}, 400)
        
        # Idempotency check
        sig = _submission_sig({
            "quiz_type": data.get("quiz_type"),
            "domain": data.get("domain"),
            "questions": data.get("questions"),
            "answers": data.get("answers"),
        })
        last_sig = session.get("last_submit_sig")
        last_ts = session.get("last_submit_ts", 0.0)
        last_result = session.get("last_submit_result")
        now_ts = time.time()
        
        if last_sig == sig and (now_ts - float(last_ts)) < 10 and last_result:
            return safe_json_response(last_result)
        
        questions = data.get("questions", [])
        answers = data.get("answers", {})
        quiz_type = data.get("quiz_type", "practice")
        domain = data.get("domain", "random").strip() or "random"
        
        total = len(questions)
        correct = 0
        detailed = []
        
        for i, q in enumerate(questions):
            user_letter = answers.get(str(i))
            correct_letter = q.get("correct")
            opts = q.get("options", {})
            is_correct = (user_letter == correct_letter)
            
            if is_correct:
                correct += 1
            
            detailed.append({
                "index": i + 1,
                "question": q.get("question", ""),
                "correct_letter": correct_letter,
                "correct_text": opts.get(correct_letter, ""),
                "user_letter": user_letter,
                "user_text": opts.get(user_letter, "") if user_letter else None,
                "explanation": q.get("explanation", ""),
                "is_correct": bool(is_correct),
            })
        
        percentage = (correct / total * 100.0) if total else 0.0
        
        increment_usage(user['email'], 'quizzes')
        increment_usage(user['email'], 'questions', total)
        
        insights = []
        if percentage >= 90:
            insights.append("🎯 Excellent — mastery level performance.")
        elif percentage >= 80:
            insights.append("✅ Strong — a few areas to review.")
        elif percentage >= 70:
            insights.append("📚 Fair — focus on weak concepts.")
        else:
            insights.append("⚠️ Needs improvement — study before a real exam.")
        
        result_payload = {
            "success": True,
            "score": round(percentage, 1),
            "correct": correct,
            "total": total,
            "domain": domain,
            "type": quiz_type,
            "performance_insights": insights,
            "detailed_results": detailed
        }
        
        session["last_submit_sig"] = sig
        session["last_submit_ts"] = now_ts
        session["last_submit_result"] = result_payload
        
        # Save to history
        result_id = str(uuid.uuid4())
        hist_entry = {
            "id": result_id,
            "type": quiz_type,
            "domain": domain,
            "date": datetime.utcnow().isoformat(),
            "score": percentage,
            "total": total,
            "correct": correct,
        }
        
        hist = session.get("quiz_history", [])
        hist.append(hist_entry)
        session["quiz_history"] = hist[-50:]
        
        _append_user_history(user['email'], hist_entry)
        
        logger.info(f"Quiz completed - User: {user['email']}, Score: {percentage}%, Domain: {domain}")
        return safe_json_response(result_payload)
        
    except Exception as e:
        logger.error(f"Quiz submission error: {str(e)}", exc_info=True)
        return safe_json_response({"error": "Failed to process quiz submission"}, 500)

# Flashcards
@app.get("/flashcards")
@login_required
def flashcards_page():
    chips = ['<span class="badge bg-secondary me-2 mb-2 domain-chip" data-domain="random">Random</span>']
    chips.extend([f'<span class="badge bg-primary me-2 mb-2 domain-chip" data-domain="{k}">{v}</span>' for k, v in DOMAINS.items()])
    
    all_cards = []
    for q in ALL_QUESTIONS:
        ans = q["options"].get(q["correct"], "")
        back = f"✅ Correct: {ans}\n\n💡 {q.get('explanation', '')}"
        all_cards.append({"front": q["question"], "back": back, "domain": q["domain"]})
    
    cards_json = json.dumps(all_cards)

    body = f"""
    <div class="container mt-4">
      <div class="row justify-content-center">
        <div class="col-lg-8">
          <div class="card">
            <div class="card-body">
              <div class="d-flex justify-content-between align-items-center mb-3">
                <h2><i class="bi bi-card-list"></i> Flashcards</h2>
                <div>
                  <button class="btn btn-outline-secondary" id="prevCard">◀ Prev</button>
                  <button class="btn btn-outline-secondary" id="nextCard">Next ▶</button>
                </div>
              </div>
              
              <div class="mb-3">
                {''.join(chips)}
              </div>
              
              <div class="flashcard-container text-center">
                <div class="card flashcard" style="min-height: 300px; cursor: pointer;" id="flashcard">
                  <div class="card-body d-flex align-items-center justify-content-center">
                    <div id="cardContent">
                      <p>Select a domain to start studying</p>
                    </div>
                  </div>
                </div>
                
                <div class="mt-3">
                  <button class="btn btn-danger me-2" id="dontKnow">❌ Don't Know</button>
                  <button class="btn btn-success" id="know">✅ Know</button>
                </div>
                
                <div class="mt-3">
                  <small class="text-muted">
                    Viewed: <span id="viewed">0</span> |
                    Know: <span id="knowCount">0</span> |
                    Don't Know: <span id="dontKnowCount">0</span>
                  </small>
                </div>
                
                <div class="mt-2">
                  <small class="text-muted">Press J to flip, L for next, K for prev.</small>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
    
    <script>
      const allCards = {cards_json};
      let currentCards = [];
      let currentIndex = 0;
      let showingBack = false;
      let currentDomain = 'random';
      let stats = {{viewed: 0, know: 0, dontKnow: 0}};
      
      function filterCards(domain) {{
        if (domain === 'random') {{
          currentCards = allCards.slice();
        }} else {{
          currentCards = allCards.filter(card => card.domain === domain);
        }}
        currentIndex = 0;
        showingBack = false;
        shuffleCards();
        showCurrentCard();
      }}
      
      function shuffleCards() {{
        for (let i = currentCards.length - 1; i > 0; i--) {{
          const j = Math.floor(Math.random() * (i + 1));
          [currentCards[i], currentCards[j]] = [currentCards[j], currentCards[i]];
        }}
      }}
      
      function showCurrentCard() {{
        if (currentCards.length === 0) {{
          document.getElementById('cardContent').innerHTML = '<p>No cards available for this domain</p>';
          return;
        }}
        
        const card = currentCards[currentIndex];
        const content = showingBack ? card.back.replace(/\\n/g, '<br>') : card.front;
        
        document.getElementById('cardContent').innerHTML = `
          <div class="card-number mb-2">
            <small class="text-muted">${{currentIndex + 1}} of ${{currentCards.length}}</small>
          </div>
          <div class="card-text">
            ${{content}}
          </div>
          <div class="mt-3">
            <small class="text-muted">${{showingBack ? 'Back' : 'Front'}} - Click to flip</small>
          </div>
        `;
      }}
      
      function flipCard() {{
        showingBack = !showingBack;
        showCurrentCard();
      }}
      
      function nextCard() {{
        if (currentCards.length === 0) return;
        currentIndex = (currentIndex + 1) % currentCards.length;
        showingBack = false;
        showCurrentCard();
        updateStats('viewed');
      }}
      
      function prevCard() {{
        if (currentCards.length === 0) return;
        currentIndex = currentIndex === 0 ? currentCards.length - 1 : currentIndex - 1;
        showingBack = false;
        showCurrentCard();
      }}
      
      function markCard(know) {{
        updateStats(know ? 'know' : 'dontKnow');
        
        fetch('/api/flashcards/mark', {{
          method: 'POST',
          headers: {{'Content-Type': 'application/json'}},
          body: JSON.stringify({{know: know, domain: currentDomain}})
        }});
        
        nextCard();
      }}
      
      function updateStats(type) {{
        stats[type]++;
        document.getElementById('viewed').textContent = stats.viewed;
        document.getElementById('knowCount').textContent = stats.know;
        document.getElementById('dontKnowCount').textContent = stats.dontKnow;
      }}
      
      // Event listeners
      document.querySelectorAll('.domain-chip').forEach(chip => {{
        chip.addEventListener('click', function() {{
          document.querySelectorAll('.domain-chip').forEach(c => {{
            c.className = c.className.replace('bg-success', 'bg-primary').replace('bg-secondary', 'bg-secondary');
          }});
          this.className = this.className.replace('bg-primary', 'bg-success').replace('bg-secondary', 'bg-success');
          currentDomain = this.dataset.domain;
          filterCards(currentDomain);
        }});
      }});
      
      document.getElementById('flashcard').addEventListener('click', flipCard);
      document.getElementById('nextCard').addEventListener('click', nextCard);
      document.getElementById('prevCard').addEventListener('click', prevCard);
      document.getElementById('know').addEventListener('click', () => markCard(true));
      document.getElementById('dontKnow').addEventListener('click', () => markCard(false));
      
      // Keyboard shortcuts
      document.addEventListener('keydown', function(e) {{
        if (e.key === 'j' || e.key === 'J') {{
          flipCard();
        }} else if (e.key === 'l' || e.key === 'L') {{
          nextCard();
        }} else if (e.key === 'k' || e.key === 'K') {{
          prevCard();
        }}
      }});
      
      // Initialize
      filterCards('random');
    </script>
    """
    return base_layout("Flashcards", body)

@app.post("/api/flashcards/mark")
@login_required
def flashcards_mark():
    user = _find_user(session.get('email', ''))
    can_use, error_msg = check_usage_limit(user, 'flashcards')
    
    if not can_use:
        return safe_json_response({"error": error_msg, "upgrade_required": True}, 403)
        
    data = request.get_json() or {}
    know = bool(data.get("know"))
    domain = (data.get("domain") or "random").strip() or "random"

    stats = session.get("flashcard_stats", {})
    by_dom = stats.get(domain, {"know": 0, "dont": 0, "viewed": 0})
    if know:
        by_dom["know"] += 1
    else:
        by_dom["dont"] += 1
    by_dom["viewed"] += 1
    stats[domain] = by_dom
    session["flashcard_stats"] = stats
    
    increment_usage(user['email'], 'flashcards')
    return safe_json_response({"ok": True, "stats": by_dom})

# Mock Exam
@app.get("/mock-exam")
@login_required
def mock_exam_page():
    chips = ['<span class="badge bg-secondary me-2 mb-2 domain-chip" data-domain="random">Random</span>']
    chips.extend([f'<span class="badge bg-primary me-2 mb-2 domain-chip" data-domain="{k}">{v}</span>' for k, v in DOMAINS.items()])
    
    q = build_quiz(25, "random")
    q_json = json.dumps(q)
    
    body = f"""
    <div class="container mt-4">
      <div class="card">
        <div class="card-body">
          <div class="row">
            <div class="col-md-8">
              <h2><i class="bi bi-clipboard-check"></i> Mock Exam</h2>
              <p id="examInfo">25 questions • Domain: Random</p>
              <div class="alert alert-warning">
                <strong>Exam Mode:</strong> This simulates real exam conditions. Take your time and answer carefully.
              </div>
            </div>
            <div class="col-md-4 text-end">
              <div class="btn-group">
                <select class="form-select" id="questionCount">
                  <option value="25" selected>25</option>
                  <option value="50">50</option>
                  <option value="75">75</option>
                  <option value="100">100</option>
                </select>
                <button class="btn btn-outline-secondary" id="buildExam">Build Exam</button>
              </div>
            </div>
          </div>
          
          <div class="mb-3">
            {''.join(chips)}
          </div>
          
          <div id="examContainer">
            <div id="examQuestions"></div>
            <button class="btn btn-warning btn-lg" id="submitExam" style="display:none">Submit Exam</button>
          </div>
          
          <div id="resultsModal" class="modal" tabindex="-1">
            <div class="modal-dialog modal-lg">
              <div class="modal-content">
                <div class="modal-header">
                  <h5 class="modal-title">Mock Exam Results</h5>
                  <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body" id="resultsContent"></div>
                <div class="modal-footer">
                  <button type="button" class="btn btn-primary" data-bs-dismiss="modal">Close</button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
    
    <script>
      let currentExam = {q_json};
      let currentDomain = 'random';
      let userAnswers = {{}};
      let startTime = null;
      
      function renderExam() {{
        const container = document.getElementById('examQuestions');
        const questions = currentExam.questions || [];
        startTime = Date.now();
        
        container.innerHTML = questions.map((q, i) => `
          <div class="card mb-3">
            <div class="card-body">
              <h6>Question ${{i + 1}} of ${{questions.length}}</h6>
              <p>${{q.question}}</p>
              ${{Object.entries(q.options).map(([letter, text]) => `
                <div class="form-check">
                  <input class="form-check-input" type="radio" name="q${{i}}" value="${{letter}}" id="eq${{i}}${{letter}}">
                  <label class="form-check-label" for="eq${{i}}${{letter}}">
                    ${{letter}}) ${{text}}
                  </label>
                </div>
              `).join('')}}
            </div>
          </div>
        `).join('');
        
        document.getElementById('submitExam').style.display = questions.length > 0 ? 'block' : 'none';
        
        container.querySelectorAll('input[type="radio"]').forEach(input => {{
          input.addEventListener('change', function() {{
            const questionIndex = this.name.replace('q', '');
            userAnswers[questionIndex] = this.value;
          }});
        }});
      }}
      
      function buildExam() {{
        const count = document.getElementById('questionCount').value;
        fetch('/api/build-quiz', {{
          method: 'POST',
          headers: {{'Content-Type': 'application/json'}},
          body: JSON.stringify({{domain: currentDomain, count: parseInt(count)}})
        }})
        .then(r => r.json())
        .then(data => {{
          currentExam = data;
          userAnswers = {{}};
          document.getElementById('examInfo').textContent = `${{count}} questions • Domain: ${{currentDomain === 'random' ? 'Random' : currentDomain}}`;
          renderExam();
        }});
      }}
      
      function submitExam() {{
        const questions = currentExam.questions || [];
        const unanswered = questions.length - Object.keys(userAnswers).length;
        
        if (unanswered > 0) {{
          if (!confirm(`You have ${{unanswered}} unanswered questions. Submit anyway?`)) {{
            return;
          }}
        }}
        
        const timeSpent = Math.round((Date.now() - startTime) / 1000 / 60);
        
        fetch('/api/submit-quiz', {{
          method: 'POST',
          headers: {{'Content-Type': 'application/json'}},
          body: JSON.stringify({{
            quiz_type: 'mock_exam',
            domain: currentDomain,
            questions: questions,
            answers: userAnswers,
            time_spent: timeSpent
          }})
        }})
        .then(r => r.json())
        .then(data => {{
          if (data.success) {{
            showResults(data, timeSpent);
          }} else {{
            alert(data.error || 'Submission failed');
          }}
        }});
      }}
      
      function showResults(data, timeSpent) {{
        const content = document.getElementById('resultsContent');
        const insights = data.performance_insights.join('<br>');
        const passFail = data.score >= 70 ? 'PASS' : 'FAIL';
        const passingClass = data.score >= 70 ? 'success' : 'danger';
        
        content.innerHTML = `
          <div class="text-center mb-4">
            <h3 class="display-4 text-${{passingClass}}">${{data.score}}%</h3>
            <h4 class="text-${{passingClass}}">${{passFail}}</h4>
            <p>You got ${{data.correct}} out of ${{data.total}} questions correct</p>
            <p><small class="text-muted">Time spent: ${{timeSpent}} minutes</small></p>
            <div class="alert alert-info">${{insights}}</div>
          </div>
          
          <div class="row mb-4">
            <div class="col-md-4 text-center">
              <div class="card">
                <div class="card-body">
                  <h5>${{data.score}}%</h5>
                  <small>Overall Score</small>
                </div>
              </div>
            </div>
            <div class="col-md-4 text-center">
              <div class="card">
                <div class="card-body">
                  <h5>${{data.correct}}/${{data.total}}</h5>
                  <small>Correct</small>
                </div>
              </div>
            </div>
            <div class="col-md-4 text-center">
              <div class="card">
                <div class="card-body">
                  <h5>${{timeSpent}}m</h5>
                  <small>Time Spent</small>
                </div>
              </div>
            </div>
          </div>
          
          <h5>Detailed Results</h5>
          <div style="max-height: 400px; overflow-y: auto;">
            ${{data.detailed_results.map((result, i) => `
              <div class="card mb-2 ${{result.is_correct ? 'border-success' : 'border-danger'}}">
                <div class="card-body">
                  <div class="d-flex justify-content-between">
                    <strong>Question ${{result.index}}</strong>
                    <span class="badge bg-${{result.is_correct ? 'success' : 'danger'}}">
                      ${{result.is_correct ? 'Correct' : 'Incorrect'}}
                    </span>
                  </div>
                  <p class="mt-2">${{result.question}}</p>
                  <div class="row">
                    <div class="col-md-6">
                      <small><strong>Your answer:</strong> ${{result.user_letter || 'None'}} ${{result.user_text || ''}}</small>
                    </div>
                    <div class="col-md-6">
                      <small><strong>Correct answer:</strong> ${{result.correct_letter}} ${{result.correct_text}}</small>
                    </div>
                  </div>
                  ${{result.explanation ? `<div class="alert alert-light mt-2"><small>${{result.explanation}}</small></div>` : ''}}
                </div>
              </div>
            `).join('')}}
          </div>
        `;
        
        new bootstrap.Modal(document.getElementById('resultsModal')).show();
      }}
      
      document.querySelectorAll('.domain-chip').forEach(chip => {{
        chip.addEventListener('click', function() {{
          document.querySelectorAll('.domain-chip').forEach(c => {{
            c.className = c.className.replace('bg-success', 'bg-primary').replace('bg-secondary', 'bg-secondary');
          }});
          this.className = this.className.replace('bg-primary', 'bg-success').replace('bg-secondary', 'bg-success');
          currentDomain = this.dataset.domain;
        }});
      }});
      
      document.getElementById('buildExam').addEventListener('click', buildExam);
      document.getElementById('submitExam').addEventListener('click', submitExam);
      
      renderExam();
    </script>
    """
    return base_layout("Mock Exam", body)

# Progress page
@app.get("/progress")
@login_required
def progress_page():
    sess_hist = session.get("quiz_history", [])
    email = session.get('email', '')
    user_hist = []
    if email:
        u = _find_user(email)
        if u:
            user_hist = u.get("history", [])
    
    seen = set()
    merged = []
    for row in (user_hist + sess_hist):
        rid = row.get("id") or f"{row.get('type')}|{row.get('domain')}|{row.get('date')}|{row.get('score')}"
        if rid in seen:
            continue
        seen.add(rid)
        merged.append(row)

    overall = round(sum(float(h.get("score", 0.0)) for h in merged) / len(merged), 1) if merged else 0.0

    domain_totals = {}
    for d_key in list(DOMAINS.keys()) + ["random"]:
        domain_totals[d_key] = {"sum": 0.0, "n": 0}
    for h in merged:
        d = (h.get("domain") or "random")
        if d not in domain_totals:
            domain_totals[d] = {"sum": 0.0, "n": 0}
        domain_totals[d]["sum"] += float(h.get("score", 0.0))
        domain_totals[d]["n"] += 1

    def bar_class(pct):
        if pct >= 80:
            return "bg-success"
        if pct >= 60:
            return "bg-warning"
        return "bg-danger"

    rows_html = []
    for d_key, agg in domain_totals.items():
        n = agg["n"]
        avg = round(agg["sum"] / n, 1) if n else 0.0
        name = DOMAINS.get(d_key, "All Domains (Random)") if d_key != "random" else "All Domains (Random)"
        if n > 0:  # Only show domains with attempts
            rows_html.append(f'''
            <tr>
              <td>{name}</td>
              <td>{n}</td>
              <td>
                <div class="progress">
                  <div class="progress-bar {bar_class(avg)}" style="width: {min(100, avg)}%">
                    <span class="text-dark fw-bold">{avg}%</span>
                  </div>
                </div>
              </td>
            </tr>
            ''')
    
    rows = "\n".join(rows_html) or '<tr><td colspan="3" class="text-center text-muted">No data yet — take a quiz!</td></tr>'

    # Recent activity
    recent_activity = sorted(merged, key=lambda x: x.get('date', ''), reverse=True)[:10]
    activity_html = []
    for activity in recent_activity:
        date_str = activity.get('date', '')
        try:
            date_obj = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
            formatted_date = date_obj.strftime('%m/%d %H:%M')
        except:
            formatted_date = date_str[:16] if date_str else 'Unknown'
        
        domain_name = DOMAINS.get(activity.get('domain', 'random'), activity.get('domain', 'Random'))
        score = activity.get('score', 0)
        quiz_type = activity.get('type', 'practice').replace('_', ' ').title()
        
        score_class = 'success' if score >= 80 else 'warning' if score >= 60 else 'danger'
        
        activity_html.append(f'''
        <div class="d-flex justify-content-between align-items-center border-bottom py-2">
          <div>
            <strong>{quiz_type}</strong> - {domain_name}<br>
            <small class="text-muted">{formatted_date}</small>
          </div>
          <span class="badge bg-{score_class}">{score}%</span>
        </div>
        ''')
    
    activity_section = '\n'.join(activity_html) if activity_html else '<p class="text-muted text-center">No recent activity</p>'

    body = f"""
    <div class="container mt-4">
      <div class="row">
        <div class="col-lg-8">
          <div class="card mb-4">
            <div class="card-body">
              <h2><i class="bi bi-graph-up"></i> Progress Overview</h2>
              
              <div class="row text-center mb-4">
                <div class="col-md-4">
                  <div class="card bg-light">
                    <div class="card-body">
                      <h3 class="display-6 text-primary">{overall}%</h3>
                      <p class="card-text">Overall Average</p>
                    </div>
                  </div>
                </div>
                <div class="col-md-4">
                  <div class="card bg-light">
                    <div class="card-body">
                      <h3 class="display-6 text-info">{len(merged)}</h3>
                      <p class="card-text">Total Attempts</p>
                    </div>
                  </div>
                </div>
                <div class="col-md-4">
                  <div class="card bg-light">
                    <div class="card-body">
                      <h3 class="display-6 text-success">{len([h for h in merged if h.get('score', 0) >= 70])}</h3>
                      <p class="card-text">Passing Scores</p>
                    </div>
                  </div>
                </div>
              </div>

              <h4>Performance by Domain</h4>
              <div class="table-responsive">
                <table class="table">
                  <thead>
                    <tr>
                      <th>Domain</th>
                      <th>Attempts</th>
                      <th>Average</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rows}
                  </tbody>
                </table>
              </div>

              <form method="POST" action="/progress/reset" class="mt-4">
                <button type="submit" class="btn btn-outline-danger btn-sm" onclick="return confirm('Reset all progress data?')">
                  Reset Session Progress
                </button>
              </form>
            </div>
          </div>
        </div>
        
        <div class="col-lg-4">
          <div class="card">
            <div class="card-body">
              <h5>Recent Activity</h5>
              <div class="recent-activity">
                {activity_section}
              </div>
              <div class="mt-3">
                <a href="/quiz" class="btn btn-primary btn-sm">Take Another Quiz</a>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
    """
    return base_layout("Progress", body)

@app.post("/progress/reset")
@login_required
def progress_reset():
    session.pop("quiz_history", None)
    session.pop("flashcard_stats", None)
    return redirect(url_for("progress_page"))

# Usage dashboard
@app.get("/usage")
@login_required
def usage_dashboard():
    user = _find_user(session.get('email', ''))
    if not user:
        return redirect(url_for('login_page'))
    
    subscription = user.get('subscription', 'free')
    usage = user.get('usage', {})
    
    today = datetime.utcnow()
    month_key = today.strftime('%Y-%m')
    monthly_usage = usage.get('monthly', {}).get(month_key, {})
    
    limits = {
        'free': {'quizzes': 5, 'questions': 50, 'tutor_msgs': 10, 'flashcards': 25},
        'premium': {'quizzes': '∞', 'questions': '∞', 'tutor_msgs': '∞', 'flashcards': '∞'},
        'trial': {'quizzes': 20, 'questions': 200, 'tutor_msgs': 50, 'flashcards': 100}
    }
    
    user_limits = limits.get(subscription, limits['free'])
    
    def usage_percentage(used, limit):
        if limit == '∞':
            return 0
        return min(100, (used / limit) * 100) if limit > 0 else 0
    
    def usage_color(used, limit):
        if limit == '∞':
            return 'success'
        pct = usage_percentage(used, limit)
        if pct >= 90:
            return 'danger'
        elif pct >= 70:
            return 'warning'
        return 'success'

    body = f"""
    <div class="container mt-4">
      <h2>Usage Dashboard</h2>
      
      <div class="row mb-4">
        <div class="col-md-6">
          <div class="card">
            <div class="card-body">
              <h5>Current Plan: <span class="badge plan-{subscription}">{subscription.title()}</span></h5>
              <p>Month: {today.strftime('%B %Y')}</p>
              
              {'<a href="/billing" class="btn btn-primary btn-sm">Upgrade to Premium</a>' if subscription == 'free' else ''}
            </div>
          </div>
        </div>
      </div>
      
      <div class="row">
        <div class="col-md-3 mb-3">
          <div class="card">
            <div class="card-body text-center">
              <h6>Quizzes</h6>
              <div class="progress mb-2" style="height: 20px;">
                <div class="progress-bar bg-{usage_color(monthly_usage.get('quizzes', 0), user_limits['quizzes'])}" 
                     style="width: {usage_percentage(monthly_usage.get('quizzes', 0), user_limits['quizzes'])}%">
                </div>
              </div>
              <small><strong>{monthly_usage.get('quizzes', 0)}</strong> / {user_limits['quizzes']}</small>
            </div>
          </div>
        </div>
        
        <div class="col-md-3 mb-3">
          <div class="card">
            <div class="card-body text-center">
              <h6>Questions</h6>
              <div class="progress mb-2" style="height: 20px;">
                <div class="progress-bar bg-{usage_color(monthly_usage.get('questions', 0), user_limits['questions'])}" 
                     style="width: {usage_percentage(monthly_usage.get('questions', 0), user_limits['questions'])}%">
                </div>
              </div>
              <small><strong>{monthly_usage.get('questions', 0)}</strong> / {user_limits['questions']}</small>
            </div>
          </div>
        </div>
        
        <div class="col-md-3 mb-3">
          <div class="card">
            <div class="card-body text-center">
              <h6>AI Tutor</h6>
              <div class="progress mb-2" style="height: 20px;">
                <div class="progress-bar bg-{usage_color(monthly_usage.get('tutor_msgs', 0), user_limits['tutor_msgs'])}" 
                     style="width: {usage_percentage(monthly_usage.get('tutor_msgs', 0), user_limits['tutor_msgs'])}%">
                </div>
              </div>
              <small><strong>{monthly_usage.get('tutor_msgs', 0)}</strong> / {user_limits['tutor_msgs']}</small>
            </div>
          </div>
        </div>
        
        <div class="col-md-3 mb-3">
          <div class="card">
            <div class="card-body text-center">
              <h6>Flashcards</h6>
              <div class="progress mb-2" style="height: 20px;">
                <div class="progress-bar bg-{usage_color(monthly_usage.get('flashcards', 0), user_limits['flashcards'])}" 
                     style="width: {usage_percentage(monthly_usage.get('flashcards', 0), user_limits['flashcards'])}%">
                </div>
              </div>
              <small><strong>{monthly_usage.get('flashcards', 0)}</strong> / {user_limits['flashcards']}</small>
            </div>
          </div>
        </div>
      </div>
      
      {'<div class="alert alert-warning mt-4"><strong>Approaching Limits:</strong> Consider upgrading to Premium for unlimited access.</div>' if any(usage_percentage(monthly_usage.get(k, 0), v) > 70 for k, v in user_limits.items() if v != '∞') else ''}
    </div>
    """
    return base_layout("Usage Dashboard", body)

# Billing and Stripe
@app.get("/billing")
@login_required
def billing_page():
    user = _find_user(session.get('email', ''))
    if not user:
        return redirect(url_for('login_page'))
    
    subscription = user.get('subscription', 'free')
    
    body = f"""
    <div class="container mt-5">
      <div class="row justify-content-center">
        <div class="col-md-8">
          <h2>Billing & Subscription</h2>
          
          <div class="card mb-4">
            <div class="card-body">
              <h5>Current Plan: <span class="badge plan-{subscription}">{subscription.title()}</span></h5>
              
              {'''
              <div class="row mt-4">
                <div class="col-md-6">
                  <div class="card border-primary">
                    <div class="card-body text-center">
                      <h4>Premium Plan</h4>
                      <h2 class="text-primary">$29<small>/month</small></h2>
                      <ul class="list-unstyled">
                        <li>✓ Unlimited quizzes</li>
                        <li>✓ Full AI tutor access</li>
                        <li>✓ Advanced analytics</li>
                        <li>✓ Priority support</li>
                        <li>✓ Mobile app access</li>
                      </ul>
                      <a href="/billing/checkout/premium" class="btn btn-primary btn-lg">
                        Upgrade Now
                      </a>
                    </div>
                  </div>
                </div>
                <div class="col-md-6">
                  <div class="card">
                    <div class="card-body">
                      <h5>Why Upgrade?</h5>
                      <ul>
                        <li>Remove all monthly limits</li>
                        <li>Access to premium question bank</li>
                        <li>Detailed performance analytics</li>
                        <li>Priority customer support</li>
                        <li>Early access to new features</li>
                      </ul>
                      
                      <div class="mt-3">
                        <h6>Discount Codes</h6>
                        <p><small>Have a code? Enter it during signup for special pricing.</small></p>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
              ''' if subscription == 'free' else '''
              <div class="alert alert-success">
                <h5><i class="bi bi-check-circle"></i> Premium Active</h5>
                <p>You have unlimited access to all features. Thank you for your support!</p>
                <ul>
                  <li>✓ Unlimited quizzes and AI tutor access</li>
                  <li>✓ Advanced progress tracking</li>
                  <li>✓ Priority customer support</li>
                </ul>
              </div>
              '''}
            </div>
          </div>
          
          <div class="card">
            <div class="card-body">
              <h5>Billing History</h5>
              <p class="text-muted">Billing history and invoices will appear here once available through Stripe.</p>
            </div>
          </div>
        </div>
      </div>
    </div>
    """
    return base_layout("Billing", body)

@app.get('/billing/checkout/<plan>')
@login_required
def billing_checkout(plan):
    user = _find_user(session.get('email', ''))
    if not user:
        return redirect(url_for('login_page'))
    
    if plan not in ['premium']:
        return redirect(url_for('billing_page'))
    
    checkout_url = create_stripe_checkout_session(user['email'], plan)
    if checkout_url:
        return redirect(checkout_url)
    else:
        return redirect(url_for('billing_page'))

@app.get('/billing/success')
@login_required
def billing_success():
    body = """
    <div class="container mt-5">
      <div class="row justify-content-center">
        <div class="col-md-6 text-center">
          <div class="alert alert-success">
            <h4>🎉 Welcome to Premium!</h4>
            <p>Your subscription is now active. You have unlimited access to all features.</p>
          </div>
          <a href="/quiz" class="btn btn-primary btn-lg">Start Learning</a>
        </div>
      </div>
    </div>
    """
    return base_layout("Welcome to Premium", body)

@app.post('/stripe/webhook')
def stripe_webhook():
    payload = request.get_data()
    sig_header = request.headers.get('Stripe-Signature')
    
    if not STRIPE_WEBHOOK_SECRET:
        return '', 400
    
    try:
        event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
    except ValueError:
        logger.error("Invalid Stripe webhook payload")
        return '', 400
    except stripe.error.SignatureVerificationError:
        logger.error("Invalid Stripe webhook signature")
        return '', 400
    
    if event['type'] == 'checkout.session.completed':
        session_obj = event['data']['object']
        customer_email = session_obj.get('customer_email')
        
        if customer_email:
            user = _find_user(customer_email)
            if user:
                user['subscription'] = 'premium'
                user['stripe_customer_id'] = session_obj.get('customer')
                _save_json("users.json", USERS)
                logger.info(f"Updated subscription for {customer_email} to premium")
    
    elif event['type'] == 'customer.subscription.deleted':
        subscription = event['data']['object']
        customer_id = subscription['customer']
        
        for user in USERS:
            if user.get('stripe_customer_id') == customer_id:
                user['subscription'] = 'free'
                _save_json("users.json", USERS)
                logger.info(f"Downgraded subscription for {user['email']} to free")
                break
    
    return '', 200

# Settings
@app.get("/settings")
@login_required
def settings_page():
    name = session.get("name", "")
    email = session.get("email", "")
    tz = session.get("timezone", "UTC")

    body = f"""
    <div class="container mt-4">
      <div class="row justify-content-center">
        <div class="col-md-6">
          <div class="card">
            <div class="card-body">
              <h2>Settings</h2>
              
              <form method="POST" action="/settings">
                <div class="mb-3">
                  <label for="email" class="form-label">Email</label>
                  <input type="email" class="form-control" name="email" value="{html.escape(email or '')}" required>
                  <div class="form-text">Used to associate your usage with your account.</div>
                </div>
                
                <div class="mb-3">
                  <label for="name" class="form-label">Name</label>
                  <input type="text" class="form-control" name="name" value="{html.escape(name or '')}" required>
                  <div class="form-text">Shown on the dashboard and in communications.</div>
                </div>

                <div class="mb-3">
                  <label for="timezone" class="form-label">Timezone</label>
                  <select class="form-select" name="timezone">
                    <option value="UTC" {'selected' if tz == 'UTC' else ''}>UTC</option>
                    <option value="US/Eastern" {'selected' if tz == 'US/Eastern' else ''}>Eastern Time</option>
                    <option value="US/Central" {'selected' if tz == 'US/Central' else ''}>Central Time</option>
                    <option value="US/Mountain" {'selected' if tz == 'US/Mountain' else ''}>Mountain Time</option>
                    <option value="US/Pacific" {'selected' if tz == 'US/Pacific' else ''}>Pacific Time</option>
                  </select>
                  <div class="form-text">Used for timestamps and study plans.</div>
                </div>

                <button type="submit" class="btn btn-primary">Save Changes</button>
              </form>
            </div>
          </div>
        </div>
      </div>
    </div>
    """
    return base_layout("Settings", body)

@app.post("/settings")
@login_required
def settings_save():
    name = (request.form.get("name") or "").strip()
    email = (request.form.get("email") or "").strip().lower()
    tz = (request.form.get("timezone") or "").strip() or "UTC"
    
    if not name or not email:
        return redirect(url_for('settings_page'))
    
    # Update user record
    user = _find_user(session.get('email', ''))
    if user:
        user['name'] = name
        user['email'] = email
        _save_json("users.json", USERS)
    
    session["name"] = name
    session["email"] = email
    session["timezone"] = tz
    return redirect(url_for('settings_page'))

# Admin routes
@app.post("/admin/login")
def admin_login():
    pwd = (request.form.get("password") or "").strip()
    nxt = request.form.get("next") or url_for("admin_home")
    if ADMIN_PASSWORD and pwd == ADMIN_PASSWORD:
        session["admin_ok"] = True
        return redirect(nxt)
    return redirect(url_for("admin_login_page", error=("nopass" if not ADMIN_PASSWORD else "badpass")))
    
@app.get("/admin/login")
def admin_login_page():
    if is_admin():
        return redirect(url_for("admin_home"))
    error = request.args.get("error")
    body = f"""
    <div class="container mt-5">
      <div class="row justify-content-center">
        <div class="col-md-6">
          <div class="card">
            <div class="card-body">
              <h2>Admin Login</h2>
              
              {'<div class="alert alert-danger">Incorrect password</div>' if error=="badpass" else ''}
              {'<div class="alert alert-warning">ADMIN_PASSWORD is not set; admin login is disabled.</div>' if (not ADMIN_PASSWORD or error=="nopass") else ''}
              
              <form method="POST" action="/admin/login">
                <input type="hidden" name="next" value="{request.args.get('next', '')}">
                <div class="mb-3">
                  <label for="password" class="form-label">Password</label>
                  <input type="password" class="form-control" name="password" required>
                </div>
                <button type="submit" class="btn btn-primary">Sign in</button>
              </form>
            </div>
          </div>
        </div>
      </div>
    </div>
    """
    return base_layout("Admin Login", body)

@app.post("/admin/logout")
def admin_logout():
    session.pop("admin_ok", None)
    return redirect(url_for("admin_login_page"))

@app.get("/admin")
def admin_home():
    if not is_admin():
        return redirect(url_for("admin_login_page", next=request.path))
        
    tab = request.args.get("tab", "questions")

    # Build questions table
    q_rows = []
    for q in QUESTIONS:
        domain = q.get("domain", "random")
        question_text = (q.get("question","")[:120]).replace("<","&lt;").replace(">","&gt;")
        opts = q.get("options", {})
        if isinstance(opts, dict):
            opt_preview = ", ".join([f"{L}) {opts.get(L,'')}" for L in ("A","B","C","D")])
        else:
            opt_preview = ", ".join([f"{i+1}) {o}" for i,o in enumerate(opts)])[:120]
        opt_preview = opt_preview.replace("<","&lt;").replace(">","&gt;")[:120]

        q_rows.append(f'''
        <tr>
          <td>{domain}</td>
          <td>{question_text}</td>
          <td>{opt_preview}</td>
          <td>{q.get("correct","")}</td>
          <td>
            <form method="POST" action="/admin/questions/delete" class="d-inline">
              <input type="hidden" name="id" value="{q.get('id', '')}">
              <button type="submit" class="btn btn-sm btn-danger" onclick="return confirm('Delete this question?')">Delete</button>
            </form>
          </td>
        </tr>
        ''')
    q_table = "\n".join(q_rows) or '<tr><td colspan="5" class="text-muted">No questions yet.</td></tr>'

    # Build users table
    u_rows = []
    for u in USERS:
        usage = u.get("usage", {})
        last_active = usage.get("last_active") or ""
        u_rows.append(f'''
        <tr>
          <td>{u.get("name","")}</td>
          <td>{u.get("email","")}</td>
          <td><span class="badge plan-{u.get("subscription","free")}">{u.get("subscription","free")}</span></td>
          <td>{usage.get("quizzes",0)}</td>
          <td>{usage.get("questions",0)}</td>
          <td>{last_active}</td>
        </tr>
        ''')
    u_table = "\n".join(u_rows) or '<tr><td colspan="6" class="text-muted">No users yet.</td></tr>'

    domain_select = '<select name="domain" class="form-control">' + ''.join([f'<option value="{k}">{v}</option>' for k, v in DOMAINS.items()]) + '</select>'

    body = f"""
    <div class="container-fluid mt-4">
      <div class="d-flex justify-content-between align-items-center mb-4">
        <h2>Admin Dashboard</h2>
        <form method="POST" action="/admin/logout" class="d-inline">
          <button type="submit" class="btn btn-outline-secondary">Log out</button>
        </form>
      </div>
      
      <ul class="nav nav-tabs mb-4">
        <li class="nav-item">
          <a class="nav-link {'active' if tab == 'questions' else ''}" href="?tab=questions">Questions</a>
        </li>
        <li class="nav-item">
          <a class="nav-link {'active' if tab == 'users' else ''}" href="?tab=users">Users</a>
        </li>
      </ul>

      {'<div>' if tab == 'questions' else '<div style="display:none;">'}
        <div class="card mb-4">
          <div class="card-body">
            <h4>Add Question</h4>
            <form method="POST" action="/admin/questions/add">
              <div class="row">
                <div class="col-md-3">
                  <label>Domain</label>
                  {domain_select}
                </div>
                <div class="col-md-9">
                  <label>Question</label>
                  <input type="text" name="question" class="form-control" required>
                </div>
              </div>
              <div class="row mt-3">
                <div class="col-md-3"><input type="text" name="opt1" placeholder="Option A" class="form-control" required></div>
                <div class="col-md-3"><input type="text" name="opt2" placeholder="Option B" class="form-control" required></div>
                <div class="col-md-3"><input type="text" name="opt3" placeholder="Option C" class="form-control" required></div>
                <div class="col-md-3"><input type="text" name="opt4" placeholder="Option D" class="form-control" required></div>
              </div>
              <div class="row mt-3">
                <div class="col-md-2">
                  <label>Answer (1-4)</label>
                  <input type="number" name="answer" min="1" max="4" class="form-control" required>
                </div>
                <div class="col-md-10">
                  <label>Explanation</label>
                  <input type="text" name="explanation" class="form-control">
                </div>
              </div>
              <button type="submit" class="btn btn-primary mt-3">Add Question</button>
            </form>
          </div>
        </div>

        <div class="card mb-4">
          <div class="card-body">
            <h4>Import Questions (CSV)</h4>
            <form method="POST" action="/admin/questions/import" enctype="multipart/form-data">
              <div class="mb-3">
                <input type="file" name="csv" accept=".csv" class="form-control" required>
              </div>
              <button type="submit" class="btn btn-success">Upload and Import</button>
              <a href="/admin/example/questions.csv" class="btn btn-outline-info">Download Template</a>
            </form>
            <small class="text-muted">Columns: domain, question, A, B, C, D, correct, explanation</small>
          </div>
        </div>

        <div class="card">
          <div class="card-body">
            <h4>Questions</h4>
            <div class="table-responsive">
              <table class="table">
                <thead>
                  <tr>
                    <th>Domain</th>
                    <th>Question</th>
                    <th>Options</th>
                    <th>Answer</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {q_table}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>

      {'<div>' if tab == 'users' else '<div style="display:none;">'}
        <div class="card">
          <div class="card-body">
            <h4>Users</h4>
            <div class="table-responsive">
              <table class="table">
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Email</th>
                    <th>Plan</th>
                    <th>Quizzes</th>
                    <th>Questions</th>
                    <th>Last Active</th>
                  </tr>
                </thead>
                <tbody>
                  {u_table}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    </div>
    """
    return base_layout("Admin", body)

# Admin CRUD operations
@app.post("/admin/questions/add")
def admin_questions_add():
    if not is_admin():
        return redirect("/admin")
    form = request.form
    dom = (form.get("domain") or "security-principles").strip()

    num_to_letter = {1:"A", 2:"B", 3:"C", 4:"D"}
    try:
        ans_num = int(form.get("answer") or 1)
        correct_letter = num_to_letter.get(ans_num, "A")
    except Exception:
        correct_letter = "A"

    q = {
        "id": str(uuid.uuid4()),
        "domain": dom,
        "question": (form.get("question") or "").strip(),
        "options": {
            "A": (form.get("opt1") or "").strip(),
            "B": (form.get("opt2") or "").strip(),
            "C": (form.get("opt3") or "").strip(),
            "D": (form.get("opt4") or "").strip(),
        },
        "correct": correct_letter,
        "explanation": (form.get("explanation") or "").strip(),
        "created_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
    }
    if q["question"] and all(q["options"].get(L) for L in ("A","B","C","D")):
        QUESTIONS.append(q)
        _save_json("questions.json", QUESTIONS)

    global ALL_QUESTIONS
    ALL_QUESTIONS = _build_all_questions()
    return redirect("/admin?tab=questions")

@app.post("/admin/questions/delete")
def admin_questions_delete():
    if not is_admin():
        return redirect("/admin")
    qid = request.form.get("id")
    if qid:
        idx = next((i for i,x in enumerate(QUESTIONS) if x.get("id")==qid), -1)
        if idx >= 0:
            QUESTIONS.pop(idx)
            _save_json("questions.json", QUESTIONS)
            global ALL_QUESTIONS
            ALL_QUESTIONS = _build_all_questions()
    return redirect("/admin?tab=questions")

@app.post("/admin/questions/import")
def admin_questions_import():
    if not is_admin():
        return redirect("/admin?tab=questions")
    f = request.files.get("csv")
    if not f:
        return redirect("/admin?tab=questions")

    reader = csv.DictReader(f.stream.read().decode("utf-8").splitlines())
    count = 0
    for row in reader:
        dom = (row.get("domain") or "security-principles").strip()
        
        opts = {
            "A": (row.get("A") or "").strip(),
            "B": (row.get("B") or "").strip(),
            "C": (row.get("C") or "").strip(),
            "D": (row.get("D") or "").strip(),
        }
        correct = (row.get("correct") or "A").strip().upper()
        if correct not in ("A","B","C","D"):
            correct = "A"

        q = {
            "id": str(uuid.uuid4()),
            "domain": dom,
            "question": (row.get("question") or "").strip(),
            "options": opts,
            "correct": correct,
            "explanation": (row.get("explanation") or "").strip(),
            "created_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        }
        if q["question"] and all(q["options"].get(L) for L in ("A","B","C","D")):
            QUESTIONS.append(q)
            count += 1

    if count:
        _save_json("questions.json", QUESTIONS)
        global ALL_QUESTIONS
        ALL_QUESTIONS = _build_all_questions()

    return redirect("/admin?tab=questions")

@app.get("/admin/example/questions.csv")
def admin_example_questions_csv():
    if not is_admin():
        return redirect("/admin")
    csv_text = (
        "domain,question,A,B,C,D,correct,explanation\n"
        "security-principles,What is defense in depth?,Layered controls,Single control,No controls,Budget only,A,Multiple layers reduce single-point failures\n"
    )
    return Response(csv_text, mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=questions_template.csv"})

# Error handlers
@app.errorhandler(403)
def forbidden(e):
    return base_layout("Access Denied", """
    <div class="container mt-5">
      <div class="row justify-content-center">
        <div class="col-md-6 text-center">
          <h1 class="display-1 text-muted">403</h1>
          <h3>Access Denied</h3>
          <p class="text-muted">You don't have permission to access this resource.</p>
          <a href="/" class="btn btn-primary">Go Home</a>
        </div>
      </div>
    </div>
    """), 403

@app.errorhandler(404)
def not_found(e):
    return base_layout("Not Found", """
    <div class="container mt-5">
      <div class="row justify-content-center">
        <div class="col-md-6 text-center">
          <h1 class="display-1 text-muted">404</h1>
          <h3>Page Not Found</h3>
          <p class="text-muted">The page you're looking for doesn't exist.</p>
          <a href="/" class="btn btn-primary">Go Home</a>
        </div>
      </div>
    </div>
    """), 404

@app.errorhandler(500)
def server_error(e):
    logger.error(f"Server error: {str(e)}", exc_info=True)
    return base_layout("Server Error", """
    <div class="container mt-5">
      <div class="row justify-content-center">
        <div class="col-md-6 text-center">
          <h1 class="display-1 text-muted">500</h1>
          <h3>Something went wrong</h3>
          <p class="text-muted">We're working to fix this issue. Please try again later.</p>
          <a href="/" class="btn btn-primary">Go Home</a>
        </div>
      </div>
    </div>
    """), 500

# Health check
@app.get("/diag/openai")
def diag_openai():
    try:
        msg = chat_with_ai(["Say 'pong' if you can hear me."])
        ok = "pong" in msg.lower()
        return jsonify({"success": ok, "preview": msg[:200]}), (200 if ok else 500)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# Main entry point
if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=DEBUG)






