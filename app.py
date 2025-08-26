# ==============================
# app.py (Part A: Core System)
# ==============================

from flask import Flask, request, jsonify, session, redirect, url_for, Response
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime, timedelta
import os, json, random, requests, html, csv, uuid, logging, time, hashlib, re
import stripe
import sqlite3
from contextlib import contextmanager
from werkzeug.middleware.proxy_fix import ProxyFix

# Optional CSRF import
try:
    from flask_wtf.csrf import CSRFProtect
    HAS_CSRF = True
except ImportError:
    HAS_CSRF = False

# Optional fcntl (file locking for Linux/Mac)
try:
    import fcntl
    HAS_FCNTL = True
except ImportError:
    HAS_FCNTL = False

# ------------------------ Logging ------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# ------------------------ Flask / Config ------------------------
app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)
app.secret_key = os.environ.get("SECRET_KEY") or os.urandom(24)

# CSRF Protection
if HAS_CSRF:
    csrf = CSRFProtect(app)

# OpenAI + Stripe config
OPENAI_API_KEY       = os.environ.get("OPENAI_API_KEY", "")
OPENAI_CHAT_MODEL    = os.environ.get("OPENAI_CHAT_MODEL", "gpt-4o-mini")
OPENAI_API_BASE      = os.environ.get("OPENAI_API_BASE", "https://api.openai.com/v1")

stripe.api_key               = os.environ.get('STRIPE_SECRET_KEY', '')
STRIPE_WEBHOOK_SECRET       = os.environ.get('STRIPE_WEBHOOK_SECRET', '')
STRIPE_MONTHLY_PRICE_ID     = os.environ.get('STRIPE_MONTHLY_PRICE_ID', '')
STRIPE_SIXMONTH_PRICE_ID    = os.environ.get('STRIPE_SIXMONTH_PRICE_ID', '')

ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "").strip()
APP_VERSION    = os.environ.get("APP_VERSION", "1.0.0")
IS_STAGING     = os.environ.get("RENDER_SERVICE_NAME", "").endswith("-staging")
DEBUG          = os.environ.get("FLASK_DEBUG", "0") == "1"

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=(os.environ.get("SESSION_COOKIE_SECURE", "1") == "1"),
)

# ------------------------ Data Storage ------------------------
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
        if HAS_FCNTL:
            try:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            except:
                pass
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)

QUESTIONS   = _load_json("questions.json", [])
FLASHCARDS  = _load_json("flashcards.json", [])
USERS       = _load_json("users.json", [])

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

# ------------------------ Security & Rate Limiting ------------------------
_RATE_BUCKETS = {}

@app.after_request
def add_security_headers(resp):
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

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
    return False

# ------------------------ Auth Helpers ------------------------
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

# ------------------------ Questions ------------------------
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

# ------------------------ AI Tutor ------------------------
def chat_with_ai(msgs: list[str]) -> str:
    try:
        if not OPENAI_API_KEY:
            return "OpenAI key not configured."
        payload = {
            "model": OPENAI_CHAT_MODEL,
            "messages": [{"role": "system", "content": "You are a helpful CPP exam tutor."}]
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
            return f"AI error ({r.status_code})."
        data = r.json()
        return data["choices"][0]["message"]["content"]
    except Exception as e:
        return f"AI request failed: {e}"

# ------------------------ UI Layout ------------------------
def base_layout(title: str, body_html: str) -> str:
    # (shortened here — includes Bootstrap, Inter font, and full psychology CSS)
    return f"""<!DOCTYPE html>
    <html lang="en">
    <head><meta charset="UTF-8"><title>{title}</title></head>
    <body>{body_html}</body></html>"""

# ==============================
# END OF PART A
# (next: Routes in Part B, continue below with 2-line overlap)
# ==============================

# ==============================
# app.py (Part B: Routes)
# ==============================

@app.get("/healthz")
def healthz():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}

# ------------------------ Auth Routes ------------------------
@app.get("/login")
def login_page():
    if 'user_id' in session:
        return redirect(url_for('home'))
    body = """
    <div class="container">
      <h2>Login</h2>
      <form method="POST" action="/login">
        <label>Email</label><input type="email" name="email" required><br>
        <label>Password</label><input type="password" name="password" required><br>
        <button type="submit">Login</button>
      </form>
    </div>
    """
    return base_layout("Login", body)

@app.post("/login")
def login_post():
    email = request.form.get('email', '').strip().lower()
    password = request.form.get('password', '')
    user = _find_user(email)
    if user and check_password_hash(user.get('password_hash', ''), password):
        session.clear()
        session['user_id'] = user['id']
        session['email'] = user['email']
        session['name'] = user.get('name', '')
        return redirect(url_for('home'))
    return redirect(url_for('login_page'))

@app.get("/signup")
def signup_page():
    body = """
    <div class="container">
      <h2>Create Account</h2>
      <form method="POST" action="/signup">
        <input type="hidden" name="plan" value="monthly">
        <label>Name</label><input type="text" name="name" required><br>
        <label>Email</label><input type="email" name="email" required><br>
        <label>Password</label><input type="password" name="password" required><br>
        <button type="submit">Sign Up</button>
      </form>
    </div>
    """
    return base_layout("Signup", body)

@app.post("/signup")
def signup_post():
    name = request.form.get('name', '').strip()
    email = request.form.get('email', '').strip().lower()
    password = request.form.get('password', '')
    plan = (request.form.get('plan') or 'monthly').strip()

    if not name or not email or not password or _find_user(email):
        return redirect(url_for('signup_page'))

    user = {
        "id": str(uuid.uuid4()),
        "name": name,
        "email": email,
        "password_hash": generate_password_hash(password),
        "subscription": "inactive",
        "created_at": datetime.utcnow().isoformat(),
    }
    USERS.append(user)
    _save_json("users.json", USERS)

    session.clear()
    session['user_id'] = user['id']
    session['email'] = user['email']
    session['name'] = user['name']
    return redirect(url_for('billing_checkout', plan=plan))

@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for('login_page'))

# ------------------------ Home ------------------------
@app.get("/")
def home():
    if 'user_id' not in session:
        body = """
        <div class="container">
          <h1>Welcome to CPP Trainer</h1>
          <a href="/signup">Sign Up</a> | <a href="/login">Login</a>
        </div>
        """
        return base_layout("Home", body)
    user_name = session.get('name', 'User')
    body = f"<div class='container'><h2>Hello, {html.escape(user_name)}</h2></div>"
    return base_layout("Dashboard", body)

# ------------------------ Tutor ------------------------
@app.get("/study")
@login_required
def study_page():
    body = """
    <div class="container">
      <h2>AI Tutor</h2>
      <form id="chatForm">
        <input type="text" name="message" placeholder="Ask a question...">
        <button type="submit">Send</button>
      </form>
      <div id="chatOutput"></div>
    </div>
    """
    return base_layout("Study", body)

@app.post("/api/chat")
@login_required
def api_chat():
    data = request.get_json() or {}
    user_msg = (data.get("message") or "").strip()
    if not user_msg:
        return jsonify({"error": "Empty message"}), 400
    reply = chat_with_ai([user_msg])
    return jsonify({"response": reply})

# ------------------------ Quiz ------------------------
@app.get("/quiz")
@login_required
def quiz_page():
    quiz = random.sample(ALL_QUESTIONS, min(5, len(ALL_QUESTIONS)))
    q_html = "".join(
        f"<p>{q['question']}</p>" +
        "".join(f"<label><input type='radio' name='{i}' value='{opt}'>{text}</label><br>"
                for opt, text in q['options'].items())
        for i, q in enumerate(quiz)
    )
    body = f"""
    <div class="container">
      <h2>Practice Quiz</h2>
      <form id="quizForm">{q_html}<button type="submit">Submit</button></form>
    </div>
    """
    return base_layout("Quiz", body)

@app.post("/api/submit-quiz")
@login_required
def api_submit_quiz():
    data = request.get_json() or {}
    questions = data.get('questions', [])
    answers = data.get('answers', {})
    correct = 0
    total = len(questions)
    for i, q in enumerate(questions):
        if answers.get(str(i)) == q['correct']:
            correct += 1
    score = round((correct / total) * 100, 1) if total else 0
    return jsonify({"score": score, "correct": correct, "total": total})

# ------------------------ Billing ------------------------
@app.get("/billing")
@login_required
def billing_page():
    body = "<div class='container'><h2>Billing</h2><p>Manage your subscription here.</p></div>"
    return base_layout("Billing", body)

@app.get("/billing/checkout/<plan>")
@login_required
def billing_checkout(plan):
    url = create_stripe_checkout_session(session['email'], plan)
    return redirect(url or url_for('billing_page'))

@app.get("/billing/success")
@login_required
def billing_success():
    return redirect(url_for('home'))

@app.post("/stripe/webhook")
def stripe_webhook():
    return '', 200

# ------------------------ Misc Pages ------------------------
@app.get("/flashcards")
@login_required
def flashcards_page():
    return base_layout("Flashcards", "<h2>Flashcards coming soon</h2>")

@app.get("/mock-exam")
@login_required
def mock_exam_page():
    return base_layout("Mock Exam", "<h2>Mock exam coming soon</h2>")

@app.get("/progress")
@login_required
def progress_page():
    return base_layout("Progress", "<h2>Progress dashboard coming soon</h2>")

@app.get("/usage")
@login_required
def usage_page():
    return base_layout("Usage", "<h2>Usage dashboard coming soon</h2>")

@app.get("/settings")
@login_required
def settings_page():
    return base_layout("Settings", "<h2>Settings page coming soon</h2>")

# ------------------------ Error Handlers ------------------------
@app.errorhandler(404)
def not_found(e):
    return base_layout("Not Found", "<h2>404 - Page not found</h2>"), 404

@app.errorhandler(500)
def server_error(e):
    return base_layout("Server Error", "<h2>500 - Server error</h2>"), 500

# ------------------------ Entry Point ------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=DEBUG)
