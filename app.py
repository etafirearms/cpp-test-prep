# app.py

# ====== Imports & Basic Config ======
from flask import Flask, request, jsonify, session, redirect, url_for, Response, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from functools import wraps
from datetime import datetime, timedelta
from contextlib import contextmanager
from typing import Dict, Any, Tuple, List

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

def _atomic_write_json(path: str, data: Any):
    """Atomic JSON write (POSIX-safe)."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp_path = f"{path}.tmp.{os.getpid()}.{uuid.uuid4().hex}"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_path, path)

def _save_json(name, data):
    """
    Robust, atomic JSON save with fallback.
    """
    path = os.path.join(DATA_DIR, name)
    try:
        _atomic_write_json(path, data)
    except Exception as e:
        logger.warning("Atomic _save_json failed for %s: %s; attempting simple write", name, e)
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

# ====== CPP Content Bank — Paths, Whitelist, Targets, Index ======
BANK_DIR = os.path.join(DATA_DIR, "bank")
os.makedirs(BANK_DIR, exist_ok=True)

BANK_FLASHCARDS_PATH = os.path.join(BANK_DIR, "cpp_flashcards_v1.json")
BANK_QUESTIONS_PATH  = os.path.join(BANK_DIR, "cpp_questions_v1.json")
CONTENT_INDEX_PATH   = os.path.join(DATA_DIR, "content_index.json")

ALLOWED_HOSTS = {
    "nist.gov", "cisa.gov", "fema.gov", "osha.gov", "gao.gov",
    "popcenter.asu.edu", "ncpc.org", "fbi.gov", "rand.org",
    "hsdl.org", "nfpa.org", "iso.org", "justice.gov",
    "house.texas.gov"
    # city/state official domains are allowed; validated by suffix '.gov' check below
}

# Exact inventory targets
FLASHCARD_TARGETS = {
    "Principles": 60,
    "Business": 39,
    "Investigations": 27,
    "Personnel": 36,
    "Physical": 54,
    "InfoSec": 42,
    "Crisis": 42
}
QUESTION_TARGETS = {
    # domain: total, with per-type splits in QUESTION_SPLITS
    "Principles": 192,
    "Business": 125,
    "Investigations": 87,
    "Personnel": 115,
    "Physical": 173,
    "InfoSec": 134,
    "Crisis": 134
}
QUESTION_SPLITS = {
    # domain: (T/F, MCQ, Scenario)
    "Principles": (48, 115, 29),
    "Business": (31, 75, 19),
    "Investigations": (22, 52, 13),
    "Personnel": (29, 69, 17),
    "Physical": (43, 104, 26),
    "InfoSec": (34, 80, 20),
    "Crisis": (34, 80, 20),
}
QUESTION_TYPE_MAP = {"tf": "mcq", "mcq": "mcq", "scenario_mcq": "scenario_mcq"}

DOMAINS = {
    "security-principles": "Security Principles & Practices",
    "business-principles": "Business Principles & Practices",
    "investigations": "Investigations",
    "personnel-security": "Personnel Security",
    "physical-security": "Physical Security",
    "information-security": "Information Security",
    "crisis-management": "Crisis Management",
}
CPP_DOMAIN_CANON = ["Principles","Business","Investigations","Personnel","Physical","InfoSec","Crisis"]

# ====== Content Index (hashes for dedup) ======
def _load_content_index():
    idx = _load_json("content_index.json", None)
    if not idx or not isinstance(idx, dict):
        idx = {"seen_hashes": [], "items": {}}
    idx.setdefault("seen_hashes", [])
    idx.setdefault("items", {})
    return idx

def _save_content_index(index: dict):
    _atomic_write_json(CONTENT_INDEX_PATH, index)

CONTENT_INDEX = _load_content_index()

# ====== Hashing & Signatures ======
def _norm_spaces(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "")).strip()

def _flashcard_hash(front: str, back: str, domain: str) -> str:
    sig = (_norm_spaces(front).lower() + "||" +
           _norm_spaces(back).lower() + "||" +
           (domain or "").lower())
    return hashlib.sha256(sig.encode("utf-8")).hexdigest()

def _question_hash(stem: str, choices: List[str], correct_index: int, domain: str) -> str:
    stem_clean = _norm_spaces(stem).lower()
    choices_clean = "||".join(_norm_spaces(c).lower() for c in choices)
    sig = f"{stem_clean}||{choices_clean}||{correct_index}||{(domain or '').lower()}"
    return hashlib.sha256(sig.encode("utf-8")).hexdigest()

def _near_dup(a: str, b: str, threshold: float = 0.92) -> bool:
    try:
        import difflib
        return difflib.SequenceMatcher(None, _norm_spaces(a).lower(), _norm_spaces(b).lower()).ratio() > threshold
    except Exception:
        return False

# ====== Source Whitelist Enforcement ======
def _is_allowed_url(url: str) -> bool:
    if not url or not isinstance(url, str):
        return False
    url = url.strip()
    m = re.match(r'^https?://([^/]+)/', url)
    if not m:
        return False
    host = m.group(1).lower()
    # allow *.gov and listed hosts
    if host.endswith(".gov") or host in ALLOWED_HOSTS:
        return True
    # allow specific subdomains of allowed hosts
    for ah in ALLOWED_HOSTS:
        if host.endswith("." + ah):
            return True
    return False

def _filter_sources(sources: List[dict]) -> List[dict]:
    out = []
    for s in (sources or []):
        title = (s.get("title") or "").strip()
        url = (s.get("url") or "").strip()
        if title and url and _is_allowed_url(url) and not re.match(r"^https?://[^/]+/?$", url):
            out.append({"title": title, "url": url})
            if len(out) >= 3:
                break
    return out

# ====== Schema Validators (strict) ======
def _valid_flashcard(item: dict) -> Tuple[bool, str]:
    req_keys = {"id","type","question","answer","rationale","sources","domain","difficulty"}
    if not isinstance(item, dict) or not req_keys.issubset(item.keys()):
        return False, "missing keys"
    if item.get("type") != "flashcard":
        return False, "type not flashcard"
    if item.get("difficulty") not in {"easy","medium","hard"}:
        return False, "bad difficulty"
    if item.get("domain") not in CPP_DOMAIN_CANON:
        return False, "bad domain"
    srcs = _filter_sources(item.get("sources") or [])
    if not srcs:
        return False, "no allowed sources"
    item["sources"] = srcs
    if not item.get("question") or not item.get("answer"):
        return False, "empty sides"
    if len(_norm_spaces(item.get("rationale") or "")) < 5:
        return False, "rationale too short"
    return True, ""

def _valid_question(item: dict) -> Tuple[bool, str]:
    req = {"id","type","question","choices","correct_index","answer","rationale","sources","domain","difficulty"}
    if not isinstance(item, dict) or not req.issubset(item.keys()):
        return False, "missing keys"
    if item.get("type") not in {"mcq","scenario_mcq"}:
        return False, "bad type"
    if item.get("difficulty") not in {"easy","medium","hard"}:
        return False, "bad difficulty"
    if item.get("domain") not in CPP_DOMAIN_CANON:
        return False, "bad domain"
    # choices
    choices = item.get("choices")
    if not isinstance(choices, list):
        return False, "choices not list"
    if choices == ["True","False"]:
        # T/F strict requirement
        if len(choices) != 2 or choices[0] != "True" or choices[1] != "False":
            return False, "bad TF order"
    else:
        if len(choices) < 4 or len(choices) > 5:
            return False, "mcq choices 4-5"
        if len(set(choices)) != len(choices):
            return False, "duplicate choices"
    # correct
    try:
        ci = int(item.get("correct_index"))
    except Exception:
        return False, "correct_index not int"
    if ci < 0 or ci >= len(choices):
        return False, "correct_index out of range"
    if item.get("answer") != choices[ci]:
        return False, "answer mismatch"
    # rationale
    if len(_norm_spaces(item.get("rationale") or "")) < 5:
        return False, "rationale too short"
    # sources
    srcs = _filter_sources(item.get("sources") or [])
    if not srcs:
        return False, "no allowed sources"
    item["sources"] = srcs
    # language checks
    stem = _norm_spaces(item.get("question") or "")
    if re.search(r"\balways\b|\bnever\b", stem.lower()):
        # allow only if clearly sourced as universal; safer to reject automatically (will regenerate)
        return False, "overly absolute claim"
    return True, ""

# ====== CPP Bank Loaders & Normalizers into Engine ======
def _load_bank_file(path: str) -> list:
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except Exception as e:
        logger.warning("Failed to load bank file %s: %s", path, e)
        return []

def _ensure_content_index_in_memory():
    global CONTENT_INDEX
    CONTENT_INDEX = _load_content_index()

def _save_bank_atomic(flashcards: list, questions: list):
    _atomic_write_json(BANK_FLASHCARDS_PATH, flashcards)
    _atomic_write_json(BANK_QUESTIONS_PATH, questions)

# Transform bank questions into quiz engine format (choices dict with A-D keys)
def _bank_q_to_engine(q: dict) -> dict:
    letters = ["A","B","C","D","E"]
    choices = q.get("choices") or []
    opts = {letters[i]: str(choices[i]) for i in range(min(len(choices),5))}
    correct_key = None
    try:
        ci = int(q.get("correct_index"))
        if 0 <= ci < len(choices):
            correct_key = letters[ci]
    except Exception:
        pass
    # Map CPP domain back to engine domain slugs for existing UI labels
    domain_slug_map = {
        "Principles": "security-principles",
        "Business": "business-principles",
        "Investigations": "investigations",
        "Personnel": "personnel-security",
        "Physical": "physical-security",
        "InfoSec": "information-security",
        "Crisis": "crisis-management",
    }
    return {
        "id": q.get("id") or str(uuid.uuid4()),
        "question": q.get("question") or "",
        "options": opts,
        "correct": correct_key or "A",
        "explanation": q.get("rationale") or "",
        "domain": domain_slug_map.get(q.get("domain"), "security-principles"),
        "difficulty": q.get("difficulty") or "medium"
    }

def _flashcard_minimal(card: dict) -> dict:
    # Keep only what the cards feature needs; sources kept for API access
    return {
        "id": card.get("id") or str(uuid.uuid4()),
        "type": "flashcard",
        "question": card.get("question") or "",
        "answer": card.get("answer") or "",
        "rationale": card.get("rationale") or "",
        "sources": card.get("sources") or [],
        "domain": card.get("domain") or "",
        "difficulty": card.get("difficulty") or "easy"
    }

# ====== Banks in memory ======
BANK_FLASHCARDS = []
BANK_QUESTIONS = []

def _reload_banks_into_memory():
    global BANK_FLASHCARDS, BANK_QUESTIONS

    raw_cards = _load_bank_file(BANK_FLASHCARDS_PATH)
    raw_qs    = _load_bank_file(BANK_QUESTIONS_PATH)

    # Hard-validate loaded items and drop anything invalid
    good_cards = []
    seen_fc_hashes = set()
    for c in raw_cards:
        ok, _msg = _valid_flashcard(c)
        if not ok:
            continue
        h = _flashcard_hash(c.get("question",""), c.get("answer",""), c.get("domain",""))
        if h in seen_fc_hashes:
            continue
        seen_fc_hashes.add(h)
        good_cards.append(_flashcard_minimal(c))

    good_qs = []
    seen_q_hashes = set()
    for q in raw_qs:
        ok, _msg = _valid_question(q)
        if not ok:
            continue
        h = _question_hash(q.get("question",""), q.get("choices") or [], int(q.get("correct_index",0)), q.get("domain",""))
        if h in seen_q_hashes:
            continue
        seen_q_hashes.add(h)
        good_qs.append(q)

    BANK_FLASHCARDS = good_cards
    BANK_QUESTIONS  = good_qs
    logger.info("Loaded banks: flashcards=%d, questions=%d", len(BANK_FLASHCARDS), len(BANK_QUESTIONS))

# ====== Legacy Sample Questions (kept for fallback) ======
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

# ====== Build legacy ALL_QUESTIONS + Bank Merge ======
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
    else:
        return None
    if nq.get("correct") not in ("A","B","C","D"):
        return None
    return nq

def _build_all_questions_fallback():
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
    add_many(QUESTIONS)
    add_many(BASE_QUESTIONS)
    return merged

# Initialize banks and engine pools
_reload_banks_into_memory()

def _engine_pool_from_banks():
    """Convert bank questions to engine legacy shape used by quiz/mock."""
    pool = []
    for q in BANK_QUESTIONS:
        pool.append(_bank_q_to_engine(q))
    if not pool:
        # Fallback to legacy pool if bank not yet built
        for x in _build_all_questions_fallback():
            pool.append({
                "question": x["question"],
                "options": x["options"],
                "correct": x["correct"],
                "explanation": x.get("explanation",""),
                "domain": x.get("domain","security-principles"),
                "difficulty": x.get("difficulty","medium")
            })
    return pool

ALL_QUESTIONS_ENGINE = _engine_pool_from_banks()

# ====== Misc Helpers ======
def safe_json_response(data, status_code=200):
    try:
        return jsonify(data), status_code
    except Exception as e:
        logger.error(f"JSON serialization error: {e}")
        return jsonify({"error": "Internal server error"}), 500

def filter_questions(domain_key: str | None):
    pool = ALL_QUESTIONS_ENGINE
    if not domain_key or domain_key == "random":
        return pool[:]
    return [q for q in pool if q.get("domain") == domain_key]

def build_quiz(num: int, domain_key: str | None):
    pool = filter_questions(domain_key)
    out = []
    if not pool:
        pool = ALL_QUESTIONS_ENGINE[:]
    while len(out) < num:
        random.shuffle(pool)
        for q in pool:
            if len(out) >= num:
                break
            # remap to legacy expected structure for renderer
            out.append({
                "id": str(uuid.uuid4()),
                "text": q.get("question",""),
                "domain": q.get("domain"),
                "choices": [{"key": k, "text": v} for k, v in (q.get("options") or {}).items()],
                "correct_key": q.get("correct")
            })
    title = f"Practice ({num} questions)"
    return {"title": title, "domain": domain_key or "random", "questions": out[:num]}

# ====== Tutor (unchanged prompt for now; leave UI unchanged) ======
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

    # Precompute staging banner
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
    if 'user_id' not in session:
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
    return redirect(url_for('home'))

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
    </div></div>
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
        logger.info("Sample data initialized (engine questions loaded: %d, bank cards: %d)", len(ALL_QUESTIONS_ENGINE), len(BANK_FLASHCARDS))
    except Exception as e:
        logger.error("Failed to initialize sample data: %s", e)

# ====== Quiz / Mock Exam Engine (file-backed; preserves layout) ======

# ---------- Helpers ----------
def _user_id():
    return (session.get("user_id")
            or session.get("email")
            or "unknown")

def _normalize_question(q, idx=None):
    """
    Normalize heterogeneous question shapes into a common structure:
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
    """
    Use bank-driven engine questions first. Fallback to legacy if bank empty.
    """
    pool = []
    # Prefer bank-backed engine pool
    if ALL_QUESTIONS_ENGINE:
        for q in ALL_QUESTIONS_ENGINE:
            nq = {
                "id": q.get("id") or str(uuid.uuid4()),
                "text": q.get("question",""),
                "domain": q.get("domain"),
                "choices": [{"key": k, "text": v} for k, v in (q.get("options") or {}).items()],
                "correct_key": q.get("correct")
            }
            if nq["text"] and nq["choices"]:
                pool.append(nq)
    return pool

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

    if run.get("finished"):
        results = _grade(run)
        _record_attempt(user_id, "mock", run, results)
        _finish_run("mock", user_id)
        return _render_results_card("Mock Exam", "/mock-exam", run, results)

    curr_idx = int(run.get("index", 0))
    return _render_question_card("Mock Exam", "/mock-exam", run, curr_idx, error_msg)

# ====== Flashcards Placeholder (UI unchanged; wired in Section 4) ======
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
    Calls your Tutor agent using env configuration.
    Supports:
      - OpenAI (OPENAI_API_KEY, OPENAI_API_BASE?, MODEL_TUTOR?)
      - Azure OpenAI (AZURE_OPENAI_ENDPOINT, AZURE_OPENAI_API_KEY, AZURE_OPENAI_DEPLOYMENT)
    Adds: retries, richer errors, and small timeouts.
    """
    meta = meta or {}
    timeout_s = float(os.environ.get("TUTOR_TIMEOUT", "45"))
    temperature = float(os.environ.get("TUTOR_TEMP", "0.3"))
    max_tokens = int(os.environ.get("TUTOR_MAX_TOKENS", "800"))
    system_msg = os.environ.get("TUTOR_SYSTEM_PROMPT",
        "You are a calm, expert CPP/PSP study tutor. Explain clearly, step-by-step, "
        "cite domain numbers when relevant, and ask a short follow-up check for understanding."
    )

    # --- Detect provider: Azure OpenAI vs OpenAI-compatible ---
    azure_endpoint = os.environ.get("AZURE_OPENAI_ENDPOINT", "").rstrip("/")
    azure_key = os.environ.get("AZURE_OPENAI_API_KEY", "").strip()
    azure_deploy = os.environ.get("AZURE_OPENAI_DEPLOYMENT", "").strip()

    if azure_endpoint and azure_key and azure_deploy:
        # Azure OpenAI
        url = f"{azure_endpoint}/openai/deployments/{azure_deploy}/chat/completions?api-version=2024-06-01"
        headers = {
            "api-key": azure_key,
            "Content-Type": "application/json",
        }
        payload = {
            "messages": [
                {"role": "system", "content": system_msg},
                {"role": "user", "content": user_query}
            ],
            "temperature": temperature,
            "max_tokens": max_tokens,
            # Azure ignores "model" here; it's tied to the deployment
        }
    else:
        # OpenAI / compatible
        api_key = os.environ.get("OPENAI_API_KEY", "").strip()
        if not api_key:
            return False, "Tutor is not configured: missing API key.", {}
        base_url = os.environ.get("OPENAI_API_BASE", "https://api.openai.com/v1").rstrip("/")
        model = os.environ.get("MODEL_TUTOR", "gpt-4o-mini").strip()
        url = f"{base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        org = os.environ.get("OPENAI_ORG", "").strip()
        if org:
            headers["OpenAI-Organization"] = org
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_msg},
                {"role": "user", "content": user_query}
            ],
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

    # --- Simple retry with backoff for transient errors ---
    backoffs = [0, 1.5, 3.0]  # seconds
    last_err = None
    for wait_s in backoffs:
        if wait_s:
            time.sleep(wait_s)
        try:
            resp = requests.post(url, headers=headers, data=json.dumps(payload), timeout=timeout_s)
            status = resp.status_code
            # Soft-handle rate limits/transients with another retry
            if status in (429, 500, 502, 503, 504):
                last_err = f"{status} {resp.text[:300]}"
                continue
            if status >= 400:
                # Try to surface a readable message from JSON error
                try:
                    j = resp.json()
                    msg = (j.get("error") or {}).get("message") or resp.text[:300]
                except Exception:
                    msg = resp.text[:300]
                return False, f"Agent error {status}: {msg}", {"status": status}
            data = resp.json()
            answer = (data.get("choices") or [{}])[0].get("message", {}).get("content", "")
            usage = data.get("usage", {})
            # Normalize meta for analytics
            meta_out = {"usage": usage}
            if azure_endpoint:
                meta_out.update({"provider": "azure", "deployment": azure_deploy})
            else:
                meta_out.update({"provider": "openai", "model": payload.get("model")})
            return True, answer, meta_out
        except Exception as e:
            last_err = str(e)
            continue

    return False, f"Network/agent error: {last_err or 'unknown'}", {}


# ====== Page Views Tracking (no UI change) ======
@app.before_request
def _track_page_views():
    try:
        uid = session.get("user_id") or session.get("email") or "anon"
        _log_event(uid, "page.view", {"path": request.path, "method": request.method})
    except Exception:
        pass


# ====== Tutor Routes (verbatim UI preserved) ======
# IMPORTANT: Ensure this is the ONLY Tutor block in the file.
@app.route("/tutor", methods=["GET", "POST"], strict_slashes=False)
@app.route("/tutor/", methods=["GET", "POST"], strict_slashes=False)
@login_required
def tutor_page():
# --- Alias: keep existing UI link "/study" working without changing markup ---
@app.route("/study", methods=["GET", "POST"], strict_slashes=False)
@app.route("/study/", methods=["GET", "POST"], strict_slashes=False)
@login_required
def study_alias():
    return tutor_page()

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
                    "model": meta.get("model") or meta.get("deployment") or ""
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


@app.route("/tutor/ping", methods=["GET"])
@login_required
def tutor_ping():
    """
    Quick sanity check for Tutor config from the browser.
    Does a tiny roundtrip with the agent and returns JSON (no UI).
    """
    ok, answer, meta = _call_tutor_agent("Reply 'pong' only.", meta={"ping": True})
    # Trim long answers defensively
    short = (answer or "")[:200]
    return jsonify({
        "ok": bool(ok),
        "answer_preview": short,
        "meta": meta
    }), (200 if ok else 502)


# ====== Analytics Endpoint ======
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
# ====== Content Banks: Validation, Whitelist, Dedup, Persistence ======
import difflib
from urllib.parse import urlparse

# ---- Whitelist (hard gate) ----
ALLOWED_HOSTS = {
    "nist.gov", "cisa.gov", "fema.gov", "osha.gov", "gao.gov",
    "popcenter.asu.edu", "ncpc.org", "fbi.gov", "rand.org", "hsdl.org",
    "nfpa.org", "iso.org", "justice.gov"  # includes official public AARs
    # (city/state *.gov are covered by their exact hosts at runtime)
}

BANK_DIR = os.path.join(DATA_DIR, "bank")
os.makedirs(BANK_DIR, exist_ok=True)

FLASHCARDS_BANK_PATH = os.path.join(BANK_DIR, "cpp_flashcards_v1.json")
QUESTIONS_BANK_PATH  = os.path.join(BANK_DIR, "cpp_questions_v1.json")
INDEX_PATH           = os.path.join(DATA_DIR, "content_index.json")

# ---- Targets (exact counts) ----
FLASHCARD_TARGETS = {
    "Principles": 60,
    "Business": 39,
    "Investigations": 27,
    "Personnel": 36,
    "Physical": 54,
    "InfoSec": 42,
    "Crisis": 42,
}
QUESTION_TARGET_TOTAL = 960
QUESTION_TARGETS = {
    # domain: (T/F, MCQ, Scenario)
    "Principles":     (48, 115, 29),
    "Business":       (31, 75, 19),
    "Investigations": (22, 52, 13),
    "Personnel":      (29, 69, 17),
    "Physical":       (43, 104, 26),
    "InfoSec":        (34, 80, 20),
    "Crisis":         (34, 80, 20),
}
QUESTION_TYPE_KEYS = ("tf", "mcq", "scenario_mcq")

# ---- Safe loads for banks & index ----
def _load_bank(path):
    data = _load_json(os.path.relpath(path, DATA_DIR), [])
    return data if isinstance(data, list) else []

def _save_bank(path, items):
    name = os.path.relpath(path, DATA_DIR)
    _save_json(name, items)

def _load_index():
    idx = _load_json(os.path.relpath(INDEX_PATH, DATA_DIR), {})
    if not isinstance(idx, dict):
        idx = {}
    idx.setdefault("seen_hashes", [])
    idx.setdefault("items", {})
    # normalize to sets/dicts in memory
    idx["seen_hashes"] = set(idx.get("seen_hashes") or [])
    idx["items"] = dict(idx.get("items") or {})
    return idx

def _save_index(idx):
    out = {
        "seen_hashes": sorted(list(idx.get("seen_hashes", set()))),
        "items": idx.get("items", {})
    }
    _save_json(os.path.relpath(INDEX_PATH, DATA_DIR), out)

# ---- URL & whitelist helpers ----
def _is_allowed_source(url: str) -> bool:
    try:
        pu = urlparse(url.strip())
        host = (pu.hostname or "").lower()
        if not pu.scheme.startswith("http"):
            return False
        if host in ALLOWED_HOSTS:
            return True
        # Allow official city/state *.gov domains and subdomains of allowed hosts
        if host.endswith(".gov"):
            return True
        for base in ALLOWED_HOSTS:
            if host == base or host.endswith("." + base):
                return True
        return False
    except Exception:
        return False

def _normalize_sources(sources):
    """Return filtered list of dicts with allowed URLs only; drop generic homepages."""
    out = []
    if not isinstance(sources, list):
        return out
    for s in sources:
        if not isinstance(s, dict):
            continue
        title = str(s.get("title", "")).strip()[:160]
        url = str(s.get("url", "")).strip()
        if not url or not _is_allowed_source(url):
            continue
        # reject generic homepages (e.g., https://www.nist.gov/)
        try:
            pu = urlparse(url)
            if pu.path in ("", "/", None):
                continue
        except Exception:
            continue
        out.append({"title": title or "Source", "url": url})
        if len(out) >= 3:
            break
    return out

# ---- Schema validators ----
def _valid_domain(val: str) -> bool:
    return val in FLASHCARD_TARGETS.keys()

def _valid_difficulty(val: str) -> bool:
    return val in ("easy", "medium", "hard")

def _validate_flashcard(item: dict) -> tuple[bool, str, dict]:
    try:
        req = ["id", "type", "question", "answer", "rationale", "sources", "domain", "difficulty"]
        if not all(k in item for k in req):
            return False, "missing-keys", {}
        if item.get("type") != "flashcard":
            return False, "wrong-type", {}
        q = str(item.get("question","")).strip()
        a = str(item.get("answer","")).strip()
        r = str(item.get("rationale","")).strip()
        d = str(item.get("domain","")).strip()
        diff = str(item.get("difficulty","")).strip()
        if not q or not a or not r:
            return False, "empty-fields", {}
        if not _valid_domain(d):
            return False, "bad-domain", {}
        if not _valid_difficulty(diff):
            return False, "bad-difficulty", {}
        sources = _normalize_sources(item.get("sources"))
        if not sources:
            return False, "no-valid-sources", {}
        clean = {
            "id": str(item.get("id")),
            "type": "flashcard",
            "question": q,
            "answer": a,
            "rationale": r,
            "sources": sources,
            "domain": d,
            "difficulty": diff
        }
        return True, "", clean
    except Exception as e:
        return False, f"exception:{e}", {}

def _is_tf_choice_set(choices):
    return isinstance(choices, list) and len(choices) == 2 and choices[0] == "True" and choices[1] == "False"

def _validate_question(item: dict) -> tuple[bool, str, dict, str]:
    """
    Returns: ok, reason, clean_item, q_kind ('tf'|'mcq'|'scenario_mcq')
    """
    try:
        req = ["id", "type", "question", "choices", "correct_index", "answer", "rationale", "sources", "domain", "difficulty"]
        if not all(k in item for k in req):
            return False, "missing-keys", {}, ""
        t = item.get("type")
        if t not in ("mcq", "scenario_mcq"):
            return False, "wrong-type", {}, ""
        stem = str(item.get("question","")).strip()
        if not stem:
            return False, "empty-stem", {}, ""
        d = str(item.get("domain","")).strip()
        if not _valid_domain(d):
            return False, "bad-domain", {}, ""
        diff = str(item.get("difficulty","")).strip()
        if not _valid_difficulty(diff):
            return False, "bad-difficulty", {}, ""

        choices = item.get("choices")
        # T/F special case: exactly ["True","False"] in that order
        if _is_tf_choice_set(choices):
            q_kind = "tf"
            correct_index = int(item.get("correct_index"))
            if correct_index not in (0,1):
                return False, "bad-correct-index", {}, ""
            answer = str(item.get("answer",""))
            if answer not in ("True","False") or answer != choices[correct_index]:
                return False, "answer-mismatch", {}, ""
        else:
            # MCQ / Scenario: 4–5 options, exactly one best answer
            if not isinstance(choices, list) or len(choices) < 4 or len(choices) > 5:
                return False, "choices-count", {}, ""
            if len(set(choices)) != len(choices):
                return False, "dup-choices", {}, ""
            correct_index = int(item.get("correct_index"))
            if correct_index < 0 or correct_index >= len(choices):
                return False, "bad-correct-index", {}, ""
            answer = str(item.get("answer",""))
            if answer != choices[correct_index]:
                return False, "answer-mismatch", {}, ""
            q_kind = ("scenario_mcq" if t == "scenario_mcq" else "mcq")

        rationale = str(item.get("rationale","")).strip()
        if not rationale or rationale.count(" ") < 1:
            return False, "weak-rationale", {}, ""

        sources = _normalize_sources(item.get("sources"))
        if not sources:
            return False, "no-valid-sources", {}, ""

        clean = {
            "id": str(item.get("id")),
            "type": t,
            "question": stem,
            "choices": choices,
            "correct_index": correct_index,
            "answer": answer,
            "rationale": rationale,
            "sources": sources,
            "domain": d,
            "difficulty": diff
        }
        return True, "", clean, q_kind
    except Exception as e:
        return False, f"exception:{e}", {}, ""

# ---- Hashing & near-dup rules ----
def _flashcard_hash(card: dict) -> str:
    front = str(card.get("question","")).strip()
    back  = str(card.get("answer","")).strip()
    dom   = str(card.get("domain","")).strip()
    sig = (front + "||" + back + "||" + dom).strip().lower()
    return hashlib.sha256(sig.encode("utf-8")).hexdigest()

def _question_hash(q: dict) -> str:
    stem = " ".join(str(q.get("question","")).split()).lower()
    choices = q.get("choices") or []
    choices_clean = "||".join([str(c).strip().lower() for c in choices])
    idx = str(q.get("correct_index"))
    dom = str(q.get("domain","")).strip()
    sig = f"{stem}||{choices_clean}||{idx}||{dom}"
    return hashlib.sha256(sig.encode("utf-8")).hexdigest()

def _is_near_dup(stem_a: str, stem_b: str, threshold: float = 0.92) -> bool:
    a = " ".join(stem_a.lower().split())
    b = " ".join(stem_b.lower().split())
    return difflib.SequenceMatcher(None, a, b).ratio() > threshold

# ---- Bank state in memory (lazy loaded) ----
_flashcards_bank = None
_questions_bank  = None
_index_cache     = None

def _ensure_banks_loaded():
    global _flashcards_bank, _questions_bank, _index_cache
    if _flashcards_bank is None:
        _flashcards_bank = _load_bank(FLASHCARDS_BANK_PATH)
    if _questions_bank is None:
        _questions_bank = _load_bank(QUESTIONS_BANK_PATH)
    if _index_cache is None:
        _index_cache = _load_index()

def _persist_all():
    _save_bank(FLASHCARDS_BANK_PATH, _flashcards_bank or [])
    _save_bank(QUESTIONS_BANK_PATH,  _questions_bank  or [])
    _save_index(_index_cache or {"seen_hashes": set(), "items": {}})

# ---- Helper: classify question kind for quota tracking ----
def _q_kind(item: dict) -> str:
    if _is_tf_choice_set(item.get("choices")):
        return "tf"
    return "scenario_mcq" if item.get("type") == "scenario_mcq" else "mcq"

# ---- Quota counters (current counts by domain/type) ----
def _current_quota():
    _ensure_banks_loaded()
    # Flashcards per domain
    fc_counts = {d: 0 for d in FLASHCARD_TARGETS}
    for c in _flashcards_bank:
        d = c.get("domain")
        if d in fc_counts:
            fc_counts[d] += 1
    # Questions per domain/type
    q_counts = {d: {"tf": 0, "mcq": 0, "scenario_mcq": 0} for d in FLASHCARD_TARGETS}
    for q in _questions_bank:
        d = q.get("domain")
        if d in q_counts:
            q_counts[d][_q_kind(q)] += 1
    return fc_counts, q_counts

# ---- Ingest pipeline ----
def _ingest_items(items: list[dict]):
    """
    Applies:
      - whitelist enforcement
      - schema validation
      - dedup (hash & near-dup)
      - quota-aware acceptance (keeps within targets when finalizing later)
    Stores valid items into working banks immediately; exact counts enforced by /finalize.
    """
    _ensure_banks_loaded()
    kept, dropped = [], []

    # Prepare existing stems for near-dup checks
    existing_stems_fc = [c.get("question","") for c in _flashcards_bank]
    existing_stems_q  = [q.get("question","") for q in _questions_bank]

    for it in (items or []):
        try:
            # ---- Flashcard ----
            if it.get("type") == "flashcard":
                ok, reason, clean = _validate_flashcard(it)
                if not ok:
                    dropped.append({"id": it.get("id"), "reason": reason})
                    continue
                # Hash & near-dup
                h = _flashcard_hash(clean)
                if h in _index_cache["seen_hashes"]:
                    dropped.append({"id": clean["id"], "reason": "dup-hash"})
                    continue
                if any(_is_near_dup(clean["question"], s) for s in existing_stems_fc):
                    dropped.append({"id": clean["id"], "reason": "near-dup"})
                    continue
                _flashcards_bank.append(clean)
                _index_cache["seen_hashes"].add(h)
                _index_cache["items"][clean["id"]] = h
                existing_stems_fc.append(clean["question"])
                kept.append({"id": clean["id"], "type": "flashcard"})
            # ---- Question ----
            elif it.get("type") in ("mcq", "scenario_mcq"):
                ok, reason, clean, kind = _validate_question(it)
                if not ok:
                    dropped.append({"id": it.get("id"), "reason": reason})
                    continue
                h = _question_hash(clean)
                if h in _index_cache["seen_hashes"]:
                    dropped.append({"id": clean["id"], "reason": "dup-hash"})
                    continue
                if any(_is_near_dup(clean["question"], s) for s in existing_stems_q):
                    dropped.append({"id": clean["id"], "reason": "near-dup"})
                    continue
                _questions_bank.append(clean)
                _index_cache["seen_hashes"].add(h)
                _index_cache["items"][clean["id"]] = h
                existing_stems_q.append(clean["question"])
                kept.append({"id": clean["id"], "type": kind})
            else:
                dropped.append({"id": it.get("id"), "reason": "unknown-type"})
        except Exception as e:
            dropped.append({"id": it.get("id"), "reason": f"exception:{e}"})

    _persist_all()
    # instrumentation
    domain_summary_fc, domain_summary_q = _current_quota()
    _log_event(_user_id(), "content.ingest", {
        "kept": len(kept), "dropped": len(dropped),
        "flashcards_total": len(_flashcards_bank),
        "questions_total": len(_questions_bank)
    })
    return {
        "ok": True,
        "kept": kept,
        "dropped": dropped,
        "flashcards_total": len(_flashcards_bank),
        "questions_total": len(_questions_bank),
        "flashcards_by_domain": domain_summary_fc,
        "questions_by_domain": domain_summary_q
    }

# ---- Finalize: enforce exact targets & write banks ----
def _finalize_banks():
    _ensure_banks_loaded()

    # Trim/pack flashcards per domain
    fc_targeted = []
    domain_buckets = {d: [] for d in FLASHCARD_TARGETS}
    for c in _flashcards_bank:
        d = c.get("domain")
        if d in domain_buckets:
            domain_buckets[d].append(c)
    for d, target in FLASHCARD_TARGETS.items():
        fc_targeted.extend(domain_buckets[d][:target])

    # Questions per domain/type quotas
    q_targeted = []
    bucket_q = {d: {"tf": [], "mcq": [], "scenario_mcq": []} for d in FLASHCARD_TARGETS}
    for q in _questions_bank:
        d = q.get("domain")
        if d in bucket_q:
            bucket_q[d][_q_kind(q)].append(q)

    for d, (tf_t, mcq_t, sc_t) in QUESTION_TARGETS.items():
        q_targeted.extend(bucket_q[d]["tf"][:tf_t])
        q_targeted.extend(bucket_q[d]["mcq"][:mcq_t])
        q_targeted.extend(bucket_q[d]["scenario_mcq"][:sc_t])

    # Save finalized banks
    _save_bank(FLASHCARDS_BANK_PATH, fc_targeted)
    _save_bank(QUESTIONS_BANK_PATH,  q_targeted)
    _persist_all()

    # Summaries
    fc_counts = {d: 0 for d in FLASHCARD_TARGETS}
    for c in fc_targeted:
        fc_counts[c["domain"]] += 1

    q_counts = {d: {"tf": 0, "mcq": 0, "scenario_mcq": 0} for d in FLASHCARD_TARGETS}
    for q in q_targeted:
        q_counts[q["domain"]][_q_kind(q)] += 1

    _log_event(_user_id(), "content.finalize", {
        "flashcards": len(fc_targeted),
        "questions": len(q_targeted)
    })

    return {
        "ok": True,
        "flashcards_total": len(fc_targeted),
        "questions_total": len(q_targeted),
        "flashcards_by_domain": fc_counts,
        "questions_by_domain": q_counts
    }

# ---- Admin guard ----
def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not is_admin():
            # Fallback: allow with ADMIN_PASSWORD via basic form/header for headless calls
            pw = request.headers.get("X-Admin-Password", "") or request.args.get("admin_pw","") or ""
            if not pw or pw != (ADMIN_PASSWORD or ""):
                abort(403)
        return f(*args, **kwargs)
    return wrapper

# ---- Admin endpoints (no UI changes) ----
@app.get("/admin/content/status")
@login_required
@admin_required
def admin_content_status():
    _ensure_banks_loaded()
    fc_counts, q_counts = _current_quota()
    resp = {
        "flashcards_total": len(_flashcards_bank),
        "questions_total": len(_questions_bank),
        "flashcards_by_domain": fc_counts,
        "questions_by_domain": q_counts,
        "targets": {
            "flashcards": FLASHCARD_TARGETS,
            "questions": {k: {"tf": v[0], "mcq": v[1], "scenario_mcq": v[2]} for k, v in QUESTION_TARGETS.items()},
            "questions_total": QUESTION_TARGET_TOTAL
        }
    }
    return safe_json_response(resp)

@app.post("/admin/content/ingest")
@login_required
@admin_required
def admin_content_ingest():
    try:
        payload = request.get_json(force=True, silent=True) or {}
        items = payload if isinstance(payload, list) else payload.get("items", [])
        result = _ingest_items(items)
        return safe_json_response(result)
    except Exception as e:
        logger.error("ingest error: %s", e, exc_info=True)
        return safe_json_response({"ok": False, "error": "ingest-failed"}, 500)

@app.post("/admin/content/finalize")
@login_required
@admin_required
def admin_content_finalize():
    try:
        result = _finalize_banks()
        return safe_json_response(result)
    except Exception as e:
        logger.error("finalize error: %s", e, exc_info=True)
        return safe_json_response({"ok": False, "error": "finalize-failed"}, 500)

# ---- Bank usage hooks for existing Quiz/Mock/Flashcards routes (no UI changes yet) ----
def _get_flashcards_bank():
    _ensure_banks_loaded()
    return _flashcards_bank or []

def _get_questions_bank():
    _ensure_banks_loaded()
    return _questions_bank or []
# ====== Bank-backed selection (no UI changes) ======
def _normalized_bank_questions():
    """
    Convert bank-format questions into the quiz engine's normalized structure:
      {
        "id": str,
        "text": "...",
        "domain": "Principles|Business|...",
        "choices": [{"key":"A","text":"..."}, ...],
        "correct_key": "A"
      }
    """
    qs = []
    letters = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    for q in _get_questions_bank():
        try:
            stem = (q.get("question") or "").strip()
            if not stem:
                continue
            raw_choices = q.get("choices") or []
            # Convert list -> [{"key":"A","text":"..."}]
            ch = []
            for i, opt in enumerate(raw_choices):
                if i >= len(letters):
                    break
                key = letters[i]
                ch.append({"key": key, "text": str(opt)})
            if len(ch) < 2:
                continue
            ci = int(q.get("correct_index", -1))
            if ci < 0 or ci >= len(ch):
                continue
            correct_key = ch[ci]["key"]
            qs.append({
                "id": str(q.get("id") or uuid.uuid4()),
                "text": stem,
                "domain": q.get("domain"),
                "choices": ch,
                "correct_key": correct_key
            })
        except Exception:
            continue
    return qs

# Override the earlier helper to prefer bank questions when present
def _all_normalized_questions():
    bank_qs = _normalized_bank_questions()
    if bank_qs:
        return bank_qs
    # Fallback to legacy in-memory set
    try:
        base = ALL_QUESTIONS
    except Exception:
        base = []
    out = []
    letters = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    for i, q in enumerate(base):
        try:
            qid = str(q.get("id") or i or uuid.uuid4())
            text = (q.get("question") or q.get("q") or q.get("stem") or q.get("text") or "").strip()
            domain = (q.get("domain") or q.get("category") or q.get("section") or None)
            raw_choices = (q.get("choices") or q.get("options") or q.get("answers") or [])
            choices = []
            for j, c in enumerate(raw_choices[:5]):
                if isinstance(c, dict):
                    k = str(c.get("key") or letters[j])
                    t = str(c.get("text") or c.get("label") or c.get("value") or "")
                else:
                    k = letters[j]
                    t = str(c)
                choices.append({"key": k.strip(), "text": t})
            correct = q.get("correct") or q.get("answer") or q.get("correct_key")
            correct_key = None
            if isinstance(correct, (int, float)) and 0 <= int(correct) < len(choices):
                correct_key = choices[int(correct)]["key"]
            elif isinstance(correct, str):
                ck = correct.strip()
                if ck in {c["key"] for c in choices}:
                    correct_key = ck
                else:
                    for c in choices:
                        if ck.lower() == c["text"].strip().lower():
                            correct_key = c["key"]; break
            if text and choices:
                out.append({"id": qid, "text": text, "domain": domain, "choices": choices, "correct_key": correct_key})
        except Exception:
            continue
    return out

def _pick_questions(count, domain=None):
    """
    Uses bank-backed pool (if present). Domain filter matches bank domains exactly.
    """
    pool = _all_normalized_questions()
    if domain:
        pool = [q for q in pool if str(q.get("domain") or "").lower() == str(domain).lower()]
    random.shuffle(pool)
    return pool[:max(1, min(count, len(pool)))]

# ====== Flashcards: bank-backed API (no UI change to /flashcards page) ======
def _normalized_bank_flashcards():
    """Expose flashcards as a simple list of dicts (id, question, answer, rationale, domain, difficulty, sources)."""
    cards = []
    for c in _get_flashcards_bank():
        try:
            cards.append({
                "id": str(c.get("id") or uuid.uuid4()),
                "question": (c.get("question") or "").strip(),
                "answer": (c.get("answer") or "").strip(),
                "rationale": (c.get("rationale") or "").strip(),
                "domain": c.get("domain"),
                "difficulty": c.get("difficulty"),
                "sources": c.get("sources") or []
            })
        except Exception:
            continue
    return cards

@app.get("/api/flashcards")
@login_required
def api_flashcards_list():
    """
    Lightweight JSON feed to power the existing Flashcards page client-side (no markup change).
    Query params:
      - domain: optional exact domain match
      - count: optional int (default 20)
      - offset: optional int (default 0)
    """
    try:
        domain = request.args.get("domain")
        try:
            count = max(1, min(int(request.args.get("count", 20)), 100))
        except Exception:
            count = 20
        try:
            offset = max(0, int(request.args.get("offset", 0)))
        except Exception:
            offset = 0

        cards = _normalized_bank_flashcards()
        if domain:
            cards = [c for c in cards if str(c.get("domain")) == domain]
        total = len(cards)
        page = cards[offset: offset + count]
        _log_event(_user_id(), "flashcards.fetch", {"count": len(page), "offset": offset, "domain": domain or "all"})
        return safe_json_response({"ok": True, "total": total, "items": page})
    except Exception as e:
        logger.error("api/flashcards failed: %s", e, exc_info=True)
        return safe_json_response({"ok": False, "error": "server-error"}, 500)

@app.get("/api/bank/status")
@login_required
def api_bank_status():
    """
    Simple status for the frontend or admin to confirm bank availability without UI changes.
    """
    try:
        fc = _get_flashcards_bank()
        qq = _get_questions_bank()
        fc_counts, q_counts = _current_quota()
        return safe_json_response({
            "ok": True,
            "flashcards_total": len(fc),
            "questions_total": len(qq),
            "flashcards_by_domain": fc_counts,
            "questions_by_domain": q_counts
        })
    except Exception as e:
        logger.error("api/bank/status failed: %s", e, exc_info=True)
        return safe_json_response({"ok": False, "error": "server-error"}, 500)

# ====== Answer instrumentation for quiz/mock (already wired via /api/track) ======
# Nothing else needed here; quiz/mock routes automatically pick from the bank now.
# ====== Generation Runner (admin-only; no UI changes) ======
# Purpose:
# - Report remaining counts by domain/type
# - Accept generator batches (validates + dedups via the existing ingest)
# - Finalize banks to exact targets
# - Reset working banks if you need to start over
# - Expose the kickoff prompt text for your generator

# ---- Helpers: compute remaining needs ----
def _count_flashcards_by_domain(cards):
    counts = {d: 0 for d in FLASHCARD_TARGETS}
    for c in cards:
        d = c.get("domain")
        if d in counts:
            counts[d] += 1
    return counts

def _count_questions_by_domain_type(questions):
    counts = {d: {"tf": 0, "mcq": 0, "scenario_mcq": 0} for d in FLASHCARD_TARGETS}
    for q in questions:
        d = q.get("domain")
        if d in counts:
            counts[d][_q_kind(q)] += 1
    return counts

def _remaining_targets():
    _ensure_banks_loaded()
    fc_have  = _count_flashcards_by_domain(_flashcards_bank)
    q_have   = _count_questions_by_domain_type(_questions_bank)

    fc_need = {d: max(0, FLASHCARD_TARGETS[d] - fc_have.get(d, 0)) for d in FLASHCARD_TARGETS}

    q_need = {}
    for d, (tf_t, mcq_t, sc_t) in QUESTION_TARGETS.items():
        cur = q_have.get(d, {"tf": 0, "mcq": 0, "scenario_mcq": 0})
        q_need[d] = {
            "tf": max(0, tf_t - cur["tf"]),
            "mcq": max(0, mcq_t - cur["mcq"]),
            "scenario_mcq": max(0, sc_t - cur["scenario_mcq"]),
        }

    total_q_have = sum(sum(v.values()) for v in q_have.values())
    total_q_need = max(0, QUESTION_TARGET_TOTAL - total_q_have)

    return {
        "flashcards": {"have": fc_have, "need": fc_need, "target": FLASHCARD_TARGETS},
        "questions":  {"have": q_have, "need": q_need, "target": {
            d: {"tf": t[0], "mcq": t[1], "scenario_mcq": t[2]}
            for d, t in QUESTION_TARGETS.items()
        }, "total_have": total_q_have, "total_need": total_q_need, "total_target": QUESTION_TARGET_TOTAL}
    }

# ---- Admin endpoints for generation control ----
@app.get("/admin/generate/needs")
@login_required
@admin_required
def admin_generate_needs():
    return safe_json_response({"ok": True, "summary": _remaining_targets()})

@app.post("/admin/generate/batch")
@login_required
@admin_required
def admin_generate_batch():
    """
    POST JSON:
      {
        "items": [ ... array of flashcards/questions per Section 2 schema ... ],
        "meta": {
          "domain": "Principles|Business|Investigations|Personnel|Physical|InfoSec|Crisis",
          "type": "flashcard|tf|mcq|scenario_mcq",
          "count": <int>,
          "difficulty": "easy|medium|hard|mixed"
        }
      }
    Behavior:
      - Runs through _ingest_items (whitelist + schema + de-dup)
      - Logs generation metrics
    """
    try:
        payload = request.get_json(force=True, silent=True) or {}
        items = payload.get("items") or []
        meta  = payload.get("meta") or {}
        before_fc = len(_get_flashcards_bank())
        before_q  = len(_get_questions_bank())

        result = _ingest_items(items)

        after_fc = len(_get_flashcards_bank())
        after_q  = len(_get_questions_bank())

        # Instrumentation for analytics (per the spec)
        _log_event(_user_id(), "flashcards.generate" if meta.get("type") == "flashcard" else "quiz.generate", {
            "domain": meta.get("domain"),
            "count_requested": meta.get("count"),
            "difficulty": meta.get("difficulty"),
            "kept": len(result.get("kept", [])),
            "dropped": len(result.get("dropped", [])),
            "flashcards_delta": max(0, after_fc - before_fc),
            "questions_delta": max(0, after_q - before_q),
        })

        return safe_json_response({"ok": True, "result": result, "needs": _remaining_targets()})
    except Exception as e:
        logger.error("generate_batch error: %s", e, exc_info=True)
        return safe_json_response({"ok": False, "error": "generate-batch-failed"}, 500)

@app.post("/admin/generate/finalize")
@login_required
@admin_required
def admin_generate_finalize():
    """
    Enforces exact targets and writes:
      - data/bank/cpp_flashcards_v1.json  (300)
      - data/bank/cpp_questions_v1.json   (960)
      - data/content_index.json           (hashes)
    """
    res = _finalize_banks()
    # Add acceptance-like summary in response for quick audits
    ok_300 = (res.get("flashcards_total") == 300)
    ok_960 = (res.get("questions_total")  == 960)
    res.update({"checks": {"flashcards_300": ok_300, "questions_960": ok_960}})
    return safe_json_response(res)

@app.post("/admin/generate/reset")
@login_required
@admin_required
def admin_generate_reset():
    """
    Clears the working banks and index (does NOT touch finalized files unless they are the working ones).
    Use carefully.
    """
    try:
        global _flashcards_bank, _questions_bank, _index_cache
        _flashcards_bank = []
        _questions_bank  = []
        _index_cache     = {"seen_hashes": set(), "items": {}}
        _persist_all()
        _log_event(_user_id(), "content.reset", {})
        return safe_json_response({"ok": True})
    except Exception as e:
        logger.error("reset error: %s", e, exc_info=True)
        return safe_json_response({"ok": False, "error": "reset-failed"}, 500)

# ---- Kickoff Prompt (served back for convenience) ----
KICKOFF_PROMPT = (
    "Context: You’re continuing a Flask CPP study app. Do not change layout/CSS. We need a CPP-only content bank "
    "built from open sources. Use the inventory, schema, validation, whitelist, and dedup rules below. Generate "
    "batches per domain/type until we have 300 flashcards and 960 questions (25% T/F, 60% MCQ, 15% scenario), with "
    "the exact domain distribution specified. Enforce uniqueness with the hashing/signature rules. Include 1–3 allowed "
    "citations on every item. When finished, save to: • data/bank/cpp_flashcards_v1.json (300 items) "
    "• data/bank/cpp_questions_v1.json (960 items) …and a data/content_index.json with hashes. You may regenerate items "
    "that fail validation or collide. Use atomic file writes. Now ask me for my current app.py so you can wire the app "
    "to read these banks without changing the UI."
)

@app.get("/admin/generate/prompt")
@login_required
@admin_required
def admin_generate_prompt():
    return safe_json_response({"ok": True, "kickoff_prompt": KICKOFF_PROMPT})

# ---- Acceptance Quick Check ----
@app.get("/admin/content/acceptance")
@login_required
@admin_required
def admin_content_acceptance():
    """
    Convenience endpoint to verify Acceptance Test items (Section 10).
    """
    _ensure_banks_loaded()

    # 1) Counts
    fc = _load_bank(FLASHCARDS_BANK_PATH)
    qq = _load_bank(QUESTIONS_BANK_PATH)
    counts_ok = (len(fc) == 300 and len(qq) == 960)

    # 2) Source whitelist quick scan
    def _urls_ok(items):
        for it in items:
            for s in (it.get("sources") or []):
                if not _is_allowed_source(s.get("url","")):
                    return False
        return True

    urls_ok = _urls_ok(fc) and _urls_ok(qq)

    # 3) T/F choice rule
    tf_ok = True
    for q in qq:
        if _q_kind(q) == "tf":
            if not _is_tf_choice_set(q.get("choices")):
                tf_ok = False
                break

    # 4) Options count rule
    opts_ok = True
    for q in qq:
        if _q_kind(q) != "tf":
            ch = q.get("choices") or []
            if len(ch) < 4 or len(ch) > 5:
                opts_ok = False
                break

    # 5) Domain distribution within ±1 only for rounding (we enforce exact in finalize anyway)
    #    Here, just report the actuals.
    fc_counts = _count_flashcards_by_domain(fc)
    q_counts  = _count_questions_by_domain_type(qq)

    return safe_json_response({
        "ok": counts_ok and urls_ok and tf_ok and opts_ok,
        "checks": {
            "counts": counts_ok,
            "whitelist": urls_ok,
            "tf_rule": tf_ok,
            "options_rule": opts_ok
        },
        "flashcards_total": len(fc),
        "questions_total": len(qq),
        "flashcards_by_domain": fc_counts,
        "questions_by_domain": q_counts,
        "targets": {
            "flashcards": FLASHCARD_TARGETS,
            "questions": {d: {"tf": t[0], "mcq": t[1], "scenario_mcq": t[2]} for d, t in QUESTION_TARGETS.items()},
            "questions_total": QUESTION_TARGET_TOTAL
        }
    })

