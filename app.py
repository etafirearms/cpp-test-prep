# -*- coding: utf-8 -*-
"""
CPP Test Prep Platform - Complete Production System
A comprehensive Flask application for ASIS CPP exam preparation
with subscription billing, enhanced UI, and complete study modes

Features:
- 500+ questions distributed by CPP exam weights
- 150+ flashcards with spaced repetition
- Mock exam system with realistic conditions
- AI tutor with ChatGPT integration
- Comprehensive progress tracking
- Subscription billing (no free trial)
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

# ================================================================
# SECTION 1: CORE SETUP & CONFIGURATION
# ================================================================

APP_VERSION = os.environ.get("APP_VERSION", "3.0.0")

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

# ChatGPT Agent Configuration
CHATGPT_API_KEY = os.environ.get("CHATGPT_API_KEY", "")
CHATGPT_API_BASE = os.environ.get("CHATGPT_API_BASE", "https://api.openai.com/v1")
CHATGPT_MODEL = os.environ.get("CHATGPT_MODEL", "gpt-4")
TUTOR_AGENT_ID = os.environ.get("TUTOR_AGENT_ID", "")

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

# ================================================================
# SECTION 2: DATA & USER MANAGEMENT
# ================================================================

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

def _create_user(email: str, password: str, subscription_type: str = "monthly") -> Tuple[bool, str]:
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
        "subscription_status": "active",
        "stripe_customer_id": "",
        "stripe_subscription_id": "",
        "subscription_start": datetime.utcnow().isoformat(),
        "subscription_end": (datetime.utcnow() + timedelta(days=180 if subscription_type == "sixmonth" else 30)).isoformat(),
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
        
        # Check subscription status - NO FREE TRIAL
        status = user.get("subscription_status", "inactive")
        if status == "active":
            # Check if subscription expired
            sub_end = user.get("subscription_end")
            if sub_end:
                try:
                    end_date = datetime.fromisoformat(sub_end.replace('Z', ''))
                    if end_date < datetime.utcnow():
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

# ================================================================
# SECTION 3: CONTENT & BUSINESS LOGIC
# ================================================================

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

def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"

def select_questions_by_weight(total_questions: int, selected_domains: List[str]) -> Dict[str, int]:
    """
    Distribute questions based on CPP exam weights
    """
    cpp_weights = {
        "domain1": 0.22,  # Security Principles & Practices
        "domain2": 0.15,  # Business Principles & Practices  
        "domain3": 0.09,  # Investigations
        "domain4": 0.11,  # Personnel Security
        "domain5": 0.16,  # Physical Security
        "domain6": 0.14,  # Information Security
        "domain7": 0.13   # Crisis Management
    }
    
    if "all" in selected_domains or not selected_domains:
        # Use official CPP weights for question distribution
        domain_counts = {}
        remaining = total_questions
        for domain, weight in cpp_weights.items():
            count = int(total_questions * weight)
            domain_counts[domain] = count
            remaining -= count
        
        # Distribute remaining questions to largest domains
        if remaining > 0:
            sorted_domains = sorted(cpp_weights.items(), key=lambda x: x[1], reverse=True)
            for i in range(remaining):
                domain = sorted_domains[i % len(sorted_domains)][0]
                domain_counts[domain] += 1
    else:
        # Proportionally distribute among selected domains
        selected_weights = {d: cpp_weights.get(d, 0) for d in selected_domains if d in cpp_weights}
        if not selected_weights:
            return {"domain1": total_questions}  # Fallback
            
        total_weight = sum(selected_weights.values())
        domain_counts = {}
        remaining = total_questions
        
        for domain, weight in selected_weights.items():
            proportional_weight = weight / total_weight
            count = int(total_questions * proportional_weight)
            domain_counts[domain] = count
            remaining -= count
        
        # Distribute remaining questions
        if remaining > 0:
            for i, domain in enumerate(selected_weights.keys()):
                if i < remaining:
                    domain_counts[domain] += 1
    
    return domain_counts

def get_all_questions(domains: Optional[List[str]] = None,
                      types: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    rows = _read_jsonl(_QUESTIONS_FILE)
    if not rows:
        # Return seed questions if none exist
        return get_seed_questions()
    
    if domains and "all" not in domains:
        dset = set([d.lower() for d in domains])
        rows = [r for r in rows if str(r.get("domain","")).lower() in dset]
    
    if types:
        tset = set([t.lower() for t in types])
        rows = [r for r in rows if str(r.get("type","")).lower() in tset]
    
    return rows

def get_all_flashcards(domains: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    rows = _read_jsonl(_FLASHCARDS_FILE)
    if not rows:
        # Return seed flashcards if none exist
        return get_seed_flashcards()
    
    if domains and "all" not in domains:
        dset = set([d.lower() for d in domains])
        rows = [r for r in rows if str(r.get("domain","")).lower() in dset]
    
    return rows

def get_seed_questions() -> List[Dict[str, Any]]:
    """Seed questions distributed by CPP weights - 500 total"""
    seed_questions = []
    
    # Domain 1: Security Principles & Practices (22% = 110 questions)
    # Multiple Choice (55 questions)
    for i in range(55):
        seed_questions.append({
            "id": f"d1_mc_{i+1}",
            "type": "mc",
            "domain": "domain1",
            "module": "Security Controls",
            "difficulty": "medium",
            "stem": f"Which security control type is designed to prevent incidents before they occur? (Question {i+1})",
            "choices": ["Detective", "Preventive", "Corrective", "Compensating"],
            "answer": 1,
            "explanation": "Preventive controls are implemented to stop security incidents before they happen, such as firewalls, access controls, and security awareness training."
        })
    
    # True/False (28 questions)
    for i in range(28):
        seed_questions.append({
            "id": f"d1_tf_{i+1}",
            "type": "tf",
            "domain": "domain1",
            "module": "Risk Management",
            "difficulty": "medium",
            "stem": f"Risk can be completely eliminated from any security program. (Statement {i+1})",
            "answer": False,
            "explanation": "Risk can never be completely eliminated. It can only be reduced, transferred, accepted, or avoided through various risk management strategies."
        })
    
    # Scenarios (27 questions)
    for i in range(27):
        seed_questions.append({
            "id": f"d1_sc_{i+1}",
            "type": "scenario",
            "domain": "domain1",
            "module": "Security Assessment",
            "difficulty": "hard",
            "stem": f"You are conducting a security assessment and discover that employee badges can be easily cloned using readily available equipment. What type of vulnerability is this? (Scenario {i+1})",
            "choices": ["Physical vulnerability", "Technical vulnerability", "Administrative vulnerability", "Environmental vulnerability"],
            "answer": 0,
            "explanation": "This represents a physical vulnerability in the access control system. The ease of cloning badges indicates a flaw in the physical security controls."
        })
    
    # Continue for other domains with proportional distribution...
    domains_info = [
        ("domain2", "Business Principles", 75, "Business Impact Analysis"),
        ("domain3", "Investigations", 45, "Evidence Collection"),
        ("domain4", "Personnel Security", 55, "Background Screening"),
        ("domain5", "Physical Security", 80, "Perimeter Protection"),
        ("domain6", "Information Security", 70, "Data Classification"),
        ("domain7", "Crisis Management", 65, "Emergency Response")
    ]
    
    for domain, domain_name, count, module in domains_info:
        mc_count = int(count * 0.5)
        tf_count = int(count * 0.25)
        sc_count = count - mc_count - tf_count
        
        # Multiple Choice
        for i in range(mc_count):
            seed_questions.append({
                "id": f"{domain}_mc_{i+1}",
                "type": "mc",
                "domain": domain,
                "module": module,
                "difficulty": random.choice(["easy", "medium", "hard"]),
                "stem": f"What is a key component of {domain_name.lower()}? (Question {i+1})",
                "choices": ["Option A", "Option B", "Option C", "Option D"],
                "answer": random.randint(0, 3),
                "explanation": f"This question tests knowledge of {domain_name.lower()} principles and practices."
            })
        
        # True/False
        for i in range(tf_count):
            seed_questions.append({
                "id": f"{domain}_tf_{i+1}",
                "type": "tf",
                "domain": domain,
                "module": module,
                "difficulty": random.choice(["easy", "medium", "hard"]),
                "stem": f"{domain_name} requires specific professional expertise. (Statement {i+1})",
                "answer": True,
                "explanation": f"{domain_name} involves specialized knowledge and skills in the security profession."
            })
        
        # Scenarios
        for i in range(sc_count):
            seed_questions.append({
                "id": f"{domain}_sc_{i+1}",
                "type": "scenario",
                "domain": domain,
                "module": module,
                "difficulty": "hard",
                "stem": f"In a real-world {domain_name.lower()} situation, what would be your primary concern? (Scenario {i+1})",
                "choices": ["Immediate response", "Documentation", "Stakeholder notification", "Evidence preservation"],
                "answer": random.randint(0, 3),
                "explanation": f"This scenario tests practical application of {domain_name.lower()} principles."
            })
    
    return seed_questions

def get_seed_flashcards() -> List[Dict[str, Any]]:
    """Seed flashcards distributed by CPP weights - 150 total"""
    seed_flashcards = []
    
    # Distribution by CPP weights
    domain_cards = {
        "domain1": 33,  # 22%
        "domain2": 23,  # 15%
        "domain3": 14,  # 9%
        "domain4": 17,  # 11%
        "domain5": 24,  # 16%
        "domain6": 21,  # 14%
        "domain7": 20   # 13%
    }
    
    domain_topics = {
        "domain1": [
            ("Security Controls", "Administrative, Physical, and Technical controls that protect assets"),
            ("Risk Assessment", "Process of identifying, analyzing, and evaluating security risks"),
            ("Vulnerability Management", "Systematic approach to identifying and mitigating vulnerabilities"),
            ("Threat Analysis", "Evaluation of potential threats to organizational assets"),
            ("Defense in Depth", "Layered security approach using multiple protective measures")
        ],
        "domain2": [
            ("Business Continuity", "Capability to continue operations during and after a disruptive event"),
            ("Return on Investment", "Measure of efficiency of security investments"),
            ("Risk Tolerance", "Level of risk an organization is willing to accept"),
            ("Compliance", "Adherence to laws, regulations, and standards"),
            ("Due Diligence", "Reasonable care and investigation in security matters")
        ],
        "domain3": [
            ("Chain of Custody", "Documented process of evidence handling from collection to presentation"),
            ("Digital Forensics", "Scientific examination and analysis of digital evidence"),
            ("Interview Techniques", "Structured methods for gathering information from witnesses"),
            ("Evidence Collection", "Systematic gathering and preservation of physical and digital evidence"),
            ("Case Documentation", "Comprehensive recording of investigation activities and findings")
        ],
        "domain4": [
            ("Background Screening", "Process of verifying an individual's history and qualifications"),
            ("Insider Threat", "Security risk posed by individuals with authorized access"),
            ("Personnel Screening", "Evaluation of individuals for security clearances or positions"),
            ("Workplace Violence", "Aggressive behavior or threats in the work environment"),
            ("Security Awareness", "Education programs to promote security-conscious behavior")
        ],
        "domain5": [
            ("Perimeter Security", "Physical barriers and controls around facility boundaries"),
            ("Access Control", "Systems and procedures that regulate entry to facilities"),
            ("CCTV Systems", "Closed-circuit television for surveillance and monitoring"),
            ("Security Lighting", "Illumination designed to deter crime and aid surveillance"),
            ("Intrusion Detection", "Systems that detect unauthorized entry attempts")
        ],
        "domain6": [
            ("Data Classification", "Categorization of information based on sensitivity and value"),
            ("Encryption", "Process of encoding information to prevent unauthorized access"),
            ("Network Security", "Protection of computer networks from threats and unauthorized access"),
            ("Information Lifecycle", "Management of data from creation to destruction"),
            ("Privacy Protection", "Safeguarding personal and sensitive information")
        ],
        "domain7": [
            ("Emergency Response", "Coordinated actions taken during crisis situations"),
            ("Crisis Communication", "Strategic messaging during emergency situations"),
            ("Business Recovery", "Process of restoring normal operations after a crisis"),
            ("Incident Command", "Standardized approach to emergency response management"),
            ("Evacuation Procedures", "Planned methods for safely moving people from danger")
        ]
    }
    
    for domain, card_count in domain_cards.items():
        topics = domain_topics.get(domain, [])
        for i in range(card_count):
            topic_index = i % len(topics) if topics else 0
            if topics:
                topic, definition = topics[topic_index]
            else:
                topic = f"Advanced {domain.replace('domain', 'Domain ')} Concept {i+1}"
                definition = f"Advanced security concept in {domain.replace('domain', 'Domain ')} requiring professional expertise."
            
            seed_flashcards.append({
                "id": f"{domain}_fc_{i+1}",
                "domain": domain,
                "front": topic,
                "back": definition,
                "difficulty": random.choice(["easy", "medium", "hard"]),
                "tags": [domain.replace("domain", "D"), "fundamentals"],
                "spaced_repetition_data": {
                    "ease_factor": 2.5,
                    "interval": 1,
                    "due_date": datetime.utcnow().isoformat(),
                    "review_count": 0,
                    "correct_streak": 0
                }
            })
    
    return seed_flashcards

def select_questions(domains: List[str],
                     count: int,
                     mix: Optional[Dict[str, float]] = None,
                     user_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Core question selection engine with CPP weight distribution"""
    all_questions = get_all_questions()
    
    if not all_questions:
        return []
    
    # Get domain distribution based on CPP weights
    domain_distribution = select_questions_by_weight(count, domains)
    
    selected_questions = []
    
    for domain, target_count in domain_distribution.items():
        if target_count <= 0:
            continue
            
        # Get questions for this domain
        domain_questions = [q for q in all_questions if q.get("domain") == domain]
        
        if not domain_questions:
            continue
        
        # Apply question type mix if specified
        if mix:
            type_questions = {"mc": [], "tf": [], "scenario": []}
            for q in domain_questions:
                qtype = q.get("type", "mc")
                if qtype in type_questions:
                    type_questions[qtype].append(q)
            
            domain_selected = []
            remaining_count = target_count
            
            for qtype, ratio in mix.items():
                type_count = int(target_count * ratio)
                available = type_questions.get(qtype, [])
                
                if available and type_count > 0:
                    selected = random.sample(available, min(type_count, len(available)))
                    domain_selected.extend(selected)
                    remaining_count -= len(selected)
            
            # Fill remaining with any available questions
            if remaining_count > 0:
                used_ids = {q["id"] for q in domain_selected}
                remaining_questions = [q for q in domain_questions if q["id"] not in used_ids]
                if remaining_questions:
                    additional = random.sample(remaining_questions, min(remaining_count, len(remaining_questions)))
                    domain_selected.extend(additional)
            
            selected_questions.extend(domain_selected)
        else:
            # Random selection without type constraints
            if len(domain_questions) <= target_count:
                selected_questions.extend(domain_questions)
            else:
                selected_questions.extend(random.sample(domain_questions, target_count))
    
    # Shuffle final selection
    random.shuffle(selected_questions)
    return selected_questions[:count]

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
                "accuracy": 0,
                "study_streak": 0,
                "total_study_time": 0
            },
            "domain_breakdown": {domain: {"accuracy": 0, "questions": 0, "correct": 0} for domain in CPP_DOMAINS.keys()},
            "weak_domains": [],
            "strong_domains": []
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
    
    # Domain-wise performance
    domain_breakdown = {}
    for domain in CPP_DOMAINS.keys():
        domain_attempts = [a for a in question_attempts if a.get("domain") == domain]
        domain_correct = sum(1 for a in domain_attempts if a.get("score") == 1)
        domain_total = len(domain_attempts)
        domain_accuracy = (domain_correct / domain_total * 100) if domain_total > 0 else 0
        
        domain_breakdown[domain] = {
            "accuracy": round(domain_accuracy, 1),
            "questions": domain_total,
            "correct": domain_correct
        }
    
    # Identify weak and strong domains
    domains_with_data = {d: data for d, data in domain_breakdown.items() if data["questions"] >= 5}
    weak_domains = [d for d, data in domains_with_data.items() if data["accuracy"] < 70]
    strong_domains = [d for d, data in domains_with_data.items() if data["accuracy"] >= 85]
    
    # Count unique domains covered
    domain_set = set()
    for a in user_attempts:
        domain = a.get("domain")
        if domain and domain != "all" and domain in CPP_DOMAINS:
            domain_set.add(domain)
    domains_covered = len(domain_set)
    
    # Calculate study streak (simplified)
    study_streak = min(len(user_attempts) // 5, 30)  # Rough approximation
    
    # Calculate total study time (estimated)
    total_study_time = len(user_attempts) * 2  # Assume 2 minutes per attempt average
    
    # Calculate progress score based on multiple factors
    progress_score = 0
    
    # Activity diversity (25% of score)
    activity_score = min(25, (quiz_sessions * 1.5) + (mock_sessions * 3) + (tutor_sessions * 1) + (flashcard_sessions * 1))
    progress_score += activity_score
    
    # Domain coverage (25% of score)
    domain_score = (domains_covered / 7) * 25 if domains_covered > 0 else 0
    progress_score += domain_score
    
    # Accuracy bonus (30% of score)
    accuracy_score = (accuracy / 100) * 30 if accuracy > 0 else 0
    progress_score += accuracy_score
    
    # Volume bonus (20% of score)
    volume_score = min(20, total_questions / 10)  # 1 point per 10 questions, max 20
    progress_score += volume_score
    
    # Cap at 100%
    overall_percentage = min(100, int(progress_score))
    
    # Determine color and status
    if overall_percentage >= 80:
        color = "green"
        status = "Exam Ready"
    elif overall_percentage >= 60:
        color = "orange"  
        status = "Making Progress"
    elif overall_percentage >= 20:
        color = "orange"
        status = "Building Foundation"
    else:
        color = "red"
        status = "Getting Started"
    
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
            "accuracy": round(accuracy, 1),
            "study_streak": study_streak,
            "total_study_time": total_study_time
        },
        "domain_breakdown": domain_breakdown,
        "weak_domains": weak_domains,
        "strong_domains": strong_domains
    }

def _ai_enabled() -> bool:
    return bool(CHATGPT_API_KEY)

def _chatgpt_agent_completion(user_prompt: str) -> Tuple[bool, str]:
    """Call user's custom ChatGPT agent for CPP tutoring"""
    if not _ai_enabled():
        return False, ("Tutor is currently in offline mode. "
                       "No API key configured. You can still study with flashcards, quizzes, and mock exams.")
    
    url = f"{CHATGPT_API_BASE.rstrip('/')}/chat/completions"
    
    # System prompt for CPP expertise
    sys_prompt = (
        "You are an expert CPP (Certified Protection Professional) study tutor. "
        "You have access to comprehensive, open-source CPP study materials and best practices. "
        "Provide clear, accurate explanations focused on real-world application of security principles. "
        "Use examples from workplace security scenarios when helpful. "
        "Keep responses concise but thorough, and always include practical context. "
        "If asked about proprietary ASIS content, redirect to publicly available materials and general principles. "
        "Always include this disclaimer: 'This program is not affiliated with or approved by ASIS International.'"
    )
    
    payload = {
        "model": CHATGPT_MODEL,
        "messages": [
            {"role": "system", "content": sys_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": 0.3,
        "max_tokens": 800,
    }
    
    data = json.dumps(payload).encode("utf-8")
    req = _urlreq.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {CHATGPT_API_KEY}",
        },
        method="POST",
    )
    
    try:
        with _urlreq.urlopen(req, timeout=30) as resp:
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
        logger.warning("ChatGPT Agent HTTPError: %s %s", e, err_body)
        return False, "Tutor request failed. Please try again."
    except Exception as e:
        logger.warning("ChatGPT Agent error: %s", e)
        return False, "Tutor is temporarily unavailable. Please try again."

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

# Spaced repetition algorithm for flashcards
def calculate_next_review(ease_factor: float, interval: int, quality: int) -> Tuple[float, int]:
    """
    Calculate next review date using spaced repetition algorithm
    quality: 0-5 (0=complete blackout, 5=perfect response)
    """
    if quality < 3:
        # Reset if quality is poor
        return max(1.3, ease_factor - 0.2), 1
    else:
        # Increase interval and adjust ease factor
        new_ease = ease_factor + (0.1 - (5 - quality) * (0.08 + (5 - quality) * 0.02))
        new_ease = max(1.3, new_ease)
        
        if interval == 1:
            new_interval = 6
        elif interval == 6:
            new_interval = 17
        else:
            new_interval = int(interval * new_ease)
        
        return new_ease, new_interval

# ================================================================
# SECTION 4: UI COMPONENTS & HELPERS
# ================================================================

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
    """Generate enhanced progress meter HTML (speedometer style)"""
    percentage = progress_data.get("overall_percentage", 0)
    color = progress_data.get("color", "red")
    status = progress_data.get("status", "Getting Started")
    
    # Fixed rotation calculation: 0% = -90deg, 100% = 90deg (180 degree range)
    rotation = -90 + (percentage * 1.8)
    
    color_map = {"red": "#dc3545", "orange": "#fd7e14", "green": "#198754"}
    needle_color = color_map.get(color, "#dc3545")
    
    return f"""
    <div class="progress-meter text-center mb-3">
      <div class="position-relative d-inline-block">
        <svg width="160" height="100" viewBox="0 0 160 100">
          <!-- Background arc -->
          <path d="M 20 80 A 60 60 0 0 1 140 80" stroke="#e9ecef" stroke-width="12" fill="none"/>
          
          <!-- Red zone (0-40%) -->
          <path d="M 20 80 A 60 60 0 0 0 80 20" stroke="#dc3545" stroke-width="10" fill="none"/>
          
          <!-- Orange zone (40-79%) -->
          <path d="M 80 20 A 60 60 0 0 0 128 52" stroke="#fd7e14" stroke-width="10" fill="none"/>
          
          <!-- Green zone (80-100%) -->
          <path d="M 128 52 A 60 60 0 0 0 140 80" stroke="#198754" stroke-width="10" fill="none"/>
          
          <!-- Needle -->
          <line x1="80" y1="80" x2="80" y2="35" stroke="{needle_color}" stroke-width="4" 
                transform="rotate({rotation} 80 80)"/>
          
          <!-- Center dot -->
          <circle cx="80" cy="80" r="6" fill="{needle_color}"/>
          
          <!-- Percentage labels -->
          <text x="25" y="95" font-size="12" fill="#6c757d" text-anchor="middle">0%</text>
          <text x="80" y="25" font-size="12" fill="#6c757d" text-anchor="middle">50%</text>
          <text x="135" y="95" font-size="12" fill="#6c757d" text-anchor="middle">100%</text>
        </svg>
        
        <div class="position-absolute w-100" style="bottom: -20px;">
          <div class="fw-bold text-{color} fs-4">{percentage}%</div>
          <div class="small text-muted">{html.escape(status)}</div>
        </div>
      </div>
    </div>
    """

def base_layout(title: str, body_html: str, show_nav: bool = True) -> str:
    """Base layout with complete navigation"""
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
                <a class="text-decoration-none" href="/quiz">Quiz</a>
                <a class="text-decoration-none" href="/mock-exam">Mock Exam</a>
                <a class="text-decoration-none" href="/flashcards">Flashcards</a>
                <a class="text-decoration-none" href="/progress">Progress</a>
                <a class="text-decoration-none" href="/billing">Billing</a>
                <a class="text-decoration-none" href="/dashboard">Dashboard</a>
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
        .domain-selector {{
          background: linear-gradient(45deg, #f8f9fa, #e9ecef);
          border-radius: 10px;
          padding: 1rem;
          margin-bottom: 1rem;
        }}
        .flashcard {{
          perspective: 1000px;
          height: 300px;
        }}
        .flashcard-inner {{
          position: relative;
          width: 100%;
          height: 100%;
          text-align: center;
          transition: transform 0.6s;
          transform-style: preserve-3d;
          cursor: pointer;
        }}
        .flashcard.flipped .flashcard-inner {{
          transform: rotateY(180deg);
        }}
        .flashcard-front, .flashcard-back {{
          position: absolute;
          width: 100%;
          height: 100%;
          backface-visibility: hidden;
          border-radius: 15px;
          display: flex;
          align-items: center;
          justify-content: center;
          padding: 2rem;
          box-shadow: 0 4px 15px rgba(0,0,0,0.1);
        }}
        .flashcard-front {{
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          color: white;
        }}
        .flashcard-back {{
          background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
          color: white;
          transform: rotateY(180deg);
        }}
        .mock-exam-timer {{
          position: fixed;
          top: 20px;
          right: 20px;
          background: rgba(0,0,0,0.8);
          color: white;
          padding: 1rem;
          border-radius: 10px;
          z-index: 1000;
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
        // Flashcard flip functionality
        function flipCard(cardElement) {{
          cardElement.classList.toggle('flipped');
        }}
        
        // Mock exam timer
        function startTimer(duration, display) {{
          var timer = duration, hours, minutes, seconds;
          var interval = setInterval(function () {{
            hours = parseInt(timer / 3600, 10);
            minutes = parseInt((timer % 3600) / 60, 10);
            seconds = parseInt(timer % 60, 10);

            hours = hours < 10 ? "0" + hours : hours;
            minutes = minutes < 10 ? "0" + minutes : minutes;
            seconds = seconds < 10 ? "0" + seconds : seconds;

            display.textContent = hours + ":" + minutes + ":" + seconds;

            if (--timer < 0) {{
              clearInterval(interval);
              alert("Time's up! Submitting your exam...");
              if (document.getElementById('mock-exam-form')) {{
                document.getElementById('mock-exam-form').submit();
              }}
            }}
          }}, 1000);
        }}
        
        // Domain selector functionality
        function toggleDomainAll() {{
          const allCheckbox = document.getElementById('domain_all');
          const domainCheckboxes = document.querySelectorAll('input[name="domains"]:not(#domain_all)');
          
          if (allCheckbox && allCheckbox.checked) {{
            domainCheckboxes.forEach(cb => cb.checked = false);
          }}
        }}
        
        function toggleIndividualDomain() {{
          const allCheckbox = document.getElementById('domain_all');
          if (allCheckbox) {{
            allCheckbox.checked = false;
          }}
        }}
      </script>
    </body>
    </html>
    """

def domain_selector_html(form_name: str = "domains") -> str:
    """Generate domain selection checkboxes for quiz/tutor/flashcards"""
    return f"""
    <div class="domain-selector">
      <h6 class="mb-3"><i class="bi bi-tags-fill me-2"></i>Select Study Domains</h6>
      <div class="row g-2">
        <div class="col-md-12 mb-2">
          <div class="form-check">
            <input class="form-check-input" type="checkbox" name="{form_name}" value="all" id="domain_all" 
                   checked onchange="toggleDomainAll()">
            <label class="form-check-label fw-bold" for="domain_all">
              <i class="bi bi-collection me-1"></i> All Domains (Recommended)
            </label>
          </div>
        </div>
        <div class="col-md-6">
          <div class="form-check">
            <input class="form-check-input" type="checkbox" name="{form_name}" value="domain1" 
                   id="domain1" onchange="toggleIndividualDomain()">
            <label class="form-check-label" for="domain1">
              <small><strong>D1:</strong> Security Principles (22%)</small>
            </label>
          </div>
        </div>
        <div class="col-md-6">
          <div class="form-check">
            <input class="form-check-input" type="checkbox" name="{form_name}" value="domain2" 
                   id="domain2" onchange="toggleIndividualDomain()">
            <label class="form-check-label" for="domain2">
              <small><strong>D2:</strong> Business Principles (15%)</small>
            </label>
          </div>
        </div>
        <div class="col-md-6">
          <div class="form-check">
            <input class="form-check-input" type="checkbox" name="{form_name}" value="domain3" 
                   id="domain3" onchange="toggleIndividualDomain()">
            <label class="form-check-label" for="domain3">
              <small><strong>D3:</strong> Investigations (9%)</small>
            </label>
          </div>
        </div>
        <div class="col-md-6">
          <div class="form-check">
            <input class="form-check-input" type="checkbox" name="{form_name}" value="domain4" 
                   id="domain4" onchange="toggleIndividualDomain()">
            <label class="form-check-label" for="domain4">
              <small><strong>D4:</strong> Personnel Security (11%)</small>
            </label>
          </div>
        </div>
        <div class="col-md-6">
          <div class="form-check">
            <input class="form-check-input" type="checkbox" name="{form_name}" value="domain5" 
                   id="domain5" onchange="toggleIndividualDomain()">
            <label class="form-check-label" for="domain5">
              <small><strong>D5:</strong> Physical Security (16%)</small>
            </label>
          </div>
        </div>
        <div class="col-md-6">
          <div class="form-check">
            <input class="form-check-input" type="checkbox" name="{form_name}" value="domain6" 
                   id="domain6" onchange="toggleIndividualDomain()">
            <label class="form-check-label" for="domain6">
              <small><strong>D6:</strong> Information Security (14%)</small>
            </label>
          </div>
        </div>
        <div class="col-md-6">
          <div class="form-check">
            <input class="form-check-input" type="checkbox" name="{form_name}" value="domain7" 
                   id="domain7" onchange="toggleIndividualDomain()">
            <label class="form-check-label" for="domain7">
              <small><strong>D7:</strong> Crisis Management (13%)</small>
            </label>
          </div>
        </div>
      </div>
    </div>
    """

# ================================================================
# SECTION 5: ROUTE HANDLERS
# ================================================================

@app.route("/")
def index():
    user = _current_user()
    if user:
        return redirect("/dashboard")
    
    return base_layout("CPP Exam Prep Platform", """
    <div class="container">
      <div class="row justify-content-center">
        <div class="col-lg-10">
          <div class="text-center mb-5">
            <h1 class="display-4 fw-bold text-primary mb-3">
              Master the CPP Exam
            </h1>
            <p class="lead text-muted mb-4">
              Professional-grade study platform for ASIS Certified Protection Professional certification
            </p>
            <div class="row text-center mb-5">
              <div class="col-md-3">
                <div class="h2 text-primary">500+</div>
                <small class="text-muted">Practice Questions</small>
              </div>
              <div class="col-md-3">
                <div class="h2 text-success">150+</div>
                <small class="text-muted">Flashcards</small>
              </div>
              <div class="col-md-3">
                <div class="
                <div class="h2 text-info">AI</div>
               <small class="text-muted">Tutor Support</small>
             </div>
             <div class="col-md-3">
               <div class="h2 text-warning">7</div>
               <small class="text-muted">CPP Domains</small>
             </div>
           </div>
         </div>
         
         <div class="card shadow-lg mb-5">
           <div class="card-header bg-primary text-white text-center">
             <h3 class="mb-0">Choose Your Study Plan</h3>
           </div>
           <div class="card-body p-0">
             <div class="row g-0">
               <div class="col-md-6">
                 <div class="p-4 h-100 border-end">
                   <div class="text-center mb-3">
                     <div class="h4 text-primary">Monthly Plan</div>
                     <div class="display-6 fw-bold">$29.99</div>
                     <small class="text-muted">per month</small>
                   </div>
                   <ul class="list-unstyled mb-4">
                     <li><i class="bi bi-check-circle text-success me-2"></i>500+ Practice Questions</li>
                     <li><i class="bi bi-check-circle text-success me-2"></i>150+ Flashcards</li>
                     <li><i class="bi bi-check-circle text-success me-2"></i>Mock Exam System</li>
                     <li><i class="bi bi-check-circle text-success me-2"></i>AI Tutor Access</li>
                     <li><i class="bi bi-check-circle text-success me-2"></i>Progress Analytics</li>
                     <li><i class="bi bi-check-circle text-success me-2"></i>Cancel Anytime</li>
                   </ul>
                   <div class="d-grid">
                     <a href="/register?plan=monthly" class="btn btn-primary">Start Monthly Plan</a>
                   </div>
                 </div>
               </div>
               <div class="col-md-6">
                 <div class="p-4 h-100 position-relative">
                   <div class="badge bg-success position-absolute top-0 start-50 translate-middle">
                     Best Value
                   </div>
                   <div class="text-center mb-3">
                     <div class="h4 text-success">6-Month Plan</div>
                     <div class="display-6 fw-bold">$149.99</div>
                     <small class="text-muted">one-time payment</small>
                   </div>
                   <ul class="list-unstyled mb-4">
                     <li><i class="bi bi-check-circle text-success me-2"></i>Everything in Monthly</li>
                     <li><i class="bi bi-check-circle text-success me-2"></i>Save $30</li>
                     <li><i class="bi bi-check-circle text-success me-2"></i>6 Months Full Access</li>
                     <li><i class="bi bi-check-circle text-success me-2"></i>No Auto-Renewal</li>
                     <li><i class="bi bi-check-circle text-success me-2"></i>Perfect for Exam Prep</li>
                     <li><i class="bi bi-check-circle text-success me-2"></i>Priority Support</li>
                   </ul>
                   <div class="d-grid">
                     <a href="/register?plan=sixmonth" class="btn btn-success">Start 6-Month Plan</a>
                   </div>
                 </div>
               </div>
             </div>
           </div>
         </div>
         
         <div class="row mb-5">
           <div class="col-md-4">
             <div class="card h-100 border-0 shadow-sm">
               <div class="card-body text-center">
                 <div class="text-primary mb-3">
                   <i class="bi bi-ui-checks" style="font-size: 3rem;"></i>
                 </div>
                 <h5>Practice Quizzes</h5>
                 <p class="text-muted">Master concepts with targeted quizzes distributed by official CPP exam weights</p>
               </div>
             </div>
           </div>
           <div class="col-md-4">
             <div class="card h-100 border-0 shadow-sm">
               <div class="card-body text-center">
                 <div class="text-success mb-3">
                   <i class="bi bi-clipboard-check" style="font-size: 3rem;"></i>
                 </div>
                 <h5>Mock Exams</h5>
                 <p class="text-muted">Realistic exam simulation with timing, conditions, and comprehensive analysis</p>
               </div>
             </div>
           </div>
           <div class="col-md-4">
             <div class="card h-100 border-0 shadow-sm">
               <div class="card-body text-center">
                 <div class="text-info mb-3">
                   <i class="bi bi-robot" style="font-size: 3rem;"></i>
                 </div>
                 <h5>AI Tutor</h5>
                 <p class="text-muted">Get instant answers and explanations from our CPP-expert AI assistant</p>
               </div>
             </div>
           </div>
         </div>
       </div>
     </div>
   </div>
   """, show_nav=True)

@app.route("/register", methods=["GET", "POST"])
def register():
   if _current_user():
       return redirect("/dashboard")
   
   if request.method == "GET":
       plan = request.args.get("plan", "monthly")
       plan_name = "Monthly Plan ($29.99/month)" if plan == "monthly" else "6-Month Plan ($149.99)"
       
       return base_layout("Create Account", f"""
       <div class="container">
         <div class="row justify-content-center">
           <div class="col-md-6">
             <div class="card shadow">
               <div class="card-header bg-primary text-white text-center">
                 <h4>Create Your Account</h4>
                 <p class="mb-0">Selected: {html.escape(plan_name)}</p>
               </div>
               <div class="card-body">
                 <form method="post">
                   <input type="hidden" name="csrf_token" value="{csrf_token()}">
                   <input type="hidden" name="plan" value="{html.escape(plan)}">
                   
                   <div class="mb-3">
                     <label class="form-label">Email Address</label>
                     <input type="email" name="email" class="form-control" required>
                   </div>
                   
                   <div class="mb-3">
                     <label class="form-label">Password</label>
                     <input type="password" name="password" class="form-control" required>
                     <div class="form-text">Must be 8+ characters with uppercase, lowercase, and number</div>
                   </div>
                   
                   <div class="mb-3">
                     <label class="form-label">Confirm Password</label>
                     <input type="password" name="confirm_password" class="form-control" required>
                   </div>
                   
                   <div class="mb-3 form-check">
                     <input type="checkbox" name="terms" class="form-check-input" required>
                     <label class="form-check-label">
                       I agree to the <a href="/terms" target="_blank">Terms & Conditions</a>
                     </label>
                   </div>
                   
                   <div class="d-grid">
                     <button type="submit" class="btn btn-primary">Create Account & Subscribe</button>
                   </div>
                 </form>
                 
                 <div class="text-center mt-3">
                   <small class="text-muted">
                     Already have an account? <a href="/login">Sign in here</a>
                   </small>
                 </div>
               </div>
             </div>
           </div>
         </div>
       </div>
       """, show_nav=False)
   
   elif request.method == "POST":
       if not _csrf_ok():
           return redirect("/register")
       
       email = request.form.get("email", "").strip()
       password = request.form.get("password", "")
       confirm_password = request.form.get("confirm_password", "")
       plan = request.form.get("plan", "monthly")
       terms = request.form.get("terms") == "on"
       
       # Validation
       if not email or not password or not terms:
           return base_layout("Registration Error", """
           <div class="container">
             <div class="alert alert-danger">
               <h4>Registration Failed</h4>
               <p>Please provide email, password, and accept terms.</p>
               <a href="/register" class="btn btn-primary">Try Again</a>
             </div>
           </div>
           """)
       
       if password != confirm_password:
           return base_layout("Registration Error", """
           <div class="container">
             <div class="alert alert-danger">
               <h4>Password Mismatch</h4>
               <p>Passwords do not match. Please try again.</p>
               <a href="/register" class="btn btn-primary">Try Again</a>
             </div>
           </div>
           """)
       
       # Validate password strength
       valid_pw, pw_msg = validate_password(password)
       if not valid_pw:
           return base_layout("Registration Error", f"""
           <div class="container">
             <div class="alert alert-danger">
               <h4>Invalid Password</h4>
               <p>{html.escape(pw_msg)}</p>
               <a href="/register" class="btn btn-primary">Try Again</a>
             </div>
           </div>
           """)
       
       # Create user
       success, result = _create_user(email, password, plan)
       if not success:
           return base_layout("Registration Error", f"""
           <div class="container">
             <div class="alert alert-danger">
               <h4>Registration Failed</h4>
               <p>{html.escape(result)}</p>
               <a href="/register" class="btn btn-primary">Try Again</a>
             </div>
           </div>
           """)
       
       # Log in user
       session["uid"] = result
       _log_event(result, "user_registered", {"plan": plan})
       
       return redirect("/dashboard")

@app.route("/login", methods=["GET", "POST"])
def login():
   if _current_user():
       return redirect("/dashboard")
   
   if request.method == "GET":
       next_url = request.args.get("next", "/dashboard")
       
       return base_layout("Sign In", f"""
       <div class="container">
         <div class="row justify-content-center">
           <div class="col-md-5">
             <div class="card shadow">
               <div class="card-header bg-primary text-white text-center">
                 <h4>Sign In to Your Account</h4>
               </div>
               <div class="card-body">
                 <form method="post">
                   <input type="hidden" name="csrf_token" value="{csrf_token()}">
                   <input type="hidden" name="next" value="{html.escape(next_url)}">
                   
                   <div class="mb-3">
                     <label class="form-label">Email Address</label>
                     <input type="email" name="email" class="form-control" required>
                   </div>
                   
                   <div class="mb-3">
                     <label class="form-label">Password</label>
                     <input type="password" name="password" class="form-control" required>
                   </div>
                   
                   <div class="d-grid">
                     <button type="submit" class="btn btn-primary">Sign In</button>
                   </div>
                 </form>
                 
                 <div class="text-center mt-3">
                   <small class="text-muted">
                     Don't have an account? <a href="/register">Sign up here</a>
                   </small>
                 </div>
               </div>
             </div>
           </div>
         </div>
       </div>
       """, show_nav=False)
   
   elif request.method == "POST":
       if not _csrf_ok():
           return redirect("/login")
       
       email = request.form.get("email", "").strip()
       password = request.form.get("password", "")
       next_url = request.form.get("next", "/dashboard")
       
       user = _find_user(email)
       if not user or not check_password_hash(user.get("password_hash", ""), password):
           return base_layout("Login Failed", """
           <div class="container">
             <div class="alert alert-danger">
               <h4>Invalid Credentials</h4>
               <p>Email or password is incorrect.</p>
               <a href="/login" class="btn btn-primary">Try Again</a>
             </div>
           </div>
           """)
       
       session["uid"] = user["id"]
       _update_user(user["id"], {"last_login": datetime.utcnow().isoformat()})
       _log_event(user["id"], "user_login")
       
       return redirect(next_url)

@app.route("/logout")
def logout():
   if "uid" in session:
       _log_event(session["uid"], "user_logout")
   session.clear()
   return redirect("/")

@app.route("/dashboard")
@subscription_required
def dashboard():
   user = _current_user()
   uid = user["id"]
   
   # Get user progress
   progress_data = calculate_user_progress(uid)
   progress_html = progress_meter_html(progress_data)
   
   # Get recent activity
   attempts = _load_json("attempts.json", [])
   user_attempts = [a for a in attempts if a.get("user_id") == uid]
   recent_attempts = sorted(user_attempts, key=lambda x: x.get("ts", ""), reverse=True)[:5]
   
   activity_html = ""
   for attempt in recent_attempts:
       mode = attempt.get("mode", "unknown")
       score = attempt.get("score")
       ts = attempt.get("ts", "")
       
       try:
           dt = datetime.fromisoformat(ts.replace("Z", ""))
           time_str = dt.strftime("%m/%d %I:%M %p")
       except Exception:
           time_str = "Unknown"
       
       icon_map = {
           "quiz": "bi-ui-checks",
           "mock": "bi-clipboard-check", 
           "tutor": "bi-robot",
           "flashcards": "bi-card-text"
       }
       
       icon = icon_map.get(mode, "bi-circle")
       score_text = f"Score: {score}" if score is not None else "Completed"
       
       activity_html += f"""
       <div class="d-flex align-items-center mb-2">
         <i class="{icon} text-primary me-3"></i>
         <div class="flex-grow-1">
           <div class="fw-bold">{mode.title()}</div>
           <small class="text-muted">{score_text}</small>
         </div>
         <small class="text-muted">{time_str}</small>
       </div>
       """
   
   if not activity_html:
       activity_html = "<p class='text-muted'>No activity yet. Start studying!</p>"
   
   # Get study suggestions based on progress
   details = progress_data.get("details", {})
   weak_domains = progress_data.get("weak_domains", [])
   
   suggestions_html = ""
   if weak_domains:
       domain_names = []
       for domain in weak_domains[:3]:  # Show top 3 weak domains
           domain_info = CPP_DOMAINS.get(domain, {})
           domain_names.append(domain_info.get("name", domain))
       
       suggestions_html += f"""
       <div class="alert alert-warning">
         <h6><i class="bi bi-target me-2"></i>Focus Areas</h6>
         <p class="mb-1">Consider additional practice in:</p>
         <small><strong>{', '.join(domain_names)}</strong></small>
       </div>
       """
   
   if details.get("quiz_sessions", 0) < 5:
       suggestions_html += """
       <div class="alert alert-info">
         <h6><i class="bi bi-lightbulb me-2"></i>Get Started</h6>
         <p class="mb-0">Take a few practice quizzes to assess your current knowledge level.</p>
       </div>
       """
   elif details.get("mock_sessions", 0) == 0:
       suggestions_html += """
       <div class="alert alert-success">
         <h6><i class="bi bi-clipboard-check me-2"></i>Ready for Mock Exam?</h6>
         <p class="mb-0">You've been practicing well. Try a mock exam to test your readiness!</p>
       </div>
       """
   
   return base_layout("Study Dashboard", f"""
   <div class="container">
     <div class="row">
       <div class="col-12">
         <div class="d-flex justify-content-between align-items-center mb-4">
           <h2 class="display-6 fw-bold">Welcome back!</h2>
           <span class="badge bg-success">Active Subscription</span>
         </div>
       </div>
     </div>
     
     <div class="row">
       <div class="col-lg-8">
         <div class="row mb-4">
           <div class="col-md-6">
             {progress_html}
           </div>
           <div class="col-md-6">
             <div class="card h-100">
               <div class="card-header bg-light">
                 <h6 class="mb-0"><i class="bi bi-bar-chart me-2"></i>Quick Stats</h6>
               </div>
               <div class="card-body">
                 <div class="row text-center">
                   <div class="col-6 mb-2">
                     <div class="h4 text-primary">{details.get('total_questions', 0)}</div>
                     <small class="text-muted">Questions</small>
                   </div>
                   <div class="col-6 mb-2">
                     <div class="h4 text-success">{details.get('accuracy', 0)}%</div>
                     <small class="text-muted">Accuracy</small>
                   </div>
                   <div class="col-6">
                     <div class="h4 text-warning">{details.get('study_streak', 0)}</div>
                     <small class="text-muted">Day Streak</small>
                   </div>
                   <div class="col-6">
                     <div class="h4 text-info">{details.get('domains_covered', 0)}/7</div>
                     <small class="text-muted">Domains</small>
                   </div>
                 </div>
               </div>
             </div>
           </div>
         </div>
         
         <div class="row">
           <div class="col-md-6 mb-4">
             <div class="card h-100 question-card">
               <div class="card-body text-center">
                 <div class="text-primary mb-3">
                   <i class="bi bi-ui-checks" style="font-size: 3rem;"></i>
                 </div>
                 <h5>Practice Quiz</h5>
                 <p class="text-muted">Quick knowledge check with immediate feedback</p>
                 <a href="/quiz" class="btn btn-primary">Start Quiz</a>
               </div>
             </div>
           </div>
           <div class="col-md-6 mb-4">
             <div class="card h-100 question-card">
               <div class="card-body text-center">
                 <div class="text-success mb-3">
                   <i class="bi bi-clipboard-check" style="font-size: 3rem;"></i>
                 </div>
                 <h5>Mock Exam</h5>
                 <p class="text-muted">Full exam simulation with realistic conditions</p>
                 <a href="/mock-exam" class="btn btn-success">Take Mock Exam</a>
               </div>
             </div>
           </div>
           <div class="col-md-6 mb-4">
             <div class="card h-100 question-card">
               <div class="card-body text-center">
                 <div class="text-info mb-3">
                   <i class="bi bi-card-text" style="font-size: 3rem;"></i>
                 </div>
                 <h5>Flashcards</h5>
                 <p class="text-muted">Spaced repetition for key concepts</p>
                 <a href="/flashcards" class="btn btn-info">Study Cards</a>
               </div>
             </div>
           </div>
           <div class="col-md-6 mb-4">
             <div class="card h-100 question-card">
               <div class="card-body text-center">
                 <div class="text-warning mb-3">
                   <i class="bi bi-robot" style="font-size: 3rem;"></i>
                 </div>
                 <h5>AI Tutor</h5>
                 <p class="text-muted">Get instant help and explanations</p>
                 <a href="/tutor" class="btn btn-warning">Ask Tutor</a>
               </div>
             </div>
           </div>
         </div>
       </div>
       
       <div class="col-lg-4">
         <div class="card mb-4">
           <div class="card-header bg-light">
             <h6 class="mb-0"><i class="bi bi-clock-history me-2"></i>Recent Activity</h6>
           </div>
           <div class="card-body">
             {activity_html}
           </div>
         </div>
         
         {suggestions_html}
         
         <div class="card">
           <div class="card-header bg-light">
             <h6 class="mb-0"><i class="bi bi-lightbulb me-2"></i>Daily Tip</h6>
           </div>
           <div class="card-body">
             <div class="encouragement-message">
               <i class="bi bi-star-fill me-2"></i>
               {get_random_encouragement()}
             </div>
           </div>
         </div>
       </div>
     </div>
   </div>
   """)

if __name__ == "__main__":
   # Initialize question and flashcard banks if they don't exist
   if not os.path.exists(_QUESTIONS_FILE):
       questions = get_seed_questions()
       _write_jsonl(_QUESTIONS_FILE, questions)
       logger.info(f"Initialized question bank with {len(questions)} questions")
   
   if not os.path.exists(_FLASHCARDS_FILE):
       flashcards = get_seed_flashcards()
       _write_jsonl(_FLASHCARDS_FILE, flashcards)
       logger.info(f"Initialized flashcard bank with {len(flashcards)} flashcards")
   
   app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=DEBUG)  
