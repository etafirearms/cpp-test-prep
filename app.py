#!/usr/bin/env python3
"""
CPP Test Prep Application - Production Ready Version
A secure, scalable Flask application for CPP exam preparation
"""

import os
import json
import random
import requests
import html
import uuid
import logging
import time
import hashlib
import re
import sqlite3
from datetime import datetime, timedelta
from contextlib import contextmanager
from functools import wraps
from typing import Optional, Dict, List, Any, Tuple

from flask import Flask, request, jsonify, session, redirect, url_for, render_template_string
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix

# Optional imports with graceful fallbacks
try:
    import stripe
    HAS_STRIPE = True
except ImportError:
    HAS_STRIPE = False
    stripe = None

try:
    from flask_wtf.csrf import CSRFProtect, generate_csrf
    HAS_CSRF = True
except ImportError:
    HAS_CSRF = False
    generate_csrf = lambda: ""

try:
    import fcntl
    HAS_FCNTL = True
except ImportError:
    HAS_FCNTL = False

# =============================================================================
# CONFIGURATION AND SETUP
# =============================================================================

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('app.log') if os.path.exists('/var/log') else logging.NullHandler()
    ]
)
logger = logging.getLogger(__name__)

# Flask app initialization
app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

# Security configuration
app.secret_key = os.environ.get("SECRET_KEY") or os.urandom(32)
app.config.update({
    'SESSION_COOKIE_HTTPONLY': True,
    'SESSION_COOKIE_SAMESITE': 'Lax',
    'SESSION_COOKIE_SECURE': True,  # Always secure in production
    'PERMANENT_SESSION_LIFETIME': timedelta(days=30),
    'MAX_CONTENT_LENGTH': 16 * 1024 * 1024,  # 16MB max request
})

# Initialize CSRF protection
if HAS_CSRF:
    csrf = CSRFProtect(app)
else:
    logger.warning("CSRF protection not available - install flask-wtf")

# Environment variables
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
OPENAI_CHAT_MODEL = os.environ.get("OPENAI_CHAT_MODEL", "gpt-4o-mini")
OPENAI_API_BASE = os.environ.get("OPENAI_API_BASE", "https://api.openai.com/v1")

# Stripe configuration
if HAS_STRIPE:
    stripe.api_key = os.environ.get('STRIPE_SECRET_KEY', '')
    STRIPE_WEBHOOK_SECRET = os.environ.get('STRIPE_WEBHOOK_SECRET', '')
    STRIPE_MONTHLY_PRICE_ID = os.environ.get('STRIPE_MONTHLY_PRICE_ID', '')
    STRIPE_SIXMONTH_PRICE_ID = os.environ.get('STRIPE_SIXMONTH_PRICE_ID', '')

# Application settings
APP_VERSION = os.environ.get("APP_VERSION", "2.0.0")
IS_STAGING = os.environ.get("RENDER_SERVICE_NAME", "").endswith("-staging")
DEBUG = os.environ.get("FLASK_DEBUG", "0") == "1"
DATA_DIR = os.environ.get("DATA_DIR", "data")

# Ensure data directory exists
os.makedirs(DATA_DIR, exist_ok=True)

# =============================================================================
# DATA MODELS AND STORAGE
# =============================================================================

class DataStore:
    """Centralized data storage management"""
    
    def __init__(self, data_dir: str):
        self.data_dir = data_dir
        self.database_path = os.path.join(data_dir, "app.db")
        self._init_database()
        
    def _init_database(self):
        """Initialize SQLite database with proper schema"""
        with self.get_db_connection() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    subscription TEXT DEFAULT 'inactive',
                    subscription_expires_at TEXT,
                    stripe_customer_id TEXT,
                    usage_data TEXT DEFAULT '{}',
                    quiz_history TEXT DEFAULT '[]',
                    created_at TEXT DEFAULT (datetime('now', 'utc')),
                    updated_at TEXT DEFAULT (datetime('now', 'utc'))
                );
                
                CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
                CREATE INDEX IF NOT EXISTS idx_users_subscription ON users(subscription);
                
                CREATE TABLE IF NOT EXISTS questions (
                    id TEXT PRIMARY KEY,
                    question TEXT NOT NULL,
                    options TEXT NOT NULL,
                    correct_answer TEXT NOT NULL,
                    explanation TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    difficulty TEXT DEFAULT 'medium',
                    created_at TEXT DEFAULT (datetime('now', 'utc'))
                );
                
                CREATE INDEX IF NOT EXISTS idx_questions_domain ON questions(domain);
                CREATE INDEX IF NOT EXISTS idx_questions_difficulty ON questions(difficulty);
                
                CREATE TABLE IF NOT EXISTS flashcards (
                    id TEXT PRIMARY KEY,
                    front TEXT NOT NULL,
                    back TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    tags TEXT DEFAULT '[]',
                    created_at TEXT DEFAULT (datetime('now', 'utc'))
                );
                
                CREATE INDEX IF NOT EXISTS idx_flashcards_domain ON flashcards(domain);
            """)
            conn.commit()
    
    @contextmanager
    def get_db_connection(self):
        """Get database connection with proper error handling"""
        conn = sqlite3.connect(self.database_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        except Exception as e:
            conn.rollback()
            logger.error(f"Database error: {e}")
            raise
        finally:
            conn.close()
    
    def find_user_by_email(self, email: str) -> Optional[Dict]:
        """Find user by email address"""
        if not email:
            return None
        
        with self.get_db_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM users WHERE email = ? LIMIT 1",
                (email.strip().lower(),)
            )
            row = cursor.fetchone()
            if row:
                user_data = dict(row)
                user_data['usage'] = json.loads(user_data.get('usage_data', '{}'))
                user_data['history'] = json.loads(user_data.get('quiz_history', '[]'))
                return user_data
        return None
    
    def create_user(self, name: str, email: str, password_hash: str) -> str:
        """Create new user and return user ID"""
        user_id = str(uuid.uuid4())
        with self.get_db_connection() as conn:
            conn.execute("""
                INSERT INTO users (id, name, email, password_hash, created_at, updated_at)
                VALUES (?, ?, ?, ?, datetime('now', 'utc'), datetime('now', 'utc'))
            """, (user_id, name, email.strip().lower(), password_hash))
            conn.commit()
        return user_id
    
    def update_user(self, user_id: str, updates: Dict[str, Any]):
        """Update user data"""
        if not updates:
            return
            
        set_clauses = []
        values = []
        
        for key, value in updates.items():
            if key == 'usage':
                set_clauses.append("usage_data = ?")
                values.append(json.dumps(value))
            elif key == 'history':
                set_clauses.append("quiz_history = ?")
                values.append(json.dumps(value))
            else:
                set_clauses.append(f"{key} = ?")
                values.append(value)
        
        set_clauses.append("updated_at = datetime('now', 'utc')")
        values.append(user_id)
        
        with self.get_db_connection() as conn:
            conn.execute(
                f"UPDATE users SET {', '.join(set_clauses)} WHERE id = ?",
                values
            )
            conn.commit()

# Initialize data store
data_store = DataStore(DATA_DIR)

# =============================================================================
# SECURITY AND RATE LIMITING
# =============================================================================

class RateLimiter:
    """In-memory rate limiter with cleanup"""
    
    def __init__(self):
        self._buckets = {}
        self._last_cleanup = time.time()
    
    def is_rate_limited(self, key: str, limit: int, window: int) -> bool:
        """Check if request is rate limited"""
        now = time.time()
        
        # Periodic cleanup
        if now - self._last_cleanup > 300:  # 5 minutes
            self._cleanup(now)
        
        # Get or create bucket
        if key not in self._buckets:
            self._buckets[key] = []
        
        bucket = self._buckets[key]
        
        # Remove old entries
        bucket[:] = [t for t in bucket if now - t < window]
        
        # Check limit
        if len(bucket) >= limit:
            return True
        
        # Add current request
        bucket.append(now)
        return False
    
    def _cleanup(self, current_time: float):
        """Clean up old rate limit data"""
        cutoff = current_time - 3600  # Keep 1 hour of data
        for key in list(self._buckets.keys()):
            self._buckets[key] = [t for t in self._buckets[key] if t > cutoff]
            if not self._buckets[key]:
                del self._buckets[key]
        self._last_cleanup = current_time

rate_limiter = RateLimiter()

def get_client_id() -> str:
    """Get unique client identifier for rate limiting"""
    email = session.get("email", "").strip().lower()
    ip = request.remote_addr or "unknown"
    return f"{email}|{ip}"

# =============================================================================
# AUTHENTICATION AND AUTHORIZATION
# =============================================================================

def login_required(f):
    """Decorator for routes requiring authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated_function

def validate_email(email: str) -> bool:
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

def validate_password(password: str) -> Tuple[bool, str]:
    """Validate password strength"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r'[A-Za-z]', password):
        return False, "Password must contain at least one letter"
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number"
    return True, ""

# =============================================================================
# USAGE MANAGEMENT
# =============================================================================

class UsageManager:
    """Manage user usage limits and tracking"""
    
    LIMITS = {
        'monthly': {'quizzes': -1, 'questions': -1, 'tutor_msgs': -1, 'flashcards': -1},
        'sixmonth': {'quizzes': -1, 'questions': -1, 'tutor_msgs': -1, 'flashcards': -1},
        'inactive': {'quizzes': 3, 'questions': 25, 'tutor_msgs': 5, 'flashcards': 10},
    }
    
    @classmethod
    def check_limit(cls, user: Dict, action_type: str) -> Tuple[bool, str]:
        """Check if user has exceeded usage limit"""
        if not user:
            return False, "Please log in to continue"
        
        subscription = user.get('subscription', 'inactive')
        
        # Check subscription expiry
        if subscription == 'sixmonth':
            expires_at = user.get('subscription_expires_at')
            if expires_at:
                try:
                    expires_dt = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
                    if expires_dt.replace(tzinfo=None) < datetime.utcnow():
                        # Subscription expired - update user
                        data_store.update_user(user['id'], {
                            'subscription': 'inactive',
                            'subscription_expires_at': None
                        })
                        subscription = 'inactive'
                except Exception:
                    logger.warning(f"Invalid subscription expiry date for user {user['id']}")
        
        # Get usage limits
        user_limits = cls.LIMITS.get(subscription, cls.LIMITS['inactive'])
        limit = user_limits.get(action_type, 0)
        
        if limit == -1:  # Unlimited
            return True, ""
        
        # Check current month usage
        today = datetime.utcnow()
        month_key = today.strftime('%Y-%m')
        usage = user.get('usage', {})
        monthly_usage = usage.get('monthly', {}).get(month_key, {})
        used = monthly_usage.get(action_type, 0)
        
        if used >= limit:
            return False, f"Monthly {action_type} limit reached ({used}/{limit}). Upgrade for unlimited access!"
        
        return True, ""
    
    @classmethod
    def increment_usage(cls, user_id: str, action_type: str, count: int = 1):
        """Increment usage counter for user"""
        user = data_store.find_user_by_email(session.get('email', ''))
        if not user:
            return
        
        today = datetime.utcnow()
        month_key = today.strftime('%Y-%m')
        
        usage = user.get('usage', {})
        monthly = usage.setdefault('monthly', {})
        month_usage = monthly.setdefault(month_key, {})
        month_usage[action_type] = month_usage.get(action_type, 0) + count
        usage['last_active'] = today.isoformat() + 'Z'
        
        data_store.update_user(user_id, {'usage': usage})

# =============================================================================
# CPP CONTENT AND QUESTIONS
# =============================================================================

DOMAINS = {
    "security-principles": "Security Principles & Practices",
    "business-principles": "Business Principles & Practices", 
    "investigations": "Investigations",
    "personnel-security": "Personnel Security",
    "physical-security": "Physical Security",
    "information-security": "Information Security",
    "crisis-management": "Crisis Management",
}

BASE_QUESTIONS = [
    {
        "question": "What is the primary purpose of a security risk assessment?",
        "options": {"A": "Identify all threats", "B": "Determine cost-effective mitigation", "C": "Eliminate all risks", "D": "Satisfy compliance"},
        "correct": "B",
        "explanation": "Risk assessments balance risk, cost, and operational impact to choose practical controls.",
        "domain": "security-principles",
        "difficulty": "medium"
    },
    {
        "question": "In CPTED, natural surveillance primarily accomplishes what?",
        "options": {"A": "Reduces guard costs", "B": "Increases observation likelihood", "C": "Eliminates cameras", "D": "Provides legal protection"},
        "correct": "B",
        "explanation": "Design that increases visibility makes misconduct more likely to be observed and deterred.",
        "domain": "physical-security",
        "difficulty": "medium"
    },
    {
        "question": "Which concept applies multiple layers so if one fails others still protect?",
        "options": {"A": "Security by Obscurity", "B": "Defense in Depth", "C": "Zero Trust", "D": "Least Privilege"},
        "correct": "B",
        "explanation": "Layered controls maintain protection despite single-point failures.",
        "domain": "security-principles",
        "difficulty": "medium"
    },
    {
        "question": "In incident response, what is usually the FIRST priority?",
        "options": {"A": "Notify law enforcement", "B": "Contain the incident", "C": "Eradicate malware", "D": "Lessons learned"},
        "correct": "B",
        "explanation": "Containment stops the incident from spreading before eradication and recovery.",
        "domain": "information-security",
        "difficulty": "medium"
    },
    {
        "question": "Background investigations primarily support which objective?",
        "options": {"A": "Regulatory compliance only", "B": "Marketing outcomes", "C": "Reduce insider risk", "D": "Disaster response"},
        "correct": "C",
        "explanation": "They help verify suitability and reduce personnel security risks.",
        "domain": "personnel-security",
        "difficulty": "medium"
    },
    {
        "question": "What is the primary goal of business continuity planning?",
        "options": {"A": "Prevent all disasters", "B": "Maintain critical operations during disruption", "C": "Reduce insurance costs", "D": "Only satisfy regulators"},
        "correct": "B",
        "explanation": "BCP ensures critical functions continue during and after a disruption.",
        "domain": "crisis-management",
        "difficulty": "medium"
    },
    {
        "question": "What establishes legal admissibility of evidence in investigations?",
        "options": {"A": "Chain of custody", "B": "Digital timestamps", "C": "Witness statements only", "D": "Management approval"},
        "correct": "A",
        "explanation": "Chain of custody proves integrity of evidence handling.",
        "domain": "investigations",
        "difficulty": "medium"
    },
    {
        "question": "Best approach to security budgeting?",
        "options": {"A": "Historical spend", "B": "Risk-based allocation", "C": "Industry averages", "D": "Spend remaining funds"},
        "correct": "B",
        "explanation": "Direct funds to the highest-impact, risk-reducing controls.",
        "domain": "business-principles",
        "difficulty": "medium"
    }
]

class QuestionManager:
    """Manage quiz questions and generation"""
    
    @staticmethod
    def get_questions_by_domain(domain: Optional[str] = None) -> List[Dict]:
        """Get questions filtered by domain"""
        questions = BASE_QUESTIONS.copy()
        
        if domain and domain != "random":
            questions = [q for q in questions if q.get("domain") == domain]
        
        return questions
    
    @staticmethod
    def build_quiz(num_questions: int, domain: Optional[str] = None) -> Dict:
        """Build a quiz with specified number of questions"""
        questions = QuestionManager.get_questions_by_domain(domain)
        
        if not questions:
            questions = BASE_QUESTIONS.copy()
        
        # Shuffle and select questions
        random.shuffle(questions)
        selected_questions = questions[:num_questions]
        
        # If we don't have enough questions, repeat some
        while len(selected_questions) < num_questions:
            remaining_needed = num_questions - len(selected_questions)
            additional = questions[:remaining_needed]
            selected_questions.extend(additional)
        
        return {
            "title": f"Practice Quiz ({num_questions} questions)",
            "domain": domain or "random",
            "questions": selected_questions[:num_questions]
        }

# =============================================================================
# AI INTEGRATION
# =============================================================================

class AIService:
    """Handle AI-related functionality"""
    
    @staticmethod
    def chat_with_tutor(messages: List[str]) -> str:
        """Chat with AI tutor"""
        if not OPENAI_API_KEY:
            return "AI tutor is not available. Please configure OpenAI API key."
        
        try:
            payload = {
                "model": OPENAI_CHAT_MODEL,
                "messages": [
                    {"role": "system", "content": "You are a helpful CPP exam tutor. Provide clear, concise explanations with practical examples. Format responses with bullet points and short paragraphs for readability."}
                ] + [{"role": "user", "content": msg} for msg in messages[-5:]],  # Limit context
                "temperature": 0.7,
                "max_tokens": 500,
            }
            
            response = requests.post(
                f"{OPENAI_API_BASE}/chat/completions",
                headers={
                    "Authorization": f"Bearer {OPENAI_API_KEY}",
                    "Content-Type": "application/json"
                },
                json=payload,
                timeout=30,
            )
            
            if response.status_code == 200:
                data = response.json()
                return data["choices"][0]["message"]["content"]
            else:
                logger.error(f"OpenAI API error {response.status_code}: {response.text[:200]}")
                return f"AI service temporarily unavailable (Error {response.status_code}). Please try again."
                
        except requests.exceptions.Timeout:
            return "AI service timeout. Please try again."
        except Exception as e:
            logger.error(f"AI service error: {e}")
            return "AI service error. Please try again later."

# =============================================================================
# SECURITY MIDDLEWARE
# =============================================================================

@app.after_request
def add_security_headers(response):
    """Add security headers to all responses"""
    response.headers.update({
        'X-Frame-Options': 'DENY',
        'X-Content-Type-Options': 'nosniff',
        'X-XSS-Protection': '1; mode=block',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Content-Security-Policy': (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://js.stripe.com; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "img-src 'self' data: https:; "
            "font-src 'self' https://cdn.jsdelivr.net; "
            "connect-src 'self' https://api.stripe.com; "
            "frame-src https://js.stripe.com; "
            "frame-ancestors 'none'"
        )
    })
    return response

# =============================================================================
# HTML TEMPLATES
# =============================================================================

def get_base_template() -> str:
    """Get base HTML template"""
    return '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="csrf-token" content="{{ csrf_token }}">
    <title>{{ title }} - CPP Test Prep</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css" rel="stylesheet">
    <style>
        :root {
            --primary: #2563eb;
            --success: #059669;
            --warning: #d97706;
            --danger: #dc2626;
            --light-bg: #f8fafc;
        }
        body {
            background: linear-gradient(135deg, var(--light-bg) 0%, #e2e8f0 100%);
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
        }
        .card {
            border: none;
            border-radius: 16px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.08);
            transition: all 0.3s ease;
        }
        .card:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 24px rgba(0,0,0,0.12);
        }
        .btn {
            border-radius: 12px;
            font-weight: 600;
            padding: 0.75rem 1.5rem;
            transition: all 0.2s ease;
        }
        .btn:hover {
            transform: translateY(-1px);
        }
        .navbar-brand {
            font-weight: 700;
            font-size: 1.5rem;
        }
        .bg-gradient-primary {
            background: linear-gradient(135deg, var(--primary), #7c3aed) !important;
        }
        .alert {
            border-radius: 12px;
            border: none;
            padding: 1.25rem;
        }
        .form-control, .form-select {
            border-radius: 10px;
            border: 2px solid #e5e7eb;
            padding: 0.75rem 1rem;
        }
        .form-control:focus, .form-select:focus {
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.1);
        }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-light bg-gradient-primary sticky-top shadow-sm">
        <div class="container">
            <a class="navbar-brand text-white" href="/">
                <i class="bi bi-shield-check text-warning"></i> CPP Test Prep
            </a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav me-auto">
                    {% if is_logged_in %}
                    <li class="nav-item"><a class="nav-link text-white-50" href="/study">AI Tutor</a></li>
                    <li class="nav-item"><a class="nav-link text-white-50" href="/quiz">Quiz</a></li>
                    <li class="nav-item"><a class="nav-link text-white-50" href="/flashcards">Flashcards</a></li>
                    <li class="nav-item"><a class="nav-link text-white-50" href="/progress">Progress</a></li>
                    {% endif %}
                </ul>
                <ul class="navbar-nav">
                    {% if is_logged_in %}
                    <li class="nav-item dropdown">
                        <a class="nav-link dropdown-toggle text-white" href="#" data-bs-toggle="dropdown">
                            {{ user_name }}
                        </a>
                        <ul class="dropdown-menu">
                            <li><a class="dropdown-item" href="/settings">Settings</a></li>
                            <li><a class="dropdown-item" href="/billing">Billing</a></li>
                            <li><hr class="dropdown-divider"></li>
                            <li>
                                <form method="POST" action="/logout" class="d-inline">
                                    <input type="hidden" name="csrf_token" value="{{ csrf_token }}"/>
                                    <button type="submit" class="dropdown-item">Logout</button>
                                </form>
                            </li>
                        </ul>
                    </li>
                    {% else %}
                    <li class="nav-item"><a class="nav-link text-white-50" href="/login">Login</a></li>
                    <li class="nav-item"><a class="nav-link btn btn-outline-light ms-2" href="/signup">Sign Up</a></li>
                    {% endif %}
                </ul>
            </div>
        </div>
    </nav>
    
    {% if is_staging %}
    <div class="alert alert-warning alert-dismissible fade show m-0" role="alert">
        <div class="container text-center">
            <strong>STAGING ENVIRONMENT</strong> - For testing purposes only
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
    </div>
    {% endif %}
    
    <main class="py-4">
        {{ content }}
    </main>
    
    <footer class="bg-light py-4 mt-5 border-top">
        <div class="container">
            <div class="row">
                <div class="col-md-8">
                    <small class="text-muted">
                        <strong>Notice:</strong> Independent platform not affiliated with ASIS International. 
                        CPP® is a registered trademark of ASIS International.
                    </small>
                </div>
                <div class="col-md-4 text-end">
                    <small class="text-muted">Version {{ version }}</small>
                </div>
            </div>
        </div>
    </footer>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>'''

def render_page(title: str, content: str, **kwargs) -> str:
    """Render page with base template"""
    template_vars = {
        'title': title,
        'content': content,
        'csrf_token': generate_csrf(),
        'is_logged_in': 'user_id' in session,
        'user_name': session.get('name', ''),
        'is_staging': IS_STAGING,
        'version': APP_VERSION,
        **kwargs
    }
    
    return render_template_string(get_base_template(), **template_vars)

# =============================================================================
# ROUTE HANDLERS
# =============================================================================

@app.route('/healthz')
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'version': APP_VERSION
    })

@app.route('/')
def home():
    """Home page"""
    if 'user_id' not in session:
        content = '''
        <div class="container">
            <div class="row justify-content-center text-center">
                <div class="col-lg-10">
                    <div class="mb-5">
                        <i class="bi bi-mortarboard text-primary display-1 mb-4"></i>
                        <h1 class="display-3 fw-bold mb-4">Master the CPP Exam</h1>
                        <p class="lead fs-4 text-muted mb-5">
                            AI-powered learning platform for CPP certification success
                        </p>
                    </div>
                    
                    <div class="row mb-5 g-4">
                        <div class="col-md-4">
                            <div class="card border-0 h-100">
                                <div class="card-body text-center p-4">
                                    <i class="bi bi-robot display-4 text-primary mb-3"></i>
                                    <h4 class="fw-bold">AI Study Tutor</h4>
                                    <p class="text-muted">Get instant explanations and personalized guidance</p>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="card border-0 h-100">
                                <div class="card-body text-center p-4">
                                    <i class="bi bi-card-text display-4 text-success mb-3"></i>
                                    <h4 class="fw-bold">Practice Quizzes</h4>
                                    <p class="text-muted">Test knowledge across all CPP domains</p>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="card border-0 h-100">
                                <div class="card-body text-center p-4">
                                    <i class="bi bi-graph-up display-4 text-warning mb-3"></i>
                                    <h4 class="fw-bold">Progress Tracking</h4>
                                    <p class="text-muted">Monitor your improvement over time</p>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="mb-5">
                        <a href="/signup" class="btn btn-primary btn-lg me-3 px-5 py-3">
                            <i class="bi bi-rocket-takeoff me-2"></i>Get Started
                        </a>
                        <a href="/login" class="btn btn-outline-primary btn-lg px-5 py-3">
                            <i class="bi bi-box-arrow-in-right me-2"></i>Sign In
                        </a>
                    </div>
                </div>
            </div>
        </div>
        '''
        return render_page("CPP Test Prep - Master Your Certification", content)
    
    # Logged in user dashboard
    user_name = session.get('name', '').split()[0] or 'there'
    content = f'''
    <div class="container">
        <div class="row">
            <div class="col-lg-8">
                <div class="card mb-4">
                    <div class="card-body">
                        <h1 class="h3 mb-3">Welcome back, {html.escape(user_name)}!</h1>
                        <p class="text-muted">Ready to continue your CPP preparation?</p>
                    </div>
                </div>
                
                <div class="row g-3">
                    <div class="col-md-6">
                        <a href="/study" class="text-decoration-none">
                            <div class="card h-100">
                                <div class="card-body text-center">
                                    <i class="bi bi-robot text-primary display-6 mb-3"></i>
                                    <h5>AI Study Tutor</h5>
                                    <p class="text-muted small">Get instant help</p>
                                </div>
                            </div>
                        </a>
                    </div>
                    <div class="col-md-6">
                        <a href="/quiz" class="text-decoration-none">
                            <div class="card h-100">
                                <div class="card-body text-center">
                                    <i class="bi bi-card-text text-success display-6 mb-3"></i>
                                    <h5>Practice Quiz</h5>
                                    <p class="text-muted small">Test your knowledge</p>
                                </div>
                            </div>
                        </a>
                    </div>
                </div>
            </div>
        </div>
    </div>
    '''
    return render_page("Dashboard", content)

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    """Login page and handler"""
    if 'user_id' in session:
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        # Rate limiting
        if rate_limiter.is_rate_limited(get_client_id(), 5, 300):
            return redirect(url_for('login_page'))
        
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        
        if not email or not password:
            return redirect(url_for('login_page'))
        
        user = data_store.find_user_by_email(email)
        if user and check_password_hash(user.get('password_hash', ''), password):
            session.clear()
            session.permanent = True
            session['user_id'] = user['id']
            session['email'] = user['email']
            session['name'] = user.get('name', '')
            logger.info(f"User logged in: {email}")
            return redirect(url_for('home'))
        
        logger.warning(f"Failed login attempt: {email}")
        return redirect(url_for('login_page'))
    
    # GET request - show login form
    content = '''
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-md-6 col-lg-4">
                <div class="card shadow-lg">
                    <div class="card-body p-4">
                        <div class="text-center mb-4">
                            <i class="bi bi-shield-check text-primary display-4 mb-3"></i>
                            <h2 class="card-title fw-bold text-primary">Welcome Back</h2>
                        </div>
                        <form method="POST">
                            <input type="hidden" name="csrf_token" value="{{ csrf_token }}"/>
                            <div class="mb-3">
                                <label class="form-label fw-semibold">Email</label>
                                <input type="email" class="form-control" name="email" required>
                            </div>
                            <div class="mb-4">
                                <label class="form-label fw-semibold">Password</label>
                                <input type="password" class="form-control" name="password" required>
                            </div>
                            <button type="submit" class="btn btn-primary w-100">Sign In</button>
                        </form>
                        <div class="text-center mt-3">
                            <p class="text-muted">Don't have an account?</p>
                            <a href="/signup" class="btn btn-outline-primary">Create Account</a>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    '''
    return render_page("Sign In", content)

@app.route('/signup', methods=['GET', 'POST'])
def signup_page():
    """Signup page and handler"""
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        
        # Validation
        if not name or not email or not password:
            return redirect(url_for('signup_page'))
        
        if not validate_email(email):
            return redirect(url_for('signup_page'))
        
        is_valid, error_msg = validate_password(password)
        if not is_valid:
            return redirect(url_for('signup_page'))
        
        if data_store.find_user_by_email(email):
            return redirect(url_for('signup_page'))
        
        # Create user
        try:
            password_hash = generate_password_hash(password)
            user_id = data_store.create_user(name, email, password_hash)
            
            # Log in user
            session.clear()
            session.permanent = True
            session['user_id'] = user_id
            session['email'] = email
            session['name'] = name
            
            logger.info(f"New user created: {email}")
            return redirect(url_for('home'))
            
        except Exception as e:
            logger.error(f"User creation failed: {e}")
            return redirect(url_for('signup_page'))
    
    # GET request - show signup form
    content = '''
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-md-8 col-lg-6">
                <div class="card shadow-lg">
                    <div class="card-body p-4">
                        <div class="text-center mb-4">
                            <i class="bi bi-mortarboard text-primary display-4 mb-3"></i>
                            <h2 class="card-title fw-bold text-primary">Create Account</h2>
                        </div>
                        <form method="POST">
                            <input type="hidden" name="csrf_token" value="{{ csrf_token }}"/>
                            <div class="row">
                                <div class="col-md-12 mb-3">
                                    <label class="form-label fw-semibold">Full Name</label>
                                    <input type="text" class="form-control" name="name" required>
                                </div>
                                <div class="col-md-12 mb-3">
                                    <label class="form-label fw-semibold">Email</label>
                                    <input type="email" class="form-control" name="email" required>
                                </div>
                                <div class="col-md-12 mb-4">
                                    <label class="form-label fw-semibold">Password</label>
                                    <input type="password" class="form-control" name="password" required minlength="8">
                                    <div class="form-text">At least 8 characters with letters and numbers</div>
                                </div>
                            </div>
                            <button type="submit" class="btn btn-primary w-100 btn-lg">
                                <i class="bi bi-rocket-takeoff me-2"></i>Create Account
                            </button>
                        </form>
                        <div class="text-center mt-3">
                            <p class="text-muted">Already have an account?</p>
                            <a href="/login" class="btn btn-outline-primary">Sign In</a>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    '''
    return render_page("Create Account", content)

@app.route('/logout', methods=['POST'])
def logout():
    """Logout handler"""
    session.clear()
    return redirect(url_for('login_page'))

@app.route('/study')
@login_required
def study_page():
    """AI tutor study page"""
    user = data_store.find_user_by_email(session.get('email', ''))
    can_use, error_msg = UsageManager.check_limit(user, 'tutor_msgs')
    
    content = f'''
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-lg-8">
                <div class="card">
                    <div class="card-header bg-primary text-white">
                        <h3 class="mb-0"><i class="bi bi-robot me-2"></i>AI Study Tutor</h3>
                    </div>
                    <div class="card-body">
                        {'<div class="alert alert-warning">' + error_msg + '</div>' if not can_use else ''}
                        <div id="chat-history" class="border rounded p-3 mb-3" style="height: 400px; overflow-y: auto; background: #f8f9fa;">
                            <p class="text-muted text-center">Ask me anything about CPP concepts!</p>
                        </div>
                        <form id="chat-form" {'style="display:none;"' if not can_use else ''}>
                            <div class="input-group">
                                <input type="text" class="form-control" id="user-message" 
                                       placeholder="Ask about CPP topics..." required>
                                <button type="submit" class="btn btn-primary">Send</button>
                            </div>
                        </form>
                        {'<div class="text-center mt-3"><a href="/billing" class="btn btn-success">Upgrade for Unlimited Access</a></div>' if not can_use else ''}
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <script>
    document.getElementById('chat-form')?.addEventListener('submit', async function(e) {{
        e.preventDefault();
        const messageInput = document.getElementById('user-message');
        const message = messageInput.value.trim();
        if (!message) return;
        
        const chatHistory = document.getElementById('chat-history');
        chatHistory.innerHTML += '<div class="mb-2"><strong>You:</strong> ' + message + '</div>';
        messageInput.value = '';
        chatHistory.scrollTop = chatHistory.scrollHeight;
        
        try {{
            const response = await fetch('/api/chat', {{
                method: 'POST',
                headers: {{'Content-Type': 'application/json', 'X-CSRFToken': '{{ csrf_token }}'}},
                body: JSON.stringify({{message: message}})
            }});
            const data = await response.json();
            
            chatHistory.innerHTML += '<div class="mb-2"><strong>AI Tutor:</strong> ' + data.response + '</div>';
            chatHistory.scrollTop = chatHistory.scrollHeight;
        }} catch (error) {{
            chatHistory.innerHTML += '<div class="mb-2 text-danger"><strong>Error:</strong> Failed to get response</div>';
        }}
    }});
    </script>
    '''
    return render_page("AI Study Tutor", content)

@app.route('/api/chat', methods=['POST'])
@login_required
def chat_api():
    """Chat API endpoint"""
    user = data_store.find_user_by_email(session.get('email', ''))
    can_use, error_msg = UsageManager.check_limit(user, 'tutor_msgs')
    
    if not can_use:
        return jsonify({'error': error_msg}), 403
    
    data = request.get_json()
    if not data or not data.get('message'):
        return jsonify({'error': 'Message required'}), 400
    
    message = data['message'].strip()
    if not message:
        return jsonify({'error': 'Message cannot be empty'}), 400
    
    # Get AI response
    response = AIService.chat_with_tutor([message])
    
    # Increment usage
    UsageManager.increment_usage(session['user_id'], 'tutor_msgs', 1)
    
    return jsonify({'response': response})

@app.route('/quiz')
@login_required
def quiz_page():
    """Quiz selection page"""
    content = f'''
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-lg-8">
                <div class="card">
                    <div class="card-header bg-success text-white">
                        <h3 class="mb-0"><i class="bi bi-card-text me-2"></i>Practice Quiz</h3>
                    </div>
                    <div class="card-body">
                        <form action="/quiz/start" method="POST">
                            <input type="hidden" name="csrf_token" value="{{ csrf_token }}"/>
                            <div class="mb-3">
                                <label class="form-label fw-semibold">Select Domain</label>
                                <select class="form-select" name="domain">
                                    <option value="random">All Domains (Mixed)</option>
                                    {chr(10).join(f'<option value="{key}">{name}</option>' for key, name in DOMAINS.items())}
                                </select>
                            </div>
                            <div class="mb-4">
                                <label class="form-label fw-semibold">Number of Questions</label>
                                <select class="form-select" name="count">
                                    <option value="5">5 Questions</option>
                                    <option value="10" selected>10 Questions</option>
                                    <option value="15">15 Questions</option>
                                    <option value="20">20 Questions</option>
                                </select>
                            </div>
                            <button type="submit" class="btn btn-success btn-lg w-100">
                                <i class="bi bi-play-circle me-2"></i>Start Quiz
                            </button>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>
    '''
    return render_page("Practice Quiz", content)

@app.route('/quiz/start', methods=['POST'])
@login_required
def start_quiz():
    """Start a new quiz"""
    user = data_store.find_user_by_email(session.get('email', ''))
    can_use, error_msg = UsageManager.check_limit(user, 'questions')
    
    if not can_use:
        return redirect(url_for('quiz_page'))
    
    domain = request.form.get('domain', 'random')
    count = int(request.form.get('count', 10))
    
    if count > 25:
        count = 25
    
    quiz_data = QuestionManager.build_quiz(count, domain if domain != 'random' else None)
    
    # Store quiz in session
    session['current_quiz'] = quiz_data
    session['quiz_answers'] = {}
    
    return redirect(url_for('take_quiz'))

@app.route('/quiz/take')
@login_required
def take_quiz():
    """Take quiz interface"""
    quiz_data = session.get('current_quiz')
    if not quiz_data:
        return redirect(url_for('quiz_page'))
    
    questions_html = []
    for i, q in enumerate(quiz_data['questions']):
        options_html = []
        for letter, text in q['options'].items():
            options_html.append(f'''
                <div class="form-check">
                    <input class="form-check-input" type="radio" name="q{i}" value="{letter}" id="q{i}{letter}">
                    <label class="form-check-label" for="q{i}{letter}">
                        <strong>{letter}.</strong> {html.escape(text)}
                    </label>
                </div>
            ''')
        
        questions_html.append(f'''
            <div class="card mb-4">
                <div class="card-body">
                    <h5 class="card-title">Question {i+1}</h5>
                    <p class="card-text">{html.escape(q['question'])}</p>
                    {''.join(options_html)}
                </div>
            </div>
        ''')
    
    content = f'''
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-lg-10">
                <div class="card mb-4">
                    <div class="card-header bg-info text-white">
                        <h3 class="mb-0">{html.escape(quiz_data['title'])}</h3>
                        <small>Domain: {DOMAINS.get(quiz_data['domain'], 'All Domains')}</small>
                    </div>
                </div>
                
                <form action="/quiz/submit" method="POST">
                    <input type="hidden" name="csrf_token" value="{{ csrf_token }}"/>
                    {''.join(questions_html)}
                    
                    <div class="text-center">
                        <button type="submit" class="btn btn-primary btn-lg">
                            <i class="bi bi-check-circle me-2"></i>Submit Quiz
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </div>
    '''
    return render_page("Take Quiz", content)

@app.route('/quiz/submit', methods=['POST'])
@login_required
def submit_quiz():
    """Submit quiz and show results"""
    quiz_data = session.get('current_quiz')
    if not quiz_data:
        return redirect(url_for('quiz_page'))
    
    # Collect answers
    user_answers = {}
    for i in range(len(quiz_data['questions'])):
        answer = request.form.get(f'q{i}')
        if answer:
            user_answers[i] = answer
    
    # Calculate score
    correct = 0
    total = len(quiz_data['questions'])
    results = []
    
    for i, question in enumerate(quiz_data['questions']):
        user_answer = user_answers.get(i)
        correct_answer = question['correct']
        is_correct = user_answer == correct_answer
        
        if is_correct:
            correct += 1
        
        results.append({
            'question': question['question'],
            'user_answer': user_answer,
            'correct_answer': correct_answer,
            'is_correct': is_correct,
            'explanation': question.get('explanation', '')
        })
    
    score = round((correct / total) * 100, 1) if total > 0 else 0
    
    # Save to user history
    history_entry = {
        'date': datetime.utcnow().isoformat() + 'Z',
        'score': score,
        'correct': correct,
        'total': total,
        'domain': quiz_data['domain']
    }
    
    user = data_store.find_user_by_email(session.get('email', ''))
    if user:
        history = user.get('history', [])
        history.append(history_entry)
        if len(history) > 100:
            history = history[-100:]  # Keep last 100 attempts
        data_store.update_user(user['id'], {'history': history})
    
    # Increment usage
    UsageManager.increment_usage(session['user_id'], 'questions', total)
    
    # Clear quiz from session
    session.pop('current_quiz', None)
    session.pop('quiz_answers', None)
    
    # Show results
    score_class = 'success' if score >= 80 else 'warning' if score >= 60 else 'danger'
    
    results_html = []
    for i, result in enumerate(results):
        status_icon = 'check-circle-fill text-success' if result['is_correct'] else 'x-circle-fill text-danger'
        results_html.append(f'''
            <div class="card mb-3">
                <div class="card-body">
                    <div class="d-flex align-items-start">
                        <i class="bi bi-{status_icon} me-3 mt-1"></i>
                        <div class="flex-grow-1">
                            <h6>Question {i+1}</h6>
                            <p class="mb-2">{html.escape(result['question'])}</p>
                            <p class="mb-1">
                                <strong>Your answer:</strong> {result['user_answer'] or 'Not answered'} 
                                {'✓' if result['is_correct'] else '✗'}
                            </p>
                            <p class="mb-2"><strong>Correct answer:</strong> {result['correct_answer']}</p>
                            {f'<p class="text-muted small">{html.escape(result["explanation"])}</p>' if result['explanation'] else ''}
                        </div>
                    </div>
                </div>
            </div>
        ''')
    
    content = f'''
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-lg-10">
                <div class="card mb-4">
                    <div class="card-body text-center">
                        <h2 class="text-{score_class} mb-3">Quiz Complete!</h2>
                        <div class="row justify-content-center">
                            <div class="col-md-6">
                                <div class="alert alert-{score_class} border-0">
                                    <h3 class="mb-1">{score}%</h3>
                                    <p class="mb-0">{correct} out of {total} correct</p>
                                </div>
                            </div>
                        </div>
                        <a href="/quiz" class="btn btn-primary me-2">Take Another Quiz</a>
                        <a href="/progress" class="btn btn-outline-primary">View Progress</a>
                    </div>
                </div>
                
                <h4 class="mb-3">Review Your Answers</h4>
                {''.join(results_html)}
            </div>
        </div>
    </div>
    '''
    return render_page("Quiz Results", content)

@app.route('/progress')
@login_required
def progress_page():
    """Progress tracking page"""
    user = data_store.find_user_by_email(session.get('email', ''))
    history = user.get('history', []) if user else []
    
    if not history:
        content = '''
        <div class="container">
            <div class="row justify-content-center">
                <div class="col-lg-8">
                    <div class="card text-center">
                        <div class="card-body p-5">
                            <i class="bi bi-graph-up text-muted display-1 mb-4"></i>
                            <h2 class="text-muted mb-3">No Progress Data Yet</h2>
                            <p class="text-muted mb-4">Take your first quiz to start tracking progress</p>
                            <a href="/quiz" class="btn btn-primary">Start First Quiz</a>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        '''
        return render_page("Progress Tracking", content)
    
    # Calculate statistics
    recent_scores = [h.get('score', 0) for h in history[-10:]]
    avg_score = round(sum(recent_scores) / len(recent_scores), 1) if recent_scores else 0
    best_score = max(h.get('score', 0) for h in history) if history else 0
    total_questions = sum(h.get('total', 0) for h in history)
    
    # History table
    history_rows = []
    for entry in reversed(history[-20:]):  # Last 20 attempts
        date_str = entry.get('date', '')
        if date_str:
            try:
                date_obj = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
                date_str = date_obj.strftime('%m/%d %H:%M')
            except:
                date_str = 'Unknown'
        
        score = entry.get('score', 0)
        score_class = 'text-success' if score >= 80 else 'text-warning' if score >= 60 else 'text-danger'
        domain_name = DOMAINS.get(entry.get('domain', ''), 'Mixed')
        
        history_rows.append(f'''
            <tr>
                <td>{date_str}</td>
                <td class="{score_class} fw-bold">{score}%</td>
                <td>{entry.get('correct', 0)}/{entry.get('total', 0)}</td>
                <td>{domain_name}</td>
            </tr>
        ''')
    
    content = f'''
    <div class="container">
        <div class="row">
            <div class="col-lg-12">
                <div class="card">
                    <div class="card-header bg-info text-white">
                        <h3 class="mb-0"><i class="bi bi-graph-up me-2"></i>Learning Progress</h3>
                    </div>
                    <div class="card-body">
                        <div class="row g-4 mb-4">
                            <div class="col-md-3">
                                <div class="text-center p-3 bg-primary bg-opacity-10 rounded-3">
                                    <h3 class="text-primary mb-1">{avg_score}%</h3>
                                    <small class="text-muted">Average Score</small>
                                </div>
                            </div>
                            <div class="col-md-3">
                                <div class="text-center p-3 bg-success bg-opacity-10 rounded-3">
                                    <h3 class="text-success mb-1">{best_score}%</h3>
                                    <small class="text-muted">Best Score</small>
                                </div>
                            </div>
                            <div class="col-md-3">
                                <div class="text-center p-3 bg-info bg-opacity-10 rounded-3">
                                    <h3 class="text-info mb-1">{len(history)}</h3>
                                    <small class="text-muted">Quiz Attempts</small>
                                </div>
                            </div>
                            <div class="col-md-3">
                                <div class="text-center p-3 bg-warning bg-opacity-10 rounded-3">
                                    <h3 class="text-warning mb-1">{total_questions}</h3>
                                    <small class="text-muted">Questions Answered</small>
                                </div>
                            </div>
                        </div>
                        
                        <h5 class="mb-3">Recent Quiz History</h5>
                        <div class="table-responsive">
                            <table class="table table-hover">
                                <thead class="table-light">
                                    <tr>
                                        <th>Date</th>
                                        <th>Score</th>
                                        <th>Questions</th>
                                        <th>Domain</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {''.join(history_rows) if history_rows else '<tr><td colspan="4" class="text-center text-muted">No quiz history yet</td></tr>'}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    '''
    return render_page("Progress Tracking", content)

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings_page():
    """User settings page"""
    user = data_store.find_user_by_email(session.get('email', ''))
    if not user:
        return redirect(url_for('login_page'))
    
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        password = request.form.get('password', '').strip()
        
        updates = {}
        if name and name != user.get('name'):
            updates['name'] = name
            session['name'] = name
        
        if password:
            is_valid, error_msg = validate_password(password)
            if is_valid:
                updates['password_hash'] = generate_password_hash(password)
        
        if updates:
            data_store.update_user(user['id'], updates)
        
        return redirect(url_for('settings_page'))
    
    # GET request - show settings form
    content = f'''
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-lg-6">
                <div class="card">
                    <div class="card-header bg-secondary text-white">
                        <h3 class="mb-0"><i class="bi bi-gear me-2"></i>Account Settings</h3>
                    </div>
                    <div class="card-body">
                        <form method="POST">
                            <input type="hidden" name="csrf_token" value="{{ csrf_token }}"/>
                            <div class="mb-3">
                                <label class="form-label fw-semibold">Name</label>
                                <input type="text" class="form-control" name="name" 
                                       value="{html.escape(user.get('name', ''))}" required>
                            </div>
                            <div class="mb-3">
                                <label class="form-label fw-semibold">Email</label>
                                <input type="email" class="form-control" 
                                       value="{html.escape(user.get('email', ''))}" readonly>
                                <div class="form-text">Email cannot be changed</div>
                            </div>
                            <div class="mb-4">
                                <label class="form-label fw-semibold">New Password</label>
                                <input type="password" class="form-control" name="password" 
                                       minlength="8" placeholder="Leave blank to keep current password">
                            </div>
                            <button type="submit" class="btn btn-primary">Update Settings</button>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>
    '''
    return render_page("Account Settings", content)

@app.route('/billing')
@login_required
def billing_page():
    """Billing and subscription page"""
    user = data_store.find_user_by_email(session.get('email', ''))
    subscription = user.get('subscription', 'inactive') if user else 'inactive'
    
    plan_names = {
        'monthly': 'Monthly Plan',
        'sixmonth': '6-Month Plan',
        'inactive': 'Free Plan'
    }
    
    content = f'''
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-lg-8">
                <div class="card">
                    <div class="card-header bg-warning text-dark">
                        <h3 class="mb-0"><i class="bi bi-credit-card me-2"></i>Billing & Subscription</h3>
                    </div>
                    <div class="card-body">
                        <div class="alert {'alert-success' if subscription != 'inactive' else 'alert-info'} border-0 mb-4">
                            <div class="d-flex align-items-center">
                                <i class="bi bi-{'check-circle' if subscription != 'inactive' else 'info-circle'} fs-4 me-3"></i>
                                <div>
                                    <h6 class="alert-heading mb-1">Current Plan: {plan_names.get(subscription, 'Unknown')}</h6>
                                    <p class="mb-0">
                                        {'You have unlimited access to all features.' if subscription != 'inactive' else 'Limited access - upgrade for unlimited features.'}
                                    </p>
                                </div>
                            </div>
                        </div>
                        
                        {'''
                        <div class="row g-3">
                            <div class="col-md-6">
                                <div class="card border-primary">
                                    <div class="card-header bg-primary text-white text-center">
                                        <h5 class="mb-0">Monthly Plan</h5>
                                    </div>
                                    <div class="card-body text-center">
                                        <h3 class="text-primary">$39.99/month</h3>
                                        <p class="text-muted">Unlimited access</p>
                                        <a href="/billing/checkout?plan=monthly" class="btn btn-primary">Upgrade</a>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="card border-success">
                                    <div class="card-header bg-success text-white text-center">
                                        <h5 class="mb-0">6-Month Plan</h5>
                                    </div>
                                    <div class="card-body text-center">
                                        <h3 class="text-success">$99.00</h3>
                                        <p class="text-muted">One-time payment</p>
                                        <a href="/billing/checkout?plan=sixmonth" class="btn btn-success">Upgrade</a>
                                    </div>
                                </div>
                            </div>
                        </div>
                        ''' if subscription == 'inactive' else '''
                        <div class="alert alert-info border-0">
                            <i class="bi bi-info-circle me-2"></i>
                            Your subscription is active. Contact support for changes.
                        </div>
                        '''}
                    </div>
                </div>
            </div>
        </div>
    </div>
    '''
    return render_page("Billing", content)

@app.route('/billing/checkout')
@login_required
def billing_checkout():
    """Billing checkout - simplified for demo"""
    plan = request.args.get('plan', 'monthly')
    user_email = session.get('email', '')
    
    if not user_email:
        return redirect(url_for('login_page'))
    
    # In production, this would integrate with Stripe
    # For demo, just activate the subscription
    user = data_store.find_user_by_email(user_email)
    if user:
        updates = {'subscription': plan}
        if plan == 'sixmonth':
            expiry = datetime.utcnow() + timedelta(days=180)
            updates['subscription_expires_at'] = expiry.isoformat() + 'Z'
        data_store.update_user(user['id'], updates)
    
    return redirect(url_for('billing_success', plan=plan))

@app.route('/billing/success')
@login_required
def billing_success():
    """Billing success page"""
    plan = request.args.get('plan', 'monthly')
    plan_name = 'Monthly' if plan == 'monthly' else '6-Month'
    
    content = f'''
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-md-6">
                <div class="card text-center">
                    <div class="card-body p-5">
                        <i class="bi bi-check-circle-fill text-success display-1 mb-4"></i>
                        <h2 class="text-success mb-3">Payment Successful!</h2>
                        <p class="text-muted mb-4">Your {plan_name} subscription is now active.</p>
                        <a href="/" class="btn btn-primary">Start Learning</a>
                    </div>
                </div>
            </div>
        </div>
    </div>
    '''
    return render_page("Payment Success", content)

@app.route('/flashcards')
@login_required
def flashcards_page():
    """Flashcards study page"""
    user = data_store.find_user_by_email(session.get('email', ''))
    can_use, error_msg = UsageManager.check_limit(user, 'flashcards')
    
    # Basic flashcards for demo
    sample_flashcards = [
        {
            'front': 'What does CPTED stand for?',
            'back': 'Crime Prevention Through Environmental Design - using architectural and design elements to reduce crime opportunities.',
            'domain': 'physical-security'
        },
        {
            'front': 'Define Defense in Depth',
            'back': 'A security strategy that uses multiple layers of protection so that if one layer fails, others continue to provide security.',
            'domain': 'security-principles'
        },
        {
            'front': 'What is the primary goal of incident response?',
            'back': 'To minimize damage and recovery time while preserving evidence and preventing further incidents.',
            'domain': 'information-security'
        },
        {
            'front': 'Key elements of background investigations',
            'back': 'Identity verification, criminal history, employment history, education verification, and character references.',
            'domain': 'personnel-security'
        },
        {
            'front': 'What is Business Continuity Planning?',
            'back': 'The process of creating systems to prevent and recover from potential threats, ensuring business operations continue.',
            'domain': 'crisis-management'
        }
    ]
    
    if not can_use:
        content = f'''
        <div class="container">
            <div class="card">
                <div class="card-body text-center p-4">
                    <div class="alert alert-warning">{error_msg}</div>
                    <a href="/billing" class="btn btn-success">Upgrade for Unlimited Access</a>
                </div>
            </div>
        </div>
        '''
        return render_page("Flashcards", content)
    
    # Generate flashcard HTML
    cards_html = []
    for i, card in enumerate(sample_flashcards):
        cards_html.append(f'''
            <div class="col-lg-6 mb-4">
                <div class="flashcard" onclick="flipCard(this)">
                    <div class="flashcard-inner">
                        <div class="flashcard-front">
                            <h5>{html.escape(card['front'])}</h5>
                            <small class="opacity-75">Click to flip</small>
                        </div>
                        <div class="flashcard-back">
                            <p>{html.escape(card['back'])}</p>
                        </div>
                    </div>
                </div>
            </div>
        ''')
    
    content = f'''
    <div class="container">
        <div class="card mb-4">
            <div class="card-header bg-info text-white">
                <h3 class="mb-0"><i class="bi bi-card-list me-2"></i>Study Flashcards</h3>
            </div>
        </div>
        
        <div class="row">
            {''.join(cards_html)}
        </div>
    </div>
    
    <style>
        .flashcard {{
            perspective: 1000px;
            height: 200px;
            cursor: pointer;
        }}
        
        .flashcard-inner {{
            position: relative;
            width: 100%;
            height: 100%;
            text-align: center;
            transition: transform 0.6s;
            transform-style: preserve-3d;
        }}
        
        .flashcard.flipped .flashcard-inner {{
            transform: rotateY(180deg);
        }}
        
        .flashcard-front, .flashcard-back {{
            position: absolute;
            width: 100%;
            height: 100%;
            backface-visibility: hidden;
            border-radius: 16px;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding: 1.5rem;
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }}
        
        .flashcard-front {{
            background: linear-gradient(135deg, #2563eb, #7c3aed);
            color: white;
        }}
        
        .flashcard-back {{
            background: linear-gradient(135deg, #059669, #10b981);
            color: white;
            transform: rotateY(180deg);
        }}
    </style>
    
    <script>
        function flipCard(card) {{
            card.classList.toggle('flipped');
        }}
    </script>
    '''
    return render_page("Flashcards", content)

# =============================================================================
# ERROR HANDLERS
# =============================================================================

@app.errorhandler(404)
def not_found_error(error):
    """Handle 404 errors"""
    content = '''
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-md-6">
                <div class="card text-center">
                    <div class="card-body p-5">
                        <i class="bi bi-exclamation-triangle text-warning display-1 mb-4"></i>
                        <h2 class="mb-3">Page Not Found</h2>
                        <p class="text-muted mb-4">The page you're looking for doesn't exist.</p>
                        <a href="/" class="btn btn-primary">Go Home</a>
                    </div>
                </div>
            </div>
        </div>
    </div>
    '''
    return render_page("Page Not Found", content), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    logger.error(f"Internal server error: {error}")
    content = '''
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-md-6">
                <div class="card text-center">
                    <div class="card-body p-5">
                        <i class="bi bi-exclamation-circle text-danger display-1 mb-4"></i>
                        <h2 class="mb-3">Something went wrong</h2>
                        <p class="text-muted mb-4">We're experiencing technical difficulties.</p>
                        <a href="/" class="btn btn-primary">Go Home</a>
                    </div>
                </div>
            </div>
        </div>
    </div>
    '''
    return render_page("Server Error", content), 500

@app.errorhandler(413)
def request_too_large(error):
    """Handle request too large errors"""
    content = '''
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-md-6">
                <div class="card text-center">
                    <div class="card-body p-5">
                        <i class="bi bi-file-earmark-x text-warning display-1 mb-4"></i>
                        <h2 class="mb-3">Request Too Large</h2>
                        <p class="text-muted mb-4">The request is too large to process.</p>
                        <a href="/" class="btn btn-primary">Go Home</a>
                    </div>
                </div>
            </div>
        </div>
    </div>
    '''
    return render_page("Request Too Large", content), 413

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def init_sample_data():
    """Initialize sample data if needed"""
    try:
        # This could load additional questions, flashcards, etc.
        logger.info("Sample data initialized")
    except Exception as e:
        logger.error(f"Failed to initialize sample data: {e}")

# =============================================================================
# APPLICATION STARTUP
# =============================================================================

def create_app():
    """Application factory"""
    # Initialize sample data
    init_sample_data()
    
    # Log startup
    logger.info(f"CPP Test Prep Application v{APP_VERSION} starting up")
    logger.info(f"Debug mode: {DEBUG}")
    logger.info(f"Staging mode: {IS_STAGING}")
    logger.info(f"CSRF protection: {'enabled' if HAS_CSRF else 'disabled'}")
    logger.info(f"Stripe integration: {'enabled' if HAS_STRIPE else 'disabled'}")
    logger.info(f"OpenAI integration: {'enabled' if OPENAI_API_KEY else 'disabled'}")
    
    return app

# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    # Create the application
    application = create_app()
    
    # Run the application
    port = int(os.environ.get("PORT", 5000))
    host = os.environ.get("HOST", "0.0.0.0")
    
    logger.info(f"Starting server on {host}:{port}")
    
    if DEBUG:
        application.run(host=host, port=port, debug=True)
    else:
        # Production server (use gunicorn in production)
        application.run(host=host, port=port, debug=False)
