# =========================
# CPP Test Prep - Production Ready Version
# =========================
# SECTION 1/8: Core Infrastructure, Configuration, and Database Layer
# =========================

import os
import json
import uuid
import time
import hashlib
import logging
import sqlite3
import threading
from datetime import datetime, timedelta
from contextlib import contextmanager
from typing import Dict, Any, List, Optional, Tuple, Union
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor
from functools import wraps, lru_cache
import redis
from redis.exceptions import RedisError

# Enhanced imports with fallbacks
try:
    from flask import Flask, request, jsonify, session, redirect, url_for, Response, abort, g
    from werkzeug.security import generate_password_hash, check_password_hash
    from werkzeug.middleware.proxy_fix import ProxyFix
    from werkzeug.exceptions import RequestEntityTooLarge
except ImportError as e:
    raise ImportError(f"Flask dependencies missing: {e}")

try:
    from flask_wtf.csrf import CSRFProtect, validate_csrf, generate_csrf
    HAS_CSRF = True
except ImportError:
    HAS_CSRF = False
    CSRFProtect = None
    validate_csrf = None
    def generate_csrf() -> str:
        return ""

try:
    import fcntl
    HAS_FCNTL = True
except ImportError:
    HAS_FCNTL = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import stripe
    HAS_STRIPE = True
except ImportError:
    HAS_STRIPE = False

# Enhanced logging configuration
def setup_logging():
    """Configure structured logging with rotation"""
    log_level = getattr(logging, os.environ.get('LOG_LEVEL', 'INFO').upper())
    log_format = '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s'
    
    logging.basicConfig(
        level=log_level,
        format=log_format,
        handlers=[
            logging.StreamHandler(),
            # File handler would be added here for production
        ]
    )
    
    # Reduce noise from third-party libraries
    logging.getLogger('werkzeug').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    
    return logging.getLogger("cpp-app")

logger = setup_logging()

# =========================
# Configuration Management
# =========================

@dataclass
class Config:
    """Type-safe configuration with validation"""
    
    # Core Flask settings
    SECRET_KEY: str
    DEBUG: bool = False
    TESTING: bool = False
    
    # Database settings
    DATABASE_URL: str = "sqlite:///data/app.db"
    REDIS_URL: Optional[str] = None
    DATABASE_POOL_SIZE: int = 20
    DATABASE_TIMEOUT: int = 30
    
    # Storage settings
    DATA_DIR: str = "data"
    MAX_FILE_SIZE: int = 100 * 1024 * 1024  # 100MB
    BACKUP_RETENTION_DAYS: int = 30
    
    # Security settings
    SESSION_COOKIE_SECURE: bool = True
    SESSION_COOKIE_HTTPONLY: bool = True
    SESSION_COOKIE_SAMESITE: str = "Lax"
    BCRYPT_LOG_ROUNDS: int = 12
    MAX_LOGIN_ATTEMPTS: int = 5
    LOGIN_ATTEMPT_WINDOW: int = 300  # 5 minutes
    
    # Rate limiting
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_STORAGE: str = "memory"  # memory, redis
    DEFAULT_RATE_LIMIT: str = "100/hour"
    
    # External services
    OPENAI_API_KEY: str = ""
    OPENAI_API_BASE: str = "https://api.openai.com/v1"
    OPENAI_CHAT_MODEL: str = "gpt-4o-mini"
    OPENAI_ORG: str = ""
    OPENAI_TIMEOUT: int = 45
    
    # Stripe settings
    STRIPE_SECRET_KEY: str = ""
    STRIPE_PUBLISHABLE_KEY: str = ""
    STRIPE_WEBHOOK_SECRET: str = ""
    STRIPE_MONTHLY_PRICE_ID: str = ""
    STRIPE_SIXMONTH_PRICE_ID: str = ""
    
    # Application settings
    APP_VERSION: str = "2.0.0"
    ADMIN_PASSWORD: str = ""
    IS_STAGING: bool = False
    
    # Tutor settings
    TUTOR_TIMEOUT: int = 45
    TUTOR_TEMP: float = 0.3
    TUTOR_MAX_TOKENS: int = 800
    TUTOR_WEB_AWARE: bool = False
    
    @classmethod
    def from_env(cls) -> 'Config':
        """Create configuration from environment variables with validation"""
        
        # Required settings
        secret_key = os.environ.get("SECRET_KEY")
        if not secret_key:
            if os.environ.get("FLASK_ENV") == "development":
                secret_key = "dev-key-not-for-production"
                logger.warning("Using development SECRET_KEY")
            else:
                raise ValueError("SECRET_KEY environment variable is required")
        
        # Parse boolean values
        def parse_bool(value: str, default: bool = False) -> bool:
            if not value:
                return default
            return value.lower() in ("1", "true", "yes", "on")
        
        # Parse integer values with validation
        def parse_int(value: str, default: int, min_val: int = None, max_val: int = None) -> int:
            if not value:
                return default
            try:
                val = int(value)
                if min_val is not None and val < min_val:
                    logger.warning(f"Value {val} below minimum {min_val}, using default {default}")
                    return default
                if max_val is not None and val > max_val:
                    logger.warning(f"Value {val} above maximum {max_val}, using default {default}")
                    return default
                return val
            except ValueError:
                logger.warning(f"Invalid integer value '{value}', using default {default}")
                return default
        
        return cls(
            SECRET_KEY=secret_key,
            DEBUG=parse_bool(os.environ.get("FLASK_DEBUG", "0")),
            TESTING=parse_bool(os.environ.get("FLASK_TESTING", "0")),
            
            DATABASE_URL=os.environ.get("DATABASE_URL", "sqlite:///data/app.db"),
            REDIS_URL=os.environ.get("REDIS_URL"),
            DATABASE_POOL_SIZE=parse_int(os.environ.get("DATABASE_POOL_SIZE", "20"), 20, 5, 100),
            DATABASE_TIMEOUT=parse_int(os.environ.get("DATABASE_TIMEOUT", "30"), 30, 10, 300),
            
            DATA_DIR=os.environ.get("DATA_DIR", "data"),
            MAX_FILE_SIZE=parse_int(os.environ.get("MAX_FILE_SIZE", str(100*1024*1024)), 100*1024*1024, 1024*1024),
            BACKUP_RETENTION_DAYS=parse_int(os.environ.get("BACKUP_RETENTION_DAYS", "30"), 30, 1, 365),
            
            SESSION_COOKIE_SECURE=parse_bool(os.environ.get("SESSION_COOKIE_SECURE", "1")),
            BCRYPT_LOG_ROUNDS=parse_int(os.environ.get("BCRYPT_LOG_ROUNDS", "12"), 12, 4, 15),
            MAX_LOGIN_ATTEMPTS=parse_int(os.environ.get("MAX_LOGIN_ATTEMPTS", "5"), 5, 1, 50),
            LOGIN_ATTEMPT_WINDOW=parse_int(os.environ.get("LOGIN_ATTEMPT_WINDOW", "300"), 300, 60, 3600),
            
            RATE_LIMIT_ENABLED=parse_bool(os.environ.get("RATE_LIMIT_ENABLED", "1")),
            RATE_LIMIT_STORAGE=os.environ.get("RATE_LIMIT_STORAGE", "memory"),
            DEFAULT_RATE_LIMIT=os.environ.get("DEFAULT_RATE_LIMIT", "100/hour"),
            
            OPENAI_API_KEY=os.environ.get("OPENAI_API_KEY", "").strip(),
            OPENAI_API_BASE=os.environ.get("OPENAI_API_BASE", "https://api.openai.com/v1").rstrip("/"),
            OPENAI_CHAT_MODEL=os.environ.get("OPENAI_CHAT_MODEL", "gpt-4o-mini").strip(),
            OPENAI_ORG=os.environ.get("OPENAI_ORG", "").strip(),
            OPENAI_TIMEOUT=parse_int(os.environ.get("OPENAI_TIMEOUT", "45"), 45, 10, 300),
            
            STRIPE_SECRET_KEY=os.environ.get('STRIPE_SECRET_KEY', '').strip(),
            STRIPE_PUBLISHABLE_KEY=os.environ.get('STRIPE_PUBLISHABLE_KEY', '').strip(),
            STRIPE_WEBHOOK_SECRET=os.environ.get('STRIPE_WEBHOOK_SECRET', '').strip(),
            STRIPE_MONTHLY_PRICE_ID=os.environ.get('STRIPE_MONTHLY_PRICE_ID', '').strip(),
            STRIPE_SIXMONTH_PRICE_ID=os.environ.get('STRIPE_SIXMONTH_PRICE_ID', '').strip(),
            
            APP_VERSION=os.environ.get("APP_VERSION", "2.0.0"),
            ADMIN_PASSWORD=os.environ.get("ADMIN_PASSWORD", "").strip(),
            IS_STAGING=os.environ.get("RENDER_SERVICE_NAME", "").endswith("-staging"),
            
            TUTOR_TIMEOUT=parse_int(os.environ.get("TUTOR_TIMEOUT", "45"), 45, 10, 300),
            TUTOR_TEMP=min(2.0, max(0.0, float(os.environ.get("TUTOR_TEMP", "0.3")))),
            TUTOR_MAX_TOKENS=parse_int(os.environ.get("TUTOR_MAX_TOKENS", "800"), 800, 100, 4000),
            TUTOR_WEB_AWARE=parse_bool(os.environ.get("TUTOR_WEB_AWARE", "0")),
        )
    
    def validate(self) -> List[str]:
        """Validate configuration and return list of issues"""
        issues = []
        
        if self.DEBUG and self.SECRET_KEY == "dev-key-not-for-production":
            issues.append("Using development SECRET_KEY in production")
            
        if self.OPENAI_API_KEY and not self.OPENAI_API_KEY.startswith(('sk-', 'org-')):
            issues.append("OPENAI_API_KEY format appears invalid")
            
        if self.STRIPE_SECRET_KEY and not self.STRIPE_SECRET_KEY.startswith(('sk_test_', 'sk_live_')):
            issues.append("STRIPE_SECRET_KEY format appears invalid")
            
        return issues

# Global configuration instance
config = Config.from_env()

# Validate configuration
config_issues = config.validate()
for issue in config_issues:
    logger.warning(f"Configuration issue: {issue}")

# =========================
# Database Layer
# =========================

class DatabaseManager:
    """Thread-safe database manager with connection pooling"""
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if hasattr(self, '_initialized'):
            return
        
        self._initialized = True
        self._local = threading.local()
        self.database_url = config.DATABASE_URL
        self._setup_database()
        
    def _setup_database(self):
        """Initialize database schema"""
        try:
            if self.database_url.startswith('sqlite:'):
                db_path = self.database_url.replace('sqlite:///', '').replace('sqlite://', '')
                os.makedirs(os.path.dirname(db_path) if os.path.dirname(db_path) else '.', exist_ok=True)
                
            with self.get_connection() as conn:
                self._create_tables(conn)
                logger.info("Database initialized successfully")
                
        except Exception as e:
            logger.error(f"Database setup failed: {e}")
            raise
    
    def _create_tables(self, conn: sqlite3.Connection):
        """Create all database tables with proper indexes"""
        
        # Enable foreign keys and WAL mode for SQLite
        if 'sqlite' in self.database_url:
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA synchronous = NORMAL")
            conn.execute("PRAGMA cache_size = 10000")
            conn.execute("PRAGMA temp_store = MEMORY")
        
        # Users table with enhanced fields
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            subscription TEXT DEFAULT 'inactive' CHECK (subscription IN ('inactive', 'monthly', 'sixmonth')),
            subscription_expires_at DATETIME,
            stripe_customer_id TEXT,
            created_at DATETIME DEFAULT (datetime('now', 'utc')),
            updated_at DATETIME DEFAULT (datetime('now', 'utc')),
            last_login_at DATETIME,
            login_attempts INTEGER DEFAULT 0,
            locked_until DATETIME,
            is_active BOOLEAN DEFAULT 1,
            preferences TEXT DEFAULT '{}',
            CONSTRAINT email_format CHECK (email LIKE '%@%.%')
        );
        
        CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
        CREATE INDEX IF NOT EXISTS idx_users_subscription ON users(subscription);
        CREATE INDEX IF NOT EXISTS idx_users_stripe_customer ON users(stripe_customer_id);
        
        -- Usage tracking table
        CREATE TABLE IF NOT EXISTS user_usage (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            action_type TEXT NOT NULL,
            count INTEGER DEFAULT 1,
            period_start DATE NOT NULL,
            created_at DATETIME DEFAULT (datetime('now', 'utc')),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        
        CREATE INDEX IF NOT EXISTS idx_usage_user_period ON user_usage(user_id, period_start);
        CREATE INDEX IF NOT EXISTS idx_usage_action_type ON user_usage(action_type);
        
        -- Sessions table for better session management
        CREATE TABLE IF NOT EXISTS user_sessions (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            session_data TEXT,
            created_at DATETIME DEFAULT (datetime('now', 'utc')),
            expires_at DATETIME NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        
        CREATE INDEX IF NOT EXISTS idx_sessions_user ON user_sessions(user_id);
        CREATE INDEX IF NOT EXISTS idx_sessions_expires ON user_sessions(expires_at);
        
        -- Questions table
        CREATE TABLE IF NOT EXISTS questions (
            id TEXT PRIMARY KEY,
            question TEXT NOT NULL,
            options TEXT NOT NULL, -- JSON
            correct TEXT NOT NULL CHECK (correct IN ('A', 'B', 'C', 'D')),
            explanation TEXT,
            domain TEXT NOT NULL,
            difficulty TEXT DEFAULT 'medium' CHECK (difficulty IN ('easy', 'medium', 'hard')),
            sources TEXT DEFAULT '[]', -- JSON array
            created_at DATETIME DEFAULT (datetime('now', 'utc')),
            updated_at DATETIME DEFAULT (datetime('now', 'utc')),
            is_active BOOLEAN DEFAULT 1
        );
        
        CREATE INDEX IF NOT EXISTS idx_questions_domain ON questions(domain);
        CREATE INDEX IF NOT EXISTS idx_questions_difficulty ON questions(difficulty);
        CREATE INDEX IF NOT EXISTS idx_questions_active ON questions(is_active);
        
        -- Flashcards table
        CREATE TABLE IF NOT EXISTS flashcards (
            id TEXT PRIMARY KEY,
            front TEXT NOT NULL,
            back TEXT NOT NULL,
            domain TEXT NOT NULL,
            sources TEXT DEFAULT '[]', -- JSON array
            created_at DATETIME DEFAULT (datetime('now', 'utc')),
            updated_at DATETIME DEFAULT (datetime('now', 'utc')),
            is_active BOOLEAN DEFAULT 1
        );
        
        CREATE INDEX IF NOT EXISTS idx_flashcards_domain ON flashcards(domain);
        CREATE INDEX IF NOT EXISTS idx_flashcards_active ON flashcards(is_active);
        
        -- User attempts/results
        CREATE TABLE IF NOT EXISTS user_attempts (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            attempt_type TEXT NOT NULL CHECK (attempt_type IN ('quiz', 'mock', 'flashcard')),
            question_count INTEGER NOT NULL,
            correct_count INTEGER NOT NULL,
            score_percentage REAL NOT NULL,
            domain_filter TEXT,
            results TEXT, -- JSON with detailed results
            started_at DATETIME NOT NULL,
            completed_at DATETIME DEFAULT (datetime('now', 'utc')),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        
        CREATE INDEX IF NOT EXISTS idx_attempts_user ON user_attempts(user_id);
        CREATE INDEX IF NOT EXISTS idx_attempts_type ON user_attempts(attempt_type);
        CREATE INDEX IF NOT EXISTS idx_attempts_completed ON user_attempts(completed_at);
        
        -- Events table for analytics
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT,
            event_type TEXT NOT NULL,
            event_data TEXT, -- JSON
            ip_address TEXT,
            user_agent TEXT,
            created_at DATETIME DEFAULT (datetime('now', 'utc'))
        );
        
        CREATE INDEX IF NOT EXISTS idx_events_user ON events(user_id);
        CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
        CREATE INDEX IF NOT EXISTS idx_events_created ON events(created_at);
        
        -- Content index for deduplication
        CREATE TABLE IF NOT EXISTS content_hashes (
            hash TEXT PRIMARY KEY,
            content_type TEXT NOT NULL CHECK (content_type IN ('question', 'flashcard')),
            content_id TEXT NOT NULL,
            created_at DATETIME DEFAULT (datetime('now', 'utc'))
        );
        
        CREATE INDEX IF NOT EXISTS idx_content_hashes_type ON content_hashes(content_type);
        """)
        
        conn.commit()
    
    def get_connection(self) -> sqlite3.Connection:
        """Get database connection with proper configuration"""
        if not hasattr(self._local, 'connection') or self._local.connection is None:
            if self.database_url.startswith('sqlite:'):
                db_path = self.database_url.replace('sqlite:///', '').replace('sqlite://', '')
                conn = sqlite3.connect(
                    db_path,
                    timeout=config.DATABASE_TIMEOUT,
                    check_same_thread=False,
                    isolation_level=None  # Autocommit mode
                )
                conn.row_factory = sqlite3.Row
                conn.execute("PRAGMA foreign_keys = ON")
                self._local.connection = conn
            else:
                raise NotImplementedError("Only SQLite is currently supported")
        
        return self._local.connection
    
    @contextmanager
    def transaction(self):
        """Context manager for database transactions"""
        conn = self.get_connection()
        try:
            conn.execute("BEGIN")
            yield conn
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
    
    def close_connection(self):
        """Close the current thread's database connection"""
        if hasattr(self._local, 'connection') and self._local.connection:
            self._local.connection.close()
            self._local.connection = None

# Global database manager
db = DatabaseManager()

# =========================
# Caching Layer
# =========================

class CacheManager:
    """Redis-backed cache with fallback to in-memory"""
    
    def __init__(self):
        self._redis_client = None
        self._memory_cache = {}
        self._memory_cache_lock = threading.Lock()
        self._setup_cache()
    
    def _setup_cache(self):
        """Initialize Redis connection if available"""
        if config.REDIS_URL:
            try:
                import redis
                self._redis_client = redis.from_url(
                    config.REDIS_URL,
                    decode_responses=True,
                    socket_timeout=5,
                    socket_connect_timeout=5,
                    health_check_interval=30
                )
                # Test connection
                self._redis_client.ping()
                logger.info("Redis cache connected successfully")
            except Exception as e:
                logger.warning(f"Redis connection failed, using memory cache: {e}")
                self._redis_client = None
        else:
            logger.info("No Redis URL provided, using memory cache")
    
    def get(self, key: str, default=None):
        """Get value from cache"""
        try:
            if self._redis_client:
                value = self._redis_client.get(key)
                if value is not None:
                    return json.loads(value)
            else:
                with self._memory_cache_lock:
                    if key in self._memory_cache:
                        item = self._memory_cache[key]
                        if item['expires'] > time.time():
                            return item['value']
                        else:
                            del self._memory_cache[key]
        except Exception as e:
            logger.warning(f"Cache get error for key {key}: {e}")
        
        return default
    
    def set(self, key: str, value, ttl: int = 3600):
        """Set value in cache with TTL"""
        try:
            if self._redis_client:
                self._redis_client.setex(key, ttl, json.dumps(value))
            else:
                with self._memory_cache_lock:
                    self._memory_cache[key] = {
                        'value': value,
                        'expires': time.time() + ttl
                    }
                    # Simple cleanup of expired items
                    if len(self._memory_cache) > 1000:
                        self._cleanup_memory_cache()
        except Exception as e:
            logger.warning(f"Cache set error for key {key}: {e}")
    
    def delete(self, key: str):
        """Delete value from cache"""
        try:
            if self._redis_client:
                self._redis_client.delete(key)
            else:
                with self._memory_cache_lock:
                    self._memory_cache.pop(key, None)
        except Exception as e:
            logger.warning(f"Cache delete error for key {key}: {e}")
    
    def _cleanup_memory_cache(self):
        """Remove expired items from memory cache"""
        now = time.time()
        expired_keys = [k for k, v in self._memory_cache.items() if v['expires'] <= now]
        for k in expired_keys:
            del self._memory_cache[k]

# Global cache manager
cache = CacheManager()

# =========================
# File Storage Manager
# =========================

class FileStorageManager:
    """Thread-safe file operations with atomic writes and backup"""
    
    def __init__(self, base_dir: str = None):
        self.base_dir = base_dir or config.DATA_DIR
        self._ensure_directory_structure()
        self._lock = threading.RLock()
    
    def _ensure_directory_structure(self):
        """Create necessary directory structure"""
        directories = [
            self.base_dir,
            os.path.join(self.base_dir, 'bank'),
            os.path.join(self.base_dir, 'backups'),
            os.path.join(self.base_dir, 'temp'),
            os.path.join(self.base_dir, 'cache')
        ]
        
        for directory in directories:
            os.makedirs(directory, exist_ok=True)
    
    def load_json(self, filename: str, default=None) -> Any:
        """Load JSON file with caching"""
        cache_key = f"file:{filename}"
        cached = cache.get(cache_key)
        if cached is not None:
            return cached
            
        filepath = os.path.join(self.base_dir, filename)
        
        try:
            with self._lock:
                if not os.path.exists(filepath):
                    return default
                
                with open(filepath, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                # Cache for 5 minutes
                cache.set(cache_key, data, ttl=300)
                return data
                
        except Exception as e:
            logger.error(f"Failed to load JSON file {filename}: {e}")
            return default
    
    def save_json(self, filename: str, data: Any, create_backup: bool = True) -> bool:
        """Atomically save JSON file with optional backup"""
        filepath = os.path.join(self.base_dir, filename)
        
        try:
            with self._lock:
                # Create backup if file exists
                if create_backup and os.path.exists(filepath):
                    self._create_backup(filepath)
                
                # Atomic write using temporary file
                temp_filepath = filepath + f".tmp.{os.getpid()}.{uuid.uuid4().hex[:8]}"
                
                with open(temp_filepath, 'w', encoding='utf-8') as f:
                    json.dump(data, f, ensure_ascii=False, indent=2)
                    f.flush()
                    os.fsync(f.fileno())
                
                # Atomic move
                if os.name == 'nt':  # Windows
                    if os.path.exists(filepath):
                        os.remove(filepath)
                os.rename(temp_filepath, filepath)
                
                # Update cache
                cache_key = f"file:{filename}"
                cache.set(cache_key, data, ttl=300)
                
                return True
                
        except Exception as e:
            logger.error(f"Failed to save JSON file {filename}: {e}")
            # Cleanup temp file if it exists
            try:
                temp_filepath = filepath + f".tmp.{os.getpid()}.{uuid.uuid4().hex[:8]}"
                if os.path.exists(temp_filepath):
                    os.remove(temp_filepath)
            except:
                pass
            return False
    
    def _create_backup(self, filepath: str):
        """Create backup of existing file"""
        try:
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            backup_name = f"{os.path.basename(filepath)}.{timestamp}.backup"
            backup_path = os.path.join(self.base_dir, 'backups', backup_name)
            
            import shutil
            shutil.copy2(filepath, backup_path)
            
            # Cleanup old backups
            self._cleanup_backups()
            
        except Exception as e:
            logger.warning(f"Failed to create backup for {filepath}: {e}")
    
    def _cleanup_backups(self):
        """Remove backups older than retention period"""
        try:
            backup_dir = os.path.join(self.base_dir, 'backups')
            cutoff_date = datetime.utcnow() - timedelta(days=config.BACKUP_RETENTION_DAYS)
            
            for filename in os.listdir(backup_dir):
                filepath = os.path.join(backup_dir, filename)
                if os.path.isfile(filepath):
                    file_time = datetime.fromtimestamp(os.path.getmtime(filepath))
                    if file_time < cutoff_date:
                        os.remove(filepath)
                        
        except Exception as e:
            logger.warning(f"Backup cleanup failed: {e}")

# Global file storage manager
file_storage = FileStorageManager()

# =========================
# Application Factory
# =========================

def create_app() -> Flask:
    """Create and configure Flask application"""
    
    app = Flask(__name__)
    
    # Basic Flask configuration
    app.config.update(
        SECRET_KEY=config.SECRET_KEY,
        DEBUG=config.DEBUG,
        TESTING=config.TESTING,
        MAX_CONTENT_LENGTH=config.MAX_FILE_SIZE,
        SESSION_COOKIE_HTTPONLY=config.SESSION_COOKIE_HTTPONLY,
        SESSION_COOKIE_SECURE=config.SESSION_COOKIE_SECURE,
        SESSION_COOKIE_SAMESITE=config.SESSION_COOKIE_SAMESITE,
        PERMANENT_SESSION_LIFETIME=timedelta(hours=24)
    )
    
    # Proxy fix for production deployment
    app.wsgi_app = ProxyFix(
        app.wsgi_app,
        x_for=1,
        x_proto=1,
        x_host=1,
        x_port=1
    )
    
    # CSRF Protection
    if HAS_CSRF:
        csrf = CSRFProtect(app)
        logger.info("CSRF protection enabled")
    else:
        logger.warning("CSRF protection disabled - Flask-WTF not available")
    
    # Stripe configuration
    if HAS_STRIPE and config.STRIPE_SECRET_KEY:
        stripe.api_key = config.STRIPE_SECRET_KEY
        logger.info("Stripe integration enabled")
    else:
        logger.warning("Stripe integration disabled")
    
    # Request/Response hooks
    @app.before_request
    def before_request():
        """Setup request context"""
        g.start_time = time.time()
        g.request_id = str(uuid.uuid4())[:8]
        
        # Request size check
        if request.content_length and request.content_length > config.MAX_FILE_SIZE:
            abort(413)
    
    @app.after_request
    def after_request(response):
        """Add security headers and logging"""
        
        # Security headers
        response.headers.update({
            'X-Frame-Options': 'DENY',
            'X-Content-Type-Options': 'nosniff',
            'X-XSS-Protection': '1; mode=block',
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
        })
        
        # HSTS header for HTTPS
        if request.is_secure:
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        
        # CSP header
        csp_policy = (
            "default-src 'self' https: data: blob:; "
            "img-src 'self' https: data:; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://js.stripe.com; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "font-src 'self' https: data:; "
            "connect-src 'self' https://api.openai.com https://js.stripe.com https://api.stripe.com; "
            "frame-src https://js.stripe.com; "
            "frame-ancestors 'none'"
        )
        response.headers['Content-Security-Policy'] = csp_policy
        
        # Response time logging
        if hasattr(g, 'start_time'):
            duration = int((time.time() - g.start_time) * 1000)
            if duration > 1000:  # Log slow requests
                logger.warning(f"Slow request: {request.method} {request.path} took {duration}ms")
        
        return response
    
    @app.teardown_appcontext
    def close_db(error):
        """Clean up database connections"""
        try:
            db.close_connection()
        except Exception as e:
            logger.error(f"Error closing database connection: {e}")
    
    # Error handlers
    @app.errorhandler(413)
    def request_entity_too_large(error):
        logger.warning(f"File too large: {request.remote_addr}")
        return jsonify({"error": "File too large"}), 413
    
    @app.errorhandler(429)
    def ratelimit_handler(e):
        return jsonify({"error": "Rate limit exceeded"}), 429
    
    return app

# Initialize the Flask app
app = create_app()

# =========================
# Health Check Endpoint
# =========================

@app.route('/healthz')
def health_check():
    """Comprehensive health check endpoint"""
    checks = {
        'database': False,
        'cache': False,
        'storage': False,
        'external_apis': {}
    }
    
    status = 200
    
    # Database check
    try:
        with db.get_connection() as conn:
            conn.execute("SELECT 1").fetchone()
        checks['database'] = True
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        status = 503
    
    # Cache check
    try:
        test_key = "health_check"
        cache.set(test_key, "ok", ttl=10)
        checks['cache'] = cache.get(test_key) == "ok"
        cache.delete(test_key)
    except Exception as e:
        logger.error(f"Cache health check failed: {e}")
        status = 503
    
    # Storage check
    try:
        test_data = {"test": "health_check"}
        file_storage.save_json("health_check.json", test_data, create_backup=False)
        loaded = file_storage.load_json("health_check.json")
        checks['storage'] = loaded == test_data
        # Cleanup
        try:
            os.remove(os.path.join(file_storage.base_dir, "health_check.json"))
        except:
            pass
    except Exception as e:
        logger.error(f"Storage health check failed: {e}")
        status = 503
    
    # External API checks (non-blocking)
    if config.OPENAI_API_KEY:
        checks['external_apis']['openai'] = 'configured'
    
    if config.STRIPE_SECRET_KEY:
        checks['external_apis']['stripe'] = 'configured'
    
    return jsonify({
        'status': 'healthy' if status == 200 else 'unhealthy',
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'version': config.APP_VERSION,
        'checks': checks
    }), status

logger.info(f"CPP Test Prep v{config.APP_VERSION} - Section 1 initialized")
# =========================
# SECTION 2/8: User Management, Authentication, and Security
# =========================

import re
import hashlib
import secrets
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field, asdict
from functools import wraps
from collections import defaultdict
from urllib.parse import urlparse, urljoin

from werkzeug.security import generate_password_hash, check_password_hash
from flask import request, session, redirect, url_for, jsonify, g, flash, abort

# =========================
# User Data Models
# =========================

@dataclass
class User:
    """User model with validation"""
    id: str
    name: str
    email: str
    password_hash: str
    subscription: str = 'inactive'
    subscription_expires_at: Optional[datetime] = None
    stripe_customer_id: Optional[str] = None
    created_at: datetime = field(default_factory=lambda: datetime.utcnow())
    updated_at: datetime = field(default_factory=lambda: datetime.utcnow())
    last_login_at: Optional[datetime] = None
    login_attempts: int = 0
    locked_until: Optional[datetime] = None
    is_active: bool = True
    preferences: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        data = asdict(self)
        # Convert datetime objects to ISO strings
        for key in ['created_at', 'updated_at', 'last_login_at', 'locked_until', 'subscription_expires_at']:
            if data[key]:
                data[key] = data[key].isoformat() + 'Z'
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'User':
        """Create User from dictionary"""
        # Convert ISO strings back to datetime objects
        for key in ['created_at', 'updated_at', 'last_login_at', 'locked_until', 'subscription_expires_at']:
            if data.get(key):
                if isinstance(data[key], str):
                    data[key] = datetime.fromisoformat(data[key].replace('Z', '+00:00')).replace(tzinfo=None)
        
        return cls(**{k: v for k, v in data.items() if k in cls.__annotations__})
    
    def is_subscription_active(self) -> bool:
        """Check if user has an active subscription"""
        if self.subscription == 'inactive':
            return False
        
        if self.subscription == 'monthly':
            return True  # Monthly subscriptions are managed by Stripe
        
        if self.subscription == 'sixmonth' and self.subscription_expires_at:
            return datetime.utcnow() < self.subscription_expires_at
        
        return False
    
    def is_account_locked(self) -> bool:
        """Check if account is temporarily locked"""
        if not self.locked_until:
            return False
        return datetime.utcnow() < self.locked_until

@dataclass
class UserUsage:
    """User usage tracking model"""
    user_id: str
    action_type: str
    count: int
    period_start: datetime
    created_at: datetime = field(default_factory=lambda: datetime.utcnow())

# =========================
# Security Utilities
# =========================

class SecurityValidator:
    """Security validation utilities"""
    
    # Password requirements
    MIN_PASSWORD_LENGTH = 8
    MAX_PASSWORD_LENGTH = 128
    
    # Email validation
    EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    
    # Name validation
    NAME_REGEX = re.compile(r'^[a-zA-Z\s\-\'\.]{2,50}$')
    
    @classmethod
    def validate_email(cls, email: str) -> Tuple[bool, str]:
        """Validate email format and security"""
        if not email:
            return False, "Email is required"
        
        email = email.strip().lower()
        
        if len(email) > 254:
            return False, "Email address is too long"
        
        if not cls.EMAIL_REGEX.match(email):
            return False, "Invalid email format"
        
        # Check for suspicious patterns
        suspicious_patterns = [
            r'\.{2,}',  # Multiple consecutive dots
            r'^\.+',    # Starting with dots
            r'\.+$',    # Ending with dots
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, email):
                return False, "Invalid email format"
        
        return True, ""
    
    @classmethod
    def validate_password(cls, password: str) -> Tuple[bool, str]:
        """Validate password strength"""
        if not password:
            return False, "Password is required"
        
        if len(password) < cls.MIN_PASSWORD_LENGTH:
            return False, f"Password must be at least {cls.MIN_PASSWORD_LENGTH} characters long"
        
        if len(password) > cls.MAX_PASSWORD_LENGTH:
            return False, f"Password must be no more than {cls.MAX_PASSWORD_LENGTH} characters long"
        
        # Check for basic complexity
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password)
        
        complexity_count = sum([has_upper, has_lower, has_digit, has_special])
        
        if complexity_count < 3:
            return False, "Password must contain at least 3 of: uppercase, lowercase, numbers, special characters"
        
        # Check for common weak patterns
        weak_patterns = [
            r'(.)\1{3,}',          # 4 or more repeated characters
            r'(012|123|234|345|456|567|678|789|890)',  # Sequential numbers
            r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)',  # Sequential letters
        ]
        
        for pattern in weak_patterns:
            if re.search(pattern, password.lower()):
                return False, "Password contains weak patterns. Please choose a stronger password"
        
        return True, ""
    
    @classmethod
    def validate_name(cls, name: str) -> Tuple[bool, str]:
        """Validate user name"""
        if not name:
            return False, "Name is required"
        
        name = name.strip()
        
        if len(name) < 2:
            return False, "Name must be at least 2 characters long"
        
        if len(name) > 50:
            return False, "Name must be no more than 50 characters long"
        
        if not cls.NAME_REGEX.match(name):
            return False, "Name can only contain letters, spaces, hyphens, apostrophes, and periods"
        
        return True, ""
    
    @classmethod
    def generate_secure_id(cls) -> str:
        """Generate a cryptographically secure ID"""
        return secrets.token_urlsafe(32)
    
    @classmethod
    def hash_password(cls, password: str) -> str:
        """Hash password with secure parameters"""
        return generate_password_hash(
            password,
            method='pbkdf2:sha256',
            salt_length=16
        )
    
    @classmethod
    def check_password(cls, password_hash: str, password: str) -> bool:
        """Verify password against hash"""
        return check_password_hash(password_hash, password)

# =========================
# Rate Limiting
# =========================

class RateLimiter:
    """Thread-safe rate limiter with Redis/memory backend"""
    
    def __init__(self):
        self._memory_store = defaultdict(list)
        self._lock = threading.Lock()
    
    def _get_client_identifier(self) -> str:
        """Get unique identifier for rate limiting"""
        # Try to get authenticated user first
        if 'user_id' in session:
            return f"user:{session['user_id']}"
        
        # Fall back to IP-based limiting
        forwarded_for = request.headers.get('X-Forwarded-For', '').split(',')
        if forwarded_for and forwarded_for[0].strip():
            client_ip = forwarded_for[0].strip()
        else:
            client_ip = request.remote_addr or 'unknown'
        
        return f"ip:{client_ip}"
    
    def is_rate_limited(self, endpoint: str, limit: int = 10, window: int = 60) -> Tuple[bool, Dict[str, Any]]:
        """
        Check if client is rate limited
        
        Args:
            endpoint: The endpoint being accessed
            limit: Maximum requests allowed
            window: Time window in seconds
            
        Returns:
            Tuple of (is_limited, info_dict)
        """
        if not config.RATE_LIMIT_ENABLED:
            return False, {}
        
        client_id = self._get_client_identifier()
        key = f"rate_limit:{endpoint}:{client_id}"
        current_time = time.time()
        
        try:
            if cache._redis_client:
                # Use Redis for distributed rate limiting
                pipe = cache._redis_client.pipeline()
                pipe.zremrangebyscore(key, 0, current_time - window)
                pipe.zcard(key)
                pipe.zadd(key, {str(current_time): current_time})
                pipe.expire(key, window)
                results = pipe.execute()
                
                request_count = results[1]
                is_limited = request_count >= limit
                
                return is_limited, {
                    'limit': limit,
                    'remaining': max(0, limit - request_count - 1),
                    'reset_time': current_time + window,
                    'window': window
                }
            else:
                # Use memory store
                with self._lock:
                    requests = self._memory_store[key]
                    # Remove expired entries
                    requests[:] = [t for t in requests if current_time - t < window]
                    
                    is_limited = len(requests) >= limit
                    
                    if not is_limited:
                        requests.append(current_time)
                    
                    return is_limited, {
                        'limit': limit,
                        'remaining': max(0, limit - len(requests)),
                        'reset_time': current_time + window,
                        'window': window
                    }
                    
        except Exception as e:
            logger.error(f"Rate limiting error: {e}")
            # Fail open - don't block on rate limiter errors
            return False, {}

# Global rate limiter
rate_limiter = RateLimiter()

def rate_limit(endpoint: str, limit: int = 10, window: int = 60):
    """Decorator for rate limiting endpoints"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            is_limited, info = rate_limiter.is_rate_limited(endpoint, limit, window)
            
            if is_limited:
                if request.is_json:
                    return jsonify({
                        'error': 'Rate limit exceeded',
                        'retry_after': info.get('reset_time', time.time() + window)
                    }), 429
                else:
                    flash('Too many requests. Please wait before trying again.', 'error')
                    return redirect(request.referrer or url_for('home'))
            
            # Add rate limit headers to response
            response = f(*args, **kwargs)
            if hasattr(response, 'headers'):
                response.headers['X-RateLimit-Limit'] = str(info.get('limit', limit))
                response.headers['X-RateLimit-Remaining'] = str(info.get('remaining', 0))
                response.headers['X-RateLimit-Reset'] = str(int(info.get('reset_time', time.time() + window)))
            
            return response
        
        return decorated_function
    return decorator

# =========================
# User Repository
# =========================

class UserRepository:
    """Database operations for users"""
    
    def __init__(self):
        self._cache_ttl = 300  # 5 minutes
    
    def create_user(self, name: str, email: str, password: str) -> Optional[User]:
        """Create a new user"""
        # Validate input
        valid_email, email_error = SecurityValidator.validate_email(email)
        if not valid_email:
            raise ValueError(email_error)
        
        valid_name, name_error = SecurityValidator.validate_name(name)
        if not valid_name:
            raise ValueError(name_error)
        
        valid_password, password_error = SecurityValidator.validate_password(password)
        if not valid_password:
            raise ValueError(password_error)
        
        email = email.strip().lower()
        name = name.strip()
        
        # Check if user already exists
        if self.get_user_by_email(email):
            raise ValueError("User with this email already exists")
        
        user = User(
            id=SecurityValidator.generate_secure_id(),
            name=name,
            email=email,
            password_hash=SecurityValidator.hash_password(password)
        )
        
        try:
            with db.transaction() as conn:
                conn.execute("""
                    INSERT INTO users (id, name, email, password_hash, subscription,
                                     created_at, updated_at, is_active, preferences)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    user.id, user.name, user.email, user.password_hash,
                    user.subscription, user.created_at, user.updated_at,
                    user.is_active, json.dumps(user.preferences)
                ))
                
                logger.info(f"User created: {email}")
                return user
                
        except sqlite3.IntegrityError as e:
            if "UNIQUE constraint failed: users.email" in str(e):
                raise ValueError("User with this email already exists")
            raise ValueError(f"Failed to create user: {e}")
        except Exception as e:
            logger.error(f"Error creating user {email}: {e}")
            raise ValueError(f"Failed to create user: {e}")
    
    def get_user_by_email(self, email: str) -> Optional[User]:
        """Get user by email with caching"""
        if not email:
            return None
        
        email = email.strip().lower()
        cache_key = f"user:email:{email}"
        
        # Try cache first
        cached_user = cache.get(cache_key)
        if cached_user:
            return User.from_dict(cached_user)
        
        try:
            with db.get_connection() as conn:
                row = conn.execute("""
                    SELECT id, name, email, password_hash, subscription,
                           subscription_expires_at, stripe_customer_id,
                           created_at, updated_at, last_login_at,
                           login_attempts, locked_until, is_active, preferences
                    FROM users WHERE email = ? AND is_active = 1
                """, (email,)).fetchone()
                
                if not row:
                    return None
                
                user_data = dict(row)
                
                # Parse JSON fields
                if user_data['preferences']:
                    user_data['preferences'] = json.loads(user_data['preferences'])
                else:
                    user_data['preferences'] = {}
                
                # Parse datetime fields
                for field in ['created_at', 'updated_at', 'last_login_at', 'locked_until', 'subscription_expires_at']:
                    if user_data[field]:
                        user_data[field] = datetime.fromisoformat(user_data[field].replace('Z', ''))
                
                user = User.from_dict(user_data)
                
                # Cache the result
                cache.set(cache_key, user.to_dict(), ttl=self._cache_ttl)
                
                return user
                
        except Exception as e:
            logger.error(f"Error getting user by email {email}: {e}")
            return None
    
    def get_user_by_id(self, user_id: str) -> Optional[User]:
        """Get user by ID with caching"""
        if not user_id:
            return None
        
        cache_key = f"user:id:{user_id}"
        
        # Try cache first
        cached_user = cache.get(cache_key)
        if cached_user:
            return User.from_dict(cached_user)
        
        try:
            with db.get_connection() as conn:
                row = conn.execute("""
                    SELECT id, name, email, password_hash, subscription,
                           subscription_expires_at, stripe_customer_id,
                           created_at, updated_at, last_login_at,
                           login_attempts, locked_until, is_active, preferences
                    FROM users WHERE id = ? AND is_active = 1
                """, (user_id,)).fetchone()
                
                if not row:
                    return None
                
                user_data = dict(row)
                
                # Parse JSON fields
                if user_data['preferences']:
                    user_data['preferences'] = json.loads(user_data['preferences'])
                else:
                    user_data['preferences'] = {}
                
                # Parse datetime fields
                for field in ['created_at', 'updated_at', 'last_login_at', 'locked_until', 'subscription_expires_at']:
                    if user_data[field]:
                        user_data[field] = datetime.fromisoformat(user_data[field].replace('Z', ''))
                
                user = User.from_dict(user_data)
                
                # Cache the result
                cache.set(cache_key, user.to_dict(), ttl=self._cache_ttl)
                
                return user
                
        except Exception as e:
            logger.error(f"Error getting user by ID {user_id}: {e}")
            return None
    
    def update_user(self, user_id: str, updates: Dict[str, Any]) -> bool:
        """Update user with cache invalidation"""
        if not user_id or not updates:
            return False
        
        # Get current user to validate email changes
        current_user = self.get_user_by_id(user_id)
        if not current_user:
            return False
        
        # Validate email if being updated
        if 'email' in updates:
            valid_email, error = SecurityValidator.validate_email(updates['email'])
            if not valid_email:
                raise ValueError(error)
            updates['email'] = updates['email'].strip().lower()
            
            # Check for email conflicts
            if updates['email'] != current_user.email:
                existing = self.get_user_by_email(updates['email'])
                if existing and existing.id != user_id:
                    raise ValueError("Email already in use by another account")
        
        # Validate name if being updated
        if 'name' in updates:
            valid_name, error = SecurityValidator.validate_name(updates['name'])
            if not valid_name:
                raise ValueError(error)
            updates['name'] = updates['name'].strip()
        
        # Always update the updated_at timestamp
        updates['updated_at'] = datetime.utcnow()
        
        try:
            with db.transaction() as conn:
                # Build dynamic update query
                set_clauses = []
                params = []
                
                for key, value in updates.items():
                    if key == 'preferences':
                        set_clauses.append(f"{key} = ?")
                        params.append(json.dumps(value))
                    elif isinstance(value, datetime):
                        set_clauses.append(f"{key} = ?")
                        params.append(value.isoformat() + 'Z')
                    else:
                        set_clauses.append(f"{key} = ?")
                        params.append(value)
                
                params.append(user_id)
                
                query = f"""
                    UPDATE users SET {', '.join(set_clauses)}
                    WHERE id = ? AND is_active = 1
                """
                
                result = conn.execute(query, params)
                
                if result.rowcount == 0:
                    return False
                
                # Invalidate cache
                self._invalidate_user_cache(current_user.email, user_id)
                
                logger.info(f"User updated: {user_id}")
                return True
                
        except sqlite3.IntegrityError as e:
            if "UNIQUE constraint failed: users.email" in str(e):
                raise ValueError("Email already in use by another account")
            raise ValueError(f"Failed to update user: {e}")
        except Exception as e:
            logger.error(f"Error updating user {user_id}: {e}")
            return False
    
    def authenticate_user(self, email: str, password: str, ip_address: str = None) -> Tuple[Optional[User], str]:
        """Authenticate user with login attempt tracking"""
        if not email or not password:
            return None, "Email and password are required"
        
        user = self.get_user_by_email(email)
        if not user:
            # Prevent user enumeration by taking same time as real auth
            SecurityValidator.check_password("dummy_hash", password)
            return None, "Invalid email or password"
        
        # Check if account is locked
        if user.is_account_locked():
            time_left = (user.locked_until - datetime.utcnow()).total_seconds()
            return None, f"Account locked. Try again in {int(time_left/60)} minutes"
        
        # Check password
        if not SecurityValidator.check_password(user.password_hash, password):
            # Increment failed login attempts
            self._handle_failed_login(user)
            return None, "Invalid email or password"
        
        # Successful login - reset attempts and update last login
        self._handle_successful_login(user, ip_address)
        
        return user, ""
    
    def _handle_failed_login(self, user: User):
        """Handle failed login attempt"""
        attempts = user.login_attempts + 1
        updates = {'login_attempts': attempts}
        
        # Lock account if too many attempts
        if attempts >= config.MAX_LOGIN_ATTEMPTS:
            lockout_duration = timedelta(minutes=15)  # 15 minute lockout
            updates['locked_until'] = datetime.utcnow() + lockout_duration
            logger.warning(f"Account locked due to failed login attempts: {user.email}")
        
        self.update_user(user.id, updates)
    
    def _handle_successful_login(self, user: User, ip_address: str = None):
        """Handle successful login"""
        updates = {
            'last_login_at': datetime.utcnow(),
            'login_attempts': 0,
            'locked_until': None
        }
        
        self.update_user(user.id, updates)
        logger.info(f"User login successful: {user.email}")
    
    def deactivate_user(self, user_id: str) -> bool:
        """Soft delete user account"""
        try:
            with db.transaction() as conn:
                result = conn.execute("""
                    UPDATE users SET is_active = 0, updated_at = ?
                    WHERE id = ? AND is_active = 1
                """, (datetime.utcnow(), user_id))
                
                if result.rowcount == 0:
                    return False
                
                # Invalidate cache
                user = self.get_user_by_id(user_id)
                if user:
                    self._invalidate_user_cache(user.email, user_id)
                
                logger.info(f"User deactivated: {user_id}")
                return True
                
        except Exception as e:
            logger.error(f"Error deactivating user {user_id}: {e}")
            return False
    
    def _invalidate_user_cache(self, email: str, user_id: str):
        """Invalidate user cache entries"""
        if email:
            cache.delete(f"user:email:{email.lower()}")
        if user_id:
            cache.delete(f"user:id:{user_id}")

# Global user repository
user_repo = UserRepository()

# =========================
# Authentication Decorators
# =========================

def login_required(f):
    """Require user authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            if request.is_json:
                return jsonify({'error': 'Authentication required'}), 401
            
            # Store the intended destination
            next_url = request.url if request.method == 'GET' else None
            if next_url and _is_safe_url(next_url):
                session['next'] = next_url
            
            return redirect(url_for('login_page'))
        
        # Load user into g for easy access
        g.current_user = user_repo.get_user_by_id(session['user_id'])
        if not g.current_user:
            session.clear()
            return redirect(url_for('login_page'))
        
        return f(*args, **kwargs)
    
    return decorated_function

def admin_required(f):
    """Require admin authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_ok'):
            next_url = request.url if request.method == 'GET' else None
            return redirect(url_for('admin_login_page', next=next_url))
        return f(*args, **kwargs)
    
    return decorated_function

def subscription_required(f):
    """Require active subscription"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # First ensure user is logged in
        if 'user_id' not in session:
            return redirect(url_for('login_page'))
        
        user = getattr(g, 'current_user', None) or user_repo.get_user_by_id(session['user_id'])
        if not user or not user.is_subscription_active():
            if request.is_json:
                return jsonify({'error': 'Active subscription required'}), 402
            
            flash('This feature requires an active subscription.', 'warning')
            return redirect(url_for('billing_page'))
        
        return f(*args, **kwargs)
    
    return decorated_function

# =========================
# Session Management
# =========================

class SessionManager:
    """Enhanced session management"""
    
    def create_session(self, user: User, remember: bool = False) -> str:
        """Create a new user session"""
        try:
            # Regenerate session ID for security
            if hasattr(session, 'regenerate'):
                session.regenerate()
            else:
                # Fallback for older Flask versions
                session.clear()
                session.permanent = remember
            
            # Set session data
            session['user_id'] = user.id
            session['email'] = user.email
            session['name'] = user.name
            session['login_time'] = datetime.utcnow().isoformat()
            
            if remember:
                session.permanent = True
                app.permanent_session_lifetime = timedelta(days=30)
            
            # Store session in database for tracking
            session_id = session.get('_id', secrets.token_urlsafe(32))
            self._store_session_record(session_id, user)
            
            return session_id
            
        except Exception as e:
            logger.error(f"Error creating session for user {user.id}: {e}")
            raise
    
    def destroy_session(self, user_id: str = None):
        """Destroy current session"""
        try:
            session_id = session.get('_id')
            if session_id:
                self._remove_session_record(session_id)
            
            session.clear()
            
            if user_id:
                logger.info(f"Session destroyed for user: {user_id}")
                
        except Exception as e:
            logger.error(f"Error destroying session: {e}")
    
    def _store_session_record(self, session_id: str, user: User):
        """Store session record in database"""
        try:
            expires_at = datetime.utcnow() + app.permanent_session_lifetime
            
            with db.transaction() as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO user_sessions 
                    (id, user_id, created_at, expires_at, ip_address, user_agent)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    session_id, user.id, datetime.utcnow(), expires_at,
                    request.remote_addr, request.user_agent.string[:500] if request.user_agent else None
                ))
                
        except Exception as e:
            logger.error(f"Error storing session record: {e}")
    
    def _remove_session_record(self, session_id: str):
        """Remove session record from database"""
        try:
            with db.transaction() as conn:
                conn.execute("DELETE FROM user_sessions WHERE id = ?", (session_id,))
        except Exception as e:
            logger.error(f"Error removing session record: {e}")
    
    def cleanup_expired_sessions(self):
        """Clean up expired sessions"""
        try:
            with db.transaction() as conn:
                result = conn.execute("""
                    DELETE FROM user_sessions 
                    WHERE expires_at < datetime('now', 'utc')
                """)
                
                if result.rowcount > 0:
                    logger.info(f"Cleaned up {result.rowcount} expired sessions")
                    
        except Exception as e:
            logger.error(f"Error cleaning up expired sessions: {e}")

# Global session manager
session_manager = SessionManager()

# =========================
# Security Utilities
# =========================

def _is_safe_url(target: str) -> bool:
    """Check if URL is safe for redirects"""
    if not target:
        return False
    
    try:
        ref_url = urlparse(request.host_url)
        test_url = urlparse(urljoin(request.host_url, target))
        
        return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc
    except:
        return False

def get_csrf_token() -> str:
    """Get CSRF token with fallback"""
    if HAS_CSRF:
        try:
            return generate_csrf()
        except:
            pass
    return ""

def validate_csrf_token(token: str = None) -> bool:
    """Validate CSRF token with fallback"""
    if not HAS_CSRF:
        return True
    
    try:
        if token is None:
            token = request.form.get('csrf_token') or request.headers.get('X-CSRFToken')
        
        validate_csrf(token)
        return True
    except:
        return False

# =========================
# Request Context Setup
# =========================

@app.before_request
def load_user():
    """Load current user into request context"""
    g.current_user = None
    
    if 'user_id' in session:
        user = user_repo.get_user_by_id(session['user_id'])
        if user and user.is_active:
            g.current_user = user
        else:
            # Clear invalid session
            session.clear()

@app.before_request
def check_account_status():
    """Check if user account is locked or inactive"""
    if g.current_user and g.current_user.is_account_locked():
        session.clear()
        flash('Your account has been temporarily locked. Please try again later.', 'error')
        return redirect(url_for('login_page'))

# =========================
# Template Context
# =========================

@app.context_processor
def inject_template_vars():
    """Inject common template variables"""
    return {
        'current_user': g.get('current_user'),
        'csrf_token': get_csrf_token,
        'config': {
            'APP_VERSION': config.APP_VERSION,
            'IS_STAGING': config.IS_STAGING,
            'STRIPE_PUBLISHABLE_KEY': config.STRIPE_PUBLISHABLE_KEY if HAS_STRIPE else None
        }
    }

logger.info("Section 2: User Management, Authentication, and Security - initialized")
# =========================
# SECTION 3/8: Content Management and Question/Flashcard Systems
# =========================

import json
import hashlib
import random
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Union
from dataclasses import dataclass, field, asdict
from urllib.parse import urlparse
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

# =========================
# Content Models
# =========================

class DifficultyLevel(Enum):
    EASY = "easy"
    MEDIUM = "medium"
    HARD = "hard"

class ContentStatus(Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    PENDING_REVIEW = "pending_review"
    REJECTED = "rejected"

@dataclass
class Source:
    """Source citation model"""
    title: str
    url: str
    
    def __post_init__(self):
        self.title = self.title.strip()
        self.url = self.url.strip()
        
        if not self.title or not self.url:
            raise ValueError("Source title and URL cannot be empty")
        
        # Validate URL format
        try:
            parsed = urlparse(self.url)
            if not parsed.scheme or not parsed.netloc:
                raise ValueError("Invalid URL format")
        except Exception:
            raise ValueError("Invalid URL format")
    
    def to_dict(self) -> Dict[str, str]:
        return {"title": self.title, "url": self.url}
    
    @classmethod
    def from_dict(cls, data: Dict[str, str]) -> 'Source':
        return cls(title=data["title"], url=data["url"])

@dataclass
class Question:
    """Question model with validation"""
    id: str
    question: str
    options: Dict[str, str]  # A, B, C, D -> option text
    correct: str  # A, B, C, or D
    explanation: str = ""
    domain: str = "security-principles"
    difficulty: DifficultyLevel = DifficultyLevel.MEDIUM
    sources: List[Source] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.utcnow())
    updated_at: datetime = field(default_factory=lambda: datetime.utcnow())
    status: ContentStatus = ContentStatus.ACTIVE
    
    def __post_init__(self):
        # Validate question text
        if not self.question.strip():
            raise ValueError("Question text cannot be empty")
        
        # Validate options
        if not isinstance(self.options, dict) or len(self.options) != 4:
            raise ValueError("Question must have exactly 4 options")
        
        required_keys = {"A", "B", "C", "D"}
        if set(self.options.keys()) != required_keys:
            raise ValueError("Options must be keyed as A, B, C, D")
        
        for key, option in self.options.items():
            if not option.strip():
                raise ValueError(f"Option {key} cannot be empty")
        
        # Validate correct answer
        if self.correct not in {"A", "B", "C", "D"}:
            raise ValueError("Correct answer must be A, B, C, or D")
        
        # Validate sources
        if len(self.sources) > 3:
            raise ValueError("Maximum 3 sources allowed")
        
        # Ensure sources are Source objects
        validated_sources = []
        for source in self.sources:
            if isinstance(source, dict):
                validated_sources.append(Source.from_dict(source))
            elif isinstance(source, Source):
                validated_sources.append(source)
            else:
                raise ValueError("Invalid source format")
        self.sources = validated_sources
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        data = asdict(self)
        data['difficulty'] = self.difficulty.value
        data['status'] = self.status.value
        data['sources'] = [source.to_dict() for source in self.sources]
        data['created_at'] = self.created_at.isoformat() + 'Z'
        data['updated_at'] = self.updated_at.isoformat() + 'Z'
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Question':
        """Create Question from dictionary"""
        # Handle datetime fields
        if isinstance(data.get('created_at'), str):
            data['created_at'] = datetime.fromisoformat(data['created_at'].replace('Z', ''))
        if isinstance(data.get('updated_at'), str):
            data['updated_at'] = datetime.fromisoformat(data['updated_at'].replace('Z', ''))
        
        # Handle enum fields
        if isinstance(data.get('difficulty'), str):
            data['difficulty'] = DifficultyLevel(data['difficulty'])
        if isinstance(data.get('status'), str):
            data['status'] = ContentStatus(data['status'])
        
        # Handle sources
        if data.get('sources'):
            data['sources'] = [
                Source.from_dict(source) if isinstance(source, dict) else source
                for source in data['sources']
            ]
        
        return cls(**{k: v for k, v in data.items() if k in cls.__annotations__})
    
    def compute_hash(self) -> str:
        """Compute content hash for deduplication"""
        content = {
            "question": self.question.lower().strip(),
            "options": {k: v.lower().strip() for k, v in self.options.items()},
            "correct": self.correct,
            "domain": self.domain.lower(),
            "sources": [{"title": s.title.lower(), "url": s.url.lower()} for s in self.sources]
        }
        return hashlib.sha256(json.dumps(content, sort_keys=True).encode()).hexdigest()

@dataclass
class Flashcard:
    """Flashcard model with validation"""
    id: str
    front: str
    back: str
    domain: str = "security-principles"
    sources: List[Source] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.utcnow())
    updated_at: datetime = field(default_factory=lambda: datetime.utcnow())
    status: ContentStatus = ContentStatus.ACTIVE
    
    def __post_init__(self):
        # Validate content
        if not self.front.strip():
            raise ValueError("Flashcard front cannot be empty")
        if not self.back.strip():
            raise ValueError("Flashcard back cannot be empty")
        
        # Validate sources
        if len(self.sources) > 3:
            raise ValueError("Maximum 3 sources allowed")
        
        # Ensure sources are Source objects
        validated_sources = []
        for source in self.sources:
            if isinstance(source, dict):
                validated_sources.append(Source.from_dict(source))
            elif isinstance(source, Source):
                validated_sources.append(source)
            else:
                raise ValueError("Invalid source format")
        self.sources = validated_sources
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        data = asdict(self)
        data['status'] = self.status.value
        data['sources'] = [source.to_dict() for source in self.sources]
        data['created_at'] = self.created_at.isoformat() + 'Z'
        data['updated_at'] = self.updated_at.isoformat() + 'Z'
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Flashcard':
        """Create Flashcard from dictionary"""
        # Handle datetime fields
        if isinstance(data.get('created_at'), str):
            data['created_at'] = datetime.fromisoformat(data['created_at'].replace('Z', ''))
        if isinstance(data.get('updated_at'), str):
            data['updated_at'] = datetime.fromisoformat(data['updated_at'].replace('Z', ''))
        
        # Handle enum fields
        if isinstance(data.get('status'), str):
            data['status'] = ContentStatus(data['status'])
        
        # Handle sources
        if data.get('sources'):
            data['sources'] = [
                Source.from_dict(source) if isinstance(source, dict) else source
                for source in data['sources']
            ]
        
        return cls(**{k: v for k, v in data.items() if k in cls.__annotations__})
    
    def compute_hash(self) -> str:
        """Compute content hash for deduplication"""
        content = {
            "front": self.front.lower().strip(),
            "back": self.back.lower().strip(),
            "domain": self.domain.lower(),
            "sources": [{"title": s.title.lower(), "url": s.url.lower()} for s in self.sources]
        }
        return hashlib.sha256(json.dumps(content, sort_keys=True).encode()).hexdigest()

# =========================
# Domain Configuration
# =========================

class DomainManager:
    """Manages CPP exam domains and their properties"""
    
    DOMAINS = {
        "security-principles": {
            "name": "Security Principles",
            "color": "primary",
            "description": "Fundamental security concepts and frameworks"
        },
        "business-principles": {
            "name": "Business Principles", 
            "color": "secondary",
            "description": "Business continuity and organizational security"
        },
        "investigations": {
            "name": "Investigations",
            "color": "info", 
            "description": "Security investigations and incident response"
        },
        "personnel-security": {
            "name": "Personnel Security",
            "color": "success",
            "description": "Personnel screening and security awareness"
        },
        "physical-security": {
            "name": "Physical Security",
            "color": "warning",
            "description": "Physical protection systems and access control"
        },
        "information-security": {
            "name": "Information Security",
            "color": "dark",
            "description": "Data protection and cybersecurity"
        },
        "crisis-management": {
            "name": "Crisis & Continuity",
            "color": "danger",
            "description": "Emergency response and business continuity"
        }
    }
    
    @classmethod
    def get_domain_name(cls, domain_key: str) -> str:
        """Get human-readable domain name"""
        return cls.DOMAINS.get(domain_key, {}).get("name", domain_key)
    
    @classmethod
    def get_domain_color(cls, domain_key: str) -> str:
        """Get Bootstrap color class for domain"""
        return cls.DOMAINS.get(domain_key, {}).get("color", "primary")
    
    @classmethod
    def get_all_domains(cls) -> Dict[str, Dict[str, str]]:
        """Get all domains configuration"""
        return cls.DOMAINS.copy()
    
    @classmethod
    def is_valid_domain(cls, domain_key: str) -> bool:
        """Check if domain key is valid"""
        return domain_key in cls.DOMAINS

# =========================
# Source Validation
# =========================

class SourceValidator:
    """Validates content sources against whitelist"""
    
    ALLOWED_DOMAINS = {
        # Government & standards
        "nist.gov", "cisa.gov", "fema.gov", "osha.gov", "gao.gov",
        "fbi.gov", "dhs.gov", "ready.gov",
        
        # Research & practice
        "popcenter.asu.edu",  # POP Center
        "ncpc.org",           # National Crime Prevention Council
        "rand.org",
        "hsdl.org",           # Homeland Security Digital Library
        
        # Professional organizations (limited)
        "nfpa.org",           # National Fire Protection Association
        "iso.org",            # International Organization for Standardization
        
        # Government sites (state/local)
        "ca.gov", "ny.gov", "tx.gov", "wa.gov", "mass.gov",
        "phila.gov", "denvergov.org", "boston.gov", "chicago.gov",
        "seattle.gov", "sandiego.gov", "lacounty.gov"
    }
    
    @classmethod
    def is_domain_allowed(cls, url: str) -> bool:
        """Check if URL domain is in whitelist"""
        try:
            domain = urlparse(url).netloc.lower()
            if not domain:
                return False
            
            # Check exact match or subdomain
            for allowed in cls.ALLOWED_DOMAINS:
                if domain == allowed or domain.endswith('.' + allowed):
                    return True
            
            return False
            
        except Exception:
            return False
    
    @classmethod
    def validate_sources(cls, sources: List[Union[Source, Dict[str, str]]]) -> Tuple[bool, str]:
        """Validate list of sources"""
        if not sources or len(sources) == 0:
            return False, "At least one source is required"
        
        if len(sources) > 3:
            return False, "Maximum 3 sources allowed"
        
        for i, source in enumerate(sources):
            if isinstance(source, dict):
                title = source.get("title", "").strip()
                url = source.get("url", "").strip()
            elif isinstance(source, Source):
                title = source.title.strip()
                url = source.url.strip()
            else:
                return False, f"Source {i+1}: Invalid format"
            
            if not title or not url:
                return False, f"Source {i+1}: Title and URL are required"
            
            if not cls.is_domain_allowed(url):
                return False, f"Source {i+1}: Domain not allowed ({urlparse(url).netloc})"
        
        return True, ""

# =========================
# Content Repositories
# =========================

class QuestionRepository:
    """Database operations for questions"""
    
    def __init__(self):
        self._cache_ttl = 600  # 10 minutes
        self._lock = threading.RLock()
    
    def create_question(self, question_data: Dict[str, Any]) -> Optional[Question]:
        """Create a new question with validation and deduplication"""
        try:
            # Create question object (validates automatically)
            question = Question.from_dict(question_data)
            
            # Check for duplicates
            content_hash = question.compute_hash()
            if self._hash_exists(content_hash):
                raise ValueError("Question with similar content already exists")
            
            with db.transaction() as conn:
                # Insert question
                conn.execute("""
                    INSERT INTO questions (id, question, options, correct, explanation, 
                                         domain, difficulty, sources, created_at, updated_at, is_active)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    question.id, question.question, json.dumps(question.options),
                    question.correct, question.explanation, question.domain,
                    question.difficulty.value, json.dumps([s.to_dict() for s in question.sources]),
                    question.created_at, question.updated_at, question.status == ContentStatus.ACTIVE
                ))
                
                # Store content hash
                conn.execute("""
                    INSERT INTO content_hashes (hash, content_type, content_id)
                    VALUES (?, 'question', ?)
                """, (content_hash, question.id))
                
                logger.info(f"Question created: {question.id}")
                
                # Invalidate cache
                self._invalidate_cache()
                
                return question
                
        except Exception as e:
            logger.error(f"Error creating question: {e}")
            raise
    
    def get_question_by_id(self, question_id: str) -> Optional[Question]:
        """Get question by ID"""
        try:
            with db.get_connection() as conn:
                row = conn.execute("""
                    SELECT id, question, options, correct, explanation, domain, 
                           difficulty, sources, created_at, updated_at, is_active
                    FROM questions WHERE id = ?
                """, (question_id,)).fetchone()
                
                if not row:
                    return None
                
                return self._row_to_question(row)
                
        except Exception as e:
            logger.error(f"Error getting question {question_id}: {e}")
            return None
    
    def get_questions(self, domain: str = None, difficulty: DifficultyLevel = None, 
                     limit: int = None, active_only: bool = True) -> List[Question]:
        """Get questions with filtering"""
        cache_key = f"questions:{domain or 'all'}:{difficulty.value if difficulty else 'all'}:{limit or 'all'}:{active_only}"
        
        # Try cache first
        cached = cache.get(cache_key)
        if cached:
            return [Question.from_dict(q) for q in cached]
        
        try:
            query_parts = ["SELECT id, question, options, correct, explanation, domain, difficulty, sources, created_at, updated_at, is_active FROM questions WHERE 1=1"]
            params = []
            
            if active_only:
                query_parts.append("AND is_active = 1")
            
            if domain and domain != "random":
                query_parts.append("AND domain = ?")
                params.append(domain)
            
            if difficulty:
                query_parts.append("AND difficulty = ?")
                params.append(difficulty.value)
            
            query_parts.append("ORDER BY created_at DESC")
            
            if limit:
                query_parts.append("LIMIT ?")
                params.append(limit)
            
            query = " ".join(query_parts)
            
            with db.get_connection() as conn:
                rows = conn.execute(query, params).fetchall()
                
                questions = [self._row_to_question(row) for row in rows]
                
                # Cache results
                cache.set(cache_key, [q.to_dict() for q in questions], ttl=self._cache_ttl)
                
                return questions
                
        except Exception as e:
            logger.error(f"Error getting questions: {e}")
            return []
    
    def get_random_questions(self, count: int, domain: str = None, 
                            difficulty: DifficultyLevel = None) -> List[Question]:
        """Get random questions with optional filtering"""
        questions = self.get_questions(domain=domain, difficulty=difficulty, active_only=True)
        
        if not questions:
            return []
        
        # Shuffle and take requested count
        random.shuffle(questions)
        return questions[:min(count, len(questions))]
    
    def update_question(self, question_id: str, updates: Dict[str, Any]) -> bool:
        """Update question"""
        try:
            current_question = self.get_question_by_id(question_id)
            if not current_question:
                return False
            
            # Apply updates
            question_data = current_question.to_dict()
            question_data.update(updates)
            question_data['updated_at'] = datetime.utcnow()
            
            # Validate updated question
            updated_question = Question.from_dict(question_data)
            
            with db.transaction() as conn:
                conn.execute("""
                    UPDATE questions SET question = ?, options = ?, correct = ?, 
                           explanation = ?, domain = ?, difficulty = ?, sources = ?, updated_at = ?
                    WHERE id = ?
                """, (
                    updated_question.question, json.dumps(updated_question.options),
                    updated_question.correct, updated_question.explanation,
                    updated_question.domain, updated_question.difficulty.value,
                    json.dumps([s.to_dict() for s in updated_question.sources]),
                    updated_question.updated_at, question_id
                ))
                
                logger.info(f"Question updated: {question_id}")
                
                # Invalidate cache
                self._invalidate_cache()
                
                return True
                
        except Exception as e:
            logger.error(f"Error updating question {question_id}: {e}")
            return False
    
    def delete_question(self, question_id: str) -> bool:
        """Soft delete question"""
        try:
            with db.transaction() as conn:
                result = conn.execute("""
                    UPDATE questions SET is_active = 0, updated_at = ?
                    WHERE id = ?
                """, (datetime.utcnow(), question_id))
                
                if result.rowcount > 0:
                    logger.info(f"Question deleted: {question_id}")
                    self._invalidate_cache()
                    return True
                
                return False
                
        except Exception as e:
            logger.error(f"Error deleting question {question_id}: {e}")
            return False
    
    def get_domain_counts(self) -> Dict[str, int]:
        """Get question counts by domain"""
        try:
            with db.get_connection() as conn:
                rows = conn.execute("""
                    SELECT domain, COUNT(*) as count
                    FROM questions WHERE is_active = 1
                    GROUP BY domain
                """).fetchall()
                
                return {row['domain']: row['count'] for row in rows}
                
        except Exception as e:
            logger.error(f"Error getting domain counts: {e}")
            return {}
    
    def _row_to_question(self, row) -> Question:
        """Convert database row to Question object"""
        data = dict(row)
        
        # Parse JSON fields
        data['options'] = json.loads(data['options'])
        data['sources'] = [Source.from_dict(s) for s in json.loads(data['sources'] or '[]')]
        
        # Convert datetime strings
        data['created_at'] = datetime.fromisoformat(data['created_at'].replace('Z', ''))
        data['updated_at'] = datetime.fromisoformat(data['updated_at'].replace('Z', ''))
        
        # Convert difficulty
        data['difficulty'] = DifficultyLevel(data['difficulty'])
        
        # Convert status
        data['status'] = ContentStatus.ACTIVE if data['is_active'] else ContentStatus.INACTIVE
        del data['is_active']
        
        return Question.from_dict(data)
    
    def _hash_exists(self, content_hash: str) -> bool:
        """Check if content hash already exists"""
        try:
            with db.get_connection() as conn:
                row = conn.execute("""
                    SELECT 1 FROM content_hashes 
                    WHERE hash = ? AND content_type = 'question'
                """, (content_hash,)).fetchone()
                
                return row is not None
                
        except Exception:
            return False
    
    def _invalidate_cache(self):
        """Invalidate all question-related cache entries"""
        # This is a simple implementation - in production you might want more targeted invalidation
        if hasattr(cache, '_redis_client') and cache._redis_client:
            try:
                keys = cache._redis_client.keys("questions:*")
                if keys:
                    cache._redis_client.delete(*keys)
            except Exception:
                pass

class FlashcardRepository:
    """Database operations for flashcards"""
    
    def __init__(self):
        self._cache_ttl = 600  # 10 minutes
        self._lock = threading.RLock()
    
    def create_flashcard(self, flashcard_data: Dict[str, Any]) -> Optional[Flashcard]:
        """Create a new flashcard with validation and deduplication"""
        try:
            # Create flashcard object (validates automatically)
            flashcard = Flashcard.from_dict(flashcard_data)
            
            # Check for duplicates
            content_hash = flashcard.compute_hash()
            if self._hash_exists(content_hash):
                raise ValueError("Flashcard with similar content already exists")
            
            with db.transaction() as conn:
                # Insert flashcard
                conn.execute("""
                    INSERT INTO flashcards (id, front, back, domain, sources, 
                                          created_at, updated_at, is_active)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    flashcard.id, flashcard.front, flashcard.back, flashcard.domain,
                    json.dumps([s.to_dict() for s in flashcard.sources]),
                    flashcard.created_at, flashcard.updated_at,
                    flashcard.status == ContentStatus.ACTIVE
                ))
                
                # Store content hash
                conn.execute("""
                    INSERT INTO content_hashes (hash, content_type, content_id)
                    VALUES (?, 'flashcard', ?)
                """, (content_hash, flashcard.id))
                
                logger.info(f"Flashcard created: {flashcard.id}")
                
                # Invalidate cache
                self._invalidate_cache()
                
                return flashcard
                
        except Exception as e:
            logger.error(f"Error creating flashcard: {e}")
            raise
    
    def get_flashcard_by_id(self, flashcard_id: str) -> Optional[Flashcard]:
        """Get flashcard by ID"""
        try:
            with db.get_connection() as conn:
                row = conn.execute("""
                    SELECT id, front, back, domain, sources, created_at, updated_at, is_active
                    FROM flashcards WHERE id = ?
                """, (flashcard_id,)).fetchone()
                
                if not row:
                    return None
                
                return self._row_to_flashcard(row)
                
        except Exception as e:
            logger.error(f"Error getting flashcard {flashcard_id}: {e}")
            return None
    
    def get_flashcards(self, domain: str = None, limit: int = None, 
                      active_only: bool = True) -> List[Flashcard]:
        """Get flashcards with filtering"""
        cache_key = f"flashcards:{domain or 'all'}:{limit or 'all'}:{active_only}"
        
        # Try cache first
        cached = cache.get(cache_key)
        if cached:
            return [Flashcard.from_dict(f) for f in cached]
        
        try:
            query_parts = ["SELECT id, front, back, domain, sources, created_at, updated_at, is_active FROM flashcards WHERE 1=1"]
            params = []
            
            if active_only:
                query_parts.append("AND is_active = 1")
            
            if domain and domain != "random":
                query_parts.append("AND domain = ?")
                params.append(domain)
            
            query_parts.append("ORDER BY created_at DESC")
            
            if limit:
                query_parts.append("LIMIT ?")
                params.append(limit)
            
            query = " ".join(query_parts)
            
            with db.get_connection() as conn:
                rows = conn.execute(query, params).fetchall()
                
                flashcards = [self._row_to_flashcard(row) for row in rows]
                
                # Cache results
                cache.set(cache_key, [f.to_dict() for f in flashcards], ttl=self._cache_ttl)
                
                return flashcards
                
        except Exception as e:
            logger.error(f"Error getting flashcards: {e}")
            return []
    
    def get_random_flashcards(self, count: int, domain: str = None) -> List[Flashcard]:
        """Get random flashcards with optional filtering"""
        flashcards = self.get_flashcards(domain=domain, active_only=True)
        
        if not flashcards:
            return []
        
        # Shuffle and take requested count
        random.shuffle(flashcards)
        return flashcards[:min(count, len(flashcards))]
    
    def update_flashcard(self, flashcard_id: str, updates: Dict[str, Any]) -> bool:
        """Update flashcard"""
        try:
            current_flashcard = self.get_flashcard_by_id(flashcard_id)
            if not current_flashcard:
                return False
            
            # Apply updates
            flashcard_data = current_flashcard.to_dict()
            flashcard_data.update(updates)
            flashcard_data['updated_at'] = datetime.utcnow()
            
            # Validate updated flashcard
            updated_flashcard = Flashcard.from_dict(flashcard_data)
            
            with db.transaction() as conn:
                conn.execute("""
                    UPDATE flashcards SET front = ?, back = ?, domain = ?, 
                           sources = ?, updated_at = ?
                    WHERE id = ?
                """, (
                    updated_flashcard.front, updated_flashcard.back,
                    updated_flashcard.domain,
                    json.dumps([s.to_dict() for s in updated_flashcard.sources]),
                    updated_flashcard.updated_at, flashcard_id
                ))
                
                logger.info(f"Flashcard updated: {flashcard_id}")
                
                # Invalidate cache
                self._invalidate_cache()
                
                return True
                
        except Exception as e:
            logger.error(f"Error updating flashcard {flashcard_id}: {e}")
            return False
    
    def delete_flashcard(self, flashcard_id: str) -> bool:
        """Soft delete flashcard"""
        try:
            with db.transaction() as conn:
                result = conn.execute("""
                    UPDATE flashcards SET is_active = 0, updated_at = ?
                    WHERE id = ?
                """, (datetime.utcnow(), flashcard_id))
                
                if result.rowcount > 0:
                    logger.info(f"Flashcard deleted: {flashcard_id}")
                    self._invalidate_cache()
                    return True
                
                return False
                
        except Exception as e:
            logger.error(f"Error deleting flashcard {flashcard_id}: {e}")
            return False
    
    def get_domain_counts(self) -> Dict[str, int]:
        """Get flashcard counts by domain"""
        try:
            with db.get_connection() as conn:
                rows = conn.execute("""
                    SELECT domain, COUNT(*) as count
                    FROM flashcards WHERE is_active = 1
                    GROUP BY domain
                """).fetchall()
                
                return {row['domain']: row['count'] for row in rows}
                
        except Exception as e:
            logger.error(f"Error getting domain counts: {e}")
            return {}
    
    def _row_to_flashcard(self, row) -> Flashcard:
        """Convert database row to Flashcard object"""
        data = dict(row)
        
        # Parse JSON fields
        data['sources'] = [Source.from_dict(s) for s in json.loads(data['sources'] or '[]')]
        
        # Convert datetime strings
        data['created_at'] = datetime.fromisoformat(data['created_at'].replace('Z', ''))
        data['updated_at'] = datetime.fromisoformat(data['updated_at'].replace('Z', ''))
        
        # Convert status
        data['status'] = ContentStatus.ACTIVE if data['is_active'] else ContentStatus.INACTIVE
        del data['is_active']
        
        return Flashcard.from_dict(data)
    
    def _hash_exists(self, content_hash: str) -> bool:
        """Check if content hash already exists"""
        try:
            with db.get_connection() as conn:
                row = conn.execute("""
                    SELECT 1 FROM content_hashes 
                    WHERE hash = ? AND content_type = 'flashcard'
                """, (content_hash,)).fetchone()
                
                return row is not None
                
        except Exception:
            return False
    
    def _invalidate_cache(self):
        """Invalidate all flashcard-related cache entries"""
        if hasattr(cache, '_redis_client') and cache._redis_client:
            try:
                keys = cache._redis_client.keys("flashcards:*")
                if keys:
                    cache._redis_client.delete(*keys)
            except Exception:
                pass

# =========================
# Content Services
# =========================

class ContentService:
    """High-level content management service"""
    
    def __init__(self):
        self.question_repo = QuestionRepository()
        self.flashcard_repo = FlashcardRepository()
        self.source_validator = SourceValidator()
        self.domain_manager = DomainManager()
    
    def create_questions_batch(self, questions_data: List[Dict[str, Any]]) -> Tuple[List[Question], List[str]]:
        """Create multiple questions with validation"""
        created_questions = []
        errors = []
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_data = {
                executor.submit(self._create_single_question, data): i 
                for i, data in enumerate(questions_data)
            }
            
            for future in as_completed(future_to_data):
                index = future_to_data[future]
                try:
                    question = future.result()
                    if question:
                        created_questions.append(question)
                    else:
                        errors.append(f"Question {index + 1}: Failed to create")
                except Exception as e:
                    errors.append(f"Question {index + 1}: {str(e)}")
        
        return created_questions, errors
    
    def create_flashcards_batch(self, flashcards_data: List[Dict[str, Any]]) -> Tuple[List[Flashcard], List[str]]:
        """Create multiple flashcards with validation"""
        created_flashcards = []
        errors = []
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_data = {
                executor.submit(self._create_single_flashcard, data): i 
                for i, data in enumerate(flashcards_data)
            }
            
            for future in as_completed(future_to_data):
                index = future_to_data[future]
                try:
                    flashcard = future.result()
                    if flashcard:
                        created_flashcards.append(flashcard)
                    else:
                        errors.append(f"Flashcard {index + 1}: Failed to create")
                except Exception as e:
                    errors.append(f"Flashcard {index + 1}: {str(e)}")
        
        return created_flashcards, errors
    
    def _create_single_question(self, data: Dict[str, Any]) -> Optional[Question]:
        """Create a single question with full validation"""
        try:
            # Normalize and validate data
            normalized_data = self._normalize_question_data(data)
            
            # Validate sources
            if normalized_data.get('sources'):
                valid, error = self.source_validator.validate_sources(normalized_data['sources'])
                if not valid:
                    raise ValueError(error)
            
            return self.question_repo.create_question(normalized_data)
            
        except Exception as e:
            logger.error(f"Error creating question: {e}")
            raise
    
    def _create_single_flashcard(self, data: Dict[str, Any]) -> Optional[Flashcard]:
        """Create a single flashcard with full validation"""
        try:
            # Normalize and validate data
            normalized_data = self._normalize_flashcard_data(data)
            
            # Validate sources
            if normalized_data.get('sources'):
                valid, error = self.source_validator.validate_sources(normalized_data['sources'])
                if not valid:
                    raise ValueError(error)
            
            return self.flashcard_repo.create_flashcard(normalized_data)
            
        except Exception as e:
            logger.error(f"Error creating flashcard: {e}")
            raise
    
    def _normalize_question_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize question data from various input formats"""
        # Generate ID if not provided
        if 'id' not in data:
            data['id'] = SecurityValidator.generate_secure_id()
        
        # Normalize question text
        question_text = (
            data.get('question') or 
            data.get('q') or 
            data.get('stem') or 
            data.get('text', '')
        ).strip()
        
        if not question_text:
            raise ValueError("Question text is required")
        
        data['question'] = question_text
        
        # Normalize options
        options = data.get('options') or data.get('choices') or data.get('answers')
        if isinstance(options, dict):
            # Already in correct format
            normalized_options = {}
            for key in ['A', 'B', 'C', 'D']:
                value = options.get(key) or options.get(key.lower())
                if not value:
                    raise ValueError(f"Missing option {key}")
                normalized_options[key] = str(value).strip()
        elif isinstance(options, list) and len(options) >= 4:
            # Convert from list format
            normalized_options = {}
            letters = ['A', 'B', 'C', 'D']
            for i, letter in enumerate(letters):
                if i < len(options):
                    option_text = options[i]
                    if isinstance(option_text, dict):
                        option_text = option_text.get('text', str(option_text))
                    normalized_options[letter] = str(option_text).strip()
                else:
                    raise ValueError(f"Missing option {letter}")
        else:
            raise ValueError("Options must be provided as dict or list with 4 items")
        
        data['options'] = normalized_options
        
        # Normalize correct answer
        correct = data.get('correct') or data.get('answer') or data.get('correct_key')
        if isinstance(correct, str) and correct.upper() in ['A', 'B', 'C', 'D']:
            data['correct'] = correct.upper()
        elif isinstance(correct, int) and 1 <= correct <= 4:
            data['correct'] = ['A', 'B', 'C', 'D'][correct - 1]
        else:
            raise ValueError("Correct answer must be A/B/C/D or 1-4")
        
        # Normalize domain
        domain = data.get('domain') or data.get('category') or 'security-principles'
        if not self.domain_manager.is_valid_domain(domain):
            domain = 'security-principles'
        data['domain'] = domain
        
        # Normalize difficulty
        difficulty = data.get('difficulty', 'medium')
        if difficulty not in ['easy', 'medium', 'hard']:
            difficulty = 'medium'
        data['difficulty'] = difficulty
        
        # Normalize explanation
        data['explanation'] = (data.get('explanation') or '').strip()
        
        # Normalize sources
        sources = data.get('sources', [])
        if not isinstance(sources, list):
            sources = []
        
        normalized_sources = []
        for source in sources[:3]:  # Max 3 sources
            if isinstance(source, dict) and source.get('title') and source.get('url'):
                normalized_sources.append({
                    'title': source['title'].strip(),
                    'url': source['url'].strip()
                })
        
        data['sources'] = normalized_sources
        
        return data
    
    def _normalize_flashcard_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize flashcard data from various input formats"""
        # Generate ID if not provided
        if 'id' not in data:
            data['id'] = SecurityValidator.generate_secure_id()
        
        # Normalize front/back text
        front = (
            data.get('front') or 
            data.get('q') or 
            data.get('term', '')
        ).strip()
        
        back = (
            data.get('back') or 
            data.get('a') or 
            data.get('definition', '')
        ).strip()
        
        if not front or not back:
            raise ValueError("Flashcard front and back text are required")
        
        data['front'] = front
        data['back'] = back
        
        # Normalize domain
        domain = data.get('domain') or data.get('category') or 'security-principles'
        if not self.domain_manager.is_valid_domain(domain):
            domain = 'security-principles'
        data['domain'] = domain
        
        # Normalize sources
        sources = data.get('sources', [])
        if not isinstance(sources, list):
            sources = []
        
        normalized_sources = []
        for source in sources[:3]:  # Max 3 sources
            if isinstance(source, dict) and source.get('title') and source.get('url'):
                normalized_sources.append({
                    'title': source['title'].strip(),
                    'url': source['url'].strip()
                })
        
        data['sources'] = normalized_sources
        
        return data

# Global repositories and services
question_repo = QuestionRepository()
flashcard_repo = FlashcardRepository()
content_service = ContentService()

logger.info("Section 3: Content Management and Question/Flashcard Systems - initialized")
# =========================
# SECTION 4/8: Usage Management, Subscription System, and Business Logic
# =========================

import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Union
from dataclasses import dataclass, field, asdict
from enum import Enum
import calendar
from collections import defaultdict
import threading
from functools import wraps

# =========================
# Subscription Models
# =========================

class SubscriptionType(Enum):
    INACTIVE = "inactive"
    MONTHLY = "monthly"
    SIXMONTH = "sixmonth"

class UsageActionType(Enum):
    QUIZ = "quizzes"
    QUESTION = "questions"
    TUTOR_MESSAGE = "tutor_msgs"
    FLASHCARD_SESSION = "flashcards"

@dataclass
class SubscriptionPlan:
    """Subscription plan configuration"""
    type: SubscriptionType
    name: str
    price: float
    duration_days: Optional[int]  # None for recurring monthly
    limits: Dict[UsageActionType, int]  # -1 for unlimited
    features: List[str]
    stripe_price_id: Optional[str] = None
    
    def is_unlimited(self, action_type: UsageActionType) -> bool:
        """Check if action type is unlimited for this plan"""
        return self.limits.get(action_type, 0) == -1
    
    def get_limit(self, action_type: UsageActionType) -> int:
        """Get usage limit for action type (-1 for unlimited)"""
        return self.limits.get(action_type, 0)

@dataclass
class UsageRecord:
    """Individual usage record"""
    user_id: str
    action_type: UsageActionType
    count: int
    period_start: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.utcnow())

@dataclass
class UsageSummary:
    """Usage summary for a period"""
    user_id: str
    period_start: datetime
    period_end: datetime
    usage_by_type: Dict[UsageActionType, int]
    total_usage: int
    
    def get_usage(self, action_type: UsageActionType) -> int:
        """Get usage count for specific action type"""
        return self.usage_by_type.get(action_type, 0)

# =========================
# Subscription Configuration
# =========================

class SubscriptionConfig:
    """Central configuration for subscription plans"""
    
    PLANS = {
        SubscriptionType.INACTIVE: SubscriptionPlan(
            type=SubscriptionType.INACTIVE,
            name="Free Plan",
            price=0.0,
            duration_days=None,
            limits={
                UsageActionType.QUIZ: 0,
                UsageActionType.QUESTION: 0,
                UsageActionType.TUTOR_MESSAGE: 0,
                UsageActionType.FLASHCARD_SESSION: 0
            },
            features=[
                "Account creation",
                "Basic content access",
                "Progress tracking"
            ]
        ),
        
        SubscriptionType.MONTHLY: SubscriptionPlan(
            type=SubscriptionType.MONTHLY,
            name="Monthly Plan",
            price=39.99,
            duration_days=None,  # Recurring
            limits={
                UsageActionType.QUIZ: -1,  # Unlimited
                UsageActionType.QUESTION: -1,
                UsageActionType.TUTOR_MESSAGE: -1,
                UsageActionType.FLASHCARD_SESSION: -1
            },
            features=[
                "Unlimited practice quizzes",
                "AI tutor with instant help",
                "Progress tracking & analytics",
                "Mobile-friendly study",
                "Cancel anytime"
            ],
            stripe_price_id=config.STRIPE_MONTHLY_PRICE_ID
        ),
        
        SubscriptionType.SIXMONTH: SubscriptionPlan(
            type=SubscriptionType.SIXMONTH,
            name="6-Month Plan",
            price=99.00,
            duration_days=180,
            limits={
                UsageActionType.QUIZ: -1,  # Unlimited
                UsageActionType.QUESTION: -1,
                UsageActionType.TUTOR_MESSAGE: -1,
                UsageActionType.FLASHCARD_SESSION: -1
            },
            features=[
                "Everything in Monthly",
                "6 full months of access",
                "No auto-renewal",
                "Save $140+ vs monthly",
                "Extended study time"
            ],
            stripe_price_id=config.STRIPE_SIXMONTH_PRICE_ID
        )
    }
    
    @classmethod
    def get_plan(cls, subscription_type: SubscriptionType) -> SubscriptionPlan:
        """Get plan configuration"""
        return cls.PLANS.get(subscription_type, cls.PLANS[SubscriptionType.INACTIVE])
    
    @classmethod
    def get_all_plans(cls) -> List[SubscriptionPlan]:
        """Get all available plans"""
        return list(cls.PLANS.values())

# =========================
# Usage Repository
# =========================

class UsageRepository:
    """Database operations for usage tracking"""
    
    def __init__(self):
        self._cache_ttl = 300  # 5 minutes
        self._lock = threading.RLock()
    
    def record_usage(self, user_id: str, action_type: UsageActionType, 
                    count: int = 1, metadata: Dict[str, Any] = None) -> bool:
        """Record usage for a user"""
        try:
            period_start = self._get_current_period_start()
            
            with db.transaction() as conn:
                # Check if record exists for this period
                existing = conn.execute("""
                    SELECT id, count FROM user_usage 
                    WHERE user_id = ? AND action_type = ? AND period_start = ?
                """, (user_id, action_type.value, period_start)).fetchone()
                
                if existing:
                    # Update existing record
                    new_count = existing['count'] + count
                    conn.execute("""
                        UPDATE user_usage SET count = ?, created_at = ?
                        WHERE id = ?
                    """, (new_count, datetime.utcnow(), existing['id']))
                else:
                    # Create new record
                    conn.execute("""
                        INSERT INTO user_usage (user_id, action_type, count, period_start, created_at)
                        VALUES (?, ?, ?, ?, ?)
                    """, (user_id, action_type.value, count, period_start, datetime.utcnow()))
                
                # Invalidate cache
                self._invalidate_user_cache(user_id)
                
                logger.info(f"Usage recorded: {user_id} - {action_type.value} - {count}")
                return True
                
        except Exception as e:
            logger.error(f"Error recording usage for {user_id}: {e}")
            return False
    
    def get_usage_summary(self, user_id: str, period_start: datetime = None) -> UsageSummary:
        """Get usage summary for a user and period"""
        if not period_start:
            period_start = self._get_current_period_start()
        
        cache_key = f"usage_summary:{user_id}:{period_start.strftime('%Y-%m')}"
        cached = cache.get(cache_key)
        if cached:
            return UsageSummary(**cached)
        
        try:
            with db.get_connection() as conn:
                rows = conn.execute("""
                    SELECT action_type, SUM(count) as total_count
                    FROM user_usage 
                    WHERE user_id = ? AND period_start = ?
                    GROUP BY action_type
                """, (user_id, period_start)).fetchall()
                
                usage_by_type = {}
                total_usage = 0
                
                for row in rows:
                    try:
                        action_type = UsageActionType(row['action_type'])
                        count = int(row['total_count'])
                        usage_by_type[action_type] = count
                        total_usage += count
                    except ValueError:
                        # Skip unknown action types
                        continue
                
                period_end = self._get_period_end(period_start)
                
                summary = UsageSummary(
                    user_id=user_id,
                    period_start=period_start,
                    period_end=period_end,
                    usage_by_type=usage_by_type,
                    total_usage=total_usage
                )
                
                # Cache the result
                cache.set(cache_key, asdict(summary), ttl=self._cache_ttl)
                
                return summary
                
        except Exception as e:
            logger.error(f"Error getting usage summary for {user_id}: {e}")
            return UsageSummary(
                user_id=user_id,
                period_start=period_start,
                period_end=self._get_period_end(period_start),
                usage_by_type={},
                total_usage=0
            )
    
    def get_usage_history(self, user_id: str, months: int = 6) -> List[UsageSummary]:
        """Get usage history for multiple months"""
        summaries = []
        current_date = datetime.utcnow()
        
        for i in range(months):
            # Calculate period start for i months ago
            if i == 0:
                period_start = self._get_current_period_start()
            else:
                year = current_date.year
                month = current_date.month - i
                
                if month <= 0:
                    month += 12
                    year -= 1
                
                period_start = datetime(year, month, 1)
            
            summary = self.get_usage_summary(user_id, period_start)
            summaries.append(summary)
        
        return summaries
    
    def cleanup_old_usage(self, months_to_keep: int = 24) -> int:
        """Clean up old usage records"""
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=months_to_keep * 30)
            cutoff_period = datetime(cutoff_date.year, cutoff_date.month, 1)
            
            with db.transaction() as conn:
                result = conn.execute("""
                    DELETE FROM user_usage WHERE period_start < ?
                """, (cutoff_period,))
                
                deleted_count = result.rowcount
                if deleted_count > 0:
                    logger.info(f"Cleaned up {deleted_count} old usage records")
                
                return deleted_count
                
        except Exception as e:
            logger.error(f"Error cleaning up old usage records: {e}")
            return 0
    
    def _get_current_period_start(self) -> datetime:
        """Get the start of the current billing period (month)"""
        now = datetime.utcnow()
        return datetime(now.year, now.month, 1)
    
    def _get_period_end(self, period_start: datetime) -> datetime:
        """Get the end of a billing period"""
        if period_start.month == 12:
            return datetime(period_start.year + 1, 1, 1) - timedelta(seconds=1)
        else:
            return datetime(period_start.year, period_start.month + 1, 1) - timedelta(seconds=1)
    
    def _invalidate_user_cache(self, user_id: str):
        """Invalidate usage cache for user"""
        if hasattr(cache, '_redis_client') and cache._redis_client:
            try:
                keys = cache._redis_client.keys(f"usage_summary:{user_id}:*")
                if keys:
                    cache._redis_client.delete(*keys)
            except Exception:
                pass

# =========================
# Subscription Service
# =========================

class SubscriptionService:
    """High-level subscription management"""
    
    def __init__(self):
        self.usage_repo = UsageRepository()
        self._lock = threading.RLock()
    
    def check_usage_limit(self, user: User, action_type: UsageActionType, 
                         count: int = 1) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Check if user can perform an action based on their subscription and usage
        
        Returns:
            (can_perform, message, usage_info)
        """
        try:
            # Get user's subscription plan
            subscription_type = SubscriptionType(user.subscription)
            plan = SubscriptionConfig.get_plan(subscription_type)
            
            # Check if subscription is still active for time-limited plans
            if subscription_type == SubscriptionType.SIXMONTH:
                if not user.subscription_expires_at or user.subscription_expires_at < datetime.utcnow():
                    # Subscription expired - downgrade to inactive
                    user_repo.update_user(user.id, {
                        'subscription': SubscriptionType.INACTIVE.value,
                        'subscription_expires_at': None
                    })
                    plan = SubscriptionConfig.get_plan(SubscriptionType.INACTIVE)
            
            # Get usage limit for this action
            limit = plan.get_limit(action_type)
            
            # If unlimited, allow
            if limit == -1:
                return True, "", {
                    'limit': -1,
                    'used': 0,
                    'remaining': -1,
                    'plan': plan.name
                }
            
            # If limit is 0, deny
            if limit == 0:
                return False, f"Your current plan ({plan.name}) doesn't include this feature. Please upgrade for unlimited access.", {
                    'limit': 0,
                    'used': 0,
                    'remaining': 0,
                    'plan': plan.name
                }
            
            # Check current usage
            usage_summary = self.usage_repo.get_usage_summary(user.id)
            current_usage = usage_summary.get_usage(action_type)
            
            # Check if adding this usage would exceed limit
            if current_usage + count > limit:
                remaining = max(0, limit - current_usage)
                return False, f"Usage limit reached for {plan.name}. You have {remaining} remaining this month.", {
                    'limit': limit,
                    'used': current_usage,
                    'remaining': remaining,
                    'plan': plan.name
                }
            
            # Usage is within limits
            return True, "", {
                'limit': limit,
                'used': current_usage,
                'remaining': limit - current_usage - count,
                'plan': plan.name
            }
            
        except Exception as e:
            logger.error(f"Error checking usage limit for {user.id}: {e}")
            # Fail open - allow the action but log the error
            return True, "", {}
    
    def record_usage(self, user_id: str, action_type: UsageActionType, 
                    count: int = 1, metadata: Dict[str, Any] = None) -> bool:
        """Record usage for a user"""
        return self.usage_repo.record_usage(user_id, action_type, count, metadata)
    
    def get_user_usage_dashboard(self, user: User) -> Dict[str, Any]:
        """Get comprehensive usage dashboard data for user"""
        try:
            # Get subscription plan
            subscription_type = SubscriptionType(user.subscription)
            plan = SubscriptionConfig.get_plan(subscription_type)
            
            # Get current period usage
            current_usage = self.usage_repo.get_usage_summary(user.id)
            
            # Get usage history
            usage_history = self.usage_repo.get_usage_history(user.id, months=6)
            
            # Build dashboard data
            dashboard = {
                'subscription': {
                    'type': subscription_type.value,
                    'name': plan.name,
                    'price': plan.price,
                    'features': plan.features,
                    'expires_at': user.subscription_expires_at.isoformat() + 'Z' if user.subscription_expires_at else None,
                    'is_active': user.is_subscription_active()
                },
                'current_period': {
                    'start': current_usage.period_start.isoformat() + 'Z',
                    'end': current_usage.period_end.isoformat() + 'Z',
                    'total_usage': current_usage.total_usage
                },
                'usage_by_type': {},
                'limits': {},
                'history': []
            }
            
            # Add usage by type with limits
            for action_type in UsageActionType:
                used = current_usage.get_usage(action_type)
                limit = plan.get_limit(action_type)
                
                dashboard['usage_by_type'][action_type.value] = {
                    'used': used,
                    'limit': limit,
                    'remaining': max(0, limit - used) if limit != -1 else -1,
                    'percentage': (used / limit * 100) if limit > 0 else 0
                }
                
                dashboard['limits'][action_type.value] = limit
            
            # Add historical data
            for summary in usage_history:
                dashboard['history'].append({
                    'period': summary.period_start.strftime('%Y-%m'),
                    'total': summary.total_usage,
                    'by_type': {at.value: summary.get_usage(at) for at in UsageActionType}
                })
            
            return dashboard
            
        except Exception as e:
            logger.error(f"Error getting usage dashboard for {user.id}: {e}")
            return {
                'subscription': {'type': 'inactive', 'name': 'Free Plan'},
                'current_period': {'total_usage': 0},
                'usage_by_type': {},
                'limits': {},
                'history': []
            }
    
    def upgrade_subscription(self, user_id: str, new_subscription: SubscriptionType, 
                           expires_at: datetime = None, stripe_customer_id: str = None) -> bool:
        """Upgrade user subscription"""
        try:
            updates = {
                'subscription': new_subscription.value,
                'updated_at': datetime.utcnow()
            }
            
            if expires_at:
                updates['subscription_expires_at'] = expires_at
            
            if stripe_customer_id:
                updates['stripe_customer_id'] = stripe_customer_id
            
            success = user_repo.update_user(user_id, updates)
            
            if success:
                logger.info(f"Subscription upgraded: {user_id} -> {new_subscription.value}")
                
                # Clear usage cache to reflect new limits
                self.usage_repo._invalidate_user_cache(user_id)
            
            return success
            
        except Exception as e:
            logger.error(f"Error upgrading subscription for {user_id}: {e}")
            return False
    
    def cancel_subscription(self, user_id: str) -> bool:
        """Cancel user subscription (downgrade to inactive)"""
        try:
            updates = {
                'subscription': SubscriptionType.INACTIVE.value,
                'subscription_expires_at': None,
                'updated_at': datetime.utcnow()
            }
            
            success = user_repo.update_user(user_id, updates)
            
            if success:
                logger.info(f"Subscription cancelled: {user_id}")
                
                # Clear usage cache
                self.usage_repo._invalidate_user_cache(user_id)
            
            return success
            
        except Exception as e:
            logger.error(f"Error cancelling subscription for {user_id}: {e}")
            return False

# =========================
# Usage Decorators
# =========================

def track_usage(action_type: UsageActionType, count: int = 1):
    """Decorator to automatically track usage"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Execute the function first
            result = f(*args, **kwargs)
            
            # Only track usage if function succeeded and user is logged in
            if hasattr(g, 'current_user') and g.current_user:
                try:
                    subscription_service.record_usage(
                        g.current_user.id, 
                        action_type, 
                        count,
                        {'endpoint': request.endpoint, 'method': request.method}
                    )
                except Exception as e:
                    logger.error(f"Error tracking usage: {e}")
            
            return result
        
        return decorated_function
    return decorator

def require_usage_limit(action_type: UsageActionType, count: int = 1):
    """Decorator to check usage limits before executing function"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not hasattr(g, 'current_user') or not g.current_user:
                return redirect(url_for('login_page'))
            
            can_perform, message, usage_info = subscription_service.check_usage_limit(
                g.current_user, action_type, count
            )
            
            if not can_perform:
                if request.is_json:
                    return jsonify({
                        'error': message,
                        'usage_info': usage_info,
                        'upgrade_required': True
                    }), 402
                else:
                    flash(message, 'warning')
                    return redirect(url_for('billing_page'))
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator

# =========================
# Business Logic Helpers
# =========================

def get_plan_badge_html(subscription_type: SubscriptionType) -> str:
    """Get HTML badge for subscription plan"""
    plan = SubscriptionConfig.get_plan(subscription_type)
    
    badge_classes = {
        SubscriptionType.INACTIVE: 'badge bg-secondary',
        SubscriptionType.MONTHLY: 'badge bg-primary',
        SubscriptionType.SIXMONTH: 'badge bg-success'
    }
    
    badge_class = badge_classes.get(subscription_type, 'badge bg-secondary')
    
    return f'<span class="{badge_class}">{plan.name}</span>'

def format_usage_percentage(used: int, limit: int) -> str:
    """Format usage as percentage string"""
    if limit == -1:
        return "Unlimited"
    elif limit == 0:
        return "Not available"
    else:
        percentage = (used / limit * 100) if limit > 0 else 0
        return f"{used}/{limit} ({percentage:.1f}%)"

def get_upgrade_recommendation(user: User, current_usage: UsageSummary) -> Optional[SubscriptionType]:
    """Get upgrade recommendation based on usage patterns"""
    if user.subscription != SubscriptionType.INACTIVE.value:
        return None
    
    # If user has any usage, recommend monthly plan
    if current_usage.total_usage > 0:
        return SubscriptionType.MONTHLY
    
    return None

# =========================
# Analytics and Reporting
# =========================

class UsageAnalytics:
    """Usage analytics for business intelligence"""
    
    @staticmethod
    def get_platform_usage_stats(days: int = 30) -> Dict[str, Any]:
        """Get platform-wide usage statistics"""
        try:
            end_date = datetime.utcnow()
            start_date = end_date - timedelta(days=days)
            
            with db.get_connection() as conn:
                # Total usage by action type
                usage_by_type = conn.execute("""
                    SELECT action_type, SUM(count) as total_count, COUNT(DISTINCT user_id) as unique_users
                    FROM user_usage 
                    WHERE created_at >= ? AND created_at <= ?
                    GROUP BY action_type
                """, (start_date, end_date)).fetchall()
                
                # Daily usage trends
                daily_usage = conn.execute("""
                    SELECT DATE(created_at) as date, SUM(count) as total_count
                    FROM user_usage 
                    WHERE created_at >= ? AND created_at <= ?
                    GROUP BY DATE(created_at)
                    ORDER BY date
                """, (start_date, end_date)).fetchall()
                
                # Active users by subscription type
                subscription_stats = conn.execute("""
                    SELECT u.subscription, COUNT(DISTINCT uu.user_id) as active_users
                    FROM user_usage uu
                    JOIN users u ON uu.user_id = u.id
                    WHERE uu.created_at >= ? AND uu.created_at <= ?
                    GROUP BY u.subscription
                """, (start_date, end_date)).fetchall()
                
                return {
                    'period_days': days,
                    'start_date': start_date.isoformat() + 'Z',
                    'end_date': end_date.isoformat() + 'Z',
                    'usage_by_type': [dict(row) for row in usage_by_type],
                    'daily_usage': [dict(row) for row in daily_usage],
                    'subscription_stats': [dict(row) for row in subscription_stats]
                }
                
        except Exception as e:
            logger.error(f"Error getting platform usage stats: {e}")
            return {}
    
    @staticmethod
    def get_user_engagement_metrics(days: int = 30) -> Dict[str, Any]:
        """Get user engagement metrics"""
        try:
            end_date = datetime.utcnow()
            start_date = end_date - timedelta(days=days)
            
            with db.get_connection() as conn:
                # User activity levels
                user_activity = conn.execute("""
                    SELECT 
                        CASE 
                            WHEN total_usage = 0 THEN 'inactive'
                            WHEN total_usage <= 10 THEN 'low'
                            WHEN total_usage <= 50 THEN 'medium'
                            ELSE 'high'
                        END as activity_level,
                        COUNT(*) as user_count
                    FROM (
                        SELECT user_id, SUM(count) as total_usage
                        FROM user_usage 
                        WHERE created_at >= ? AND created_at <= ?
                        GROUP BY user_id
                    ) user_totals
                    GROUP BY activity_level
                """, (start_date, end_date)).fetchall()
                
                return {
                    'period_days': days,
                    'user_activity_distribution': [dict(row) for row in user_activity]
                }
                
        except Exception as e:
            logger.error(f"Error getting engagement metrics: {e}")
            return {}

# Global services
subscription_service = SubscriptionService()
usage_analytics = UsageAnalytics()

logger.info("Section 4: Usage Management, Subscription System, and Business Logic - initialized")
# =========================
# SECTION 5/8: Web Interface, Template System, and User Experience
# =========================

import html
import json
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any, Union
from functools import lru_cache
import threading
from urllib.parse import urlparse, urljoin

from flask import render_template_string, request, session, url_for, flash, g, make_response

# =========================
# Template System
# =========================

class TemplateManager:
    """Centralized template management with caching"""
    
    def __init__(self):
        self._template_cache = {}
        self._cache_lock = threading.RLock()
    
    @lru_cache(maxsize=100)
    def get_base_template(self) -> str:
        """Get the base HTML template with all styling and navigation"""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="csrf-token" content="{{ csrf_token() }}">
    <title>{{ title }} - CPP Test Prep</title>
    
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css" rel="stylesheet">
    
    <!-- Google Fonts -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    
    <!-- Custom Styles -->
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
            --border-light: #e5e7eb;
            --shadow-sm: 0 1px 2px 0 rgb(0 0 0 / 0.05);
            --shadow-md: 0 4px 6px -1px rgb(0 0 0 / 0.1);
            --shadow-lg: 0 10px 15px -3px rgb(0 0 0 / 0.1);
            --shadow-xl: 0 20px 25px -5px rgb(0 0 0 / 0.1);
        }
        
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
            background: linear-gradient(135deg, var(--soft-gray) 0%, #e2e8f0 100%);
            color: var(--text-dark);
            line-height: 1.6;
            min-height: 100vh;
        }
        
        /* Navigation */
        .navbar {
            backdrop-filter: blur(10px);
            border-bottom: 1px solid rgba(255, 255, 255, 0.2);
        }
        
        .bg-gradient-primary {
            background: linear-gradient(135deg, var(--primary-blue) 0%, var(--purple-accent) 100%) !important;
        }
        
        .navbar-brand {
            font-size: 1.5rem;
            font-weight: 700;
            text-shadow: 0 1px 2px rgba(0, 0, 0, 0.1);
        }
        
        .text-white-75 {
            color: rgba(255, 255, 255, 0.85) !important;
            transition: color 0.2s ease;
        }
        
        .text-white-75:hover {
            color: #fff !important;
        }
        
        /* Cards */
        .card {
            box-shadow: var(--shadow-lg);
            border: none;
            border-radius: 16px;
            background: var(--warm-white);
            transition: all 0.3s ease;
            overflow: hidden;
            backdrop-filter: blur(10px);
        }
        
        .card:hover {
            transform: translateY(-2px);
            box-shadow: var(--shadow-xl);
        }
        
        .card-header {
            background: none;
            border-bottom: 1px solid var(--border-light);
            font-weight: 600;
            padding: 1.5rem 1.5rem 1rem;
        }
        
        .card-body {
            padding: 1.5rem;
        }
        
        /* Buttons */
        .btn {
            border-radius: 12px;
            font-weight: 600;
            letter-spacing: 0.025em;
            padding: 0.75rem 1.5rem;
            transition: all 0.2s ease;
            border: 2px solid transparent;
        }
        
        .btn-primary {
            background: linear-gradient(135deg, var(--primary-blue), var(--purple-accent));
            border: none;
            box-shadow: var(--shadow-md);
            color: white;
        }
        
        .btn-primary:hover {
            transform: translateY(-1px);
            box-shadow: var(--shadow-lg);
            filter: brightness(1.05);
        }
        
        .btn-outline-primary {
            border-color: var(--primary-blue);
            color: var(--primary-blue);
            background: transparent;
        }
        
        .btn-outline-primary:hover {
            background: var(--primary-blue);
            color: white;
            transform: translateY(-1px);
        }
        
        /* Domain buttons */
        .domain-btn {
            border-radius: 999px;
            padding: 0.4rem 0.9rem;
            margin: 0.2rem;
            transition: all 0.2s ease;
        }
        
        .domain-btn.active {
            outline: 3px solid rgba(0, 0, 0, 0.1);
            box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.15) inset;
            transform: scale(1.02);
        }
        
        /* Plan badges */
        .plan-monthly {
            background: linear-gradient(45deg, var(--primary-blue), var(--purple-accent));
            color: white;
            padding: 0.25rem 0.75rem;
            border-radius: 999px;
            font-size: 0.875rem;
            font-weight: 500;
        }
        
        .plan-sixmonth {
            background: linear-gradient(45deg, var(--purple-accent), #8b5cf6);
            color: white;
            padding: 0.25rem 0.75rem;
            border-radius: 999px;
            font-size: 0.875rem;
            font-weight: 500;
        }
        
        .plan-inactive {
            background: #6b7280;
            color: white;
            padding: 0.25rem 0.75rem;
            border-radius: 999px;
            font-size: 0.875rem;
            font-weight: 500;
        }
        
        /* Alerts */
        .alert {
            border-radius: 12px;
            border: none;
            padding: 1.25rem;
            margin-bottom: 1.5rem;
        }
        
        .alert-success {
            background: linear-gradient(135deg, #d1fae5, #a7f3d0);
            color: #065f46;
            border-left: 4px solid var(--success-green);
        }
        
        .alert-info {
            background: linear-gradient(135deg, #dbeafe, #bfdbfe);
            color: #1e3a8a;
            border-left: 4px solid var(--primary-blue);
        }
        
        .alert-warning {
            background: linear-gradient(135deg, #fef3c7, #fed7aa);
            color: #92400e;
            border-left: 4px solid var(--warning-orange);
        }
        
        .alert-danger {
            background: linear-gradient(135deg, #fee2e2, #fecaca);
            color: #991b1b;
            border-left: 4px solid var(--danger-red);
        }
        
        /* Form controls */
        .form-control,
        .form-select {
            border-radius: 10px;
            border: 2px solid var(--border-light);
            padding: 0.75rem 1rem;
            transition: all 0.2s ease;
            background: rgba(255, 255, 255, 0.8);
        }
        
        .form-control:focus,
        .form-select:focus {
            border-color: var(--primary-blue);
            box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.1);
            background: white;
        }
        
        .form-label {
            font-weight: 600;
            color: var(--text-dark);
            margin-bottom: 0.5rem;
        }
        
        /* Progress indicators */
        .progress {
            height: 8px;
            border-radius: 4px;
            background: var(--border-light);
        }
        
        .progress-bar {
            border-radius: 4px;
            background: linear-gradient(90deg, var(--primary-blue), var(--purple-accent));
        }
        
        /* Usage indicators */
        .usage-indicator {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.5rem 0;
        }
        
        .usage-badge {
            padding: 0.25rem 0.5rem;
            border-radius: 6px;
            font-size: 0.75rem;
            font-weight: 600;
        }
        
        .usage-unlimited {
            background: var(--success-green);
            color: white;
        }
        
        .usage-limited {
            background: var(--warning-orange);
            color: white;
        }
        
        .usage-exceeded {
            background: var(--danger-red);
            color: white;
        }
        
        /* Responsive design */
        @media (max-width: 768px) {
            .container {
                padding: 0 20px;
            }
            
            .card {
                margin-bottom: 1.5rem;
                border-radius: 12px;
            }
            
            .btn {
                padding: 0.6rem 1.2rem;
            }
            
            .navbar-brand {
                font-size: 1.25rem;
            }
        }
        
        /* Loading states */
        .loading {
            opacity: 0.7;
            pointer-events: none;
        }
        
        .spinner-border-sm {
            width: 1rem;
            height: 1rem;
        }
        
        /* Flash message animations */
        .flash-message {
            animation: slideInDown 0.3s ease-out;
        }
        
        @keyframes slideInDown {
            from {
                transform: translateY(-100%);
                opacity: 0;
            }
            to {
                transform: translateY(0);
                opacity: 1;
            }
        }
        
        /* Utility classes */
        .text-success { color: var(--success-green) !important; }
        .text-warning { color: var(--warning-orange) !important; }
        .text-danger { color: var(--danger-red) !important; }
        .bg-gradient-success { background: linear-gradient(135deg, #10b981, #059669) !important; }
        .bg-gradient-warning { background: linear-gradient(135deg, #f59e0b, #d97706) !important; }
        .bg-gradient-danger { background: linear-gradient(135deg, #ef4444, #dc2626) !important; }
    </style>
</head>
<body class="d-flex flex-column min-vh-100">
    {{ navigation }}
    {{ staging_banner }}
    
    <!-- Flash Messages -->
    {{ flash_messages }}
    
    <main class="flex-grow-1 py-4">
        {{ content }}
    </main>
    
    {{ footer }}
    
    <!-- Bootstrap JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
    
    <!-- Custom JavaScript -->
    <script>
        // CSRF token setup
        const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');
        
        // Add CSRF token to all AJAX requests
        if (csrfToken) {
            const originalFetch = window.fetch;
            window.fetch = function(url, options = {}) {
                if (options.method && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(options.method.toUpperCase())) {
                    options.headers = options.headers || {};
                    options.headers['X-CSRFToken'] = csrfToken;
                }
                return originalFetch(url, options);
            };
        }
        
        // Auto-dismiss flash messages
        document.addEventListener('DOMContentLoaded', function() {
            const alerts = document.querySelectorAll('.alert[data-auto-dismiss]');
            alerts.forEach(alert => {
                setTimeout(() => {
                    const bsAlert = new bootstrap.Alert(alert);
                    bsAlert.close();
                }, 5000);
            });
        });
        
        // Loading state management
        function setLoading(element, loading = true) {
            if (loading) {
                element.classList.add('loading');
                element.disabled = true;
                const spinner = element.querySelector('.spinner-border') || document.createElement('span');
                spinner.className = 'spinner-border spinner-border-sm me-2';
                element.prepend(spinner);
            } else {
                element.classList.remove('loading');
                element.disabled = false;
                const spinner = element.querySelector('.spinner-border');
                if (spinner) spinner.remove();
            }
        }
        
        // Form validation helpers
        function showFieldError(field, message) {
            field.classList.add('is-invalid');
            let feedback = field.parentNode.querySelector('.invalid-feedback');
            if (!feedback) {
                feedback = document.createElement('div');
                feedback.className = 'invalid-feedback';
                field.parentNode.appendChild(feedback);
            }
            feedback.textContent = message;
        }
        
        function clearFieldErrors(form) {
            form.querySelectorAll('.is-invalid').forEach(field => {
                field.classList.remove('is-invalid');
            });
            form.querySelectorAll('.invalid-feedback').forEach(feedback => {
                feedback.remove();
            });
        }
    </script>
    
    {{ custom_scripts }}
</body>
</html>
"""
    
    def render_layout(self, title: str, content: str, custom_scripts: str = "") -> str:
        """Render complete page layout"""
        try:
            # Get user info
            user = getattr(g, 'current_user', None)
            is_logged_in = user is not None
            
            # Build navigation
            navigation = self._build_navigation(user, is_logged_in)
            
            # Build staging banner
            staging_banner = self._build_staging_banner() if config.IS_STAGING else ""
            
            # Build flash messages
            flash_messages = self._build_flash_messages()
            
            # Build footer
            footer = self._build_footer()
            
            # Replace template variables
            template = self.get_base_template()
            
            # Use string formatting for safety
            rendered = template.replace('{{ title }}', html.escape(title))
            rendered = rendered.replace('{{ navigation }}', navigation)
            rendered = rendered.replace('{{ staging_banner }}', staging_banner)
            rendered = rendered.replace('{{ flash_messages }}', flash_messages)
            rendered = rendered.replace('{{ content }}', content)
            rendered = rendered.replace('{{ footer }}', footer)
            rendered = rendered.replace('{{ custom_scripts }}', custom_scripts)
            rendered = rendered.replace('{{ csrf_token() }}', get_csrf_token())
            
            return rendered
            
        except Exception as e:
            logger.error(f"Error rendering layout: {e}")
            # Return minimal safe layout
            return self._build_error_layout(title, content, str(e))
    
    def _build_navigation(self, user: Optional[User], is_logged_in: bool) -> str:
        """Build navigation bar HTML"""
        # User menu
        if is_logged_in and user:
            user_name = html.escape(user.name or user.email)
            subscription_type = SubscriptionType(user.subscription)
            plan_badge = get_plan_badge_html(subscription_type)
            
            user_menu = f"""
            <li class="nav-item dropdown">
                <a class="nav-link dropdown-toggle text-white-75" href="#" id="userDropdown" 
                   role="button" data-bs-toggle="dropdown" aria-expanded="false">
                    {user_name} {plan_badge}
                </a>
                <ul class="dropdown-menu dropdown-menu-end" aria-labelledby="userDropdown">
                    <li><a class="dropdown-item" href="{url_for('usage_dashboard')}">
                        <i class="bi bi-graph-up me-2"></i>Usage Dashboard</a></li>
                    <li><a class="dropdown-item" href="{url_for('billing_page')}">
                        <i class="bi bi-credit-card me-2"></i>Billing</a></li>
                    <li><a class="dropdown-item" href="{url_for('settings_page')}">
                        <i class="bi bi-gear me-2"></i>Settings</a></li>
                    <li><hr class="dropdown-divider"></li>
                    <li>
                        <form method="POST" action="{url_for('logout')}" class="d-inline">
                            <input type="hidden" name="csrf_token" value="{get_csrf_token()}"/>
                            <button type="submit" class="dropdown-item">
                                <i class="bi bi-box-arrow-right me-2"></i>Logout
                            </button>
                        </form>
                    </li>
                </ul>
            </li>
            """
            
            nav_items = f"""
            <li class="nav-item">
                <a class="nav-link text-white-75" href="{url_for('tutor_page')}">
                    <i class="bi bi-robot me-1"></i>Tutor
                </a>
            </li>
            <li class="nav-item">
                <a class="nav-link text-white-75" href="{url_for('flashcards_page')}">
                    <i class="bi bi-card-list me-1"></i>Flashcards
                </a>
            </li>
            <li class="nav-item">
                <a class="nav-link text-white-75" href="{url_for('quiz_page')}">
                    <i class="bi bi-card-text me-1"></i>Quiz
                </a>
            </li>
            <li class="nav-item">
                <a class="nav-link text-white-75" href="{url_for('mock_exam_page')}">
                    <i class="bi bi-clipboard-check me-1"></i>Mock Exam
                </a>
            </li>
            <li class="nav-item">
                <a class="nav-link text-white-75" href="{url_for('progress_page')}">
                    <i class="bi bi-graph-up me-1"></i>Progress
                </a>
            </li>
            """
        else:
            user_menu = f"""
            <li class="nav-item">
                <a class="nav-link text-white-75" href="{url_for('login_page')}">Login</a>
            </li>
            <li class="nav-item">
                <a class="nav-link btn btn-outline-light ms-2" href="{url_for('signup_page')}">
                    Create Account
                </a>
            </li>
            """
            nav_items = ""
        
        return f"""
        <nav class="navbar navbar-expand-lg navbar-light bg-gradient-primary sticky-top shadow-sm">
            <div class="container">
                <a class="navbar-brand fw-bold text-white" href="{url_for('home')}">
                    <i class="bi bi-shield-check text-warning me-2"></i>CPP Test Prep
                </a>
                
                <button class="navbar-toggler" type="button" data-bs-toggle="collapse" 
                        data-bs-target="#navbarNav" aria-controls="navbarNav" 
                        aria-expanded="false" aria-label="Toggle navigation">
                    <span class="navbar-toggler-icon"></span>
                </button>
                
                <div class="collapse navbar-collapse" id="navbarNav">
                    <ul class="navbar-nav me-auto">
                        {nav_items}
                    </ul>
                    <ul class="navbar-nav">
                        {user_menu}
                    </ul>
                </div>
            </div>
        </nav>
        """
    
    def _build_staging_banner(self) -> str:
        """Build staging environment banner"""
        return """
        <div class="alert alert-warning alert-dismissible fade show m-0" role="alert">
            <div class="container text-center">
                <strong>STAGING ENVIRONMENT</strong> - Not for production use.
                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
            </div>
        </div>
        """
    
    def _build_flash_messages(self) -> str:
        """Build flash messages HTML"""
        messages = []
        
        # Get Flask flash messages
        try:
            from flask import get_flashed_messages
            flashed = get_flashed_messages(with_categories=True)
            
            for category, message in flashed:
                # Map Flask categories to Bootstrap classes
                bootstrap_class = {
                    'error': 'danger',
                    'warning': 'warning',
                    'success': 'success',
                    'info': 'info'
                }.get(category, 'info')
                
                icon = {
                    'error': 'exclamation-triangle',
                    'warning': 'exclamation-circle',
                    'success': 'check-circle',
                    'info': 'info-circle'
                }.get(category, 'info-circle')
                
                messages.append(f"""
                <div class="alert alert-{bootstrap_class} alert-dismissible fade show flash-message" 
                     role="alert" data-auto-dismiss="true">
                    <i class="bi bi-{icon} me-2"></i>
                    {html.escape(message)}
                    <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                </div>
                """)
        except:
            pass
        
        if messages:
            return f'<div class="container mt-3">{"".join(messages)}</div>'
        return ""
    
    def _build_footer(self) -> str:
        """Build footer HTML"""
        return f"""
        <footer class="bg-light py-4 mt-5 border-top">
            <div class="container">
                <div class="row">
                    <div class="col-md-8">
                        <small class="text-muted">
                            <strong>Notice:</strong> This platform is independent and not affiliated with ASIS International.
                            CPP&reg; is a trademark of ASIS International, Inc.
                        </small>
                    </div>
                    <div class="col-md-4 text-end">
                        <small class="text-muted">
                            Version {config.APP_VERSION}
                        </small>
                    </div>
                </div>
            </div>
        </footer>
        """
    
    def _build_error_layout(self, title: str, content: str, error: str) -> str:
        """Build minimal error layout when main template fails"""
        return f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>{html.escape(title)} - CPP Test Prep</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
        </head>
        <body>
            <div class="container mt-5">
                <div class="alert alert-warning">
                    <strong>Template Error:</strong> {html.escape(error)}
                </div>
                {content}
            </div>
        </body>
        </html>
        """

# =========================
# Component Builders
# =========================

class ComponentBuilder:
    """Reusable UI component builder"""
    
    @staticmethod
    def build_domain_buttons(selected_key: str = "random", field_name: str = "domain") -> str:
        """Build domain selection buttons"""
        def _btn(key, label, color):
            active = " active" if key == (selected_key or "random") else ""
            return f"""
            <button type="button" class="btn domain-btn btn-{color}{active}" 
                    data-value="{html.escape(key)}">
                {html.escape(label)}
            </button>
            """
        
        buttons = []
        # Random button
        buttons.append(_btn("random", "Random (all domains)", "outline-secondary"))
        
        # Domain buttons
        for key, config in DomainManager.get_all_domains().items():
            buttons.append(_btn(key, config["name"], config["color"]))
        
        hidden_input = f"""
        <input type="hidden" name="{html.escape(field_name)}" 
               id="{html.escape(field_name)}_val" 
               value="{html.escape(selected_key or 'random')}">
        """
        
        script = f"""
        <script>
        (function() {{
            const container = document.currentScript.parentElement;
            const hiddenInput = container.querySelector('#{html.escape(field_name)}_val');
            
            container.querySelectorAll('.domain-btn').forEach(btn => {{
                btn.addEventListener('click', function() {{
                    // Remove active class from all buttons
                    container.querySelectorAll('.domain-btn').forEach(b => {{
                        b.classList.remove('active');
                    }});
                    
                    // Add active class to clicked button
                    btn.classList.add('active');
                    
                    // Update hidden input
                    if (hiddenInput) {{
                        hiddenInput.value = btn.getAttribute('data-value');
                    }}
                }});
            }});
        }})();
        </script>
        """
        
        return f"""
        <div class="d-flex flex-wrap gap-2 mb-3">
            {''.join(buttons)}
        </div>
        {hidden_input}
        {script}
        """
    
    @staticmethod
    def build_usage_indicator(action_type: UsageActionType, used: int, limit: int) -> str:
        """Build usage indicator widget"""
        if limit == -1:
            return f"""
            <div class="usage-indicator">
                <span class="usage-badge usage-unlimited">Unlimited</span>
                <span class="text-muted small">{used} used this month</span>
            </div>
            """
        elif limit == 0:
            return f"""
            <div class="usage-indicator">
                <span class="usage-badge usage-exceeded">Not Available</span>
                <span class="text-muted small">Upgrade required</span>
            </div>
            """
        else:
            remaining = max(0, limit - used)
            percentage = (used / limit * 100) if limit > 0 else 0
            
            badge_class = "usage-exceeded" if used >= limit else "usage-limited"
            
            return f"""
            <div class="usage-indicator">
                <span class="usage-badge {badge_class}">{used}/{limit}</span>
                <div class="flex-grow-1 mx-2">
                    <div class="progress" style="height: 6px;">
                        <div class="progress-bar" style="width: {percentage:.1f}%"></div>
                    </div>
                </div>
                <span class="text-muted small">{remaining} remaining</span>
            </div>
            """
    
    @staticmethod
    def build_subscription_cards(current_subscription: SubscriptionType = SubscriptionType.INACTIVE) -> str:
        """Build subscription plan cards"""
        plans = [
            SubscriptionConfig.get_plan(SubscriptionType.MONTHLY),
            SubscriptionConfig.get_plan(SubscriptionType.SIXMONTH)
        ]
        
        cards = []
        for plan in plans:
            is_current = plan.type == current_subscription
            
            # Build features list
            features_html = "".join([
                f'<li class="mb-2"><i class="bi bi-check-circle-fill text-success me-2"></i>{html.escape(feature)}</li>'
                for feature in plan.features
            ])
            
            # Determine styling
            if plan.type == SubscriptionType.MONTHLY:
                card_class = "border-primary"
                header_class = "bg-primary text-white"
                button_class = "btn-primary"
            else:
                card_class = "border-success position-relative"
                header_class = "bg-success text-white"
                button_class = "btn-success"
                
            # Best value badge for 6-month plan
            best_value_badge = """
            <div class="badge bg-warning text-dark position-absolute top-0 start-50 translate-middle px-3 py-2 fw-bold">
                <i class="bi bi-star-fill me-1"></i>Best Value
            </div>
            """ if plan.type == SubscriptionType.SIXMONTH else ""
            
            # Current plan indicator
            current_indicator = """
            <div class="alert alert-info mt-3">
                <i class="bi bi-check-circle me-2"></i>Your current plan
            </div>
            """ if is_current else ""
            
            # Button
            if is_current:
                button_html = f'<button class="btn {button_class} btn-lg w-100" disabled>Current Plan</button>'
            else:
                checkout_url = url_for('billing_checkout', plan=plan.type.value)
                button_html = f'<a href="{checkout_url}" class="btn {button_class} btn-lg w-100">Choose {plan.name}</a>'
            
            cards.append(f"""
            <div class="col-md-6 mb-4">
                <div class="card h-100 {card_class}">
                    {best_value_badge}
                    <div class="card-header {header_class} text-center {'pt-4' if best_value_badge else ''}">
                        <h4 class="mb-0">{html.escape(plan.name)}</h4>
                    </div>
                    <div class="card-body text-center p-4">
                        <div class="mb-3">
                            <span class="display-4 fw-bold text-{'success' if plan.type == SubscriptionType.SIXMONTH else 'primary'}">${plan.price:.2f}</span>
                            <span class="text-muted fs-5">{'one-time' if plan.duration_days else '/month'}</span>
                        </div>
                        <ul class="list-unstyled mb-4 text-start">
                            {features_html}
                        </ul>
                        {button_html}
                        {current_indicator}
                    </div>
                </div>
            </div>
            """)
        
        return f'<div class="row">{"".join(cards)}</div>'
    
    @staticmethod
    def build_progress_chart(usage_history: List[UsageSummary], action_type: UsageActionType) -> str:
        """Build simple progress chart"""
        if not usage_history:
            return '<div class="text-muted">No usage data available</div>'
        
        # Prepare data for chart
        chart_data = []
        max_value = 0
        
        for summary in reversed(usage_history[-6:]):  # Last 6 months
            value = summary.get_usage(action_type)
            chart_data.append({
                'label': summary.period_start.strftime('%b %Y'),
                'value': value
            })
            max_value = max(max_value, value)
        
        if max_value == 0:
            return '<div class="text-muted">No usage data for this period</div>'
        
        # Build simple bar chart
        bars = []
        for data in chart_data:
            height = (data['value'] / max_value * 100) if max_value > 0 else 0
            bars.append(f"""
            <div class="text-center" style="flex: 1;">
                <div style="height: 100px; display: flex; align-items: end; justify-content: center;">
                    <div style="width: 20px; height: {height}%; background: linear-gradient(to top, var(--primary-blue), var(--purple-accent)); border-radius: 2px;"></div>
                </div>
                <small class="text-muted">{html.escape(data['label'])}</small>
                <div><small class="fw-bold">{data['value']}</small></div>
            </div>
            """)
        
        return f"""
        <div class="d-flex gap-2 align-items-end" style="height: 140px;">
            {''.join(bars)}
        </div>
        """

# =========================
# Page Builders
# =========================

class PageBuilder:
    """High-level page construction"""
    
    def __init__(self):
        self.template_manager = TemplateManager()
        self.component_builder = ComponentBuilder()
    
    def build_error_page(self, title: str, error_code: int, message: str, 
                        show_home_link: bool = True) -> str:
        """Build standardized error page"""
        icon_map = {
            403: "slash-circle",
            404: "exclamation-triangle", 
            429: "clock",
            500: "bug"
        }
        
        color_map = {
            403: "danger",
            404: "warning",
            429: "warning", 
            500: "danger"
        }
        
        icon = icon_map.get(error_code, "exclamation-triangle")
        color = color_map.get(error_code, "danger")
        
        home_link = f"""
        <a class="btn btn-primary me-2" href="{url_for('home')}">
            <i class="bi bi-house me-1"></i>Go Home
        </a>
        """ if show_home_link else ""
        
        content = f"""
        <div class="container">
            <div class="row justify-content-center">
                <div class="col-md-8">
                    <div class="card">
                        <div class="card-header bg-{color} text-white">
                            <h3 class="mb-0">
                                <i class="bi bi-{icon} me-2"></i>{html.escape(title)}
                            </h3>
                        </div>
                        <div class="card-body text-center">
                            <p class="text-muted mb-3">{html.escape(message)}</p>
                            {home_link}
                            <a class="btn btn-outline-secondary" href="javascript:history.back()">
                                <i class="bi bi-arrow-left me-1"></i>Go Back
                            </a>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        """
        
        return self.template_manager.render_layout(title, content)
    
    def build_loading_page(self, title: str, message: str = "Loading...", 
                          redirect_url: str = None) -> str:
        """Build loading page with optional redirect"""
        redirect_script = ""
        if redirect_url:
            redirect_script = f"""
            <script>
            setTimeout(() => {{
                window.location.href = '{html.escape(redirect_url)}';
            }}, 2000);
            </script>
            """
        
        content = f"""
        <div class="container">
            <div class="row justify-content-center">
                <div class="col-md-6">
                    <div class="card">
                        <div class="card-body text-center py-5">
                            <div class="spinner-border text-primary mb-3" role="status">
                                <span class="visually-hidden">Loading...</span>
                            </div>
                            <h5>{html.escape(message)}</h5>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        {redirect_script}
        """
        
        return self.template_manager.render_layout(title, content)

# =========================
# Global Instances
# =========================

template_manager = TemplateManager()
component_builder = ComponentBuilder()
page_builder = PageBuilder()

# =========================
# Template Functions
# =========================

def render_page(title: str, content: str, scripts: str = "") -> str:
    """Render a complete page"""
    return template_manager.render_layout(title, content, scripts)

def render_error_page(error_code: int, title: str = None, message: str = None) -> Tuple[str, int]:
    """Render error page with appropriate status code"""
    default_messages = {
        403: ("Forbidden", "You don't have permission to access this resource."),
        404: ("Page Not Found", "The page you're looking for doesn't exist."),
        429: ("Too Many Requests", "Please wait before trying again."),
        500: ("Server Error", "An unexpected error occurred.")
    }
    
    if not title or not message:
        default_title, default_message = default_messages.get(error_code, ("Error", "An error occurred."))
        title = title or default_title
        message = message or default_message
    
    content = page_builder.build_error_page(title, error_code, message)
    return content, error_code

def render_json_response(data: Any, status_code: int = 200) -> Tuple[str, int]:
    """Render JSON response with proper headers"""
    try:
        response = make_response(json.dumps(data, default=str), status_code)
        response.headers['Content-Type'] = 'application/json'
        return response
    except Exception as e:
        logger.error(f"JSON serialization error: {e}")
        error_response = make_response(
            json.dumps({"error": "Internal server error"}), 
            500
        )
        error_response.headers['Content-Type'] = 'application/json'
        return error_response

logger.info("Section 5: Web Interface, Template System, and User Experience - initialized")
# =========================
# SECTION 6/8: Quiz Engine, Mock Exam System, and Interactive Learning
# =========================

import json
import random
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Union
from dataclasses import dataclass, field, asdict
from enum import Enum
import threading
from collections import defaultdict

from flask import request, session, redirect, url_for, flash, g

# =========================
# Quiz and Exam Models
# =========================

class AttemptType(Enum):
    QUIZ = "quiz"
    MOCK_EXAM = "mock_exam"
    FLASHCARD_SESSION = "flashcard_session"

class AttemptStatus(Enum):
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    ABANDONED = "abandoned"
    EXPIRED = "expired"

@dataclass
class QuizConfiguration:
    """Configuration for a quiz or exam"""
    attempt_type: AttemptType
    question_count: int
    domain_filter: Optional[str] = None
    difficulty_filter: Optional[DifficultyLevel] = None
    time_limit_minutes: Optional[int] = None
    randomize_questions: bool = True
    randomize_options: bool = False  # For enhanced difficulty
    show_explanations: bool = True
    allow_review: bool = True

@dataclass
class UserAnswer:
    """User's answer to a question"""
    question_id: str
    selected_option: str  # A, B, C, or D
    is_correct: bool
    time_spent_seconds: int
    timestamp: datetime = field(default_factory=lambda: datetime.utcnow())

@dataclass
class AttemptResult:
    """Results of a completed attempt"""
    attempt_id: str
    user_id: str
    attempt_type: AttemptType
    configuration: QuizConfiguration
    questions: List[Question]
    answers: List[UserAnswer]
    score: int
    total_questions: int
    percentage: float
    time_taken_seconds: int
    domain_breakdown: Dict[str, Dict[str, int]]  # domain -> {correct, total}
    started_at: datetime
    completed_at: datetime
    
    def get_domain_percentage(self, domain: str) -> float:
        """Get percentage score for a specific domain"""
        domain_data = self.domain_breakdown.get(domain, {})
        correct = domain_data.get('correct', 0)
        total = domain_data.get('total', 0)
        return (correct / total * 100) if total > 0 else 0.0

@dataclass
class ActiveAttempt:
    """An in-progress quiz/exam attempt"""
    id: str
    user_id: str
    attempt_type: AttemptType
    configuration: QuizConfiguration
    questions: List[Question]
    answers: Dict[str, UserAnswer]  # question_id -> UserAnswer
    current_question_index: int
    started_at: datetime
    expires_at: Optional[datetime]
    last_activity_at: datetime = field(default_factory=lambda: datetime.utcnow())
    
    def is_expired(self) -> bool:
        """Check if attempt has expired"""
        if self.expires_at:
            return datetime.utcnow() > self.expires_at
        return False
    
    def get_progress_percentage(self) -> float:
        """Get completion percentage"""
        if not self.questions:
            return 0.0
        answered_count = len([q for q in self.questions if q.id in self.answers])
        return (answered_count / len(self.questions)) * 100
    
    def get_time_remaining_seconds(self) -> Optional[int]:
        """Get remaining time in seconds"""
        if not self.expires_at:
            return None
        remaining = (self.expires_at - datetime.utcnow()).total_seconds()
        return max(0, int(remaining))

# =========================
# Quiz Session Management
# =========================

class QuizSessionManager:
    """Manages active quiz/exam sessions"""
    
    def __init__(self):
        self._sessions = {}  # user_id -> ActiveAttempt
        self._lock = threading.RLock()
        self._cleanup_interval = 300  # 5 minutes
        self._last_cleanup = datetime.utcnow()
    
    def create_attempt(self, user_id: str, config: QuizConfiguration) -> ActiveAttempt:
        """Create a new quiz/exam attempt"""
        with self._lock:
            # Clean up any existing attempt for this user
            self.end_attempt(user_id)
            
            # Get questions based on configuration
            questions = self._select_questions(config)
            if not questions:
                raise ValueError("No questions available for the specified criteria")
            
            # Calculate expiry time
            expires_at = None
            if config.time_limit_minutes:
                expires_at = datetime.utcnow() + timedelta(minutes=config.time_limit_minutes)
            
            # Create attempt
            attempt = ActiveAttempt(
                id=str(uuid.uuid4()),
                user_id=user_id,
                attempt_type=config.attempt_type,
                configuration=config,
                questions=questions,
                answers={},
                current_question_index=0,
                started_at=datetime.utcnow(),
                expires_at=expires_at
            )
            
            # Store in memory and database
            self._sessions[user_id] = attempt
            self._save_attempt_to_db(attempt)
            
            logger.info(f"Created {config.attempt_type.value} attempt for user {user_id}: {attempt.id}")
            return attempt
    
    def get_attempt(self, user_id: str) -> Optional[ActiveAttempt]:
        """Get active attempt for user"""
        with self._lock:
            attempt = self._sessions.get(user_id)
            if attempt and attempt.is_expired():
                self.end_attempt(user_id, status=AttemptStatus.EXPIRED)
                return None
            return attempt
    
    def update_attempt(self, user_id: str, question_id: str, selected_option: str, 
                      time_spent: int) -> bool:
        """Update attempt with user's answer"""
        with self._lock:
            attempt = self.get_attempt(user_id)
            if not attempt:
                return False
            
            # Find the question
            question = next((q for q in attempt.questions if q.id == question_id), None)
            if not question:
                return False
            
            # Create answer record
            is_correct = selected_option == question.correct
            answer = UserAnswer(
                question_id=question_id,
                selected_option=selected_option,
                is_correct=is_correct,
                time_spent_seconds=time_spent
            )
            
            # Store answer
            attempt.answers[question_id] = answer
            attempt.last_activity_at = datetime.utcnow()
            
            # Update in database
            self._update_attempt_in_db(attempt)
            
            return True
    
    def navigate_attempt(self, user_id: str, direction: str) -> Optional[int]:
        """Navigate to next/previous question"""
        with self._lock:
            attempt = self.get_attempt(user_id)
            if not attempt:
                return None
            
            current_index = attempt.current_question_index
            
            if direction == "next":
                new_index = min(current_index + 1, len(attempt.questions) - 1)
            elif direction == "previous":
                new_index = max(current_index - 1, 0)
            else:
                return None
            
            attempt.current_question_index = new_index
            attempt.last_activity_at = datetime.utcnow()
            
            return new_index
    
    def complete_attempt(self, user_id: str) -> Optional[AttemptResult]:
        """Complete and score attempt"""
        with self._lock:
            attempt = self.get_attempt(user_id)
            if not attempt:
                return None
            
            # Calculate results
            result = self._calculate_results(attempt)
            
            # Save result to database
            self._save_result_to_db(result)
            
            # Remove from active sessions
            self.end_attempt(user_id, status=AttemptStatus.COMPLETED)
            
            logger.info(f"Completed attempt {attempt.id}: {result.score}/{result.total_questions}")
            return result
    
    def end_attempt(self, user_id: str, status: AttemptStatus = AttemptStatus.ABANDONED) -> bool:
        """End an active attempt"""
        with self._lock:
            attempt = self._sessions.pop(user_id, None)
            if attempt:
                self._update_attempt_status_in_db(attempt.id, status)
                logger.info(f"Ended attempt {attempt.id} with status {status.value}")
                return True
            return False
    
    def cleanup_expired_sessions(self):
        """Clean up expired sessions"""
        if datetime.utcnow() - self._last_cleanup < timedelta(seconds=self._cleanup_interval):
            return
        
        with self._lock:
            expired_users = []
            for user_id, attempt in self._sessions.items():
                if attempt.is_expired():
                    expired_users.append(user_id)
            
            for user_id in expired_users:
                self.end_attempt(user_id, AttemptStatus.EXPIRED)
            
            self._last_cleanup = datetime.utcnow()
            
            if expired_users:
                logger.info(f"Cleaned up {len(expired_users)} expired sessions")
    
    def _select_questions(self, config: QuizConfiguration) -> List[Question]:
        """Select questions based on configuration"""
        questions = question_repo.get_questions(
            domain=config.domain_filter,
            difficulty=config.difficulty_filter,
            active_only=True
        )
        
        if config.randomize_questions:
            random.shuffle(questions)
        
        return questions[:config.question_count]
    
    def _calculate_results(self, attempt: ActiveAttempt) -> AttemptResult:
        """Calculate attempt results"""
        total_questions = len(attempt.questions)
        correct_answers = sum(1 for answer in attempt.answers.values() if answer.is_correct)
        percentage = (correct_answers / total_questions * 100) if total_questions > 0 else 0
        
        # Calculate domain breakdown
        domain_breakdown = defaultdict(lambda: {'correct': 0, 'total': 0})
        for question in attempt.questions:
            domain = question.domain
            domain_breakdown[domain]['total'] += 1
            
            answer = attempt.answers.get(question.id)
            if answer and answer.is_correct:
                domain_breakdown[domain]['correct'] += 1
        
        # Calculate total time
        time_taken = int((datetime.utcnow() - attempt.started_at).total_seconds())
        
        return AttemptResult(
            attempt_id=attempt.id,
            user_id=attempt.user_id,
            attempt_type=attempt.attempt_type,
            configuration=attempt.configuration,
            questions=attempt.questions,
            answers=list(attempt.answers.values()),
            score=correct_answers,
            total_questions=total_questions,
            percentage=percentage,
            time_taken_seconds=time_taken,
            domain_breakdown=dict(domain_breakdown),
            started_at=attempt.started_at,
            completed_at=datetime.utcnow()
        )
    
    def _save_attempt_to_db(self, attempt: ActiveAttempt):
        """Save attempt to database"""
        try:
            with db.transaction() as conn:
                conn.execute("""
                    INSERT INTO user_attempts (id, user_id, attempt_type, question_count, 
                                             correct_count, score_percentage, domain_filter, 
                                             results, started_at, completed_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    attempt.id, attempt.user_id, attempt.attempt_type.value,
                    len(attempt.questions), 0, 0.0,  # Will be updated on completion
                    attempt.configuration.domain_filter,
                    json.dumps({
                        'status': AttemptStatus.IN_PROGRESS.value,
                        'configuration': asdict(attempt.configuration),
                        'questions': [q.id for q in attempt.questions],
                        'expires_at': attempt.expires_at.isoformat() + 'Z' if attempt.expires_at else None
                    }),
                    attempt.started_at, None
                ))
        except Exception as e:
            logger.error(f"Error saving attempt to database: {e}")
    
    def _update_attempt_in_db(self, attempt: ActiveAttempt):
        """Update attempt in database"""
        try:
            with db.transaction() as conn:
                results_data = {
                    'status': AttemptStatus.IN_PROGRESS.value,
                    'configuration': asdict(attempt.configuration),
                    'questions': [q.id for q in attempt.questions],
                    'answers': {qid: asdict(answer) for qid, answer in attempt.answers.items()},
                    'current_question_index': attempt.current_question_index,
                    'expires_at': attempt.expires_at.isoformat() + 'Z' if attempt.expires_at else None
                }
                
                conn.execute("""
                    UPDATE user_attempts SET results = ?
                    WHERE id = ?
                """, (json.dumps(results_data), attempt.id))
        except Exception as e:
            logger.error(f"Error updating attempt in database: {e}")
    
    def _save_result_to_db(self, result: AttemptResult):
        """Save completed result to database"""
        try:
            with db.transaction() as conn:
                results_data = {
                    'status': AttemptStatus.COMPLETED.value,
                    'configuration': asdict(result.configuration),
                    'questions': [asdict(q) for q in result.questions],
                    'answers': [asdict(a) for a in result.answers],
                    'domain_breakdown': result.domain_breakdown,
                    'time_taken_seconds': result.time_taken_seconds
                }
                
                conn.execute("""
                    UPDATE user_attempts 
                    SET question_count = ?, correct_count = ?, score_percentage = ?, 
                        results = ?, completed_at = ?
                    WHERE id = ?
                """, (
                    result.total_questions, result.score, result.percentage,
                    json.dumps(results_data), result.completed_at, result.attempt_id
                ))
        except Exception as e:
            logger.error(f"Error saving result to database: {e}")
    
    def _update_attempt_status_in_db(self, attempt_id: str, status: AttemptStatus):
        """Update attempt status in database"""
        try:
            with db.transaction() as conn:
                # Get current results
                row = conn.execute("""
                    SELECT results FROM user_attempts WHERE id = ?
                """, (attempt_id,)).fetchone()
                
                if row and row['results']:
                    results_data = json.loads(row['results'])
                    results_data['status'] = status.value
                    
                    completed_at = datetime.utcnow() if status == AttemptStatus.COMPLETED else None
                    
                    conn.execute("""
                        UPDATE user_attempts 
                        SET results = ?, completed_at = ?
                        WHERE id = ?
                    """, (json.dumps(results_data), completed_at, attempt_id))
        except Exception as e:
            logger.error(f"Error updating attempt status: {e}")

# =========================
# Flashcard Session Manager
# =========================

@dataclass
class FlashcardSession:
    """Active flashcard study session"""
    id: str
    user_id: str
    flashcards: List[Flashcard]
    current_index: int
    started_at: datetime
    reviewed_count: int = 0
    domain_filter: Optional[str] = None

class FlashcardSessionManager:
    """Manages flashcard study sessions"""
    
    def __init__(self):
        self._sessions = {}  # user_id -> FlashcardSession
        self._lock = threading.RLock()
    
    def create_session(self, user_id: str, count: int, domain: str = None) -> FlashcardSession:
        """Create a new flashcard session"""
        with self._lock:
            # Get flashcards
            flashcards = flashcard_repo.get_random_flashcards(count, domain)
            if not flashcards:
                raise ValueError("No flashcards available")
            
            session = FlashcardSession(
                id=str(uuid.uuid4()),
                user_id=user_id,
                flashcards=flashcards,
                current_index=0,
                started_at=datetime.utcnow(),
                domain_filter=domain
            )
            
            self._sessions[user_id] = session
            logger.info(f"Created flashcard session for user {user_id}: {len(flashcards)} cards")
            return session
    
    def get_session(self, user_id: str) -> Optional[FlashcardSession]:
        """Get active flashcard session"""
        return self._sessions.get(user_id)
    
    def navigate_session(self, user_id: str, direction: str) -> Optional[int]:
        """Navigate flashcard session"""
        with self._lock:
            session = self.get_session(user_id)
            if not session:
                return None
            
            if direction == "next":
                session.current_index = min(session.current_index + 1, len(session.flashcards) - 1)
                session.reviewed_count = max(session.reviewed_count, session.current_index + 1)
            elif direction == "previous":
                session.current_index = max(session.current_index - 1, 0)
            
            return session.current_index
    
    def end_session(self, user_id: str) -> Optional[Dict[str, Any]]:
        """End flashcard session and return stats"""
        with self._lock:
            session = self._sessions.pop(user_id, None)
            if session:
                duration = (datetime.utcnow() - session.started_at).total_seconds()
                stats = {
                    'cards_reviewed': session.reviewed_count,
                    'total_cards': len(session.flashcards),
                    'duration_seconds': int(duration),
                    'completion_percentage': (session.reviewed_count / len(session.flashcards)) * 100
                }
                logger.info(f"Ended flashcard session: {stats}")
                return stats
            return None

# =========================
# Route Handlers
# =========================

# Global session managers
quiz_session_manager = QuizSessionManager()
flashcard_session_manager = FlashcardSessionManager()

@app.route("/quiz", methods=["GET", "POST"])
@login_required
def quiz_page():
    """Quiz selection and execution page"""
    user = g.current_user
    
    # Check for active attempt
    active_attempt = quiz_session_manager.get_attempt(user.id)
    
    # Handle POST - either start new quiz or process answer
    if request.method == "POST":
        if not validate_csrf_token():
            abort(403)
        
        # Starting new quiz
        if not active_attempt:
            # Check usage limits
            can_use, message, usage_info = subscription_service.check_usage_limit(
                user, UsageActionType.QUIZ, 1
            )
            
            if not can_use:
                flash(message, 'warning')
                return redirect(url_for('billing_page'))
            
            # Get configuration
            try:
                count = int(request.form.get("count", "10"))
                if count not in [5, 10, 15, 20]:
                    count = 10
                    
                domain = request.form.get("domain", "random")
                if domain == "random":
                    domain = None
                    
                config = QuizConfiguration(
                    attempt_type=AttemptType.QUIZ,
                    question_count=count,
                    domain_filter=domain,
                    time_limit_minutes=None,
                    show_explanations=True
                )
                
                active_attempt = quiz_session_manager.create_attempt(user.id, config)
                
            except ValueError as e:
                flash(str(e), 'error')
                return redirect(url_for('quiz_page'))
        
        # Processing answer for active attempt
        else:
            question_id = request.form.get("question_id")
            selected_option = request.form.get("selected_option")
            time_spent = int(request.form.get("time_spent", "0"))
            navigation = request.form.get("navigation", "next")
            
            if question_id and selected_option:
                quiz_session_manager.update_attempt(user.id, question_id, selected_option, time_spent)
            
            # Handle navigation
            if navigation == "finish":
                result = quiz_session_manager.complete_attempt(user.id)
                if result:
                    # Record usage
                    subscription_service.record_usage(
                        user.id, UsageActionType.QUIZ, 1,
                        {'questions': result.total_questions}
                    )
                    subscription_service.record_usage(
                        user.id, UsageActionType.QUESTION, result.total_questions
                    )
                    
                    session['last_quiz_result'] = result.attempt_id
                    return redirect(url_for('quiz_results'))
            else:
                quiz_session_manager.navigate_attempt(user.id, navigation)
    
    # Show quiz selection if no active attempt
    if not active_attempt:
        domain_buttons = component_builder.build_domain_buttons("random", "domain")
        
        content = f"""
        <div class="container">
            <div class="row justify-content-center">
                <div class="col-lg-8">
                    <div class="card">
                        <div class="card-header bg-success text-white">
                            <h3 class="mb-0">
                                <i class="bi bi-card-text me-2"></i>Start Quiz
                            </h3>
                        </div>
                        <div class="card-body">
                            <form method="POST">
                                <input type="hidden" name="csrf_token" value="{get_csrf_token()}"/>
                                
                                <div class="mb-3">
                                    <label class="form-label fw-semibold">Select Domain (Optional)</label>
                                    {domain_buttons}
                                </div>
                                
                                <div class="mb-4">
                                    <label class="form-label fw-semibold">Number of Questions</label>
                                    <div class="d-flex flex-wrap gap-2">
                                        <button type="submit" name="count" value="5" class="btn btn-outline-success">5 Questions</button>
                                        <button type="submit" name="count" value="10" class="btn btn-outline-success">10 Questions</button>
                                        <button type="submit" name="count" value="15" class="btn btn-outline-success">15 Questions</button>
                                        <button type="submit" name="count" value="20" class="btn btn-outline-success">20 Questions</button>
                                    </div>
                                </div>
                                
                                <div class="text-muted small mb-3">
                                    <i class="bi bi-info-circle me-1"></i>
                                    Choose a domain to focus your practice, or select Random for mixed questions.
                                </div>
                            </form>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        """
        
        return render_page("Quiz", content)
    
    # Show active quiz
    return _render_quiz_question(active_attempt)

@app.route("/mock-exam", methods=["GET", "POST"])
@login_required 
def mock_exam_page():
    """Mock exam page - similar to quiz but with more questions and time limit"""
    user = g.current_user
    
    # Check for active attempt
    active_attempt = quiz_session_manager.get_attempt(user.id)
    
    if request.method == "POST":
        if not validate_csrf_token():
            abort(403)
        
        # Starting new exam
        if not active_attempt:
            # Check usage limits
            can_use, message, usage_info = subscription_service.check_usage_limit(
                user, UsageActionType.QUIZ, 1
            )
            
            if not can_use:
                flash(message, 'warning')
                return redirect(url_for('billing_page'))
            
            try:
                count = int(request.form.get("count", "50"))
                if count not in [25, 50, 75, 100]:
                    count = 50
                    
                domain = request.form.get("domain", "random")
                if domain == "random":
                    domain = None
                
                config = QuizConfiguration(
                    attempt_type=AttemptType.MOCK_EXAM,
                    question_count=count,
                    domain_filter=domain,
                    time_limit_minutes=count * 2,  # 2 minutes per question
                    show_explanations=True
                )
                
                active_attempt = quiz_session_manager.create_attempt(user.id, config)
                
            except ValueError as e:
                flash(str(e), 'error')
                return redirect(url_for('mock_exam_page'))
        
        # Process answer (same as quiz)
        else:
            question_id = request.form.get("question_id")
            selected_option = request.form.get("selected_option") 
            time_spent = int(request.form.get("time_spent", "0"))
            navigation = request.form.get("navigation", "next")
            
            if question_id and selected_option:
                quiz_session_manager.update_attempt(user.id, question_id, selected_option, time_spent)
            
            if navigation == "finish":
                result = quiz_session_manager.complete_attempt(user.id)
                if result:
                    # Record usage
                    subscription_service.record_usage(
                        user.id, UsageActionType.QUIZ, 1,
                        {'questions': result.total_questions, 'type': 'mock_exam'}
                    )
                    subscription_service.record_usage(
                        user.id, UsageActionType.QUESTION, result.total_questions
                    )
                    
                    session['last_exam_result'] = result.attempt_id
                    return redirect(url_for('exam_results'))
            else:
                quiz_session_manager.navigate_attempt(user.id, navigation)
    
    # Show exam selection
    if not active_attempt:
        domain_buttons = component_builder.build_domain_buttons("random", "domain")
        
        content = f"""
        <div class="container">
            <div class="row justify-content-center">
                <div class="col-lg-8">
                    <div class="card">
                        <div class="card-header bg-warning text-dark">
                            <h3 class="mb-0">
                                <i class="bi bi-clipboard-check me-2"></i>Mock Exam
                            </h3>
                        </div>
                        <div class="card-body">
                            <div class="alert alert-info">
                                <i class="bi bi-clock me-2"></i>
                                <strong>Timed Exam:</strong> You'll have 2 minutes per question to complete the exam.
                            </div>
                            
                            <form method="POST">
                                <input type="hidden" name="csrf_token" value="{get_csrf_token()}"/>
                                
                                <div class="mb-3">
                                    <label class="form-label fw-semibold">Select Domain (Optional)</label>
                                    {domain_buttons}
                                </div>
                                
                                <div class="mb-4">
                                    <label class="form-label fw-semibold">Number of Questions</label>
                                    <div class="d-flex flex-wrap gap-2">
                                        <button type="submit" name="count" value="25" class="btn btn-outline-warning">25 Questions</button>
                                        <button type="submit" name="count" value="50" class="btn btn-outline-warning">50 Questions</button>
                                        <button type="submit" name="count" value="75" class="btn btn-outline-warning">75 Questions</button>
                                        <button type="submit" name="count" value="100" class="btn btn-outline-warning">100 Questions</button>
                                    </div>
                                </div>
                            </form>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        """
        
        return render_page("Mock Exam", content)
    
    # Show active exam (with timer)
    return _render_quiz_question(active_attempt, show_timer=True)

def _render_quiz_question(attempt: ActiveAttempt, show_timer: bool = False) -> str:
    """Render current quiz question"""
    if attempt.current_question_index >= len(attempt.questions):
        # Auto-complete if all questions answered
        result = quiz_session_manager.complete_attempt(attempt.user_id)
        if result:
            session['last_quiz_result'] = result.attempt_id
            return redirect(url_for('quiz_results'))
    
    current_question = attempt.questions[attempt.current_question_index]
    question_num = attempt.current_question_index + 1
    total_questions = len(attempt.questions)
    
    # Get existing answer if any
    existing_answer = attempt.answers.get(current_question.id)
    selected_option = existing_answer.selected_option if existing_answer else ""
    
    # Build option buttons
    options_html = []
    for option_key in ['A', 'B', 'C', 'D']:
        option_text = current_question.options.get(option_key, "")
        checked = "checked" if selected_option == option_key else ""
        
        options_html.append(f"""
        <div class="form-check mb-3">
            <input class="form-check-input" type="radio" name="selected_option" 
                   id="option_{option_key}" value="{option_key}" {checked}>
            <label class="form-check-label" for="option_{option_key}">
                <strong>{option_key}.</strong> {html.escape(option_text)}
            </label>
        </div>
        """)
    
    # Navigation buttons
    prev_disabled = "disabled" if attempt.current_question_index == 0 else ""
    next_text = "Finish Exam" if attempt.current_question_index == total_questions - 1 else "Next Question"
    next_value = "finish" if attempt.current_question_index == total_questions - 1 else "next"
    
    # Timer display
    timer_html = ""
    if show_timer and attempt.expires_at:
        remaining_seconds = attempt.get_time_remaining_seconds()
        if remaining_seconds is not None:
            timer_html = f"""
            <div class="alert alert-warning d-flex align-items-center justify-content-between">
                <span><i class="bi bi-clock me-2"></i>Time Remaining:</span>
                <span class="fw-bold" id="timer">{remaining_seconds // 60}:{remaining_seconds % 60:02d}</span>
            </div>
            """
    
    # Progress bar
    progress = attempt.get_progress_percentage()
    
    attempt_type_display = "Mock Exam" if attempt.attempt_type == AttemptType.MOCK_EXAM else "Quiz"
    
    content = f"""
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-lg-10">
                <div class="card">
                    <div class="card-header bg-{'warning text-dark' if attempt.attempt_type == AttemptType.MOCK_EXAM else 'success text-white'}">
                        <div class="d-flex justify-content-between align-items-center">
                            <h3 class="mb-0">
                                <i class="bi bi-{'clipboard-check' if attempt.attempt_type == AttemptType.MOCK_EXAM else 'card-text'} me-2"></i>
                                {attempt_type_display}
                            </h3>
                            <span class="badge bg-light text-dark">
                                Question {question_num} of {total_questions}
                            </span>
                        </div>
                        <div class="progress mt-2" style="height: 4px;">
                            <div class="progress-bar" style="width: {progress}%"></div>
                        </div>
                    </div>
                    <div class="card-body">
                        {timer_html}
                        
                        <div class="mb-4">
                            <h5 class="mb-3">Question {question_num}</h5>
                            <p class="lead">{html.escape(current_question.question)}</p>
                            {f'<div class="text-muted small"><strong>Domain:</strong> {html.escape(DomainManager.get_domain_name(current_question.domain))}</div>' if current_question.domain else ''}
                        </div>
                        
                        <form method="POST" id="questionForm">
                            <input type="hidden" name="csrf_token" value="{get_csrf_token()}"/>
                            <input type="hidden" name="question_id" value="{current_question.id}"/>
                            <input type="hidden" name="time_spent" value="0" id="timeSpent"/>
                            
                            <div class="mb-4">
                                {''.join(options_html)}
                            </div>
                            
                            <div class="d-flex justify-content-between">
                                <button type="submit" name="navigation" value="previous" 
                                        class="btn btn-outline-secondary" {prev_disabled}>
                                    <i class="bi bi-arrow-left me-1"></i>Previous
                                </button>
                                
                                <button type="submit" name="navigation" value="{next_value}" 
                                        class="btn btn-primary" id="nextBtn">
                                    {next_text} <i class="bi bi-arrow-right ms-1"></i>
                                </button>
                            </div>
                        </form>
                        
                        <div class="mt-3">
                            <a href="{url_for('quiz_page' if attempt.attempt_type == AttemptType.QUIZ else 'mock_exam_page')}?abandon=1" 
                               class="btn btn-outline-danger btn-sm"
                               onclick="return confirm('Are you sure you want to abandon this {attempt_type_display.lower()}?')">
                                <i class="bi bi-x-circle me-1"></i>Abandon {attempt_type_display}
                            </a>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        let startTime = Date.now();
        let timerInterval;
        
        // Update time spent when form is submitted
        document.getElementById('questionForm').addEventListener('submit', function() {{
            const timeSpent = Math.floor((Date.now() - startTime) / 1000);
            document.getElementById('timeSpent').value = timeSpent;
        }});
        
        // Timer countdown
        {f'''
        let remainingSeconds = {attempt.get_time_remaining_seconds() or 0};
        if (remainingSeconds > 0) {{
            timerInterval = setInterval(function() {{
                remainingSeconds--;
                const minutes = Math.floor(remainingSeconds / 60);
                const seconds = remainingSeconds % 60;
                document.getElementById('timer').textContent = minutes + ':' + seconds.toString().padStart(2, '0');
                
                if (remainingSeconds <= 0) {{
                    clearInterval(timerInterval);
                    alert('Time is up! Submitting exam...');
                    document.getElementById('nextBtn').click();
                }}
            }}, 1000);
        }}
        ''' if show_timer and attempt.expires_at else ''}
        
        // Auto-save answer on selection
        document.querySelectorAll('input[name="selected_option"]').forEach(radio => {{
            radio.addEventListener('change', function() {{
                // Visual feedback that answer is selected
                document.getElementById('nextBtn').classList.remove('btn-outline-primary');
                document.getElementById('nextBtn').classList.add('btn-primary');
            }});
        }});
    </script>
    """
    
    return render_page(attempt_type_display, content)

# Cleanup expired sessions periodically
@app.before_request
def cleanup_quiz_sessions():
    """Cleanup expired quiz sessions before each request"""
    try:
        quiz_session_manager.cleanup_expired_sessions()
    except Exception as e:
        logger.error(f"Error cleaning up quiz sessions: {e}")

logger.info("Section 6: Quiz Engine, Mock Exam System, and Interactive Learning - initialized") 
# =========================
# SECTION 7/8: AI Tutor System, Content Ingestion, and Admin Interface
# =========================

import json
import re
import time
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Union
from dataclasses import dataclass, field, asdict
from enum import Enum
from urllib.parse import urlparse
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests

from flask import request, session, redirect, url_for, flash, g, jsonify, abort

# =========================
# AI Tutor Models
# =========================

class TutorSessionStatus(Enum):
    ACTIVE = "active"
    COMPLETED = "completed"
    EXPIRED = "expired"

@dataclass
class TutorMessage:
    """Individual message in tutor conversation"""
    id: str
    user_id: str
    role: str  # 'user' or 'assistant'
    content: str
    timestamp: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat() + 'Z'
        return data

@dataclass
class TutorSession:
    """AI tutor conversation session"""
    id: str
    user_id: str
    messages: List[TutorMessage]
    domain_context: Optional[str]
    started_at: datetime
    last_activity_at: datetime
    status: TutorSessionStatus = TutorSessionStatus.ACTIVE
    
    def add_message(self, role: str, content: str, metadata: Dict[str, Any] = None) -> TutorMessage:
        """Add message to session"""
        message = TutorMessage(
            id=str(uuid.uuid4()),
            user_id=self.user_id,
            role=role,
            content=content,
            timestamp=datetime.utcnow(),
            metadata=metadata or {}
        )
        self.messages.append(message)
        self.last_activity_at = datetime.utcnow()
        return message
    
    def get_conversation_context(self, max_messages: int = 10) -> List[Dict[str, str]]:
        """Get recent messages for AI context"""
        recent_messages = self.messages[-max_messages:] if self.messages else []
        return [
            {"role": msg.role, "content": msg.content}
            for msg in recent_messages
        ]

# =========================
# AI Service Integration
# =========================

class AITutorService:
    """AI-powered tutoring service with web-aware citations"""
    
    def __init__(self):
        self._request_lock = threading.RLock()
        self._cache_ttl = 3600  # 1 hour
        self.web_aware_enabled = self._load_tutor_settings().get('web_aware', False)
    
    def generate_response(self, user_query: str, session: TutorSession, 
                         domain_context: str = None) -> Tuple[bool, str, Dict[str, Any]]:
        """Generate AI tutor response with optional web citations"""
        try:
            # Rate limiting check
            if self._is_rate_limited(session.user_id):
                return False, "Too many requests. Please wait before asking another question.", {}
            
            # Get conversation context
            conversation_history = session.get_conversation_context(max_messages=6)
            
            # Get citations if web-aware mode is enabled
            citations = []
            if self.web_aware_enabled:
                citations = self._find_content_citations(user_query, max_citations=3)
            
            # Build system prompt
            system_prompt = self._build_system_prompt(domain_context, citations)
            
            # Call AI service
            success, response, metadata = self._call_ai_service(
                system_prompt, user_query, conversation_history
            )
            
            if success and citations:
                metadata['citations_used'] = citations
                metadata['web_aware'] = True
            
            return success, response, metadata
            
        except Exception as e:
            logger.error(f"Error generating tutor response: {e}")
            return False, "I'm having trouble responding right now. Please try again.", {}
    
    def _build_system_prompt(self, domain_context: str = None, citations: List[Dict] = None) -> str:
        """Build comprehensive system prompt"""
        base_prompt = """You are an expert CPP/PSP (Certified Protection Professional/Physical Security Professional) study tutor. 

Your role:
- Provide clear, accurate, step-by-step explanations of security concepts
- Map advice to specific CPP domains when relevant
- Use practical examples from real-world security scenarios
- Be encouraging but precise in your explanations
- Focus on helping students understand underlying principles, not just memorize facts

CPP Domains to reference:
- Security Principles & Practices
- Business Principles & Practices  
- Investigations
- Personnel Security
- Physical Security
- Information Security
- Crisis & Emergency Management

Communication style:
- Be conversational but professional
- Use bullet points for complex topics
- Provide concrete examples
- Reference industry standards when appropriate
- Keep responses focused and actionable"""
        
        # Add domain-specific context
        if domain_context and domain_context != "random":
            domain_name = DomainManager.get_domain_name(domain_context)
            base_prompt += f"\n\nCurrent focus area: {domain_name}"
        
        # Add citation instructions if web-aware
        if citations:
            citation_content = "\n".join([
                f"- {cite['title']} — {cite['url']}"
                for cite in citations
            ])
            
            base_prompt += f"""

Supporting sources available:
{citation_content}

If these sources are relevant to the question, incorporate their information and include a brief "Sources" section at the end with title and URL for 1-3 most relevant sources."""
        
        return base_prompt
    
    def _call_ai_service(self, system_prompt: str, user_query: str, 
                        conversation_history: List[Dict[str, str]]) -> Tuple[bool, str, Dict[str, Any]]:
        """Make API call to AI service"""
        if not config.OPENAI_API_KEY:
            return False, "AI tutor is not configured. Please contact support.", {}
        
        # Build messages
        messages = [{"role": "system", "content": system_prompt}]
        
        # Add conversation history
        messages.extend(conversation_history)
        
        # Add current query
        messages.append({"role": "user", "content": user_query})
        
        # API configuration
        headers = {
            "Authorization": f"Bearer {config.OPENAI_API_KEY}",
            "Content-Type": "application/json"
        }
        
        if config.OPENAI_ORG:
            headers["OpenAI-Organization"] = config.OPENAI_ORG
        
        payload = {
            "model": config.OPENAI_CHAT_MODEL,
            "messages": messages,
            "temperature": config.TUTOR_TEMP,
            "max_tokens": config.TUTOR_MAX_TOKENS
        }
        
        # Make request with retries
        for attempt in range(3):
            try:
                response = requests.post(
                    f"{config.OPENAI_API_BASE}/chat/completions",
                    headers=headers,
                    json=payload,
                    timeout=config.TUTOR_TIMEOUT
                )
                
                if response.status_code == 429:
                    wait_time = min(2 ** attempt, 8)
                    time.sleep(wait_time)
                    continue
                
                if response.status_code >= 400:
                    error_data = response.json() if response.headers.get('content-type') == 'application/json' else {}
                    error_msg = error_data.get('error', {}).get('message', 'API request failed')
                    return False, f"AI service error: {error_msg}", {"status_code": response.status_code}
                
                data = response.json()
                content = data.get('choices', [{}])[0].get('message', {}).get('content', '')
                usage = data.get('usage', {})
                
                return True, content, {
                    "model": config.OPENAI_CHAT_MODEL,
                    "usage": usage,
                    "provider": "openai"
                }
                
            except requests.RequestException as e:
                if attempt == 2:  # Last attempt
                    return False, f"Network error: {str(e)}", {}
                time.sleep(1)
        
        return False, "Failed to get response after multiple attempts", {}
    
    def _find_content_citations(self, query: str, max_citations: int = 3) -> List[Dict[str, str]]:
        """Find relevant citations from content bank"""
        try:
            # Extract keywords from query
            keywords = self._extract_keywords(query)
            if not keywords:
                return []
            
            # Get all available sources from content
            all_sources = list(self._get_all_content_sources())
            if not all_sources:
                return []
            
            # Score and rank sources
            scored_sources = []
            for source in all_sources:
                score = self._score_source_relevance(source, keywords)
                if score > 0:
                    scored_sources.append((score, source))
            
            # Sort by score and return top results
            scored_sources.sort(key=lambda x: x[0], reverse=True)
            return [source for _, source in scored_sources[:max_citations]]
            
        except Exception as e:
            logger.error(f"Error finding citations: {e}")
            return []
    
    def _extract_keywords(self, text: str) -> set:
        """Extract relevant keywords from text"""
        # Remove common stop words and extract meaningful terms
        stop_words = {
            'the', 'and', 'for', 'with', 'from', 'this', 'that', 'into', 
            'over', 'under', 'your', 'about', 'have', 'what', 'when', 
            'where', 'which', 'how', 'why', 'can', 'could', 'should', 
            'would', 'will', 'are', 'is', 'was', 'were', 'been', 'being'
        }
        
        # Extract words 3+ characters, convert to lowercase
        words = re.findall(r'\b[a-zA-Z]{3,}\b', text.lower())
        keywords = {word for word in words if word not in stop_words}
        
        # Add domain-specific terms with higher weight
        security_terms = {
            'security', 'protection', 'risk', 'threat', 'vulnerability',
            'assessment', 'control', 'physical', 'personnel', 'information',
            'crisis', 'emergency', 'investigation', 'compliance', 'audit'
        }
        
        # Boost security-related keywords
        boosted_keywords = set()
        for keyword in keywords:
            if any(term in keyword for term in security_terms):
                boosted_keywords.add(keyword)
        
        return keywords.union(boosted_keywords)
    
    def _get_all_content_sources(self):
        """Get all unique sources from questions and flashcards"""
        seen_urls = set()
        
        # From questions
        questions = question_repo.get_questions(limit=1000, active_only=True)
        for question in questions:
            for source in question.sources:
                if source.url not in seen_urls and self._is_source_allowed(source.url):
                    seen_urls.add(source.url)
                    yield {
                        'title': source.title,
                        'url': source.url,
                        'domain': urlparse(source.url).netloc.lower(),
                        'content_type': 'question'
                    }
        
        # From flashcards
        flashcards = flashcard_repo.get_flashcards(limit=1000, active_only=True)
        for flashcard in flashcards:
            for source in flashcard.sources:
                if source.url not in seen_urls and self._is_source_allowed(source.url):
                    seen_urls.add(source.url)
                    yield {
                        'title': source.title,
                        'url': source.url,
                        'domain': urlparse(source.url).netloc.lower(),
                        'content_type': 'flashcard'
                    }
    
    def _score_source_relevance(self, source: Dict[str, str], keywords: set) -> int:
        """Score source relevance to keywords"""
        score = 0
        title_words = set(re.findall(r'\b[a-zA-Z]{3,}\b', source['title'].lower()))
        
        # Title keyword matches (higher weight)
        common_keywords = title_words.intersection(keywords)
        score += len(common_keywords) * 3
        
        # Domain authority bonus
        authority_domains = {
            'nist.gov': 3, 'cisa.gov': 3, 'fema.gov': 2, 'fbi.gov': 2,
            'gao.gov': 2, 'osha.gov': 2, 'ready.gov': 2
        }
        
        domain = source['domain']
        for auth_domain, bonus in authority_domains.items():
            if domain == auth_domain or domain.endswith('.' + auth_domain):
                score += bonus
                break
        
        return score
    
    def _is_source_allowed(self, url: str) -> bool:
        """Check if source URL is from allowed domain"""
        return SourceValidator.is_domain_allowed(url)
    
    def _is_rate_limited(self, user_id: str) -> bool:
        """Check if user is rate limited for tutor requests"""
        cache_key = f"tutor_rate_limit:{user_id}"
        
        try:
            current_count = cache.get(cache_key, 0)
            if current_count >= 20:  # 20 requests per hour
                return True
            
            cache.set(cache_key, current_count + 1, ttl=3600)
            return False
            
        except Exception:
            return False
    
    def _load_tutor_settings(self) -> Dict[str, Any]:
        """Load tutor configuration settings"""
        return file_storage.load_json("tutor_settings.json", {
            "web_aware": os.environ.get("TUTOR_WEB_AWARE", "0") == "1"
        })
    
    def update_settings(self, settings: Dict[str, Any]) -> bool:
        """Update tutor settings"""
        try:
            current_settings = self._load_tutor_settings()
            current_settings.update(settings)
            
            success = file_storage.save_json("tutor_settings.json", current_settings)
            if success:
                self.web_aware_enabled = current_settings.get('web_aware', False)
                logger.info(f"Tutor settings updated: {settings}")
            
            return success
            
        except Exception as e:
            logger.error(f"Error updating tutor settings: {e}")
            return False

# =========================
# Tutor Session Management
# =========================

class TutorSessionManager:
    """Manages AI tutor conversation sessions"""
    
    def __init__(self):
        self._sessions = {}  # user_id -> TutorSession
        self._lock = threading.RLock()
        self.ai_service = AITutorService()
    
    def get_or_create_session(self, user_id: str, domain_context: str = None) -> TutorSession:
        """Get existing session or create new one"""
        with self._lock:
            session = self._sessions.get(user_id)
            
            if not session:
                session = TutorSession(
                    id=str(uuid.uuid4()),
                    user_id=user_id,
                    messages=[],
                    domain_context=domain_context,
                    started_at=datetime.utcnow(),
                    last_activity_at=datetime.utcnow()
                )
                self._sessions[user_id] = session
                
                # Add welcome message
                welcome_msg = self._generate_welcome_message(domain_context)
                session.add_message("assistant", welcome_msg)
            
            return session
    
    def process_user_message(self, user_id: str, message: str, 
                           domain_context: str = None) -> Tuple[bool, str, Dict[str, Any]]:
        """Process user message and generate AI response"""
        try:
            session = self.get_or_create_session(user_id, domain_context)
            
            # Add user message to session
            session.add_message("user", message)
            
            # Generate AI response
            success, response, metadata = self.ai_service.generate_response(
                message, session, domain_context
            )
            
            if success:
                # Add AI response to session
                session.add_message("assistant", response, metadata)
                
                # Save session to database
                self._save_session_to_db(session)
            
            return success, response, metadata
            
        except Exception as e:
            logger.error(f"Error processing tutor message: {e}")
            return False, "I encountered an error. Please try again.", {}
    
    def get_session_history(self, user_id: str, limit: int = 10) -> List[TutorMessage]:
        """Get recent message history for user"""
        session = self._sessions.get(user_id)
        if session:
            return session.messages[-limit:] if session.messages else []
        
        # Load from database if not in memory
        return self._load_session_history_from_db(user_id, limit)
    
    def clear_session(self, user_id: str) -> bool:
        """Clear current tutor session"""
        with self._lock:
            session = self._sessions.pop(user_id, None)
            if session:
                session.status = TutorSessionStatus.COMPLETED
                self._save_session_to_db(session)
                return True
            return False
    
    def _generate_welcome_message(self, domain_context: str = None) -> str:
        """Generate contextual welcome message"""
        if domain_context and domain_context != "random":
            domain_name = DomainManager.get_domain_name(domain_context)
            return f"""Hi! I'm your CPP study tutor. I'm here to help you understand security concepts and prepare for your certification.

I see you're focusing on **{domain_name}** - I can help explain key concepts, provide practical examples, and answer any questions you have about this domain.

What would you like to learn about?"""
        
        return """Hi! I'm your CPP study tutor. I'm ready to help you understand security principles, review concepts, and answer questions about any of the CPP domains:

• Security Principles & Practices
• Business Principles & Practices  
• Investigations
• Personnel Security
• Physical Security
• Information Security
• Crisis & Emergency Management

What topic would you like to explore?"""
    
    def _save_session_to_db(self, session: TutorSession):
        """Save session to database for persistence"""
        try:
            # For now, just save recent messages to user history file
            history_key = f"tutor_history_{session.user_id}.json"
            history_data = [msg.to_dict() for msg in session.messages[-20:]]  # Keep last 20 messages
            file_storage.save_json(history_key, history_data, create_backup=False)
            
        except Exception as e:
            logger.error(f"Error saving tutor session: {e}")
    
    def _load_session_history_from_db(self, user_id: str, limit: int) -> List[TutorMessage]:
        """Load session history from database"""
        try:
            history_key = f"tutor_history_{user_id}.json"
            history_data = file_storage.load_json(history_key, [])
            
            messages = []
            for msg_data in history_data[-limit:]:
                try:
                    # Parse timestamp
                    timestamp_str = msg_data.get('timestamp', '')
                    timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '')) if timestamp_str else datetime.utcnow()
                    
                    message = TutorMessage(
                        id=msg_data.get('id', str(uuid.uuid4())),
                        user_id=user_id,
                        role=msg_data.get('role', 'user'),
                        content=msg_data.get('content', ''),
                        timestamp=timestamp,
                        metadata=msg_data.get('metadata', {})
                    )
                    messages.append(message)
                    
                except Exception as e:
                    logger.warning(f"Error parsing message history: {e}")
                    continue
            
            return messages
            
        except Exception as e:
            logger.error(f"Error loading tutor history: {e}")
            return []

# =========================
# Content Ingestion System
# =========================

class ContentIngestionService:
    """Handles batch content ingestion with validation and deduplication"""
    
    def __init__(self):
        self._processing_lock = threading.RLock()
    
    def ingest_content_batch(self, content_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process batch content ingestion"""
        with self._processing_lock:
            start_time = datetime.utcnow()
            
            questions_data = content_data.get('questions', [])
            flashcards_data = content_data.get('flashcards', [])
            
            # Process questions
            questions_result = self._process_questions_batch(questions_data)
            
            # Process flashcards  
            flashcards_result = self._process_flashcards_batch(flashcards_data)
            
            processing_time = (datetime.utcnow() - start_time).total_seconds()
            
            return {
                'success': True,
                'processing_time_seconds': processing_time,
                'questions': questions_result,
                'flashcards': flashcards_result,
                'summary': {
                    'total_items_processed': len(questions_data) + len(flashcards_data),
                    'questions_added': questions_result['added'],
                    'flashcards_added': flashcards_result['added'],
                    'total_errors': len(questions_result['errors']) + len(flashcards_result['errors'])
                }
            }
    
    def _process_questions_batch(self, questions_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Process batch of questions"""
        if not questions_data:
            return {'added': 0, 'errors': [], 'skipped_duplicates': 0}
        
        added = 0
        errors = []
        skipped = 0
        
        # Use thread pool for parallel processing
        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_index = {
                executor.submit(self._process_single_question, i, q_data): i
                for i, q_data in enumerate(questions_data)
            }
            
            for future in as_completed(future_to_index):
                index = future_to_index[future]
                try:
                    result = future.result()
                    if result['success']:
                        if result['added']:
                            added += 1
                        else:
                            skipped += 1
                    else:
                        errors.append(f"Question {index + 1}: {result['error']}")
                        
                except Exception as e:
                    errors.append(f"Question {index + 1}: Processing error: {str(e)}")
        
        return {
            'added': added,
            'errors': errors[:50],  # Limit error list
            'skipped_duplicates': skipped,
            'total_processed': len(questions_data)
        }
    
    def _process_single_question(self, index: int, q_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process a single question"""
        try:
            # Normalize question data
            normalized = content_service._normalize_question_data(q_data.copy())
            
            # Validate sources
            if normalized.get('sources'):
                valid, error = SourceValidator.validate_sources(normalized['sources'])
                if not valid:
                    return {'success': False, 'error': error, 'added': False}
            
            # Create question
            question = question_repo.create_question(normalized)
            return {'success': True, 'error': None, 'added': True}
            
        except ValueError as e:
            if "already exists" in str(e).lower():
                return {'success': True, 'error': None, 'added': False}  # Duplicate
            return {'success': False, 'error': str(e), 'added': False}
        except Exception as e:
            return {'success': False, 'error': f"Unexpected error: {str(e)}", 'added': False}
    
    def _process_flashcards_batch(self, flashcards_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Process batch of flashcards"""
        if not flashcards_data:
            return {'added': 0, 'errors': [], 'skipped_duplicates': 0}
        
        added = 0
        errors = []
        skipped = 0
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_index = {
                executor.submit(self._process_single_flashcard, i, fc_data): i
                for i, fc_data in enumerate(flashcards_data)
            }
            
            for future in as_completed(future_to_index):
                index = future_to_index[future]
                try:
                    result = future.result()
                    if result['success']:
                        if result['added']:
                            added += 1
                        else:
                            skipped += 1
                    else:
                        errors.append(f"Flashcard {index + 1}: {result['error']}")
                        
                except Exception as e:
                    errors.append(f"Flashcard {index + 1}: Processing error: {str(e)}")
        
        return {
            'added': added,
            'errors': errors[:50],
            'skipped_duplicates': skipped,
            'total_processed': len(flashcards_data)
        }
    
    def _process_single_flashcard(self, index: int, fc_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process a single flashcard"""
        try:
            # Normalize flashcard data
            normalized = content_service._normalize_flashcard_data(fc_data.copy())
            
            # Validate sources
            if normalized.get('sources'):
                valid, error = SourceValidator.validate_sources(normalized['sources'])
                if not valid:
                    return {'success': False, 'error': error, 'added': False}
            
            # Create flashcard
            flashcard = flashcard_repo.create_flashcard(normalized)
            return {'success': True, 'error': None, 'added': True}
            
        except ValueError as e:
            if "already exists" in str(e).lower():
                return {'success': True, 'error': None, 'added': False}
            return {'success': False, 'error': str(e), 'added': False}
        except Exception as e:
            return {'success': False, 'error': f"Unexpected error: {str(e)}", 'added': False}

# =========================
# Route Handlers
# =========================

# Global services
tutor_session_manager = TutorSessionManager()
content_ingestion_service = ContentIngestionService()

@app.route("/tutor", methods=["GET", "POST"])
@login_required
@require_usage_limit(UsageActionType.TUTOR_MESSAGE, 1)
def tutor_page():
    """AI tutor interface"""
    user = g.current_user
    
    # Handle message submission
    if request.method == "POST":
        if not validate_csrf_token():
            abort(403)
        
        user_message = request.form.get("query", "").strip()
        domain_context = request.form.get("domain", "random")
        
        if domain_context == "random":
            domain_context = None
        
        if user_message:
            # Process message
            success, response, metadata = tutor_session_manager.process_user_message(
                user.id, user_message, domain_context
            )
            
            if success:
                # Track usage
                subscription_service.record_usage(
                    user.id, UsageActionType.TUTOR_MESSAGE, 1,
                    {'domain': domain_context, 'model': metadata.get('model')}
                )
            
            # For AJAX requests, return JSON
            if request.headers.get('Content-Type') == 'application/json':
                return jsonify({
                    'success': success,
                    'response': response,
                    'metadata': metadata
                })
    
    # Get conversation history
    history = tutor_session_manager.get_session_history(user.id, limit=10)
    
    # Build domain selection
    domain_buttons = component_builder.build_domain_buttons("random", "domain")
    
    # Format conversation history
    conversation_html = ""
    if history:
        for msg in history:
            if msg.role == "user":
                conversation_html += f"""
                <div class="message user-message mb-3">
                    <div class="d-flex align-items-start">
                        <div class="avatar bg-primary text-white me-3">
                            <i class="bi bi-person-fill"></i>
                        </div>
                        <div class="message-content">
                            <strong>You</strong>
                            <div class="mt-1">{html.escape(msg.content).replace(chr(10), '<br>')}</div>
                            <small class="text-muted">{msg.timestamp.strftime('%I:%M %p')}</small>
                        </div>
                    </div>
                </div>
                """
            else:
                conversation_html += f"""
                <div class="message assistant-message mb-3">
                    <div class="d-flex align-items-start">
                        <div class="avatar bg-success text-white me-3">
                            <i class="bi bi-robot"></i>
                        </div>
                        <div class="message-content">
                            <strong>Tutor</strong>
                            <div class="mt-1">{html.escape(msg.content).replace(chr(10), '<br>')}</div>
                            <small class="text-muted">{msg.timestamp.strftime('%I:%M %p')}</small>
                        </div>
                    </div>
                </div>
                """
    
    if not conversation_html:
        conversation_html = """
        <div class="text-center text-muted py-5">
            <i class="bi bi-chat-dots display-4 mb-3"></i>
            <p>Start a conversation with your AI tutor!</p>
        </div>
        """
    
    content = f"""
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-lg-10">
                <div class="card">
                    <div class="card-header bg-info text-white">
                        <div class="d-flex justify-content-between align-items-center">
                            <h3 class="mb-0">
                                <i class="bi bi-robot me-2"></i>AI Tutor
                            </h3>
                            <button class="btn btn-outline-light btn-sm" onclick="clearConversation()">
                                <i class="bi bi-arrow-repeat me-1"></i>New Conversation
                            </button>
                        </div>
                    </div>
                    <div class="card-body">
                        <!-- Domain Selection -->
                        <div class="mb-3">
                            <label class="form-label fw-semibold">Focus Domain (Optional)</label>
                            {domain_buttons}
                        </div>
                        
                        <!-- Conversation History -->
                        <div id="conversationHistory" class="conversation-history mb-4" style="max-height: 400px; overflow-y: auto;">
                            {conversation_html}
                        </div>
                        
                        <!-- Message Input -->
                        <form method="POST" id="tutorForm">
                            <input type="hidden" name="csrf_token" value="{get_csrf_token()}"/>
                            <div class="input-group">
                                <textarea name="query" class="form-control" rows="2" 
                                         placeholder="Ask me anything about CPP topics..." 
                                         id="messageInput" required></textarea>
                                <button type="submit" class="btn btn-primary" id="sendButton">
                                    <i class="bi bi-send"></i>
                                </button>
                            </div>
                        </form>
                        
                        <div class="text-muted small mt-2">
                            <i class="bi bi-info-circle me-1"></i>
                            Tip: Ask about specific concepts, request examples, or get help with practice questions.
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        // Auto-resize textarea
        document.getElementById('messageInput').addEventListener('input', function() {{
            this.style.height = 'auto';
            this.style.height = this.scrollHeight + 'px';
        }});
        
        // Handle form submission
        document.getElementById('tutorForm').addEventListener('submit', function(e) {{
            e.preventDefault();
            
            const messageInput = document.getElementById('messageInput');
            const sendButton = document.getElementById('sendButton');
            const message = messageInput.value.trim();
            
            if (!message) return;
            
            // Show loading state
            sendButton.disabled = true;
            sendButton.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>Thinking...';
            
            // Add user message to conversation
            addMessageToConversation('user', message);
            messageInput.value = '';
            messageInput.style.height = 'auto';
            
            // Submit form normally
            this.submit();
        }});
        
        // Enter key handling
        document.getElementById('messageInput').addEventListener('keydown', function(e) {{
            if (e.key === 'Enter' && !e.shiftKey) {{
                e.preventDefault();
                document.getElementById('tutorForm').dispatchEvent(new Event('submit'));
            }}
        }});
        
        function addMessageToConversation(role, content) {{
            const history = document.getElementById('conversationHistory');
            const timestamp = new Date().toLocaleTimeString([], {{hour: '2-digit', minute:'2-digit'}});
            
            const messageDiv = document.createElement('div');
            messageDiv.className = `message ${{role}}-message mb-3`;
            
            const avatar = role === 'user' ? 
                '<div class="avatar bg-primary text-white me-3"><i class="bi bi-person-fill"></i></div>' :
                '<div class="avatar bg-success text-white me-3"><i class="bi bi-robot"></i></div>';
            
            const name = role === 'user' ? 'You' : 'Tutor';
            
            messageDiv.innerHTML = `
                <div class="d-flex align-items-start">
                    ${{avatar}}
                    <div class="message-content">
                        <strong>${{name}}</strong>
                        <div class="mt-1">${{content.replace(/\\n/g, '<br>')}}</div>
                        <small class="text-muted">${{timestamp}}</small>
                    </div>
                </div>
            `;
            
            history.appendChild(messageDiv);
            history.scrollTop = history.scrollHeight;
        }}
        
        function clearConversation() {{
            if (confirm('Clear current conversation? This cannot be undone.')) {{
                window.location.href = '/tutor?clear=1';
            }}
        }}
        
        // Scroll to bottom on load
        document.addEventListener('DOMContentLoaded', function() {{
            const history = document.getElementById('conversationHistory');
            history.scrollTop = history.scrollHeight;
        }});
    </script>
    """
    
    return render_page("AI Tutor", content)

# Handle clear conversation
@app.route("/tutor/clear")
@login_required
def clear_tutor_conversation():
    """Clear current tutor conversation"""
    tutor_session_manager.clear_session(g.current_user.id)
    return redirect(url_for('tutor_page'))

# Content ingestion API endpoint
@app.route("/api/content/ingest", methods=["POST"])
@admin_required
@rate_limit("content_ingest", limit=10, window=3600)  # 10 per hour
def api_content_ingest():
    """Content ingestion endpoint for admins"""
    try:
        if not request.is_json:
            return jsonify({
                'success': False,
                'error': 'Content-Type must be application/json'
            }), 400
        
        content_data = request.get_json() or {}
        
        # Validate request structure
        if not content_data.get('questions') and not content_data.get('flashcards'):
            return jsonify({
                'success': False,
                'error': 'Must provide questions or flashcards array'
            }), 400
        
        # Process ingestion
        result = content_ingestion_service.ingest_content_batch(content_data)
        
        # Log the ingestion
        logger.info(f"Content ingestion completed: {result['summary']}")
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Content ingestion error: {e}")
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500

# Admin tutor settings
@app.route("/admin/tutor-settings", methods=["GET", "POST"])
@admin_required
def admin_tutor_settings():
    """Admin interface for tutor configuration"""
    ai_service = tutor_session_manager.ai_service
    
    if request.method == "POST":
        if not validate_csrf_token():
            abort(403)
        
        web_aware = request.form.get("web_aware") == "1"
        settings = {"web_aware": web_aware}
        
        if ai_service.update_settings(settings):
            flash("Tutor settings updated successfully", "success")
        else:
            flash("Failed to update settings", "error")
        
        return redirect(url_for('admin_tutor_settings'))
    
    # Load current settings
    current_settings = ai_service._load_tutor_settings()
    
    # Preview citations for sample query
    sample_query = request.args.get("preview", "").strip()
    preview_citations = []
    
    if sample_query and current_settings.get('web_aware'):
        preview_citations = ai_service._find_content_citations(sample_query, max_citations=5)
    
    citations_html = ""
    if preview_citations:
        citations_html = "<ul class='list-unstyled'>" + "".join([
            f"<li class='mb-2'><a href='{html.escape(c['url'])}' target='_blank' class='text-decoration-none'>"
            f"{html.escape(c['title'])}</a><br><small class='text-muted'>{html.escape(c['domain'])}</small></li>"
            for c in preview_citations
        ]) + "</ul>"
    elif sample_query:
        citations_html = "<p class='text-muted'>No citations found for this query.</p>"
    
    content = f"""
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-lg-8">
                <div class="card">
                    <div class="card-header bg-secondary text-white">
                        <h3 class="mb-0">
                            <i class="bi bi-robot me-2"></i>Tutor Settings
                        </h3>
                    </div>
                    <div class="card-body">
                        <form method="POST" class="mb-4">
                            <input type="hidden" name="csrf_token" value="{get_csrf_token()}"/>
                            
                            <div class="form-check form-switch mb-3">
                                <input class="form-check-input" type="checkbox" id="webAware" 
                                       name="web_aware" value="1" {'checked' if current_settings.get('web_aware') else ''}>
                                <label class="form-check-label" for="webAware">
                                    <strong>Enable Web-Aware Citations</strong>
                                </label>
                                <div class="form-text">
                                    When enabled, the tutor will include relevant citations from your content bank.
                                    Only sources from approved domains will be used.
                                </div>
                            </div>
                            
                            <button type="submit" class="btn btn-primary">
                                <i class="bi bi-check me-1"></i>Save Settings
                            </button>
                            
                            <a href="/tutor" class="btn btn-outline-secondary ms-2">
                                <i class="bi bi-arrow-left me-1"></i>Back to Tutor
                            </a>
                        </form>
                        
                        <!-- Citation Preview -->
                        <div class="border-top pt-4">
                            <h5>Citation Preview</h5>
                            <p class="text-muted">Test how citations work with a sample query:</p>
                            
                            <form method="GET" class="mb-3">
                                <div class="input-group">
                                    <input type="text" name="preview" class="form-control" 
                                           placeholder="Enter a sample question..." 
                                           value="{html.escape(sample_query)}">
                                    <button type="submit" class="btn btn-outline-primary">Preview</button>
                                </div>
                            </form>
                            
                            <div class="preview-results">
                                {citations_html}
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    """
    
    return render_page("Tutor Settings", content)

logger.info("Section 7: AI Tutor System, Content Ingestion, and Admin Interface - initialized")
# =========================
# SECTION 8/8: Payment Processing, Analytics, Error Handling, and Application Deployment
# =========================

import json
import hmac
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
import threading
from collections import defaultdict
import os
import signal
import sys
import traceback

from flask import request, session, redirect, url_for, flash, g, jsonify, make_response

# =========================
# Stripe Payment Integration
# =========================

if HAS_STRIPE:
    import stripe

class PaymentService:
    """Secure Stripe payment processing"""
    
    def __init__(self):
        self._webhook_cache = {}  # event_id -> processed_timestamp
        self._cache_lock = threading.RLock()
        self.webhook_secret = config.STRIPE_WEBHOOK_SECRET
        
    def create_checkout_session(self, user_email: str, plan_type: str) -> Optional[str]:
        """Create Stripe checkout session"""
        if not HAS_STRIPE or not config.STRIPE_SECRET_KEY:
            logger.error("Stripe not configured")
            return None
        
        try:
            plan_config = SubscriptionConfig.get_plan(SubscriptionType(plan_type))
            if not plan_config.stripe_price_id:
                logger.error(f"No Stripe price ID for plan {plan_type}")
                return None
            
            # Determine mode based on plan
            mode = "subscription" if plan_type == "monthly" else "payment"
            
            # Create session
            session_params = {
                "payment_method_types": ["card"],
                "mode": mode,
                "line_items": [{
                    "price": plan_config.stripe_price_id,
                    "quantity": 1
                }],
                "customer_email": user_email,
                "success_url": self._build_success_url(plan_type),
                "cancel_url": self._build_cancel_url(),
                "metadata": {
                    "user_email": user_email,
                    "plan": plan_type,
                    "app_version": config.APP_VERSION
                }
            }
            
            # Add duration for one-time payments
            if plan_type == "sixmonth":
                session_params["metadata"]["duration_days"] = "180"
            
            checkout_session = stripe.checkout.Session.create(**session_params)
            
            logger.info(f"Created checkout session for {user_email}: {plan_type}")
            return checkout_session.url
            
        except stripe.StripeError as e:
            logger.error(f"Stripe error creating checkout session: {e}")
            return None
        except Exception as e:
            logger.error(f"Error creating checkout session: {e}")
            return None
    
    def handle_webhook(self, payload: bytes, signature: str) -> Tuple[bool, str]:
        """Handle Stripe webhook events"""
        if not self.webhook_secret:
            return False, "Webhook secret not configured"
        
        try:
            # Verify webhook signature
            event = stripe.Webhook.construct_event(
                payload, signature, self.webhook_secret
            )
        except ValueError:
            return False, "Invalid payload"
        except stripe.SignatureVerificationError:
            return False, "Invalid signature"
        
        # Prevent duplicate processing
        event_id = event.get('id')
        if self._is_event_processed(event_id):
            return True, "Event already processed"
        
        try:
            # Handle different event types
            if event['type'] == 'checkout.session.completed':
                success = self._handle_checkout_completed(event['data']['object'])
            elif event['type'] == 'customer.subscription.updated':
                success = self._handle_subscription_updated(event['data']['object'])
            elif event['type'] == 'customer.subscription.deleted':
                success = self._handle_subscription_cancelled(event['data']['object'])
            elif event['type'] == 'invoice.payment_failed':
                success = self._handle_payment_failed(event['data']['object'])
            else:
                # Unknown event type - log but don't fail
                logger.info(f"Unhandled webhook event type: {event['type']}")
                success = True
            
            if success:
                self._mark_event_processed(event_id)
                return True, "Event processed successfully"
            else:
                return False, "Event processing failed"
                
        except Exception as e:
            logger.error(f"Error processing webhook event {event_id}: {e}")
            return False, f"Processing error: {str(e)}"
    
    def _handle_checkout_completed(self, session) -> bool:
        """Handle successful checkout completion"""
        try:
            metadata = session.get('metadata', {})
            user_email = metadata.get('user_email')
            plan = metadata.get('plan')
            customer_id = session.get('customer')
            
            if not user_email or not plan:
                logger.error("Missing metadata in checkout session")
                return False
            
            # Find user
            user = user_repo.get_user_by_email(user_email)
            if not user:
                logger.error(f"User not found for checkout: {user_email}")
                return False
            
            # Update subscription
            subscription_type = SubscriptionType(plan)
            updates = {
                'subscription': subscription_type.value,
                'stripe_customer_id': customer_id
            }
            
            # Add expiration for time-limited plans
            if subscription_type == SubscriptionType.SIXMONTH:
                duration_days = int(metadata.get('duration_days', 180))
                expires_at = datetime.utcnow() + timedelta(days=duration_days)
                updates['subscription_expires_at'] = expires_at
            
            success = user_repo.update_user(user.id, updates)
            
            if success:
                logger.info(f"Subscription activated: {user_email} -> {plan}")
                
                # Clear usage cache to reflect new limits
                subscription_service.usage_repo._invalidate_user_cache(user.id)
            
            return success
            
        except Exception as e:
            logger.error(f"Error handling checkout completion: {e}")
            return False
    
    def _handle_subscription_updated(self, subscription) -> bool:
        """Handle subscription updates (renewals, changes)"""
        try:
            customer_id = subscription.get('customer')
            status = subscription.get('status')
            
            # Find user by customer ID
            user = self._find_user_by_customer_id(customer_id)
            if not user:
                logger.warning(f"User not found for customer ID: {customer_id}")
                return True  # Don't fail for unknown customers
            
            # Update subscription status
            if status == 'active':
                updates = {'subscription': SubscriptionType.MONTHLY.value}
                user_repo.update_user(user.id, updates)
                logger.info(f"Subscription activated for user: {user.email}")
            elif status in ['canceled', 'unpaid', 'past_due']:
                updates = {
                    'subscription': SubscriptionType.INACTIVE.value,
                    'subscription_expires_at': None
                }
                user_repo.update_user(user.id, updates)
                logger.info(f"Subscription deactivated for user: {user.email}")
            
            return True
            
        except Exception as e:
            logger.error(f"Error handling subscription update: {e}")
            return False
    
    def _handle_subscription_cancelled(self, subscription) -> bool:
        """Handle subscription cancellation"""
        try:
            customer_id = subscription.get('customer')
            
            user = self._find_user_by_customer_id(customer_id)
            if not user:
                return True
            
            # Downgrade to inactive
            updates = {
                'subscription': SubscriptionType.INACTIVE.value,
                'subscription_expires_at': None
            }
            
            success = user_repo.update_user(user.id, updates)
            if success:
                logger.info(f"Subscription cancelled for user: {user.email}")
            
            return success
            
        except Exception as e:
            logger.error(f"Error handling subscription cancellation: {e}")
            return False
    
    def _handle_payment_failed(self, invoice) -> bool:
        """Handle failed payments"""
        try:
            customer_id = invoice.get('customer')
            
            user = self._find_user_by_customer_id(customer_id)
            if not user:
                return True
            
            # Log the failure - could trigger email notifications
            logger.warning(f"Payment failed for user: {user.email}")
            
            # For now, just log. In production, might want to:
            # - Send email notification
            # - Grace period before downgrading
            # - Retry payment
            
            return True
            
        except Exception as e:
            logger.error(f"Error handling payment failure: {e}")
            return False
    
    def _find_user_by_customer_id(self, customer_id: str) -> Optional[User]:
        """Find user by Stripe customer ID"""
        try:
            with db.get_connection() as conn:
                row = conn.execute("""
                    SELECT id, name, email, password_hash, subscription,
                           subscription_expires_at, stripe_customer_id,
                           created_at, updated_at, last_login_at,
                           login_attempts, locked_until, is_active, preferences
                    FROM users WHERE stripe_customer_id = ? AND is_active = 1
                """, (customer_id,)).fetchone()
                
                if not row:
                    return None
                
                user_data = dict(row)
                
                # Parse JSON fields
                if user_data['preferences']:
                    user_data['preferences'] = json.loads(user_data['preferences'])
                else:
                    user_data['preferences'] = {}
                
                # Parse datetime fields
                for field in ['created_at', 'updated_at', 'last_login_at', 'locked_until', 'subscription_expires_at']:
                    if user_data[field]:
                        user_data[field] = datetime.fromisoformat(user_data[field].replace('Z', ''))
                
                return User.from_dict(user_data)
                
        except Exception as e:
            logger.error(f"Error finding user by customer ID: {e}")
            return None
    
    def _is_event_processed(self, event_id: str) -> bool:
        """Check if webhook event was already processed"""
        with self._cache_lock:
            if event_id in self._webhook_cache:
                # Check if event is recent (within 24 hours)
                processed_time = self._webhook_cache[event_id]
                if datetime.utcnow() - processed_time < timedelta(hours=24):
                    return True
                else:
                    # Remove old entry
                    del self._webhook_cache[event_id]
            
            return False
    
    def _mark_event_processed(self, event_id: str):
        """Mark webhook event as processed"""
        with self._cache_lock:
            self._webhook_cache[event_id] = datetime.utcnow()
            
            # Cleanup old entries
            if len(self._webhook_cache) > 1000:
                cutoff = datetime.utcnow() - timedelta(hours=24)
                self._webhook_cache = {
                    eid: timestamp for eid, timestamp in self._webhook_cache.items()
                    if timestamp > cutoff
                }
    
    def _build_success_url(self, plan_type: str) -> str:
        """Build success URL for checkout"""
        return f"{request.url_root.rstrip('/')}/billing/success?plan={plan_type}&session_id={{CHECKOUT_SESSION_ID}}"
    
    def _build_cancel_url(self) -> str:
        """Build cancel URL for checkout"""
        return f"{request.url_root.rstrip('/')}/billing"

# =========================
# Analytics and Reporting
# =========================

class AnalyticsService:
    """Application analytics and reporting"""
    
    def __init__(self):
        self._metrics_cache = {}
        self._cache_lock = threading.RLock()
        self._cache_ttl = 300  # 5 minutes
    
    def get_platform_metrics(self) -> Dict[str, Any]:
        """Get comprehensive platform metrics"""
        cache_key = "platform_metrics"
        
        with self._cache_lock:
            if cache_key in self._metrics_cache:
                cached_time, data = self._metrics_cache[cache_key]
                if datetime.utcnow() - cached_time < timedelta(seconds=self._cache_ttl):
                    return data
        
        try:
            metrics = self._calculate_platform_metrics()
            
            with self._cache_lock:
                self._metrics_cache[cache_key] = (datetime.utcnow(), metrics)
            
            return metrics
            
        except Exception as e:
            logger.error(f"Error calculating platform metrics: {e}")
            return {}
    
    def _calculate_platform_metrics(self) -> Dict[str, Any]:
        """Calculate current platform metrics"""
        try:
            now = datetime.utcnow()
            last_7_days = now - timedelta(days=7)
            last_30_days = now - timedelta(days=30)
            
            with db.get_connection() as conn:
                # User metrics
                total_users = conn.execute("SELECT COUNT(*) FROM users WHERE is_active = 1").fetchone()[0]
                
                active_subscribers = conn.execute("""
                    SELECT COUNT(*) FROM users 
                    WHERE is_active = 1 AND subscription != 'inactive'
                """).fetchone()[0]
                
                new_users_7d = conn.execute("""
                    SELECT COUNT(*) FROM users 
                    WHERE is_active = 1 AND created_at >= ?
                """, (last_7_days,)).fetchone()[0]
                
                # Content metrics
                total_questions = conn.execute("SELECT COUNT(*) FROM questions WHERE is_active = 1").fetchone()[0]
                total_flashcards = conn.execute("SELECT COUNT(*) FROM flashcards WHERE is_active = 1").fetchone()[0]
                
                # Usage metrics
                attempts_7d = conn.execute("""
                    SELECT COUNT(*) FROM user_attempts 
                    WHERE started_at >= ?
                """, (last_7_days,)).fetchone()[0]
                
                # Subscription breakdown
                subscription_breakdown = {}
                for row in conn.execute("""
                    SELECT subscription, COUNT(*) as count 
                    FROM users WHERE is_active = 1 
                    GROUP BY subscription
                """).fetchall():
                    subscription_breakdown[row['subscription']] = row['count']
                
                # Top domains by usage
                domain_usage = {}
                for row in conn.execute("""
                    SELECT domain_filter, COUNT(*) as count 
                    FROM user_attempts 
                    WHERE domain_filter IS NOT NULL AND started_at >= ?
                    GROUP BY domain_filter 
                    ORDER BY count DESC LIMIT 5
                """, (last_30_days,)).fetchall():
                    if row['domain_filter']:
                        domain_name = DomainManager.get_domain_name(row['domain_filter'])
                        domain_usage[domain_name] = row['count']
                
                return {
                    'timestamp': now.isoformat() + 'Z',
                    'users': {
                        'total': total_users,
                        'active_subscribers': active_subscribers,
                        'new_last_7_days': new_users_7d,
                        'subscription_breakdown': subscription_breakdown
                    },
                    'content': {
                        'questions': total_questions,
                        'flashcards': total_flashcards
                    },
                    'usage': {
                        'attempts_last_7_days': attempts_7d,
                        'top_domains': domain_usage
                    },
                    'system': {
                        'version': config.APP_VERSION,
                        'environment': 'staging' if config.IS_STAGING else 'production'
                    }
                }
                
        except Exception as e:
            logger.error(f"Error calculating metrics: {e}")
            return {'error': str(e)}
    
    def track_event(self, user_id: str, event_type: str, properties: Dict[str, Any] = None):
        """Track application event"""
        try:
            with db.transaction() as conn:
                conn.execute("""
                    INSERT INTO events (user_id, event_type, event_data, ip_address, user_agent, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    user_id, event_type, json.dumps(properties or {}),
                    request.remote_addr, 
                    request.user_agent.string[:500] if request.user_agent else None,
                    datetime.utcnow()
                ))
        except Exception as e:
            logger.error(f"Error tracking event: {e}")

# =========================
# Error Handling and Monitoring
# =========================

class ErrorHandler:
    """Centralized error handling and monitoring"""
    
    def __init__(self):
        self._error_counts = defaultdict(int)
        self._last_reset = datetime.utcnow()
        self._lock = threading.RLock()
    
    def handle_exception(self, e: Exception, context: Dict[str, Any] = None) -> str:
        """Handle application exception with logging and tracking"""
        error_id = str(uuid.uuid4())[:8]
        
        # Log the error
        logger.error(f"Error {error_id}: {str(e)}", exc_info=True)
        
        # Track error frequency
        with self._lock:
            self._error_counts[type(e).__name__] += 1
            
            # Reset counts every hour
            if datetime.utcnow() - self._last_reset > timedelta(hours=1):
                self._error_counts.clear()
                self._last_reset = datetime.utcnow()
        
        # Store error details (in production, might send to external service)
        try:
            error_data = {
                'id': error_id,
                'type': type(e).__name__,
                'message': str(e),
                'traceback': traceback.format_exc(),
                'context': context or {},
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'user_id': getattr(g, 'current_user', {}).id if hasattr(g, 'current_user') and g.current_user else None
            }
            
            file_storage.save_json(f"errors/error_{error_id}.json", error_data, create_backup=False)
            
        except Exception as log_error:
            logger.error(f"Failed to save error details: {log_error}")
        
        return error_id
    
    def get_error_summary(self) -> Dict[str, Any]:
        """Get summary of recent errors"""
        with self._lock:
            return {
                'error_counts': dict(self._error_counts),
                'period_start': self._last_reset.isoformat() + 'Z',
                'total_errors': sum(self._error_counts.values())
            }

# =========================
# Route Handlers for Final Features
# =========================

# Global services
payment_service = PaymentService() if HAS_STRIPE else None
analytics_service = AnalyticsService()
error_handler = ErrorHandler()

# Billing routes
@app.route("/billing")
@login_required
def billing_page():
    """Billing and subscription management"""
    user = g.current_user
    subscription_type = SubscriptionType(user.subscription)
    
    # Get usage dashboard data
    dashboard_data = subscription_service.get_user_usage_dashboard(user)
    
    # Build subscription cards if user is inactive
    if subscription_type == SubscriptionType.INACTIVE:
        subscription_cards = component_builder.build_subscription_cards(subscription_type)
        
        content = f"""
        <div class="container">
            <div class="row justify-content-center">
                <div class="col-lg-10">
                    <div class="card">
                        <div class="card-header bg-warning text-dark">
                            <h3 class="mb-0">
                                <i class="bi bi-credit-card me-2"></i>Billing & Subscription
                            </h3>
                        </div>
                        <div class="card-body">
                            <div class="alert alert-info border-0 mb-4">
                                <div class="d-flex align-items-center">
                                    <i class="bi bi-info-circle fs-4 me-3"></i>
                                    <div>
                                        <h6 class="alert-heading mb-1">Current Plan: Free Plan</h6>
                                        <p class="mb-0">Upgrade for unlimited access to all features including AI tutor, practice quizzes, and progress tracking.</p>
                                    </div>
                                </div>
                            </div>
                            
                            {subscription_cards}
                        </div>
                    </div>
                </div>
            </div>
        </div>
        """
    else:
        # Active subscription - show management options
        plan_config = SubscriptionConfig.get_plan(subscription_type)
        
        content = f"""
        <div class="container">
            <div class="row justify-content-center">
                <div class="col-lg-8">
                    <div class="card">
                        <div class="card-header bg-success text-white">
                            <h3 class="mb-0">
                                <i class="bi bi-credit-card me-2"></i>Billing & Subscription
                            </h3>
                        </div>
                        <div class="card-body">
                            <div class="alert alert-success border-0 mb-4">
                                <div class="d-flex align-items-center">
                                    <i class="bi bi-check-circle fs-4 me-3"></i>
                                    <div>
                                        <h6 class="alert-heading mb-1">Active Plan: {plan_config.name}</h6>
                                        <p class="mb-0">You have unlimited access to all features.</p>
                                        {f'<p class="mb-0"><small>Expires: {user.subscription_expires_at.strftime("%B %d, %Y")}</small></p>' if user.subscription_expires_at else ''}
                                    </div>
                                </div>
                            </div>
                            
                            <div class="text-center">
                                <p class="text-muted">Need to make changes to your subscription? Contact support for assistance.</p>
                                <a href="mailto:support@cpptestprep.com" class="btn btn-outline-primary">
                                    <i class="bi bi-envelope me-1"></i>Contact Support
                                </a>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        """
    
    return render_page("Billing", content)

@app.route("/billing/checkout")
@login_required
def billing_checkout():
    """Redirect to Stripe checkout"""
    if not payment_service:
        flash("Payment processing is not available", "error")
        return redirect(url_for('billing_page'))
    
    plan = request.args.get("plan", "monthly")
    if plan not in ["monthly", "sixmonth"]:
        plan = "monthly"
    
    checkout_url = payment_service.create_checkout_session(g.current_user.email, plan)
    
    if checkout_url:
        return redirect(checkout_url)
    else:
        flash("Unable to create checkout session. Please try again.", "error")
        return redirect(url_for('billing_page'))

@app.route("/billing/success")
@login_required
def billing_success():
    """Billing success page"""
    plan = request.args.get("plan", "monthly")
    plan_name = "Monthly Plan" if plan == "monthly" else "6-Month Plan"
    
    content = f"""
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-md-6">
                <div class="card text-center">
                    <div class="card-body p-5">
                        <i class="bi bi-check-circle-fill text-success display-1 mb-4"></i>
                        <h2 class="text-success mb-3">Payment Successful!</h2>
                        <p class="text-muted mb-4">
                            Your {plan_name} subscription is now active. You have unlimited access to all features.
                        </p>
                        <a href="{url_for('home')}" class="btn btn-primary btn-lg">
                            <i class="bi bi-house-door me-1"></i>Start Learning
                        </a>
                    </div>
                </div>
            </div>
        </div>
    </div>
    """
    
    return render_page("Payment Successful", content)

# Stripe webhook endpoint
@app.route("/stripe/webhook", methods=["POST"])
def stripe_webhook():
    """Handle Stripe webhook events"""
    if not payment_service:
        return "Payment service not configured", 400
    
    payload = request.data
    signature = request.headers.get("Stripe-Signature", "")
    
    success, message = payment_service.handle_webhook(payload, signature)
    
    if success:
        return message, 200
    else:
        logger.error(f"Webhook processing failed: {message}")
        return message, 400

# Usage dashboard
@app.route("/usage")
@login_required
def usage_dashboard():
    """User usage dashboard"""
    user = g.current_user
    dashboard_data = subscription_service.get_user_usage_dashboard(user)
    
    # Build usage indicators
    usage_indicators = ""
    for action_type in UsageActionType:
        type_data = dashboard_data['usage_by_type'].get(action_type.value, {})
        used = type_data.get('used', 0)
        limit = type_data.get('limit', 0)
        
        action_name = {
            'quizzes': 'Practice Quizzes',
            'questions': 'Questions Answered', 
            'tutor_msgs': 'Tutor Messages',
            'flashcards': 'Flashcard Sessions'
        }.get(action_type.value, action_type.value)
        
        indicator = component_builder.build_usage_indicator(action_type, used, limit)
        
        usage_indicators += f"""
        <div class="card mb-3">
            <div class="card-body">
                <div class="d-flex justify-content-between align-items-center mb-2">
                    <h6 class="mb-0">{action_name}</h6>
                </div>
                {indicator}
            </div>
        </div>
        """
    
    # Build history chart (simplified)
    history_chart = ""
    if dashboard_data.get('history'):
        chart_data = dashboard_data['history'][-6:]  # Last 6 months
        history_chart = component_builder.build_progress_chart(
            [type('Summary', (), {
                'period_start': datetime.fromisoformat(item['period'] + '-01'),
                'get_usage': lambda at: item['total']
            }) for item in chart_data],
            UsageActionType.QUIZ
        )
    
    content = f"""
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-lg-10">
                <div class="card">
                    <div class="card-header bg-info text-white">
                        <h3 class="mb-0">
                            <i class="bi bi-graph-up me-2"></i>Usage Dashboard
                        </h3>
                    </div>
                    <div class="card-body">
                        <div class="row">
                            <div class="col-md-8">
                                <h5 class="mb-3">Current Usage</h5>
                                {usage_indicators}
                            </div>
                            <div class="col-md-4">
                                <h5 class="mb-3">Usage History</h5>
                                {history_chart}
                            </div>
                        </div>
                        
                        <div class="text-center mt-4">
                            <a href="{url_for('billing_page')}" class="btn btn-primary">
                                <i class="bi bi-credit-card me-1"></i>Manage Subscription
                            </a>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    """
    
    return render_page("Usage Dashboard", content)

# Progress tracking
@app.route("/progress")
@login_required  
def progress_page():
    """User progress and performance tracking"""
    user = g.current_user
    
    try:
        # Get user attempts from database
        with db.get_connection() as conn:
            attempts = conn.execute("""
                SELECT id, attempt_type, question_count, correct_count, score_percentage,
                       domain_filter, started_at, completed_at
                FROM user_attempts 
                WHERE user_id = ? AND completed_at IS NOT NULL
                ORDER BY completed_at DESC
                LIMIT 50
            """, (user.id,)).fetchall()
        
        # Calculate summary stats
        total_attempts = len(attempts)
        total_questions = sum(row['question_count'] for row in attempts)
        total_correct = sum(row['correct_count'] for row in attempts)
        
        avg_score = sum(row['score_percentage'] for row in attempts) / total_attempts if total_attempts > 0 else 0
        best_score = max((row['score_percentage'] for row in attempts), default=0)
        
        # Build attempts table
        attempts_rows = []
        for attempt in attempts[:20]:  # Show last 20
            attempt_type = "Mock Exam" if attempt['attempt_type'] == 'mock_exam' else "Quiz"
            date_str = datetime.fromisoformat(attempt['completed_at'].replace('Z', '')).strftime('%m/%d %I:%M%p')
            domain = DomainManager.get_domain_name(attempt['domain_filter']) if attempt['domain_filter'] else "Mixed"
            
            attempts_rows.append(f"""
            <tr>
                <td>{date_str}</td>
                <td>{attempt_type}</td>
                <td>{domain}</td>
                <td class="text-end">{attempt['correct_count']}/{attempt['question_count']}</td>
                <td class="text-end">{attempt['score_percentage']:.1f}%</td>
            </tr>
            """)
        
        attempts_table = "".join(attempts_rows) if attempts_rows else """
        <tr><td colspan="5" class="text-center text-muted">No completed attempts yet</td></tr>
        """
        
        content = f"""
        <div class="container">
            <div class="row justify-content-center">
                <div class="col-lg-10">
                    <div class="card">
                        <div class="card-header bg-primary text-white">
                            <h3 class="mb-0">
                                <i class="bi bi-graph-up-arrow me-2"></i>Progress & Performance
                            </h3>
                        </div>
                        <div class="card-body">
                            <!-- Summary Stats -->
                            <div class="row g-3 mb-4">
                                <div class="col-md-3">
                                    <div class="p-3 border rounded-3 text-center">
                                        <div class="h4 text-primary mb-1">{total_attempts}</div>
                                        <div class="small text-muted">Attempts</div>
                                    </div>
                                </div>
                                <div class="col-md-3">
                                    <div class="p-3 border rounded-3 text-center">
                                        <div class="h4 text-success mb-1">{total_questions}</div>
                                        <div class="small text-muted">Questions</div>
                                    </div>
                                </div>
                                <div class="col-md-3">
                                    <div class="p-3 border rounded-3 text-center">
                                        <div class="h4 text-info mb-1">{avg_score:.1f}%</div>
                                        <div class="small text-muted">Average</div>
                                    </div>
                                </div>
                                <div class="col-md-3">
                                    <div class="p-3 border rounded-3 text-center">
                                        <div class="h4 text-warning mb-1">{best_score:.1f}%</div>
                                        <div class="small text-muted">Best Score</div>
                                    </div>
                                </div>
                            </div>
                            
                            <!-- Recent Attempts -->
                            <h5 class="mb-3">Recent Attempts</h5>
                            <div class="table-responsive">
                                <table class="table table-sm align-middle">
                                    <thead class="table-light">
                                        <tr>
                                            <th>Date</th>
                                            <th>Type</th>
                                            <th>Domain</th>
                                            <th class="text-end">Score</th>
                                            <th class="text-end">Percentage</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {attempts_table}
                                    </tbody>
                                </table>
                            </div>
                            
                            <div class="text-center mt-4">
                                <a href="{url_for('quiz_page')}" class="btn btn-primary me-2">
                                    <i class="bi bi-card-text me-1"></i>Take Quiz
                                </a>
                                <a href="{url_for('mock_exam_page')}" class="btn btn-outline-primary">
                                    <i class="bi bi-clipboard-check me-1"></i>Mock Exam
                                </a>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        """
        
        return render_page("Progress", content)
        
    except Exception as e:
        error_id = error_handler.handle_exception(e, {'user_id': user.id, 'endpoint': 'progress'})
        flash(f"Unable to load progress data. Error ID: {error_id}", "error")
        return redirect(url_for('home'))

# Global error handlers
@app.errorhandler(403)
def handle_forbidden(e):
    return render_error_page(403, "Access Forbidden", "You don't have permission to access this resource.")

@app.errorhandler(404) 
def handle_not_found(e):
    return render_error_page(404, "Page Not Found", "The page you're looking for doesn't exist.")

@app.errorhandler(429)
def handle_rate_limited(e):
    return render_error_page(429, "Too Many Requests", "Please wait before trying again.")

@app.errorhandler(500)
def handle_server_error(e):
    error_id = error_handler.handle_exception(e, {'endpoint': request.endpoint})
    return render_error_page(500, "Server Error", f"An unexpected error occurred. Error ID: {error_id}")

# Application startup and shutdown
def cleanup_on_shutdown():
    """Clean up resources on application shutdown"""
    try:
        logger.info("Application shutting down...")
        
        # Cleanup quiz sessions
        quiz_session_manager.cleanup_expired_sessions()
        
        # Close database connections
        db.close_connection()
        
        logger.info("Cleanup completed")
        
    except Exception as e:
        logger.error(f"Error during shutdown cleanup: {e}")

# Signal handlers for graceful shutdown
def signal_handler(signum, frame):
    """Handle shutdown signals"""
    logger.info(f"Received signal {signum}, shutting down gracefully...")
    cleanup_on_shutdown()
    sys.exit(0)

signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)

# Initialize sample data for new installations
def init_sample_data():
    """Initialize sample data if database is empty"""
    try:
        # Check if we have any questions
        existing_questions = question_repo.get_questions(limit=1)
        if existing_questions:
            return
        
        logger.info("Initializing sample data...")
        
        # Add base questions from Section 1 if none exist
        for q_data in BASE_QUESTIONS:
            try:
                # Add ID and sources
                q_data_copy = q_data.copy()
                q_data_copy['id'] = str(uuid.uuid4())
                q_data_copy['sources'] = []
                
                question_repo.create_question(q_data_copy)
            except Exception as e:
                logger.warning(f"Failed to add sample question: {e}")
        
        logger.info("Sample data initialized")
        
    except Exception as e:
        logger.error(f"Error initializing sample data: {e}")

# Application factory for production deployment
def create_production_app():
    """Create production-ready application instance"""
    try:
        # Initialize sample data
        init_sample_data()
        
        # Setup periodic cleanup tasks
        @app.before_request
        def periodic_cleanup():
            """Run periodic cleanup tasks"""
            try:
                # Cleanup quiz sessions
                quiz_session_manager.cleanup_expired_sessions()
                
                # Cleanup old usage records (once per day)
                if datetime.utcnow().hour == 2:  # 2 AM cleanup
                    subscription_service.usage_repo.cleanup_old_usage()
                    
            except Exception as e:
                logger.error(f"Periodic cleanup error: {e}")
        
        logger.info(f"CPP Test Prep v{config.APP_VERSION} production app created successfully")
        return app
        
    except Exception as e:
        logger.error(f"Failed to create production app: {e}")
        raise

# For development server
if __name__ == "__main__":
    try:
        create_production_app()
        port = int(os.environ.get("PORT", 5000))
        host = os.environ.get("HOST", "0.0.0.0")
        
        logger.info(f"Starting development server on {host}:{port}")
        app.run(host=host, port=port, debug=config.DEBUG)
        
    except Exception as e:
        logger.error(f"Failed to start application: {e}")
        sys.exit(1)
    finally:
        cleanup_on_shutdown()

logger.info("Section 8: Payment Processing, Analytics, Error Handling, and Application Deployment - initialized")
logger.info("CPP Test Prep application fully initialized and ready for production deployment")
