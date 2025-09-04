# STABILITY: Ensure source is parsed as UTF-8 everywhere (avoids invalid char errors on Render)
# -*- coding: utf-8 -*-

# =========================
# SECTION 1/8: Imports, App Config, Utilities, Security, Base Layout (+ Footer, Home, Terms)
# =========================

# STABILITY: keep imports largely the same; add ProxyFix and g for request logging & proxy headers.
import os, re, json, time, uuid, hashlib, random, html, logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Tuple
from urllib.parse import quote as _urlquote

from flask import (
    Flask, request, session, redirect, url_for, abort, jsonify, make_response, g
)
from flask import render_template_string
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix  # STABILITY: honor X-Forwarded-* on Render

# ---- App & Logging ----
APP_VERSION = "1.0.0"

# STABILITY: env bool helper used throughout
def _env_bool(val: str | None, default: bool = False) -> bool:
    s = (val if val is not None else ("1" if default else "0")).strip().lower()
    return s in ("1", "true", "yes", "y", "on")

IS_STAGING = _env_bool(os.environ.get("STAGING", "0"), default=False)
DEBUG = _env_bool(os.environ.get("DEBUG", "0"), default=False)

# STABILITY: compute SECRET_KEY & cookie security early and fail fast when unsafe
SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-change-me")
SESSION_COOKIE_SECURE_FLAG = _env_bool(os.environ.get("SESSION_COOKIE_SECURE", "1"), default=True)
if (SESSION_COOKIE_SECURE_FLAG or not DEBUG) and SECRET_KEY == "dev-secret-change-me":
    raise RuntimeError(
        "SECURITY: SECRET_KEY must be set to a non-default value when running with "
        "SESSION_COOKIE_SECURE=1 or when DEBUG is false."
    )

app = Flask(__name__)
app.secret_key = SECRET_KEY

# STABILITY: session & CSRF config hardening; CSRF time limit off for compatibility
app.config.update(
    SESSION_COOKIE_SECURE=SESSION_COOKIE_SECURE_FLAG,
    SESSION_COOKIE_SAMESITE="Lax",
    WTF_CSRF_TIME_LIMIT=None,
)

# STABILITY: trust Render’s proxy headers so request.url_root is https://
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

logger = logging.getLogger("cpp_prep")
handler = logging.StreamHandler()
fmt = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
handler.setFormatter(fmt)
logger.setLevel(logging.INFO)
logger.addHandler(handler)

# ---- Paths & Data ----
# STABILITY: DATA_DIR reads env DATA_DIR or legacy Data_Dir, with fallback to ./data
DATA_DIR = (
    os.environ.get("DATA_DIR")
    or os.environ.get("Data_Dir")
    or os.path.join(os.getcwd(), "data")
)
os.makedirs(DATA_DIR, exist_ok=True)

# ---- Feature Flags / Keys (display-only in this section) ----
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
OPENAI_API_BASE = os.environ.get("OPENAI_API_BASE", "https://api.openai.com/v1")
OPENAI_CHAT_MODEL = os.environ.get("OPENAI_CHAT_MODEL", "gpt-4o-mini")

STRIPE_PUBLISHABLE_KEY = os.environ.get("STRIPE_PUBLISHABLE_KEY", "")
STRIPE_MONTHLY_PRICE_ID = os.environ.get("STRIPE_MONTHLY_PRICE_ID", "")
STRIPE_SIXMONTH_PRICE_ID = os.environ.get("STRIPE_SIXMONTH_PRICE_ID", "")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
# NOTE: STRIPE_SECRET_KEY and stripe import/config live in Section 5.

ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")

# ---- CSRF (harmonized with Flask-WTF if available) ----
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
    """Return a form token that matches what CSRFProtect expects when enabled."""
    if HAS_CSRF:
        return generate_csrf()
    val = session.get("_csrf_token")
    if not val:
        val = uuid.uuid4().hex
        session["_csrf_token"] = val
    return val

def _csrf_ok() -> bool:
    """When Flask-WTF is active it enforces CSRF; fallback here is a simple equality check."""
    if HAS_CSRF:
        return True
    return (request.form.get("csrf_token") == session.get("_csrf_token"))

# ---- Simple Rate Limit (per IP/Path) ----
_RATE = {}
def _rate_ok(key: str, per_sec: float = 1.0) -> bool:
    t = time.time()
    last = _RATE.get(key, 0.0)
    if (t - last) < (1.0 / per_sec):
        return False
    _RATE[key] = t
    return True

# ---- Security Headers & CSP (this is the single CSP owner) ----
# Other sections may add headers with resp.headers.setdefault(...), but should NOT override CSP.
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
def sec1_after_request(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer-when-downgrade"
    resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    # HSTS is safe if you serve over HTTPS (Render does). Tune as desired.
    resp.headers.setdefault("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
    # Single CSP owner — other sections must not overwrite this.
    resp.headers["Content-Security-Policy"] = CSP
    return resp

# STABILITY: lightweight request logger (skip /static and /favicon.ico)
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

# ---- JSON helpers ----
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

# STABILITY: atomic JSON write (write .tmp, fsync, os.replace)
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

# ---- Users store helpers ----
def _users_all() -> List[dict]:
    return _load_json("users.json", [])

def _find_user(email: str) -> dict | None:
    email = (email or "").strip().lower()
    for u in _users_all():
        if (u.get("email") or "").lower() == email:
            return u
    return None

def _update_user(uid: str, patch: dict):
    users = _users_all()
    for u in users:
        if u.get("id") == uid:
            u.update(patch or {})
            break
    _save_json("users.json", users)

def _create_user(email: str, password: str) -> Tuple[bool, str]:
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
        "subscription": "inactive",
        "terms_accept_version": "",
        "terms_accept_ts": ""
    })
    _save_json("users.json", users)
    return True, uid

def validate_password(pw: str) -> Tuple[bool, str]:
    if not pw or len(pw) < 8:
        return False, "Password must be at least 8 characters."
    return True, ""

# ---- Sessions / Auth guards ----
def _login_redirect_url(next_path: str | None = None) -> str:
    """
    Build a safe login URL:
    - Prefer a real login endpoint if it exists (e.g., 'login' or 'sec1_login_page').
    - Fall back to '/login?next=...'.
    Never points to admin login.
    """
    next_val = next_path or request.path or "/"
    try:
        for ep in ("login", "login_page", "sec3_login_page", "sec1_login_page", "sec2_login_page"):
            if ep in app.view_functions:
                return url_for(ep, next=next_val)
    except Exception:
        pass
    return f"/login?next={_urlquote(next_val)}"

def _user_id() -> str:
    return session.get("uid", "")

def login_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not _user_id():
            return redirect(_login_redirect_url(request.path))
        return fn(*args, **kwargs)
    return wrapper

def is_admin() -> bool:
    return bool(session.get("admin_ok"))

# ---- Events / Usage (minimal event logger) ----
def _log_event(uid: str, name: str, data: dict | None = None):
    evts = _load_json("events.json", [])
    evts.append({
        "ts": datetime.utcnow().isoformat() + "Z",
        "user_id": uid,
        "name": name,
        "data": data or {}
    })
    _save_json("events.json", evts)

# ---- Canonical Domains ----
DOMAINS = {
    "random": "Random",
    "security-principles": "Security Principles & Practices",
    "business-principles": "Business Principles & Practices",
    "investigations": "Investigations",
    "personnel-security": "Personnel Security",
    "physical-security": "Physical Security",
    "information-security": "Information Security",
    "crisis-management": "Crisis Management",
}

# ---- Domain Buttons helper (shared across sections) ----
def domain_buttons_html(selected_key="random", field_name="domain"):
    order = ["random","security-principles","business-principles","investigations",
             "personnel-security","physical-security","information-security","crisis-management"]
    b = []
    for k in order:
        lab = "Random (all)" if k == "random" else DOMAINS.get(k, k)
        active = " active" if selected_key == k else ""
        b.append(
            f'<button type="button" class="btn btn-outline-success domain-btn{active}" '
            f'data-value="{html.escape(k)}">{html.escape(lab)}</button>'
        )
    hidden = (
        f'<input type="hidden" id="domain_val" name="{html.escape(field_name)}" '
        f'value="{html.escape(selected_key)}"/>'
    )
    return f'<div class="d-flex flex-wrap gap-2">{"".join(b)}</div>{hidden}'

# ---- Global Footer ----
def _footer_html():
    # STABILITY: replace © with &copy; to avoid source-encoding issues in some environments.
    return """
    <footer class="mt-5 py-3 border-top text-center small text-muted">
      <div>
        Educational use only. Not affiliated with ASIS. No legal, safety, or professional advice.
        Use official sources to verify. No refunds. &copy; CPP-Exam-Prep
      </div>
    </footer>
    """

# ---- Base Layout with Bootstrap & footer ----
def base_layout(title: str, body_html: str) -> str:
    # Render with Jinja (no Python f-string surrounding Jinja syntax)
    tpl = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{ title }} — CPP Exam Prep</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css" rel="stylesheet">
  <style>
    .fc-card .front, .fc-card .back { min-height: 120px; padding: 1rem; border: 1px solid #ddd; border-radius: .5rem; }
    .fc-card .front { background: #f8f9fa; }
  </style>
</head>
<body>
  <nav class="navbar navbar-expand-lg bg-light border-bottom">
    <div class="container">
      <a class="navbar-brand" href="/"><i class="bi bi-shield-lock"></i> CPP Prep</a>
      <div class="ms-auto d-flex align-items-center gap-3">
        <a class="text-decoration-none" href="/flashcards">Flashcards</a>
        <a class="text-decoration-none" href="/progress">Progress</a>
        <a class="text-decoration-none" href="/usage">Usage</a>
        <a class="text-decoration-none" href="/billing">Billing</a>
        <a class="text-decoration-none" href="/tutor">Tutor</a>
        <a class="text-decoration-none" href="/legal/terms">Terms</a>
        {% if session.get('uid') %}
          <a class="btn btn-outline-danger btn-sm" href="/logout">Logout</a>
        {% else %}
          <a class="btn btn-outline-primary btn-sm" href="/login">Login</a>
        {% endif %}
      </div>
    </div>
  </nav>

  <main class="py-4">
    {{ body_html | safe }}
  </main>

  {{ footer | safe }}

  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
    """
    return render_template_string(tpl, title=(title or "CPP Exam Prep"), body_html=body_html, footer=_footer_html())

# ---- Domain weights (for Content Balance; used later) ----
DOMAIN_TARGETS = {
    "security-principles": {"total": 198, "MCQ": 99, "TF": 50, "SC": 50},
    "business-principles": {"total": 198, "MCQ": 99, "TF": 50, "SC": 50},
    "investigations": {"total": 108, "MCQ": 54, "TF": 27, "SC": 27},
    "personnel-security": {"total": 90,  "MCQ": 45, "TF": 22, "SC": 22},
    "physical-security":  {"total": 180, "MCQ": 90, "TF": 45, "SC": 45},
    "information-security":{"total": 54,  "MCQ": 27, "TF": 14, "SC": 14},
    "crisis-management":  {"total": 72,  "MCQ": 36, "TF": 18, "SC": 18},
}

# ---- App init helpers used later ----
def init_sample_data():
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        for name, default in [
            ("users.json", []),
            ("questions.json", []),
            ("flashcards.json", []),
            ("attempts.json", []),
            ("events.json", []),
            # STABILITY: use _env_bool for TUTOR_WEB_AWARE flag
            ("tutor_settings.json", {"web_aware": _env_bool(os.environ.get("TUTOR_WEB_AWARE", "0"), default=False)}),
            ("bank/cpp_flashcards_v1.json", []),
            ("bank/cpp_questions_v1.json", []),
            ("bank/content_index.json", {}),
        ]:
            p = _path(name)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            if not os.path.exists(p):
                _save_json(name, default)
    except Exception as e:
        logger.warning("init_sample_data error: %s", e)

# Ensure initial data files exist at startup
init_sample_data()

# ---- Public, unprotected routes owned by Section 1 ----
# STABILITY: provide real owners for "/" and "/legal/terms" to avoid 404 at root.

@app.get("/", endpoint="sec1_home_page")
def sec1_home_page():
    body = """
    <div class="container">
      <div class="py-4">
        <h1 class="h3 mb-3"><i class="bi bi-shield-lock"></i> CPP Prep</h1>
        <p class="text-muted mb-4">
          Self-study AI-assisted prep for the ASIS Certified Protection Professional (CPP) exam.
          Educational use only; not affiliated with ASIS.
        </p>

        <div class="row g-3">
          <div class="col-md-6">
            <div class="p-3 border rounded-3 h-100">
              <h2 class="h5 mb-2"><i class="bi bi-ui-checks-grid me-1"></i> Quiz</h2>
              <p class="mb-2 small text-muted">Practice by domain or mix everything.</p>
              <a class="btn btn-primary btn-sm" href="/quiz">Go to Quiz</a>
            </div>
          </div>
          <div class="col-md-6">
            <div class="p-3 border rounded-3 h-100">
              <h2 class="h5 mb-2"><i class="bi bi-journal-check me-1"></i> Mock Exam</h2>
              <p class="mb-2 small text-muted">Longer, exam-style sessions.</p>
              <a class="btn btn-warning btn-sm" href="/mock">Start Mock</a>
            </div>
          </div>
          <div class="col-md-6">
            <div class="p-3 border rounded-3 h-100">
              <h2 class="h5 mb-2"><i class="bi bi-layers me-1"></i> Flashcards</h2>
              <p class="mb-2 small text-muted">Flip through key facts and terms.</p>
              <a class="btn btn-success btn-sm" href="/flashcards">Open Flashcards</a>
            </div>
          </div>
          <div class="col-md-6">
            <div class="p-3 border rounded-3 h-100">
              <h2 class="h5 mb-2"><i class="bi bi-chat-dots me-1"></i> Tutor</h2>
              <p class="mb-2 small text-muted">Ask questions, get quick explanations.</p>
              <a class="btn btn-secondary btn-sm" href="/tutor">Ask the Tutor</a>
            </div>
          </div>
        </div>

        <div class="mt-4">
          <a class="btn btn-outline-secondary btn-sm" href="/progress"><i class="bi bi-graph-up me-1"></i> Progress</a>
          <a class="btn btn-outline-secondary btn-sm" href="/usage"><i class="bi bi-speedometer2 me-1"></i> Usage</a>
          <a class="btn btn-outline-secondary btn-sm" href="/billing"><i class="bi bi-credit-card me-1"></i> Billing</a>
          <a class="btn btn-outline-secondary btn-sm" href="/legal/terms"><i class="bi bi-file-earmark-text me-1"></i> Terms</a>
        </div>
      </div>
    </div>
    """
    return base_layout("Home", body)

@app.get("/legal/terms", endpoint="sec1_legal_terms")
def sec1_legal_terms():
    body = """
    <div class="container">
      <div class="py-4">
        <h1 class="h4 mb-3"><i class="bi bi-file-earmark-text"></i> Terms</h1>
        <div class="p-3 border rounded-3">
          <p class="small text-muted mb-2">
            Educational use only. Not affiliated with ASIS International. This site provides practice
            content generated from public sources; it does not include actual exam items. No legal,
            safety, or professional advice. Verify information with official sources.
          </p>
          <p class="small text-muted mb-0">
            Use constitutes acceptance of these terms. No refunds.
          </p>
        </div>
        <a class="btn btn-outline-secondary mt-3" href="/"><i class="bi bi-house me-1"></i> Home</a>
      </div>
    </div>
    """
    return base_layout("Terms", body)

# =========================
# SECTION 2/8 — Operational & Security Utilities
# Owner notes:
#   - This section is the ONLY owner of:
#       * GET /healthz
#       * GET /robots.txt
#       * GET /favicon.ico
#   - Endpoints are prefixed with "sec2_" to avoid collisions.
#   - Security headers here are applied with `setdefault` only, so they DO NOT
#     override the definitive CSP & headers set in Section 1.
# =========================

# STABILITY: local imports (explicit here to avoid cross-section coupling issues)
import os
import time
from datetime import datetime, timezone
from flask import jsonify, make_response, Response

# Monotonic start reference for uptime (local to Section 2)
_SEC2_START_TS = time.time()

def _sec2_safe_get(name: str, default=None):
    """Safely read globals defined in other sections (e.g., Section 1) without import-order issues."""
    return globals().get(name, default)

@app.get("/healthz", endpoint="sec2_healthz")
def sec2_healthz():
    """
    Lightweight liveness/readiness probe for Render/ingress health checks.
    Returns static/low-cost info only (no DB, no network).
    """
    now = time.time()
    uptime_s = int(now - _SEC2_START_TS)

    # Pull shared metadata if available; fall back safely.
    app_version = _sec2_safe_get("APP_VERSION", "unknown")
    debug_mode = bool(_sec2_safe_get("DEBUG", False))
    is_staging = bool(_sec2_safe_get("IS_STAGING", False))

    # STABILITY: Determine DATA_DIR from Section 1, then check existence & writability.
    data_dir = _sec2_safe_get("DATA_DIR", os.path.join(os.getcwd(), "data"))
    data_dir_exists = bool(data_dir and os.path.isdir(data_dir))

    data_dir_writable = False
    if data_dir_exists:
        try:
            # Try a tiny write/delete to confirm actual write permissions.
            test_name = f".healthz_{int(now)}_{os.getpid()}.tmp"
            test_path = os.path.join(data_dir, test_name)
            with open(test_path, "w", encoding="utf-8") as f:
                f.write("ok")
                f.flush()
                os.fsync(f.fileno())
            os.remove(test_path)
            data_dir_writable = True
        except Exception:
            data_dir_writable = False

    return jsonify({
        "ok": True,
        "service": "cpp-exam-prep",
        "version": str(app_version),         # kept for backward compatibility
        "app_version": str(app_version),     # STABILITY: explicit field as requested
        "debug": debug_mode,
        "staging": is_staging,
        "started_at": datetime.fromtimestamp(_SEC2_START_TS, tz=timezone.utc).isoformat(),
        "uptime_seconds": uptime_s,
        # STABILITY: new health fields
        "data_dir_exists": data_dir_exists,
        "data_dir_writable": data_dir_writable,
    })

@app.get("/robots.txt", endpoint="sec2_robots_txt")
def sec2_robots_txt():
    """
    Minimal robots policy to reduce 404 noise and make crawler intent explicit.
    """
    body = "User-agent: *\nDisallow: /admin/\nDisallow: /api/\n"
    resp = make_response(body, 200)
    resp.headers["Content-Type"] = "text/plain; charset=utf-8"
    return resp

@app.get("/favicon.ico", endpoint="sec2_favicon")
def sec2_favicon():
    """
    Favicon handler to stop 404 spam. If/when you add a real icon, replace with send_from_directory.
    Returning 204 is acceptable for browsers.
    """
    # Example for later:
    # from flask import send_from_directory
    # return send_from_directory("static", "favicon.ico")
    return Response(status=204)

# ---- Additive Security Headers (idempotent) ---------------------------------
# Important: Section 1 is the single owner of CSP and core headers. Here we only
# provide defaults where they are missing. We NEVER overwrite values set earlier.
@app.after_request
def sec2_apply_security_headers(resp):
    # DO NOT overwrite CSP set in Section 1; only provide a default if somehow missing.
    csp_default = (
        "default-src 'self'; "
        "img-src 'self' data: https:; "
        "style-src 'self' 'unsafe-inline' https:; "
        "script-src 'self' 'unsafe-inline'; "
        "font-src 'self' https: data:; "
        "connect-src 'self' https:; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )
    resp.headers.setdefault("Content-Security-Policy", csp_default)

    # Common hardening headers (only set if not already present)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    # Use the stricter variant when we are the one providing the default
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

    # HSTS default if HTTPS is expected (true on Render). Section 1 already sets this;
    # this is just a safety net if order ever changes.
    if _sec2_safe_get("ENABLE_HSTS", True):
        resp.headers.setdefault("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
    return resp
# ========================= END SECTION 2/8 =========================

# =========================
# =========================
# SECTION 3/8 — Quiz & Practice
# Routes (must match your existing ownership):
#   /quiz                   [GET, POST]
#   /practice               [GET, POST]
#   /results                [GET]
# =========================
from flask import render_template_string

# NOTE: This section intentionally renders any HTML that contains <script> with
#       render_template_string to avoid Python f-string parsing of JS braces.

# ---------- Shared tiny helpers ----------
def _domain_label(key: str) -> str:
    return DOMAINS.get(key, "Mixed") if key and key != "random" else "Random (all)"

def _safe_int(v, default: int) -> int:
    try:
        x = int(v)
        return x
    except Exception:
        return default

# ---------- QUIZ PICKER ----------
@app.route("/quiz", methods=["GET", "POST"], endpoint="sec3_quiz_page")
@login_required
def sec3_quiz_page():
    if request.method == "GET":
        csrf_val = csrf_token()
        domain_buttons = domain_buttons_html(selected_key="random", field_name="domain")

        tpl = """
        <div class="container">
          <div class="row justify-content-center"><div class="col-lg-8 col-xl-7">
            <div class="card">
              <div class="card-header bg-primary text-white">
                <h3 class="mb-0"><i class="bi bi-check2-circle me-2"></i>Quiz</h3>
              </div>
              <div class="card-body">
                <form method="POST" class="mb-3">
                  <input type="hidden" name="csrf_token" value="{{ csrf_val }}"/>
                  <label class="form-label fw-semibold">Domain</label>
                  {{ domain_buttons|safe }}
                  <div class="row g-3 mt-2">
                    <div class="col-sm-6">
                      <label class="form-label fw-semibold">Number of questions</label>
                      <div class="d-flex flex-wrap gap-2">
                        <button class="btn btn-outline-primary" name="count" value="10">10</button>
                        <button class="btn btn-outline-primary" name="count" value="20">20</button>
                        <button class="btn btn-outline-primary" name="count" value="30">30</button>
                      </div>
                    </div>
                    <div class="col-sm-6">
                      <label class="form-label fw-semibold">Mode</label>
                      <div>
                        <label class="me-3"><input type="radio" name="mode" value="exam" checked> Exam</label>
                        <label class="me-3"><input type="radio" name="mode" value="practice"> Practice</label>
                      </div>
                    </div>
                  </div>
                </form>
                <div class="text-muted small">Tip: Choose a domain or use Random to mix all.</div>
              </div>
            </div>
          </div></div>
        </div>

        <script>
          (function() {
            var container = document.currentScript.closest('.card').querySelector('.card-body');
            var hidden = container.querySelector('#domain_val');
            container.querySelectorAll('.domain-btn').forEach(function(btn) {
              btn.addEventListener('click', function() {
                container.querySelectorAll('.domain-btn').forEach(function(b) { b.classList.remove('active'); });
                btn.classList.add('active');
                if (hidden) hidden.value = btn.getAttribute('data-value');
              });
            });
          })();
        </script>
        """
        return base_layout("Quiz", render_template_string(tpl, csrf_val=csrf_val, domain_buttons=domain_buttons))

    # POST: start a quiz session (client-side rendered; server just prepares items)
    if not _csrf_ok():
        abort(403)

    domain = (request.form.get("domain") or "random").strip()
    mode = (request.form.get("mode") or "exam").strip()
    count = _safe_int(request.form.get("count"), 20)
    if count not in (10, 20, 30):
        count = 20

    # Load bank questions and filter
    bank = _load_json("bank/cpp_questions_v1.json", [])
    pool = []
    dk = domain.lower()
    for q in bank:
        d = str(q.get("domain", "")).strip().lower()
        if domain == "random" or d == dk:
            pool.append(q)
    random.shuffle(pool)
    items = pool[:max(0, min(count, len(pool)))]

    # Render client quiz (no server session)
    rows = []
    for idx, q in enumerate(items, start=1):
        stem = html.escape(q.get("question", ""))
        opts = q.get("options", {}) or {}
        def esc(k): return html.escape(opts.get(k, ""))
        rows.append(f"""
          <div class="quiz-q mb-3" data-idx="{idx}" data-correct="{html.escape(q.get('correct',''))}">
            <div class="fw-semibold mb-1">{idx}. {stem}</div>
            <div class="ps-2">
              <div><label><input type="radio" name="q{idx}" value="A"> A) {esc('A')}</label></div>
              <div><label><input type="radio" name="q{idx}" value="B"> B) {esc('B')}</label></div>
              <div><label><input type="radio" name="q{idx}" value="C"> C) {esc('C')}</label></div>
              <div><label><input type="radio" name="q{idx}" value="D"> D) {esc('D')}</label></div>
            </div>
          </div>
        """)
    questions_html = "".join(rows) or "<div class='text-muted'>No questions available. Add items to <code>data/bank/cpp_questions_v1.json</code>.</div>"

    tpl = """
    <div class="container">
      <div class="row justify-content-center"><div class="col-xl-10">
        <div class="card">
          <div class="card-header bg-primary text-white d-flex justify-content-between align-items-center">
            <h3 class="mb-0"><i class="bi bi-check2-circle me-2"></i>Quiz</h3>
            <a href="/quiz" class="btn btn-outline-light btn-sm">New Quiz</a>
          </div>
          <div class="card-body">
            <div class="small text-muted mb-2">Domain: <strong>{{ domain_label }}</strong> &bull; Questions: {{ n_items }} &bull; Mode: {{ mode }}</div>
            <form id="quizForm">
              {{ questions_html|safe }}
              <div class="mt-3">
                <button type="button" id="submitBtn" class="btn btn-primary"><i class="bi bi-clipboard-check me-1"></i>Submit</button>
                <a class="btn btn-outline-secondary ms-2" href="/"><i class="bi bi-house me-1"></i>Home</a>
                <span class="ms-3 small text-muted" id="scoreLabel"></span>
              </div>
            </form>
          </div>
        </div>
      </div></div>
    </div>

    <script>
    (function() {
      var form = document.getElementById('quizForm');
      var btn = document.getElementById('submitBtn');
      function grade() {
        var total = 0, ok = 0;
        document.querySelectorAll('.quiz-q').forEach(function(block) {
          total += 1;
          var correct = block.getAttribute('data-correct') || '';
          var checked = block.querySelector('input[type=radio]:checked');
          var val = checked ? checked.value : '';
          if (val === correct) ok += 1;
        });
        var pct = total ? Math.round(100.0 * ok / total) : 0;
        document.getElementById('scoreLabel').textContent = 'Score: ' + ok + '/' + total + ' (' + pct + '%)';
      }
      btn.addEventListener('click', grade);
    })();
    </script>
    """
    # (Optional) record usage
    try:
        _bump_usage("quizzes", 1)
    except Exception:
        pass

    return base_layout("Quiz", render_template_string(
        tpl,
        domain_label=_domain_label(domain),
        n_items=len(items),
        mode=("Exam" if mode == "exam" else "Practice"),
        questions_html=questions_html
    ))

# ---------- PRACTICE (single Q per page; simple client) ----------
@app.route("/practice", methods=["GET", "POST"], endpoint="sec3_practice_page")
@login_required
def sec3_practice_page():
    if request.method == "GET":
        csrf_val = csrf_token()
        domain_buttons = domain_buttons_html(selected_key="random", field_name="domain")

        tpl = """
        <div class="container">
          <div class="row justify-content-center"><div class="col-lg-8 col-xl-7">
            <div class="card">
              <div class="card-header bg-success text-white">
                <h3 class="mb-0"><i class="bi bi-lightning-charge me-2"></i>Practice</h3>
              </div>
              <div class="card-body">
                <form method="POST" class="mb-3">
                  <input type="hidden" name="csrf_token" value="{{ csrf_val }}"/>
                  <label class="form-label fw-semibold">Domain</label>
                  {{ domain_buttons|safe }}
                  <div class="mt-3">
                    <button class="btn btn-success" type="submit" name="start" value="1"><i class="bi bi-play-circle me-1"></i>Start</button>
                    <a class="btn btn-outline-secondary ms-2" href="/"><i class="bi bi-house me-1"></i>Home</a>
                  </div>
                </form>
                <div class="text-muted small">Tip: Pick a domain, then tap Start.</div>
              </div>
            </div>
          </div></div>
        </div>

        <script>
          (function() {
            var container = document.currentScript.closest('.card').querySelector('.card-body');
            var hidden = container.querySelector('#domain_val');
            container.querySelectorAll('.domain-btn').forEach(function(btn) {
              btn.addEventListener('click', function() {
                container.querySelectorAll('.domain-btn').forEach(function(b) { b.classList.remove('active'); });
                btn.classList.add('active');
                if (hidden) hidden.value = btn.getAttribute('data-value');
              });
            });
          })();
        </script>
        """
        return base_layout("Practice", render_template_string(tpl, csrf_val=csrf_val, domain_buttons=domain_buttons))

    # POST -> pick one random question and render it client-side
    if not _csrf_ok():
        abort(403)

    domain = (request.form.get("domain") or "random").strip()
    bank = _load_json("bank/cpp_questions_v1.json", [])
    pool = []
    dk = domain.lower()
    for q in bank:
        d = str(q.get("domain", "")).strip().lower()
        if domain == "random" or d == dk:
            pool.append(q)
    random.shuffle(pool)
    q = pool[0] if pool else None

    if not q:
        body = """
        <div class="container"><div class="row justify-content-center"><div class="col-md-6">
          <div class="alert alert-info mt-4">No questions available for this domain.</div>
          <a href="/practice" class="btn btn-outline-secondary"><i class="bi bi-arrow-left me-1"></i>Back</a>
        </div></div></div>
        """
        return base_layout("Practice", body)

    stem = html.escape(q.get("question", ""))
    opts = q.get("options", {}) or {}
    def esc(k): return html.escape(opts.get(k, ""))

    tpl = """
    <div class="container">
      <div class="row justify-content-center"><div class="col-lg-8 col-xl-7">
        <div class="card">
          <div class="card-header bg-success text-white d-flex justify-content-between align-items-center">
            <h3 class="mb-0"><i class="bi bi-lightning-charge me-2"></i>Practice</h3>
            <a href="/practice" class="btn btn-outline-light btn-sm">New</a>
          </div>
          <div class="card-body">
            <div class="small text-muted mb-2">Domain: <strong>{{ domain_label }}</strong></div>
            <div class="mb-2 fw-semibold">{{ stem }}</div>
            <div class="ps-2" id="practiceBlock">
              <div><label><input type="radio" name="a" value="A"> A) {{ A }}</label></div>
              <div><label><input type="radio" name="a" value="B"> B) {{ B }}</label></div>
              <div><label><input type="radio" name="a" value="C"> C) {{ C }}</label></div>
              <div><label><input type="radio" name="a" value="D"> D) {{ D }}</label></div>
            </div>
            <div class="mt-3">
              <button type="button" id="revealBtn" class="btn btn-success"><i class="bi bi-eye me-1"></i>Reveal</button>
              <a class="btn btn-outline-secondary ms-2" href="/"><i class="bi bi-house me-1"></i>Home</a>
              <span class="ms-3 small text-muted" id="resultLabel"></span>
            </div>
          </div>
        </div>
      </div></div>
    </div>

    <script>
    (function() {
      var correct = "{{ correct }}";
      var btn = document.getElementById('revealBtn');
      var label = document.getElementById('resultLabel');
      btn.addEventListener('click', function() {
        var checked = document.querySelector('#practiceBlock input[type=radio]:checked');
        var val = checked ? checked.value : '';
        if (!val) { label.textContent = 'Choose an option'; return; }
        label.textContent = (val === correct) ? 'Correct!' : ('Incorrect — correct answer is ' + correct);
      });
    })();
    </script>
    """
    # optional usage bump
    try:
        _bump_usage("questions", 1)
    except Exception:
        pass

    return base_layout("Practice", render_template_string(
        tpl,
        domain_label=_domain_label(domain),
        stem=stem,
        A=esc("A"), B=esc("B"), C=esc("C"), D=esc("D"),
        correct=q.get("correct", "")
    ))


# =========================
# SECTION 4/8 — Mock Exam
# Route ownership:
#   /mock         [GET]   -> picker (domain + count)
#   /mock/start   [POST]  -> start a client-side session
# =========================

# STABILITY: ensure we render HTML/JS via Jinja, not Python f-strings
from flask import render_template_string

def _mock_filter_questions_domain(items: list[dict], domain_key: str | None):
    if not domain_key or domain_key == "random":
        return items[:]
    dk = str(domain_key).strip().lower()
    return [q for q in items if str(q.get("domain","")).strip().lower() == dk]

@app.get("/mock", endpoint="sec4_mock_picker")
@login_required
def sec4_mock_picker():
    """
    Mock Exam picker. Renders with render_template_string so that inline <script>{...}</script>
    braces do NOT get parsed by Python as an f-string.
    """
    csrf_val = csrf_token()
    # Reuse the existing helper that builds the domain radio/group buttons.
    # The helper returns ready-to-insert HTML.
    domain_buttons = domain_buttons_html(selected_key="random", field_name="domain")

    tmpl = """
    <div class="container">
      <div class="row justify-content-center"><div class="col-lg-8 col-xl-7">
        <div class="card">
          <div class="card-header bg-primary text-white">
            <h3 class="mb-0"><i class="bi bi-ui-checks-grid me-2"></i>Mock Exam</h3>
          </div>
          <div class="card-body">
            <form method="POST" action="/mock/start" class="mb-3">
              <input type="hidden" name="csrf_token" value="{{ csrf_val }}"/>
              <label class="form-label fw-semibold">Domain</label>
              {{ domain_buttons|safe }}

              <div class="mt-3 mb-2 fw-semibold">How many questions?</div>
              <div class="d-flex flex-wrap gap-2">
                <button class="btn btn-outline-primary" name="count" value="10">10</button>
                <button class="btn btn-outline-primary" name="count" value="20">20</button>
                <button class="btn btn-outline-primary" name="count" value="30">30</button>
              </div>
            </form>
            <div class="text-muted small">Tip: Use Random for a mixed-domain exam.</div>
          </div>
        </div>
      </div></div>
    </div>

    <script>
      (function() {
        var container = document.currentScript.closest('.card').querySelector('.card-body');
        var hidden = container.querySelector('#domain_val');
        container.querySelectorAll('.domain-btn').forEach(function(btn) {
          btn.addEventListener('click', function() {
            container.querySelectorAll('.domain-btn').forEach(function(b){ b.classList.remove('active'); });
            btn.classList.add('active');
            if (hidden) hidden.value = btn.getAttribute('data-value');
          });
        });
      })();
    </script>
    """
    content = render_template_string(tmpl, csrf_val=csrf_val, domain_buttons=domain_buttons)
    try:
        _log_event(_user_id(), "mock.picker", {})
    except Exception:
        pass
    return base_layout("Mock Exam", content)

@app.post("/mock/start", endpoint="sec4_mock_start")
@login_required
def sec4_mock_start():
    """
    Starts a client-side mock exam session. Keeps the existing behavior:
    - reads count + domain
    - samples from bank questions
    - renders HTML+JS client to navigate questions locally
    NOTE: We render with render_template_string to avoid f-string/brace issues.
    """
    if not _csrf_ok():
        abort(403)

    try:
        count = int(request.form.get("count") or 20)
    except Exception:
        count = 20
    if count not in (10, 20, 30):
        count = 20
    domain = request.form.get("domain") or "random"

    # Pull questions from bank (Section 6 helpers).
    questions = _bank_read_questions()
    pool = _mock_filter_questions_domain(questions, domain)
    random.shuffle(pool)
    items = pool[:max(0, min(count, len(pool)))]

    # Prepare a compact client payload (id, question, options, correct stored but hidden)
    # Sources/domains preserved; UI unchanged.
    q_payload = []
    for q in items:
        q_payload.append({
            "id": q.get("id"),
            "question": q.get("question"),
            "options": q.get("options", {}),
            "correct": q.get("correct"),
            "domain": q.get("domain", "Unspecified"),
            "sources": q.get("sources", []),
        })

    domain_label = DOMAINS.get(domain, "Mixed") if domain != "random" else "Random (all)"
    total = len(q_payload)

    tmpl = """
    <div class="container">
      <div class="row justify-content-center"><div class="col-xl-10">
        <div class="card">
          <div class="card-header bg-primary text-white d-flex justify-content-between align-items-center">
            <h3 class="mb-0"><i class="bi bi-ui-checks-grid me-2"></i>Mock Exam</h3>
            <a href="/mock" class="btn btn-outline-light btn-sm">New Setup</a>
          </div>
          <div class="card-body">
            <div class="mb-2 small text-muted">
              Domain: <strong>{{ domain_label }}</strong> &bull; Questions: {{ total }}
            </div>

            <div id="q-wrap" class="border rounded-3 p-3" style="min-height: 160px;"></div>

            <div class="d-flex align-items-center gap-2 mt-3">
              <button class="btn btn-outline-secondary" id="prevBtn"><i class="bi bi-arrow-left"></i></button>
              <button class="btn btn-primary" id="revealBtn"><i class="bi bi-eye me-1"></i>Reveal</button>
              <button class="btn btn-outline-secondary" id="nextBtn"><i class="bi bi-arrow-right"></i></button>
              <div class="ms-auto small"><span id="idx">0</span>/<span id="total">{{ total }}</span></div>
            </div>

            <a href="/" class="btn btn-outline-secondary mt-3"><i class="bi bi-house me-1"></i>Home</a>
          </div>
        </div>
      </div></div>
    </div>

    <script>
      (function() {
        var data = {{ q_payload | tojson }};
        var i = 0, total = data.length;
        var wrap = document.getElementById('q-wrap');
        function render(idx, reveal) {
          if (!total) { wrap.innerHTML = "<div class='text-muted'>No questions found.</div>"; return; }
          var q = data[idx];
          var opts = q.options || {};
          var html = "";
          html += "<div class='fw-semibold mb-2'>" + escapeHtml(q.question || "") + "</div>";
          html += "<div class='list-group'>";
          ["A","B","C","D"].forEach(function(L) {
            var t = escapeHtml(String(opts[L] || ""));
            html += "<div class='list-group-item'>" + L + ". " + t + "</div>";
          });
          html += "</div>";
          if (reveal) {
            html += "<div class='alert alert-success mt-3 mb-0 small'><i class='bi bi-check2-circle me-1'></i>";
            html += "Answer: <strong>" + escapeHtml(q.correct || "") + "</strong></div>";
            if ((q.sources || []).length) {
              html += "<div class='small mt-2'><span class='text-muted'>Sources:</span><ul class='small mb-0 ps-3'>";
              (q.sources || []).forEach(function(s) {
                var t = escapeHtml(String(s.title||""));
                var u = String(s.url||"#");
                html += "<li><a href='" + u + "' target='_blank' rel='noopener'>" + t + "</a></li>";
              });
              html += "</ul></div>";
            }
          }
          wrap.innerHTML = html;
          document.getElementById('idx').textContent = (total ? idx+1 : 0);
        }
        function next() { if (!total) return; i = Math.min(total-1, i+1); render(i, false); }
        function prev() { if (!total) return; i = Math.max(0, i-1); render(i, false); }
        function reveal() { if (!total) return; render(i, true); }

        function escapeHtml(s){
          return String(s).replace(/[&<>"']/g, function(m){
            return ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]);
          });
        }

        document.getElementById('nextBtn').addEventListener('click', function(){ next(); });
        document.getElementById('prevBtn').addEventListener('click', function(){ prev(); });
        document.getElementById('revealBtn').addEventListener('click', function(){ reveal(); });

        render(i, false);
      })();
    </script>
    """
    content = render_template_string(
        tmpl,
        q_payload=q_payload,
        domain_label=domain_label,
        total=total,
    )

    try:
        _log_event(_user_id(), "mock.start", {"count": total, "domain": domain})
        _bump_usage("quizzes", 1)
        _bump_usage("questions", total)
    except Exception:
        pass
    return base_layout("Mock Exam", content)

# =========================
# SECTION 5/8 (OWNED ROUTES): Flashcards, Progress, Usage,
# Billing/Stripe (+ Debug), Admin Login/Reset
# =========================
# Route ownership:
#   /flashcards              [GET, POST]
#   /progress                [GET]
#   /usage                   [GET]
#   /billing                 [GET]
#   /billing/checkout        [GET]
#   /billing/success         [GET]
#   /stripe/webhook          [POST]
#   /billing/debug           [GET]
#   /admin/login             [GET, POST]
#   /admin/reset-password    [GET, POST]
#
# NOTE: Section 6 owns content ingestion & bank validation endpoints.
#       Do NOT define them here.

# STABILITY: import for template rendering without f-strings around JS
from flask import render_template_string

# ---------- STRIPE IMPORT & CONFIG (SAFE) ----------
# Keep runtime graceful if stripe library or secret key is missing.
try:
    import stripe  # type: ignore
except Exception:
    stripe = None  # type: ignore

STRIPE_SECRET_KEY        = os.environ.get("STRIPE_SECRET_KEY", "")
STRIPE_PUBLISHABLE_KEY   = os.environ.get("STRIPE_PUBLISHABLE_KEY", "")
STRIPE_MONTHLY_PRICE_ID  = os.environ.get("STRIPE_MONTHLY_PRICE_ID", "")
STRIPE_SIXMONTH_PRICE_ID = os.environ.get("STRIPE_SIXMONTH_PRICE_ID", "")
STRIPE_WEBHOOK_SECRET    = os.environ.get("STRIPE_WEBHOOK_SECRET", "")

if stripe is not None:
    try:
        stripe.api_key = STRIPE_SECRET_KEY or None  # None safe; gate calls with _stripe_ready()
    except Exception:
        pass

def _stripe_ready() -> bool:
    """Stripe usable only if the library imported AND a secret key is present."""
    return (stripe is not None) and bool(STRIPE_SECRET_KEY)

# ---------- FLASHCARDS ----------
def sec5_normalize_flashcard(item: dict | None):
    """
    Accepts shapes like:
      {"front": "...", "back":"...", "domain":"...", "sources":[{"title":"...", "url":"..."}]}
      {"q":"...", "a":"..."} or {"term":"...", "definition":"..."}
    Returns normalized or None if invalid:
      {"id":"...", "front":"...", "back":"...", "domain":"...", "sources":[...]}
    """
    if not item or not isinstance(item, dict):
        return None
    front = (item.get("front") or item.get("q") or item.get("term") or "").strip()
    back  = (item.get("back")  or item.get("a") or item.get("definition") or "").strip()
    if not front or not back:
        return None
    domain = (item.get("domain") or item.get("category") or "Unspecified").strip()

    cleaned_sources: list[dict] = []
    for s in (item.get("sources") or [])[:3]:
        t = (s.get("title") or "").strip()
        u = (s.get("url") or "").strip()
        if t and u:
            cleaned_sources.append({"title": t, "url": u})

    return {
        "id": item.get("id") or str(uuid.uuid4()),
        "front": front,
        "back": back,
        "domain": domain,
        "sources": cleaned_sources,
    }

def sec5_all_flashcards() -> list[dict]:
    """
    Merge legacy data/flashcards.json + optional bank/cpp_flashcards_v1.json,
    normalize, and de-duplicate by (front, back, domain).
    """
    out: list[dict] = []
    seen: set[tuple[str, str, str]] = set()

    # Legacy flashcards file
    legacy = _load_json("flashcards.json", [])
    for fc in (legacy or []):
        n = sec5_normalize_flashcard(fc)
        if not n:
            continue
        key = (n["front"], n["back"], n["domain"])
        if key in seen:
            continue
        seen.add(key)
        out.append(n)

    # Bank flashcards (preferred if present)
    bank = _load_json("bank/cpp_flashcards_v1.json", [])
    for fc in (bank or []):
        n = sec5_normalize_flashcard(fc)
        if not n:
            continue
        key = (n["front"], n["back"], n["domain"])
        if key in seen:
            continue
        seen.add(key)
        out.append(n)

    return out

def sec5_filter_flashcards_domain(cards: list[dict], domain_key: str | None):
    if not domain_key or domain_key == "random":
        return cards[:]
    dk = str(domain_key).strip().lower()
    return [c for c in cards if str(c.get("domain", "")).strip().lower() == dk]

@app.route("/flashcards", methods=["GET", "POST"], endpoint="sec5_flashcards_page")
@login_required
def sec5_flashcards_page():
    # GET -> picker
    if request.method == "GET":
        csrf_val = csrf_token()
        domain_buttons = domain_buttons_html(selected_key="random", field_name="domain")

        # STABILITY: Use render_template_string to avoid Python f-string parsing of JS braces
        tpl = """
        <div class="container">
          <div class="row justify-content-center"><div class="col-lg-8 col-xl-7">
            <div class="card">
              <div class="card-header bg-success text-white">
                <h3 class="mb-0"><i class="bi bi-layers me-2"></i>Flashcards</h3>
              </div>
              <div class="card-body">
                <form method="POST" class="mb-3">
                  <input type="hidden" name="csrf_token" value="{{ csrf_val }}"/>
                  <label class="form-label fw-semibold">Domain</label>
                  {{ domain_buttons|safe }}
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
          (function() {
            var container = document.currentScript.closest('.card').querySelector('.card-body');
            var hidden = container.querySelector('#domain_val');
            container.querySelectorAll('.domain-btn').forEach(function(btn) {
              btn.addEventListener('click', function() {
                container.querySelectorAll('.domain-btn').forEach(function(b) { b.classList.remove('active'); });
                btn.classList.add('active');
                if (hidden) hidden.value = btn.getAttribute('data-value');
              });
            });
          })();
        </script>
        """
        return base_layout("Flashcards", render_template_string(tpl, csrf_val=csrf_val, domain_buttons=domain_buttons))

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

    all_cards = sec5_all_flashcards()
    pool = sec5_filter_flashcards_domain(all_cards, domain)
    random.shuffle(pool)
    cards = pool[:max(0, min(count, len(pool)))]

    def _card_div(c: dict) -> str:
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

    cards_html = "".join(_card_div(c) for c in cards) or (
        "<div class='text-muted'>No flashcards found. Add content in "
        "<code>data/bank/cpp_flashcards_v1.json</code> or <code>data/flashcards.json</code>.</div>"
    )

    # STABILITY: build via Jinja template to avoid f-string+JS brace parsing
    domain_label = (DOMAINS.get(domain, "Mixed") if domain != "random" else "Random (all)")
    tpl = """
    <div class="container">
      <div class="row justify-content-center"><div class="col-lg-8 col-xl-7">
        <div class="card">
          <div class="card-header bg-success text-white d-flex justify-content-between align-items-center">
            <h3 class="mb-0"><i class="bi bi-layers me-2"></i>Flashcards</h3>
            <a href="/flashcards" class="btn btn-outline-light btn-sm">New Session</a>
          </div>
          <div class="card-body">
            <div class="mb-2 small text-muted">Domain:
              <strong>{{ domain_label }}</strong>
              &bull; Cards: {{ cards_count }}
            </div>
            <div id="fc-container">{{ cards_html|safe }}</div>

            <div class="d-flex align-items-center gap-2 mt-3">
              <button class="btn btn-outline-secondary" id="prevBtn"><i class="bi bi-arrow-left"></i></button>
              <button class="btn btn-primary" id="flipBtn"><i class="bi bi-arrow-repeat me-1"></i>Flip</button>
              <button class="btn btn-outline-secondary" id="nextBtn"><i class="bi bi-arrow-right"></i></button>
              <div class="ms-auto small"><span id="idx">0</span>/<span id="total">{{ cards_count }}</span></div>
            </div>
          </div>
        </div>
      </div></div>
    </div>

    <script>
    (function() {
      var cards = Array.prototype.slice.call(document.querySelectorAll('#fc-container .fc-card'));
      var i = 0, total = cards.length;
      function show(idx) {
        cards.forEach(function(el, j) {
          el.style.display = (j===idx) ? '' : 'none';
          if (j===idx) {
            el.querySelector('.front').classList.remove('d-none');
            el.querySelector('.back').classList.add('d-none');
          }
        });
        document.getElementById('idx').textContent = (total ? idx+1 : 0);
      }
      function flip() {
        if (!total) return;
        var cur = cards[i];
        var front = cur.querySelector('.front');
        var back  = cur.querySelector('.back');
        front.classList.toggle('d-none');
        back.classList.toggle('d-none');
      }
      function next() { if (!total) return; i = Math.min(total-1, i+1); show(i); }
      function prev() { if (!total) return; i = Math.max(0, i-1); show(i); }
      document.getElementById('flipBtn').addEventListener('click', flip);
      document.getElementById('nextBtn').addEventListener('click', next);
      document.getElementById('prevBtn').addEventListener('click', prev);
      show(i);
    })();
    </script>
    """
    try:
        _log_event(_user_id(), "flashcards.start", {"count": len(cards), "domain": domain})
        # Optional usage bumps; guarded in case helper is defined in a later section.
        _bump_usage("flashcards", len(cards))
    except Exception:
        pass
    return base_layout("Flashcards", render_template_string(
        tpl,
        domain_label=domain_label,
        cards_count=len(cards),
        cards_html=cards_html
    ))

# ---------- PROGRESS ----------
@app.get("/progress", endpoint="sec5_progress_page")
@login_required
def sec5_progress_page():
    uid = _user_id()
    attempts = [a for a in _load_json("attempts.json", []) if a.get("user_id") == uid]
    attempts.sort(key=lambda x: x.get("ts", ""), reverse=True)

    total_q  = sum(int(a.get("count", 0))   for a in attempts)
    total_ok = sum(int(a.get("correct", 0)) for a in attempts)
    best = max([float(a.get("score_pct", 0.0)) for a in attempts], default=0.0)
    avg  = round(sum([float(a.get("score_pct", 0.0)) for a in attempts]) / len(attempts), 1) if attempts else 0.0

    dom: dict[str, dict] = {}
    for a in attempts:
        for dname, stats in (a.get("domains") or {}).items():
            dd = dom.setdefault(dname, {"correct": 0, "total": 0})
            dd["correct"] += int(stats.get("correct", 0))
            dd["total"]   += int(stats.get("total", 0))

    def pct(c, t): return f"{(100.0*c/t):.1f}%" if t else "0.0%"

    # Recent attempts (max 100 rows)
    rows = []
    for a in attempts[:100]:
        rows.append(f"""
          <tr>
            <td class="text-nowrap">{html.escape(a.get('ts',''))}</td>
            <td>{html.escape(a.get('mode',''))}</td>
            <td class="text-end">{a.get('correct',0)}/{a.get('count',0)}</td>
            <td class="text-end">{html.escape(str(a.get('score_pct',0)))}%</td>
          </tr>
        """)
    attempts_html = "".join(rows) or "<tr><td colspan='4' class='text-center text-muted'>No attempts yet.</td></tr>"

    # By domain
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
          <div class="card-header bg-info text-white">
            <h3 class="mb-0"><i class="bi bi-graph-up-arrow me-2"></i>Progress</h3>
          </div>
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
@app.get("/usage", endpoint="sec5_usage_dashboard")
@login_required
def sec5_usage_dashboard():
    email = session.get("email", "")
    u = _find_user(email) or {}
    usage = (u.get("usage") or {}).get("monthly", {})
    rows = []
    for month, items in sorted(usage.items()):
        quizzes    = int(items.get("quizzes", 0))
        questions  = int(items.get("questions", 0))
        tutor      = int(items.get("tutor_msgs", 0))
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
def sec5_create_stripe_checkout_session(user_email: str, plan: str = "monthly", discount_code: str | None = None):
    """
    Creates a Stripe Checkout Session for either a subscription (monthly) or a
    one-time payment (sixmonth). If discount_code is provided, try to resolve an
    active Promotion Code in Stripe and apply it; also enable allow_promotion_codes.
    """
    if not _stripe_ready():
        logger.error("Stripe not configured (library or STRIPE_SECRET_KEY missing).")
        return None

    try:
        discounts_param = None
        if discount_code:
            try:
                pc = stripe.PromotionCode.list(code=discount_code.strip(), active=True, limit=1)
                if pc and pc.get("data"):
                    discounts_param = [{"promotion_code": pc["data"][0]["id"]}]
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
                metadata={"user_email": user_email, "plan": "monthly", "discount_code": (discount_code or "")},
            )
            return sess.url

        if plan == "sixmonth":
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
                    "discount_code": (discount_code or ""),
                },
            )
            return sess.url

        logger.warning("Unknown plan %r", plan)
        return None

    except Exception as e:
        logger.error("Stripe session creation failed: %s", e)
        return None

@app.get("/billing", endpoint="sec5_billing_page")
@login_required
def sec5_billing_page():
    user = _find_user(session.get("email", ""))
    sub = user.get("subscription", "inactive") if user else "inactive"
    names = {"monthly": "Monthly Plan", "sixmonth": "6-Month Plan", "inactive": "Free Plan"}

    # STABILITY: the content includes a tiny JS block — render with Jinja to avoid f-string brace parsing
    if sub == "inactive":
        plans_tpl = """
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
            (function() {
              function goWithCode(href) {
                var code = (document.getElementById('discount_code')||{value:''}).value.trim();
                if (code) {
                  var url = new URL(href, window.location.origin);
                  url.searchParams.set('code', code);
                  return url.toString();
                }
                return href;
              }
              document.querySelectorAll('.upgrade-btn').forEach(function(btn) {
                btn.addEventListener('click', function(e) {
                  e.preventDefault();
                  window.location.href = goWithCode(btn.getAttribute('href'));
                });
              });
              var apply = document.getElementById('apply_code');
              if (apply) {
                apply.addEventListener('click', function() {
                  /* no-op: user still clicks a plan to proceed */
                });
              }
            })();
          </script>
        """
    else:
        plans_tpl = """
          <div class="alert alert-info border-0">
            <i class="bi bi-info-circle me-2"></i>Your subscription is active. Use support to manage changes.
          </div>
        """

    body_tpl = """
    <div class="container"><div class="row justify-content-center"><div class="col-lg-8">
      <div class="card">
        <div class="card-header bg-warning text-dark">
          <h3 class="mb-0"><i class="bi bi-credit-card me-2"></i>Billing & Subscription</h3>
        </div>
        <div class="card-body">
          <div class="alert {{ 'alert-success' if sub!='inactive' else 'alert-info' }} border-0 mb-4">
            <div class="d-flex align-items-center">
              <i class="bi bi-{{ 'check-circle' if sub!='inactive' else 'info-circle' }} fs-4 me-3"></i>
              <div>
                <h6 class="alert-heading mb-1">Current Plan: {{ names.get(sub, 'Unknown') }}</h6>
                <p class="mb-0">{{ 'You have unlimited access to all features.' if sub!='inactive' else 'Limited access — upgrade for unlimited features.' }}</p>
              </div>
            </div>
          </div>

          {{ plans|safe }}
        </div>
      </div>
    </div></div></div>
    """
    return base_layout("Billing", render_template_string(body_tpl, sub=sub, names=names, plans=plans_tpl))

@app.get("/billing/checkout", endpoint="sec5_billing_checkout")
@login_required
def sec5_billing_checkout():
    plan = request.args.get("plan", "monthly")
    user_email = session.get("email", "")

    # A user can be logged in (uid set) but lack an email in session; handle gracefully.
    if not user_email:
        return redirect(_login_redirect_url(request.path))

    discount_code = (request.args.get("code") or "").strip()

    url = sec5_create_stripe_checkout_session(user_email, plan=plan, discount_code=discount_code)
    if url:
        return redirect(url)
    # If creation failed (e.g., Stripe not configured), return to Billing
    return redirect(url_for("sec5_billing_page"))

@app.get("/billing/success", endpoint="sec5_billing_success")
@login_required
def sec5_billing_success():
    sess_id = request.args.get("session_id")
    plan = request.args.get("plan", "monthly")

    if sess_id and _stripe_ready():
        try:
            cs = stripe.checkout.Session.retrieve(sess_id, expand=["customer", "subscription"])
            meta = cs.get("metadata", {}) if isinstance(cs, dict) else getattr(cs, "metadata", {}) or {}
            email = meta.get("user_email") or session.get("email")
            u = _find_user(email or "")
            if u:
                updates: Dict[str, Any] = {}
                # Store customer id either way
                cid = (cs.get("customer") if isinstance(cs, dict) else getattr(cs, "customer", None)) or u.get("stripe_customer_id")
                updates["stripe_customer_id"] = cid

                if plan == "monthly":
                    updates["subscription"] = "monthly"
                elif plan == "sixmonth":
                    updates["subscription"] = "sixmonth"
                    duration_days = int(meta.get("duration_days", 180) or 180)
                    expiry = datetime.utcnow() + timedelta(days=duration_days)
                    updates["subscription_expires_at"] = expiry.isoformat() + "Z"

                if updates:
                    _update_user(u["id"], updates)
        except Exception as e:
            logger.warning("Could not finalize success update from Stripe session: %s", e)
    elif sess_id and not _stripe_ready():
        logger.warning("Stripe success callback received but Stripe is not configured.")

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
@app.post("/stripe/webhook", endpoint="sec5_stripe_webhook")
def sec5_stripe_webhook():
    # STABILITY: if secret is empty, fail clearly (503) without attempting to verify
    if not _stripe_ready():
        logger.error("Stripe webhook invoked but Stripe is not configured.")
        return "", 400
    if not STRIPE_WEBHOOK_SECRET:
        logger.error("Stripe webhook called but STRIPE_WEBHOOK_SECRET is not set.")
        return "", 503

    payload = request.data
    sig = request.headers.get("Stripe-Signature", "")
    try:
        event = stripe.Webhook.construct_event(payload=payload, sig_header=sig, secret=STRIPE_WEBHOOK_SECRET)
    except Exception as e:
        logger.error("Stripe webhook signature verification failed: %s", e)
        return "", 400

    etype = event.get("type")
    if etype == "checkout.session.completed":
        cs = event["data"]["object"]
        meta = cs.get("metadata", {}) or {}
        email = meta.get("user_email")
        plan  = meta.get("plan", "")
        customer_id = cs.get("customer")

        # STABILITY: Log only safe fields
        try:
            logger.info("stripe_event type=%s customer=%s plan=%s", etype, str(customer_id), str(plan))
        except Exception:
            pass

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

    return "", 200

# STABILITY: Exempt webhook from CSRF if Flask-WTF is present
try:
    if HAS_CSRF and csrf is not None:
        csrf.exempt(sec5_stripe_webhook)
except Exception:
    pass

# ---------- BILLING DEBUG (admin-only; no secrets) ----------
@app.get("/billing/debug", endpoint="sec5_billing_debug")
@login_required
def sec5_billing_debug():
    if not is_admin():
        return redirect(url_for("sec5_admin_login_page", next=request.path))

    data = {
        "STRIPE_PUBLISHABLE_KEY_present": bool(STRIPE_PUBLISHABLE_KEY),
        "STRIPE_MONTHLY_PRICE_ID_present": bool(STRIPE_MONTHLY_PRICE_ID),
        "STRIPE_SIXMONTH_PRICE_ID_present": bool(STRIPE_SIXMONTH_PRICE_ID),
        "STRIPE_WEBHOOK_SECRET_present": bool(STRIPE_WEBHOOK_SECRET),
        "STRIPE_SECRET_KEY_present": bool(STRIPE_SECRET_KEY),
        "STRIPE_LIBRARY_imported": bool(stripe is not None),
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
@app.get("/admin/login", endpoint="sec5_admin_login_page")
def sec5_admin_login_page():
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

@app.post("/admin/login", endpoint="sec5_admin_login_post")
def sec5_admin_login_post():
    # If CSRFProtect is active, it enforces validity. Otherwise, manual check.
    if not HAS_CSRF:
        if request.form.get("csrf_token") != csrf_token():
            abort(403)

    nxt = request.form.get("next") or "/"
    pw = (request.form.get("pw") or "").strip()
    if ADMIN_PASSWORD and pw == ADMIN_PASSWORD:
        session["admin_ok"] = True
        return redirect(nxt)
    return redirect(url_for("sec5_admin_login_page", next=nxt))

@app.route("/admin/reset-password", methods=["GET", "POST"], endpoint="sec5_admin_reset_password")
@login_required
def sec5_admin_reset_password():
    if not is_admin():
        return redirect(url_for("sec5_admin_login_page", next=request.path))

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
# ========================= END SECTION 5/8 =========================


# =========================
# SECTION 6/8 — Tutor (UI uplift + suggestion box)
# Drop-in replacement for your existing Tutor section. Keeps routes and POST shape identical:
# - GET  /tutor    → shows Tutor with welcome text and a 4-item suggestion box
# - POST /tutor    → submits a question via form field name "q" (unchanged)
#
# Notes:
# • Clicking a suggested question fills the input and auto-submits the form (no extra click).
# • After a suggestion is clicked, it’s instantly swapped out for a new one (and the page then navigates).
# • No backend logic changed beyond the page HTML shell — your existing POST handler continues to work.
# • If your original function names differ, keep the route paths the same and replace the whole section.
# =========================

# STABILITY: helpers used across the app
def _safe_next(next_val: str | None) -> str:
    nv = (next_val or "").strip()
    if nv.startswith("/") and not nv.startswith("//"):
        return nv
    return "/"

# ---------- Tutor UI ----------
@app.get("/tutor", endpoint="sec6_tutor_page")
def sec6_tutor_page():
    # If you already gate with @login_required + TOS in before_request, nothing else needed here.

    # STABILITY: keep CSRF for the form (same name your POST expects)
    csrf_val = csrf_token()

    # Short welcome/explainer that sits above the main box
    welcome_html = """
      <div class="alert alert-info d-flex align-items-start">
        <div class="me-2"><i class="bi bi-robot fs-4"></i></div>
        <div>
          <div class="fw-semibold">Welcome to Tutor</div>
          <div class="small">
            Ask anything about the CPP domains. For best results:
            <ul class="mb-0">
              <li>Be specific (cite the domain or concept if you can).</li>
              <li>Ask for examples or step-by-step explanations.</li>
              <li>Use the practice tools (Mock Exam & Flashcards) alongside Tutor.</li>
            </ul>
          </div>
        </div>
      </div>
    """

    # The main tutor panel + suggestion rail
    # The POST target remains /tutor and the field name remains "q" so your existing handler continues to work.
    content = f"""
    <div class="container">
      <div class="row g-4">

        <!-- Left: Tutor main panel -->
        <div class="col-lg-8">
          {welcome_html}
          <div class="card shadow-sm">
            <div class="card-header bg-primary text-white">
              <h3 class="mb-0"><i class="bi bi-chat-dots me-2"></i>Tutor</h3>
            </div>
            <div class="card-body">
              <form id="tutor-form" method="POST" action="/tutor">
                <input type="hidden" name="csrf_token" value="{csrf_val}"/>
                <div class="mb-3">
                  <label for="tutor-q" class="form-label">Your question</label>
                  <textarea class="form-control" id="tutor-q" name="q" rows="4" placeholder="Ask about a CPP topic… (e.g., ‘Explain Crime Prevention through Environmental Design (CPTED) with a real-world example.’)" required></textarea>
                </div>
                <div class="d-flex gap-2">
                  <button class="btn btn-primary" type="submit"><i class="bi bi-send me-1"></i>Ask Tutor</button>
                  <a class="btn btn-outline-secondary" href="/flashcards"><i class="bi bi-collection me-1"></i>Flashcards</a>
                  <a class="btn btn-outline-secondary" href="/mock"><i class="bi bi-clipboard-check me-1"></i>Mock Exam</a>
                </div>
              </form>
            </div>
          </div>
        </div>

        <!-- Right: Suggested questions -->
        <div class="col-lg-4">
          <div class="card shadow-sm">
            <div class="card-header bg-dark text-white d-flex align-items-center">
              <i class="bi bi-lightbulb me-2"></i><span>Suggestions</span>
            </div>
            <div class="card-body">
              <div id="suggestions" class="list-group small">
                <!-- JS will inject 4 items -->
              </div>
              <div class="form-text mt-2">Click any suggestion to auto-ask Tutor.</div>
            </div>
          </div>
        </div>

      </div>
    </div>

    <!-- STABILITY: simple JS (no new deps). Four rotating suggestions + auto-submit on click -->
    <script>
    (function() {{
      // A larger pool to keep things fresh; feel free to expand safely later.
      const SUGGESTIONS_POOL = [
        "Give me a 5-minute overview of CPP Domain 1 (Security Principles and Practices).",
        "Explain CPTED with a concise example I could use at work.",
        "What’s the difference between threat, vulnerability, and risk? Provide a quick table.",
        "Walk me through a basic incident response plan for a data breach.",
        "How do I build a qualitative risk matrix for a corporate office?",
        "Summarize key steps in a professional security investigation (Domain 3).",
        "Compare access control models (MAC, DAC, RBAC) with examples.",
        "Create 5 practice questions on physical security (Domain 2) with brief answers.",
        "Help me memorize the steps of a business impact analysis (BIA).",
        "What are effective controls against tailgating in buildings?",
        "Draft a short security awareness checklist for new employees.",
        "Explain the difference between business continuity and disaster recovery.",
        "How should I evaluate a new video surveillance (CCTV) design?",
        "Outline a vendor due diligence checklist for information security.",
        "Give me a scenario-based question about executive protection planning.",
        "What metrics (KPIs) matter for a corporate security program?"
      ];

      // State
      const shown = new Set();
      const suggestionsEl = document.getElementById('suggestions');
      const form = document.getElementById('tutor-form');
      const input = document.getElementById('tutor-q');

      function randPick(exclude) {{
        // pick a suggestion not currently shown
        let tries = 0;
        while (tries < 50) {{
          const idx = Math.floor(Math.random() * SUGGESTIONS_POOL.length);
          const text = SUGGESTIONS_POOL[idx];
          if (!exclude.has(text)) return text;
          tries++;
        }}
        // fallback if pool is too small
        return SUGGESTIONS_POOL[Math.floor(Math.random() * SUGGESTIONS_POOL.length)];
      }}

      function makeItem(text) {{
        const a = document.createElement('a');
        a.href = "#";
        a.className = "list-group-item list-group-item-action";
        a.textContent = text;
        a.addEventListener('click', function(ev) {{
          ev.preventDefault();
          // Auto-fill + submit
          input.value = text;
          // Replace this suggestion immediately for a fresh feel
          shown.delete(text);
          const replacement = randPick(shown);
          shown.add(replacement);
          a.textContent = replacement;
          // Now submit the question
          form.submit();
        }});
        return a;
      }}

      function bootstrapSuggestions() {{
        // clear & seed 4 unique
        suggestionsEl.innerHTML = "";
        shown.clear();
        for (let i = 0; i < 4; i++) {{
          const s = randPick(shown);
          shown.add(s);
          suggestionsEl.appendChild(makeItem(s));
        }}
      }}

      bootstrapSuggestions();
    }})();
    </script>
    """

    return base_layout("Tutor", content)

# Keep your existing POST handler signature and behavior.
# If your original POST function name differs, reuse that name and replace only its body if needed.
@app.post("/tutor", endpoint="sec6_tutor_post")
def sec6_tutor_post():
    # STABILITY: honor CSRF the same way as before
    if not _csrf_ok():
        abort(403)

    # Your existing processing likely reads the field 'q', talks to OpenAI (when configured),
    # logs the attempt, and renders a response. We keep that contract intact.
    q = (request.form.get("q") or "").strip()

    # Graceful offline fallback if OpenAI isn’t configured/available — keep your prior logic.
    answer = ""
    try:
        answer = _tutor_answer(q)  # <-- Call your existing helper that generates an answer (LLM or fallback).
    except Exception:
        # Minimal safe fallback; you can keep your prior richer behavior if it exists.
        answer = "Tutor is temporarily unavailable. Please try again, or use Flashcards / Mock Exam in the meantime."

    # Basic render (reuse your existing renderer if you have one)
    safe_q = html.escape(q)
    safe_a = answer if isinstance(answer, str) else html.escape(str(answer))

    result_html = f"""
    <div class="container">
      <div class="row g-4">
        <div class="col-lg-8">
          <div class="card shadow-sm">
            <div class="card-header bg-primary text-white">
              <h3 class="mb-0"><i class="bi bi-chat-dots me-2"></i>Tutor</h3>
            </div>
            <div class="card-body">
              <div class="mb-3">
                <div class="text-muted small mb-1">Your question</div>
                <div class="p-2 border rounded">{safe_q or '<em>(empty)</em>'}</div>
              </div>
              <div class="mb-3">
                <div class="text-muted small mb-1">Tutor</div>
                <div class="p-3 border rounded bg-light">{safe_a}</div>
              </div>
              <a class="btn btn-outline-primary" href="/tutor"><i class="bi bi-arrow-left-short me-1"></i>Ask another</a>
            </div>
          </div>
        </div>

        <!-- Keep the suggestion rail visible even on the result page -->
        <div class="col-lg-4">
          <div class="card shadow-sm">
            <div class="card-header bg-dark text-white d-flex align-items-center">
              <i class="bi bi-lightbulb me-2"></i><span>Suggestions</span>
            </div>
            <div class="card-body">
              <div class="list-group small" id="suggestions"></div>
              <div class="form-text mt-2">Click any suggestion to ask Tutor immediately.</div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Same JS module to seed suggestions and auto-submit -->
    <script>
    (function() {{
      const SUGGESTIONS_POOL = [
        "Give me a 5-minute overview of CPP Domain 1 (Security Principles and Practices).",
        "Explain CPTED with a concise example I could use at work.",
        "What’s the difference between threat, vulnerability, and risk? Provide a quick table.",
        "Walk me through a basic incident response plan for a data breach.",
        "How do I build a qualitative risk matrix for a corporate office?",
        "Summarize key steps in a professional security investigation (Domain 3).",
        "Compare access control models (MAC, DAC, RBAC) with examples.",
        "Create 5 practice questions on physical security (Domain 2) with brief answers.",
        "Help me memorize the steps of a business impact analysis (BIA).",
        "What are effective controls against tailgating in buildings?",
        "Draft a short security awareness checklist for new employees.",
        "Explain the difference between business continuity and disaster recovery.",
        "How should I evaluate a new video surveillance (CCTV) design?",
        "Outline a vendor due diligence checklist for information security.",
        "Give me a scenario-based question about executive protection planning.",
        "What metrics (KPIs) matter for a corporate security program?"
      ];

      const container = document.getElementById('suggestions');
      if (!container) return;

      function randPick(exclude) {{
        let tries = 0;
        while (tries < 50) {{
          const idx = Math.floor(Math.random() * SUGGESTIONS_POOL.length);
          const t = SUGGESTIONS_POOL[idx];
          if (!exclude.has(t)) return t;
          tries++;
        }}
        return SUGGESTIONS_POOL[Math.floor(Math.random() * SUGGESTIONS_POOL.length)];
      }}

      function addRow(text) {{
        const a = document.createElement('a');
        a.href = "#";
        a.className = "list-group-item list-group-item-action";
        a.textContent = text;
        a.addEventListener('click', function(ev) {{
          ev.preventDefault();
          // Build and submit a minimal form to POST /tutor with CSRF baked into the page session cookie.
          const f = document.createElement('form');
          f.method = "POST";
          f.action = "/tutor";

          const ta = document.createElement('textarea');
          ta.name = "q";
          ta.value = text;
          f.appendChild(ta);

          // Include CSRF token if your app expects a form field (cookie-based double-submit).
          try {{
            const csrfInput = document.createElement('input');
            csrfInput.type = "hidden";
            csrfInput.name = "csrf_token";
            // If you use a cookie-based token, leaving this empty is fine; otherwise you can inject via a data attribute.
            csrfInput.value = "";
            f.appendChild(csrfInput);
          }} catch(e) {{}}

          document.body.appendChild(f);
          f.submit();
        }});
        container.appendChild(a);
      }}

      const shown = new Set();
      for (let i = 0; i < 4; i++) {{
        const s = randPick(shown);
        shown.add(s);
        addRow(s);
      }}
    }})();
    </script>
    """

    return base_layout("Tutor", result_html)
# ========================= END SECTION 6/8 =========================



# SECTION 7/8 — Tutor (Chat Assistant) + OpenAI integration (safe, optional)
# Route ownership:
#   /tutor  [GET, POST]
#
# Changes in this section:
# - FIX: Removed backslashes inside f-string expressions by precomputing newline -> <br> replacement.
# - Safe optional import of 'requests'; graceful fallback if missing.

# ---------- Optional dependency (safe import) ----------
try:
    import requests  # type: ignore
except Exception:
    requests = None  # type: ignore

# ---------- OpenAI readiness ----------
def _openai_ready() -> bool:
    return bool(OPENAI_API_KEY and OPENAI_CHAT_MODEL and OPENAI_API_BASE)

# ---------- Tutor system prompt ----------
def _tutor_system_prompt() -> str:
    return (
        "You are CPP Exam Prep Tutor. Help the user study for the ASIS CPP domains. "
        "Explain clearly, use step-by-step reasoning in a concise way, and when helpful, "
        "give small examples or short bullet points. Do not provide legal, medical, or safety advice. "
        "Do not claim affiliation with ASIS. If the user asks for real CPP exam questions, refuse and "
        "offer to create fresh practice items instead. Keep answers under ~200 words unless the user asks for more."
    )

# ---------- Session history helpers ----------
_TUTOR_SESS_KEY = "tutor_hist_v1"
_TUTOR_MAX_TURNS = 12   # user+assistant pairs (kept small to limit payload)
_TUTOR_MAX_INPUT_CHARS = 2000

def _tutor_get_history() -> list[dict]:
    hist = session.get(_TUTOR_SESS_KEY) or []
    out = []
    for m in hist[-(2*_TUTOR_MAX_TURNS):]:
        role = m.get("role") if isinstance(m, dict) else ""
        content = m.get("content") if isinstance(m, dict) else ""
        if role in ("user", "assistant") and isinstance(content, str):
            out.append({"role": role, "content": content})
    return out

def _tutor_save_history(hist: list[dict]) -> None:
    session[_TUTOR_SESS_KEY] = hist[-(2*_TUTOR_MAX_TURNS):]

def _tutor_append(role: str, content: str) -> None:
    hist = _tutor_get_history()
    hist.append({"role": role, "content": content})
    _tutor_save_history(hist)

# ---------- OpenAI call (server-side) ----------
def _tutor_call_openai(user_message: str, prior: list[dict]) -> tuple[bool, str]:
    """
    Returns (ok, reply_text). Never raises to the view.
    Uses Chat Completions for broad compatibility.
    """
    if not _openai_ready():
        return False, ("Tutor is offline: OpenAI is not configured on this environment. "
                       "Set OPENAI_API_KEY/OPENAI_API_BASE/OPENAI_CHAT_MODEL to enable.")

    if requests is None:
        return False, ("Tutor is offline: the 'requests' library is not available on this server. "
                       "Please install it or disable Tutor.")

    msgs = [{"role": "system", "content": _tutor_system_prompt()}]
    for m in prior[-(2*_TUTOR_MAX_TURNS):]:
        if m.get("role") in ("user", "assistant"):
            msgs.append({"role": m["role"], "content": m.get("content", "")})
    msgs.append({"role": "user", "content": user_message})

    url = (OPENAI_API_BASE.rstrip("/") + "/chat/completions")
    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": OPENAI_CHAT_MODEL,
        "messages": msgs,
        "temperature": 0.2,
        "top_p": 1.0,
        "presence_penalty": 0.0,
        "frequency_penalty": 0.2,
        "max_tokens": 600,
    }

    try:
        resp = requests.post(url, headers=headers, json=payload, timeout=20)  # type: ignore
        if resp.status_code != 200:
            logger.warning("OpenAI error %s: %s", resp.status_code, resp.text[:500])
            return False, "I couldn't reach the tutor service just now. Please try again."
        data = resp.json()
        text = ""
        try:
            text = (data["choices"][0]["message"]["content"] or "").strip()
        except Exception:
            text = ""
        if not text:
            return False, "The tutor returned an empty response. Please try again."
        return True, text
    except Exception as e:
        logger.warning("OpenAI call failed: %s", e)
        return False, "Network error while contacting the tutor. Please try again."

# ---------- Render chat UI ----------
def _tutor_chat_html(history: list[dict], banner: str = "") -> str:
    """
    Render a simple, clean chat interface.
    """
    # Build bubbles (FIX: precompute newline-><br> to avoid backslashes inside f-strings)
    bubbles = []
    for m in history:
        role = m.get("role")
        raw = (m.get("content", "") or "").strip()
        escaped = html.escape(raw)
        escaped_with_breaks = escaped.replace("\n", "<br>")

        if not escaped_with_breaks:
            continue

        if role == "user":
            bubbles.append(
                f"""
                <div class="d-flex justify-content-end my-2">
                  <div class="p-2 rounded-3 border bg-light" style="max-width: 80%;">
                    <div class="small text-muted mb-1">You</div>
                    <div>{escaped_with_breaks}</div>
                  </div>
                </div>
                """
            )
        else:
            bubbles.append(
                f"""
                <div class="d-flex justify-content-start my-2">
                  <div class="p-2 rounded-3 border" style="max-width: 80%; background:#fff;">
                    <div class="small text-muted mb-1"><i class="bi bi-robot"></i> Tutor</div>
                    <div>{escaped_with_breaks}</div>
                  </div>
                </div>
                """
            )
    bubble_html = "".join(bubbles) or "<div class='text-muted'>No messages yet — ask the tutor anything related to your CPP prep.</div>"

    csrf_val = csrf_token()
    banner_html = f"<div class='alert alert-warning'>{html.escape(banner)}</div>" if banner else ""
    return f"""
    <div class="container"><div class="row justify-content-center"><div class="col-lg-8 col-xl-7">
      <div class="card">
        <div class="card-header bg-secondary text-white d-flex align-items-center justify-content-between">
          <h3 class="mb-0"><i class="bi bi-chat-dots me-2"></i>Tutor</h3>
          <form method="POST" class="m-0">
            <input type="hidden" name="csrf_token" value="{csrf_val}"/>
            <input type="hidden" name="action" value="reset"/>
            <button class="btn btn-outline-light btn-sm" type="submit"><i class="bi bi-arrow-counterclockwise me-1"></i>Reset</button>
          </form>
        </div>
        <div class="card-body">
          {banner_html}
          <div id="chat" class="mb-3" style="min-height: 200px;">{bubble_html}</div>
          <form method="POST">
            <input type="hidden" name="csrf_token" value="{csrf_val}"/>
            <div class="mb-2">
              <label class="form-label fw-semibold">Your message</label>
              <textarea name="message" class="form-control" rows="3" maxlength="{_TUTOR_MAX_INPUT_CHARS}" placeholder="Ask about a concept, request a quick quiz, or get an explanation..." required></textarea>
            </div>
            <div class="d-flex align-items-center">
              <button class="btn btn-primary" type="submit"><i class="bi bi-send me-1"></i>Send</button>
              <a class="btn btn-outline-secondary ms-2" href="/"><i class="bi bi-house me-1"></i>Home</a>
              <div class="ms-auto small text-muted">Educational use only. No official affiliation.</div>
            </div>
          </form>
        </div>
      </div>
    </div></div></div>
    """

# ---------- Route: Tutor ----------
@app.route("/tutor", methods=["GET", "POST"], endpoint="sec7_tutor_page")
@login_required
def sec7_tutor_page():
    # GET -> render current chat
    if request.method == "GET":
        banner = ""
        if not _openai_ready():
            banner = ("Tutor is running in limited mode because OpenAI is not configured. "
                      "Set OPENAI_API_KEY/OPENAI_API_BASE/OPENAI_CHAT_MODEL to enable answers.")
        body = _tutor_chat_html(_tutor_get_history(), banner=banner)
        return base_layout("Tutor", body)

    # POST -> CSRF
    if not _csrf_ok():
        abort(403)

    # Rate-limit per IP
    rip = (request.headers.get("X-Forwarded-For") or request.remote_addr or "0.0.0.0").split(",")[0].strip()
    if not _rate_ok(f"tutor:{rip}", per_sec=0.5):   # 1 message / 2s
        body = _tutor_chat_html(_tutor_get_history(), banner="You're sending messages too quickly. Please wait a moment.")
        return base_layout("Tutor", body)

    action = (request.form.get("action") or "").strip().lower()
    if action == "reset":
        _tutor_save_history([])
        try:
            _log_event(_user_id(), "tutor.reset", {})
        except Exception:
            pass
        body = _tutor_chat_html([], banner="Chat has been reset.")
        return base_layout("Tutor", body)

    # Normal message
    user_msg = (request.form.get("message") or "").strip()
    if not user_msg:
        body = _tutor_chat_html(_tutor_get_history(), banner="Please enter a message.")
        return base_layout("Tutor", body)
    if len(user_msg) > _TUTOR_MAX_INPUT_CHARS:
        user_msg = user_msg[:_TUTOR_MAX_INPUT_CHARS]

    # Append user first so it shows even if backend fails
    _tutor_append("user", user_msg)

    # Call OpenAI (or fallback)
    ok, reply = _tutor_call_openai(user_msg, _tutor_get_history())
    if not ok:
        _tutor_append("assistant", reply)
        try:
            _log_event(_user_id(), "tutor.reply_error", {"msg_len": len(user_msg)})
        except Exception:
            pass
        body = _tutor_chat_html(_tutor_get_history(), banner="Tutor responded with an error message.")
        return base_layout("Tutor", body)

    # Success path
    _tutor_append("assistant", reply)
    try:
        _bump_usage("tutor", 1)
        _log_event(_user_id(), "tutor.reply_ok", {"msg_len": len(user_msg), "reply_len": len(reply)})
    except Exception:
        pass

    body = _tutor_chat_html(_tutor_get_history(), banner="")
    return base_layout("Tutor", body)
#=====================================================#
# =========================
# SECTION 8/8 — Public Welcome, Signup, Login & Logout (patch to stop “login → back to welcome” loop)
# Drop-in replacement for your existing SECTION 8/8.
#
# Changes in this patch:
# 1) Session/DB sync in the gate: if a logged-in user already has tos_ok=True in users.json
#    but session lacks it, we mirror it into session to avoid bouncing back to /welcome.
# 2) Optional toggle to auto-accept TOS at login (for staging): set env ACCEPT_TOS_ON_LOGIN=1.
#    In prod, leave it unset/0 to still require the explicit checkbox once.
# 3) After a guest accepts on /welcome, if they later log in we persist that acceptance to their account.
# =========================

# ---------- Helpers ----------
def _safe_next(next_val: str | None) -> str:
    nv = (next_val or "").strip()
    if nv.startswith("/") and not nv.startswith("//"):
        return nv
    return "/"

def _auth_set_session(user: dict) -> None:
    session["uid"] = user.get("id", "")
    session["email"] = user.get("email", "")
    if user.get("tos_ok"):
        session["tos_ok"] = True
    session.permanent = True  # keep user signed in

def _auth_clear_session() -> None:
    session.pop("uid", None)
    session.pop("email", None)
    session.pop("admin_ok", None)
    session.pop("tos_ok", None)

# ---------- Welcome / Disclaimer ----------
@app.route("/welcome", methods=["GET", "POST"], endpoint="sec8_welcome")
def sec8_welcome():
    # If already accepted, bounce to next/home.
    if session.get("tos_ok"):
        return redirect(_safe_next(request.args.get("next") or "/"))

    err = ""
    nxt = _safe_next(request.args.get("next") or "/")

    if request.method == "POST":
        if not _csrf_ok():
            abort(403)
        accepted = (request.form.get("agree") == "1")
        if not accepted:
            err = "Please confirm you understand and agree to the disclaimer and terms."
        else:
            # STABILITY: persist acceptance in session, and in user record if logged in
            session["tos_ok"] = True
            u = _find_user(session.get("email", "") or "")
            if u:
                try:
                    _update_user(u["id"], {"tos_ok": True})
                except Exception:
                    pass
            return redirect(_safe_next(request.form.get("next") or nxt))

    csrf_val = csrf_token()
    next_hidden = html.escape(nxt)

    body = f"""
    <div class="container"><div class="row justify-content-center"><div class="col-lg-8 col-xl-7">
      <div class="card shadow-sm">
        <div class="card-header bg-dark text-white">
          <h3 class="mb-0"><i class="bi bi-mortarboard me-2"></i>CPP Exam Prep — Welcome</h3>
        </div>
        <div class="card-body">
          {"<div class='alert alert-warning mb-3'>" + html.escape(err) + "</div>" if err else ""}
          <p class="lead">This program helps you study the ASIS CPP domains with quizzes, flashcards, and a tutor.</p>
          <div class="p-3 border rounded-3 bg-light">
            <h5 class="mb-2">Important Disclaimer</h5>
            <ul class="mb-2">
              <li>This is an independent study tool and is <strong>not</strong> approved, endorsed, or affiliated with ASIS International.</li>
              <li>Do not request or share real exam questions. We will create fresh practice items instead.</li>
              <li>Use at your own discretion; this is educational content only.</li>
            </ul>
            <div class="small text-muted">By proceeding, you acknowledge the above.</div>
          </div>

          <form method="POST" class="mt-3">
            <input type="hidden" name="csrf_token" value="{csrf_val}"/>
            <input type="hidden" name="next" value="{next_hidden}"/>
            <div class="form-check my-3">
              <input class="form-check-input" type="checkbox" id="agree" name="agree" value="1" required>
              <label class="form-check-label" for="agree">I understand the disclaimer and agree to the terms.</label>
            </div>
            <div class="d-flex gap-2 align-items-center">
              <button class="btn btn-primary" type="submit"><i class="bi bi-check2-circle me-1"></i>Continue</button>
              <a class="btn btn-outline-secondary" href="/login"><i class="bi bi-box-arrow-in-right me-1"></i>Sign In</a>
              <a class="btn btn-outline-success" href="/signup"><i class="bi bi-person-plus me-1"></i>Create Account</a>
            </div>
          </form>

          <hr class="my-4">
          <h6 class="fw-semibold">Quick Start</h6>
          <ol class="mb-0">
            <li>Accept the disclaimer above.</li>
            <li>Sign in or create an account.</li>
            <li>Start with <a href="/flashcards">Flashcards</a> or take a <a href="/mock">Mock Exam</a>.</li>
          </ol>
        </div>
      </div>
    </div></div></div>
    """
    return base_layout("Welcome", body)

# ---------- Global gate: require disclaimer acceptance (except safe paths) ----------
@app.before_request
def sec8_tos_gate():
    p = request.path or "/"
    if (
        p.startswith("/static/") or
        p.startswith("/stripe/webhook") or
        p in ("/welcome", "/login", "/signup", "/logout", "/healthz", "/legal/terms")
    ):
        return None

    # STABILITY: if user is logged-in but session lost tos_ok, sync from DB to avoid redirect loop
    if session.get("uid") and not session.get("tos_ok"):
        try:
            u = _find_user(session.get("email", "") or "")
            if u and u.get("tos_ok"):
                session["tos_ok"] = True
        except Exception:
            pass

    if not session.get("tos_ok") and request.method in ("GET", "HEAD"):
        # preserve the original destination
        dest = request.full_path if request.query_string else p
        return redirect(url_for("sec8_welcome", next=dest))
    return None

# ---------- Signup ----------
@app.get("/signup", endpoint="sec8_signup_page")
def sec8_signup_page():
    nxt = _safe_next(request.args.get("next") or "/")
    body = f"""
    <div class="container"><div class="row justify-content-center"><div class="col-md-6">
      <div class="card">
        <div class="card-header bg-success text-white"><h3 class="mb-0"><i class="bi bi-person-plus me-2"></i>Create Account</h3></div>
        <div class="card-body">
          <form method="POST" action="/signup">
            <input type="hidden" name="csrf_token" value="{csrf_token()}"/>
            <input type="hidden" name="next" value="{html.escape(nxt)}"/>
            <div class="mb-3">
              <label class="form-label">Email</label>
              <input type="email" class="form-control" name="email" placeholder="you@example.com" required>
            </div>
            <div class="mb-3">
              <label class="form-label">Password</label>
              <input type="password" class="form-control" name="password" minlength="8" required>
            </div>
            <div class="form-check mb-3">
              <input class="form-check-input" type="checkbox" id="agree2" name="agree" value="1" required>
              <label class="form-check-label" for="agree2">I accept the disclaimer and terms.</label>
            </div>
            <button class="btn btn-success" type="submit">Create Account</button>
            <a class="btn btn-outline-secondary ms-2" href="/login"><i class="bi bi-box-arrow-in-right me-1"></i>Sign In</a>
          </form>
        </div>
      </div>
    </div></div></div>
    """
    return base_layout("Sign Up", body)

@app.post("/signup", endpoint="sec8_signup_post")
def sec8_signup_post():
    if not _csrf_ok():
        abort(403)

    email = (request.form.get("email") or "").strip().lower()
    pw    = request.form.get("password") or ""
    nxt   = _safe_next(request.form.get("next"))
    agree = (request.form.get("agree") == "1")

    ok, msg = validate_password(pw)
    if not email or not ok or not agree:
        err = msg or "Please provide a valid email, an 8+ char password, and accept the terms."
        return base_layout("Sign Up", f"<div class='container'><div class='row justify-content-center'><div class='col-md-6'><div class='alert alert-warning mt-3'>{html.escape(err)}</div><a class='btn btn-outline-secondary' href='/signup'>Back</a></div></div></div>")

    if _find_user(email):
        return base_layout("Sign Up", f"<div class='container'><div class='row justify-content-center'><div class='col-md-6'><div class='alert alert-warning mt-3'>An account with that email already exists.</div><a class='btn btn-outline-secondary' href='/login'>Sign In</a></div></div></div>")

    new_user = {
        "id": str(uuid.uuid4()),
        "email": email,
        "password_hash": generate_password_hash(pw),
        "subscription": "inactive",
        "usage": {"monthly": {}},
        "tos_ok": True
    }
    try:
        users = _users_all()
        users.append(new_user)
        _save_json("users.json", users)
    except Exception:
        return base_layout("Sign Up", "<div class='container'><div class='row justify-content-center'><div class='col-md-6'><div class='alert alert-danger mt-3'>Could not create the account. Please try again.</div><a class='btn btn-outline-secondary' href='/signup'>Back</a></div></div></div>")

    _auth_set_session(new_user)
    session["tos_ok"] = True
    try:
        _log_event(_user_id(), "auth.signup", {})
    except Exception:
        pass
    return redirect(nxt or "/")

# ---------- USER LOGIN ----------
@app.get("/login", endpoint="sec1_login_page")
def sec1_login_page():
    nxt = _safe_next(request.args.get("next") or "/")
    err = (request.args.get("error") or "").strip()
    msg_html = ""
    if err == "1":
        msg_html = "<div class='alert alert-danger'>Invalid email or password.</div>"
    elif err == "rate":
        msg_html = "<div class='alert alert-warning'>Too many attempts. Please wait a moment and try again.</div>"

    content = f"""
    <div class="container"><div class="row justify-content-center"><div class="col-md-5">
      <div class="card">
        <div class="card-header bg-primary text-white"><h3 class="mb-0"><i class="bi bi-box-arrow-in-right me-2"></i>Login</h3></div>
        <div class="card-body">
          {msg_html}
          <form method="POST" action="/login">
            <input type="hidden" name="csrf_token" value="{csrf_token()}"/>
            <input type="hidden" name="next" value="{html.escape(nxt)}"/>
            <div class="mb-3">
              <label class="form-label">Email</label>
              <input type="email" class="form-control" name="email" placeholder="you@example.com" required>
            </div>
            <div class="mb-3">
              <label class="form-label">Password</label>
              <input type="password" class="form-control" name="password" minlength="8" required>
            </div>
            <button class="btn btn-primary" type="submit">Sign In</button>
            <a class="btn btn-outline-success ms-2" href="/signup"><i class="bi bi-person-plus me-1"></i>Create Account</a>
          </form>
        </div>
      </div>
    </div></div></div>
    """
    return base_layout("Login", content)

@app.post("/login", endpoint="sec1_login_post")
def sec1_login_post():
    if not _csrf_ok():
        abort(403)

    rip = (request.headers.get("X-Forwarded-For") or request.remote_addr or "0.0.0.0").split(",")[0].strip()
    if not _rate_ok(f"login:{rip}", per_sec=0.5):
        nxt = _safe_next(request.form.get("next"))
        return redirect(url_for("sec1_login_page", next=nxt, error="rate"))

    email = (request.form.get("email") or "").strip().lower()
    pw    = request.form.get("password") or ""
    nxt   = _safe_next(request.form.get("next"))

    u = _find_user(email)
    if not u or not check_password_hash(u.get("password_hash",""), pw):
        return redirect(url_for("sec1_login_page", next=nxt, error="1"))

    # STABILITY: if guest already accepted in-session, persist to user on login
    if session.get("tos_ok") and not u.get("tos_ok"):
        try:
            _update_user(u["id"], {"tos_ok": True})
            u["tos_ok"] = True
        except Exception:
            pass

    # Optional: accept TOS automatically at login (useful for staging)
    # Set env ACCEPT_TOS_ON_LOGIN=1 to enable; default is disabled for production readiness.
    try:
        auto_accept = _env_bool("ACCEPT_TOS_ON_LOGIN", default=False)
    except Exception:
        auto_accept = False
    if auto_accept and not u.get("tos_ok"):
        try:
            _update_user(u["id"], {"tos_ok": True})
            u["tos_ok"] = True
        except Exception:
            pass

    _auth_set_session(u)

    try:
        _log_event(_user_id(), "auth.login", {})
    except Exception:
        pass

    if u.get("tos_ok"):
        session["tos_ok"] = True
        return redirect(nxt or "/")
    else:
        return redirect(url_for("sec8_welcome", next=nxt or "/"))

# ---------- LOGOUT ----------
@app.get("/logout", endpoint="sec1_logout")
def sec1_logout():
    try:
        _log_event(_user_id(), "auth.logout", {})
    except Exception:
        pass
    _auth_clear_session()
    return redirect("/welcome")
# ========================= END SECTION 8/8 =========================

