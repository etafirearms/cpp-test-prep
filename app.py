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


# =====================================================================
# SECTION 6/8 — CONTENT BANK & ADMIN UPLOAD (FULL)
# START OF SECTION 6/8
# =====================================================================

# STABILITY: stdlib only
import os, io, json, time, glob, hashlib, tempfile, shutil
from typing import List, Dict, Tuple

# STABILITY: use existing logger if present
try:
    logger  # noqa: F821
except NameError:  # pragma: no cover
    import logging
    logger = logging.getLogger("app")

# STABILITY: DATA_DIR must exist from earlier env/config section
try:
    DATA_DIR  # noqa: F821
except NameError:
    DATA_DIR = os.path.join(os.getcwd(), "data")
os.makedirs(DATA_DIR, exist_ok=True)

# ---------- Canonical bank paths (7/8 will reuse these) ----------
BANK_DIR = os.path.join(DATA_DIR, "bank")
os.makedirs(BANK_DIR, exist_ok=True)

ITEMS_JSONL = os.path.join(BANK_DIR, "items.jsonl")
INDEX_JSON   = os.path.join(BANK_DIR, "index.json")   # dedup index: {dedup_key: 1}
SOURCES_JSON = os.path.join(BANK_DIR, "sources.json") # optional metadata

# ---------- Helper: atomic JSON write (reuses earlier pattern if present) ----------
def _atomic_write_bytes(path: str, data: bytes) -> None:
    """Write bytes atomically (path.tmp -> fsync -> replace)."""
    d = os.path.dirname(path) or "."
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".tmp_", dir=d)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except Exception:
            pass
        raise

def _atomic_write_json(path: str, obj) -> None:
    data = json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    _atomic_write_bytes(path, data)

# ---------- Helper: safe append to JSONL with fsync ----------
def _append_jsonl(path: str, objs: List[dict]) -> None:
    if not objs:
        return
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    # Open in append-binary and fsync; this is the safest without external locks.
    with open(path, "ab") as f:
        for o in objs:
            line = (json.dumps(o, ensure_ascii=False) + "\n").encode("utf-8")
            f.write(line)
        f.flush()
        os.fsync(f.fileno())

# ---------- Dedup normalization ----------
def _normalize_text(s: str) -> str:
    # Minimal but effective: lowercase, strip, collapse whitespace.
    # Keep punctuation (security questions may rely on symbols).
    return " ".join(str(s or "").lower().strip().split())

def _dedup_key(item: dict) -> str:
    """
    Build a deterministic key to prevent duplicates even if uploaded again:
    includes type, domain, normalized stem, and (for MCQ) normalized options.
    """
    t = _normalize_text(item.get("type", ""))
    d = _normalize_text(item.get("domain", ""))
    stem = _normalize_text(item.get("stem", ""))

    parts = [f"type={t}", f"domain={d}", f"stem={stem}"]

    # Include options for MCQ/Scenario if present
    opts = item.get("options")
    if isinstance(opts, list) and opts:
        norm_opts = [ _normalize_text(x) for x in opts ]
        parts.append("options=" + "|".join(norm_opts))

    # If True/False, include normalized answer
    ans = item.get("answer")
    if isinstance(ans, str):
        parts.append("answer=" + _normalize_text(ans))

    raw = "\n".join(parts).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()

# ---------- Index load/save ----------
def _load_index() -> Dict[str, int]:
    try:
        with open(INDEX_JSON, "r", encoding="utf-8") as f:
            obj = json.load(f) or {}
            if isinstance(obj, dict):
                return {k: int(v) for k, v in obj.items()}
    except FileNotFoundError:
        return {}
    except Exception as e:
        logger.warning("INDEX read failed: %r", e)
    return {}

def _save_index(idx: Dict[str, int]) -> None:
    _atomic_write_json(INDEX_JSON, idx)

# ---------- Canonical loader used by Section 7/8 ----------
def load_all_items() -> List[dict]:
    items: List[dict] = []

    def _read_jsonl(path: str):
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                        if isinstance(obj, dict):
                            items.append(obj)
                    except Exception:
                        continue
        except FileNotFoundError:
            return
        except Exception as e:
            logger.warning("Could not read %s: %r", path, e)

    # Primary file
    _read_jsonl(ITEMS_JSONL)

    # Any other *.jsonl files in bank/ (merging additional sources)
    for p in glob.glob(os.path.join(BANK_DIR, "*.jsonl")):
        if os.path.abspath(p) == os.path.abspath(ITEMS_JSONL):
            continue
        _read_jsonl(p)

    return items

# ---------- Public stats (per domain/type) for Admin ----------
def _stats(items: List[dict]) -> Dict[str, Dict[str, int]]:
    result: Dict[str, Dict[str, int]] = {}
    for it in items:
        d = it.get("domain", "unknown")
        t = str(it.get("type", "")).lower()
        bucket = result.setdefault(d, {})
        bucket[t] = bucket.get(t, 0) + 1
    return result

# ---------- ADMIN UPLOAD API ----------
try:
    app  # noqa: F821
    from flask import request, jsonify
    try:
        ADMIN_UPLOAD_TOKEN  # noqa: F821
    except NameError:
        ADMIN_UPLOAD_TOKEN = os.environ.get("ADMIN_UPLOAD_TOKEN", "")

    MAX_UPLOAD_BYTES = int(os.environ.get("MAX_UPLOAD_BYTES", "5242880"))  # 5 MB default
    ACCEPTED_MIME = {"application/json", "application/x-ndjson", "text/plain"}

    def _admin_auth_ok() -> bool:
        tok = request.headers.get("X-Admin-Token", "")
        return bool(ADMIN_UPLOAD_TOKEN) and tok == ADMIN_UPLOAD_TOKEN

    def _parse_upload_payload() -> Tuple[List[dict], List[str]]:
        """
        Accept either:
          - multipart/form-data with a 'file' field (JSON or JSONL/NDJSON)
          - raw JSON (list or object) in request.data
          - raw NDJSON in text/plain
        Returns (items, errors)
        """
        errors: List[str] = []
        raw: bytes = b""

        # Multipart path
        if request.files:
            f = request.files.get("file")
            if not f:
                return [], ["missing file"]
            stream = f.stream.read()
            if len(stream) > MAX_UPLOAD_BYTES:
                return [], [f"file too large (> {MAX_UPLOAD_BYTES} bytes)"]
            raw = stream
        else:
            # Raw body
            body = request.get_data(cache=False, as_text=False)
            if len(body) > MAX_UPLOAD_BYTES:
                return [], [f"payload too large (> {MAX_UPLOAD_BYTES} bytes)"]
            raw = body

        # Try JSON (array or single object)
        try:
            obj = json.loads(raw.decode("utf-8"))
            if isinstance(obj, list):
                items = [x for x in obj if isinstance(x, dict)]
            elif isinstance(obj, dict):
                # Could be {"items":[...]}
                if "items" in obj and isinstance(obj["items"], list):
                    items = [x for x in obj["items"] if isinstance(x, dict)]
                else:
                    items = [obj]
            else:
                items = []
            if items:
                return items, errors
        except Exception:
            pass

        # Try NDJSON/JSONL
        items: List[dict] = []
        try:
            for line in raw.decode("utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    o = json.loads(line)
                    if isinstance(o, dict):
                        items.append(o)
                except Exception:
                    continue
        except Exception as e:
            errors.append(f"decode error: {e!r}")

        return items, errors

    @app.post("/api/admin/items/upload")
    def api_admin_items_upload():
        if not _admin_auth_ok():
            return jsonify({"ok": False, "error": "Unauthorized"}), 401

        items, errs = _parse_upload_payload()
        if errs:
            return jsonify({"ok": False, "error": "; ".join(errs)}), 400
        if not items:
            return jsonify({"ok": False, "error": "no items parsed"}), 400

        # Normalize, dedup, and minimal validation
        idx = _load_index()
        new_items: List[dict] = []
        skipped = 0

        for it in items:
            # Minimal validation
            t = (it.get("type") or "").strip().lower()
            d = it.get("domain")
            stem = it.get("stem")
            if t not in ("mcq", "tf", "scenario"):
                # normalize aliases if any
                if t in ("truefalse", "true_false", "boolean"):
                    t = "tf"
                    it["type"] = "tf"
                else:
                    # skip unknown types
                    skipped += 1
                    continue
            if not d or not stem:
                skipped += 1
                continue

            # Normalize fields
            it["type"] = t
            it["domain"] = str(d).strip()
            it["stem"] = str(stem).strip()

            # Ensure options exist for MCQ/Scenario
            if t in ("mcq", "scenario"):
                opts = it.get("options")
                if not (isinstance(opts, list) and opts):
                    skipped += 1
                    continue

            key = _dedup_key(it)
            if key in idx:
                skipped += 1
                continue

            # Mark and collect
            idx[key] = 1
            # Attach source marker if provided
            src = request.headers.get("X-Source-Name", "").strip()
            if src:
                it.setdefault("sources", [])
                if src not in it["sources"]:
                    it["sources"].append(src)
            new_items.append(it)

        # Persist new items and updated index
        if new_items:
            _append_jsonl(ITEMS_JSONL, new_items)
            _save_index(idx)

        # Optional: update a simple sources.json tally
        try:
            sources = {}
            if os.path.exists(SOURCES_JSON):
                with open(SOURCES_JSON, "r", encoding="utf-8") as f:
                    prev = json.load(f) or {}
                    if isinstance(prev, dict):
                        sources = prev
            src_name = request.headers.get("X-Source-Name", "").strip() or "unspecified"
            sources[src_name] = int(sources.get(src_name, 0)) + len(new_items)
            _atomic_write_json(SOURCES_JSON, sources)
        except Exception as e:
            logger.warning("sources.json update failed: %r", e)

        return jsonify({
            "ok": True,
            "added": len(new_items),
            "skipped": skipped,
            "total_bank": len(load_all_items())
        }), 200

    @app.get("/api/admin/items/stats")
    def api_admin_items_stats():
        if not _admin_auth_ok():
            return jsonify({"ok": False, "error": "Unauthorized"}), 401
        items = load_all_items()
        return jsonify({
            "ok": True,
            "count": len(items),
            "by_domain_type": _stats(items)
        }), 200

    # CSRF exemption if Flask-WTF CSRF is present (matches earlier rule style)
    try:
        _csrf_obj = globals().get("csrf")
        if _csrf_obj is not None:
            _csrf_obj.exempt(api_admin_items_upload)
            _csrf_obj.exempt(api_admin_items_stats)
    except Exception:
        pass

except NameError:
    # app not defined yet (very early import); in your file order app exists already
    pass

# =====================================================================
# SECTION 6/8 — CONTENT BANK & ADMIN UPLOAD
# END OF SECTION 6/8
# =====================================================================


# =====================================================================
# =====================================================================
# SECTION 7/8 — BANK SELECTION HELPERS (FIXED, SELF-CONTAINED)
# START OF SECTION 7/8
# =====================================================================

# STABILITY: imports
import os, json, math, random, io, glob
from typing import Iterable, List, Dict, Tuple

# STABILITY: reuse existing logger if present
try:
    logger  # noqa: F821
except NameError:  # pragma: no cover
    import logging
    logger = logging.getLogger("app")

# STABILITY: DATA_DIR must exist from earlier env/config section
try:
    DATA_DIR  # noqa: F821
except NameError:
    # Last-resort fallback — matches earlier instructions
    DATA_DIR = os.path.join(os.getcwd(), "data")
os.makedirs(DATA_DIR, exist_ok=True)

# STABILITY: Define BANK_DIR here if not already defined by Section 6/8
try:
    BANK_DIR  # noqa: F821
except NameError:
    BANK_DIR = os.path.join(DATA_DIR, "bank")
    os.makedirs(BANK_DIR, exist_ok=True)

# Optional constant sometimes defined in Section 6/8; we won’t rely on it but keep it if present
try:
    ITEMS_JSONL  # noqa: F821
except NameError:
    ITEMS_JSONL = os.path.join(BANK_DIR, "items.jsonl")

# ---------- Fallback loader if Section 6/8 didn't define load_all_items() ----------
def _fallback_load_all_items() -> List[dict]:
    """
    Load all bank items from:
      - bank/items.jsonl (preferred)
      - any *.jsonl inside bank/ (merged)
    Each line should be a JSON object with keys like:
      type, domain, stem, options, answer, explanation, sources.
    """
    items: List[dict] = []

    def _read_jsonl(path: str):
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                        if isinstance(obj, dict):
                            items.append(obj)
                    except Exception:
                        # skip bad lines; keep going
                        continue
        except FileNotFoundError:
            return
        except Exception as e:
            logger.warning("Could not read %s: %r", path, e)

    # 1) Primary file
    _read_jsonl(ITEMS_JSONL)

    # 2) Any other *.jsonl in bank dir (avoid double-reading items.jsonl)
    for p in glob.glob(os.path.join(BANK_DIR, "*.jsonl")):
        if os.path.abspath(p) == os.path.abspath(ITEMS_JSONL):
            continue
        _read_jsonl(p)

    return items

# Use existing load_all_items() from Section 6/8 if present; else fallback
try:
    load_all_items  # noqa: F821
except NameError:
    def load_all_items() -> List[dict]:  # type: ignore
        return _fallback_load_all_items()

# ---------- Domain weights (CPP weighting support) ----------
# Admin may provide a weights file mapping domain -> weight (any positive numbers).
# Example file: bank/weights.json
# {
#   "Domain 1 - Security Principles and Practices": 25,
#   "Domain 2 - Business Principles": 15,
#   ...
# }
_WEIGHTS_FILE = os.path.join(BANK_DIR, "weights.json")

def _load_domain_weights(allowed_domains: Iterable[str]) -> Dict[str, float]:
    """Load domain weights from bank/weights.json if present; fallback to uniform."""
    weights: Dict[str, float] = {}
    try:
        if os.path.exists(_WEIGHTS_FILE):
            with open(_WEIGHTS_FILE, "r", encoding="utf-8") as f:
                raw = json.load(f) or {}
                for d in allowed_domains:
                    v = raw.get(d)
                    if isinstance(v, (int, float)) and v > 0:
                        weights[d] = float(v)
    except Exception as e:
        logger.warning("Could not read weights.json: %r", e)

    # Fallback to uniform over allowed domains
    if not weights:
        weights = {d: 1.0 for d in allowed_domains}

    # Normalize to sum 1.0
    total = sum(weights.values()) or 1.0
    return {k: (v / total) for k, v in weights.items()}

# ---------- Utility: pull all items ----------
def _bank_all_items() -> List[dict]:
    try:
        return load_all_items()  # from Section 6/8 or our fallback
    except Exception as e:
        logger.error("load_all_items() failed: %r", e)
        return []

# ---------- Filters ----------
def _filter_by_domain(items: List[dict], domain: str) -> List[dict]:
    if not domain or domain.lower() in ("random", "mixed", "any"):
        return items[:]  # all domains
    return [it for it in items if it.get("domain") == domain]

def _filter_by_types(items: List[dict], allowed_types: Iterable[str]) -> List[dict]:
    allowed = set([t.lower() for t in allowed_types])
    return [it for it in items if str(it.get("type", "")).lower() in allowed]

# ---------- Type mix targets (50% MCQ, 25% TF, 25% Scenario) ----------
_TYPE_TARGETS = {"mcq": 0.50, "tf": 0.25, "scenario": 0.25}
# If bank lacks enough of a type, we degrade gracefully and fill with others.

def _compute_type_needs(total: int, available_counts: Dict[str, int]) -> Dict[str, int]:
    """Given a total and what the bank has, decide how many of each type to take."""
    # Initial ideal targets (rounded down)
    wants = {t: int(math.floor(_TYPE_TARGETS[t] * total)) for t in _TYPE_TARGETS}
    # Fix rounding gaps by adding to the largest buckets until sum == total
    gap = total - sum(wants.values())
    if gap > 0:
        for t in ("mcq", "tf", "scenario"):
            if gap <= 0:
                break
            wants[t] += 1
            gap -= 1

    # Cap by availability, record shortage
    shortage = 0
    for t, need in list(wants.items()):
        have = int(available_counts.get(t, 0))
        if need > have:
            shortage += (need - have)
            wants[t] = have

    if shortage > 0:
        # Redistribute shortage into any types with spare items
        for t in ("mcq", "tf", "scenario"):
            if shortage <= 0:
                break
            spare = max(0, available_counts.get(t, 0) - wants.get(t, 0))
            if spare > 0:
                take = min(spare, shortage)
                wants[t] += take
                shortage -= take

    return wants

# ---------- Random helpers ----------
_RNG = random.Random()

def _sample(items: List[dict], k: int) -> List[dict]:
    """Return up to k items randomly without replacement (k may exceed len)."""
    if k <= 0:
        return []
    if k >= len(items):
        copy = items[:]
        _RNG.shuffle(copy)
        return copy
    return _RNG.sample(items, k)

# ---------- Core picker ----------
def pick_from_bank(domain: str, total: int) -> List[dict]:
    """
    Select questions from the bank honoring:
      - specific domain if requested; otherwise weighted across domains (CPP weights)
      - type distribution: 50% mcq, 25% tf, 25% scenario (with graceful fallback)
    Returns a list of raw item dicts.
    """
    all_items = _bank_all_items()
    if not all_items:
        logger.warning("Content bank is empty; returning no items")
        return []

    # Determine target pool by domain(s)
    if not domain or domain.lower() in ("random", "mixed", "any"):
        # Weighted selection across domains
        by_domain: Dict[str, List[dict]] = {}
        for it in all_items:
            d = it.get("domain", "unknown")
            by_domain.setdefault(d, []).append(it)

        allowed_domains = list(by_domain.keys())
        weights = _load_domain_weights(allowed_domains)

        # Draw domain labels according to weights, stopping when we have enough items
        selected_domains: List[str] = []
        if total <= 0:
            return []

        domains = allowed_domains[:]
        probs = [weights[d] for d in domains]
        s = sum(probs) or 1.0
        probs = [p / s for p in probs]

        while len(selected_domains) < total and any(by_domain.values()):
            r = _RNG.random()
            acc = 0.0
            chosen = domains[-1]
            for d, p in zip(domains, probs):
                acc += p
                if r <= acc:
                    chosen = d
                    break
            # Only keep if domain still has items
            if by_domain.get(chosen):
                selected_domains.append(chosen)

        pool: List[dict] = []
        for d in selected_domains:
            bucket = by_domain.get(d) or []
            if bucket:
                pool.append(_RNG.choice(bucket))

        if not pool:
            pool = all_items[:]  # extreme fallback
    else:
        # Specific domain
        pool = _filter_by_domain(all_items, domain)

    # Enforce type distribution from pool
    mcq_pool  = [it for it in pool if str(it.get("type","")).lower() == "mcq"]
    tf_pool   = [it for it in pool if str(it.get("type","")).lower() == "tf"]
    scen_pool = [it for it in pool if str(it.get("type","")).lower() == "scenario"]

    avail = {"mcq": len(mcq_pool), "tf": len(tf_pool), "scenario": len(scen_pool)}
    wants = _compute_type_needs(max(0, int(total)), avail)

    chosen: List[dict] = []
    chosen.extend(_sample(mcq_pool, wants.get("mcq", 0)))
    chosen.extend(_sample(tf_pool, wants.get("tf", 0)))
    chosen.extend(_sample(scen_pool, wants.get("scenario", 0)))

    # If still short (e.g., small pool), fill from leftovers
    if len(chosen) < total:
        leftovers = [it for it in pool if it not in chosen]
        chosen.extend(_sample(leftovers, total - len(chosen)))

    _RNG.shuffle(chosen)
    return chosen[:total]

# ---------- Facade helpers for your routes (call these) ----------
def get_flashcards_from_bank(domain: str, count: int) -> List[dict]:
    """Return `count` items for flashcards."""
    count = max(0, int(count))
    return pick_from_bank(domain, count)

def get_quiz_questions_from_bank(domain: str, count: int) -> List[dict]:
    """Return `count` items for a quiz session."""
    count = max(0, int(count))
    return pick_from_bank(domain, count)

def get_mock_questions_from_bank(domain: str, count: int) -> List[dict]:
    """Return `count` items for mock exam."""
    count = max(0, int(count))
    return pick_from_bank(domain, count)

# ---------- Optional: admin dry-run picker ----------
try:
    app  # noqa: F821
    from flask import request  # local import is fine
    try:
        ADMIN_UPLOAD_TOKEN  # noqa: F821
    except NameError:
        ADMIN_UPLOAD_TOKEN = os.environ.get("ADMIN_UPLOAD_TOKEN", "")

    @app.get("/api/admin/items/dry-run-pick")
    def api_admin_dry_run_pick():
        """Debug endpoint to visualize a pick without exposing answers to students."""
        token_hdr = request.headers.get("X-Admin-Token", "")
        if not ADMIN_UPLOAD_TOKEN or token_hdr != ADMIN_UPLOAD_TOKEN:
            return {"ok": False, "error": "Unauthorized"}, 401
        domain = request.args.get("domain", "random")
        n = int(request.args.get("n", "20"))
        items = pick_from_bank(domain, n)
        # return only minimal info (no answers)
        preview = [{"domain": it.get("domain"), "type": it.get("type"), "stem": it.get("stem")} for it in items]
        return {"ok": True, "picked": preview, "count": len(preview)}, 200

    # CSRF exemption if CSRF is present
    try:
        _csrf_obj = globals().get("csrf")
        if _csrf_obj is not None:
            _csrf_obj.exempt(api_admin_dry_run_pick)
    except Exception:
        pass

except NameError:
    # app not defined yet (unlikely in your file order); skip optional endpoint
    pass

# =====================================================================
# SECTION 7/8 — BANK SELECTION HELPERS
# END OF SECTION 7/8
# =====================================================================

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




