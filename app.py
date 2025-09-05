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


### START OF SECTION 4/8 — QUIZ & MOCK (BANK-POWERED, UI PRESERVED)

# Notes:
# - Keeps your existing flows (/quiz, /quiz/start, /mock, /mock/start).
# - Leaves your domain buttons and count pickers intact.
# - Uses select_questions(...) from Section 7/8 and bank from Section 6/8.
# - No new dependencies. No template system change.
# - Avoids f-strings to prevent { } collisions inside inline JS.

from flask import request, abort, redirect, url_for
import html
import json

# ---- Helpers ---------------------------------------------------------------

def _html_escape(s):
    try:
        return html.escape(str(s), quote=True)
    except Exception:
        return str(s)

def _req_int(name, default, lo=1, hi=500):
    try:
        v = int(request.form.get(name, request.args.get(name, default)))
        return max(lo, min(hi, v))
    except Exception:
        return default

def _selected_domains_from_request() -> list:
    """
    Accepts:
      - 'domain_val' (single hidden input from your button group)
      - 'domain' (single)
      - 'domain[]' (multi)
    Returns list[str]
    """
    vals = []
    # multi-select support
    multi = request.form.getlist("domain[]") or request.args.getlist("domain[]")
    if multi:
        vals.extend([v for v in multi if v])
    # single hidden input
    one = request.form.get("domain_val") or request.args.get("domain_val")
    if one:
        vals.append(one)
    # single plain field
    one2 = request.form.get("domain") or request.args.get("domain")
    if one2:
        vals.append(one2)

    # normalize & unique, preserve order
    seen = set()
    out = []
    for v in vals:
        vv = str(v).strip()
        if not vv:
            continue
        if vv not in seen:
            out.append(vv)
            seen.add(vv)
    return out

def _render_picker_page(title: str, post_action: str, default_count: int = 10) -> str:
    """
    Minimal picker UI; preserves your domain button behavior and count control.
    """
    content = """
    <div class="container" style="max-width: 960px;">
      <div class="card shadow-sm my-4">
        <div class="card-header d-flex align-items-center">
          <div>
            <h4 class="mb-0">{title}</h4>
            <div class="text-muted small">Choose your domain(s) and how many questions to practice.</div>
          </div>
        </div>
        <div class="card-body">
          <form method="post" action="{action}">
            <input type="hidden" id="domain_val" name="domain_val" value="">
            <div class="mb-3">
              <label class="form-label">Domains</label>
              <div class="d-flex flex-wrap gap-2">
                <button type="button" class="btn btn-outline-primary domain-btn" data-value="Domain 1">Domain 1</button>
                <button type="button" class="btn btn-outline-primary domain-btn" data-value="Domain 2">Domain 2</button>
                <button type="button" class="btn btn-outline-primary domain-btn" data-value="Domain 3">Domain 3</button>
                <button type="button" class="btn btn-outline-primary domain-btn" data-value="Domain 4">Domain 4</button>
                <button type="button" class="btn btn-outline-primary domain-btn" data-value="Domain 5">Domain 5</button>
                <button type="button" class="btn btn-outline-primary domain-btn" data-value="Domain 6">Domain 6</button>
                <button type="button" class="btn btn-outline-primary domain-btn" data-value="Domain 7">Domain 7</button>
              </div>
              <div class="text-muted small mt-2">Tip: Leave blank for a mixed-domain set based on CPP blueprint weights.</div>
            </div>

            <div class="mb-3">
              <label class="form-label">How many questions?</label>
              <input type="number" class="form-control" name="count" min="1" max="200" value="{count}">
            </div>

            <div class="d-flex gap-2">
              <button class="btn btn-primary" type="submit">Start</button>
              <a class="btn btn-outline-secondary" href="/">Cancel</a>
            </div>
          </form>
        </div>
      </div>
    </div>

    <script>
      (function(){
        var container = document.currentScript.closest('.card').querySelector('.card-body');
        var hidden = container.querySelector('#domain_val');
        container.querySelectorAll('.domain-btn').forEach(function(btn){
          btn.addEventListener('click', function(){
            container.querySelectorAll('.domain-btn').forEach(function(b){ b.classList.remove('active'); });
            btn.classList.add('active');
            if (hidden) hidden.value = btn.getAttribute('data-value');
          });
        });
      })();
    </script>
    """.replace("{title}", _html_escape(title))\
       .replace("{action}", _html_escape(post_action))\
       .replace("{count}", _html_escape(default_count))
    return base_layout(title, content)

def _render_exam_page(title: str, questions: list) -> str:
    """
    Render a lightweight, keyboard-friendly practice page.
    - One question per screen with Next/Prev
    - 'Reveal Answer' per question (no auto-submission)
    - Works for MC, TF, Scenario
    """
    # We JSON-embed only non-sensitive fields.
    safe_qs = []
    for q in questions:
        t = str(q.get("type","")).lower()
        safe = {
            "id": q.get("id"),
            "domain": q.get("domain"),
            "type": t,
            "stem": q.get("stem"),
            "choices": q.get("choices", []) if t == "mc" else [],
            "answer": q.get("answer", None) if t in ("mc","tf") else None,
            "options": q.get("options", []) if t == "scenario" else [],
            "answers": q.get("answers", []) if t == "scenario" else [],
            "explanation": q.get("explanation","")
        }
        safe_qs.append(safe)

    payload = _html_escape(json.dumps(safe_qs, ensure_ascii=False))

    content = """
    <div class="container" style="max-width: 960px;">
      <div class="card shadow-sm my-4">
        <div class="card-header d-flex align-items-center justify-content-between">
          <div>
            <h4 class="mb-0">{title}</h4>
            <div class="text-muted small" id="prog"></div>
          </div>
          <div class="text-muted small">Use ← → keys to navigate</div>
        </div>
        <div class="card-body">
          <div id="qroot"></div>
          <div class="d-flex justify-content-between mt-3">
            <button class="btn btn-outline-secondary" id="prevBtn">Prev</button>
            <button class="btn btn-primary" id="nextBtn">Next</button>
          </div>
        </div>
      </div>
    </div>

    <script>
      (function(){
        var data = JSON.parse("{payload}");
        var idx = 0;

        var root = document.getElementById('qroot');
        var prog = document.getElementById('prog');
        var prevBtn = document.getElementById('prevBtn');
        var nextBtn = document.getElementById('nextBtn');

        function render() {
          if (!data.length) {
            root.innerHTML = '<div class="alert alert-warning">No questions available for this selection.</div>';
            prog.textContent = '';
            prevBtn.disabled = true; nextBtn.disabled = true;
            return;
          }
          var q = data[idx];
          prog.textContent = 'Question ' + (idx+1) + ' of ' + data.length + (q.domain ? (' — ' + q.domain) : '');

          var html = '';
          html += '<div class="mb-2"><strong>' + escapeHtml(q.stem || '') + '</strong></div>';

          if (q.type === 'mc') {
            html += '<ol type="A">';
            (q.choices || []).forEach(function(c, i){
              html += '<li>' + escapeHtml(String(c || "")) + '</li>';
            });
            html += '</ol>';
            html += '<button class="btn btn-sm btn-outline-primary" id="revealBtn">Reveal Answer</button>';
            html += '<div class="mt-2 d-none" id="ans"><span class="badge bg-success">Answer: ' + _letter(q.answer) + '</span>'
                 +  (q.explanation ? ('<div class="mt-2 text-muted">'+ escapeHtml(q.explanation) +'</div>') : '')
                 +  '</div>';
          } else if (q.type === 'tf') {
            html += '<div class="mb-2">True or False?</div>';
            html += '<ul><li>True</li><li>False</li></ul>';
            html += '<button class="btn btn-sm btn-outline-primary" id="revealBtn">Reveal Answer</button>';
            html += '<div class="mt-2 d-none" id="ans"><span class="badge bg-success">Answer: ' + (q.answer ? 'True' : 'False') + '</span>'
                 +  (q.explanation ? ('<div class="mt-2 text-muted">'+ escapeHtml(q.explanation) +'</div>') : '')
                 +  '</div>';
          } else {
            // scenario: multi-answer
            html += '<div class="mb-2">Select all that apply:</div>';
            html += '<ol type="A">';
            (q.options || []).forEach(function(c, i){
              html += '<li>' + escapeHtml(String(c || "")) + '</li>';
            });
            html += '</ol>';
            var letters = (q.answers || []).map(function(i){ return _letter(i); });
            html += '<button class="btn btn-sm btn-outline-primary" id="revealBtn">Reveal Answer</button>';
            html += '<div class="mt-2 d-none" id="ans"><span class="badge bg-success">Answer: ' + letters.join(', ') + '</span>'
                 +  (q.explanation ? ('<div class="mt-2 text-muted">'+ escapeHtml(q.explanation) +'</div>') : '')
                 +  '</div>';
          }

          root.innerHTML = html;
          var rb = document.getElementById('revealBtn');
          var ans = document.getElementById('ans');
          if (rb && ans) rb.addEventListener('click', function(){
            ans.classList.remove('d-none');
          });

          prevBtn.disabled = (idx === 0);
          nextBtn.disabled = (idx === data.length - 1);
        }

        function _letter(i){
          var A = 'A'.charCodeAt(0);
          var n = parseInt(i, 10);
          if (isNaN(n) || n < 0) return '?';
          return String.fromCharCode(A + n);
        }

        function escapeHtml(s){
          return String(s)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
        }

        prevBtn.addEventListener('click', function(){ if (idx>0){ idx--; render(); }});
        nextBtn.addEventListener('click', function(){ if (idx < data.length-1){ idx++; render(); }});
        window.addEventListener('keydown', function(e){
          if (e.key === 'ArrowLeft'){ if (idx>0){ idx--; render(); } }
          if (e.key === 'ArrowRight'){ if (idx < data.length-1){ idx++; render(); } }
        });

        render();
      })();
    </script>
    """.replace("{title}", _html_escape(title))\
       .replace("{payload}", payload)
    return base_layout(title, content)

def _log_safely(event_name: str, payload: dict):
    try:
        if "_log_event" in globals():
            _log_event(_user_id(), event_name, payload)
    except Exception:
        pass

# ---- Routes: QUIZ ----------------------------------------------------------

@app.get("/quiz")
@login_required
def sec4_quiz_picker():
    # lightweight event
    _log_safely("quiz.picker.view", {})
    # Render picker; form posts to /quiz/start
    return _render_picker_page("Quiz", "/quiz/start", default_count=10)

@app.post("/quiz/start")
@login_required
def sec4_quiz_start():
    if not _csrf_ok():
        abort(403)

    # selected domains (or empty → use weights)
    domains = _selected_domains_from_request()
    # how many questions (keep your user's freedom)
    count = _req_int("count", default=10, lo=1, hi=200)

    # use selection engine (Section 7/8)
    try:
        qs = select_questions(domains=domains, count=count, mix=None, user_id=_user_id())
    except Exception as e:
        _log_safely("quiz.start.error", {"error": str(e)})
        return base_layout("Quiz", '<div class="alert alert-danger">Could not build quiz set. Please try again.</div>')

    _log_safely("quiz.start", {"domains": domains, "count": count, "actual": len(qs)})
    return _render_exam_page("Quiz", qs)

# ---- Routes: MOCK EXAM -----------------------------------------------------

@app.get("/mock")
@login_required
def sec4_mock_picker():
    _log_safely("mock.picker.view", {})
    return _render_picker_page("Mock Exam", "/mock/start", default_count=50)

@app.post("/mock/start")
@login_required
def sec4_mock_start():
    if not _csrf_ok():
        abort(403)

    domains = _selected_domains_from_request()
    count = _req_int("count", default=50, lo=10, hi=500)

    try:
        qs = select_questions(domains=domains, count=count, mix=None, user_id=_user_id())
    except Exception as e:
        _log_safely("mock.start.error", {"error": str(e)})
        return base_layout("Mock Exam", '<div class="alert alert-danger">Could not build mock exam. Please try again.</div>')

    _log_safely("mock.start", {"domains": domains, "count": count, "actual": len(qs)})
    return _render_exam_page("Mock Exam", qs)

### END OF SECTION 4/8 — QUIZ & MOCK (BANK-POWERED, UI PRESERVED)


# ===== SECTION 5/8 — TUTOR ROUTE (RESTORE & STABLE) — START =====
# STABILITY: This section restores a working /tutor endpoint to fix 404s
# without redesigning the UI. It is safe to paste wholesale.
#
# Placement:
#   - Replace your entire existing “SECTION 5/8 …” with this block.
#   - If you no longer have a Section 5/8, insert this whole block
#     *after* Section 4/8 and *before* Section 6/8.
#
# Notes:
#   - Keeps route name /tutor unchanged (prevents 404).
#   - Gracefully degrades if OpenAI isn’t configured: shows a clear banner.
#   - No external deps added; no template files required.
#   - Uses base_layout() provided earlier in your app.
#   - If you already have a /tutor route elsewhere, we won’t re-register it.

import os
import html

try:
    from flask import request, abort, redirect
    from flask import url_for  # used in links if needed
except Exception:  # pragma: no cover
    pass

# Try to import Flask-Login decorators if they exist in your app.
try:
    from flask_login import login_required, current_user
except Exception:  # pragma: no cover
    def login_required(fn):  # no-op if flask_login isn’t present
        return fn
    current_user = None  # sentinel


def _sx5_route_exists(path: str) -> bool:
    """Return True if a rule with the given path is already registered."""
    try:
        for rule in app.url_map.iter_rules():  # 'app' defined earlier
            if str(rule.rule) == path:
                return True
    except Exception:
        pass
    return False


def _sx5_tutor_ready() -> bool:
    """Minimal readiness check for Tutor (OpenAI)."""
    # We don’t import any SDK here; we only check for a key to avoid UI lies.
    key = os.environ.get("OPENAI_API_KEY", "").strip()
    return bool(key)


# Only register the route if it doesn’t already exist (prevents overwrite).
if not _sx5_route_exists("/tutor"):

    @app.get("/tutor")
    @login_required
    def sec5_tutor_page():
        """
        A minimal, stable Tutor page that prevents 404s and degrades gracefully
        when OpenAI isn’t configured. This keeps paths stable for navigation.
        """
        ready = _sx5_tutor_ready()
        # Keep HTML simple and compatible (no f-string braces in JS).
        # We avoid inline JS with curly braces to prevent accidental f-string issues.
        banner = ""
        if not ready:
            banner = (
                '<div class="alert alert-warning mb-3">'
                "Tutor is currently offline (AI key not configured). "
                "Your study modes remain available."
                "</div>"
            )

        # We do not change your existing global page shell. This content
        # will be wrapped by base_layout().
        content = (
            '<div class="container py-3">'
            '  <div class="row">'
            '    <div class="col-12 col-lg-8">'
            '      <div class="card shadow-sm mb-3">'
            '        <div class="card-header">AI Tutor</div>'
            '        <div class="card-body">'
            f'          {banner}'
            '          <p class="text-muted">'
            '            Ask concept questions about CPP domains, exam strategy, or definitions.'
            '          </p>'
            '          <form method="post" action="/tutor/ask">'
            '            <div class="mb-3">'
            '              <textarea name="q" class="form-control" rows="4" '
            '                placeholder="Type your question about any CPP domain..."></textarea>'
            '            </div>'
            '            <button class="btn btn-primary" type="submit"'
            '              title="Send question to Tutor">Ask Tutor</button>'
            '          </form>'
            '        </div>'
            '      </div>'
            '    </div>'
            '    <div class="col-12 col-lg-4">'
            '      <div class="card shadow-sm mb-3">'
            '        <div class="card-header">Tips</div>'
            '        <div class="card-body small text-muted">'
            '          <ul class="mb-0">'
            '            <li>Mention your target domain for focused help.</li>'
            '            <li>Ask for definitions, comparisons, or step-by-steps.</li>'
            '            <li>Use follow-ups like “give me a scenario”.</li>'
            '          </ul>'
            '        </div>'
            '      </div>'
            '    </div>'
            '  </div>'
            '</div>'
        )
        try:
            return base_layout("Tutor", content)
        except Exception:
            # If base_layout isn’t available for some reason, fall back.
            return content

    # Optional: very small handler that simply echoes the question when Tutor isn’t ready.
    # This avoids a 404 on form POST while keeping behavior harmless until AI is wired.
    @app.post("/tutor/ask")
    @login_required
    def sec5_tutor_ask():
        q = (request.form.get("q") or "").strip()
        if not q:
            # No question — just bounce back to GET page.
            return redirect("/tutor")
        if not _sx5_tutor_ready():
            # Tutor offline: show a simple, non-breaking page with the echoed question.
            safe_q = html.escape(q)
            content = (
                '<div class="container py-3">'
                '  <div class="alert alert-warning">'
                '    Tutor offline (no AI key configured). Showing your question only.'
                '  </div>'
                '  <div class="card shadow-sm">'
                '    <div class="card-header">Your question</div>'
                f'    <div class="card-body"><pre class="mb-0">{safe_q}</pre></div>'
                '  </div>'
                '  <div class="mt-3">'
                '    <a class="btn btn-secondary" href="/tutor">Back to Tutor</a>'
                '  </div>'
                '</div>'
            )
            try:
                return base_layout("Tutor", content)
            except Exception:
                return content, 200

        # If Tutor is ready, we hand-off to your existing AI workflow if present.
        # Many codebases already have a helper like _tutor_answer(); we call it
        # only if it exists. Otherwise, we show a polite placeholder.
        try:
            _tutor_answer  # type: ignore  # noqa: F401
        except NameError:
            # No internal tutor function provided; placeholder response.
            safe_q = html.escape(q)
            content = (
                '<div class="container py-3">'
                '  <div class="alert alert-info">'
                '    Tutor is configured, but no answer function is wired yet.'
                '  </div>'
                '  <div class="card shadow-sm mb-3">'
                '    <div class="card-header">Your question</div>'
                f'    <div class="card-body"><pre class="mb-0">{safe_q}</pre></div>'
                '  </div>'
                '  <div>'
                '    <a class="btn btn-secondary" href="/tutor">Back to Tutor</a>'
                '  </div>'
                '</div>'
            )
            try:
                return base_layout("Tutor", content)
            except Exception:
                return content, 200

        # If your project defines _tutor_answer(q, user_id) we’ll use it.
        try:
            uid = _user_id() if " _user_id" in globals() else None  # safe best-effort
        except Exception:
            uid = None
        try:
            answer_html = _tutor_answer(q, uid)  # expected to return sanitized HTML
        except Exception as ex:
            # Do not crash the page if the model call fails.
            safe_err = html.escape(str(ex))
            answer_html = (
                '<div class="alert alert-danger">'
                'Tutor error. Please try again later.<br>'
                f'<small>{safe_err}</small>'
                '</div>'
            )

        # Render the Q/A result
        safe_q = html.escape(q)
        content = (
            '<div class="container py-3">'
            '  <div class="card shadow-sm mb-3">'
            '    <div class="card-header">Your question</div>'
            f'    <div class="card-body"><pre class="mb-0">{safe_q}</pre></div>'
            '  </div>'
            '  <div class="card shadow-sm mb-3">'
            '    <div class="card-header">Tutor</div>'
            f'    <div class="card-body">{answer_html}</div>'
            '  </div>'
            '  <div>'
            '    <a class="btn btn-secondary" href="/tutor">Ask another</a>'
            '  </div>'
            '</div>'
        )
        try:
            return base_layout("Tutor", content)
        except Exception:
            return content, 200

# ===== SECTION 5/8 — TUTOR ROUTE (RESTORE & STABLE) — END =====

### START OF SECTION 6/8 — CONTENT BANK & DATA MODEL (NEW)

# STABILITY: stdlib-only imports (no new deps)
import os, json, time, uuid, random, hashlib, tempfile, io, difflib
from typing import List, Dict, Any, Optional, Tuple

# STABILITY: reuse existing DATA_DIR if defined; else fall back to cwd/data
if "DATA_DIR" not in globals():
    DATA_DIR = os.path.join(os.getcwd(), "data")
os.makedirs(DATA_DIR, exist_ok=True)

# STABILITY: establish bank/ tree under DATA_DIR; no rename of existing data files elsewhere
BANK_DIR = os.path.join(DATA_DIR, "bank")
os.makedirs(BANK_DIR, exist_ok=True)

# STABILITY: file paths for the shared content bank
_QUESTIONS_FILE = os.path.join(BANK_DIR, "questions.jsonl")   # one JSON object per line
_FLASHCARDS_FILE = os.path.join(BANK_DIR, "flashcards.jsonl") # one JSON object per line
_WEIGHTS_FILE = os.path.join(BANK_DIR, "weights.json")        # {"Domain 1": 0.15, ...}

# -------------------------------------------------------------------------------------------------
# Atomic I/O helpers
# -------------------------------------------------------------------------------------------------

def _atomic_write_bytes(path: str, data: bytes) -> None:
    """Write bytes to a temp file then atomic replace to avoid partial writes."""
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

def _atomic_write_json(path: str, obj: Any) -> None:
    _atomic_write_text(path, json.dumps(obj, ensure_ascii=False, indent=2))

# STABILITY: keep shape and call-sites if an old _save_json exists; otherwise define it now.
if "_save_json" not in globals():
    def _save_json(path: str, obj: Any) -> None:
        # STABILITY: atomic write as required; preserves signature
        _atomic_write_json(path, obj)

# STABILITY: existing _load_json stays untouched if already defined; otherwise provide it.
if "_load_json" not in globals():
    def _load_json(path: str, default: Any) -> Any:
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError:
            return default
        except Exception as e:
            # Keep existing warnings style (if any) minimal
            try:
                app.logger.warning("Failed to load JSON %s: %s", path, e)
            except Exception:
                pass
            return default

# JSONL convenience
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
                # skip corrupted lines (do not break)
                continue
    return out

def _write_jsonl(path: str, rows: List[Dict[str, Any]]) -> None:
    # atomic write: construct full text then replace
    buf = io.StringIO()
    for r in rows:
        buf.write(json.dumps(r, ensure_ascii=False))
        buf.write("\n")
    _atomic_write_text(path, buf.getvalue())

# -------------------------------------------------------------------------------------------------
# Normalization, IDs, and de-dup
# -------------------------------------------------------------------------------------------------

def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"

def _norm_text(s: str) -> str:
    return " ".join(str(s).strip().lower().split())

def _q_signature(q: Dict[str, Any]) -> str:
    """
    A stable signature for de-dup across types.
    MC  : stem + sorted choices
    TF  : stem + 'true/false'
    SCN : stem + sorted options (if present)
    """
    t = q.get("type", "").lower()
    stem = _norm_text(q.get("stem", ""))
    if t == "mc":
        choices = [_norm_text(c) for c in q.get("choices", [])]
        choices.sort()
        base = stem + "||" + "|".join(choices)
    elif t in ("tf", "truefalse", "true_false"):
        base = stem + "||tf"
    else:  # scenario or custom
        opts = [_norm_text(c) for c in q.get("options", [])]
        opts.sort()
        base = stem + "||" + "|".join(opts)
    return hashlib.sha256(base.encode("utf-8")).hexdigest()

def _looks_like_dup(a: str, b: str, threshold: float = 0.92) -> bool:
    """Fuzzy near-duplicate check on normalized stems."""
    ra = _norm_text(a); rb = _norm_text(b)
    if not ra or not rb:
        return False
    return difflib.SequenceMatcher(a=ra, b=rb).ratio() >= threshold

# -------------------------------------------------------------------------------------------------
# Public read API
# -------------------------------------------------------------------------------------------------

def get_domain_weights() -> Dict[str, float]:
    """
    Returns a dict mapping domain -> weight (sums ≈ 1).
    If file absent, return a sane default CPP blueprint and write it.
    """
    default = {
        # STABILITY: safe defaults; admin can edit weights.json
        "Domain 1": 0.15,
        "Domain 2": 0.10,
        "Domain 3": 0.20,
        "Domain 4": 0.15,
        "Domain 5": 0.12,
        "Domain 6": 0.13,
        "Domain 7": 0.15,
    }
    data = _load_json(_WEIGHTS_FILE, None)
    if not data:
        _save_json(_WEIGHTS_FILE, default)
        return default
    # normalize
    try:
        total = float(sum(float(v) for v in data.values())) or 1.0
        return {k: float(v)/total for k, v in data.items()}
    except Exception:
        return default

def get_all_questions(domains: Optional[List[str]] = None,
                      types: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    rows = _read_jsonl(_QUESTIONS_FILE)
    if domains:
        dset = set([d.lower() for d in domains])
        rows = [r for r in rows if str(r.get("domain","")).lower() in dset]
    if types:
        tset = set([t.lower() for t in types])
        rows = [r for r in rows if str(r.get("type","")).lower() in tset]
    return rows

def get_all_flashcards(domains: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    rows = _read_jsonl(_FLASHCARDS_FILE)
    if domains:
        dset = set([d.lower() for d in domains])
        rows = [r for r in rows if str(r.get("domain","")).lower() in dset]
    return rows

# -------------------------------------------------------------------------------------------------
# Ingestion (admin or background)
# -------------------------------------------------------------------------------------------------

def ingest_questions(new_items: List[Dict[str, Any]], source: str = "upload") -> Tuple[int,int]:
    """
    Ingest question dicts. Each item should include:
      - type: "mc" | "tf" | "scenario"
      - domain: string (e.g., "Domain 3")
      - stem: question text
      - choices (mc): list[str]
      - answer (mc): int index in choices
      - answer (tf): bool
      - options/answers (scenario): options: list[str], answers: list[int] or list[str]
      - explanation (optional)
      - tags (optional list[str])
    Returns: (added_count, skipped_as_dupe)
    """
    existing = _read_jsonl(_QUESTIONS_FILE)
    seen_sigs = { _q_signature(q) for q in existing }
    existing_stems = [ _norm_text(q.get("stem","")) for q in existing ]

    added, skipped = 0, 0
    out = list(existing)

    now = int(time.time())
    for raw in new_items:
        q = dict(raw)  # shallow copy
        q.setdefault("id", _new_id("q"))
        q.setdefault("source", source)
        q.setdefault("created_at", now)

        # normalize type aliases
        t = str(q.get("type","")).lower().strip()
        if t in ("truefalse", "true_false"):
            t = "tf"
        elif t in ("multiplechoice", "multiple_choice"):
            t = "mc"
        elif t in ("scenario", "scn"):
            t = "scenario"
        q["type"] = t

        # minimal schema guard
        if not q.get("stem") or not q.get("domain") or t not in ("mc","tf","scenario"):
            skipped += 1
            continue

        sig = _q_signature(q)
        stem_norm = _norm_text(q.get("stem",""))

        if sig in seen_sigs:
            skipped += 1
            continue
        # fuzzy stem near-dup against existing stems
        if any(_looks_like_dup(stem_norm, s) for s in existing_stems):
            skipped += 1
            continue

        out.append(q)
        seen_sigs.add(sig)
        existing_stems.append(stem_norm)
        added += 1

    _write_jsonl(_QUESTIONS_FILE, out)
    try:
        app.logger.info("Bank ingest: questions added=%s skipped=%s total=%s", added, skipped, len(out))
    except Exception:
        pass
    return added, skipped

def ingest_flashcards(new_items: List[Dict[str, Any]], source: str = "upload") -> Tuple[int,int]:
    """
    Flashcard item fields:
      - domain: string
      - front: str
      - back: str
      - tags (optional)
    """
    existing = _read_jsonl(_FLASHCARDS_FILE)
    # simple hash on front/back
    def f_sig(fc: Dict[str, Any]) -> str:
        base = _norm_text(fc.get("front","")) + "||" + _norm_text(fc.get("back",""))
        return hashlib.sha256(base.encode("utf-8")).hexdigest()

    seen = { f_sig(x) for x in existing }
    existing_fronts = [ _norm_text(x.get("front","")) for x in existing ]

    added, skipped = 0, 0
    out = list(existing)
    now = int(time.time())

    for raw in new_items:
        fc = dict(raw)
        if not fc.get("front") or not fc.get("back") or not fc.get("domain"):
            skipped += 1
            continue
        fc.setdefault("id", _new_id("fc"))
        fc.setdefault("source", source)
        fc.setdefault("created_at", now)
        sig = f_sig(fc)
        if sig in seen:
            skipped += 1
            continue
        if any(_looks_like_dup(_norm_text(fc.get("front","")), s) for s in existing_fronts):
            skipped += 1
            continue
        out.append(fc)
        seen.add(sig)
        existing_fronts.append(_norm_text(fc.get("front","")))
        added += 1

    _write_jsonl(_FLASHCARDS_FILE, out)
    try:
        app.logger.info("Bank ingest: flashcards added=%s skipped=%s total=%s", added, skipped, len(out))
    except Exception:
        pass
    return added, skipped

# -------------------------------------------------------------------------------------------------
# Seed minimal content (safe no-op if files already exist)
# -------------------------------------------------------------------------------------------------

def ensure_bank_seeded() -> None:
    """Create default weights and a handful of sample items if bank is empty."""
    # weights
    if not os.path.exists(_WEIGHTS_FILE):
        _save_json(_WEIGHTS_FILE, get_domain_weights())  # writes defaults

    # questions
    if not os.path.exists(_QUESTIONS_FILE) or not _read_jsonl(_QUESTIONS_FILE):
        sample_qs = [
            {
                "type": "mc",
                "domain": "Domain 1",
                "stem": "Which control primarily reduces likelihood rather than impact?",
                "choices": ["Deterrent", "Corrective", "Compensating", "Recovery"],
                "answer": 0,
                "explanation": "Deterrent controls aim to discourage an action.",
                "tags": ["controls", "risk"]
            },
            {
                "type": "tf",
                "domain": "Domain 3",
                "stem": "Chain of custody must document every transfer of evidence.",
                "answer": True,
                "explanation": "Accuracy and integrity rely on continuous documentation.",
                "tags": ["investigations"]
            },
            {
                "type": "scenario",
                "domain": "Domain 6",
                "stem": "You inherit a legacy access control system with shared admin logins. Pick all best-first remediation steps.",
                "options": [
                    "Enforce unique accounts with MFA",
                    "Rotate all shared credentials",
                    "Disable audit logging to reduce storage",
                    "Implement least privilege for admins"
                ],
                "answers": [0,1,3],
                "explanation": "Unique identities, rotation, and least privilege are foundational."
            }
        ]
        ingest_questions(sample_qs, source="seed")

    # flashcards
    if not os.path.exists(_FLASHCARDS_FILE) or not _read_jsonl(_FLASHCARDS_FILE):
        sample_fc = [
            {"domain": "Domain 2", "front": "Risk = ?", "back": "Threat × Vulnerability × Impact"},
            {"domain": "Domain 4", "front": "Business Impact Analysis (BIA)", "back": "Assesses critical processes and impacts of disruption."},
        ]
        ingest_flashcards(sample_fc, source="seed")

# Ensure seed once at import
try:
    ensure_bank_seeded()
except Exception as _e:
    try:
        app.logger.warning("ensure_bank_seeded warning: %s", _e)
    except Exception:
        pass

### END OF SECTION 6/8 — CONTENT BANK & DATA MODEL (NEW)

### START OF SECTION 7/8 — SELECTION ENGINE FOR QUIZ/MOCK (NEW)

import math
from typing import List, Dict, Any, Optional, Tuple

# Domain weights (CPP blueprint) come from Section 6/8
# Questions loaded via get_all_questions()

_DEFAULT_TYPE_MIX = {
    "mc": 0.50,        # ~50% Multiple Choice
    "tf": 0.25,        # ~25% True/False
    "scenario": 0.25,  # ~25% Scenario
}

def _canonical_type(t: str) -> str:
    t = (t or "").lower().strip()
    if t in ("multiplechoice","multiple_choice"): return "mc"
    if t in ("truefalse","true_false"): return "tf"
    if t in ("scn",): return "scenario"
    return t

def _rng_for_user_context(user_id: Optional[str]) -> random.Random:
    """
    Deterministic-ish RNG per user/day to give varied but stable sets.
    Falls back to time if user id not available.
    """
    try:
        day = int(time.time() // 86400)
        seed_str = f"{user_id or 'anon'}::{day}"
        seed = int(hashlib.sha256(seed_str.encode("utf-8")).hexdigest(), 16) % (2**31)
        return random.Random(seed)
    except Exception:
        return random.Random()

def _weighted_domain_allocation(domains: List[str], weights: Dict[str, float], total: int) -> Dict[str, int]:
    """
    Allocate total questions across selected domains according to weights.
    Rounds fairly then fixes rounding drift.
    """
    if not domains:
        return {}
    # normalize a local weight map restricted to selected domains
    local = {d: float(weights.get(d, 0.0)) for d in domains}
    if sum(local.values()) <= 0:
        # equal split if no weights known
        eq = max(1, total // max(1, len(domains)))
        alloc = {d: eq for d in domains}
        # fix remainder
        rem = total - sum(alloc.values())
        for d in domains[:rem]:
            alloc[d] += 1
        return alloc
    # proportional, then round
    raw = {d: (weights.get(d, 0.0)) for d in domains}
    s = sum(raw.values()) or 1.0
    target = {d: (raw[d]/s)*total for d in domains}
    alloc = {d: int(math.floor(target[d])) for d in domains}
    rem = total - sum(alloc.values())
    # give remainder to largest fractional parts
    fr = sorted(domains, key=lambda d: target[d]-alloc[d], reverse=True)
    for d in fr[:rem]:
        alloc[d] += 1
    return alloc

def _split_type_mix(n: int, mix: Dict[str, float]) -> Dict[str, int]:
    mix = { _canonical_type(k): float(v) for k, v in mix.items() }
    # initial floor
    alloc = {k: int(math.floor(n * mix.get(k, 0.0))) for k in mix}
    rem = n - sum(alloc.values())
    # top up by largest residuals
    residuals = sorted(mix.keys(), key=lambda k: (n*mix[k]) - alloc[k], reverse=True)
    for k in residuals[:rem]:
        alloc[k] += 1
    # ensure only known keys
    out = {"mc": alloc.get("mc",0), "tf": alloc.get("tf",0), "scenario": alloc.get("scenario",0)}
    # fix drift if any
    delta = n - sum(out.values())
    for k in ("mc","tf","scenario"):
        if delta == 0: break
        out[k] += 1
        delta -= 1
    return out

def _filter_by_type(rows: List[Dict[str, Any]], t: str) -> List[Dict[str, Any]]:
    t = _canonical_type(t)
    return [r for r in rows if _canonical_type(r.get("type","")) == t]

def select_questions(domains: List[str],
                     count: int,
                     mix: Optional[Dict[str, float]] = None,
                     user_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Core selector used by Quiz/Mock.
    - domains: selected domain labels (must match what's in bank/weights)
    - count  : total questions to return (your UI picker still controls this)
    - mix    : optional override of type mix; defaults to 50/25/25 (MC/TF/Scenario)
    - user_id: optional for stable randomness day-to-day per user

    Returns a list of question dicts from the bank.
    """
    mix = mix or dict(_DEFAULT_TYPE_MIX)
    weights = get_domain_weights()
    rng = _rng_for_user_context(user_id)

    # domain allocation
    domains = list(domains or [])
    if not domains:
        # if nothing chosen, include all from weights file (keeps historical behavior)
        domains = list(weights.keys())

    per_domain = _weighted_domain_allocation(domains, weights, count)
    inventory_by_domain = {d: get_all_questions(domains=[d]) for d in domains}

    selected: List[Dict[str, Any]] = []

    for d, n_d in per_domain.items():
        if n_d <= 0:
            continue
        pool = inventory_by_domain.get(d, [])
        if not pool:
            continue
        # type split inside this domain
        t_alloc = _split_type_mix(n_d, mix)

        for t, need in t_alloc.items():
            if need <= 0: 
                continue
            sub = _filter_by_type(pool, t)
            if len(sub) <= need:
                # take all if not enough; we’ll backfill later if needed
                selected.extend(sub)
            else:
                selected.extend(rng.sample(sub, need))

    # Backfill if we fell short due to inventory constraints (keep domain pref then any)
    short = count - len(selected)
    if short > 0:
        # prefer remaining in selected domains first
        remaining = [q for d in domains for q in inventory_by_domain.get(d, []) if q not in selected]
        if len(remaining) >= short:
            selected.extend(rng.sample(remaining, short))
        else:
            selected.extend(remaining)
            # as a last resort, pull any domain
            all_pool = get_all_questions()
            extra = [q for q in all_pool if q not in selected]
            extra_need = count - len(selected)
            if extra_need > 0 and len(extra) > 0:
                take = min(extra_need, len(extra))
                selected.extend(rng.sample(extra, take))

    # Truncate if we somehow exceeded (shouldn’t), but guard anyway.
    if len(selected) > count:
        selected = selected[:count]

    return selected

# Optional helper to adapt bank questions into a generic UI-friendly shape
def to_ui_question(q: Dict[str, Any]) -> Dict[str, Any]:
    """
    Non-destructive adapter. Use only if you need a consistent shape:
      {
        "id": ..., "domain": ..., "type": "mc|tf|scenario",
        "stem": "...",
        "choices": [...],          # for "mc"
        "answer": 0,               # index for "mc"; bool for "tf"; list[int] for "scenario"
        "options": [...],          # for "scenario" only
        "explanation": "..."
      }
    """
    t = _canonical_type(q.get("type",""))
    out = {
        "id": q.get("id"),
        "domain": q.get("domain"),
        "type": t,
        "stem": q.get("stem"),
        "explanation": q.get("explanation"),
    }
    if t == "mc":
        out["choices"] = q.get("choices", [])
        out["answer"]  = q.get("answer", 0)
    elif t == "tf":
        out["answer"]  = bool(q.get("answer"))
    else:  # scenario
        out["options"] = q.get("options", [])
        out["answers"] = q.get("answers", [])
    return out

### END OF SECTION 7/8 — SELECTION ENGINE FOR QUIZ/MOCK (NEW)

### START OF SECTION 8/8 — WELCOME GATE (UPDATED WITH TERMS LINK + FOOTER)

# Replace your current Section 8/8 completely with this block.
# It keeps the same behavior (redirect gating, login/agree flow),
# and now links to /terms and uses the footer helper.

from urllib.parse import urlparse, urljoin
from flask import request, session, redirect, abort

# Safe-next guard (define if missing)
if "_safe_next" not in globals():
    def _safe_next(nxt: str, fallback: str = "/") -> str:
        try:
            if not nxt:
                return fallback
            host_url = request.host_url
            test_url = urljoin(host_url, nxt)
            host = urlparse(host_url).netloc
            test = urlparse(test_url).netloc
            return nxt if host == test else fallback
        except Exception:
            return fallback

# Helper: has agreed?
def _has_agreed() -> bool:
    try:
        return bool(session.get("agreed_terms"))
    except Exception:
        return False

# GET /welcome — shown to everyone arriving unauthenticated or not-yet-agreed
@app.get("/welcome")
def sec8_welcome():
    nxt = _safe_next(request.args.get("next") or "/")
    # Build page
    content = """
    <div class="container" style="max-width: 960px;">
      <div class="row my-4">
        <div class="col-12 col-lg-8">
          <div class="card shadow-sm mb-3">
            <div class="card-body">
              <h3 class="mb-2">Welcome to CPP_Test_Prep</h3>
              <p class="text-muted mb-3">
                This independent study platform helps you prepare for the ASIS CPP exam with an AI Tutor, Flashcards, Quizzes, and Mock Exams.
                <strong>CPP_Test_Prep is not affiliated with ASIS International.</strong>
              </p>
              <ol class="mb-3">
                <li>Read our <a href="/terms" target="_self">Terms &amp; Conditions</a> and Legal Disclaimer.</li>
                <li>Create an account or sign in.</li>
                <li>Check the box below to accept the Terms &amp; Conditions.</li>
                <li>Start learning — Tutor is front and center; Flashcards, Quiz, and Mock Exam are a click away.</li>
              </ol>

              <form method="post" action="/welcome/accept" class="mt-3">
                <input type="hidden" name="next" value="{nxt}">
                <div class="form-check mb-3">
                  <input class="form-check-input" type="checkbox" value="on" id="agree" name="agree" required>
                  <label class="form-check-label" for="agree">
                    I have read and agree to the <a href="/terms" target="_self">Terms &amp; Conditions</a>.
                  </label>
                </div>

                <div class="d-flex gap-2">
                  <a class="btn btn-outline-primary" href="/login?next={nxt}">Sign in</a>
                  <a class="btn btn-primary" href="/register?next={nxt}">Create account</a>
                  <button type="submit" class="btn btn-success">Continue</button>
                </div>
              </form>
            </div>
          </div>

          <div class="alert alert-warning mb-4">
            <strong>Important:</strong> We do not use proprietary or member-only ASIS materials. Our content is original or based on lawful open sources for educational use only.
          </div>
        </div>

        <div class="col-12 col-lg-4">
          <div class="card shadow-sm">
            <div class="card-body">
              <h5 class="mb-2">Quick tips</h5>
              <ul class="mb-0">
                <li>Use Tutor to ask “why” and “how” questions.</li>
                <li>Filter Flashcards/Quiz/Mock by domain using the buttons.</li>
                <li>Choose any number of questions; your preference is preserved.</li>
                <li>Progress updates save automatically.</li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </div>
    """.replace("{nxt}", html.escape(nxt, quote=True))

    return base_layout("Welcome", _with_footer(content))

# POST /welcome/accept — records acceptance and sends user onward
@app.post("/welcome/accept")
def sec8_welcome_accept():
    if not _csrf_ok():
        abort(403)
    nxt = _safe_next(request.form.get("next") or "/")
    agreed = request.form.get("agree") == "on"
    if not agreed:
        # Must check the box
        return redirect(url_for("sec8_welcome", next=nxt), code=302)

    # Persist acceptance in session and (optionally) in users.json
    session["agreed_terms"] = True
    try:
        if "_user_id" in globals() and _user_id():
            # optional: write the acceptance to users.json if your user store exists
            if "users_store_set_agreed" in globals():
                users_store_set_agreed(_user_id(), True)
    except Exception:
        pass

    # If not logged in, keep them on Welcome with the sign-in prompt
    try:
        if "current_user" in globals() and current_user and getattr(current_user, "is_authenticated", False):
            return redirect(nxt, code=302)
    except Exception:
        # If you don't use flask-login's current_user, just continue
        pass

    return redirect(url_for("sec8_welcome", next=nxt), code=302)

# Root redirect: always gate new visitors through /welcome until both
#   (a) logged in (if your app requires auth), AND
#   (b) agreed to the Terms.
@app.get("/")
def root_redirect():
    # If you have public pages, adjust this logic; default is to gate to /welcome.
    nxt = _safe_next(request.args.get("next") or "/tutor")
    # If already agreed (and optionally logged in), send to Tutor (or intended)
    if _has_agreed():
        return redirect(nxt, code=302)
    return redirect(url_for("sec8_welcome", next=nxt), code=302)

### END OF SECTION 8/8 — WELCOME GATE (UPDATED WITH TERMS LINK + FOOTER)










