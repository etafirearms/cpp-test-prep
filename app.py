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

# ======================================================================
# === SECTION 6/8: DATA BANK & CPP WEIGHTS — START =====================
# ======================================================================
# Purpose:
#   - Define the on-disk question bank (DATA_DIR/bank/*).
#   - Provide helpers to read items, dedupe them, and select questions.
#   - Enforce CPP domain weights and per-type quotas:
#       * Multiple Choice: 50%
#       * True/False:      25%
#       * Scenario:        25%
# Notes:
#   - No UI or route changes here. We will wire these helpers in Section 7/8.
#   - Safe to import even if bank is empty (graceful fallbacks).
#   - Avoids NameError if DOMAINS isn't defined yet.
# ======================================================================

import os, json, time, uuid, random, hashlib, re
from typing import Dict, List, Optional, Tuple, Any

# --- Bank filesystem layout ---------------------------------------------------
#  DATA_DIR/
#    bank/
#      mcq/        # *.json (one item per file)
#      tf/         # *.json (one item per file)
#      scenario/   # *.json (one item per file)
#      weights.json     # admin-managed (optional); overrides defaults

# DATA_DIR comes from Section 1/8 (env & config). Fallback to cwd/data if needed.
try:
    DATA_DIR  # type: ignore[name-defined]
except NameError:
    DATA_DIR = os.path.join(os.getcwd(), "data")
os.makedirs(DATA_DIR, exist_ok=True)

BANK_DIR = os.path.join(DATA_DIR, "bank")
for _sub in ("mcq", "tf", "scenario"):
    os.makedirs(os.path.join(BANK_DIR, _sub), exist_ok=True)

_WEIGHTS_FILE = os.path.join(BANK_DIR, "weights.json")

# --- Utility: safe json load/save --------------------------------------------
def _read_json_file(path: str) -> Optional[dict]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

def _atomic_write_json(path: str, payload: dict) -> None:
    """Atomic save compatible with Section 2/8's _save_json approach."""
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)

# --- Domain helpers -----------------------------------------------------------
def _domain_keys() -> List[str]:
    """Use your global DOMAINS mapping if present; else infer from items; fallback to Mixed."""
    if "DOMAINS" in globals() and isinstance(globals()["DOMAINS"], dict) and globals()["DOMAINS"]:
        return list(globals()["DOMAINS"].keys())
    # If DOMAINS not yet defined, provide a stable fallback:
    return ["domain1", "domain2", "domain3", "domain4", "domain5", "domain6", "domain7"]

# --- Default CPP domain weights (adjust as needed) ---------------------------
# These are *relative* weights (we'll normalize). If you already defined a
# better mapping elsewhere, you can override via bank/weights.json.
_DEFAULT_DOMAIN_WEIGHTS: Dict[str, float] = {
    # Keys must match your DOMAINS keys (e.g., "domain1", ...), not labels.
    # Replace these with your actual distribution if known; otherwise they
    # will be normalized over present keys.
}

def _load_weights() -> Dict[str, float]:
    """Load weights.json if present; otherwise use defaults stretched over known domain keys."""
    # Start with defaults over the known keys:
    keys = _domain_keys()
    base = dict(_DEFAULT_DOMAIN_WEIGHTS)
    # If defaults are empty or incomplete, fill evenly:
    if not base or any(k not in base for k in keys):
        even = 1.0 / max(1, len(keys))
        base = {k: base.get(k, even) for k in keys}

    # Merge with file overrides if present:
    file_data = _read_json_file(_WEIGHTS_FILE) or {}
    if isinstance(file_data, dict):
        for k, v in file_data.items():
            try:
                if isinstance(v, (int, float)) and k in keys:
                    base[k] = float(v)
            except Exception:
                pass

    # Normalize to sum == 1.0
    total = sum(max(0.0, x) for x in base.values())
    if total <= 0:
        even = 1.0 / max(1, len(keys))
        return {k: even for k in keys}
    return {k: max(0.0, base.get(k, 0.0)) / total for k in keys}

_DOMAIN_WEIGHTS = _load_weights()

# --- Type quotas (fixed) ------------------------------------------------------
# Enforced per selection batch: 50% MCQ, 25% T/F, 25% Scenario.
_TYPE_QUOTAS = {
    "mcq": 0.50,
    "tf": 0.25,
    "scenario": 0.25,
}

# --- Item model ---------------------------------------------------------------
# Canonical item structure expected in each *.json file:
# {
#   "id": "uuid",
#   "type": "mcq" | "tf" | "scenario",
#   "domain": "domain1" | "...",     # DOMAINS key
#   "question": "text",
#   "options": ["A", "B", "C", "D"], # for mcq; optional otherwise
#   "answer": "A" | true/false | ["multi"] | {"explain": "..."},
#   "explanation": "text (optional)",
#   "source": "string (optional)",
#   "created_at": 1712345678.123
# }

def _norm_text(s: str) -> str:
    s = s or ""
    s = re.sub(r"\s+", " ", s, flags=re.MULTILINE).strip().lower()
    return s

def _dedupe_key(item: dict) -> str:
    """Stable fingerprint to prevent duplicates (question + domain + type + answer core)."""
    q = _norm_text(str(item.get("question", "")))
    t = str(item.get("type", ""))
    d = str(item.get("domain", ""))
    a = item.get("answer", "")
    a_core = json.dumps(a, sort_keys=True, ensure_ascii=False)
    to_hash = f"{t}::{d}::{q}::{a_core}"
    return hashlib.sha256(to_hash.encode("utf-8")).hexdigest()

def _item_ok(item: Optional[dict]) -> bool:
    if not isinstance(item, dict):
        return False
    if item.get("type") not in ("mcq", "tf", "scenario"):
        return False
    if not item.get("question"):
        return False
    if not item.get("domain"):
        return False
    return True

# --- Scan bank ---------------------------------------------------------------
def _scan_dir(kind: str) -> List[dict]:
    out: List[dict] = []
    folder = os.path.join(BANK_DIR, kind)
    try:
        for name in os.listdir(folder):
            if not name.endswith(".json"):
                continue
            data = _read_json_file(os.path.join(folder, name))
            if _item_ok(data):
                out.append(data)  # trust file IDs
    except Exception:
        pass
    return out

def bank_index() -> Dict[str, List[dict]]:
    """Return {'mcq': [...], 'tf': [...], 'scenario': [...]}"""
    return {
        "mcq": _scan_dir("mcq"),
        "tf": _scan_dir("tf"),
        "scenario": _scan_dir("scenario"),
    }

# In-memory dedupe index (by fingerprint)
_DEDUPE: set = set()
def _refresh_dedupe() -> None:
    _DEDUPE.clear()
    idx = bank_index()
    for kind, items in idx.items():
        for it in items:
            _DEDUPE.add(_dedupe_key(it))

_refresh_dedupe()

# --- Add items (admin will use in Section 7/8) -------------------------------
def add_bank_items(new_items: List[dict]) -> Tuple[int, int]:
    """
    Add items to the bank with dedupe.
    Returns: (added_count, skipped_count)
    """
    added = 0
    skipped = 0
    now = time.time()

    for item in new_items:
        if not _item_ok(item):
            skipped += 1
            continue
        fp = _dedupe_key(item)
        if fp in _DEDUPE:
            skipped += 1
            continue

        # Assign ID if missing
        item.setdefault("id", str(uuid.uuid4()))
        item.setdefault("created_at", now)

        kind = item["type"]
        out_path = os.path.join(BANK_DIR, kind, f"{item['id']}.json")
        try:
            _atomic_write_json(out_path, item)
            _DEDUPE.add(fp)
            added += 1
        except Exception:
            skipped += 1

    return added, skipped

# --- Selection helpers (weights + quotas) ------------------------------------
def _weighted_domain(dom: str) -> float:
    return float(_DOMAIN_WEIGHTS.get(dom, 0.0))

def _filter_by_domain(items: List[dict], domain: Optional[str]) -> List[dict]:
    if not domain or domain == "random":
        return items[:]  # no filter
    return [x for x in items if x.get("domain") == domain]

def _quota_counts(total: int) -> Dict[str, int]:
    """Compute per-type counts from quotas; ensure sum == total."""
    raw = {k: int(total * v) for k, v in _TYPE_QUOTAS.items()}
    # fix rounding drift
    used = sum(raw.values())
    while used < total:
        # assign the remainder to the largest quota type first
        k = max(_TYPE_QUOTAS, key=_TYPE_QUOTAS.get)
        raw[k] += 1
        used += 1
    while used > total:
        k = min(_TYPE_QUOTAS, key=_TYPE_QUOTAS.get)
        if raw[k] > 0:
            raw[k] -= 1
            used -= 1
        else:
            break
    return raw

def _weighted_sample(items: List[dict], count: int) -> List[dict]:
    """Domain-weighted sampling without replacement."""
    if count <= 0 or not items:
        return []

    # Group by domain
    by_dom: Dict[str, List[dict]] = {}
    for it in items:
        by_dom.setdefault(it.get("domain", ""), []).append(it)

    # Allocate per domain by weight
    # Normalize to available pool sizes to avoid over-ask
    available = {d: len(v) for d, v in by_dom.items()}
    weights = {d: _weighted_domain(d) for d in by_dom}
    wsum = sum(weights.values()) or 1.0
    # Initial allocation
    alloc = {d: int(round(count * (weights[d] / wsum))) for d in by_dom}

    # Adjust for pool limits
    deficit = 0
    for d in list(alloc.keys()):
        if alloc[d] > available[d]:
            deficit += alloc[d] - available[d]
            alloc[d] = available[d]

    # Distribute remaining to domains with spare items
    if deficit > 0:
        spares = {d: available[d] - alloc[d] for d in by_dom}
        while deficit > 0:
            # Pick domain with biggest spare and non-zero weight
            pick = None
            best = -1
            for d, s in spares.items():
                if s > best and weights.get(d, 0.0) > 0:
                    best = s
                    pick = d
            if not pick or best <= 0:
                break
            alloc[pick] += 1
            spares[pick] -= 1
            deficit -= 1

    # Final pick
    chosen: List[dict] = []
    for d, n in alloc.items():
        pool = by_dom[d][:]
        random.shuffle(pool)
        chosen.extend(pool[:max(0, n)])

    # Trim or pad if still off due to rounding
    if len(chosen) > count:
        chosen = chosen[:count]
    elif len(chosen) < count:
        # Fill with any remaining (uniform)
        remaining = [it for d, arr in by_dom.items() for it in arr if it not in chosen]
        random.shuffle(remaining)
        need = count - len(chosen)
        chosen.extend(remaining[:need])

    return chosen

def choose_questions(
    total: int,
    domain: Optional[str] = None,
    *,
    allow_fallback: bool = True
) -> List[dict]:
    """
    Return a list of questions from the bank honoring:
      - domain weights (or a single domain filter if provided),
      - per-type quotas (MCQ 50%, TF 25%, Scenario 25%).
    If the bank lacks enough items and allow_fallback=True,
    returns as many as possible (possibly less than `total`).
    """
    total = max(1, int(total))
    quotas = _quota_counts(total)
    idx = bank_index()

    selected: List[dict] = []
    for kind, n in quotas.items():
        pool = _filter_by_domain(idx.get(kind, []), domain)
        if not pool:
            continue
        picks = _weighted_sample(pool, n)
        selected.extend(picks)

    # If we are short (bank too small), optionally fill with anything left.
    short = total - len(selected)
    if short > 0 and allow_fallback:
        rest = []
        for kind, items in idx.items():
            rest.extend(_filter_by_domain(items, domain))
        # remove already chosen (by id)
        seen = {it.get("id") for it in selected}
        rest = [it for it in rest if it.get("id") not in seen]
        random.shuffle(rest)
        selected.extend(rest[:short])

    # Final trim if somehow exceeded (shouldn’t)
    return selected[:total]

# ======================================================================
# === SECTION 6/8: DATA BANK & CPP WEIGHTS — END =======================
# ======================================================================

# ======================================================================
# === SECTION 7/8: BANK ADAPTERS FOR TUTOR / FLASHCARDS / QUIZ / MOCK ==
# ======================================================================
# Purpose:
#   Read questions from the Section 6/8 Bank and expose safe, uniform
#   adapters that higher-level routes can call WITHOUT changing any UI.
#
# What this DOES:
#   - Gives you three helpers you can call from your existing routes
#     to pull items from the Bank while honoring domain-weights and
#     the 50% MCQ / 25% TF / 25% Scenario mix:
#         * bank_get_flashcards(domain, total)
#         * bank_get_quiz_questions(domain, total)
#         * bank_get_mock_questions(domain, total)
#   - Normalizes Bank items into a stable, conservative shape that
#     existing templates can render as plain text safely.
#   - Never replaces your legacy generators: you can “try Bank first,
#     then fall back” in the route (we’ll wire this in next section).
#
# What this DOES NOT do (yet):
#   - It does not change your routes. It’s a drop-in library.
#   - It does not alter any templates or UI.
#
# Safe defaults:
#   - If the bank is empty, these return [] (so your current code can
#     fall back to legacy behavior unchanged).
#
# Call pattern you’ll use NEXT (Section 8/8, tiny route edits):
#   items = bank_get_quiz_questions(domain, total)
#   if not items:
#       items = legacy_make_quiz_questions(domain, total)  # your current path
#
# ======================================================================

from typing import List, Dict, Any, Optional
import random
import html

# --- Import selectors from Section 6/8 (already loaded in app.py) ------------
# choose_questions(total, domain, allow_fallback=True)
if "choose_questions" not in globals():
    # Defensive fallback: if Section 6/8 wasn’t included for some reason,
    # provide a stub that behaves like an empty bank.
    def choose_questions(total: int, domain: Optional[str] = None, *, allow_fallback: bool = True) -> List[dict]:
        return []

# --- Normalization to a conservative shape ------------------------------------
# This “normalized” question is intentionally simple so it won’t break any
# existing rendering. Your routes can read these keys safely:
#   {
#     "id": str,
#     "type": "mcq"|"tf"|"scenario",
#     "domain": str,
#     "question": str,          # plain text (HTML-escaped)
#     "choices": List[str],     # [] for non-MCQ; ["True","False"] for TF
#     "answer": Any,            # keep original; routes may ignore if not needed
#     "explanation": str|None,  # plain text (HTML-escaped)
#     "source": str|None        # where it came from (optional)
#   }

def _to_norm(item: Dict[str, Any]) -> Dict[str, Any]:
    q = html.escape(str(item.get("question", "")).strip())
    typ = item.get("type", "")
    domain = item.get("domain", "")
    explanation = item.get("explanation")
    if isinstance(explanation, str):
        explanation = html.escape(explanation.strip())

    choices: List[str] = []
    if typ == "mcq":
        raw = item.get("options") or []
        # Make sure everything is string & escaped
        choices = [html.escape(str(x)) for x in raw if str(x).strip() != ""]
    elif typ == "tf":
        # Standardize the two choices for UI consistency
        choices = ["True", "False"]
    else:
        # scenario or anything else => no fixed choices, UI shows the stem
        choices = []

    return {
        "id": str(item.get("id", "")),
        "type": typ,
        "domain": domain,
        "question": q,
        "choices": choices,
        "answer": item.get("answer"),
        "explanation": explanation if explanation else None,
        "source": item.get("source"),
    }

def _norm_many(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for it in items:
        try:
            out.append(_to_norm(it))
        except Exception:
            # Skip malformed
            continue
    return out

# --- Public adapters -----------------------------------------------------------
# You can call these from routes. They DO NOT throw if bank is empty.

def bank_get_flashcards(domain: Optional[str], total: int) -> List[Dict[str, Any]]:
    """
    Pulls a mixed set for flashcards (domain-weighted, mixed types).
    Rely on your flashcard UI to show question + (optional) explanation.
    """
    total = max(1, int(total))
    raw = choose_questions(total, domain=domain, allow_fallback=True)
    random.shuffle(raw)
    return _norm_many(raw)

def bank_get_quiz_questions(domain: Optional[str], total: int) -> List[Dict[str, Any]]:
    """
    Returns normalized items suitable for a quick quiz. The 50/25/25
    type-quota is enforced by choose_questions().
    """
    total = max(1, int(total))
    raw = choose_questions(total, domain=domain, allow_fallback=True)
    random.shuffle(raw)
    return _norm_many(raw)

def bank_get_mock_questions(domain: Optional[str], total: int) -> List[Dict[str, Any]]:
    """
    Returns normalized items for mock exams. Same quotas/weights as quiz.
    """
    total = max(1, int(total))
    raw = choose_questions(total, domain=domain, allow_fallback=True)
    random.shuffle(raw)
    return _norm_many(raw)

# --- Tiny helper for route bridges (used next section) ------------------------
def bank_first_then_legacy(
    supplier,            # callable(domain:str|None, total:int)->List[dict]
    legacy_builder,      # your existing function: (domain,total)->List[dict]
    domain: Optional[str],
    total: int
) -> List[Dict[str, Any]]:
    """
    Try bank supplier first (returns normalized items).
    If empty, falls back to your legacy generator unchanged.
    """
    bank_items = supplier(domain, total)
    if bank_items:
        return bank_items
    try:
        # Legacy path is unknown shape; hand it back directly for your
        # existing renderer. Callers must branch on shape if needed.
        return legacy_builder(domain, total)  # type: ignore[misc]
    except Exception:
        return []

# ======================================================================
# === SECTION 7/8: BANK ADAPTERS — END =================================
# ======================================================================

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







