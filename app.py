# STABILITY: Ensure source is parsed as UTF-8 everywhere (avoids invalid char errors on Render)
# -*- coding: utf-8 -*-

# =========================
# SECTION 1/8: Imports, App Config, Utilities, Security, Base Layout (+ Footer, Home, Terms)
# =========================

import os, re, json, time, uuid, hashlib, random, html, logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Tuple
from urllib.parse import quote as _urlquote

from flask import (
    Flask, request, session, redirect, url_for, abort, jsonify, make_response, g  # STABILITY: added g for request timing
)
from flask import render_template_string
from werkzeug.security import generate_password_hash, check_password_hash
# STABILITY: respect proxies (Render) for correct scheme/host handling
from werkzeug.middleware.proxy_fix import ProxyFix

# ---- App & Logging ----
APP_VERSION = "1.0.0"
IS_STAGING = (os.environ.get("STAGING", "0") == "1")
DEBUG = (os.environ.get("DEBUG", "0") == "1")

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")

logger = logging.getLogger("cpp_prep")
handler = logging.StreamHandler()
fmt = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
handler.setFormatter(fmt)
logger.setLevel(logging.INFO)
logger.addHandler(handler)

# STABILITY: env helpers & hardened config -------------------------------
def _env_bool(name: str, default: bool = False) -> bool:
    """Treat '1', 'true', 'yes' (case-insensitive) as truthy."""
    val = os.environ.get(name, None)
    if val is None:
        return default
    return str(val).strip().lower() in ("1", "true", "yes")

# STABILITY: honor DATA_DIR and Data_Dir with safe fallback
DATA_DIR = (
    os.environ.get("DATA_DIR")
    or os.environ.get("Data_Dir")
    or os.path.join(os.getcwd(), "data")
)
os.makedirs(DATA_DIR, exist_ok=True)

# STABILITY: production secret guard (fail fast)
if _env_bool("SESSION_COOKIE_SECURE", True) or not DEBUG:
    if app.secret_key == "dev-secret-change-me":
        raise RuntimeError("SECRET_KEY must be set to a non-default value in production.")

# STABILITY: trust reverse proxy headers on Render (for https scheme, host, etc.)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

# STABILITY: session & CSRF cookies
app.config.update(
    SESSION_COOKIE_SECURE=_env_bool("SESSION_COOKIE_SECURE", True),
    SESSION_COOKIE_SAMESITE="Lax",
    WTF_CSRF_TIME_LIMIT=None,
)
# -----------------------------------------------------------------------

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

# STABILITY: request timing/logger (minimal & quiet for static)
@app.before_request
def _stability_req_start():
    g._req_start = time.time()

@app.after_request
def _stability_req_log(resp):
    try:
        path = request.path or ""
        # avoid log spam for trivial assets if any are served later
        if not path.startswith("/static/"):
            dur_ms = (time.time() - getattr(g, "_req_start", time.time())) * 1000.0
            rid = request.headers.get("X-Request-ID") or request.headers.get("X-Request-Id") or ""
            extra = f" rid={rid}" if rid else ""
            logger.info("REQ %s %s -> %s in %.1fms%s", request.method, path, resp.status_code, dur_ms, extra)
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

# STABILITY: atomic JSON writes to prevent partial/corrupt files
def _save_json(name: str, data):
    p = _path(name)
    try:
        os.makedirs(os.path.dirname(p), exist_ok=True)
        tmp = p + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, p)
    except Exception as e:
        logger.warning("save_json %s failed: %s", name, e)

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
    return """
    <footer class="mt-5 py-3 border-top text-center small text-muted">
      <div>
        Educational use only. Not affiliated with ASIS. No legal, safety, or professional advice.
        Use official sources to verify. No refunds. © CPP-Exam-Prep
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
            ("tutor_settings.json", {"web_aware": os.environ.get("TUTOR_WEB_AWARE", "0") == "1"}),
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
# FIX: To preserve one-owner rule (Section 8 owns / and /legal/terms),
# we disable any duplicates here.
if False:
    @app.get("/", endpoint="sec1_home_page")
    def sec1_home_page():
        return base_layout("Home", "<div class='container'>Section 1 Home (disabled)</div>")

    @app.get("/legal/terms", endpoint="sec1_legal_terms")
    def sec1_legal_terms():
        return base_layout("Terms", "<div class='container'>Section 1 Terms (disabled)</div>")

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

import time, os  # STABILITY: added os for DATA_DIR checks
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

    # STABILITY: include simple DATA_DIR existence/writability checks
    data_dir = _sec2_safe_get("DATA_DIR", ".")
    dir_exists = os.path.isdir(data_dir)
    dir_writable = False
    if dir_exists:
        try:
            probe = os.path.join(data_dir, ".healthz_probe")
            with open(probe, "w", encoding="utf-8") as f:
                f.write("ok")
                f.flush()
                os.fsync(f.fileno())
            os.remove(probe)
            dir_writable = True
        except Exception:
            dir_writable = False

    return jsonify({
        "ok": True,
        "service": "cpp-exam-prep",
        "version": str(app_version),           # STABILITY: added
        "app_version": str(app_version),       # STABILITY: explicit key for clarity
        "debug": debug_mode,
        "staging": is_staging,
        "data_dir_exists": dir_exists,         # STABILITY: added
        "data_dir_writable": dir_writable,     # STABILITY: added
        "started_at": datetime.fromtimestamp(_SEC2_START_TS, tz=timezone.utc).isoformat(),
        "uptime_seconds": uptime_s,
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
# SECTION 3/8 — Legacy Quiz & Mock (picker, run, scoring)
# STATUS: DISABLED BY DEFAULT to prevent route duplication with Section 4
# PURPOSE: Keep prior implementation available behind a guard for forensic diff/testing.
# NOTE: Mounted under /legacy/* to avoid collisions with Section 4.
# =========================

# Turn ON only if you explicitly want to compare the legacy engine.
# Safe: when OFF, nothing is registered and nothing executes.
SEC3_REGISTER_ROUTES = (os.environ.get("ENABLE_LEGACY_QUIZ", "0") == "1")

# ---- Local helpers (legacy names, 'sec3_' prefix to avoid global clashes) ----

def sec3_detect_qtype(q: dict) -> str:
    """
    Infer simple type:
      - 'tf' for two-option true/false-like
      - 'scenario' if question starts with 'Scenario:' or has scenario cue
      - 'mcq' otherwise
    """
    try:
        stem = (q.get("question") or "").strip()
        opts = q.get("options") or {}
        # T/F if exactly two non-empty options and they resemble True/False
        opt_texts = [str(opts.get(k, "")).strip().lower()
                     for k in ["A", "B", "C", "D"] if opts.get(k)]
        non_empty = [t for t in opt_texts if t]
        if len(non_empty) == 2:
            tf_tokens = {"true", "false", "t", "f"}
            if all(any(tok in t.split() for tok in tf_tokens) for t in non_empty):
                return "tf"
        if stem.lower().startswith("scenario:") or "what should" in stem.lower():
            return "scenario"
    except Exception:
        pass
    return "mcq"


def sec3_filter_questions(domain_key: str, type_key: str) -> list[dict]:
    """
    Build the working pool from the 'bank' if available (Section 6), plus legacy data/questions.json.
    Filter by domain (exact match) and inferred type if provided.
    """
    pool: list[dict] = []

    # Prefer bank (if Section 6 registered a reader)
    try:
        bank_reader = globals().get("_bank_read_questions")
        if callable(bank_reader):
            pool.extend(bank_reader() or [])
    except Exception:
        pass

    # Legacy fallback
    try:
        legacy = _load_json("questions.json", [])
        if isinstance(legacy, list):
            pool.extend(legacy)
    except Exception:
        pass

    # Domain filter
    dk = (domain_key or "").strip().lower()
    if dk and dk not in ("random", "mixed", "all"):
        pool = [q for q in pool
                if str((q.get("domain") or "Unspecified")).strip().lower() == dk]

    # Type filter (optional)
    tkey = (type_key or "mixed").strip().lower()
    if tkey in ("mcq", "tf", "scenario"):
        pool = [q for q in pool if sec3_detect_qtype(q) == tkey]

    # Deduplicate by a stable key
    seen, uniq = set(), []
    for q in pool:
        try:
            h = q.get("_hash")
            if not h:
                stem = (q.get("question") or "").strip().lower()
                dom = (q.get("domain") or "unspecified").strip().lower()
                correct = (q.get("correct") or "").strip().upper()
                h = f"{stem}|{dom}|{correct}"
            if h in seen:
                continue
            seen.add(h)
            uniq.append(q)
        except Exception:
            continue
    return uniq


def sec3_sample(pool: list[dict], n: int) -> list[dict]:
    pool = pool[:]
    random.shuffle(pool)
    return pool[:max(0, min(n, len(pool)))]


def sec3_render_question_block(q: dict, idx: int) -> str:
    """Render one legacy question as A..D radio buttons (display-only helper)."""
    stem = html.escape(q.get("question", "").strip())
    opts = q.get("options") or {}
    opts_html = []
    for L in ["A", "B", "C", "D"]:
        if not opts.get(L):
            continue
        val = html.escape(str(opts[L]))
        opts_html.append(
            f"""
            <div class="form-check">
              <input class="form-check-input" type="radio" name="q{idx}" id="q{idx}_{L}" value="{L}">
              <label class="form-check-label" for="q{idx}_{L}">
                <span class="fw-semibold">{L}.</span> {val}
              </label>
            </div>
            """
        )
    dom = html.escape(q.get("domain", "Unspecified"))
    qtype = sec3_detect_qtype(q)
    meta = f'<div class="small text-muted mt-1">Domain: <span class="fw-semibold">{dom}</span> • Type: {qtype.upper()}</div>'
    return f"""
    <div class="mb-4 p-3 border rounded-3">
      <div class="fw-semibold mb-2">{idx+1}. {stem}</div>
      {''.join(opts_html) if opts_html else '<div class="text-muted">No options found for this item.</div>'}
      {meta}
    </div>
    """


def sec3_grade(questions: list[dict], answers: dict) -> tuple[int, dict]:
    """
    Returns (correct_count, per_domain_stats)
    per_domain_stats = {domain: {"correct": c, "total": t}}
    """
    correct = 0
    dom_stats: dict[str, dict] = {}
    for i, q in enumerate(questions):
        dom_name = (q.get("domain") or "Unspecified")
        st = dom_stats.setdefault(dom_name, {"correct": 0, "total": 0})
        st["total"] += 1
        user_ans = (answers.get(f"q{i}") or "").strip().upper()
        if user_ans and user_ans == (q.get("correct") or "").strip().upper():
            correct += 1
            st["correct"] += 1
    return correct, dom_stats


def sec3_attempt_record(mode: str, questions: list[dict], correct: int, domains: dict) -> dict:
    """
    Persist an attempt for /progress. This matches the shape that Section 5 reads.
    """
    total = len(questions)
    pct = round(100.0 * correct / total, 1) if total else 0.0
    by_types = {"mcq": 0, "tf": 0, "scenario": 0}
    for q in questions:
        t = sec3_detect_qtype(q)
        by_types[t] = by_types.get(t, 0) + 1

    rec = {
        "ts": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "user_id": _user_id(),
        "mode": mode,
        "count": total,
        "correct": correct,
        "score_pct": pct,
        "domains": domains,
        "types": by_types,
    }
    data = _load_json("attempts.json", [])
    if isinstance(data, list):
        data.append(rec)
        _save_json("attempts.json", data)

    # Best-effort usage tallies (guarded; the helper may live in a later section)
    try:
        _bump_usage("quizzes", 1)
        _bump_usage("questions", total)
    except Exception:
        pass

    _log_event(_user_id(), "legacy.quiz.complete",
               {"mode": mode, "count": total, "correct": correct, "pct": pct})
    return rec


# ---- Route registration (ONLY when explicitly enabled) ----
if SEC3_REGISTER_ROUTES:
    # NOTE: We intentionally mount under /legacy/* to avoid collisions with Section 4’s owners.

    @app.get("/legacy/quiz")
    @login_required
    def sec3_quiz_picker_get():
        """Legacy Quiz Picker (domain + type + count)."""
        csrf_val = csrf_token()

        # Reuse modern domain helper from Section 1 if present
        try:
            domain_buttons = domain_buttons_html(selected_key="random", field_name="domain")
        except Exception:
            # Ultra-minimal fallback if helper is missing
            domain_buttons = '<input type="hidden" id="domain_val" name="domain" value="random">'

        content = f"""
        <div class="container">
          <div class="row justify-content-center"><div class="col-lg-8 col-xl-7">
            <div class="card">
              <div class="card-header bg-primary text-white">
                <h3 class="mb-0"><i class="bi bi-ui-checks-grid me-2"></i>Legacy Quiz Builder</h3>
              </div>
              <div class="card-body">
                <form method="POST" action="/legacy/quiz">
                  <input type="hidden" name="csrf_token" value="{csrf_val}"/>

                  <label class="form-label fw-semibold">Domain</label>
                  {domain_buttons}

                  <div class="mt-3">
                    <label class="form-label fw-semibold">Question Type</label>
                    <div class="d-flex flex-wrap gap-2">
                      <input type="hidden" id="type_val" name="qtype" value="mixed"/>
                      <button type="button" class="btn btn-outline-primary type-btn active" data-value="mixed">Mixed</button>
                      <button type="button" class="btn btn-outline-primary type-btn" data-value="mcq">MCQ</button>
                      <button type="button" class="btn btn-outline-primary type-btn" data-value="tf">True/False</button>
                      <button type="button" class="btn btn-outline-primary type-btn" data-value="scenario">Scenario</button>
                    </div>
                  </div>

                  <div class="mt-3">
                    <label class="form-label fw-semibold">How many?</label>
                    <div class="d-flex gap-2 flex-wrap">
                      <button class="btn btn-outline-success" name="count" value="10">10</button>
                      <button class="btn btn-outline-success" name="count" value="20">20</button>
                      <button class="btn btn-outline-success" name="count" value="30">30</button>
                      <button class="btn btn-outline-success" name="count" value="50">50</button>
                    </div>
                  </div>
                </form>
                <div class="text-muted small mt-3">Mounted on /legacy/* to avoid conflicts with the new engine.</div>
              </div>
            </div>
          </div></div>
        </div>

 """
<script>
  (function(){{
    var container = document.currentScript.closest('.card').querySelector('.card-body');
    var hidden = container.querySelector('#domain_val');
    container.querySelectorAll('.domain-btn').forEach(function(btn){{
      btn.addEventListener('click', function(){{
        container.querySelectorAll('.domain-btn').forEach(function(b){{ b.classList.remove('active'); }});
        btn.classList.add('active');
        if (hidden) hidden.value = btn.getAttribute('data-value');
      }});
    }});
  }})();
</script>
"""
        _log_event(_user_id(), "legacy.quiz.picker", {})
        return base_layout("Legacy Quiz", content)


    @app.post("/legacy/quiz")
    @login_required
    def sec3_quiz_start_post():
        """Legacy Quiz: build one-shot quiz and render it."""
        if not _csrf_ok():
            abort(403)

        # Parse inputs (bounded)
        domain = (request.form.get("domain") or "random").strip()
        qtype = (request.form.get("qtype") or "mixed").strip().lower()
        try:
            count = int(request.form.get("count") or 20)
        except Exception:
            count = 20
        if count not in (10, 20, 30, 50):
            count = 20

        # Prepare questions
        pool = sec3_filter_questions(domain, qtype)
        random.shuffle(pool)
        questions = sec3_sample(pool, count)

        # Minimal payload for grading
        payload_items = [{
            "question": q.get("question", ""),
            "options": {k: q.get("options", {}).get(k, "") for k in ["A", "B", "C", "D"]},
            "correct": (q.get("correct") or "").strip().upper(),
            "domain": q.get("domain", "Unspecified"),
        } for q in questions]
        payload = html.escape(json.dumps(payload_items, ensure_ascii=False))

        # Render
        qblocks = "".join(sec3_render_question_block(q, i) for i, q in enumerate(questions)) or \
                  "<div class='text-muted'>No questions available.</div>"

        content = f"""
        <div class="container">
          <div class="row justify-content-center"><div class="col-xl-10">
            <div class="card">
              <div class="card-header bg-primary text-white d-flex justify-content-between align-items-center">
                <h3 class="mb-0"><i class="bi bi-ui-checks-grid me-2"></i>Legacy Quiz</h3>
                <a href="/legacy/quiz" class="btn btn-outline-light btn-sm">New Quiz</a>
              </div>
              <div class="card-body">
                <div class="small text-muted mb-3">
                  Domain: <strong>{html.escape(DOMAINS.get(domain, 'Mixed')) if domain!='random' else 'Random (all)'}</strong> •
                  Type: <strong>{html.escape(qtype.capitalize()) if qtype!='mixed' else 'Mixed'}</strong> •
                  Count: <strong>{len(questions)}</strong>
                </div>
                <form method="POST" action="/legacy/quiz/grade">
                  <input type="hidden" name="csrf_token" value="{csrf_token()}"/>
                  <textarea name="payload" class="d-none">{payload}</textarea>
                  {qblocks}
                  <div class="d-flex gap-2">
                    <button class="btn btn-success" type="submit"><i class="bi bi-clipboard-check me-1"></i>Grade</button>
                    <a class="btn btn-outline-secondary" href="/legacy/quiz"><i class="bi bi-arrow-left me-1"></i>Back</a>
                  </div>
                </form>
              </div>
            </div>
          </div></div>
        </div>
        """
        _log_event(_user_id(), "legacy.quiz.start", {"count": len(questions), "domain": domain, "type": qtype})
        try:
            _bump_usage("quizzes", 1)
            _bump_usage("questions", len(questions))
        except Exception:
            pass
        return base_layout("Legacy Quiz", content)


    @app.post("/legacy/quiz/grade")
    @login_required
    def sec3_quiz_grade_post():
        """Legacy Quiz grading."""
        if not _csrf_ok():
            abort(403)

        raw = request.form.get("payload") or "[]"
        try:
            questions = json.loads(raw)
            if not isinstance(questions, list):
                questions = []
        except Exception:
            questions = []

        answers = {f"q{i}": (request.form.get(f"q{i}") or "").strip().upper()
                   for i in range(len(questions))}
        correct, dom_stats = sec3_grade(questions, answers)
        rec = sec3_attempt_record("quiz", questions, correct, dom_stats)

        # Build domain table
        def pct(c, t): return f"{(100.0*c/t):.1f}%" if t else "0.0%"
        drows = []
        for dname in sorted(dom_stats.keys()):
            c = dom_stats[dname]["correct"]; t = dom_stats[dname]["total"]
            drows.append(f"<tr><td>{html.escape(dname)}</td><td class='text-end'>{c}/{t}</td><td class='text-end'>{pct(c,t)}</td></tr>")
        dtable = "".join(drows) or "<tr><td colspan='3' class='text-center text-muted'>None</td></tr>"

        total = len(questions)
        pct_str = f"{rec['score_pct']:.1f}%"
        content = f"""
        <div class="container">
          <div class="row justify-content-center"><div class="col-lg-8 col-xl-7">
            <div class="card">
              <div class="card-header bg-success text-white">
                <h3 class="mb-0"><i class="bi bi-clipboard-check me-2"></i>Legacy Results</h3>
              </div>
              <div class="card-body">
                <div class="row g-3 mb-2">
                  <div class="col-6"><div class="p-3 border rounded-3">
                    <div class="small text-muted">Score</div><div class="h4 mb-0">{correct}/{total}</div>
                  </div></div>
                  <div class="col-6"><div class="p-3 border rounded-3">
                    <div class="small text-muted">Percent</div><div class="h4 mb-0">{pct_str}</div>
                  </div></div>
                </div>

                <div class="p-3 border rounded-3">
                  <div class="fw-semibold mb-2">By Domain</div>
                  <div class="table-responsive">
                    <table class="table table-sm align-middle">
                      <thead><tr><th>Domain</th><th class="text-end">Correct</th><th class="text-end">%</th></tr></thead>
                      <tbody>{dtable}</tbody>
                    </table>
                  </div>
                </div>

                <div class="d-flex gap-2 mt-3">
                  <a class="btn btn-primary" href="/legacy/quiz"><i class="bi bi-arrow-repeat me-1"></i>New Quiz</a>
                  <a class="btn btn-outline-secondary" href="/progress"><i class="bi bi-graph-up-arrow me-1"></i>Progress</a>
                  <a class="btn btn-outline-secondary" href="/"><i class="bi bi-house me-1"></i>Home</a>
                </div>
              </div>
            </div>
          </div></div>
        </div>
        """
        return base_layout("Legacy Quiz Results", content)


    @app.get("/legacy/mock-exam")
    @login_required
    def sec3_mock_picker_get():
        """Legacy Mock Exam launcher (fixed counts)."""
        csrf_val = csrf_token()
        content = f"""
        <div class="container">
          <div class="row justify-content-center"><div class="col-lg-8 col-xl-7">
            <div class="card">
              <div class="card-header bg-warning text-dark">
                <h3 class="mb-0"><i class="bi bi-mortarboard me-2"></i>Legacy Mock Exam</h3>
              </div>
              <div class="card-body">
                <form method="POST" action="/legacy/mock-exam">
                  <input type="hidden" name="csrf_token" value="{csrf_val}"/>
                  <div class="mb-2 text-muted small">Choose how many questions:</div>
                  <div class="d-flex gap-2 flex-wrap">
                    <button class="btn btn-outline-warning" name="count" value="50">50</button>
                    <button class="btn btn-outline-warning" name="count" value="100">100</button>
                    <button class="btn btn-outline-warning" name="count" value="150">150</button>
                  </div>
                </form>
                <div class="text-muted small mt-3">Results still appear in your Progress.</div>
              </div>
            </div>
          </div></div>
        </div>
        """
        return base_layout("Legacy Mock Exam", content)


    @app.post("/legacy/mock-exam")
    @login_required
    def sec3_mock_start_post():
        """Legacy Mock Exam start."""
        if not _csrf_ok():
            abort(403)
        try:
            count = int(request.form.get("count") or 100)
        except Exception:
            count = 100
        if count not in (50, 100, 150):
            count = 100

        pool = sec3_filter_questions("random", "mixed")
        random.shuffle(pool)
        questions = sec3_sample(pool, count)

        payload_items = [{
            "question": q.get("question", ""),
            "options": {k: q.get("options", {}).get(k, "") for k in ["A", "B", "C", "D"]},
            "correct": (q.get("correct") or "").strip().upper(),
            "domain": q.get("domain", "Unspecified"),
        } for q in questions]
        payload = html.escape(json.dumps(payload_items, ensure_ascii=False))

        qblocks = "".join(sec3_render_question_block(q, i) for i, q in enumerate(questions)) or \
                  "<div class='text-muted'>No questions available.</div>"

        content = f"""
        <div class="container">
          <div class="row justify-content-center"><div class="col-xl-10">
            <div class="card">
              <div class="card-header bg-warning text-dark d-flex justify-content-between align-items-center">
                <h3 class="mb-0"><i class="bi bi-mortarboard me-2"></i>Legacy Mock Exam</h3>
                <a href="/legacy/mock-exam" class="btn btn-outline-dark btn-sm">New Mock</a>
              </div>
              <div class="card-body">
                <div class="small text-muted mb-3">Mixed domains • Mixed types • Count: <strong>{len(questions)}</strong></div>
                <form method="POST" action="/legacy/mock-exam/grade">
                  <input type="hidden" name="csrf_token" value="{csrf_token()}"/>
                  <textarea name="payload" class="d-none">{payload}</textarea>
                  {qblocks}
                  <div class="d-flex gap-2">
                    <button class="btn btn-success" type="submit"><i class="bi bi-clipboard-check me-1"></i>Grade</button>
                    <a class="btn btn-outline-secondary" href="/legacy/mock-exam"><i class="bi bi-arrow-left me-1"></i>Back</a>
                  </div>
                </form>
              </div>
            </div>
          </div></div>
        </div>
        """
        _log_event(_user_id(), "legacy.mock.start", {"count": len(questions)})
        try:
            _bump_usage("quizzes", 1)
            _bump_usage("questions", len(questions))
        except Exception:
            pass
        return base_layout("Legacy Mock Exam", content)


    @app.post("/legacy/mock-exam/grade")
    @login_required
    def sec3_mock_grade_post():
        """Legacy Mock Exam grading."""
        if not _csrf_ok():
            abort(403)

        raw = request.form.get("payload") or "[]"
        try:
            questions = json.loads(raw)
            if not isinstance(questions, list):
                questions = []
        except Exception:
            questions = []

        answers = {f"q{i}": (request.form.get(f"q{i}") or "").strip().upper()
                   for i in range(len(questions))}
        correct, dom_stats = sec3_grade(questions, answers)
        rec = sec3_attempt_record("mock", questions, correct, dom_stats)

        def pct(c, t): return f"{(100.0*c/t):.1f}%" if t else "0.0%"
        drows = []
        for dname in sorted(dom_stats.keys()):
            c = dom_stats[dname]["correct"]; t = dom_stats[dname]["total"]
            drows.append(f"<tr><td>{html.escape(dname)}</td><td class='text-end'>{c}/{t}</td><td class='text-end'>{pct(c,t)}</td></tr>")
        dtable = "".join(drows) or "<tr><td colspan='3' class='text-center text-muted'>None</td></tr>"

        total = len(questions)
        pct_str = f"{rec['score_pct']:.1f}%"
        content = f"""
        <div class="container">
          <div class="row justify-content-center"><div class="col-lg-8 col-xl-7">
            <div class="card">
              <div class="card-header bg-success text-white">
                <h3 class="mb-0"><i class="bi bi-clipboard-check me-2"></i>Legacy Mock Results</h3>
              </div>
              <div class="card-body">
                <div class="row g-3 mb-2">
                  <div class="col-6"><div class="p-3 border rounded-3">
                    <div class="small text-muted">Score</div><div class="h4 mb-0">{correct}/{total}</div>
                  </div></div>
                  <div class="col-6"><div class="p-3 border rounded-3">
                    <div class="small text-muted">Percent</div><div class="h4 mb-0">{pct_str}</div>
                  </div></div>
                </div>

                <div class="p-3 border rounded-3">
                  <div class="fw-semibold mb-2">By Domain</div>
                  <div class="table-responsive">
                    <table class="table table-sm align-middle">
                      <thead><tr><th>Domain</th><th class="text-end">Correct</th><th class="text-end">%</th></tr></thead>
                      <tbody>{dtable}</tbody>
                    </table>
                  </div>
                </div>

                <div class="d-flex gap-2 mt-3">
                  <a class="btn btn-warning" href="/legacy/mock-exam"><i class="bi bi-mortarboard me-1"></i>New Mock</a>
                  <a class="btn btn-outline-secondary" href="/progress"><i class="bi bi-graph-up-arrow me-1"></i>Progress</a>
                  <a class="btn btn-outline-secondary" href="/"><i class="bi bi-house me-1"></i>Home</a>
                </div>
              </div>
            </div>
          </div></div>
        </div>
        """
        return base_layout("Legacy Mock Results", content)

# ========================= END SECTION 3/8 =========================

# =========================
# SECTION 4/8: Quizzes & Mock Exams (picker, runner, grading, attempt logging)
# One-owner rule: THIS SECTION OWNS the /quiz* and /mock* routes.
# Endpoint function names are all prefixed with `sec4_` to avoid collisions.
# =========================

# ---- Local helpers (safe, no conflicts) --------------------------------------

def sec4_now_iso() -> str:
    try:
        return datetime.utcnow().isoformat() + "Z"
    except Exception:
        return ""

def sec4_domains_map() -> dict:
    """
    Prefer the global DOMAINS (from Section 1) if present; otherwise a safe default.
    """
    return globals().get("DOMAINS") or {
        "security-principles": "Security Principles & Practices",
        "business-principles": "Business Principles & Practices",
        "investigations": "Investigations",
        "personnel-security": "Personnel Security",
        "physical-security": "Physical Security",
        "information-security": "Information Security",
        "crisis-management": "Crisis Management",
    }

def sec4_domain_buttons_html(selected_key: str = "random", field_name: str = "domain") -> str:
    """
    Render domain selector buttons + hidden input. We keep this local (sec4_*) to
    avoid naming overlap and ensure the UI works even if Section 1 changes later.
    """
    dom = sec4_domains_map()
    order = ["random"] + [k for k in dom.keys()]
    btns = []
    for key in order:
        lbl = "Random (all)" if key == "random" else dom.get(key, key)
        active = " active" if key == selected_key else ""
        btns.append(
            f'<button type="button" class="btn btn-outline-primary domain-btn{active}" '
            f'data-value="{html.escape(key)}">{html.escape(lbl)}</button>'
        )
    return (
        f'<div class="d-flex flex-wrap gap-2">{"".join(btns)}</div>'
        f'<input type="hidden" id="domain_val" name="{html.escape(field_name)}" '
        f'value="{html.escape(selected_key)}"/>'
    )

def sec4_load_all_questions() -> list[dict]:
    """
    Merge bank questions (if Section 6 registered _bank_read_questions) with any
    legacy data/questions.json content. Returns a raw, heterogeneous list that
    downstream functions will normalize.
    """
    out: list[dict] = []
    try:
        bank_fn = globals().get("_bank_read_questions")
        if callable(bank_fn):
            out.extend(bank_fn() or [])
    except Exception:
        pass
    try:
        out.extend(_load_json("questions.json", []) or [])
    except Exception:
        pass
    return out

def sec4_filter_questions_by_domain(items: list[dict], domain_key: str | None) -> list[dict]:
    if not domain_key or domain_key == "random":
        return items[:]
    dk = str(domain_key).strip().lower()
    out = []
    for q in items:
        dname = (q.get("domain") or q.get("category") or "Unspecified")
        if str(dname).strip().lower() == dk:
            out.append(q)
    return out

def sec4_normalize_question(q: dict) -> dict | None:
    """
    Normalize into:
      {
        "id": str,
        "question": str,
        "options": {"A": "...","B":"...","C":"...","D":"..."},
        "correct": "A"|"B"|"C"|"D",
        "domain": str,
        "sources": [{title,url}, ...]  # optional, at most a few
      }
    Rejects invalid question shapes by returning None.
    """
    try:
        if not isinstance(q, dict):
            return None

        stem = (q.get("question") or q.get("q") or "").strip()
        if not stem:
            return None

        # Options: accept dict/A..D or list[4] with text fields
        opts_in = q.get("options") or q.get("choices") or {}
        opts: dict[str, str] = {}
        if isinstance(opts_in, dict):
            for L in ["A", "B", "C", "D"]:
                v = opts_in.get(L) or opts_in.get(L.lower())
                if not v:
                    return None
                opts[L] = str(v).strip()
        elif isinstance(opts_in, list) and len(opts_in) >= 4:
            letters = ["A", "B", "C", "D"]
            for i, L in enumerate(letters):
                v = opts_in[i]
                if isinstance(v, dict):
                    text = v.get("text") or v.get("label") or v.get("value")
                else:
                    text = v
                if not text:
                    return None
                opts[L] = str(text).strip()
        else:
            return None

        # Correct answer: allow "A..D" or 1..4
        correct = (q.get("correct") or q.get("answer") or "").strip().upper()
        if correct not in ("A", "B", "C", "D"):
            try:
                idx = int(correct)
                correct = ["A", "B", "C", "D"][idx - 1]
            except Exception:
                return None

        dom = (q.get("domain") or q.get("category") or "Unspecified").strip()

        sources = []
        for s in (q.get("sources") or [])[:3]:
            t = (s.get("title") or "").strip()
            u = (s.get("url") or "").strip()
            if t and u:
                sources.append({"title": t, "url": u})

        return {
            "id": q.get("id") or hashlib.sha1(
                f"{stem}|{json.dumps(opts, sort_keys=True)}|{dom}".encode("utf-8")
            ).hexdigest(),
            "question": stem,
            "options": opts,
            "correct": correct,
            "domain": dom,
            "sources": sources,
        }
    except Exception:
        return None

def sec4_select_questions(all_q: list[dict], count: int) -> list[dict]:
    pool: list[dict] = []
    for q in all_q:
        n = sec4_normalize_question(q)
        if n:
            pool.append(n)
    random.shuffle(pool)
    return pool[:max(0, min(count, len(pool)))]

def sec4_render_question_block(q: dict, idx: int) -> str:
    """Render a single question with A..D radio inputs + hidden correctness/meta."""
    stem = html.escape(q["question"])
    dom_label = html.escape(q.get("domain", "Unspecified"))
    opt_html = []
    name = f"q_{idx}"
    qid = html.escape(q.get("id", str(idx)))
    for L in ["A", "B", "C", "D"]:
        val = html.escape(q["options"].get(L, ""))
        oid = f"{name}_{L}"
        opt_html.append(
            f"""
            <div class="form-check">
              <input class="form-check-input" type="radio" id="{oid}" name="{name}" value="{L}" required>
              <label class="form-check-label" for="{oid}"><strong>{L}.</strong> {val}</label>
            </div>
            """
        )
    return f"""
    <div class="border rounded-3 p-3 mb-3">
      <div class="small text-muted mb-1">Domain: <strong>{dom_label}</strong></div>
      <div class="fw-semibold mb-2">{stem}</div>
      {''.join(opt_html)}
      <input type="hidden" name="{name}_id" value="{qid}">
      <input type="hidden" name="{name}_correct" value="{q['correct']}">
      <input type="hidden" name="{name}_domain" value="{html.escape(q.get('domain','Unspecified'))}">
      <input type="hidden" name="{name}_sources" value="{html.escape(json.dumps(q.get('sources') or []))}">
    </div>
    """

def sec4_grade_submission(form: dict, total: int) -> tuple[int, list[dict], dict]:
    """
    Returns (correct_count, detailed_rows, per_domain_stats)
    detailed_rows: [{qid, chosen, correct, domain, sources, is_correct}]
    per_domain_stats: {domain: {"correct": int, "total": int}}
    """
    correct = 0
    rows: list[dict] = []
    dom_stats: dict[str, dict] = {}

    for i in range(total):
        name = f"q_{i}"
        chosen = (form.get(name) or "").strip().upper()
        qid = form.get(f"{name}_id") or ""
        right = (form.get(f"{name}_correct") or "").strip().upper()
        domain = (form.get(f"{name}_domain") or "Unspecified").strip()
        sources_json = form.get(f"{name}_sources") or "[]"
        try:
            sources = json.loads(sources_json)
        except Exception:
            sources = []

        is_ok = (chosen == right)
        if is_ok:
            correct += 1

        ds = dom_stats.setdefault(domain, {"correct": 0, "total": 0})
        ds["total"] += 1
        if is_ok:
            ds["correct"] += 1

        rows.append({
            "qid": qid,
            "chosen": chosen or "—",
            "correct": right,
            "domain": domain,
            "sources": sources,
            "is_correct": is_ok,
        })

    return correct, rows, dom_stats

def sec4_attempt_append(record: dict):
    """Append an attempt to attempts.json (safe/no-op on failure)."""
    try:
        attempts = _load_json("attempts.json", [])
        attempts.append(record)
        _save_json("attempts.json", attempts)
    except Exception as e:
        try:
            logger.warning("Could not append attempt: %s", e)
        except Exception:
            pass

def sec4_pct(c: int, t: int) -> str:
    return f"{(100.0 * c / t):.1f}%" if t else "0.0%"

# ---- Routes: QUIZ -------------------------------------------------------------

@app.get("/quiz", endpoint="sec4_quiz_picker")
@login_required
def sec4_quiz_picker():
    csrf_val = csrf_token()
    dom_buttons = sec4_domain_buttons_html(selected_key="random", field_name="domain")

    content = f"""
    <div class="container">
      <div class="row justify-content-center"><div class="col-lg-8 col-xl-7">
        <div class="card">
          <div class="card-header bg-primary text-white">
            <h3 class="mb-0"><i class="bi bi-ui-checks-grid me-2"></i>Quiz</h3>
          </div>
          <div class="card-body">
            <form method="POST" action="/quiz/start" class="mb-3">
              <input type="hidden" name="csrf_token" value="{csrf_val}"/>
              <label class="form-label fw-semibold">Domain</label>
              {dom_buttons}
              <div class="mt-3 mb-2 fw-semibold">How many questions?</div>
              <div class="d-flex flex-wrap gap-2">
                <button class="btn btn-outline-primary" name="count" value="10">10</button>
                <button class="btn btn-outline-primary" name="count" value="20">20</button>
                <button class="btn btn-outline-primary" name="count" value="30">30</button>
                <button class="btn btn-outline-primary" name="count" value="50">50</button>
              </div>
            </form>
            <div class="text-muted small">Tip: Pick a domain or use Random to mix all.</div>
          </div>
        </div>
      </div></div>
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
    """
    try:
        _log_event(_user_id(), "quiz.picker", {})
    except Exception:
        pass
    return base_layout("Quiz", content)

@app.post("/quiz/start", endpoint="sec4_quiz_start")
@login_required
def sec4_quiz_start():
    if not _csrf_ok():
        abort(403)

    try:
        count = int(request.form.get("count") or 20)
    except Exception:
        count = 20
    if count not in (10, 20, 30, 50):
        count = 20
    domain = request.form.get("domain") or "random"

    all_q = sec4_load_all_questions()
    pool = sec4_filter_questions_by_domain(all_q, domain)
    chosen = sec4_select_questions(pool, count)

    csrf_val = csrf_token()
    cards = [sec4_render_question_block(q, i) for i, q in enumerate(chosen)]
    dom_name = sec4_domains_map().get(domain, "Random (all)") if domain != "random" else "Random (all)"

    content = f"""
    <div class="container">
      <div class="row justify-content-center"><div class="col-xl-10">
        <div class="card">
          <div class="card-header bg-primary text-white d-flex justify-content-between align-items-center">
            <h3 class="mb-0"><i class="bi bi-ui-checks-grid me-2"></i>Quiz</h3>
            <a href="/quiz" class="btn btn-outline-light btn-sm">New Session</a>
          </div>
          <div class="card-body">
            <div class="mb-2 small text-muted">Domain: <strong>{html.escape(dom_name)}</strong> • Questions: {len(chosen)}</div>
            <form method="POST" action="/quiz/grade" id="quizForm">
              <input type="hidden" name="csrf_token" value="{csrf_val}"/>
              <input type="hidden" name="mode" value="Quiz"/>
              <input type="hidden" name="count" value="{len(chosen)}"/>
              <div>{''.join(cards)}</div>
              <div class="d-flex align-items-center mt-3">
                <button class="btn btn-success" type="submit"><i class="bi bi-check2-circle me-1"></i>Submit Answers</button>
                <a class="btn btn-outline-secondary ms-2" href="/quiz"><i class="bi bi-arrow-left me-1"></i>Back</a>
              </div>
            </form>
          </div>
        </div>
      </div></div>
    </div>
    """
    try:
        _log_event(_user_id(), "quiz.start", {"count": len(chosen), "domain": domain})
        _bump_usage("quizzes", 1); _bump_usage("questions", len(chosen))
    except Exception:
        pass
    return base_layout("Quiz • In Progress", content)

@app.post("/quiz/grade", endpoint="sec4_quiz_grade")
@login_required
def sec4_quiz_grade():
    if not _csrf_ok():
        abort(403)

    mode = (request.form.get("mode") or "Quiz").strip()
    try:
        total = int(request.form.get("count") or 0)
    except Exception:
        total = 0

    correct, rows, dom_stats = sec4_grade_submission(request.form, total)
    pct = round((100.0 * correct / total), 1) if total else 0.0

    # Build rows
    def _row_html(r):
        ic = '<span class="badge bg-success">Correct</span>' if r["is_correct"] else '<span class="badge bg-danger">Wrong</span>'
        src_bits = ""
        if r.get("sources"):
            links = []
            for s in (r["sources"] or [])[:3]:
                t = html.escape((s.get("title") or "").strip())
                u = html.escape((s.get("url") or "").strip())
                if t and u:
                    links.append(f'<li><a href="{u}" target="_blank" rel="noopener">{t}</a></li>')
            if links:
                src_bits = f'<div class="small mt-1"><span class="text-muted">Sources:</span><ul class="small mb-0 ps-3">{"".join(links)}</ul></div>'
        return f"""
        <tr>
          <td class="text-nowrap">{html.escape(r["domain"])}</td>
          <td class="text-center">{html.escape(r["chosen"])}</td>
          <td class="text-center">{html.escape(r["correct"])}</td>
          <td class="text-center">{ic}{src_bits}</td>
        </tr>
        """

    rows_html = "".join(_row_html(r) for r in rows) or "<tr><td colspan='4' class='text-center text-muted'>No answers submitted.</td></tr>"

    # Domain breakdown
    def _dom_row(dn, st):
        return f"<tr><td>{html.escape(dn)}</td><td class='text-end'>{st['correct']}/{st['total']}</td><td class='text-end'>{sec4_pct(st['correct'], st['total'])}</td></tr>"

    dom_html = "".join(_dom_row(d, st) for d, st in sorted(dom_stats.items())) or "<tr><td colspan='3' class='text-center text-muted'>No data.</td></tr>"

    # Persist attempt
    rec = {
        "user_id": _user_id(),
        "ts": sec4_now_iso(),
        "mode": mode,
        "count": total,
        "correct": correct,
        "score_pct": pct,
        "domains": dom_stats
    }
    sec4_attempt_append(rec)
    try:
        _log_event(_user_id(), "quiz.finish", {"mode": mode, "count": total, "correct": correct, "score_pct": pct})
    except Exception:
        pass

    content = f"""
    <div class="container">
      <div class="row justify-content-center"><div class="col-xl-10">
        <div class="card">
          <div class="card-header bg-success text-white d-flex justify-content-between align-items-center">
            <h3 class="mb-0"><i class="bi bi-clipboard2-check me-2"></i>Results</h3>
            <a href="/quiz" class="btn btn-outline-light btn-sm">New Quiz</a>
          </div>
          <div class="card-body">
            <div class="row g-3 mb-3">
              <div class="col-md-3"><div class="p-3 border rounded-3"><div class="small text-muted">Mode</div><div class="h5 mb-0">{html.escape(mode)}</div></div></div>
              <div class="col-md-3"><div class="p-3 border rounded-3"><div class="small text-muted">Questions</div><div class="h5 mb-0">{total}</div></div></div>
              <div class="col-md-3"><div class="p-3 border rounded-3"><div class="small text-muted">Correct</div><div class="h5 mb-0">{correct}</div></div></div>
              <div class="col-md-3"><div class="p-3 border rounded-3"><div class="small text-muted">Score</div><div class="h5 mb-0">{pct}%</div></div></div>
            </div>

            <div class="row g-3">
              <div class="col-lg-5">
                <div class="p-3 border rounded-3">
                  <div class="fw-semibold mb-2">By Domain</div>
                  <div class="table-responsive">
                    <table class="table table-sm align-middle">
                      <thead><tr><th>Domain</th><th class="text-end">Correct</th><th class="text-end">%</th></tr></thead>
                      <tbody>{dom_html}</tbody>
                    </table>
                  </div>
                </div>
              </div>
              <div class="col-lg-7">
                <div class="p-3 border rounded-3">
                  <div class="fw-semibold mb-2">Answer Review</div>
                  <div class="table-responsive">
                    <table class="table table-sm align-middle">
                      <thead><tr><th>Domain</th><th class="text-center">Your</th><th class="text-center">Correct</th><th class="text-center">Result</th></tr></thead>
                      <tbody>{rows_html}</tbody>
                    </table>
                  </div>
                </div>
              </div>
            </div>

            <div class="mt-3 d-flex gap-2">
              <a class="btn btn-outline-secondary" href="/progress"><i class="bi bi-graph-up me-1"></i>See Progress</a>
              <a class="btn btn-outline-primary" href="/mock"><i class="bi bi-journal-check me-1"></i>Try a Mock Exam</a>
            </div>
          </div>
        </div>
      </div></div>
    </div>
    """
    return base_layout("Quiz • Results", content)

# ---- Routes: MOCK EXAM --------------------------------------------------------

@app.get("/mock", endpoint="sec4_mock_picker")
@login_required
def sec4_mock_picker():
    csrf_val = csrf_token()
    dom_buttons = sec4_domain_buttons_html(selected_key="random", field_name="domain")

    content = f"""
    <div class="container">
      <div class="row justify-content-center"><div class="col-lg-8 col-xl-7">
        <div class="card">
          <div class="card-header bg-warning text-dark">
            <h3 class="mb-0"><i class="bi bi-journal-check me-2"></i>Mock Exam</h3>
          </div>
          <div class="card-body">
            <form method="POST" action="/mock/start" class="mb-3">
              <input type="hidden" name="csrf_token" value="{csrf_val}"/>
              <label class="form-label fw-semibold">Domain</label>
              {dom_buttons}
              <div class="mt-3 mb-2 fw-semibold">How many questions?</div>
              <div class="d-flex flex-wrap gap-2">
                <button class="btn btn-outline-warning" name="count" value="50">50</button>
                <button class="btn btn-outline-warning" name="count" value="100">100</button>
                <button class="btn btn-outline-warning" name="count" value="150">150</button>
              </div>
            </form>
            <div class="text-muted small">Tip: Use Random for a mixed-domain exam.</div>
          </div>
        </div>
      </div></div>
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
    """
    try:
        _log_event(_user_id(), "mock.picker", {})
    except Exception:
        pass
    return base_layout("Mock Exam", content)

@app.post("/mock/start", endpoint="sec4_mock_start")
@login_required
def sec4_mock_start():
    if not _csrf_ok():
        abort(403)

    try:
        count = int(request.form.get("count") or 100)
    except Exception:
        count = 100
    if count not in (50, 100, 150):
        count = 100
    domain = request.form.get("domain") or "random"

    all_q = sec4_load_all_questions()
    pool = sec4_filter_questions_by_domain(all_q, domain)
    chosen = sec4_select_questions(pool, count)

    csrf_val = csrf_token()
    cards = [sec4_render_question_block(q, i) for i, q in enumerate(chosen)]
    dom_name = sec4_domains_map().get(domain, "Random (all)") if domain != "random" else "Random (all)"

    content = f"""
    <div class="container">
      <div class="row justify-content-center"><div class="col-xl-10">
        <div class="card">
          <div class="card-header bg-warning text-dark d-flex justify-content-between align-items-center">
            <h3 class="mb-0"><i class="bi bi-journal-check me-2"></i>Mock Exam</h3>
            <a href="/mock" class="btn btn-outline-dark btn-sm">New Mock</a>
          </div>
          <div class="card-body">
            <div class="mb-2 small text-muted">Domain: <strong>{html.escape(dom_name)}</strong> • Questions: {len(chosen)}</div>
            <form method="POST" action="/mock/grade" id="mockForm">
              <input type="hidden" name="csrf_token" value="{csrf_val}"/>
              <input type="hidden" name="mode" value="Mock"/>
              <input type="hidden" name="count" value="{len(chosen)}"/>
              <div>{''.join(cards)}</div>
              <div class="d-flex align-items-center mt-3">
                <button class="btn btn-success" type="submit"><i class="bi bi-check2-circle me-1"></i>Submit Answers</button>
                <a class="btn btn-outline-secondary ms-2" href="/mock"><i class="bi bi-arrow-left me-1"></i>Back</a>
              </div>
            </form>
          </div>
        </div>
      </div></div>
    </div>
    """
    try:
        _log_event(_user_id(), "mock.start", {"count": len(chosen), "domain": domain})
        _bump_usage("quizzes", 1); _bump_usage("questions", len(chosen))
    except Exception:
        pass
    return base_layout("Mock Exam • In Progress", content)

@app.post("/mock/grade", endpoint="sec4_mock_grade")
@login_required
def sec4_mock_grade():
    if not _csrf_ok():
        abort(403)

    mode = (request.form.get("mode") or "Mock").strip()
    try:
        total = int(request.form.get("count") or 0)
    except Exception:
        total = 0

    correct, rows, dom_stats = sec4_grade_submission(request.form, total)
    pct = round((100.0 * correct / total), 1) if total else 0.0

    def _row_html(r):
        ic = '<span class="badge bg-success">Correct</span>' if r["is_correct"] else '<span class="badge bg-danger">Wrong</span>'
        src_bits = ""
        if r.get("sources"):
            links = []
            for s in (r["sources"] or [])[:3]:
                t = html.escape((s.get("title") or "").strip())
                u = html.escape((s.get("url") or "").strip())
                if t and u:
                    links.append(f'<li><a href="{u}" target="_blank" rel="noopener">{t}</a></li>')
            if links:
                src_bits = f'<div class="small mt-1"><span class="text-muted">Sources:</span><ul class="small mb-0 ps-3">{"".join(links)}</ul></div>'
        return f"""
        <tr>
          <td class="text-nowrap">{html.escape(r["domain"])}</td>
          <td class="text-center">{html.escape(r["chosen"])}</td>
          <td class="text-center">{html.escape(r["correct"])}</td>
          <td class="text-center">{ic}{src_bits}</td>
        </tr>
        """

    rows_html = "".join(_row_html(r) for r in rows) or "<tr><td colspan='4' class='text-center text-muted'>No answers submitted.</td></tr>"

    def _dom_row(dn, st):
        return f"<tr><td>{html.escape(dn)}</td><td class='text-end'>{st['correct']}/{st['total']}</td><td class='text-end'>{sec4_pct(st['correct'], st['total'])}</td></tr>"

    dom_html = "".join(_dom_row(d, st) for d, st in sorted(dom_stats.items())) or "<tr><td colspan='3' class='text-center text-muted'>No data.</td></tr>"

    # Persist attempt
    rec = {
        "user_id": _user_id(),
        "ts": sec4_now_iso(),
        "mode": mode,
        "count": total,
        "correct": correct,
        "score_pct": pct,
        "domains": dom_stats
    }
    sec4_attempt_append(rec)
    try:
        _log_event(_user_id(), "mock.finish", {"mode": mode, "count": total, "correct": correct, "score_pct": pct})
    except Exception:
        pass

    content = f"""
    <div class="container">
      <div class="row justify-content-center"><div class="col-xl-10">
        <div class="card">
          <div class="card-header bg-success text-white d-flex justify-content-between align-items-center">
            <h3 class="mb-0"><i class="bi bi-clipboard2-check me-2"></i>Results</h3>
            <a href="/mock" class="btn btn-outline-light btn-sm">New Mock</a>
          </div>
          <div class="card-body">
            <div class="row g-3 mb-3">
              <div class="col-md-3"><div class="p-3 border rounded-3"><div class="small text-muted">Mode</div><div class="h5 mb-0">{html.escape(mode)}</div></div></div>
              <div class="col-md-3"><div class="p-3 border rounded-3"><div class="small text-muted">Questions</div><div class="h5 mb-0">{total}</div></div></div>
              <div class="col-md-3"><div class="p-3 border rounded-3"><div class="small text-muted">Correct</div><div class="h5 mb-0">{correct}</div></div></div>
              <div class="col-md-3"><div class="p-3 border rounded-3"><div class="small text-muted">Score</div><div class="h5 mb-0">{pct}%</div></div></div>
            </div>

            <div class="row g-3">
              <div class="col-lg-5">
                <div class="p-3 border rounded-3">
                  <div class="fw-semibold mb-2">By Domain</div>
                  <div class="table-responsive">
                    <table class="table table-sm align-middle">
                      <thead><tr><th>Domain</th><th class="text-end">Correct</th><th class="text-end">%</th></tr></thead>
                      <tbody>{dom_html}</tbody>
                    </table>
                  </div>
                </div>
              </div>
              <div class="col-lg-7">
                <div class="p-3 border rounded-3">
                  <div class="fw-semibold mb-2">Answer Review</div>
                  <div class="table-responsive">
                    <table class="table table-sm align-middle">
                      <thead><tr><th>Domain</th><th class="text-center">Your</th><th class="text-center">Correct</th><th class="text-center">Result</th></tr></thead>
                      <tbody>{rows_html}</tbody>
                    </table>
                  </div>
                </div>
              </div>
            </div>

            <div class="mt-3 d-flex gap-2">
              <a class="btn btn-outline-secondary" href="/progress"><i class="bi bi-graph-up me-1"></i>See Progress</a>
              <a class="btn btn-outline-primary" href="/quiz"><i class="bi bi-ui-checks-grid me-1"></i>Take a Quiz</a>
            </div>
          </div>
        </div>
      </div></div>
    </div>
    """
    return base_layout("Mock Exam • Results", content)
# ========================= END SECTION 4/8 =========================

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

# ---------- STRIPE IMPORT & CONFIG (SAFE) ----------
# Keep runtime graceful if stripe library or secret key is missing.
try:
    import stripe  # type: ignore
except Exception:
    stripe = None  # type: ignore

STRIPE_SECRET_KEY       = os.environ.get("STRIPE_SECRET_KEY", "")
STRIPE_PUBLISHABLE_KEY  = os.environ.get("STRIPE_PUBLISHABLE_KEY", "")
STRIPE_MONTHLY_PRICE_ID = os.environ.get("STRIPE_MONTHLY_PRICE_ID", "")
STRIPE_SIXMONTH_PRICE_ID= os.environ.get("STRIPE_SIXMONTH_PRICE_ID", "")
STRIPE_WEBHOOK_SECRET   = os.environ.get("STRIPE_WEBHOOK_SECRET", "")

if stripe is not None:
    try:
        stripe.api_key = STRIPE_SECRET_KEY or None  # None safe; we gate calls with _stripe_ready()
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

        content = f"""
        <div class="container">
          <div class="row justify-content-center"><div class="col-lg-8 col-xl-7">
            <div class="card">
              <div class="card-header bg-success text-white">
                <h3 class="mb-0"><i class="bi bi-layers me-2"></i>Flashcards</h3>
              </div>
              <div class="card-body">
                <form method="POST" class="mb-3">
                  <input type="hidden" name="csrf_token" value="{csrf_val}"/>
                  <label class="form-label fw-semibold">Domain</label>
                  {domain_buttons}
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
          (function() {{
            var container = document.currentScript.closest('.card').querySelector('.card-body');
            var hidden = container.querySelector('#domain_val');
            container.querySelectorAll('.domain-btn').forEach(function(btn) {{
              btn.addEventListener('click', function() {{
                container.querySelectorAll('.domain-btn').forEach(function(b) {{ b.classList.remove('active'); }});
                btn.classList.add('active');
                if (hidden) hidden.value = btn.getAttribute('data-value');
              }});
            }});
          }})();
        </script>
        """
        return base_layout("Flashcards", content)

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

    content = f"""
    <div class="container">
      <div class="row justify-content-center"><div class="col-lg-8 col-xl-7">
        <div class="card">
          <div class="card-header bg-success text-white d-flex justify-content-between align-items-center">
            <h3 class="mb-0"><i class="bi bi-layers me-2"></i>Flashcards</h3>
            <a href="/flashcards" class="btn btn-outline-light btn-sm">New Session</a>
          </div>
          <div class="card-body">
            <div class="mb-2 small text-muted">Domain:
              <strong>{html.escape(DOMAINS.get(domain, 'Mixed')) if domain!='random' else 'Random (all)'}</strong>
              &bull; Cards: {len(cards)}
            </div>
            <div id="fc-container">{cards_html}</div>

            <div class="d-flex align-items-center gap-2 mt-3">
              <button class="btn btn-outline-secondary" id="prevBtn"><i class="bi bi-arrow-left"></i></button>
              <button class="btn btn-primary" id="flipBtn"><i class="bi bi-arrow-repeat me-1"></i>Flip</button>
              <button class="btn btn-outline-secondary" id="nextBtn"><i class="bi bi-arrow-right"></i></button>
              <div class="ms-auto small"><span id="idx">0</span>/<span id="total">{len(cards)}</span></div>
            </div>
          </div>
        </div>
      </div></div>
    </div>

    <script>
    (function() {{
      var cards = Array.prototype.slice.call(document.querySelectorAll('#fc-container .fc-card'));
      var i = 0, total = cards.length;
      function show(idx) {{
        cards.forEach(function(el, j) {{
          el.style.display = (j===idx) ? '' : 'none';
          if (j===idx) {{
            el.querySelector('.front').classList.remove('d-none');
            el.querySelector('.back').classList.add('d-none');
          }}
        }});
        document.getElementById('idx').textContent = (total ? idx+1 : 0);
      }}
      function flip() {{
        if (!total) return;
        var cur = cards[i];
        var front = cur.querySelector('.front');
        var back  = cur.querySelector('.back');
        front.classList.toggle('d-none');
        back.classList.toggle('d-none');
      }}
      function next() {{ if (!total) return; i = Math.min(total-1, i+1); show(i); }}
      function prev() {{ if (!total) return; i = Math.max(0, i-1); show(i); }}
      document.getElementById('flipBtn').addEventListener('click', flip);
      document.getElementById('nextBtn').addEventListener('click', next);
      document.getElementById('prevBtn').addEventListener('click', prev);
      show(i);
    }})();
    </script>
    """
    try:
        _log_event(_user_id(), "flashcards.start", {"count": len(cards), "domain": domain})
        # Optional usage bumps; guarded in case helper is defined in a later section.
        _bump_usage("flashcards", len(cards))
    except Exception:
        pass
    return base_layout("Flashcards", content)


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

    if sub == "inactive":
        # Discount code input is only on the Billing page; appended to checkout link via JS.
        plans_html = """
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
            (function() {{
              function goWithCode(href) {{
                var code = (document.getElementById('discount_code')||{{value:''}}).value.trim();
                if (code) {{
                  var url = new URL(href, window.location.origin);
                  url.searchParams.set('code', code);
                  return url.toString();
                }}
                return href;
              }}
              document.querySelectorAll('.upgrade-btn').forEach(function(btn) {{
                btn.addEventListener('click', function(e) {{
                  e.preventDefault();
                  window.location.href = goWithCode(btn.getAttribute('href'));
                }});
              }});
              var apply = document.getElementById('apply_code');
              if (apply) {{
                apply.addEventListener('click', function() {{
                  /* no-op: user still clicks a plan to proceed */
                }});
              }}
            }})();
          </script>
        """
    else:
        plans_html = """
          <div class="alert alert-info border-0">
            <i class="bi bi-info-circle me-2"></i>Your subscription is active. Use support to manage changes.
          </div>
        """

    body = f"""
    <div class="container"><div class="row justify-content-center"><div class="col-lg-8">
      <div class="card">
        <div class="card-header bg-warning text-dark">
          <h3 class="mb-0"><i class="bi bi-credit-card me-2"></i>Billing & Subscription</h3>
        </div>
        <div class="card-body">
          <div class="alert {'alert-success' if sub!='inactive' else 'alert-info'} border-0 mb-4">
            <div class="d-flex align-items-center">
              <i class="bi bi-{'check-circle' if sub!='inactive' else 'info-circle'} fs-4 me-3"></i>
              <div>
                <h6 class="alert-heading mb-1">Current Plan: {names.get(sub, 'Unknown')}</h6>
                <p class="mb-0">{'You have unlimited access to all features.' if sub!='inactive' else 'Limited access — upgrade for unlimited features.'}</p>
              </div>
            </div>
          </div>

          {plans_html}
        </div>
      </div>
    </div></div></div>
    """
    return base_layout("Billing", body)

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
    # STABILITY: guard missing secret
    if not STRIPE_WEBHOOK_SECRET:
        logger.error("Stripe webhook invoked but STRIPE_WEBHOOK_SECRET is not configured.")
        return "", 503

    if not _stripe_ready():
        logger.error("Stripe webhook invoked but Stripe is not configured.")
        return "", 400

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
                logger.info("Stripe event: %s customer=%s plan=%s", etype, customer_id, plan)  # STABILITY: minimal info log
    else:
        # STABILITY: log only type to avoid noisy payloads
        logger.info("Stripe event: %s", etype)

    return "", 200

# STABILITY: exempt webhook from CSRF if CSRFProtect is active
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


# SECTION 6/8 — Content Bank: ingestion, helpers, validation UI
# Route ownership (unique in app):
#   /api/dev/ingest     [POST]  -> JSON ingestion (admin or token)
#   /admin/check-bank   [GET]   -> Admin validation dashboard
#
# Shared helpers:
#   _bank_read_questions(), _bank_save_questions()
#   _bank_read_flashcards(), _bank_save_flashcards()
#   _bump_usage(kind, amount)
#   _update_content_index()

# ---------- Constants & paths ----------
BANK_DIR = _path("bank")
BANK_QUESTIONS = "bank/cpp_questions_v1.json"
BANK_FLASHCARDS = "bank/cpp_flashcards_v1.json"
BANK_INDEX = "bank/content_index.json"

DEV_INGEST_TOKEN = os.environ.get("DEV_INGEST_TOKEN", "")  # optional API token for CI/automation

# Ensure bank directory exists at import time
try:
    os.makedirs(BANK_DIR, exist_ok=True)
except Exception as _e:
    logger.warning("Could not ensure bank dir: %s", _e)

# ---------- Usage bump helper (shared) ----------
def _bump_usage(kind: str, amount: int = 1):
    """
    Increment the current user's monthly usage counters (idempotent on data shape).
    kind: "quizzes" | "questions" | "tutor" | "flashcards"
    """
    uid = _user_id()
    if not uid or amount <= 0:
        return
    # get user by session email (if present) otherwise by uid
    email = session.get("email", "")
    u = _find_user(email) or None
    # fallback: find by id
    if not u:
        for x in _users_all():
            if x.get("id") == uid:
                u = x
                break
    if not u:
        return

    # month key: YYYY-MM
    now = datetime.utcnow()
    mkey = f"{now.year:04d}-{now.month:02d}"

    usage = u.setdefault("usage", {})
    monthly = usage.setdefault("monthly", {})
    rec = monthly.setdefault(mkey, {"quizzes": 0, "questions": 0, "tutor_msgs": 0, "flashcards": 0})

    if kind == "quizzes":
        rec["quizzes"] = int(rec.get("quizzes", 0)) + int(amount)
    elif kind == "questions":
        rec["questions"] = int(rec.get("questions", 0)) + int(amount)
    elif kind == "tutor":
        rec["tutor_msgs"] = int(rec.get("tutor_msgs", 0)) + int(amount)
    elif kind == "flashcards":
        rec["flashcards"] = int(rec.get("flashcards", 0)) + int(amount)
    else:
        return  # unknown kind -> no write

    # persist modified user back to users.json
    try:
        _update_user(u["id"], {"usage": usage})
    except Exception as e:
        logger.warning("Could not bump usage for %s: %s", uid, e)

# ---------- Stable hashes for de-dup ----------
def _q_stable_hash(stem: str, options: dict, correct: str, domain: str) -> str:
    norm_stem = re.sub(r"\s+", " ", (stem or "").strip().lower())
    dom = (domain or "unspecified").strip().lower()
    optA = (options.get("A") or "").strip().lower()
    optB = (options.get("B") or "").strip().lower()
    optC = (options.get("C") or "").strip().lower()
    optD = (options.get("D") or "").strip().lower()
    ans  = (correct or "").strip().upper()
    raw = json.dumps([norm_stem, dom, optA, optB, optC, optD, ans], ensure_ascii=False)
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()

def _fc_stable_hash(front: str, back: str, domain: str) -> str:
    norm_f = re.sub(r"\s+", " ", (front or "").strip().lower())
    norm_b = re.sub(r"\s+", " ", (back  or "").strip().lower())
    dom    = (domain or "unspecified").strip().lower()
    raw = json.dumps([norm_f, norm_b, dom], ensure_ascii=False)
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()

# ---------- Normalizers (bank canonical form) ----------
def _sec6_normalize_question_for_bank(q: dict) -> dict | None:
    if not isinstance(q, dict):
        return None
    stem = (q.get("question") or q.get("q") or "").strip()
    if not stem:
        return None

    opts_in = q.get("options") or q.get("choices") or {}
    opts: dict[str, str] = {}
    if isinstance(opts_in, dict):
        for L in ["A", "B", "C", "D"]:
            v = opts_in.get(L) or opts_in.get(L.lower())
            if not v:
                return None
            opts[L] = str(v).strip()
    elif isinstance(opts_in, list) and len(opts_in) >= 4:
        letters = ["A", "B", "C", "D"]
        for i, L in enumerate(letters):
            v = opts_in[i]
            if isinstance(v, dict):
                text = v.get("text") or v.get("label") or v.get("value")
            else:
                text = v
            if not text:
                return None
            opts[L] = str(text).strip()
    else:
        return None

    correct = (q.get("correct") or q.get("answer") or "").strip().upper()
    if correct not in ("A", "B", "C", "D"):
        try:
            idx = int(correct)
            correct = ["A", "B", "C", "D"][idx - 1]
        except Exception:
            return None

    domain = (q.get("domain") or q.get("category") or "Unspecified").strip()

    sources_in = q.get("sources") or []
    sources: list[dict] = []
    if isinstance(sources_in, list):
        for s in sources_in[:3]:
            t = (s.get("title") or "").strip()
            u = (s.get("url") or "").strip()
            if t and u:
                sources.append({"title": t, "url": u})

    sh = _q_stable_hash(stem, opts, correct, domain)
    return {
        "id": q.get("id") or sh,
        "question": stem,
        "options": opts,
        "correct": correct,
        "domain": domain,
        "sources": sources,
        "_hash": sh
    }

def _sec6_normalize_flashcard_for_bank(fc: dict) -> dict | None:
    if not isinstance(fc, dict):
        return None
    front = (fc.get("front") or fc.get("q") or fc.get("term") or "").strip()
    back  = (fc.get("back")  or fc.get("a") or fc.get("definition") or "").strip()
    if not front or not back:
        return None
    domain = (fc.get("domain") or fc.get("category") or "Unspecified").strip()

    sources_in = fc.get("sources") or []
    sources: list[dict] = []
    if isinstance(sources_in, list):
        for s in sources_in[:3]:
            t = (s.get("title") or "").strip()
            u = (s.get("url") or "").strip()
            if t and u:
                sources.append({"title": t, "url": u})

    sh = _fc_stable_hash(front, back, domain)
    return {
        "id": fc.get("id") or sh,
        "front": front,
        "back": back,
        "domain": domain,
        "sources": sources,
        "_hash": sh
    }

# ---------- File helpers ----------
def _bank_read_questions() -> list[dict]:
    data = _load_json(BANK_QUESTIONS, [])
    return data if isinstance(data, list) else []

def _bank_save_questions(items: list[dict]):
    os.makedirs(os.path.dirname(_path(BANK_QUESTIONS)), exist_ok=True)
    _save_json(BANK_QUESTIONS, items or [])

def _bank_read_flashcards() -> list[dict]:
    data = _load_json(BANK_FLASHCARDS, [])
    return data if isinstance(data, list) else []

def _bank_save_flashcards(items: list[dict]):
    os.makedirs(os.path.dirname(_path(BANK_FLASHCARDS)), exist_ok=True)
    _save_json(BANK_FLASHCARDS, items or [])

def _update_content_index():
    """
    Build a compact content inventory for quick admin checks and tooling.
    Writes bank/content_index.json
    """
    q = _bank_read_questions()
    f = _bank_read_flashcards()
    q_dom: dict[str, int] = {}
    f_dom: dict[str, int] = {}

    for it in q:
        dk = str((it.get("domain") or "Unspecified")).strip()
        q_dom[dk] = q_dom.get(dk, 0) + 1
    for it in f:
        dk = str((it.get("domain") or "Unspecified")).strip()
        f_dom[dk] = f_dom.get(dk, 0) + 1

    idx = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "totals": {"questions": len(q), "flashcards": len(f)},
        "domains": {"questions": q_dom, "flashcards": f_dom},
        "files": {
            "questions": BANK_QUESTIONS,
            "flashcards": BANK_FLASHCARDS
        }
    }
    os.makedirs(os.path.dirname(_path(BANK_INDEX)), exist_ok=True)
    _save_json(BANK_INDEX, idx)

# ---------- Admin validation UI ----------
@app.get("/admin/check-bank", endpoint="sec6_admin_check_bank")
@login_required
def sec6_admin_check_bank():
    if not is_admin():
        return redirect(url_for("sec5_admin_login_page", next=request.path))

    questions = _bank_read_questions()
    flashcards = _bank_read_flashcards()

    # Validate shape and compute duplicates by _hash
    q_dups: dict[str, int] = {}
    f_dups: dict[str, int] = {}
    q_bad, f_bad = [], []

    def _q_valid(x: dict) -> bool:
        try:
            ok = all([
                isinstance(x, dict),
                bool((x.get("question") or "").strip()),
                isinstance(x.get("options"), dict),
                all(x.get("options", {}).get(L) for L in ["A", "B", "C", "D"]),
                (x.get("correct") in ["A", "B", "C", "D"])
            ])
            return ok
        except Exception:
            return False

    def _f_valid(x: dict) -> bool:
        try:
            return all([
                isinstance(x, dict),
                bool((x.get("front") or "").strip()),
                bool((x.get("back") or "").strip())
            ])
        except Exception:
            return False

    for x in questions:
        h = x.get("_hash") or _q_stable_hash(x.get("question",""), x.get("options") or {}, x.get("correct",""), x.get("domain",""))
        x["_hash"] = h
        q_dups[h] = q_dups.get(h, 0) + 1
        if not _q_valid(x):
            q_bad.append(x)

    for x in flashcards:
        h = x.get("_hash") or _fc_stable_hash(x.get("front",""), x.get("back",""), x.get("domain",""))
        x["_hash"] = h
        f_dups[h] = f_dups.get(h, 0) + 1
        if not _f_valid(x):
            f_bad.append(x)

    # Prepare HTML
    q_dup_count = sum(1 for n in q_dups.values() if n > 1)
    f_dup_count = sum(1 for n in f_dups.values() if n > 1)

    # Update index file (side effect)
    try:
        _update_content_index()
    except Exception as e:
        logger.warning("Could not update content index: %s", e)

    idx = _load_json(BANK_INDEX, {})

    def _kv_table(d: dict) -> str:
        rows = []
        for k, v in sorted(d.items()):
            rows.append(f"<tr><td>{html.escape(str(k))}</td><td class='text-end'>{html.escape(str(v))}</td></tr>")
        return "".join(rows) or "<tr><td colspan='2' class='text-center text-muted'>None</td></tr>"

    q_dom_tbl = _kv_table((idx.get("domains") or {}).get("questions", {}))
    f_dom_tbl = _kv_table((idx.get("domains") or {}).get("flashcards", {}))

    # Show first few bad entries (escaped JSON)
    def _preview(items: list[dict], limit: int = 5) -> str:
        if not items:
            return "<div class='text-muted'>None</div>"
        out = []
        for x in items[:limit]:
            out.append(f"<pre class='small bg-light p-2 rounded'>{html.escape(json.dumps(x, ensure_ascii=False, indent=2))}</pre>")
        if len(items) > limit:
            out.append(f"<div class='small text-muted'>…and {len(items)-limit} more</div>")
        return "".join(out)

    body = f"""
    <div class="container"><div class="row justify-content-center"><div class="col-xl-10">
      <div class="card">
        <div class="card-header bg-dark text-white">
          <h3 class="mb-0"><i class="bi bi-search me-2"></i>Content Bank — Validation</h3>
        </div>
        <div class="card-body">
          <div class="row g-3 mb-3">
            <div class="col-md-3"><div class="p-3 border rounded-3">
              <div class="small text-muted">Questions</div>
              <div class="h5 mb-0">{len(questions)}</div>
            </div></div>
            <div class="col-md-3"><div class="p-3 border rounded-3">
              <div class="small text-muted">Flashcards</div>
              <div class="h5 mb-0">{len(flashcards)}</div>
            </div></div>
            <div class="col-md-3"><div class="p-3 border rounded-3">
              <div class="small text-muted">Q duplicates</div>
              <div class="h5 mb-0">{q_dup_count}</div>
            </div></div>
            <div class="col-md-3"><div class="p-3 border rounded-3">
              <div class="small text-muted">FC duplicates</div>
              <div class="h5 mb-0">{f_dup_count}</div>
            </div></div>
          </div>

          <div class="row g-3">
            <div class="col-lg-6">
              <div class="p-3 border rounded-3">
                <div class="fw-semibold mb-2">Questions by Domain</div>
                <div class="table-responsive">
                  <table class="table table-sm align-middle">
                    <thead><tr><th>Domain</th><th class="text-end">Count</th></tr></thead>
                    <tbody>{q_dom_tbl}</tbody>
                  </table>
                </div>
              </div>
            </div>
            <div class="col-lg-6">
              <div class="p-3 border rounded-3">
                <div class="fw-semibold mb-2">Flashcards by Domain</div>
                <div class="table-responsive">
                  <table class="table table-sm align-middle">
                    <thead><tr><th>Domain</th><th class="text-end">Count</th></tr></thead>
                    <tbody>{f_dom_tbl}</tbody>
                  </table>
                </div>
              </div>
            </div>
          </div>

          <div class="row g-3 mt-2">
            <div class="col-lg-6">
              <div class="p-3 border rounded-3">
                <div class="fw-semibold mb-2">Invalid Questions (first 5)</div>
                {_preview(q_bad, 5)}
              </div>
            </div>
            <div class="col-lg-6">
              <div class="p-3 border rounded-3">
                <div class="fw-semibold mb-2">Invalid Flashcards (first 5)</div>
                {_preview(f_bad, 5)}
              </div>
            </div>
          </div>

          <a href="/" class="btn btn-outline-secondary mt-3"><i class="bi bi-house me-1"></i>Home</a>
        </div>
      </div>
    </div></div></div>
    """
    return base_layout("Admin • Check Bank", body)

# ---------- Ingestion API (admin or token) ----------
@app.post("/api/dev/ingest", endpoint="sec6_api_dev_ingest")
def sec6_api_dev_ingest():
    """
    JSON API to ingest new content into the bank.
    Auth:
      - If an admin session exists -> allowed.
      - Else, require header 'X-Ingest-Token: <DEV_INGEST_TOKEN>' (if configured).
    Payload (application/json):
      {
        "questions": [ {question, options{A..D}, correct, domain, sources[]?}, ... ],
        "flashcards": [ {front, back, domain, sources[]?}, ... ]
      }
    Behavior:
      - Normalize each item into canonical bank shape.
      - De-duplicate by stable '_hash'.
      - Append new items, keep existing on collisions.
      - Rebuild content_index.json.
      - Returns a summary report.
    Rate limiting: 1 request / 2 seconds per IP.
    """
    # Simple rate limit (per IP + path)
    rip = request.headers.get("X-Forwarded-For", request.remote_addr or "0.0.0.0").split(",")[0].strip()
    rkey = f"ingest:{rip}"
    if not _rate_ok(rkey, per_sec=0.5):  # = 1 every 2 seconds
        return jsonify({"ok": False, "error": "rate_limited"}), 429

    # Authz
    token_ok = False
    got = request.headers.get("X-Ingest-Token", "")
    if DEV_INGEST_TOKEN and got and got == DEV_INGEST_TOKEN:
        token_ok = True
    if not (is_admin() or token_ok):
        return jsonify({"ok": False, "error": "forbidden"}), 403

    if request.content_type and "application/json" not in request.content_type:
        return jsonify({"ok": False, "error": "content_type"}), 400

    try:
        payload = request.get_json(silent=True) or {}
    except Exception:
        payload = {}

    q_in = payload.get("questions") or []
    f_in = payload.get("flashcards") or []
    if not isinstance(q_in, list) and not isinstance(f_in, list):
        return jsonify({"ok": False, "error": "invalid_payload"}), 400

    # Load existing
    q_cur = _bank_read_questions()
    f_cur = _bank_read_flashcards()

    q_seen = {x.get("_hash") or _q_stable_hash(x.get("question",""), x.get("options") or {}, x.get("correct",""), x.get("domain","")) for x in q_cur}
    f_seen = {x.get("_hash") or _fc_stable_hash(x.get("front",""), x.get("back",""), x.get("domain","")) for x in f_cur}

    # Normalize & collect
    q_add, q_bad = [], []
    f_add, f_bad = [], []

    for x in (q_in if isinstance(q_in, list) else []):
        n = _sec6_normalize_question_for_bank(x)
        if not n:
            q_bad.append(x)
            continue
        if n["_hash"] in q_seen:
            continue
        q_seen.add(n["_hash"])
        q_add.append(n)

    for x in (f_in if isinstance(f_in, list) else []):
        n = _sec6_normalize_flashcard_for_bank(x)
        if not n:
            f_bad.append(x)
            continue
        if n["_hash"] in f_seen:
            continue
        f_seen.add(n["_hash"])
        f_add.append(n)

    # Persist
    if q_add:
        q_new = q_cur + q_add
        _bank_save_questions(q_new)
    if f_add:
        f_new = f_cur + f_add
        _bank_save_flashcards(f_new)

    # Update index
    try:
        _update_content_index()
    except Exception as e:
        logger.warning("Index update failed after ingestion: %s", e)

    report = {
        "ok": True,
        "added": {"questions": len(q_add), "flashcards": len(f_add)},
        "skipped_invalid": {"questions": len(q_bad), "flashcards": len(f_bad)},
        "totals": {
            "questions": len(_bank_read_questions()),
            "flashcards": len(_bank_read_flashcards())
        }
    }
    # Event log (best-effort)
    try:
        _log_event(_user_id(), "bank.ingest", report)
    except Exception:
        pass

    return jsonify(report), 200

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

# SECTION 8/8 — Public Login & Logout (final glue)
# Route ownership (unique in app):
#   /login   [GET, POST]  (endpoint name must remain sec1_login_page for compatibility)
#   /logout  [GET]
#
# NOTE:
# - To avoid route collisions and preserve your current design, this section
#   does NOT redefine "/" (Home) or "/legal/terms" because they are already
#   present in Section 1 in your codebase.

# Ensure required data files exist (idempotent, safe on reload)
try:
    init_sample_data()
except Exception as _e:
    try:
        logger.warning("init_sample_data at Section 8 failed: %s", _e)
    except Exception:
        pass

# ---------- Helpers ----------
def _safe_next(next_val: str | None) -> str:
    nv = (next_val or "").strip()
    if nv.startswith("/") and not nv.startswith("//"):
        return nv
    return "/"

def _auth_set_session(user: dict) -> None:
    session["uid"] = user.get("id", "")
    session["email"] = user.get("email", "")

def _auth_clear_session() -> None:
    session.pop("uid", None)
    session.pop("email", None)
    session.pop("admin_ok", None)

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
            <a class="btn btn-outline-secondary ms-2" href="/"><i class="bi bi-house me-1"></i>Home</a>
          </form>
        </div>
      </div>
    </div></div></div>
    """
    return base_layout("Login", content)

@app.post("/login", endpoint="sec1_login_post")
def sec1_login_post():
    # CSRF (Flask-WTF enforces if installed; fallback token check when not installed)
    if not _csrf_ok():
        abort(403)

    # Basic rate limit (per-IP): 1 attempt / 2 seconds
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

    # Success
    _auth_set_session(u)
    try:
        _log_event(_user_id(), "auth.login", {})
    except Exception:
        pass
    return redirect(nxt or "/")

# ---------- LOGOUT ----------
@app.get("/logout", endpoint="sec1_logout")
def sec1_logout():
    try:
        _log_event(_user_id(), "auth.logout", {})
    except Exception:
        pass
    _auth_clear_session()
    return redirect("/")



