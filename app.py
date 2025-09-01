# =========================
# SECTION 1/8: Imports, App Config, Utilities, Security, Base Layout (+ Footer)
# =========================

import os, re, json, time, uuid, hashlib, random, html, logging, requests
from datetime import datetime, timedelta
from typing import Any, Dict, List, Tuple

from flask import (
    Flask, request, session, redirect, url_for, abort, jsonify, make_response
)
from flask import render_template_string
from werkzeug.security import generate_password_hash, check_password_hash

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

# ---- Paths & Data ----
DATA_DIR = os.path.join(os.getcwd(), "data")
os.makedirs(DATA_DIR, exist_ok=True)

# ---- Feature Flags / Keys (non-secret display only) ----
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
OPENAI_API_BASE = os.environ.get("OPENAI_API_BASE", "https://api.openai.com/v1")
OPENAI_CHAT_MODEL = os.environ.get("OPENAI_CHAT_MODEL", "gpt-4o-mini")

STRIPE_PUBLISHABLE_KEY = os.environ.get("STRIPE_PUBLISHABLE_KEY", "")
STRIPE_MONTHLY_PRICE_ID = os.environ.get("STRIPE_MONTHLY_PRICE_ID", "")
STRIPE_SIXMONTH_PRICE_ID = os.environ.get("STRIPE_SIXMONTH_PRICE_ID", "")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")

ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")

# ---- CSRF (lightweight helper; supports Flask-WTF style if present) ----
try:
    from flask_wtf import CSRFProtect
    csrf = CSRFProtect(app)
    HAS_CSRF = True
except Exception:
    csrf = None
    HAS_CSRF = False

def csrf_token() -> str:
    val = session.get("_csrf_token")
    if not val:
        val = uuid.uuid4().hex
        session["_csrf_token"] = val
    return val

def _csrf_ok() -> bool:
    if HAS_CSRF:
        return True  # Flask-WTF will enforce automatically
    # Minimal fallback
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

# ---- Security Headers & CSP ----
CSP = "default-src 'self' https:; img-src 'self' data: https:; style-src 'self' 'unsafe-inline' https:; script-src 'self' 'unsafe-inline' https:; frame-src https:; connect-src 'self' https:"

@app.after_request
def sec1_after_request(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer-when-downgrade"
    resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    resp.headers["Content-Security-Policy"] = CSP
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

def _save_json(name: str, data):
    p = _path(name)
    try:
        with open(p, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
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
        # T&C acceptance (gate enforcement)
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
def _user_id() -> str:
    return session.get("uid", "")

def login_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not _user_id():
            return redirect(url_for("sec2_login_page"))
        return fn(*args, **kwargs)
    return wrapper

def is_admin() -> bool:
    return bool(session.get("admin_ok"))

# ---- Events / Usage (minimal) ----
def _log_event(uid: str, name: str, data: dict | None = None):
    evts = _load_json("events.json", [])
    evts.append({
        "ts": datetime.utcnow().isoformat() + "Z",
        "user_id": uid,
        "name": name,
        "data": data or {}
    })
    _save_json("events.json", evts)

# ---- Domain labels ----
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

# ---- Domain Buttons helper ----
def domain_buttons_html(selected_key="random", field_name="domain"):
    # The hidden input stores the selected domain key
    btns = []
    for key, label in DOMAINS.items():
        if key == "random":
            # Only show as "Random" (not in DOMAINS headings)
            continue
    # Keep "random" plus the rest in a nice order
    order = ["random","security-principles","business-principles","investigations",
             "personnel-security","physical-security","information-security","crisis-management"]
    b = []
    for k in order:
        lab = "Random (all)" if k == "random" else DOMAINS.get(k, k)
        active = " active" if selected_key == k else ""
        b.append(f'<button type="button" class="btn btn-outline-success domain-btn{active}" data-value="{html.escape(k)}">{html.escape(lab)}</button>')
    hidden = f'<input type="hidden" id="domain_val" name="{html.escape(field_name)}" value="{html.escape(selected_key)}"/>'
    return f'<div class="d-flex flex-wrap gap-2">{ "".join(b) }</div>{hidden}'

# ---- Global Footer (short, protective disclaimer) ----
def _footer_html():
    # Short, clear liability notice – added to all pages to reduce risk.
    return """
    <footer class="mt-5 py-3 border-top text-center small text-muted">
      <div>
        Educational use only. Not affiliated with ASIS. No legal, safety, or professional advice.
        Use official sources to verify. No refunds. © CPP-Exam-Prep
      </div>
    </footer>
    """

# ---- Base Layout with bootstrap & footer ----
def base_layout(title: str, body_html: str) -> str:
    t = html.escape(title or "CPP Exam Prep")
    return render_template_string(f"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{{{title}}}} — CPP Exam Prep</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css" rel="stylesheet">
  <style>
    .fc-card .front, .fc-card .back {{ min-height: 120px; padding: 1rem; border: 1px solid #ddd; border-radius: .5rem; }}
    .fc-card .front {{ background: #f8f9fa; }}
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
        {{% if session.get('uid') %}}
          <a class="btn btn-outline-danger btn-sm" href="/logout">Logout</a>
        {{% else %}}
          <a class="btn btn-outline-primary btn-sm" href="/login">Login</a>
        {{% endif %}}
      </div>
    </div>
  </nav>

  <main class="py-4">
    {body_html}
  </main>

  {_footer_html()}

  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
    """, title=t)

# ---- Domain weights (for Content Balance) ----
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
        # Core files
        for name, default in [
            ("users.json", []),
            ("questions.json", []),      # legacy optional
            ("flashcards.json", []),     # legacy optional
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

# ========== SECTION 2/8 — Operational & Security Utilities ==========
# OWNER NOTE:
#   - This section is the SINGLE OWNER of the following routes:
#       * GET /healthz
#       * GET /robots.txt
#       * GET /favicon.ico
#   - Do NOT define these routes in any other section. Route endpoints are
#     uniquely named with a "sec2_" prefix to avoid Flask endpoint collisions.

import time
from datetime import datetime, timezone
from flask import jsonify, make_response, Response

# Monotonic start reference for uptime (local to Section 2)
_SEC2_START_TS = time.time()

def _sec2_safe_get(name: str, default=None):
    """Small helper to read globals if they exist without import-order issues."""
    return globals().get(name, default)

@app.get("/healthz", endpoint="sec2_healthz")
def sec2_healthz():
    """
    Lightweight liveness probe.
    Returns only static/low-cost info suitable for Render/ingress health checks.
    """
    now = time.time()
    uptime_s = int(now - _SEC2_START_TS)
    # Try to read shared metadata defined in Section 1; fall back safely.
    app_version = _sec2_safe_get("APP_VERSION", "unknown")
    debug_mode = bool(_sec2_safe_get("DEBUG", False))
    is_staging = bool(_sec2_safe_get("IS_STAGING", False))

    return jsonify({
        "ok": True,
        "service": "cpp-exam-prep",
        "version": str(app_version),
        "debug": debug_mode,
        "staging": is_staging,
        "started_at": datetime.fromtimestamp(_SEC2_START_TS, tz=timezone.utc).isoformat(),
        "uptime_seconds": uptime_s,
    })

@app.get("/robots.txt", endpoint="sec2_robots_txt")
def sec2_robots_txt():
    """
    Simple robots policy. Kept here to avoid 404 noise and make crawlers explicit.
    """
    body = "User-agent: *\nDisallow: /admin/\nDisallow: /api/\n"
    resp = make_response(body, 200)
    resp.headers["Content-Type"] = "text/plain; charset=utf-8"
    return resp

@app.get("/favicon.ico", endpoint="sec2_favicon")
def sec2_favicon():
    """
    Favicon handler to stop 404 spam. If a static favicon pipeline exists elsewhere,
    you can replace this with a send_file from the static directory.
    For now, return 204 (No Content) which browsers accept gracefully.
    """
    # If you later add a real icon, swap to:
    #   from flask import send_from_directory
    #   return send_from_directory("static", "favicon.ico")
    return Response(status=204)

# ---- Security Headers / CSP (idempotent) ------------------------------------
# This after_request is additive and safe to run alongside others. If another
# section sets some of these headers, we leave existing values intact.

@app.after_request
def sec2_apply_security_headers(resp):
    # Content Security Policy (conservative; align with your assets)
    csp = (
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
    resp.headers.setdefault("Content-Security-Policy", csp)

    # Common hardening headers (only set if not already present)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault("Permissions-Policy",
                            "geolocation=(), microphone=(), camera=()")
    # HSTS only if HTTPS is expected in your deployment
    if _sec2_safe_get("ENABLE_HSTS", True):
        resp.headers.setdefault("Strict-Transport-Security",
                                "max-age=63072000; includeSubDomains; preload")
    return resp
# ========================= END SECTION 2/8 =========================
# =========================
# SECTION 3/8: Quizzes & Mock Exams (picker, run, scoring)  [Owner of /quiz and /mock-exam]
# Naming: all endpoints in this section are prefixed with `sec3_` to avoid collisions.
# URLs are preserved for UX; only the Flask endpoint (function name) changes.
# =========================

from flask import request, abort, redirect, url_for
import json
import html
import random
from datetime import datetime

# ---- Helpers local to quizzes ----

def _sec3_detect_qtype(q: dict) -> str:
    """
    Infer question type for allocation/UX:
      - 'tf' for true/false (2 options with True/False-like text)
      - 'scenario' if stem starts with "Scenario:" or contains clear scenario cue
      - 'mcq' otherwise
    """
    try:
        stem = (q.get("question") or "").strip()
        opts = q.get("options") or {}
        # True/False if exactly two non-empty options and they look like T/F
        opt_texts = [str(opts.get(k,"")).strip().lower() for k in ["A","B","C","D"] if opts.get(k)]
        non_empty = [t for t in opt_texts if t]
        if len(non_empty) == 2:
            tf_tokens = {"true", "false", "t", "f"}
            if all(any(tok in t.split() for tok in tf_tokens) for t in non_empty):
                return "tf"
        # Scenario cue
        if stem.lower().startswith("scenario:") or "what should" in stem.lower():
            return "scenario"
    except Exception:
        pass
    return "mcq"

def _sec3_filter_questions(domain_key: str, type_key: str) -> list[dict]:
    """
    Pull from bank (preferred) and optionally legacy questions.json if present.
    Filter by domain (exact match on stored key) and by inferred type.
    """
    pool = []

    try:
        # Prefer bank (added in Section 6)
        bank_q = _bank_read_questions()
        pool.extend(bank_q or [])
    except Exception:
        pass

    try:
        # Legacy fallback if exists
        legacy = _load_json("questions.json", [])
        if isinstance(legacy, list):
            pool.extend(legacy)
    except Exception:
        pass

    # Domain filter
    if domain_key and domain_key not in ("random", "mixed", "all"):
        dk = str(domain_key).strip().lower()
        pool = [q for q in pool if str((q.get("domain") or "Unspecified")).strip().lower() == dk]

    # Type filter
    tkey = (type_key or "mixed").strip().lower()
    if tkey in ("mcq", "tf", "scenario"):
        pool = [q for q in pool if _sec3_detect_qtype(q) == tkey]

    # Deduplicate by stable hash if Section 6 helpers exist; otherwise by tuple
    seen = set()
    uniq = []
    for q in pool:
        try:
            if "_hash" in q:
                h = q["_hash"]
            else:
                # lightweight key
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

def _sec3_sample(pool: list[dict], n: int) -> list[dict]:
    pool = pool[:]  # copy
    random.shuffle(pool)
    return pool[:max(0, min(n, len(pool)))]

def _sec3_render_question_block(q: dict, idx: int) -> str:
    """Return HTML for one question (radio group)."""
    stem = html.escape(q.get("question","").strip())
    opts = q.get("options") or {}
    opts_html = []
    for letter in ["A","B","C","D"]:
        if not opts.get(letter):
            continue
        val = html.escape(str(opts[letter]))
        opts_html.append(
            f"""
            <div class="form-check">
              <input class="form-check-input" type="radio" name="q{idx}" id="q{idx}_{letter}" value="{letter}">
              <label class="form-check-label" for="q{idx}_{letter}"><span class="fw-semibold">{letter}.</span> {val}</label>
            </div>
            """
        )
    # Domain tag + inferred type (subtle)
    dom = html.escape(q.get("domain","Unspecified"))
    qtype = _sec3_detect_qtype(q)
    meta = f'<div class="small text-muted mt-1">Domain: <span class="fw-semibold">{dom}</span> • Type: {qtype.upper()}</div>'
    return f"""
    <div class="mb-4 p-3 border rounded-3">
      <div class="fw-semibold mb-2">{idx+1}. {stem}</div>
      {''.join(opts_html) if opts_html else '<div class="text-muted">No options found for this item.</div>'}
      {meta}
    </div>
    """

def _sec3_grade(questions: list[dict], answers: dict) -> tuple[int, dict]:
    """
    Returns (correct_count, domain_breakdown)
    domain_breakdown = {domain: {"correct": c, "total": t}}
    """
    correct = 0
    dom = {}
    for i, q in enumerate(questions):
        dom_name = (q.get("domain") or "Unspecified")
        dstat = dom.setdefault(dom_name, {"correct": 0, "total": 0})
        dstat["total"] += 1
        user_ans = (answers.get(f"q{i}") or "").strip().upper()
        if user_ans and user_ans == (q.get("correct") or "").strip().upper():
            correct += 1
            dstat["correct"] += 1
    return correct, dom

def _sec3_attempt_record(mode: str, questions: list[dict], correct: int, domains: dict) -> dict:
    """Build and persist an attempt into attempts.json for /progress page."""
    total = len(questions)
    pct = round(100.0 * correct / total, 1) if total else 0.0
    by_types = {"mcq": 0, "tf": 0, "scenario": 0}
    for q in questions:
        by_types[_sec3_detect_qtype(q)] = by_types.get(_sec3_detect_qtype(q), 0) + 1

    rec = {
        "ts": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "user_id": _user_id(),
        "mode": mode,
        "count": total,
        "correct": correct,
        "score_pct": pct,
        "domains": domains,
        "types": by_types
    }
    data = _load_json("attempts.json", [])
    if isinstance(data, list):
        data.append(rec)
        _save_json("attempts.json", data)
    try:
        # increment user usage counters (monthly)
        _bump_usage("questions", total)
    except Exception:
        pass
    _log_event(_user_id(), "quiz.complete", {"mode": mode, "count": total, "correct": correct, "pct": pct})
    return rec


# ---- Routes: Quiz Picker & Runner ----

@app.get("/quiz")
@login_required
def sec3_quiz_picker_get():
    """Quiz Picker UI (domain + type + count)."""
    csrf_val = csrf_token()
    domain_buttons = domain_buttons_html(selected_key="random", field_name="domain")
    content = f"""
    <div class="container">
      <div class="row justify-content-center"><div class="col-lg-8 col-xl-7">
        <div class="card">
          <div class="card-header bg-primary text-white">
            <h3 class="mb-0"><i class="bi bi-ui-checks-grid me-2"></i>Quiz Builder</h3>
          </div>
          <div class="card-body">
            <form method="POST" action="/quiz">
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
            <div class="text-muted small mt-3">Tip: Pick a domain to focus, or leave Random for a mix.</div>
          </div>
        </div>
      </div></div>
    </div>

    <script>
      (function(){{
        var card = document.currentScript.closest('.card');
        var body = card.querySelector('.card-body');
        var tHidden = body.querySelector('#type_val');
        body.querySelectorAll('.type-btn').forEach(function(b){{
          b.addEventListener('click', function(){{
            body.querySelectorAll('.type-btn').forEach(function(x){{ x.classList.remove('active'); }});
            b.classList.add('active');
            if (tHidden) tHidden.value = b.getAttribute('data-value');
          }});
        }});
      }})();
    </script>
    """
    return base_layout("Quiz", content)

@app.post("/quiz")
@login_required
def sec3_quiz_start_post():
    """Build a one-shot quiz (no server state) and render it."""
    if not _csrf_ok():
        abort(403)

    # Parse inputs
    domain = (request.form.get("domain") or "random").strip()
    qtype = (request.form.get("qtype") or "mixed").strip().lower()
    try:
        count = int(request.form.get("count") or 20)
    except Exception:
        count = 20
    if count not in (10, 20, 30, 50):
        count = 20

    # Filter pool
    pool = _sec3_filter_questions(domain, qtype)
    random.shuffle(pool)
    questions = _sec3_sample(pool, count)

    # Prepare lightweight payload for grading (only necessary fields)
    payload_items = []
    for q in questions:
        payload_items.append({
            "question": q.get("question",""),
            "options": {k: q.get("options",{}).get(k,"") for k in ["A","B","C","D"]},
            "correct": q.get("correct","").strip().upper(),
            "domain": q.get("domain","Unspecified")
        })
    payload = html.escape(json.dumps(payload_items, ensure_ascii=False))

    # Render quiz form
    qblocks = "".join(_sec3_render_question_block(q, i) for i, q in enumerate(questions)) or "<div class='text-muted'>No questions available.</div>"
    content = f"""
    <div class="container">
      <div class="row justify-content-center"><div class="col-xl-10">
        <div class="card">
          <div class="card-header bg-primary text-white d-flex justify-content-between align-items-center">
            <h3 class="mb-0"><i class="bi bi-ui-checks-grid me-2"></i>Quiz</h3>
            <a href="/quiz" class="btn btn-outline-light btn-sm">New Quiz</a>
          </div>
          <div class="card-body">
            <div class="small text-muted mb-3">
              Domain: <strong>{html.escape(DOMAINS.get(domain, 'Mixed')) if domain!='random' else 'Random (all)'}</strong> •
              Type: <strong>{html.escape(qtype.capitalize()) if qtype!='mixed' else 'Mixed'}</strong> •
              Count: <strong>{len(questions)}</strong>
            </div>

            <form method="POST" action="/quiz/grade">
              <input type="hidden" name="csrf_token" value="{csrf_token()}"/>
              <textarea name="payload" class="d-none">{payload}</textarea>
              {qblocks}
              <div class="d-flex gap-2">
                <button class="btn btn-success" type="submit"><i class="bi bi-clipboard-check me-1"></i>Grade</button>
                <a class="btn btn-outline-secondary" href="/quiz"><i class="bi bi-arrow-left me-1"></i>Back</a>
              </div>
            </form>
          </div>
        </div>
      </div></div>
    </div>
    """
    _log_event(_user_id(), "quiz.start", {"count": len(questions), "domain": domain, "type": qtype})
    try:
        _bump_usage("quizzes", 1)
        _bump_usage("questions", len(questions))
    except Exception:
        pass
    return base_layout("Quiz", content)

@app.post("/quiz/grade")
@login_required
def sec3_quiz_grade_post():
    """Grade the posted quiz payload."""
    if not _csrf_ok():
        abort(403)

    raw = request.form.get("payload") or "[]"
    try:
        questions = json.loads(raw)
        if not isinstance(questions, list):
            questions = []
    except Exception:
        questions = []

    # Collect answers
    answers = {}
    for i in range(len(questions)):
        answers[f"q{i}"] = (request.form.get(f"q{i}") or "").strip().upper()

    correct, dom = _sec3_grade(questions, answers)
    rec = _sec3_attempt_record("quiz", questions, correct, dom)

    # Build per-domain rows
    def pct(c, t): return f"{(100.0*c/t):.1f}%" if t else "0.0%"
    drows = []
    for dname in sorted(dom.keys()):
        c = dom[dname]["correct"]; t = dom[dname]["total"]
        drows.append(f"<tr><td>{html.escape(dname)}</td><td class='text-end'>{c}/{t}</td><td class='text-end'>{pct(c,t)}</td></tr>")
    dtable = "".join(drows) or "<tr><td colspan='3' class='text-center text-muted'>None</td></tr>"

    # Results UI
    total = len(questions)
    pct_str = f"{rec['score_pct']:.1f}%"
    content = f"""
    <div class="container">
      <div class="row justify-content-center"><div class="col-lg-8 col-xl-7">
        <div class="card">
          <div class="card-header bg-success text-white">
            <h3 class="mb-0"><i class="bi bi-clipboard-check me-2"></i>Your Results</h3>
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
              <a class="btn btn-primary" href="/quiz"><i class="bi bi-arrow-repeat me-1"></i>New Quiz</a>
              <a class="btn btn-outline-secondary" href="/progress"><i class="bi bi-graph-up-arrow me-1"></i>Progress</a>
              <a class="btn btn-outline-secondary" href="/"><i class="bi bi-house me-1"></i>Home</a>
            </div>
          </div>
        </div>
      </div></div>
    </div>
    """
    return base_layout("Quiz Results", content)


# ---- Routes: Mock Exam (longer form, same engine) ----

@app.get("/mock-exam")
@login_required
def sec3_mock_picker_get():
    """Mock Exam launcher (fixed longer count, mixed types, random domain)."""
    csrf_val = csrf_token()
    # fixed options common in many mock setups
    content = f"""
    <div class="container">
      <div class="row justify-content-center"><div class="col-lg-8 col-xl-7">
        <div class="card">
          <div class="card-header bg-warning text-dark">
            <h3 class="mb-0"><i class="bi bi-mortarboard me-2"></i>Mock Exam</h3>
          </div>
          <div class="card-body">
            <form method="POST" action="/mock-exam">
              <input type="hidden" name="csrf_token" value="{csrf_val}"/>
              <div class="mb-2 text-muted small">
                A longer, mixed-domain practice. Choose how many questions:
              </div>
              <div class="d-flex gap-2 flex-wrap">
                <button class="btn btn-outline-warning" name="count" value="50">50</button>
                <button class="btn btn-outline-warning" name="count" value="100">100</button>
                <button class="btn btn-outline-warning" name="count" value="150">150</button>
              </div>
            </form>
            <div class="text-muted small mt-3">Scored and saved to your Progress like any quiz.</div>
          </div>
        </div>
      </div></div>
    </div>
    """
    return base_layout("Mock Exam", content)

@app.post("/mock-exam")
@login_required
def sec3_mock_start_post():
    """Start a mock exam with mixed types/domains."""
    if not _csrf_ok():
        abort(403)
    try:
        count = int(request.form.get("count") or 100)
    except Exception:
        count = 100
    if count not in (50, 100, 150):
        count = 100

    pool = _sec3_filter_questions("random", "mixed")
    random.shuffle(pool)
    questions = _sec3_sample(pool, count)

    # Build payload
    payload_items = [{
        "question": q.get("question",""),
        "options": {k: q.get("options",{}).get(k,"") for k in ["A","B","C","D"]},
        "correct": q.get("correct","").strip().upper(),
        "domain": q.get("domain","Unspecified")
    } for q in questions]
    payload = html.escape(json.dumps(payload_items, ensure_ascii=False))

    # Render
    qblocks = "".join(_sec3_render_question_block(q, i) for i, q in enumerate(questions))
    content = f"""
    <div class="container">
      <div class="row justify-content-center"><div class="col-xl-10">
        <div class="card">
          <div class="card-header bg-warning text-dark d-flex justify-content-between align-items-center">
            <h3 class="mb-0"><i class="bi bi-mortarboard me-2"></i>Mock Exam</h3>
            <a href="/mock-exam" class="btn btn-outline-dark btn-sm">New Mock</a>
          </div>
          <div class="card-body">
            <div class="small text-muted mb-3">Mixed domains • Mixed types • Count: <strong>{len(questions)}</strong></div>
            <form method="POST" action="/mock-exam/grade">
              <input type="hidden" name="csrf_token" value="{csrf_token()}"/>
              <textarea name="payload" class="d-none">{payload}</textarea>
              {qblocks}
              <div class="d-flex gap-2">
                <button class="btn btn-success" type="submit"><i class="bi bi-clipboard-check me-1"></i>Grade</button>
                <a class="btn btn-outline-secondary" href="/mock-exam"><i class="bi bi-arrow-left me-1"></i>Back</a>
              </div>
            </form>
          </div>
        </div>
      </div></div>
    </div>
    """
    _log_event(_user_id(), "mock.start", {"count": len(questions)})
    try:
        _bump_usage("quizzes", 1)
        _bump_usage("questions", len(questions))
    except Exception:
        pass
    return base_layout("Mock Exam", content)

@app.post("/mock-exam/grade")
@login_required
def sec3_mock_grade_post():
    """Grade a mock exam."""
    if not _csrf_ok():
        abort(403)

    raw = request.form.get("payload") or "[]"
    try:
        questions = json.loads(raw)
        if not isinstance(questions, list):
            questions = []
    except Exception:
        questions = []

    answers = {f"q{i}": (request.form.get(f"q{i}") or "").strip().upper() for i in range(len(questions))}
    correct, dom = _sec3_grade(questions, answers)
    rec = _sec3_attempt_record("mock", questions, correct, dom)

    def pct(c, t): return f"{(100.0*c/t):.1f}%" if t else "0.0%"
    drows = []
    for dname in sorted(dom.keys()):
        c = dom[dname]["correct"]; t = dom[dname]["total"]
        drows.append(f"<tr><td>{html.escape(dname)}</td><td class='text-end'>{c}/{t}</td><td class='text-end'>{pct(c,t)}</td></tr>")
    dtable = "".join(drows) or "<tr><td colspan='3' class='text-center text-muted'>None</td></tr>"

    total = len(questions)
    pct_str = f"{rec['score_pct']:.1f}%"
    content = f"""
    <div class="container">
      <div class="row justify-content-center"><div class="col-lg-8 col-xl-7">
        <div class="card">
          <div class="card-header bg-success text-white">
            <h3 class="mb-0"><i class="bi bi-clipboard-check me-2"></i>Mock Results</h3>
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
              <a class="btn btn-warning" href="/mock-exam"><i class="bi bi-mortarboard me-1"></i>New Mock</a>
              <a class="btn btn-outline-secondary" href="/progress"><i class="bi bi-graph-up-arrow me-1"></i>Progress</a>
              <a class="btn btn-outline-secondary" href="/"><i class="bi bi-house me-1"></i>Home</a>
            </div>
          </div>
        </div>
      </div></div>
    </div>
    """
    return base_layout("Mock Results", content)
# =========================
# SECTION 4/8: Public pages & Legal Gate (OWNER of "/")
# =========================
#
# Route-ownership note:
# - This section is the ONLY owner of "/" (root). Do not define "/" in any other section.
# - Endpoint names are prefixed with "sec4_" to avoid accidental reuse.
#
# Purpose:
# - Serve a Welcome/Disclaimer landing page at "/".
# - Show T&C link and lightweight CTA buttons (Login / Sign Up).
# - If a user is logged in and has accepted Terms, show quick links into the app.
# - This page does NOT bypass the existing hard gate; the hard enforcement still lives in the
#   auth flows (signup checkbox + post-login /legal/accept redirect if needed).
#
# Dependencies:
# - base_layout(title, body_html) helper already defined earlier.
# - _find_user(email) helper already defined earlier.
# - session from Flask.
# - DO NOT import or redefine terms pages here; /legal/terms is owned by the Legal section.
#

@app.get("/")
def sec4_root_welcome_get():
    user_email = session.get("email", "")
    u = _find_user(user_email) if user_email else None
    terms_ok = bool(u and u.get("terms_accept_version"))

    # CTA block varies a bit if user is logged in and has accepted Terms.
    if u and terms_ok:
        # Keep UI minimal and consistent; we don't change the rest of the app UX.
        ctas = """
          <div class="d-flex flex-wrap gap-2 mt-3">
            <a href="/tutor" class="btn btn-primary"><i class="bi bi-mortarboard me-1"></i>Tutor</a>
            <a href="/quiz" class="btn btn-outline-primary"><i class="bi bi-ui-checks-grid me-1"></i>Quizzes</a>
            <a href="/flashcards" class="btn btn-outline-success"><i class="bi bi-layers me-1"></i>Flashcards</a>
            <a href="/progress" class="btn btn-outline-info"><i class="bi bi-graph-up-arrow me-1"></i>Progress</a>
            <a href="/billing" class="btn btn-outline-warning"><i class="bi bi-credit-card me-1"></i>Billing</a>
          </div>
        """
        user_line = f"<div class='small text-muted mt-2'>Signed in as <strong>{html.escape(user_email)}</strong>.</div>"
    else:
        ctas = """
          <div class="d-flex flex-wrap gap-2 mt-3">
            <a href="/signup" class="btn btn-primary"><i class="bi bi-person-plus me-1"></i>Create Account</a>
            <a href="/login" class="btn btn-outline-primary"><i class="bi bi-box-arrow-in-right me-1"></i>Log In</a>
            <a href="/legal/terms" class="btn btn-link">Terms &amp; Conditions</a>
          </div>
        """
        user_line = ""

    # Short, sitewide disclaimer is already placed in base_layout footer per our global footer upgrade.
    # We still display a concise welcome + disclaimer here to orient first-time visitors.
    body = f"""
    <div class="container">
      <div class="row justify-content-center">
        <div class="col-lg-8 col-xl-7">
          <div class="card shadow-sm">
            <div class="card-header bg-dark text-white">
              <h3 class="mb-0"><i class="bi bi-shield-check me-2"></i>CPP Exam Prep</h3>
            </div>
            <div class="card-body">
              <p class="lead mb-2">Welcome! This is an independent CPP study tool.</p>
              <div class="alert alert-warning">
                <div class="fw-semibold mb-1">Disclaimer</div>
                <div class="small mb-0">
                  Not affiliated with or endorsed by ASIS International. Educational use only; no guarantees of exam outcomes.
                  See the full <a href="/legal/terms">Terms &amp; Conditions</a>.
                </div>
              </div>
              <p class="mb-0">
                Use the Tutor for guided explanations, take randomized quizzes, and drill flashcards by domain. 
                Promo/discount codes are only entered during Stripe checkout.
              </p>
              {ctas}
              {user_line}
            </div>
          </div>
        </div>
      </div>
    </div>
    """
    return base_layout("Welcome", body)

# =========================
# SECTION 5/8 (OWNED ROUTES): Flashcards, Progress, Usage, Billing/Stripe (+ Debug), Admin Login/Reset
# =========================
# Route ownership notes to prevent duplicates across sections:
# - THIS SECTION OWNS ONLY:
#     /flashcards  [GET, POST]
#     /progress    [GET]
#     /usage       [GET]
#     /billing     [GET]
#     /billing/checkout [GET]
#     /billing/success  [GET]
#     /stripe/webhook   [POST]
#     /billing/debug    [GET]
#     /admin/login      [GET, POST]
#     /admin/reset-password [GET, POST]
# - SECTION 6 owns content ingestion & bank validation:
#     /api/dev/ingest (JSON) and /admin/check-bank (UI) — DO NOT DEFINE THEM HERE.
# - Endpoint (function) names are all prefixed with `sec5_` to avoid accidental reuse.

# ---------- FLASHCARDS ----------
def sec5_normalize_flashcard(item):
    """
    Accepts shapes like:
      {"front": "...", "back":"...", "domain":"...", "sources":[{"title": "...", "url":"..."}]}
    or {"q":"...", "a":"..."} etc.
    Returns normalized:
      {"id": "...", "front":"...", "back":"...", "domain":"...", "sources":[...]}
    """
    if not item:
        return None
    front = (item.get("front") or item.get("q") or item.get("term") or "").strip()
    back  = (item.get("back") or item.get("a") or item.get("definition") or "").strip()
    if not front or not back:
        return None
    domain = (item.get("domain") or item.get("category") or "Unspecified").strip()
    sources = item.get("sources") or []
    cleaned_sources = []
    for s in sources[:3]:
        t = (s.get("title") or "").strip()
        u = (s.get("url") or "").strip()
        if t and u:
            cleaned_sources.append({"title": t, "url": u})
    return {
        "id": item.get("id") or str(uuid.uuid4()),
        "front": front, "back": back, "domain": domain,
        "sources": cleaned_sources
    }

def sec5_all_flashcards():
    """
    Merge legacy FLASHCARDS + optional bank file data/bank/cpp_flashcards_v1.json
    into normalized flashcards; de-dup by (front, back, domain).
    """
    out, seen = [], set()
    for fc in (FLASHCARDS or []):
        n = sec5_normalize_flashcard(fc)
        if not n:
            continue
        key = (n["front"], n["back"], n["domain"])
        if key in seen:
            continue
        seen.add(key); out.append(n)

    bank = _load_json("bank/cpp_flashcards_v1.json", [])
    for fc in (bank or []):
        n = sec5_normalize_flashcard(fc)
        if not n:
            continue
        key = (n["front"], n["back"], n["domain"])
        if key in seen:
            continue
        seen.add(key); out.append(n)
    return out

def sec5_filter_flashcards_domain(cards, domain_key: str | None):
    if not domain_key or domain_key == "random":
        return cards[:]
    dk = str(domain_key).strip().lower()
    return [c for c in cards if str(c.get("domain","")).strip().lower() == dk]

@app.route("/flashcards", methods=["GET", "POST"], endpoint="sec5_flashcards_page")
@login_required
def sec5_flashcards_page():
    # GET -> picker (domain buttons + count buttons)
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

    def _card_div(c):
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

    cards_html = "".join(_card_div(c) for c in cards) or "<div class='text-muted'>No flashcards found. Add content in <code>data/bank/cpp_flashcards_v1.json</code>.</div>"
    content = f"""
    <div class="container">
      <div class="row justify-content-center"><div class="col-lg-8 col-xl-7">
        <div class="card">
          <div class="card-header bg-success text-white d-flex justify-content-between align-items-center">
            <h3 class="mb-0"><i class="bi bi-layers me-2"></i>Flashcards</h3>
            <a href="/flashcards" class="btn btn-outline-light btn-sm">New Session</a>
          </div>
          <div class="card-body">
            <div class="mb-2 small text-muted">Domain: <strong>{html.escape(DOMAINS.get(domain, 'Mixed')) if domain!='random' else 'Random (all)'}</strong> • Cards: {len(cards)}</div>
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
    _log_event(_user_id(), "flashcards.start", {"count": len(cards), "domain": domain})
    return base_layout("Flashcards", content)


# ---------- PROGRESS ----------
@app.get("/progress", endpoint="sec5_progress_page")
@login_required
def sec5_progress_page():
    uid = _user_id()
    attempts = [a for a in _load_json("attempts.json", []) if a.get("user_id") == uid]
    attempts.sort(key=lambda x: x.get("ts",""), reverse=True)

    total_q  = sum(a.get("count", 0) for a in attempts)
    total_ok = sum(a.get("correct", 0) for a in attempts)
    best = max([a.get("score_pct", 0.0) for a in attempts], default=0.0)
    avg  = round(sum([a.get("score_pct", 0.0) for a in attempts]) / len(attempts), 1) if attempts else 0.0

    dom = {}
    for a in attempts:
        for dname, stats in (a.get("domains") or {}).items():
            dd = dom.setdefault(dname, {"correct": 0, "total": 0})
            dd["correct"] += int(stats.get("correct", 0))
            dd["total"]   += int(stats.get("total", 0))

    def pct(c, t): return f"{(100.0*c/t):.1f}%" if t else "0.0%"

    rows = []
    for a in attempts[:100]:
        rows.append(f"""
          <tr>
            <td class="text-nowrap">{html.escape(a.get('ts',''))}</td>
            <td>{html.escape(a.get('mode',''))}</td>
            <td class="text-end">{a.get('correct',0)}/{a.get('count',0)}</td>
            <td class="text-end">{a.get('score_pct',0)}%</td>
          </tr>
        """)
    attempts_html = "".join(rows) or "<tr><td colspan='4' class='text-center text-muted'>No attempts yet.</td></tr>"

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
          <div class="card-header bg-info text-white"><h3 class="mb-0"><i class="bi bi-graph-up-arrow me-2"></i>Progress</h3></div>
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


# ---------- USAGE DASHBOARD (nav link helper) ----------
@app.get("/usage", endpoint="sec5_usage_dashboard")
@login_required
def sec5_usage_dashboard():
    email = session.get("email","")
    u = _find_user(email) or {}
    usage = (u.get("usage") or {}).get("monthly", {})
    rows = []
    for month, items in sorted(usage.items()):
        quizzes = int(items.get("quizzes", 0))
        questions = int(items.get("questions", 0))
        tutor = int(items.get("tutor_msgs", 0))
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
    Creates a Stripe Checkout Session for either a subscription (monthly) or a one-time payment (sixmonth).
    If a discount_code is provided, we look up an active Promotion Code in Stripe and apply it.
    We also enable allow_promotion_codes=True so users can enter codes on the Stripe page if needed.
    """
    try:
        # Try to resolve a Stripe Promotion Code (promo_...) from the human-readable code
        discounts_param = None
        if discount_code:
            try:
                pc = stripe.PromotionCode.list(code=discount_code.strip(), active=True, limit=1)
                if pc and pc.get("data"):
                    promo_id = pc["data"][0]["id"]  # e.g., 'promo_...'
                    discounts_param = [{"promotion_code": promo_id}]
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
                discounts=discounts_param,  # may be None
                metadata={
                    "user_email": user_email,
                    "plan": "monthly",
                    "discount_code": (discount_code or "")
                },
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
                success_url=f"{root}/billing/success?session_id={{CHECKOUT_SESSION_ID}}&plan=sixmonth",
                cancel_url=f"{root}/billing",
                allow_promotion_codes=True,
                discounts=discounts_param,  # may be None
                metadata={
                    "user_email": user_email,
                    "plan": "sixmonth",
                    "duration_days": 180,
                    "discount_code": (discount_code or "")
                },
            )
            return sess.url

        else:
            logger.warning("Unknown plan %r", plan)
            return None

    except Exception as e:
        logger.error("Stripe session creation failed: %s", e)
        return None

@app.get("/billing", endpoint="sec5_billing_page")
@login_required
def sec5_billing_page():
    user = _find_user(session.get("email",""))
    sub = user.get("subscription","inactive") if user else "inactive"
    names = {"monthly":"Monthly Plan","sixmonth":"6-Month Plan","inactive":"Free Plan"}

    if sub == 'inactive':
        # Discount code UI lives *only* on Billing page; we append it to checkout links via JS
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
            (function(){{
              function goWithCode(href) {{
                var code = (document.getElementById('discount_code')||{{value:''}}).value.trim();
                if (code) {{
                  var url = new URL(href, window.location.origin);
                  url.searchParams.set('code', code);
                  return url.toString();
                }}
                return href;
              }}
              document.querySelectorAll('.upgrade-btn').forEach(function(btn){{
                btn.addEventListener('click', function(e){{
                  e.preventDefault();
                  window.location.href = goWithCode(btn.getAttribute('href'));
                }});
              }});
              var apply = document.getElementById('apply_code');
              if (apply) {{
                apply.addEventListener('click', function(){{
                  // NOP: user still needs to click a plan button; this just keeps the code in the field
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
    </div></div></div>
    """
    return base_layout("Billing", body)

@app.get("/billing/checkout", endpoint="sec5_billing_checkout")
@login_required
def sec5_billing_checkout():
    plan = request.args.get("plan","monthly")
    user_email = session.get("email","")
    if not user_email:
        return redirect(url_for("sec3_login_page"))  # owned by Section 3

    # read promo only from query; no suggestions anywhere else
    discount_code = (request.args.get("code") or "").strip()

    url = sec5_create_stripe_checkout_session(user_email, plan=plan, discount_code=discount_code)
    if url:
        return redirect(url)
    return redirect(url_for("sec5_billing_page"))

@app.get("/billing/success", endpoint="sec5_billing_success")
@login_required
def sec5_billing_success():
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
@app.post("/stripe/webhook", endpoint="sec5_stripe_webhook")
def sec5_stripe_webhook():
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
    # If CSRFProtect is active, it will enforce validity.
    # Fallback manual check when CSRF is not enabled.
    if not HAS_CSRF:
        if request.form.get("csrf_token") != csrf_token():
            abort(403)

    nxt = request.form.get("next") or "/"
    pw = (request.form.get("pw") or "").strip()
    if ADMIN_PASSWORD and pw == ADMIN_PASSWORD:
        session["admin_ok"] = True
        return redirect(nxt)
    return redirect(url_for("sec5_admin_login_page", next=nxt))

@app.route("/admin/reset-password", methods=["GET","POST"], endpoint="sec5_admin_reset_password")
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
# =========================
# SECTION 6/8: Content ingestion (+ whitelist, hashing, acceptance checker)
# One-owner rule for these routes:
#   - /api/dev/ingest      -> endpoint="sec6_api_dev_ingest" (POST, admin-only, JSON)
#   - /admin/check-bank    -> endpoint="sec6_admin_check_bank" (GET, admin-only UI)
# This section is the ONLY owner of the above routes. Do not redefine elsewhere.
# =========================

# -------- Source whitelist (edit anytime) --------
ALLOWED_SOURCE_DOMAINS = {
    # Government & standards (non-proprietary)
    "nist.gov", "cisa.gov", "fema.gov", "osha.gov", "gao.gov",
    # Research & practice
    "popcenter.asu.edu",  # POP Center
    "ncpc.org",           # National Crime Prevention Council
    "fbi.gov",
    "rand.org",
    "hsdl.org",           # Homeland Security Digital Library
    "nfpa.org",           # view-only summaries allowed
    "iso.org",            # summaries only
    # After Action Reports (public/official postings)
    "ca.gov", "ny.gov", "tx.gov", "wa.gov", "mass.gov", "phila.gov", "denvergov.org",
    "boston.gov", "chicago.gov", "seattle.gov", "sandiego.gov", "lacounty.gov",
    "ready.gov"           # FEMA/ICS public summaries & guidance
}
# NOTE: Wikipedia intentionally NOT allowed.

from urllib.parse import urlparse

def _url_domain_ok(url: str) -> bool:
    """Return True if URL domain is in the allowed whitelist."""
    try:
        d = urlparse((url or "").strip()).netloc.lower()
        if not d:
            return False
        return any(d == dom or d.endswith("." + dom) for dom in ALLOWED_SOURCE_DOMAINS)
    except Exception:
        return False

def _validate_sources(sources: list) -> tuple[bool, str]:
    """
    Enforce 1–3 sources; each must have title + URL; URL domain must be whitelisted.
    """
    if not isinstance(sources, list) or not (1 <= len(sources) <= 3):
        return False, "Each item must include 1–3 sources."
    for s in sources:
        if not isinstance(s, dict):
            return False, "Source entries must be objects with title and url."
        t = (s.get("title") or "").strip()
        u = (s.get("url") or "").strip()
        if not t or not u:
            return False, "Source requires non-empty title and url."
        if not _url_domain_ok(u):
            return False, f"URL domain not allowed: {u}"
    return True, ""

# -------- Hash & de-dup index --------
def _item_hash_flashcard(front: str, back: str, domain: str, sources: list) -> str:
    # Canonical string for deterministic hashing
    blob = json.dumps({
        "k": "fc",
        "front": (front or "").strip().lower(),
        "back": (back or "").strip().lower(),
        "domain": (domain or "Unspecified").strip().lower(),
        "srcs": [{"t": (s.get("title","").strip().lower()),
                  "u": (s.get("url","").strip().lower())} for s in (sources or [])]
    }, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()

def _item_hash_question(question: str, options: dict, correct: str, domain: str, sources: list) -> str:
    # Keep options in A..D order for stable hashing
    ordered = {k: str((options or {}).get(k,"")).strip().lower() for k in ["A","B","C","D"]}
    blob = json.dumps({
        "k": "q",
        "q": (question or "").strip().lower(),
        "opts": ordered,
        "correct": (correct or "").strip().upper(),
        "domain": (domain or "Unspecified").strip().lower(),
        "srcs": [{"t": (s.get("title","").strip().lower()),
                  "u": (s.get("url","").strip().lower())} for s in (sources or [])]
    }, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()

def _load_content_index():
    return _load_json("bank/content_index.json", {})

def _save_content_index(idx: dict):
    _save_json("bank/content_index.json", idx)

# -------- Bank file helpers --------
def _bank_read_flashcards():
    return _load_json("bank/cpp_flashcards_v1.json", [])

def _bank_read_questions():
    return _load_json("bank/cpp_questions_v1.json", [])

def _bank_write_flashcards(items: list):
    _save_json("bank/cpp_flashcards_v1.json", items)

def _bank_write_questions(items: list):
    _save_json("bank/cpp_questions_v1.json", items)

# -------- Normalize incoming shapes to bank schema --------
def _norm_bank_flashcard(fc_in: dict) -> tuple[dict | None, str]:
    """
    Input flexible keys -> output bank schema:
    { "front": str, "back": str, "domain": str, "sources": [{title,url},..] }
    """
    if not isinstance(fc_in, dict):
        return None, "Flashcard must be an object."
    front = (fc_in.get("front") or fc_in.get("q") or fc_in.get("term") or "").strip()
    back  = (fc_in.get("back") or fc_in.get("a") or fc_in.get("definition") or "").strip()
    domain = (fc_in.get("domain") or fc_in.get("category") or "Unspecified").strip()
    sources = fc_in.get("sources") or []
    if not front or not back:
        return None, "Flashcard needs front/back text."
    ok, msg = _validate_sources(sources)
    if not ok:
        return None, msg
    out = {"front": front, "back": back, "domain": domain, "sources": sources}
    return out, ""

def _norm_bank_question(q_in: dict) -> tuple[dict | None, str]:
    """
    Input flexible keys -> bank schema (4-choice MCQ):
    {
      "question": str,
      "options": {"A": "...","B": "...","C": "...","D": "..."},
      "correct": "A"|"B"|"C"|"D",
      "domain": str,
      "sources": [{title,url}]
    }
    """
    if not isinstance(q_in, dict):
        return None, "Question must be an object."
    question = (q_in.get("question") or q_in.get("q") or q_in.get("stem") or "").strip()
    domain   = (q_in.get("domain") or q_in.get("category") or "Unspecified").strip()
    sources  = q_in.get("sources") or []

    # Options can come as dict or list
    raw_opts = q_in.get("options") or q_in.get("choices") or q_in.get("answers")
    opts = {}
    if isinstance(raw_opts, dict):
        for L in ["A","B","C","D"]:
            v = raw_opts.get(L) or raw_opts.get(L.lower())
            if not v: return None, f"Missing option {L}"
            opts[L] = str(v)
    elif isinstance(raw_opts, list) and len(raw_opts) >= 4:
        letters = ["A","B","C","D"]
        for i, L in enumerate(letters):
            v = raw_opts[i]
            if isinstance(v, dict):
                opts[L] = str(v.get("text") or v.get("label") or v.get("value") or "")
            else:
                opts[L] = str(v)
    else:
        return None, "Options must provide 4 choices."

    # Correct can be letter or 1-based index
    correct = q_in.get("correct") or q_in.get("answer") or q_in.get("correct_key")
    if isinstance(correct, str) and correct.strip().upper() in ("A","B","C","D"):
        correct = correct.strip().upper()
    else:
        try:
            idx = int(correct)
            correct = ["A","B","C","D"][idx - 1]
        except Exception:
            return None, "Correct must be A/B/C/D or 1..4."

    # Sources validate
    ok, msg = _validate_sources(sources)
    if not ok:
        return None, msg
    if not question:
        return None, "Question text required."
    return {"question": question, "options": opts, "correct": correct, "domain": domain, "sources": sources}, ""

# -------- Ingestion (admin-only JSON API) --------
# NOTE: This endpoint expects application/json and is admin-gated.
@app.post("/api/dev/ingest", endpoint="sec6_api_dev_ingest")
@login_required
def sec6_api_dev_ingest():
    if not is_admin():
        return jsonify({"ok": False, "error": "admin-required"}), 403

    if not request.is_json:
        return jsonify({"ok": False, "error": "application/json required",
                        "hint": "Use Content-Type: application/json"}), 415

    data = request.get_json(silent=True) or {}
    in_flash = data.get("flashcards") or []
    in_questions = data.get("questions") or []

    # Load current bank & index
    bank_fc = _bank_read_flashcards()
    bank_q  = _bank_read_questions()
    idx = _load_content_index()  # {hash: {...}}

    # Build quick hash sets for existing
    existing_fc_hashes = set()
    for fc in bank_fc:
        h = _item_hash_flashcard(fc.get("front",""), fc.get("back",""),
                                 fc.get("domain","Unspecified"), fc.get("sources") or [])
        existing_fc_hashes.add(h)
        idx.setdefault(h, {"type":"fc",
                           "added": idx.get(h,{}).get("added") or datetime.utcnow().isoformat()+"Z"})

    existing_q_hashes = set()
    for q in bank_q:
        h = _item_hash_question(q.get("question",""), q.get("options") or {},
                                q.get("correct",""), q.get("domain","Unspecified"),
                                q.get("sources") or [])
        existing_q_hashes.add(h)
        idx.setdefault(h, {"type":"q",
                           "added": idx.get(h,{}).get("added") or datetime.utcnow().isoformat()+"Z"})

    # Process incoming flashcards
    added_fc = 0
    rejected_fc = []
    for raw in in_flash:
        norm, msg = _norm_bank_flashcard(raw)
        if not norm:
            rejected_fc.append({"item": raw, "error": msg}); continue
        h = _item_hash_flashcard(norm["front"], norm["back"], norm["domain"], norm["sources"])
        if h in existing_fc_hashes:
            continue
        bank_fc.append(norm)
        existing_fc_hashes.add(h)
        idx[h] = {"type": "fc", "added": datetime.utcnow().isoformat()+"Z"}
        added_fc += 1

    # Process incoming questions
    added_q = 0
    rejected_q = []
    for raw in in_questions:
        norm, msg = _norm_bank_question(raw)
        if not norm:
            rejected_q.append({"item": raw, "error": msg}); continue
        h = _item_hash_question(norm["question"], norm["options"], norm["correct"],
                                norm["domain"], norm["sources"])
        if h in existing_q_hashes:
            continue
        bank_q.append(norm)
        existing_q_hashes.add(h)
        idx[h] = {"type": "q", "added": datetime.utcnow().isoformat()+"Z"}
        added_q += 1

    # Save files atomically
    _bank_write_flashcards(bank_fc)
    _bank_write_questions(bank_q)
    _save_content_index(idx)

    return jsonify({
        "ok": True,
        "summary": {
            "flashcards_added": added_fc,
            "questions_added": added_q,
            "flashcards_total": len(bank_fc),
            "questions_total": len(bank_q),
            "flashcards_rejected": len(rejected_fc),
            "questions_rejected": len(rejected_q),
        },
        "rejected": {
            "flashcards": rejected_fc[:50],  # cap to keep payload light
            "questions": rejected_q[:50]
        }
    })

# If CSRF is enabled, exempt the JSON ingestion endpoint (post-definition).
if HAS_CSRF:
    try:
        sec6_api_dev_ingest = csrf.exempt(sec6_api_dev_ingest)  # type: ignore
    except Exception:
        logger.warning("Could not CSRF-exempt /api/dev/ingest; continuing without exemption.")

# -------- Acceptance checker (admin-only UI) --------
@app.get("/admin/check-bank", endpoint="sec6_admin_check_bank")
@login_required
def sec6_admin_check_bank():
    if not is_admin():
        return redirect(url_for("admin_login_page", next=request.path))

    bank_fc = _bank_read_flashcards()
    bank_q  = _bank_read_questions()

    # Validate flashcards
    fc_errors = []
    seen_fc = set()
    for i, fc in enumerate(bank_fc):
        if not isinstance(fc, dict):
            fc_errors.append(f"FC[{i}]: not an object"); continue
        f = (fc.get("front","")).strip(); b = (fc.get("back","")).strip()
        if not f or not b:
            fc_errors.append(f"FC[{i}]: missing front/back")
        ok, msg = _validate_sources(fc.get("sources") or [])
        if not ok:
            fc_errors.append(f"FC[{i}]: {msg}")
        h = _item_hash_flashcard(f, b, (fc.get('domain') or 'Unspecified'), fc.get('sources') or [])
        if h in seen_fc:
            fc_errors.append(f"FC[{i}]: duplicate hash")
        seen_fc.add(h)

    # Validate questions
    q_errors = []
    seen_q = set()
    for i, q in enumerate(bank_q):
        if not isinstance(q, dict):
            q_errors.append(f"Q[{i}]: not an object"); continue
        question = (q.get("question","")).strip()
        opts = q.get("options") or {}
        correct = (q.get("correct","")).strip().upper()
        if not question:
            q_errors.append(f"Q[{i}]: empty question")
        # options must be A..D and all non-empty
        for L in ["A","B","C","D"]:
            if not (isinstance(opts, dict) and opts.get(L)):
                q_errors.append(f"Q[{i}]: missing option {L}")
        if correct not in ("A","B","C","D"):
            q_errors.append(f"Q[{i}]: invalid correct {correct}")
        ok, msg = _validate_sources(q.get("sources") or [])
        if not ok:
            q_errors.append(f"Q[{i}]: {msg}")
        h = _item_hash_question(question, opts, correct, (q.get("domain") or "Unspecified"), q.get("sources") or [])
        if h in seen_q:
            q_errors.append(f"Q[{i}]: duplicate hash")
        seen_q.add(h)

    # Domain counts to help balancing
    def _count_by_domain(items, key="domain"):
        d = {}
        for it in items:
            dn = (it.get(key) or "Unspecified")
            d[dn] = d.get(dn, 0) + 1
        return d

    fc_by_dom = _count_by_domain(bank_fc)
    q_by_dom  = _count_by_domain(bank_q)

    def _tbl_dict(dct):
        rows = []
        for k in sorted(dct.keys()):
            rows.append(f"<tr><td>{html.escape(str(k))}</td><td class='text-end'>{int(dct[k])}</td></tr>")
        return "".join(rows) or "<tr><td colspan='2' class='text-center text-muted'>None</td></tr>"

    fc_err_html = "".join(f"<li>{html.escape(e)}</li>" for e in fc_errors) or "<li class='text-muted'>None</li>"
    q_err_html  = "".join(f"<li>{html.escape(e)}</li>" for e in q_errors)  or "<li class='text-muted'>None</li>"

    content = f"""
    <div class="container">
      <div class="row justify-content-center"><div class="col-xl-10">
        <div class="card">
          <div class="card-header bg-dark text-white"><h3 class="mb-0"><i class="bi bi-clipboard-check me-2"></i>Bank Acceptance Check</h3></div>
          <div class="card-body">
            <div class="row g-4">
              <div class="col-md-6">
                <div class="p-3 border rounded-3">
                  <div class="fw-semibold mb-2">Flashcards</div>
                  <div class="small text-muted mb-2">Total: {len(bank_fc)}</div>
                  <div class="table-responsive">
                    <table class="table table-sm align-middle">
                      <thead><tr><th>Domain</th><th class="text-end">Count</th></tr></thead>
                      <tbody>{_tbl_dict(fc_by_dom)}</tbody>
                    </table>
                  </div>
                  <div class="mt-2">
                    <div class="fw-semibold">Issues</div>
                    <ul class="small">{fc_err_html}</ul>
                  </div>
                </div>
              </div>
              <div class="col-md-6">
                <div class="p-3 border rounded-3">
                  <div class="fw-semibold mb-2">Questions</div>
                  <div class="small text-muted mb-2">Total: {len(bank_q)}</div>
                  <div class="table-responsive">
                    <table class="table table-sm align-middle">
                      <thead><tr><th>Domain</th><th class="text-end">Count</th></tr></thead>
                      <tbody>{_tbl_dict(q_by_dom)}</tbody>
                    </table>
                  </div>
                  <div class="mt-2">
                    <div class="fw-semibold">Issues</div>
                    <ul class="small">{q_err_html}</ul>
                  </div>
                </div>
              </div>
            </div>
            <div class="mt-3 d-flex gap-2">
              <a class="btn btn-outline-secondary" href="/"><i class="bi bi-house me-1"></i>Home</a>
              <a class="btn btn-outline-primary" href="/billing/debug"><i class="bi bi-bug me-1"></i>Config Debug</a>
            </div>
          </div>
        </div>
      </div></div>
    </div>
    """
    return base_layout("Bank Checker", content)

# =========================
# END SECTION 6/8
# =========================
# =========================
# SECTION 7/8: Tutor (web-aware citations override) + settings UI
# Owner Notes:
# - This section owns ONLY the /admin/tutor-settings route.
# - It DOES NOT define /healthz, /admin/check-bank, or any other routes to avoid duplicates.
# - Endpoint names are prefixed with `sec7_` for safety.
# Prereqs expected from earlier sections:
#   - OPENAI_API_KEY, OPENAI_CHAT_MODEL, OPENAI_API_BASE
#   - _tutor_web_enabled(), _find_bank_citations(query, max_n), _extract_keywords()
#   - base_layout(), csrf_token(), HAS_CSRF, logger
# =========================

def _format_citations_for_prompt(cites: list[dict]) -> str:
    """
    Build a human-readable block for providing bank-sourced citations to the tutor.
    Input item shape: {"title": str, "url": str, "domain": str, "from": "flashcard"|"question"}
    """
    if not cites:
        return ""
    lines = []
    for i, c in enumerate(cites, 1):
        t = (c.get("title") or "").strip()
        u = (c.get("url") or "").strip()
        d = (c.get("domain") or "").strip()
        lines.append(f"[{i}] {t} — {d}\n{u}")
    return "\n".join(lines)


def _call_tutor_agent(user_query: str, meta: dict | None = None) -> tuple[bool, str, dict]:
    """
    Tutor call with optional "web-aware" grounding to bank sources (no live internet fetch).
    - When _tutor_web_enabled() is True, we pass up to 3 relevant bank citations to the model
      and request alignment with them.
    - Returns (ok, answer, info) where `info` may contain usage/model/web_aware flags.
    """
    meta = meta or {}
    timeout_s = float(os.environ.get("TUTOR_TIMEOUT", "45"))
    temperature = float(os.environ.get("TUTOR_TEMP", "0.3"))
    max_tokens = int(os.environ.get("TUTOR_MAX_TOKENS", "900"))

    base_system = os.environ.get(
        "TUTOR_SYSTEM_PROMPT",
        "You are a calm, expert CPP/PSP study tutor. Explain clearly, step-by-step."
    )

    if not OPENAI_API_KEY:
        return False, "Tutor is not configured: missing OPENAI_API_KEY.", {}

    # Determine mode
    web_on = _tutor_web_enabled()
    sources = []
    sys_msg = base_system
    user_content = user_query

    if web_on:
        try:
            sources = _find_bank_citations(user_query, max_n=3) or []
        except Exception as e:
            logger.warning("sec7: _find_bank_citations failed: %s", e)
            sources = []

        sys_msg = (
            base_system
            + "\n\nGROUNDING:\n"
              "- You are provided a small list of relevant, vetted sources (government/standards/AAR style).\n"
              "- Answer using your expertise and *align with* these sources. If something is uncertain, say so.\n"
              "- Keep the answer concise and exam-focused; show steps when helpful."
        )

        cites_block = _format_citations_for_prompt(sources)
        if cites_block:
            user_content = (
                f"{user_query}\n\n"
                f"Candidate reference material (use when helpful):\n{cites_block}"
            )

    # Prepare OpenAI request
    url = f"{OPENAI_API_BASE}/chat/completions"
    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "Content-Type": "application/json",
    }
    org = os.environ.get("OPENAI_ORG", "").strip()
    if org:
        headers["OpenAI-Organization"] = org

    payload = {
        "model": OPENAI_CHAT_MODEL,
        "messages": [
            {"role": "system", "content": sys_msg},
            {"role": "user", "content": user_content}
        ],
        "temperature": temperature,
        "max_tokens": max_tokens
    }

    # Lightweight retries for transient errors
    backoffs = [0, 1.5, 3.0]
    last_err = None
    for wait_s in backoffs:
        if wait_s:
            time.sleep(wait_s)
        try:
            resp = requests.post(url, headers=headers, data=json.dumps(payload), timeout=timeout_s)
            if resp.status_code in (429, 500, 502, 503, 504):
                last_err = f"{resp.status_code} {resp.text[:300]}"
                continue
            if resp.status_code >= 400:
                try:
                    j = resp.json()
                    msg = (j.get("error") or {}).get("message") or resp.text[:300]
                except Exception:
                    msg = resp.text[:300]
                return False, f"Agent error {resp.status_code}: {msg}", {"status": resp.status_code}

            data = resp.json()
            answer = (data.get("choices") or [{}])[0].get("message", {}).get("content", "") or ""
            usage = data.get("usage", {})

            # Append compact references if in web-aware mode
            if web_on and sources and answer:
                refs_lines = []
                for i, s in enumerate(sources, 1):
                    t = (s.get("title") or "").strip()
                    u = (s.get("url") or "").strip()
                    refs_lines.append(f"[{i}] {t} — {u}")
                answer = f"{answer}\n\nReferences:\n" + "\n".join(refs_lines)

            return True, answer, {"usage": usage, "model": OPENAI_CHAT_MODEL, "web_aware": web_on}
        except Exception as e:
            last_err = str(e)
            continue

    return False, f"Network/agent error: {last_err or 'unknown'}", {"web_aware": web_on}


# -------- Tutor settings UI (admin-only) --------
@app.route("/admin/tutor-settings", methods=["GET", "POST"], endpoint="sec7_admin_tutor_settings")
@login_required
def sec7_admin_tutor_settings():
    """
    Toggle for 'web-aware' tutor grounding (uses only ingested/whitelisted sources).
    Owner: Section 7 (unique endpoint name).
    """
    # Admin gate
    if not is_admin():
        return redirect(url_for("admin_login_page", next=request.path))

    msg = ""
    cfg = _load_tutor_settings()

    if request.method == "POST":
        # CSRF: if Flask-WTF is active it will enforce; fallback minimal when disabled
        if not HAS_CSRF:
            if request.form.get("csrf_token") != csrf_token():
                abort(403)
        web_aware = (request.form.get("web_aware") == "on")
        cfg["web_aware"] = bool(web_aware)
        try:
            _save_tutor_settings(cfg)
            msg = "Tutor settings updated."
        except Exception as e:
            logger.warning("sec7: saving tutor settings failed: %s", e)
            msg = "Could not save settings; please try again."

    csrf_val = csrf_token()
    checked = "checked" if cfg.get("web_aware") else ""
    body = f"""
    <div class="container"><div class="row justify-content-center"><div class="col-lg-7">
      <div class="card">
        <div class="card-header bg-dark text-white">
          <h3 class="mb-0"><i class="bi bi-gear-wide-connected me-2"></i>Tutor Settings</h3>
        </div>
        <div class="card-body">
          {"<div class='alert alert-success'>" + html.escape(msg) + "</div>" if msg else ""}
          <form method="POST">
            <input type="hidden" name="csrf_token" value="{csrf_val}"/>
            <div class="form-check form-switch mb-3">
              <input class="form-check-input" type="checkbox" id="webAware" name="web_aware" {checked}>
              <label class="form-check-label" for="webAware">
                Enable web-aware mode (use *ingested* sources for citations)
              </label>
            </div>
            <button class="btn btn-primary" type="submit"><i class="bi bi-save me-1"></i>Save</button>
            <a class="btn btn-outline-secondary ms-2" href="/"><i class="bi bi-house me-1"></i>Home</a>
          </form>
          <hr>
          <div class="small text-muted">
            When enabled, the Tutor will ground answers to sources you ingested under <code>data/bank</code>.
            It never fetches the live internet; it only cites your vetted, whitelisted materials.
          </div>
        </div>
      </div>
    </div></div></div>
    """
    return base_layout("Tutor Settings", body)
# =========================
# SECTION 8/8: Startup, error pages, and __main__
# =========================
# Route Ownership Notes (avoid duplicates):
#   - /healthz is OWNED by Section 2 (endpoint func: sec2_healthz). Do NOT redefine here.
#   - 404/500 handlers are defined ONLY here.
#   - Favicon/robots and any other small utility routes are defined in their respective earlier sections.
#
# This section provides:
#   * init_sample_data()  – idempotent bootstrap of required data files/folders
#   * 500 and 404 error handlers (no endpoint name collisions)
#   * create_app()        – app factory that logs config + registered routes for duplicate detection
#   * __main__            – local runner (Render uses gunicorn `app:app`)
#
# IMPORTANT: Endpoints in this section do NOT use @app.get()/post() and thus cannot collide with others.

def init_sample_data():
    """
    Ensure required folders/files exist so the app never 500s on first boot.
    Non-destructive: only creates files if missing.
    """
    try:
        # Base data dir
        os.makedirs(DATA_DIR, exist_ok=True)

        # Bank dir
        bank_dir = os.path.join(DATA_DIR, "bank")
        os.makedirs(bank_dir, exist_ok=True)

        # Core JSON stores (create if missing)
        core_defaults = [
            ("users.json", []),
            ("questions.json", []),      # legacy optional
            ("flashcards.json", []),     # legacy optional
            ("attempts.json", []),
            ("events.json", []),
        ]
        for name, default in core_defaults:
            path = os.path.join(DATA_DIR, name)
            if not os.path.exists(path):
                _save_json(name, default)

        # Bank files (create empty arrays if missing)
        if not os.path.exists(os.path.join(bank_dir, "cpp_flashcards_v1.json")):
            _save_json("bank/cpp_flashcards_v1.json", [])
        if not os.path.exists(os.path.join(bank_dir, "cpp_questions_v1.json")):
            _save_json("bank/cpp_questions_v1.json", [])
        if not os.path.exists(os.path.join(bank_dir, "content_index.json")):
            _save_json("bank/content_index.json", {})

        # Tutor settings (default OFF unless env overrides)
        tutor_path = os.path.join(DATA_DIR, "tutor_settings.json")
        if not os.path.exists(tutor_path):
            _save_json("tutor_settings.json", {"web_aware": os.environ.get("TUTOR_WEB_AWARE", "0") == "1"})

        # Terms banner state file is not persisted here; acceptance is stored on user objects.
    except Exception as e:
        logger.warning("init_sample_data encountered an issue: %s", e)


# ---- 500 error page (friendly, no stack traces) ----
@app.errorhandler(500)
def sec8_server_error(e):
    content = """
    <div class="container">
      <div class="row justify-content-center"><div class="col-md-8">
        <div class="card">
          <div class="card-header bg-danger text-white">
            <h3 class="mb-0"><i class="bi bi-bug me-2"></i>Something went wrong</h3>
          </div>
          <div class="card-body">
            <p class="text-muted mb-3">An unexpected error occurred. Please try again.</p>
            <a class="btn btn-primary" href="/"><i class="bi bi-arrow-repeat me-1"></i>Retry</a>
          </div>
        </div>
      </div></div>
    </div>
    """
    return base_layout("Server Error", content), 500


# ---- 404 error page (graceful, reduces noisy logs) ----
@app.errorhandler(404)
def sec8_not_found(e):
    content = """
    <div class="container">
      <div class="row justify-content-center"><div class="col-md-8">
        <div class="card">
          <div class="card-header bg-secondary text-white">
            <h3 class="mb-0"><i class="bi bi-question-circle me-2"></i>Page not found</h3>
          </div>
          <div class="card-body">
            <p class="text-muted mb-3">We couldn't find that page. It may have moved or never existed.</p>
            <a class="btn btn-outline-secondary" href="/"><i class="bi bi-house me-1"></i>Home</a>
          </div>
        </div>
      </div></div>
    </div>
    """
    return base_layout("Not Found", content), 404


def _sec8_log_registered_routes():
    """
    Helper to log all registered endpoints and their rules at startup.
    Useful to spot accidental duplicates during CI or on boot.
    """
    try:
        rules = []
        for r in app.url_map.iter_rules():
            # Skip Flask static rule noise if present
            if r.endpoint == "static":
                continue
            methods = ",".join(sorted(m for m in r.methods if m not in ("HEAD", "OPTIONS")))
            rules.append((r.endpoint, str(r), methods))
        rules.sort(key=lambda x: x[0])
        logger.info("Registered endpoints (%d):", len(rules))
        for ep, rule, methods in rules:
            logger.info("  - %-35s %-40s %s", ep, rule, methods)
    except Exception as e:
        logger.warning("Could not enumerate routes: %s", e)


# ---- App factory (for gunicorn / WSGI servers) ----
def create_app():
    init_sample_data()
    logger.info("CPP Test Prep v%s starting up", APP_VERSION)
    logger.info("Debug mode: %s", DEBUG)
    logger.info("Staging mode: %s", IS_STAGING)
    logger.info("CSRF protection: %s", "enabled" if HAS_CSRF else "disabled")

    # quick config sanity in logs (no secrets)
    logger.info("Stripe monthly ID present: %s", bool(STRIPE_MONTHLY_PRICE_ID))
    logger.info("Stripe 6-month ID present: %s", bool(STRIPE_SIXMONTH_PRICE_ID))
    logger.info("Stripe webhook secret present: %s", bool(STRIPE_WEBHOOK_SECRET))
    logger.info("OpenAI key present: %s", bool(OPENAI_API_KEY))

    # One-owner route policy reminder
    logger.info("Route ownership: /healthz is owned by Section 2 (endpoint=sec2_healthz).")

    # Dump the route table to help detect duplicates in pre-deploy logs
    _sec8_log_registered_routes()
    return app


# ---- Local runner (Render uses gunicorn `app:app`) ----
if __name__ == "__main__":
    init_sample_data()
    port = int(os.environ.get("PORT", "5000"))
    logger.info("Running app on port %s", port)
    app.run(host="0.0.0.0", port=port, debug=DEBUG)

