import os, re, json, time, uuid, hashlib, random, html, logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Tuple
from urllib.parse import quote as _urlquote

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
        os.makedirs(os.path.dirname(p), exist_ok=True)
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
    - Prefer a real login endpoint if it exists (e.g., 'login' or 'sec3_login_page').
    - Fall back to '/login?next=...'.
    Never points to admin login.
    """
    next_val = next_path or request.path or "/"
    try:
        # Check for likely user login endpoints without triggering BuildError
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
        {% if session.get('uid') %}
          <a class="btn btn-outline-danger btn-sm" href="/logout">Logout</a>
        {% else %}
          <a class="btn btn-outline-primary btn-sm" href="/login">Login</a>
        {% endif %}
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
              • Cards: {len(cards)}
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
    for dname in sorted(dom.keys()):   # FIX: no stray parentheses
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
            (function(){
              function goWithCode(href) {
                var code = (document.getElementById('discount_code')||{value:''}).value.trim();
                if (code) {
                  var url = new URL(href, window.location.origin);
                  url.searchParams.set('code', code);
                  return url.toString();
                }
                return href;
              }
              document.querySelectorAll('.upgrade-btn').forEach(function(btn){
                btn.addEventListener('click', function(e){
                  e.preventDefault();
                  window.location.href = goWithCode(btn.getAttribute('href'));
                });
              });
              var apply = document.getElementById('apply_code');
              if (apply) {
                apply.addEventListener('click', function(){
                  /* no-op: user still clicks a plan to proceed */
                });
              }
            })();
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
# SECTION 6/8 — Content Bank: ingestion, helpers, validation UI
# =========================
# Route ownership (unique in app):
#   /api/dev/ingest     [POST]  -> JSON ingestion (admin or token)
#   /admin/check-bank   [GET]   -> Admin validation dashboard
#
# This section also defines shared helpers used by other sections:
#   _bank_read_questions(), _bank_save_questions()
#   _bank_read_flashcards(), _bank_save_flashcards()
#   _bump_usage(kind, amount)     # monthly per-user usage counter
#   _update_content_index()       # builds bank/content_index.json

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
    """
    Build a stable content hash for a question to prevent duplicates across sources.
    - normalize whitespace, casing, and option ordering (A..D).
    """
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
    """
    Canonical question record for the bank:
      {
        "id": "<uuid|sha1>",
        "question": "<stem>",
        "options": {"A": "...", "B": "...", "C": "...", "D": "..."},
        "correct": "A"|"B"|"C"|"D",
        "domain": "<domain key or label>",
        "sources": [{"title": "...", "url": "..."}],
        "_hash": "<stable sha1>"
      }
    Accepts variants:
      - 'choices' list or dict
      - 'answer' can be A..D or 1..4
      - 'category' as domain
    Rejects if any of A..D missing or stem empty.
    """
    if not isinstance(q, dict):
        return None
    stem = (q.get("question") or q.get("q") or "").strip()
    if not stem:
        return None

    # options accept dict or list
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
        # allow 1..4
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
        "id": q.get("id") or sh,   # prefer stable id; unique enough across banks
        "question": stem,
        "options": opts,
        "correct": correct,
        "domain": domain,
        "sources": sources,
        "_hash": sh
    }

def _sec6_normalize_flashcard_for_bank(fc: dict) -> dict | None:
    """
    Canonical flashcard record:
      {
        "id": "<uuid|sha1>",
        "front": "...",
        "back": "...",
        "domain": "<domain>",
        "sources": [{"title":"...","url":"..."}],
        "_hash": "<stable sha1>"
      }
    """
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
    # ensure dir exists
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

# ========================= END SECTION 6/8 =========================
# =========================
# SECTION 7/8 — Tutor (Chat Assistant) + OpenAI integration (safe, optional)
# =========================
# Route ownership (unique in app):
#   /tutor  [GET, POST]
#
# This section:
#   - Renders a secure chat UI
#   - Stores a short chat history in session (ephemeral)
#   - Calls OpenAI (if configured) with strong fallbacks
#   - Never exposes secrets to the client
#   - Increments usage counters and logs events
#
# Depends on env vars defined in Section 1:
#   OPENAI_API_KEY, OPENAI_API_BASE, OPENAI_CHAT_MODEL
#
# Notes:
#   - If OPENAI is not configured, the page stays usable and explains why.
#   - Rate limit: 1 message / 2s per IP (server-side).
#   - CSRF: respected (Flask-WTF if present; fallback token otherwise).
#   - No streaming: simple request/response to keep deployment simple.

# ---------- OpenAI readiness ----------
def _openai_ready() -> bool:
    return bool(OPENAI_API_KEY and OPENAI_CHAT_MODEL and OPENAI_API_BASE)

# ---------- Tutor system prompt ----------
def _tutor_system_prompt() -> str:
    """
    Short, focused instruction for the assistant. Keep it exam-prep specific and safe.
    """
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
    """
    Returns a list like: [{"role":"user","content":"..."}, {"role":"assistant","content":"..."}]
    """
    hist = session.get(_TUTOR_SESS_KEY) or []
    # sanitize shape
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

    # Build chat messages: system + clipped history + new user message
    msgs = [{"role": "system", "content": _tutor_system_prompt()}]
    for m in prior[-(2*_TUTOR_MAX_TURNS):]:
        # re-check role to avoid garbage
        if m.get("role") in ("user", "assistant"):
            msgs.append({"role": m["role"], "content": m.get("content", "")})
    msgs.append({"role": "user", "content": user_message})

    # Compose request
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
        resp = requests.post(url, headers=headers, json=payload, timeout=20)
        if resp.status_code != 200:
            # redact body; log server-side
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
    # Build bubbles
    bubbles = []
    for m in history:
        role = m.get("role")
        content = html.escape(m.get("content", "").strip())
        if not content:
            continue
        if role == "user":
            bubbles.append(
                f"""
                <div class="d-flex justify-content-end my-2">
                  <div class="p-2 rounded-3 border bg-light" style="max-width: 80%;">
                    <div class="small text-muted mb-1">You</div>
                    <div>{content.replace('\\n','<br>')}</div>
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
                    <div>{content.replace('\\n','<br>')}</div>
                  </div>
                </div>
                """
            )
    bubble_html = "".join(bubbles) or "<div class='text-muted'>No messages yet — ask the tutor anything related to your CPP prep.</div>"

    # Input form
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
        # still append; this keeps transcript honest and UX clear
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

# ========================= END SECTION 7/8 =========================
# =========================
# SECTION 7/8 — Tutor (Chat Assistant) + OpenAI integration (safe, optional)
# =========================
# Route ownership (unique in app):
#   /tutor  [GET, POST]
#
# This section:
#   - Renders a secure chat UI
#   - Stores a short chat history in session (ephemeral)
#   - Calls OpenAI (if configured) with strong fallbacks
#   - Never exposes secrets to the client
#   - Increments usage counters and logs events
#
# Depends on env vars defined in Section 1:
#   OPENAI_API_KEY, OPENAI_API_BASE, OPENAI_CHAT_MODEL
#
# Notes:
#   - If OPENAI is not configured, the page stays usable and explains why.
#   - Rate limit: 1 message / 2s per IP (server-side).
#   - CSRF: respected (Flask-WTF if present; fallback token otherwise).
#   - No streaming: simple request/response to keep deployment simple.

# ---------- OpenAI readiness ----------
import requests  # <<< FIX: required by _tutor_call_openai

def _openai_ready() -> bool:
    return bool(OPENAI_API_KEY and OPENAI_CHAT_MODEL and OPENAI_API_BASE)

# ---------- Tutor system prompt ----------
def _tutor_system_prompt() -> str:
    """
    Short, focused instruction for the assistant. Keep it exam-prep specific and safe.
    """
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
    """
    Returns a list like: [{"role":"user","content":"..."}, {"role":"assistant","content":"..."}]
    """
    hist = session.get(_TUTOR_SESS_KEY) or []
    # sanitize shape
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

    # Build chat messages: system + clipped history + new user message
    msgs = [{"role": "system", "content": _tutor_system_prompt()}]
    for m in prior[-(2*_TUTOR_MAX_TURNS):]:
        # re-check role to avoid garbage
        if m.get("role") in ("user", "assistant"):
            msgs.append({"role": m["role"], "content": m.get("content", "")})
    msgs.append({"role": "user", "content": user_message})

    # Compose request
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
        resp = requests.post(url, headers=headers, json=payload, timeout=20)
        if resp.status_code != 200:
            # redact body; log server-side
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
    # Build bubbles
    bubbles = []
    for m in history:
        role = m.get("role")
        content = html.escape(m.get("content", "").strip())
        if not content:
            continue
        if role == "user":
            bubbles.append(
                f"""
                <div class="d-flex justify-content-end my-2">
                  <div class="p-2 rounded-3 border bg-light" style="max-width: 80%;">
                    <div class="small text-muted mb-1">You</div>
                    <div>{content.replace('\\n','<br>')}</div>
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
                    <div>{content.replace('\\n','<br>')}</div>
                  </div>
                </div>
                """
            )
    bubble_html = "".join(bubbles) or "<div class='text-muted'>No messages yet — ask the tutor anything related to your CPP prep.</div>"

    # Input form
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
        # still append; this keeps transcript honest and UX clear
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

# ========================= END SECTION 8/8 =========================



