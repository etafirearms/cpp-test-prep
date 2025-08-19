# app.py — Stable MVP + Domains + Clean Tutor + Safe Gauge (no template backticks)

from flask import Flask, request, jsonify, session, redirect, url_for
from flask import Response
from datetime import datetime
import os, json, random, textwrap, requests
import html
import csv, uuid

# --- Simple data storage (file-backed JSON) ---
DATA_DIR = os.environ.get("DATA_DIR", "data")
os.makedirs(DATA_DIR, exist_ok=True)

def _load_json(name, default):
    path = os.path.join(DATA_DIR, name)
    if not os.path.exists(path):
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default

def _save_json(name, data):
    path = os.path.join(DATA_DIR, name)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)

# In-memory banks (loaded at boot). Replace later with DB.
QUESTIONS = _load_json("questions.json", [])
FLASHCARDS = _load_json("flashcards.json", [])
USERS = _load_json("users.json", [])  # [{id, name, email, subscription, usage:{quizzes, questions, last_active}}]

app = Flask(__name__)

# --- Basic config ---
app.secret_key = os.environ.get("SECRET_KEY") or os.urandom(24)
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
OPENAI_CHAT_MODEL = os.environ.get("OPENAI_CHAT_MODEL", "gpt-4o-mini")
OPENAI_API_BASE = os.environ.get("OPENAI_API_BASE", "https://api.openai.com/v1")

# --- Simple in-memory base questions (domain, difficulty tags kept lightweight) ---
BASE_QUESTIONS = [
    {
        "question": "What is the primary purpose of a security risk assessment?",
        "options": {"A": "Identify all threats", "B": "Determine cost-effective mitigation", "C": "Eliminate all risks", "D": "Satisfy compliance"},
        "correct": "B",
        "explanation": "Risk assessments balance risk, cost, and operational impact to choose practical controls.",
        "domain": "security-principles", "difficulty": "medium"
    },
    {
        "question": "In CPTED, natural surveillance primarily accomplishes what?",
        "options": {"A": "Reduces guard costs", "B": "Increases observation likelihood", "C": "Eliminates cameras", "D": "Provides legal protection"},
        "correct": "B",
        "explanation": "Design that increases visibility makes misconduct more likely to be observed and deterred.",
        "domain": "physical-security", "difficulty": "medium"
    },
    {
        "question": "Which concept applies multiple layers so if one fails others still protect?",
        "options": {"A": "Security by Obscurity", "B": "Defense in Depth", "C": "Zero Trust", "D": "Least Privilege"},
        "correct": "B",
        "explanation": "Layered controls maintain protection despite single-point failures.",
        "domain": "security-principles", "difficulty": "medium"
    },
    {
        "question": "In incident response, what is usually the FIRST priority?",
        "options": {"A": "Notify law enforcement", "B": "Contain the incident", "C": "Eradicate malware", "D": "Lessons learned"},
        "correct": "B",
        "explanation": "Containment stops the bleeding before eradication and recovery.",
        "domain": "information-security", "difficulty": "medium"
    },
    {
        "question": "Background investigations primarily support which objective?",
        "options": {"A": "Regulatory compliance only", "B": "Marketing outcomes", "C": "Reduce insider risk", "D": "Disaster response"},
        "correct": "C",
        "explanation": "They help verify suitability and reduce personnel security risks.",
        "domain": "personnel-security", "difficulty": "medium"
    },
    {
        "question": "What is the primary goal of business continuity planning?",
        "options": {"A": "Prevent all disasters", "B": "Maintain critical operations during disruption", "C": "Reduce insurance costs", "D": "Only satisfy regulators"},
        "correct": "B",
        "explanation": "BCP ensures critical functions continue during and after a disruption.",
        "domain": "crisis-management", "difficulty": "medium"
    },
    {
        "question": "What establishes legal admissibility of evidence in investigations?",
        "options": {"A": "Chain of custody", "B": "Digital timestamps", "C": "Witness statements only", "D": "Management approval"},
        "correct": "A",
        "explanation": "Chain of custody proves integrity of evidence handling.",
        "domain": "investigations", "difficulty": "medium"
    },
    {
        "question": "Best approach to security budgeting?",
        "options": {"A": "Historical spend", "B": "Risk-based allocation", "C": "Industry averages", "D": "Spend remaining funds"},
        "correct": "B",
        "explanation": "Direct funds to the highest-impact, risk-reducing controls.",
        "domain": "business-principles", "difficulty": "medium"
    },
]

# Human-friendly domain names shown to the user
DOMAINS = {
    "security-principles": "Security Principles & Practices",
    "business-principles": "Business Principles & Practices",
    "investigations": "Investigations",
    "personnel-security": "Personnel Security",
    "physical-security": "Physical Security",
    "information-security": "Information Security",
    "crisis-management": "Crisis Management",
}
DOMAIN_KEYS = list(DOMAINS.keys())
def _bump_usage(delta: dict):
    """
    Increment usage counters for the current session user (matched by email).
    delta keys can include: quizzes, questions, tutor_msgs, flashcards.
    """
    email = (session.get("email") or "").strip().lower()
    if not email:
        return
    changed = False
    for u in USERS:
        if (u.get("email","").strip().lower() == email):
            usage = u.setdefault("usage", {
                "quizzes": 0, "questions": 0, "tutor_msgs": 0, "flashcards": 0, "last_active": ""
            })
            for k in ("quizzes","questions","tutor_msgs","flashcards"):
                if k in delta:
                    try:
                        usage[k] = int(usage.get(k,0)) + int(delta[k])
                    except Exception:
                        pass
            usage["last_active"] = datetime.utcnow().isoformat(timespec="seconds") + "Z"
            changed = True
            break
    if changed:
        _save_json("users.json", USERS)

# --- Helpers ---
def is_admin():
    # Dev-only toggle. Visit /admin?admin=1 to enable for your browser session.
    return session.get("is_admin") is True

def base_layout(title: str, body_html: str) -> str:
    nav = textwrap.dedent(f"""
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
      <div class="container">
        <a class="navbar-brand" href="/">CPP Test Prep</a>
        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#nav"
                aria-controls="nav" aria-expanded="false" aria-label="Toggle navigation"><span class="navbar-toggler-icon"></span></button>
        <div class="collapse navbar-collapse" id="nav">
          <div class="navbar-nav ms-auto">
            <a class="nav-link" href="/study">Tutor</a>
            <a class="nav-link" href="/flashcards">Flashcards</a>
            <a class="nav-link" href="/quiz">Quiz</a>
            <a class="nav-link" href="/mock-exam">Mock Exam</a>
            <a class="nav-link" href="/progress">Progress</a>
            <a class="nav-link" href="/settings">Settings</a>
          </div>
        </div>
      </div>
    </nav>
    """)
    disclaimer = """
    <div class="bg-light border-top mt-4 py-3">
      <div class="container small text-muted">
        <strong>Notice:</strong> This platform is independent and not affiliated with ASIS International. CPP® is a mark of ASIS International, Inc.
      </div>
    </div>
    """
    # Shared script: safe gauge drawer + sanitize helper (DOMPurify + Marked pulled on pages that need it)
    shared_js = """
    <script>
      // ---- SVG Gauge Drawer (no backticks) ----
      function polar(cx, cy, r, aDeg) {
        var a = (aDeg - 90) * Math.PI/180;
        return { x: cx + r * Math.cos(a), y: cy + r * Math.sin(a) };
      }
      function arcPath(cx, cy, r, a0, a1) {
        var p0 = polar(cx, cy, r, a0);
        var p1 = polar(cx, cy, r, a1);
        var large = (a1 - a0) > 180 ? 1 : 0;
        var sweep = 1;
        return "M " + p0.x.toFixed(1) + " " + p0.y.toFixed(1)
             + " A " + r.toFixed(1) + " " + r.toFixed(1)
             + " 0 " + large + " " + sweep
             + " " + p1.x.toFixed(1) + " " + p1.y.toFixed(1);
      }
      function gaugeSVG(percent) {
        // percent: 0..100
        var w = 260, h = 160, cx = w/2, cy = 130, r = 100;
        var minA = -100, maxA = 100; // sweep 200 deg
        var svg = '<svg width="' + w + '" height="' + h + '" viewBox="0 0 ' + w + ' ' + h + '">';
        // Bands: Red 0–40, Orange 41–79, Green 80–100
        // map percent to angle
        function map(p) { return minA + (maxA - minA) * (p/100); }
        function band(p0, p1, color) {
          svg += '<path d="' + arcPath(cx,cy,r,map(p0),map(p1)) + '" fill="none" stroke="' + color + '" stroke-width="18" stroke-linecap="round"/>';
        }
        band(0,40,"#dc3545");   // red
        band(40.1,79,"#fd7e14"); // orange (start slightly after 40 to avoid join artifact)
        band(79,100,"#198754");  // green

        // Ticks every 20%
        for (var t=0;t<=100;t+=20) {
          var a = map(t), p0 = polar(cx,cy,r-6,a), p1 = polar(cx,cy,r+6,a);
          svg += '<line x1="' + p0.x.toFixed(1) + '" y1="' + p0.y.toFixed(1)
              +  '" x2="' + p1.x.toFixed(1) + '" y2="' + p1.y.toFixed(1)
              +  '" stroke="#999" stroke-width="2"/>';
          var label = t + "%";
          var lp = polar(cx, cy, r+18, a);
          svg += '<text x="' + lp.x.toFixed(1) + '" y="' + lp.y.toFixed(1)
              +  '" text-anchor="middle" dominant-baseline="middle" font-size="10" fill="#666">' + label + '</text>';
        }
        // Needle
        var pa = map(Math.max(0, Math.min(100, percent)));
        var pN = polar(cx, cy, r, pa);
        svg += '<circle cx="' + cx + '" cy="' + cy + '" r="6" fill="#333"/>';
        svg += '<line x1="' + cx + '" y1="' + cy + '" x2="' + pN.x.toFixed(1) + '" y2="' + pN.y.toFixed(1)
            +  '" stroke="#333" stroke-width="3"/>';
        // Text
        var color = (percent <= 40) ? "#dc3545" : (percent < 80 ? "#fd7e14" : "#198754");
        var yLabel = h - 36; // label just above the bottom
var yPct   = h - 14; // big number at the very bottom
svg += '<text x="' + cx + '" y="' + yLabel + '" text-anchor="middle" font-size="14" fill="#666">Your Progress</text>';
svg += '<text x="' + cx + '" y="' + yPct + '" text-anchor="middle" font-size="28" font-weight="800" fill="' + color + '">' + percent.toFixed(1) + '%</text>';
        svg += '</svg>';
        return svg;
      }

      // Insert a gauge into a container by id
      function mountGauge(divId, pct) {
        var el = document.getElementById(divId);
        if (!el) return;
        el.innerHTML = gaugeSVG(pct || 0);
      }
    </script>
    """
    return textwrap.dedent(f"""\
    <!DOCTYPE html>
    <html lang="en"><head>
      <meta charset="utf-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1" />
      <title>{title} - CPP Test Prep</title>
      <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
      <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
      <style>
        .domain-chip {{
          display:inline-block; margin:4px 6px 4px 0; padding:8px 12px; border-radius:20px;
          background:#e3f2fd; color:#1976d2; border:1px solid #bbdefb; cursor:pointer; user-select:none;
        }}
        .domain-chip.active {{ background:#1976d2; color:#fff; border-color:#1976d2; }}
        .btn-enhanced {{ border-radius:8px; font-weight:600; }}
        .chat-bubble {{ max-width: 85%; }}
        .chat-bubble p {{ margin-bottom: .5rem; }}
        .chat-bubble ul {{ margin: .5rem 0 .5rem 1.25rem; }}
        .chat-bubble h1,.chat-bubble h2,.chat-bubble h3 {{ margin-top: .5rem; font-size:1.05rem; }}
      </style>
      {shared_js}
    </head><body>
      {nav}
      <div class="container mt-4">
        {body_html}
      </div>
      {disclaimer}
    </body></html>
    """)

def filter_questions(domain_key: str | None) -> list[dict]:
    """Return all questions if domain_key is None/'random'; otherwise only that domain."""
    if not domain_key or domain_key == "random":
        return BASE_QUESTIONS[:]
    return [q for q in BASE_QUESTIONS if q.get("domain") == domain_key]

def build_quiz(num: int, domain_key: str | None) -> dict:
    pool = filter_questions(domain_key)
    out = []
    if not pool:
        pool = BASE_QUESTIONS[:]
    while len(out) < num:
        random.shuffle(pool)
        for q in pool:
            if len(out) >= num:
                break
            out.append(q.copy())
    title = f"Practice ({num} questions)"
    return {"title": title, "domain": domain_key or "random", "questions": out[:num]}

def chat_with_ai(msgs: list[str]) -> str:
    """Simple, robust wrapper. Returns a string answer or a friendly error."""
    try:
        if not OPENAI_API_KEY:
            return "OpenAI key is not configured. Please set OPENAI_API_KEY."
        payload = {
            "model": OPENAI_CHAT_MODEL,
            "messages": [{"role": "system", "content": "You are a helpful CPP exam tutor. Format your answers for easy reading with short sections and bullet points where helpful."}]
                        + [{"role": "user", "content": m} for m in msgs][-10:],
            "temperature": 0.7,
            "max_tokens": 700,
        }
        r = requests.post(
            f"{OPENAI_API_BASE}/chat/completions",
            headers={"Authorization": f"Bearer {OPENAI_API_KEY}", "Content-Type": "application/json"},
            json=payload,
            timeout=30,
        )
        if r.status_code != 200:
            return f"AI error ({r.status_code}). Please try again."
        data = r.json()
        return data["choices"][0]["message"]["content"]
    except Exception as e:
        return f"AI request failed: {e}"

# --- Health/diag ---
@app.get("/healthz")
def healthz():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}

@app.get("/diag/openai")
def diag_openai():
    try:
        msg = chat_with_ai(["Say 'pong' if you can hear me."])
        ok = "pong" in msg.lower()
        return jsonify({"success": ok, "preview": msg[:200]}), (200 if ok else 500)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# --- Home ---
@app.get("/")
def home():
    # Optional: greet by name until real accounts are wired in
    qname = (request.args.get("name") or "").strip()
    student_name_html = f"<span class='text-primary fw-semibold'>{qname}</span>" if qname else "there"

    # Overall average from session history
    hist = session.get("quiz_history", [])
    avg = round(sum(h.get("score", 0.0) for h in hist) / len(hist), 1) if hist else 0.0

    # A rotating encouragement/tip (server-side pick so it changes on refresh)
    tips = [
        "Small wins add up — try a focused 15-minute session.",
        "Active recall beats rereading — test yourself often.",
        "Mix topics. Switching domains improves long-term memory.",
        "Practice under time pressure to build exam stamina.",
        "Teach a concept aloud — if you can explain it, you know it.",
        "Schedule study like a meeting. Protect that time.",
        "Review mistakes first — that’s where growth lives.",
    ]
    tip = random.choice(tips)

    body = """
    <div class="row justify-content-center">
      <div class="col-lg-10">
        <div class="text-center mb-3">
          <h1 class="mb-1">CPP Test Prep</h1>
          <div class="text-muted">Welcome, """ + student_name_html + """</div>
        </div>

        <!-- Encouraging message -->
        <div class="alert alert-info border-0 shadow-sm text-center mb-4">
          <div class="fw-semibold">Today’s tip</div>
          <div>""" + tip.replace("<", "&lt;") + """</div>
        </div>

        <!-- Speedometer -->
        <div class="card border-0 shadow-sm mb-4">
          <div class="card-body">
            <div class="text-center">
              <div id="gaugeWrap"></div>
              <div class="mt-2">
                <div id="gaugeLabel" class="fw-bold" style="font-size:1.6rem;"></div>
                <div class="text-muted small">Average of your recent quizzes</div>
              </div>
            </div>
          </div>
        </div>

        <!-- Quick actions -->
        <div class="d-flex flex-wrap gap-2 justify-content-center">
          <a class="btn btn-primary btn-lg" href="/study">Open Tutor</a>
          <a class="btn btn-secondary btn-lg" href="/flashcards">Flashcards</a>
          <a class="btn btn-success btn-lg" href="/quiz">Practice Quiz</a>
          <a class="btn btn-warning btn-lg" href="/mock-exam">Mock Exam</a>
          <a class="btn btn-outline-info btn-lg" href="/progress">View Progress</a>
        </div>
      </div>
    </div>

    <script>
      (function () {
        const avg = """ + str(avg) + """;
        const g = document.getElementById('gaugeWrap');
        const w = 320, h = 190, cx = w/2, cy = h-10, r = 150;

        function deg(a) { return a * Math.PI / 180; }
        function polar(cx, cy, r, ang) { return {x: cx + r*Math.cos(ang), y: cy + r*Math.sin(ang)}; }
        function arc(cx, cy, r, a0, a1) {
          const p0 = polar(cx, cy, r, a0), p1 = polar(cx, cy, r, a1);
          const large = (a1 - a0) > Math.PI ? 1 : 0, sweep = 1;
          return "M " + p0.x.toFixed(1) + " " + p0.y.toFixed(1)
               + " A " + r + " " + r + " 0 " + large + " " + sweep + " "
               + p1.x.toFixed(1) + " " + p1.y.toFixed(1);
        }

        let svg = '<svg width="' + w + '" height="' + h + '" viewBox="0 0 ' + w + ' ' + h + '">';

        // Gauge bands: 0-40 red, 41-79 orange, 80-100 green
        const bands = [
          {from:180, to:252, color:'#dc3545'},
          {from:252, to:338.4, color:'#fd7e14'},
          {from:338.4, to:360, color:'#198754'}
        ];
        bands.forEach(b => {
          svg += '<path d="' + arc(cx,cy,r,deg(b.from),deg(b.to)) + '" fill="none" stroke="' + b.color + '" stroke-width="18" stroke-linecap="round"/>';
        });

        // tick marks + labels
        [0,20,80,100].forEach(p => {
          const a = deg(180 + p*1.8), p0 = polar(cx,cy,r-12,a), p1 = polar(cx,cy,r-2,a);
          svg += '<line x1="' + p0.x.toFixed(1) + '" y1="' + p0.y.toFixed(1) + '" x2="' + p1.x.toFixed(1) + '" y2="' + p1.y.toFixed(1) + '" stroke="#b0b0b0" stroke-width="3"/>';
          const pt = polar(cx,cy,r-28,a);
          svg += '<text x="' + pt.x.toFixed(1) + '" y="' + pt.y.toFixed(1) + '" font-size="10" text-anchor="middle" fill="#6c757d">' + p + '%</text>';
        });

        // needle
        const ang = deg(180 + Math.max(0, Math.min(100, avg)) * 1.8);
        const tip = polar(cx,cy,r-24, ang);
        svg += '<line x1="' + cx + '" y1="' + cy + '" x2="' + tip.x.toFixed(1) + '" y2="' + tip.y.toFixed(1) + '" stroke="#333" stroke-width="3"/>';
        svg += '<circle cx="' + cx + '" cy="' + cy + '" r="6" fill="#333"/>';
        svg += '</svg>';

        g.innerHTML = svg;
        document.getElementById('gaugeLabel').textContent = avg.toFixed(1) + '%';
      })();
    </script>
    """
    return base_layout("Home", body)

# --- Tutor ---
@app.get("/study")
def study_page():
    # Build chips: Random + each domain
    chips = ['<span class="domain-chip active" data-domain="random">Random</span>'] + \
            [f'<span class="domain-chip" data-domain="{k}">{v}</span>' for k, v in DOMAINS.items()]

    # Simple suggestions per domain
    SUGGESTIONS = {
        "security-principles": [
            "Explain defense in depth with an example",
            "Risk assessment steps and quick scenario",
            "Least privilege vs. zero trust — differences",
            "Common control categories (prevent/detect/correct)"
        ],
        "business-principles": [
            "Risk-based budgeting in security",
            "Build a business case for CCTV upgrade",
            "ROI vs. risk reduction — how to explain",
            "KPIs for a security program"
        ],
        "investigations": [
            "Chain of custody — quick checklist",
            "Interview vs. interrogation — differences",
            "Evidence handling for digital media",
            "Scene preservation basics"
        ],
        "personnel-security": [
            "Termination checklist — access + property",
            "Pre-employment screening best practices",
            "Insider threat indicators",
            "Visitor/contractor controls"
        ],
        "physical-security": [
            "CPTED quick wins for offices",
            "Perimeter vs. internal controls",
            "Locks and key control basics",
            "Access control levels overview"
        ],
        "information-security": [
            "Incident response phases",
            "Phishing controls: people + tech",
            "Backups: 3-2-1 rule",
            "Security awareness ideas"
        ],
        "crisis-management": [
            "BCP vs. DR — differences",
            "Crisis comms checklist",
            "Tabletop exercise outline",
            "Critical function identification"
        ]
    }
    sugg_json = json.dumps(SUGGESTIONS)

    body = """
    <div class="row">
      <div class="col-md-10 mx-auto">
        <div class="card border-0 shadow">
          <div class="card-header bg-primary text-white"><h4 class="mb-0">🤖 AI Tutor</h4></div>
          <div class="card-body">
            <div class="mb-3"><strong>Pick a domain:</strong>
              <div class="mt-2">""" + "".join(chips) + """</div>
            </div>
            <div class="row">
              <div class="col-md-8">
                <div id="chat" style="height: 360px; overflow-y:auto; border:1px solid #e9ecef; border-radius:8px; padding:12px; background:#fafafa;"></div>
                <div class="input-group mt-3">
                  <input type="text" id="userInput" class="form-control" placeholder="Ask anything about CPP domains..." />
                  <button id="sendBtn" class="btn btn-primary btn-enhanced">Send</button>
                </div>
                <div class="small text-muted mt-2">
                  Tip: “Explain risk assessment steps with a quick example.”
                </div>
                <div class="mt-3 small">
                  <strong>How to use Tutor:</strong>
                  1) Pick a domain or keep Random. 2) Click a suggested topic or type your question.
                  3) The reply appears formatted for easy reading. 4) Ask follow-ups to go deeper.
                </div>
              </div>
              <div class="col-md-4">
                <div class="border rounded p-2" style="background:#f8f9fa;">
                  <div class="fw-bold mb-2">Suggested topics</div>
                  <div id="suggestions" class="d-grid gap-2"></div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
    <!-- Markdown -> HTML and Sanitizer -->
    <script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/dompurify@3.0.8/dist/purify.min.js"></script>
    <script>
      var SUGG = """ + sugg_json + """;
      var chatDiv = document.getElementById('chat');
      var input = document.getElementById('userInput');
      var sendBtn = document.getElementById('sendBtn');
      var domain = 'random';

      function setActiveChip(clicked) {
        document.querySelectorAll('.domain-chip').forEach(function(c) { c.classList.remove('active'); });
        clicked.classList.add('active');
      }

      function renderSuggestions(d) {
        var box = document.getElementById('suggestions');
        if (!box) return;
        var items = (SUGG[d] || []);
        if (d === 'random') {
          // show one suggestion from a few domains
          items = [];
          var keys = Object.keys(SUGG);
          for (var i=0; i<keys.length && items.length<4; i++) {
            var list = SUGG[keys[i]];
            if (list && list.length) items.push(list[0]);
          }
        }
        var html = '';
        for (var i=0; i<items.length; i++) {
          var t = items[i];
          html += '<button class="btn btn-outline-secondary btn-sm text-start" onclick="useSuggestion(\\'' + t.replace(/'/g,"\\'") + '\\')">' + t + '</button>';
        }
        box.innerHTML = html || '<div class="text-muted small">Pick a domain to see suggestions.</div>';
      }
      window.useSuggestion = function(text) {
        input.value = text;
        send();
      };

      document.querySelectorAll('.domain-chip').forEach(function(ch) {
        ch.addEventListener('click', function() {
          setActiveChip(ch);
          domain = ch.getAttribute('data-domain');
          renderSuggestions(domain);
          input.focus();
        });
      });
      renderSuggestions(domain);

      function append(role, html, isHTML) {
        var wrap = document.createElement('div');
        wrap.className = (role === 'user' ? 'text-end' : 'text-start') + ' mb-2';
        var badge = '<span class="badge ' + (role==='user'?'bg-primary':'bg-secondary') + ' mb-1">' + (role==='user'?'You':'Tutor') + '</span>';
        var bubble = '<div class="p-2 border rounded bg-white chat-bubble" style="margin-' + (role==='user'?'left':'right') + ':auto;">' + html + '</div>';
        wrap.innerHTML = badge + bubble;
        chatDiv.appendChild(wrap); chatDiv.scrollTop = chatDiv.scrollHeight;
      }

      async function send() {
        var q = (input.value || '').trim();
        if (!q) return;
        append('user', q.replace(/</g,'&lt;')); // simple escape
        input.value = ''; sendBtn.disabled = true; sendBtn.textContent = 'Thinking...';
        try {
          var res = await fetch('/api/chat', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({message: q, domain: domain})});
          var data = await res.json();
          var raw = data.response || data.error || 'Sorry, something went wrong.';
          // Convert markdown -> HTML, then sanitize
          var parsed = (window.marked && typeof marked.parse === 'function') ? marked.parse(raw) : raw.replace(/\\n/g,'<br>');
          var clean = (window.DOMPurify && DOMPurify.sanitize) ? DOMPurify.sanitize(parsed) : parsed;
          append('assistant', clean, true);
        } catch(e) {
          append('assistant', 'Network error.');
        } finally {
          sendBtn.disabled = false; sendBtn.textContent = 'Send'; input.focus();
        }
      }
      sendBtn.addEventListener('click', send);
      input.addEventListener('keydown', function(e){ if(e.key==='Enter' && !sendBtn.disabled) send(); });
    </script>
    """
    return base_layout("Tutor", body)

@app.post("/api/chat")
def api_chat():
    data = request.get_json() or {}
    user_msg = (data.get("message") or "").strip()
    dom = data.get("domain")
    if not user_msg:
        return jsonify({"error": "Empty message"}), 400

    prefix = ""
    if dom and dom in DOMAINS:
        prefix = f"Focus on the domain: {DOMAINS[dom]}.\n"

    reply = chat_with_ai([prefix + user_msg])
    return jsonify({"response": reply, "timestamp": datetime.utcnow().isoformat()})

@app.post("/api/flashcards/mark")
def flashcards_mark():
    data = request.get_json() or {}
    know = bool(data.get("know"))
    domain = (data.get("domain") or "random").strip() or "random"

    stats = session.get("flashcard_stats", {})
    by_dom = stats.get(domain, {"know": 0, "dont": 0, "viewed": 0})
    if know:
        by_dom["know"] += 1
    else:
        by_dom["dont"] += 1
    by_dom["viewed"] += 1
    stats[domain] = by_dom
    session["flashcard_stats"] = stats

    # NEW: count one flashcard interaction
    _bump_usage({"flashcards": 1})

    return jsonify({"ok": True, "stats": by_dom})

# --- Flashcards --- (ONLY here we show clickable left/right arrows)
@app.get("/flashcards")
def flashcards_page():
    # Build cards from filtered questions by domain, default random
    # We render domain chips and let the client rebuild the stack when the domain changes.
    chips = ['<span class="domain-chip active" data-domain="random">Random</span>'] + \
            [f'<span class="domain-chip" data-domain="{k}">{v}</span>' for k, v in DOMAINS.items()]
    all_cards = []
    for q in BASE_QUESTIONS:
        ans = q["options"].get(q["correct"], "")
        back = "✅ Correct: " + ans + "\n\n💡 " + q["explanation"]
        all_cards.append({"front": q["question"], "back": back, "domain": q["domain"]})
    cards_json = json.dumps(all_cards)

    body = """
    <div class="row">
      <div class="col-md-10 mx-auto">
        <div class="card border-0 shadow">
          <div class="card-header bg-secondary text-white d-flex flex-wrap align-items-center justify-content-between">
            <h4 class="mb-0">🃏 Flashcards</h4>
            <div>""" + "".join(chips) + """</div>
          </div>
          <div class="card-body">
            <div class="d-flex align-items-center justify-content-between mb-2">
              <button id="prevBtn" class="btn btn-outline-secondary btn-sm" title="Previous (or K)">◀ Prev</button>
              <div id="card" class="border rounded p-4 flex-grow-1 mx-2" style="min-height:220px; background:#f8f9fa; cursor:pointer;"></div>
              <button id="nextBtn" class="btn btn-outline-secondary btn-sm" title="Next (or L)">Next ▶</button>
            </div>
            <div class="d-flex gap-2 justify-content-center mt-3">
  <button id="btnDK" class="btn btn-outline-danger btn-enhanced">❌ Don't Know</button>
  <button id="btnK" class="btn btn-outline-success btn-enhanced">✅ Know</button>
</div>
<div id="fcStats" class="text-center mt-2 small">
  <span class="badge bg-light text-dark me-2">Viewed: <span id="vCount">0</span></span>
  <span class="badge bg-success me-2">Know: <span id="kCount">0</span></span>
  <span class="badge bg-danger">Don't Know: <span id="dCount">0</span></span>
</div>
<div class="text-center mt-2 small text-muted">Press J to flip, K for next.</div>
          </div>
        </div>
      </div>
    </div>
    <script>
      var ALL = """ + cards_json + """;
      var domain = 'random';
      var CARDS = [];
      var i = 0, back=false, dk=0, k=0;
      var el = document.getElementById('card');

      function rebuildCards() {
        var pool = ALL.filter(function(c){ return domain==='random' ? true : c.domain===domain; });
        if (pool.length===0) pool = ALL.slice(0);
        // duplicate/shuffle to feel fuller
        var stack = pool.slice(0);
        while (stack.length < 20) { stack = stack.concat(pool); }
        stack = stack.slice(0, 20);
        for (var s=stack.length-1;s>0;--s){ var r=Math.floor(Math.random()*(s+1)); var tmp=stack[s]; stack[s]=stack[r]; stack[r]=tmp; }
        CARDS = stack;
        i=0; back=false; render();
      }

      function render() {
        var c = CARDS[i] || {front:'No cards', back:''};
        var txt = (back ? c.back : c.front).replace(/\\n/g,'<br>');
        el.innerHTML = '<div style="font-size:1.1rem; line-height:1.6;">'+txt+'</div><div class="mt-2 small text-muted">'+(back?'Back — click/J to see front':'Front — click/J to see back')+'</div>';
      }
      function prev(){ back=false; i = (i - 1 + CARDS.length) % CARDS.length; render(); }
      function next(){ back=false; i = (i + 1) % CARDS.length; render(); }

      el.addEventListener('click', function(){ back=!back; render(); });
      document.getElementById('btnDK').addEventListener('click', function(){ dk++; next(); });
      document.getElementById('btnK').addEventListener('click', function(){ k++; next(); });
      document.getElementById('prevBtn').addEventListener('click', prev);
      document.getElementById('nextBtn').addEventListener('click', next);
      document.addEventListener('keydown', function(e){
        var key = e.key.toLowerCase();
        if(key==='j') { back=!back; render(); }
        if(key==='k') { prev(); }
        if(key==='l') { next(); }
      });

      function setActiveChip(clicked) {
        document.querySelectorAll('.domain-chip').forEach(function(c){ c.classList.remove('active'); });
        clicked.classList.add('active');
      }
      document.querySelectorAll('.domain-chip').forEach(function(ch){
        ch.addEventListener('click', function(){
          setActiveChip(ch);
          domain = ch.getAttribute('data-domain');
          rebuildCards();
        })
      });

      rebuildCards();
    </script>
    """
    return base_layout("Flashcards", body)

# --- Quiz --- (no on-screen arrows)
@app.get("/quiz")
def quiz_page():
    # Domain chips
    chips = ['<span class="domain-chip active" data-domain="random">Random</span>'] + \
            [f'<span class="domain-chip" data-domain="{k}">{v}</span>' for k, v in DOMAINS.items()]
    # default quiz
    q = build_quiz(10, "random")
    q_json = json.dumps(q)
    body = """
    <div class="row"><div class="col-md-11 mx-auto">
      <div class="card border-0 shadow">
        <div class="card-header bg-success text-white d-flex flex-wrap align-items-center justify-content-between">
          <div>
            <h4 class="mb-0">📝 Practice Quiz</h4>
            <small id="countLabel">10 questions • Domain: <span id="domName">Random</span></small>
          </div>
          <div>""" + "".join(chips) + """</div>
          <div class="ms-auto d-flex align-items-center gap-2">
            <label class="small">#</label>
            <select id="qCount" class="form-select form-select-sm" style="width:auto;">
              <option selected>10</option>
              <option>5</option>
              <option>15</option>
              <option>20</option>
            </select>
            <button id="reload" class="btn btn-light btn-sm btn-enhanced">Build Quiz</button>
            <button id="submitTop" class="btn btn-light btn-sm btn-enhanced">Submit</button>
          </div>
        </div>
        <div class="card-body" id="quiz"></div>
        <div class="card-footer text-end">
          <button id="submitBottom" class="btn btn-success btn-lg btn-enhanced">Submit Quiz</button>
        </div>
      </div>
      <div id="results" class="mt-4"></div>
    </div></div>
    <script>
      var QUIZ = """ + q_json + """;
      var DOMAIN = 'random';
      var DOMAIN_NAMES = """ + json.dumps({"random":"Random", **DOMAINS}) + """;
      var cont = document.getElementById('quiz');
      function render() {
        cont.innerHTML = '';
        (QUIZ.questions||[]).forEach(function(qq, idx){
          var card = document.createElement('div');
          card.className = 'mb-3 p-3 border rounded';
          card.id = 'q'+idx;
          card.innerHTML = '<div class="fw-bold text-primary mb-2">Question ' + (idx+1) + '</div>'
                         + '<div class="mb-2">'+ qq.question + '</div>';
          var opts = qq.options || {};
          for (var k in opts) {
            var id = 'q' + idx + '_' + k;
            var row = document.createElement('div');
            row.className = 'form-check mb-1';
            row.innerHTML = '<input class="form-check-input" type="radio" name="q'+idx+'" id="'+id+'" value="'+k+'">'
                          + '<label class="form-check-label" for="'+id+'">'+k+') '+opts[k]+'</label>';
            card.appendChild(row);
          }
          cont.appendChild(card);
        });
      }
      function build(domain, count) {
        return fetch('/api/build-quiz', {
          method:'POST', headers:{'Content-Type':'application/json'},
          body: JSON.stringify({domain: domain, count: count})
        }).then(function(r){ return r.json(); });
      }
      async function reloadQuiz() {
        var cSel = document.getElementById('qCount');
        var count = parseInt(cSel.value,10) || 10;
        var data = await build(DOMAIN, count);
        QUIZ = data;
        document.getElementById('domName').textContent = DOMAIN_NAMES[DOMAIN] || 'Random';
        document.getElementById('countLabel').innerHTML = count + ' questions • Domain: <span id="domName">' + (DOMAIN_NAMES[DOMAIN]||'Random') + '</span>';
        render();
        window.scrollTo({top:0, behavior:'smooth'});
      }
      async function submitQuiz() {
        var answers = {};
        var unanswered = [];
        (QUIZ.questions||[]).forEach(function(qq, idx){
          var sel = document.querySelector('input[name="q'+idx+'"]:checked');
          if(!sel) unanswered.push(idx+1);
          answers[String(idx)] = sel ? sel.value : null;
        });
        if(unanswered.length){
          // Jump to the first unanswered question
          var first = unanswered[0] - 1;
          var target = document.getElementById('q'+first);
          if (target) { target.scrollIntoView({behavior:'smooth'}); }
          alert('Please answer all questions. Missing: Q' + unanswered.join(', Q'));
          return;
        }
        var res = await fetch('/api/submit-quiz', {
          method:'POST', headers:{'Content-Type':'application/json'},
          body: JSON.stringify({ quiz_type:'practice', domain: DOMAIN, questions: QUIZ.questions, answers })
        });
        var data = await res.json();
        var out = document.getElementById('results');
        if (data.error) { out.innerHTML = '<div class="alert alert-danger">'+data.error+'</div>'; return; }
        // Build detailed review
        var html = '<div class="card border-0 shadow"><div class="card-body">'
                 + '<div class="text-center mb-3"><h3 class="'+(data.score>=80?'text-success':(data.score>=70?'text-warning':'text-danger'))+'">Score: '+data.score.toFixed(1)+'%</h3>'
                 + '<div class="text-muted">Correct: '+data.correct+' / '+data.total+'</div></div>';
        (data.detailed_results||[]).forEach(function(row, idx){
          var cls = row.is_correct ? 'border-success bg-success-subtle' : 'border-danger bg-danger-subtle';
          var icon = row.is_correct ? '✅' : '❌';
          html += '<div class="p-3 border rounded mb-2 '+cls+'">'
               +   '<div class="fw-bold">'+icon+' Q'+row.index+': '+row.question+'</div>';
          var options = QUIZ.questions[idx].options || {};
          // Show options with color on user choice vs correct
          for (var key in options) {
            var val = options[key];
            var lineClass = '';
            if (key === row.correct_letter) lineClass = 'text-success fw-semibold';
            if (row.user_letter && key === row.user_letter && !row.is_correct) lineClass = 'text-danger fw-semibold';
            html += '<div class="'+lineClass+'">'+key+') '+val+'</div>';
          }
          html +=   '<div class="mt-2 small"><strong>Correct:</strong> ' + row.correct_letter + ') ' + row.correct_text + '</div>'
               +   '<div class="small text-muted">💡 ' + row.explanation + '</div>'
               + '</div>';
        });
        html += '</div></div>';
        out.innerHTML = html;
        // Jump to results
        out.scrollIntoView({behavior:'smooth'});
      }
      document.getElementById('reload').addEventListener('click', reloadQuiz);
      document.getElementById('submitTop').addEventListener('click', submitQuiz);
      document.getElementById('submitBottom').addEventListener('click', submitQuiz);
      function setActiveChip(clicked) {
        document.querySelectorAll('.domain-chip').forEach(function(c){ c.classList.remove('active'); });
        clicked.classList.add('active');
      }
      document.querySelectorAll('.domain-chip').forEach(function(ch){
        ch.addEventListener('click', function(){
          setActiveChip(ch);
          DOMAIN = ch.getAttribute('data-domain');
          reloadQuiz();
        })
      });
      render();
    </script>
    """
    return base_layout("Quiz", body)

# Build-quiz endpoint (used by quiz + mock to rebuild with chosen domain/count)
@app.post("/api/build-quiz")
def api_build_quiz():
    data = request.get_json() or {}
    domain = data.get("domain") or "random"
    count = int(data.get("count") or 10)
    return jsonify(build_quiz(count, domain))

# --- Mock Exam --- (no on-screen arrows)
@app.get("/mock-exam")
def mock_exam_page():
    chips = ['<span class="domain-chip active" data-domain="random">Random</span>'] + \
            [f'<span class="domain-chip" data-domain="{k}">{v}</span>' for k, v in DOMAINS.items()]
    q = build_quiz(25, "random")
    q_json = json.dumps(q)
    body = """
    <div class="row"><div class="col-md-11 mx-auto">
      <div class="card border-0 shadow">
        <div class="card-header bg-warning text-dark d-flex flex-wrap align-items-center justify-content-between">
          <div>
            <h4 class="mb-0">🏁 Mock Exam</h4>
            <small id="countLabel">25 questions • Domain: <span id="domName">Random</span></small>
          </div>
          <div>""" + "".join(chips) + """</div>
          <div class="ms-auto d-flex align-items-center gap-2">
            <label class="small">#</label>
            <select id="qCount" class="form-select form-select-sm" style="width:auto;">
              <option>25</option>
              <option>50</option>
              <option>75</option>
              <option>100</option>
            </select>
            <button id="reload" class="btn btn-dark btn-sm btn-enhanced">Build Exam</button>
          </div>
        </div>
        <div class="card-body" id="quiz"></div>
        <div class="card-footer text-end">
          <button id="submit" class="btn btn-success btn-lg btn-enhanced">Submit Exam</button>
        </div>
      </div>
      <div id="results" class="mt-4"></div>
    </div></div>
    <script>
      var QUIZ = """ + q_json + """;
      var DOMAIN = 'random';
      var DOMAIN_NAMES = """ + json.dumps({"random":"Random", **DOMAINS}) + """;
      var cont = document.getElementById('quiz');
      function render() {
        cont.innerHTML = '';
        (QUIZ.questions||[]).forEach(function(qq, idx){
          var card = document.createElement('div');
          card.className = 'mb-3 p-3 border rounded';
          card.id = 'q'+idx;
          card.innerHTML = '<div class="fw-bold text-primary mb-2">Question ' + (idx+1) + ' of ' + (QUIZ.questions||[]).length + '</div>'
                         + '<div class="mb-2">'+ qq.question + '</div>';
          var opts = qq.options || {};
          for (var k in opts) {
            var id = 'q' + idx + '_' + k;
            var row = document.createElement('div');
            row.className = 'form-check mb-1';
            row.innerHTML = '<input class="form-check-input" type="radio" name="q'+idx+'" id="'+id+'" value="'+k+'">'
                          + '<label class="form-check-label" for="'+id+'">'+k+') '+opts[k]+'</label>';
            card.appendChild(row);
          }
          cont.appendChild(card);
        });
      }
      function build(domain, count) {
        return fetch('/api/build-quiz', {
          method:'POST', headers:{'Content-Type':'application/json'},
          body: JSON.stringify({domain: domain, count: count})
        }).then(function(r){ return r.json(); });
      }
      async function reloadQuiz() {
        var cSel = document.getElementById('qCount');
        var count = parseInt(cSel.value,10) || 25;
        var data = await build(DOMAIN, count);
        QUIZ = data;
        document.getElementById('domName').textContent = DOMAIN_NAMES[DOMAIN] || 'Random';
        document.getElementById('countLabel').innerHTML = count + ' questions • Domain: <span id="domName">' + (DOMAIN_NAMES[DOMAIN]||'Random') + '</span>';
        render();
        window.scrollTo({top:0, behavior:'smooth'});
      }
      async function submitQuiz() {
        var answers = {};
        var unanswered = [];
        (QUIZ.questions||[]).forEach(function(qq, idx){
          var sel = document.querySelector('input[name="q'+idx+'"]:checked');
          if(!sel) unanswered.push(idx+1);
          answers[String(idx)] = sel ? sel.value : null;
        });
        if(unanswered.length){
          var first = unanswered[0] - 1;
          var target = document.getElementById('q'+first);
          if (target) { target.scrollIntoView({behavior:'smooth'}); }
          alert('Please answer all questions. Missing: Q' + unanswered.join(', Q'));
          return;
        }
        var res = await fetch('/api/submit-quiz', {
          method:'POST', headers:{'Content-Type':'application/json'},
          body: JSON.stringify({ quiz_type:'mock-exam', domain: DOMAIN, questions: QUIZ.questions, answers })
        });
        var data = await res.json();
        var out = document.getElementById('results');
        if (data.error) { out.innerHTML = '<div class="alert alert-danger">'+data.error+'</div>'; return; }
        var html = '<div class="card border-0 shadow"><div class="card-body">'
                 + '<div class="text-center mb-3"><h3 class="'+(data.score>=80?'text-success':(data.score>=70?'text-warning':'text-danger'))+'">Score: '+data.score.toFixed(1)+'%</h3>'
                 + '<div class="text-muted">Correct: '+data.correct+' / '+data.total+'</div></div>';
        (data.detailed_results||[]).forEach(function(row, idx){
          var cls = row.is_correct ? 'border-success bg-success-subtle' : 'border-danger bg-danger-subtle';
          var icon = row.is_correct ? '✅' : '❌';
          html += '<div class="p-3 border rounded mb-2 '+cls+'">'
               +   '<div class="fw-bold">'+icon+' Q'+row.index+': '+row.question+'</div>';
          var options = QUIZ.questions[idx].options || {};
          for (var key in options) {
            var val = options[key];
            var lineClass = '';
            if (key === row.correct_letter) lineClass = 'text-success fw-semibold';
            if (row.user_letter && key === row.user_letter && !row.is_correct) lineClass = 'text-danger fw-semibold';
            html += '<div class="'+lineClass+'">'+key+') '+val+'</div>';
          }
          html +=   '<div class="mt-2 small"><strong>Correct:</strong> ' + row.correct_letter + ') ' + row.correct_text + '</div>'
               +   '<div class="small text-muted">💡 ' + row.explanation + '</div>'
               + '</div>';
        });
        html += '</div></div>';
        out.innerHTML = html;
        out.scrollIntoView({behavior:'smooth'});
      }
      document.getElementById('reload').addEventListener('click', reloadQuiz);
      document.getElementById('submit').addEventListener('click', submitQuiz);
      function setActiveChip(clicked) {
        document.querySelectorAll('.domain-chip').forEach(function(c){ c.classList.remove('active'); });
        clicked.classList.add('active');
      }
      document.querySelectorAll('.domain-chip').forEach(function(ch){
        ch.addEventListener('click', function(){
          setActiveChip(ch);
          DOMAIN = ch.getAttribute('data-domain');
          reloadQuiz();
        })
      });
      render();
    </script>
    """
    return base_layout("Mock Exam", body)

@app.post("/api/submit-quiz")
def submit_quiz_api():
    data = request.get_json() or {}
    questions = data.get("questions") or []
    answers = data.get("answers") or {}
    quiz_type = data.get("quiz_type") or "practice"
    # capture the domain coming from the quiz/mock page (defaults to 'random')
    domain = (data.get("domain") or "random").strip() or "random"

    # score
    total = len(questions)
    correct = 0
    detailed = []
    for i, q in enumerate(questions):
        user_letter = answers.get(str(i))
        correct_letter = q.get("correct")
        opts = q.get("options", {}) or {}
        is_corr = (user_letter == correct_letter)
        if is_corr:
            correct += 1
        detailed.append({
            "index": i + 1,
            "question": q.get("question", ""),
            "correct_letter": correct_letter,
            "correct_text": opts.get(correct_letter, ""),
            "user_letter": user_letter,
            "user_text": opts.get(user_letter, "") if user_letter else None,
            "explanation": q.get("explanation", ""),
            "is_correct": bool(is_corr),
        })

    pct = (correct / total * 100.0) if total else 0.0

    # usage — one quiz completed, and N questions answered
    _bump_usage({"quizzes": 1, "questions": total})

    # store domain in history for per-domain progress
    hist = session.get("quiz_history", [])
    hist.append({
        "type": quiz_type,
        "domain": domain,
        "date": datetime.utcnow().isoformat(),
        "score": pct,
        "total": total,
        "correct": correct,
    })
    session["quiz_history"] = hist[-50:]  # keep last 50

    insights = []
    if pct >= 90:
        insights.append("🎯 Excellent — mastery level performance.")
    elif pct >= 80:
        insights.append("✅ Strong — a few areas to review.")
    elif pct >= 70:
        insights.append("📚 Fair — focus on weak concepts.")
    else:
        insights.append("⚠️ Needs improvement — study before a real exam.")

    return jsonify({
        "success": True,
        "score": round(pct, 1),
        "correct": correct,
        "total": total,
        "domain": domain,
        "type": quiz_type,
        "performance_insights": insights,
        "detailed_results": detailed
    })

# --- Progress (session-based for now) ---
@app.get("/progress")
def progress_page():
    hist = session.get("quiz_history", [])
    overall = round(
        sum(float(h.get("score", 0.0)) for h in hist) / len(hist), 1
    ) if hist else 0.0

    # Aggregate by domain
    domain_totals = {}
    for d_key in list(DOMAINS.keys()) + ["random"]:
        domain_totals[d_key] = {"sum": 0.0, "n": 0}
    for h in hist:
        d = (h.get("domain") or "random")
        if d not in domain_totals:
            domain_totals[d] = {"sum": 0.0, "n": 0}
        domain_totals[d]["sum"] += float(h.get("score", 0.0))
        domain_totals[d]["n"] += 1

    # Build per-domain rows with Bootstrap progress bars
    def bar_class(pct):
        if pct >= 80:
            return "bg-success"  # green
        if pct >= 41:
            return "bg-warning"  # orange
        return "bg-danger"       # red

    rows_html = []
    for d_key, agg in domain_totals.items():
        n = agg["n"]
        avg = round(agg["sum"] / n, 1) if n else 0.0
        name = DOMAINS.get(d_key, "All Domains (Random)") if d_key != "random" else "All Domains (Random)"
        rows_html.append(f'''
          <tr>
            <td>{name}</td>
            <td>{n}</td>
            <td style="width:55%;">
              <div class="progress" style="height:18px;">
                <div class="progress-bar {bar_class(avg)}" role="progressbar"
                     style="width:{avg}%;" aria-valuenow="{avg}" aria-valuemin="0" aria-valuemax="100">
                  {avg}%
                </div>
              </div>
            </td>
          </tr>
        ''')
    rows = "\n".join(rows_html) or '<tr><td colspan="3" class="text-center text-muted">No data yet — take a quiz!</td></tr>'

    body_tpl = textwrap.dedent("""
    <div class="row">
      <div class="col-md-10 mx-auto">
        <div class="card border-0 shadow">
          <div class="card-header bg-info text-white"><h4 class="mb-0">📊 Progress</h4></div>
          <div class="card-body">

            <!-- Overall Speedometer -->
            <div class="text-center mb-3">
              <div id="gaugeWrap"></div>
              <div class="mt-2">
                <div class="fw-bold" id="gaugeLabel"></div>
                <div class="text-muted small">Average of your recent quizzes</div>
              </div>
            </div>

            <h5 class="mb-2">Per-domain progress</h5>
            <div class="table-responsive">
              <table class="table table-sm align-middle">
                <thead class="table-light">
                  <tr><th>Domain</th><th>Attempts</th><th>Average</th></tr>
                </thead>
                <tbody>
                  [[ROWS]]
                </tbody>
              </table>
            </div>

            <div class="text-end mt-3">
              <form method="post" action="/progress/reset" onsubmit="return confirm('Clear session progress?');">
                <button class="btn btn-outline-danger btn-sm">Reset Session Progress</button>
              </form>
            </div>

          </div>
        </div>
      </div>
    </div>

    <script>
      (function() {
        var avg = [[AVG]];
        var g = document.getElementById('gaugeWrap');
        var w = 320, h = 190, cx = w/2, cy = h-10, r = 150;

        function deg(a) { return a * Math.PI / 180; }
        function polar(cx, cy, r, ang) { return {x: cx + r*Math.cos(ang), y: cy + r*Math.sin(ang)}; }
        function arc(cx, cy, r, a0, a1) {
          var p0 = polar(cx, cy, r, a0), p1 = polar(cx, cy, r, a1);
          var large = (a1 - a0) > Math.PI ? 1 : 0, sweep = 1;
          return "M " + p0.x.toFixed(1) + " " + p0.y.toFixed(1)
               + " A " + r + " " + r + " 0 " + large + " " + sweep + " "
               + p1.x.toFixed(1) + " " + p1.y.toFixed(1);
        }

        var svg = '<svg width="' + w + '" height="' + h + '" viewBox="0 0 ' + w + ' ' + h + '">';
        var bands = [
          {from:180, to:252, color:'#dc3545'},   // 0-40 red
          {from:252, to:338.4, color:'#fd7e14'}, // 41-79 orange
          {from:338.4, to:360, color:'#198754'}  // 80-100 green
        ];
        bands.forEach(function(b) {
          svg += '<path d="' + arc(cx,cy,r,deg(b.from),deg(b.to)) + '" fill="none" stroke="' + b.color + '" stroke-width="18" stroke-linecap="round"/>';
        });

        [0,20,80,100].forEach(function(p) {
          var a = deg(180 + p*1.8), p0 = polar(cx,cy,r-12,a), p1 = polar(cx,cy,r-2,a);
          svg += '<line x1="' + p0.x.toFixed(1) + '" y1="' + p0.y.toFixed(1) + '" x2="' + p1.x.toFixed(1) + '" y2="' + p1.y.toFixed(1) + '" stroke="#b0b0b0" stroke-width="3"/>';
          var pt = polar(cx,cy,r-28,a);
          svg += '<text x="' + pt.x.toFixed(1) + '" y="' + pt.y.toFixed(1) + '" font-size="10" text-anchor="middle" fill="#6c757d">' + p + '%</text>';
        });

        var safe = Math.max(0, Math.min(100, avg));
        var ang = deg(180 + safe * 1.8);
        var tip = polar(cx,cy,r-24, ang);
        svg += '<line x1="' + cx + '" y1="' + cy + '" x2="' + tip.x.toFixed(1) + '" y2="' + tip.y.toFixed(1) + '" stroke="#333" stroke-width="3"/>';
        svg += '<circle cx="' + cx + '" cy="' + cy + '" r="6" fill="#333"/>';
        svg += '</svg>';
        g.innerHTML = svg;

        // Label below the dial (larger & bold)
        var lbl = document.getElementById('gaugeLabel');
        lbl.innerHTML = '<span style="font-size:1.7rem; font-weight:700;">' + safe.toFixed(1) + '%</span>';
      })();
    </script>
    """)
    body = body_tpl.replace("[[ROWS]]", rows).replace("[[AVG]]", str(overall))
   @app.get("/settings")
def settings_page():
    name = session.get("name", "")
    email = session.get("email", "")
    tz = session.get("timezone", "UTC")

    body_tpl = textwrap.dedent("""
    <div class="row">
      <div class="col-md-10 mx-auto">
        <div class="card border-0 shadow">
          <div class="card-header bg-secondary text-white">
            <h4 class="mb-0">Settings</h4>
          </div>
          <div class="card-body">
            <form method="post" action="/settings">
              <div class="mb-3">
                <label class="form-label">Email</label>
                <input class="form-control" type="email" name="email" value="[[EMAIL]]" placeholder="you@example.com">
                <div class="form-text">Used to associate your usage with your account.</div>
              </div>
              <div class="mb-3">
                <label class="form-label">Name</label>
                <input class="form-control" type="text" name="name" value="[[NAME]]" placeholder="Your name">
                <div class="form-text">Shown on the Home page as &ldquo;Welcome, [your name]&rdquo;.</div>
              </div>

              <div class="mb-3">
                <label class="form-label">Timezone</label>
                <input class="form-control" type="text" name="timezone" value="[[TZ]]" placeholder="UTC, America/New_York, etc.">
                <div class="form-text">Used for timestamps and study plans.</div>
              </div>

              <div class="text-end">
                <button class="btn btn-primary">Save</button>
              </div>
            </form>
          </div>
        </div>
      </div>
    </div>
    """)

    body = (
        body_tpl
        .replace("[[NAME]]", html.escape(name or ""))
        .replace("[[EMAIL]]", html.escape(email or ""))
        .replace("[[TZ]]", html.escape(tz or ""))
    )
    return base_layout("Settings", body)

@app.post("/settings")
def settings_save():
   name = (request.form.get("name") or "").strip()
email = (request.form.get("email") or "").strip().lower()
tz = (request.form.get("timezone") or "").strip() or "UTC"
session["name"] = name
session["email"] = email
session["timezone"] = tz
return redirect(url_for("home"))

# --- Error pages ---
@app.errorhandler(404)
def nf(e):
    return base_layout("Not Found", """
      <div class="text-center"><h1 class="display-5 text-muted">404</h1><p>Page not found.</p>
      <a href="/" class="btn btn-primary btn-enhanced">Go Home</a></div>"""), 404

@app.errorhandler(500)
def se(e):
    return base_layout("Server Error", """
      <div class="text-center"><h1 class="display-5 text-muted">500</h1><p>Something went wrong.</p>
      <a href="/" class="btn btn-primary btn-enhanced">Go Home</a></div>"""), 500

# --- Entrypoint for local runs ---
if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=True)

@app.get("/admin")
def admin_home():
    # Enable dev admin quickly: /admin?admin=1
    if request.args.get("admin") == "1":
        session["is_admin"] = True
    tab = request.args.get("tab", "questions")

    # Build rows for Questions table
    q_rows = []
    for q in QUESTIONS:
        opts = q.get("options", [])
        domain = q.get("domain", "random")
        q_rows.append(
            "<tr>"
            "<td>" + domain + "</td>"
            "<td>" + (q.get("question","")[:120]).replace("<","&lt;").replace(">","&gt;") + "</td>"
            "<td>" + (",".join([str(i+1)+") "+o for i,o in enumerate(opts)])[:120]).replace("<","&lt;").replace(">","&gt;") + "</td>"
            "<td>" + str(q.get("answer","")) + "</td>"
            "<td>"
              '<form method="post" action="/admin/questions/delete" style="display:inline;">'
              '<input type="hidden" name="id" value="' + str(q.get("id","")) + '"/>'
              '<button class="btn btn-sm btn-outline-danger">Delete</button>'
              "</form>"
            "</td>"
            "</tr>"
        )
    q_table = "\n".join(q_rows) or '<tr><td colspan="5" class="text-center text-muted">No questions yet.</td></tr>'

    # Build rows for Flashcards table
    f_rows = []
    for fc in FLASHCARDS:
        domain = fc.get("domain", "random")
        f_rows.append(
            "<tr>"
            "<td>" + domain + "</td>"
            "<td>" + (fc.get("front","")[:120]).replace("<","&lt;").replace(">","&gt;") + "</td>"
            "<td>" + (fc.get("back","")[:120]).replace("<","&lt;").replace(">","&gt;") + "</td>"
            "<td>"
              '<form method="post" action="/admin/flashcards/delete" style="display:inline;">'
              '<input type="hidden" name="id" value="' + str(fc.get("id","")) + '"/>'
              '<button class="btn btn-sm btn-outline-danger">Delete</button>'
              "</form>"
            "</td>"
            "</tr>"
        )
    f_table = "\n".join(f_rows) or '<tr><td colspan="4" class="text-center text-muted">No flashcards yet.</td></tr>'

    # Build rows for Users table (simple list until auth is wired)
    u_rows = []
    for u in USERS:
        usage = u.get("usage", {})
        last_active = usage.get("last_active") or ""
        u_rows.append(
            "<tr>"
            "<td>" + (u.get("name","")) + "</td>"
            "<td>" + (u.get("email","")) + "</td>"
            "<td>" + (u.get("subscription","free")) + "</td>"
            "<td>" + str(usage.get("quizzes",0)) + "</td>"
            "<td>" + str(usage.get("questions",0)) + "</td>"
            "<td>" + last_active + "</td>"
            "<td>"
              '<form method="post" action="/admin/users/subscription" class="d-flex gap-2">'
              '<input type="hidden" name="id" value="' + str(u.get("id","")) + '"/>'
              '<select class="form-select form-select-sm" name="subscription">'
                '<option value="free">free</option>'
                '<option value="trial">trial</option>'
                '<option value="active">active</option>'
                '<option value="past_due">past_due</option>'
                '<option value="canceled">canceled</option>'
              '</select>'
              '<button class="btn btn-sm btn-outline-primary">Update</button>'
              '</form>'
            "</td>"
            "</tr>"
        )
    u_table = "\n".join(u_rows) or '<tr><td colspan="7" class="text-center text-muted">No users yet.</td></tr>'

    # Tabs
    tab_q = "active" if tab == "questions" else ""
    tab_f = "active" if tab == "flashcards" else ""
    tab_u = "active" if tab == "users" else ""

    if not is_admin():
        guard = (
            '<div class="alert alert-warning mb-3">'
            'Admin mode is off. Append ?admin=1 to the URL to enable for this browser session '
            '(dev-only guard; replace with real auth later).'
            '</div>'
        )
    else:
        guard = ""

    body = f"""
<div class="row"><div class="col-md-11 mx-auto">
  ...
  {guard}
  <ul class="nav nav-tabs mb-3">
    <li class="nav-item"><a class="nav-link {tab_q}" href="/admin?tab=questions">Questions</a></li>
    <li class="nav-item"><a class="nav-link {tab_f}" href="/admin?tab=flashcards">Flashcards</a></li>
    <li class="nav-item"><a class="nav-link {tab_u}" href="/admin?tab=users">Users</a></li>
  </ul>
"""

    # Section: Questions
    attr_q = '' if tab == 'questions' else 'style="display:none;"'
    q_section = (
  '<div ' + attr_q + '>'
  + """
    <div class="card border-0 shadow-sm mb-3">
      <div class="card-header bg-light"><strong>Add Question</strong></div>
      <div class="card-body">
        <form method="post" action="/admin/questions/add" class="row g-2">
          <div class="col-md-2">
            <label class="form-label">Domain</label>
            <input class="form-control" name="domain" placeholder="e.g., 1 or random"/>
          </div>
          <div class="col-md-10">
            <label class="form-label">Question</label>
            <textarea class="form-control" name="question" rows="2" placeholder="Question text"></textarea>
          </div>
          <div class="col-md-3"><label class="form-label">Option 1</label><input class="form-control" name="opt1"/></div>
          <div class="col-md-3"><label class="form-label">Option 2</label><input class="form-control" name="opt2"/></div>
          <div class="col-md-3"><label class="form-label">Option 3</label><input class="form-control" name="opt3"/></div>
          <div class="col-md-3"><label class="form-label">Option 4</label><input class="form-control" name="opt4"/></div>
          <div class="col-md-2"><label class="form-label">Answer (1-4)</label><input class="form-control" name="answer" type="number" min="1" max="4"/></div>
          <div class="col-md-10"><label class="form-label">Explanation</label><input class="form-control" name="explanation" placeholder="Optional"/></div>
          <div class="col-12">
            <button class="btn btn-primary">Add Question</button>
            <a class="btn btn-outline-secondary ms-2" href="/admin/export/questions">Export JSON</a>
          </div>
        </form>
      </div>
    </div>

    <div class="card border-0 shadow-sm mb-4">
      <div class="card-header bg-light d-flex justify-content-between align-items-center">
        <strong>Import Questions (CSV)</strong>
        <a class="small" href="/admin/example/questions.csv">Download CSV template</a>
      </div>
      <div class="card-body">
        <form method="post" action="/admin/questions/import" enctype="multipart/form-data" class="row g-2">
          <div class="col-md-6">
            <input type="file" name="csv" accept=".csv" class="form-control"/>
          </div>
          <div class="col-md-6">
            <button class="btn btn-outline-primary">Upload and Import</button>
          </div>
        </form>
        <div class="text-muted mt-2 small">
          Columns: domain, question, opt1, opt2, opt3, opt4, answer, explanation
        </div>
      </div>
    </div>

    <div class="table-responsive">
      <table class="table table-sm align-middle">
        <thead class="table-light">
          <tr><th>Domain</th><th>Question</th><th>Options</th><th>Answer</th><th></th></tr>
        </thead>
        <tbody>
  """ + q_table + """
        </tbody>
      </table>
    </div>
  </div>
  """
)

    # Section: Flashcards
    f_section = """
  <div %s>
    <div class="card border-0 shadow-sm mb-3">
      <div class="card-header bg-light"><strong>Add Flashcard</strong></div>
      <div class="card-body">
        <form method="post" action="/admin/flashcards/add" class="row g-2">
          <div class="col-md-2">
            <label class="form-label">Domain</label>
            <input class="form-control" name="domain" placeholder="e.g., 1 or random"/>
          </div>
          <div class="col-md-5">
            <label class="form-label">Front</label>
            <textarea class="form-control" name="front" rows="2" placeholder="Prompt"></textarea>
          </div>
          <div class="col-md-5">
            <label class="form-label">Back</label>
            <textarea class="form-control" name="back" rows="2" placeholder="Answer"></textarea>
          </div>
          <div class="col-12"><button class="btn btn-primary">Add Flashcard</button>
            <a class="btn btn-outline-secondary ms-2" href="/admin/export/flashcards">Export JSON</a>
          </div>
        </form>
      </div>
    </div>

    <div class="card border-0 shadow-sm mb-4">
      <div class="card-header bg-light d-flex justify-content-between align-items-center">
        <strong>Import Flashcards (CSV)</strong>
        <a class="small" href="/admin/example/flashcards.csv">Download CSV template</a>
      </div>
      <div class="card-body">
        <form method="post" action="/admin/flashcards/import" enctype="multipart/form-data" class="row g-2">
          <div class="col-md-6">
            <input type="file" name="csv" accept=".csv" class="form-control"/>
          </div>
          <div class="col-md-6">
            <button class="btn btn-outline-primary">Upload and Import</button>
          </div>
        </form>
        <div class="text-muted mt-2 small">
          Columns: domain, front, back
        </div>
      </div>
    </div>

    <div class="table-responsive">
      <table class="table table-sm align-middle">
        <thead class="table-light">
          <tr><th>Domain</th><th>Front</th><th>Back</th><th></th></tr>
        </thead>
        <tbody>""" + f_table + """</tbody>
      </table>
    </div>
  </div>
""" % ("" if tab=="flashcards" else 'style="display:none;"')

    # Section: Users
    u_section = """
  <div %s>
    <div class="card border-0 shadow-sm mb-3">
      <div class="card-header bg-light"><strong>Add User</strong></div>
      <div class="card-body">
        <form method="post" action="/admin/users/add" class="row g-2">
          <div class="col-md-4"><label class="form-label">Name</label><input class="form-control" name="name"/></div>
          <div class="col-md-4"><label class="form-label">Email</label><input class="form-control" name="email"/></div>
          <div class="col-md-4">
            <label class="form-label">Subscription</label>
            <select class="form-select" name="subscription">
              <option value="free">free</option>
              <option value="trial">trial</option>
              <option value="active">active</option>
              <option value="past_due">past_due</option>
              <option value="canceled">canceled</option>
            </select>
          </div>
          <div class="col-12"><button class="btn btn-primary">Add User</button></div>
        </form>
      </div>
    </div>

    <div class="table-responsive">
      <table class="table table-sm align-middle">
        <thead class="table-light">
          <tr><th>Name</th><th>Email</th><th>Plan</th><th>Quizzes</th><th>Questions</th><th>Last Active</th><th></th></tr>
        </thead>
        <tbody>""" + u_table + """</tbody>
      </table>
    </div>
  </div>
""" % ("" if tab=="users" else 'style="display:none;"')

    body += q_section + f_section + u_section + "</div></div>"
    return base_layout("Admin", body)

# --- Questions CRUD ---
@app.post("/admin/questions/add")
def admin_questions_add():
    if not is_admin():
        return redirect("/admin")
    form = request.form
    q = {
        "id": str(uuid.uuid4()),
        "domain": (form.get("domain") or "random").strip(),
        "question": (form.get("question") or "").strip(),
        "options": [
            (form.get("opt1") or "").strip(),
            (form.get("opt2") or "").strip(),
            (form.get("opt3") or "").strip(),
            (form.get("opt4") or "").strip(),
        ],
        "answer": int(form.get("answer") or 1),
        "explanation": (form.get("explanation") or "").strip(),
        "created_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
    }
    QUESTIONS.append(q)
    _save_json("questions.json", QUESTIONS)
    return redirect("/admin?tab=questions")

@app.post("/admin/questions/delete")
def admin_questions_delete():
    if not is_admin():
        return redirect("/admin")
    qid = request.form.get("id")
    if qid:
        idx = next((i for i,x in enumerate(QUESTIONS) if x.get("id")==qid), -1)
        if idx >= 0:
            QUESTIONS.pop(idx)
            _save_json("questions.json", QUESTIONS)
    return redirect("/admin?tab=questions")

# --- Flashcards CRUD + exports ---

@app.post("/admin/flashcards/add")
def admin_flashcards_add():
    if not is_admin():
        return redirect("/admin")
    form = request.form
    fc = {
        "id": str(uuid.uuid4()),
        "domain": (form.get("domain") or "random").strip(),
        "front": (form.get("front") or "").strip(),
        "back": (form.get("back") or "").strip(),
        "created_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
    }
    if fc["front"] and fc["back"]:
        FLASHCARDS.append(fc)
        _save_json("flashcards.json", FLASHCARDS)
    return redirect("/admin?tab=flashcards")

@app.post("/admin/flashcards/delete")
def admin_flashcards_delete():
    if not is_admin():
        return redirect("/admin")
    fid = request.form.get("id")
    if fid:
        idx = next((i for i, x in enumerate(FLASHCARDS) if x.get("id") == fid), -1)
        if idx >= 0:
            FLASHCARDS.pop(idx)
            _save_json("flashcards.json", FLASHCARDS)
    return redirect("/admin?tab=flashcards")

@app.post("/admin/flashcards/import")
def admin_flashcards_import():
    if not is_admin():
        return redirect("/admin")
    f = request.files.get("csv")
    if not f:
        return redirect("/admin?tab=flashcards")
    reader = csv.DictReader(f.stream.read().decode("utf-8").splitlines())
    count = 0
    for row in reader:
        fc = {
            "id": str(uuid.uuid4()),
            "domain": (row.get("domain") or "random").strip(),
            "front": (row.get("front") or "").strip(),
            "back": (row.get("back") or "").strip(),
            "created_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        }
        if fc["front"] and fc["back"]:
            FLASHCARDS.append(fc)
            count += 1
    if count:
        _save_json("flashcards.json", FLASHCARDS)
    return redirect("/admin?tab=flashcards")

# --- Exports + CSV templates ---

@app.get("/admin/export/questions")
def admin_export_questions():
    if not is_admin():
        return redirect("/admin")
    return Response(
        json.dumps(QUESTIONS, ensure_ascii=False, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": "attachment; filename=questions.json"}
    )

@app.get("/admin/export/flashcards")
def admin_export_flashcards():
    if not is_admin():
        return redirect("/admin")
    return Response(
        json.dumps(FLASHCARDS, ensure_ascii=False, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": "attachment; filename=flashcards.json"}
    )

@app.get("/admin/example/questions.csv")
def admin_example_questions_csv():
    if not is_admin():
        return redirect("/admin")
    csv_text = "domain,question,opt1,opt2,opt3,opt4,answer,explanation\n" \
               "security-principles,What is defense in depth?,Layered controls,Single control,No controls,Budget only,1,Multiple layers reduce single-point failures\n"
    return Response(
        csv_text, mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=questions_template.csv"}
    )

@app.get("/admin/example/flashcards.csv")
def admin_example_flashcards_csv():
    if not is_admin():
        return redirect("/admin")
    csv_text = "domain,front,back\n" \
               "information-security,Define least privilege,Limit access to only what is required\n"
    return Response(
        csv_text, mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=flashcards_template.csv"}
    )

# --- Users (simple list until real auth) ---
@app.post("/admin/users/add")
def admin_users_add():
    if not is_admin():
        return redirect("/admin")
    form = request.form
    u = {
        "id": str(uuid.uuid4()),
        "name": (form.get("name") or "").strip(),
        "email": (form.get("email") or "").strip(),
        "subscription": (form.get("subscription") or "free"),
        "usage": {"quizzes": 0, "questions": 0, "last_active": ""},
        "created_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
    }
    USERS.append(u)
    _save_json("users.json", USERS)
    return redirect("/admin?tab=users")

@app.post("/admin/users/subscription")
def admin_users_subscription():
    if not is_admin():
        return redirect("/admin")
    uid = request.form.get("id")
    sub = request.form.get("subscription") or "free"
    for u in USERS:
        if u.get("id") == uid:
            u["subscription"] = sub
            break
    _save_json("users.json", USERS)
    return redirect("/admin?tab=users")





































