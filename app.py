# app.py — Stable MVP + Domains + Clean Tutor + Safe Gauge (no template backticks)

from flask import Flask, request, jsonify, session, redirect, url_for
from flask import Response
from datetime import datetime
import os, json, random, textwrap, requests

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

# --- Helpers ---
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
    # OPTIONAL: allow setting name via query once (demo until DB)
    qname = request.args.get("name")
    if qname:
        session["user_name"] = qname
    name = session.get("user_name")

    # Compute simple average from session history for the gauge
    hist = session.get("quiz_history", [])
    avg = round(sum(h.get("score", 0.0) for h in hist)/len(hist), 1) if hist else 0.0

    # Header text (escape < > in the name)
    display_name = (name or "")
    display_name = display_name.replace("<", "&lt;").replace(">", "&gt;")
    if display_name:
        header_html = f'<h1 class="mb-1">Welcome, {display_name} 👋</h1><div class="text-muted">CPP Test Prep</div>'
    else:
        header_html = '<h1 class="mb-2">CPP Test Prep</h1>'

    # Encouragement messages (HTML-safe, we control content)
    messages = [
        "<strong>Study tip:</strong> Use 15-minute bursts. Set a timer, focus, then take a short break.",
        "<strong>Make mistakes matter:</strong> Review every wrong answer and jot the why in one sentence.",
        "<strong>Mix it up:</strong> Rotate domains—small chunks improve recall and reduce burnout.",
        "<strong>Mini-plan:</strong> Pick 1 domain, 2 flashcards, and 3 quiz questions. Done in ~15 minutes!",
        "<strong>Positive cue:</strong> Tell yourself: “I improve a little every session.”",
        "<strong>Teach it:</strong> Explain one concept out loud or to a friend—it locks in learning.",
    ]
    messages_json = json.dumps(messages)

    body = """
    <div class="row justify-content-center">
      <div class="col-md-10">
        <div class="card border-0 shadow mb-4">
          <div class="card-body d-flex flex-column flex-md-row align-items-center gap-3">
            <div class="flex-grow-1">
              """ + header_html + """
              <div id="tip" class="mt-2 p-2 rounded" style="background:#f8f9fa; border:1px solid #eee;"></div>
              <div class="d-flex gap-2 flex-wrap mt-3">
                <a class="btn btn-primary btn-lg btn-enhanced" href="/study">Open Tutor</a>
                <a class="btn btn-secondary btn-lg btn-enhanced" href="/flashcards">Flashcards</a>
                <a class="btn btn-success btn-lg btn-enhanced" href="/quiz">Practice Quiz</a>
                <a class="btn btn-warning btn-lg btn-enhanced" href="/mock-exam">Mock Exam</a>
              </div>
            </div>
            <div class="text-center">
              <div id="homeGauge"></div>
              <div class="small text-muted mt-2">Average of your recent quizzes</div>
            </div>
          </div>
        </div>
      </div>
    </div>
    <script>
      var HOME_AVG = """ + str(avg) + """;
      var MSGS = """ + messages_json + """;
      function showMsg() {
        var el = document.getElementById('tip');
        if (!el || !MSGS.length) return;
        // rotate messages in order
        var idx = parseInt(el.getAttribute('data-idx') || '0', 10);
        el.innerHTML = MSGS[idx];
        idx = (idx + 1) % MSGS.length;
        el.setAttribute('data-idx', String(idx));
      }
      showMsg();
      // change message every 8 seconds
      setInterval(showMsg, 8000);

      // draw gauge
      mountGauge('homeGauge', HOME_AVG);
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
    # ✅ NEW: capture the domain coming from the quiz/mock page (defaults to 'random')
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

    pct = (correct / total * 100) if total else 0.0

    # ✅ NEW: store domain in history for per-domain progress
    hist = session.get("quiz_history", [])
    hist.append({
        "type": quiz_type,
        "domain": domain,              # <-- this is what Progress will read
        "date": datetime.utcnow().isoformat(),
        "score": pct,
        "total": total,
        "correct": correct,
    })
    session["quiz_history"] = hist[-50:]  # keep last 50

    insights = []
    if pct >= 90: insights.append("🎯 Excellent — mastery level performance.")
    elif pct >= 80: insights.append("✅ Strong — a few areas to review.")
    elif pct >= 70: insights.append("📚 Fair — focus on weak concepts.")
    else: insights.append("⚠️ Needs improvement — study before a real exam.")

    return jsonify({
        "success": True,
        "score": round(pct, 1),
        "correct": correct,
        "total": total,
        "domain": domain,              # helpful to echo back
        "type": quiz_type,
        "performance_insights": insights,
        "detailed_results": detailed
    })

# --- Progress (session-based for now) ---
@app.get("/progress")
def progress_page():
    hist = session.get("quiz_history", [])
    overall = round(sum(h.get("score", 0.0) for h in hist)/len(hist), 1) if hist else 0.0

    # Per-domain stats
    per = {}
    for h in hist:
        d = h.get("domain") or "random"
        per.setdefault(d, []).append(h.get("score", 0.0))
    per_rows = []
    for dkey, scores in per.items():
        avg = round(sum(scores)/len(scores), 1) if scores else 0.0
        name = DOMAINS.get(dkey, "All Domains")
        per_rows.append((name, avg, len(scores)))
    per_rows.sort(key=lambda x: x[0].lower())

    hist_rows = "".join([
        f"<tr><td>{h['date'][:19].replace('T',' ')}</td><td>{h.get('domain','random')}</td><td>{h['type']}</td><td>{h['correct']}/{h['total']}</td><td>{round(h['score'],1)}%</td></tr>"
        for h in reversed(hist)
    ]) or '<tr><td colspan="5" class="text-center text-muted">No data yet — take a quiz!</td></tr>'

    per_table = "".join([
        f"<tr><td>{name}</td><td>{count}</td><td>{avg}%</td></tr>"
        for (name, avg, count) in per_rows
    ]) or '<tr><td colspan="3" class="text-center text-muted">No domain data yet</td></tr>'

    body = f"""
    <div class="row"><div class="col-md-11 mx-auto">
      <div class="card border-0 shadow mb-3">
        <div class="card-header bg-info text-white"><h4 class="mb-0">📊 Progress</h4></div>
        <div class="card-body">
          <div class="row align-items-center">
            <div class="col-md-8">
              <div class="mb-3"><strong>Overall Average:</strong> {overall}%</div>
              <div class="table-responsive">
                <table class="table table-sm align-middle">
                  <thead class="table-light"><tr><th>When (UTC)</th><th>Domain</th><th>Type</th><th>Correct</th><th>Score</th></tr></thead>
                  <tbody>{hist_rows}</tbody>
                </table>
              </div>
              <div class="table-responsive mt-3">
                <table class="table table-sm align-middle">
                  <thead class="table-light"><tr><th>Domain</th><th>Attempts</th><th>Avg Score</th></tr></thead>
                  <tbody>{per_table}</tbody>
                </table>
              </div>
              <div class="text-end mt-2">
                <form method="post" action="/progress/reset" onsubmit="return confirm('Clear session progress?');">
                  <button class="btn btn-outline-danger btn-sm">Reset Session Progress</button>
                </form>
              </div>
            </div>
            <div class="col-md-4 text-center">
              <div id="progGauge"></div>
              <div class="small text-muted mt-2">Overall average</div>
            </div>
          </div>
        </div>
      </div>
    </div></div>
    <script>
      mountGauge('progGauge', """ + str(overall) + """);
    </script>
    """
    return base_layout("Progress", body)

@app.post("/progress/reset")
def reset_progress():
    session.pop("quiz_history", None)
    return redirect(url_for("progress_page"))

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




