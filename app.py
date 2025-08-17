# app.py — Stable MVP (no DB), with Tutor, Flashcards, Quiz/Mock, Progress
# Upgraded speedometer dial, domain picks, keyboard nav, detailed reviews.

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

DOMAINS = {
    "security-principles": "Security Principles & Practices",
    "business-principles": "Business Principles & Practices",
    "investigations": "Investigations",
    "personnel-security": "Personnel Security",
    "physical-security": "Physical Security",
    "information-security": "Information Security",
    "crisis-management": "Crisis Management",
}

# Study tips for the home page
STUDY_TIPS = [
    "Short sessions every day beat one long cram. 20–30 minutes counts.",
    "Practice like the real test: timed, quiet, and phone away.",
    "After each quiz, read the explanations—even for correct answers.",
    "Plan your study week: 3 quiz days + 1 review day works well.",
    "Teach someone a concept you learned—teaching locks it in.",
    "If you miss a question twice, make a flashcard for it.",
]

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
        .sticky-head {{ position: sticky; top: 0; background: #fff; z-index: 5; padding: 8px 0; border-bottom: 1px solid #eee; }}
        .missing {{ border-color:#dc3545 !important; background:#fff5f5; }}
        .result-card {{ border-left:4px solid; }}
        .result-card.correct {{ border-left-color:#28a745; background:linear-gradient(90deg, rgba(40,167,69,0.05), transparent); }}
        .result-card.incorrect {{ border-left-color:#dc3545; background:linear-gradient(90deg, rgba(220,53,69,0.05), transparent); }}
      </style>
    </head><body>
      {nav}
      <div class="container mt-4">
        {body_html}
      </div>
      {disclaimer}
    </body></html>
    """)

def filter_pool_by_domain(pool, domain_key):
    if not domain_key or domain_key == "all":
        return pool[:]
    return [q for q in pool if q.get("domain") == domain_key] or pool[:]

def expand_questions(pool, num):
    out = []
    if not pool: return out
    while len(out) < num:
        batch = pool[:]
        random.shuffle(batch)
        for q in batch:
            if len(out) >= num: break
            out.append(q.copy())
    return out[:num]

def chat_with_ai(msgs: list[str]) -> str:
    """Simple, robust wrapper. Returns a string answer or a friendly error."""
    try:
        if not OPENAI_API_KEY:
            return "OpenAI key is not configured. Please set OPENAI_API_KEY."
        payload = {
            "model": OPENAI_CHAT_MODEL,
            "messages": [{"role": "system", "content": "You are a helpful CPP exam tutor."}]
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
        msg = chat_with_ai(["Say 'pong' if you can hear me." ])
        ok = "pong" in msg.lower()
        return jsonify({"success": ok, "preview": msg[:200]}), (200 if ok else 500)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# --- Home ---
@app.get("/")
def home():
    # compute a quick average for the gauge (uses your existing session history)
    hist = session.get("quiz_history", [])
    avg = round(sum(h["score"] for h in hist) / len(hist), 1) if hist else 0.0

    # rotating tip on the home page
    tips = [
        "Small, daily practice beats long, rare cram sessions.",
        "Plan a short study block and stick to it — even 10 minutes counts.",
        "Active recall: quiz yourself, don’t just re-read notes.",
        "Missed questions are gold — they show you what to study next.",
        "Set a target for today: 5 questions per domain you struggle with."
    ]
    tip = random.choice(tips)

    body_top = """
    <div class="row justify-content-center">
      <div class="col-md-10">
        <div class="card border-0 shadow mb-3">
          <div class="card-body">
            <h1 class="mb-2">CPP Test Prep</h1>
            <p class="lead text-muted">AI tutor, flashcards, quizzes, and mock exams — ready to go.</p>

            <div class="alert alert-info mb-4" role="alert">
              <strong>Quick tip:</strong> """
    body_mid = tip
    body_mid2 = """</div>

            <div class="d-flex gap-2 flex-wrap">
              <a class="btn btn-primary btn-lg btn-enhanced" href="/study">Open Tutor</a>
              <a class="btn btn-secondary btn-lg btn-enhanced" href="/flashcards">Flashcards</a>
              <a class="btn btn-success btn-lg btn-enhanced" href="/quiz">Practice Quiz</a>
              <a class="btn btn-warning btn-lg btn-enhanced" href="/mock-exam">Mock Exam</a>
              <a class="btn btn-info btn-lg btn-enhanced" href="/progress">Progress</a>
            </div>
          </div>
        </div>

        <div class="card border-0 shadow">
          <div class="card-header bg-light"><strong>Overall Progress</strong></div>
          <div class="card-body">
            <div id="gaugeHome" class="d-flex justify-content-center"></div>
            <div class="text-center text-muted mt-2">Average of your saved attempts</div>
          </div>
        </div>
      </div>
    </div>

    <script>
      // Draw a half-circle gauge (0–100) with a needle.
      (function () {
        var pct = """
    body_pct = str(avg)
    body_bot = """;
        if (isNaN(pct)) { pct = 0; }
        if (pct < 0) pct = 0;
        if (pct > 100) pct = 100;

        var el = document.getElementById('gaugeHome');
        var w = 320, h = 190;
        var cx = w/2, cy = h - 10, r = Math.min(w, h*2) * 0.45; // nice sizing
        var start = 180, end = 0; // left to right along a half circle

        function polar(cx, cy, r, a) {
          var rad = (a - 90) * Math.PI/180;
          return {x: cx + r * Math.cos(rad), y: cy + r * Math.sin(rad)};
        }
        function arc(cx, cy, r, a0, a1) {
          var p0 = polar(cx,cy,r,a0), p1 = polar(cx,cy,r,a1);
          var large = ((a1 - a0 + 360) % 360) > 180 ? 1 : 0;
          var sweep = a1 > a0 ? 1 : 0;
          return 'M ' + p0.x.toFixed(1) + ' ' + p0.y.toFixed(1)
               + ' A ' + r + ' ' + r + ' 0 ' + large + ' ' + sweep + ' '
               + p1.x.toFixed(1) + ' ' + p1.y.toFixed(1);
        }

        // Choose color by pct
        var col = '#dc3545'; // red
        if (pct >= 70) col = '#fd7e14'; // orange
        if (pct >= 80) col = '#ffc107'; // yellow
        if (pct >= 90) col = '#28a745'; // green

        var svg = '<svg width="' + w + '" height="' + h + '" viewBox="0 0 ' + w + ' ' + h + '">';

        // background arc
        svg += '<path d="' + arc(cx,cy,r,start,end) + '" fill="none" stroke="#e9ecef" stroke-width="16" stroke-linecap="round"/>';

        // progress arc
        var sweep = (end - start) * (pct/100);
        svg += '<path d="' + arc(cx,cy,r,start,start+sweep) + '" fill="none" stroke="' + col + '" stroke-width="16" stroke-linecap="round"/>';

        // tick marks (every 10%)
        for (var t = 0; t <= 10; t++) {
          var a = start + (end - start) * (t/10);
          var p0 = polar(cx,cy,r+2,a);
          var p1 = polar(cx,cy,r-10,a);
          svg += '<line x1="' + p0.x.toFixed(1) + '" y1="' + p0.y.toFixed(1)
              + '" x2="' + p1.x.toFixed(1) + '" y2="' + p1.y.toFixed(1)
              + '" stroke="#ced4da" stroke-width="2" />';
        }

        // needle
        var na = start + (end - start) * (pct/100);
        var pn = polar(cx,cy,r-6,na);
        svg += '<line x1="' + cx.toFixed(1) + '" y1="' + cy.toFixed(1)
            + '" x2="' + pn.x.toFixed(1) + '" y2="' + pn.y.toFixed(1)
            + '" stroke="#343a40" stroke-width="3" />';
        svg += '<circle cx="' + cx.toFixed(1) + '" cy="' + cy.toFixed(1) + '" r="5" fill="#343a40" />';

        // label
        svg += '<text x="' + cx.toFixed(1) + '" y="' + (cy-20).toFixed(1) + '" text-anchor="middle" font-size="20" font-weight="700" fill="#212529">' + pct.toFixed(1) + '%</text>';

        svg += '</svg>';
        el.innerHTML = svg;
      })();
    </script>
    """
    body = body_top + body_mid + body_mid2 + body_pct + body_bot
    return base_layout("Home", body)

# --- Tutor ---
@app.get("/study")
def study_page():
    chips = "".join([f'<span class="domain-chip" data-domain="{k}">{v}</span>' for k, v in DOMAINS.items()])
    # domain → suggestions
    suggestions = {
        "security-principles": [
            "Explain defense in depth with a quick example",
            "What are the main steps in a risk assessment?",
            "How do I pick security KPIs for a program?"
        ],
        "business-principles": [
            "How do I build a risk-based security budget?",
            "CapEx vs OpEx in security—when to use each?",
            "Best practices for vendor management?"
        ],
        "investigations": [
            "Walk me through chain of custody basics",
            "Interview vs interrogation—key differences?",
            "What makes a solid investigation report?"
        ],
        "personnel-security": [
            "Outline a practical background check process",
            "Early signs of insider threat to watch for",
            "What should be on a termination checklist?"
        ],
        "physical-security": [
            "CPTED quick wins for a small site",
            "How to layer access control effectively?",
            "When to use barriers vs bollards?"
        ],
        "information-security": [
            "Incident response phases in plain English",
            "Password rules vs MFA—what’s better?",
            "How to run a phishing awareness campaign?"
        ],
        "crisis-management": [
            "BCP vs DR—what’s the difference?",
            "How to design a tabletop exercise",
            "What goes in a crisis comms plan?"
        ],
    }
    # help text (no jargon)
    help_html = """
    <div class="card border-0 bg-light">
      <div class="card-body small">
        <strong>How to use the Tutor:</strong>
        <ol class="mb-2">
          <li>Click a blue domain button to set the topic (optional).</li>
          <li>On the right, click one of the suggested questions.</li>
          <li>It fills the box and sends it automatically.</li>
          <li>Ask follow-ups: “give a short summary”, “show an example”, etc.</li>
        </ol>
        Tip: Save the best answers as notes you can review later.
      </div>
    </div>
    """
    body = f"""
    <div class="row">
      <div class="col-md-8">
        <div class="card border-0 shadow">
          <div class="card-header bg-primary text-white"><h4 class="mb-0">🤖 AI Tutor</h4></div>
          <div class="card-body">
            <div class="mb-3"><strong>Select a domain (optional):</strong><div class="mt-2">{chips}</div></div>
            <div id="chat" style="height: 360px; overflow-y:auto; border:1px solid #e9ecef; border-radius:8px; padding:12px; background:#fafafa;"></div>
            <div class="input-group mt-3">
              <input type="text" id="userInput" class="form-control" placeholder="Ask anything about CPP domains..." />
              <button id="sendBtn" class="btn btn-primary btn-enhanced">Send</button>
            </div>
            <div class="small text-muted mt-2 text-center">Try: “Explain risk assessment with a quick example.”</div>
          </div>
        </div>
      </div>
      <div class="col-md-4">
        <div class="card border-0 shadow mb-3">
          <div class="card-header bg-secondary text-white"><h6 class="mb-0">Suggested topics</h6></div>
          <div class="card-body">
            <ul id="sugList" class="mb-0 small" style="padding-left:18px; line-height:1.7;">
              <li class="text-muted">Pick a domain to see suggestions.</li>
            </ul>
          </div>
        </div>
        {help_html}
      </div>
    </div>
    <script>
      const chatDiv = document.getElementById('chat');
      const input = document.getElementById('userInput');
      const sendBtn = document.getElementById('sendBtn');
      const sugList = document.getElementById('sugList');
      const suggestions = {json.dumps(suggestions)};

      let domain = null;

      document.querySelectorAll('.domain-chip').forEach(ch => {{
        ch.addEventListener('click', () => {{
          document.querySelectorAll('.domain-chip').forEach(c => c.classList.remove('active'));
          ch.classList.add('active');
          domain = ch.dataset.domain;

          // Load suggestions
          const list = suggestions[domain] || [];
          if (!list.length) {{ sugList.innerHTML = '<li class="text-muted">No suggestions for this domain.</li>'; return; }}
          sugList.innerHTML = '';
          list.forEach(text => {{
            const li = document.createElement('li');
            const a = document.createElement('a');
            a.href = '#'; a.textContent = text; a.className = 'text-decoration-none';
            a.addEventListener('click', (e) => {{
              e.preventDefault();
              input.value = text;
              send();
            }});
            li.appendChild(a);
            sugList.appendChild(li);
          }});
          input.focus();
        }});
      }});

      function append(role, text) {{
        const wrap = document.createElement('div');
        wrap.className = (role === 'user' ? 'text-end' : 'text-start') + ' mb-2';
        wrap.innerHTML = '<span class="badge ' + (role==='user'?'bg-primary':'bg-secondary') + ' mb-1">' + (role==='user'?'You':'Tutor') + '</span>'
          + '<div class="p-2 border rounded bg-white" style="max-width:85%; margin-' + (role==='user'?'left':'right') + ':auto;">'
          + text.replace(/</g,'&lt;') + '</div>';
        chatDiv.appendChild(wrap); chatDiv.scrollTop = chatDiv.scrollHeight;
      }}

      async function send() {{
        const q = input.value.trim();
        if (!q) return;
        append('user', q);
        input.value = ''; sendBtn.disabled = true; sendBtn.textContent = 'Thinking...';
        try {{
          const res = await fetch('/api/chat', {{method:'POST', headers:{{'Content-Type':'application/json'}}, body: JSON.stringify({{message: q, domain}})}});
          const data = await res.json();
          append('assistant', data.response || data.error || 'Sorry, something went wrong.');
        }} catch(e) {{ append('assistant', 'Network error.'); }}
        finally {{ sendBtn.disabled = false; sendBtn.textContent = 'Send'; input.focus(); }}
      }}
      sendBtn.addEventListener('click', send);
      input.addEventListener('keydown', (e)=>{{ if(e.key==='Enter' && !sendBtn.disabled) send(); }});
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

# --- Flashcards ---
@app.get("/flashcards")
def flashcards_page():
    # Build ~20 cards from questions
    cards = []
    for q in BASE_QUESTIONS:
        ans = q["options"].get(q["correct"], "")
        back = "✅ Correct: " + ans + "\\n\\n💡 " + q["explanation"]
        cards.append({"front": q["question"], "back": back})
    cards = (cards * 3)[:20]
    random.shuffle(cards)
    cards_json = json.dumps(cards)
    chips = "".join([f'<span class="domain-chip" data-domain="{k}">{v}</span>' for k, v in DOMAINS.items()])
    body = f"""
    <div class="row">
      <div class="col-md-9 mx-auto">
        <div class="card border-0 shadow">
          <div class="card-header bg-secondary text-white d-flex justify-content-between align-items-center">
            <h4 class="mb-0">🃏 Flashcards</h4>
            <div><small><strong>Pick a domain (optional):</strong></small> <span class="ms-2">{chips}</span></div>
          </div>
          <div class="card-body">
            <div id="card" class="border rounded p-4" style="min-height:220px; background:#f8f9fa; cursor:pointer;"></div>
            <div class="d-flex gap-2 justify-content-center mt-3">
              <button id="btnDK" class="btn btn-outline-danger btn-enhanced">❌ Don't Know</button>
              <button id="btnK" class="btn btn-outline-success btn-enhanced">✅ Know</button>
            </div>
            <div class="text-center mt-2 small text-muted">Press J to flip, K for next.</div>
          </div>
        </div>
      </div>
    </div>
    <script>
      const ALL_CARDS = {cards_json};
      let CARDS = ALL_CARDS.slice(); // filtered as needed
      let i = 0, back=false;

      const el = document.getElementById('card');
      function render() {{
        const c = CARDS[i] || {{front:'No cards', back:''}};
        const txt = (back ? c.back : c.front).replace(/\\n/g,'<br>');
        el.innerHTML = '<div style="font-size:1.1rem; line-height:1.6;">'+txt+'</div><div class="mt-2 small text-muted">'+(back?'Back — click/J to see front':'Front — click/J to see back')+'</div>';
      }}
      function next() {{ back=false; i=(i+1)%CARDS.length; render(); }}
      el.addEventListener('click', ()=>{{ back=!back; render(); }});
      document.getElementById('btnDK').addEventListener('click', ()=>{{ next(); }});
      document.getElementById('btnK').addEventListener('click', ()=>{{ next(); }});
      document.addEventListener('keydown', (e)=>{{ if(e.key.toLowerCase()==='j') {{ back=!back; render(); }} if(e.key.toLowerCase()==='k') {{ next(); }} }});

      // domain filter (simple demo: rebuild from BASE_QUESTIONS client-side)
      document.querySelectorAll('.domain-chip').forEach(ch => {{
        ch.addEventListener('click', () => {{
          document.querySelectorAll('.domain-chip').forEach(c => c.classList.remove('active'));
          ch.classList.add('active');
          // For now we just reshuffle; real filtering would rebuild from server/domain pool
          i=0; back=false; render();
        }});
      }});

      render();
    </script>
    """
    return base_layout("Flashcards", body)

# --- Quiz (domain + count + keyboard + detailed review) ---
@app.get("/quiz")
def quiz_page():
    chips = "".join([f'<span class="domain-chip" data-domain="{k}">{v}</span>' for k, v in DOMAINS.items()])
    body = f"""
    <div class="row"><div class="col-md-10 mx-auto">
      <div class="card border-0 shadow">
        <div class="card-header bg-success text-white">
          <div class="d-flex flex-wrap justify-content-between align-items-center">
            <div><h4 class="mb-0">📝 Practice Quiz</h4></div>
            <div class="small">Keyboard: <code>←</code>/<code>→</code> to move</div>
          </div>
        </div>
        <div class="card-body">
          <div class="sticky-head">
            <div class="row g-2 align-items-center">
              <div class="col-md-6">
                <div class="mb-1"><strong>Choose a domain (optional):</strong></div>
                {chips}
              </div>
              <div class="col-md-3">
                <div class="mb-1"><strong>Questions:</strong></div>
                <div class="btn-group" role="group">
                  <input type="radio" class="btn-check" name="qcount" id="qc5" value="5">
                  <label class="btn btn-outline-primary btn-sm" for="qc5">5</label>
                  <input type="radio" class="btn-check" name="qcount" id="qc10" value="10" checked>
                  <label class="btn btn-outline-primary btn-sm" for="qc10">10</label>
                  <input type="radio" class="btn-check" name="qcount" id="qc15" value="15">
                  <label class="btn btn-outline-primary btn-sm" for="qc15">15</label>
                  <input type="radio" class="btn-check" name="qcount" id="qc20" value="20">
                  <label class="btn btn-outline-primary btn-sm" for="qc20">20</label>
                </div>
              </div>
              <div class="col-md-3 text-end">
                <button id="startBtn" class="btn btn-success btn-sm btn-enhanced">Start Quiz</button>
              </div>
            </div>
            <div class="d-flex justify-content-between align-items-center mt-2" id="navBar" style="display:none;">
              <div class="small text-muted">Use <strong>← / →</strong> or the buttons</div>
              <div>
                <button id="prevBtn" class="btn btn-outline-secondary btn-sm me-2">← Prev</button>
                <button id="nextBtn" class="btn btn-outline-secondary btn-sm">Next →</button>
              </div>
            </div>
          </div>
          <div id="quiz"></div>
        </div>
        <div class="card-footer d-flex justify-content-between">
          <button id="submitTop" class="btn btn-light btn-enhanced" disabled>Submit (top)</button>
          <button id="submitBottom" class="btn btn-success btn-lg btn-enhanced" disabled>Submit Quiz</button>
        </div>
      </div>
      <div id="results" class="mt-4"></div>
    </div></div>

    <script>
      const ALL = {json.dumps(BASE_QUESTIONS)};
      let DOMAIN = 'all', COUNT = 10, QUIZ = null, currentIndex = 0, startedAt = null;

      document.querySelectorAll('.domain-chip').forEach(ch => {{
        ch.addEventListener('click', () => {{
          document.querySelectorAll('.domain-chip').forEach(c => c.classList.remove('active'));
          ch.classList.add('active');
          DOMAIN = ch.dataset.domain;
        }});
      }});
      document.querySelectorAll('input[name="qcount"]').forEach(r => {{
        r.addEventListener('change', ()=>{{ COUNT = parseInt(document.querySelector('input[name="qcount"]:checked').value); }});
      }});

      function buildQuiz() {{
        // filter & expand in the browser for simplicity
        const pool = (DOMAIN==='all') ? ALL.slice() : ALL.filter(q => q.domain===DOMAIN);
        const out = [];
        while (out.length < COUNT) {{
          const shuffled = pool.slice().sort(()=>Math.random()-0.5);
          for (const q of shuffled) {{ if(out.length >= COUNT) break; out.push(structuredClone(q)); }}
        }}
        return {{title: 'Practice (' + COUNT + ' questions)', domain: DOMAIN, questions: out.slice(0, COUNT)}};
      }}

      const cont = document.getElementById('quiz');
      const navBar = document.getElementById('navBar');
      const prevBtn = document.getElementById('prevBtn');
      const nextBtn = document.getElementById('nextBtn');
      const submitTop = document.getElementById('submitTop');
      const submitBottom = document.getElementById('submitBottom');

      function render() {{
        cont.innerHTML = '';
        (QUIZ.questions||[]).forEach((qq, idx) => {{
          const card = document.createElement('div');
          card.className = 'mb-3 p-3 border rounded';
          card.id = 'q'+idx;
          card.innerHTML = '<div class="fw-bold text-primary mb-2">Question ' + (idx+1) + ' of ' + (QUIZ.questions||[]).length + '</div>'
                         + '<div class="mb-2">'+ qq.question + '</div>';
          const opts = qq.options || {{}};
          for (const k in opts) {{
            const id = 'q' + idx + '_' + k;
            const row = document.createElement('div');
            row.className = 'form-check mb-1';
            row.innerHTML = '<input class="form-check-input" type="radio" name="q'+idx+'" id="'+id+'" value="'+k+'">'
                          + '<label class="form-check-label" for="'+id+'">'+k+') '+opts[k]+'</label>';
            row.querySelector('input').addEventListener('change', () => enableSubmitIfAllAnswered());
            card.appendChild(row);
          }}
          cont.appendChild(card);
        }});
        currentIndex = 0;
        scrollToIndex(currentIndex);
        navBar.style.display = 'flex';
        enableSubmitIfAllAnswered();
      }}

      function scrollToIndex(i) {{
        const el = document.getElementById('q'+i);
        if (el) el.scrollIntoView({{behavior:'smooth', block:'center'}});
      }}

      function enableSubmitIfAllAnswered() {{
        const total = (QUIZ.questions||[]).length;
        let answered = 0;
        for (let i=0; i<total; i++) {{ if (document.querySelector('input[name="q'+i+'"]:checked')) answered++; }}
        const ready = (answered === total);
        submitTop.disabled = !ready; submitBottom.disabled = !ready;
      }}

      function firstUnanswered() {{
        const total = (QUIZ.questions||[]).length;
        for (let i=0; i<total; i++) {{ if (!document.querySelector('input[name="q'+i+'"]:checked')) return i; }}
        return -1;
      }}

      async function submitQuiz() {{
        // highlight missing & jump
        const miss = firstUnanswered();
        if (miss >= 0) {{
          document.querySelectorAll('.missing').forEach(el => el.classList.remove('missing'));
          for (let i=0;i<(QUIZ.questions||[]).length;i++) {{
            const card = document.getElementById('q'+i);
            if (!document.querySelector('input[name="q'+i+'"]:checked')) card.classList.add('missing');
          }}
          currentIndex = miss; scrollToIndex(currentIndex);
          return;
        }}

        const answers = {{}};
        (QUIZ.questions||[]).forEach((qq, idx)=>{{ const sel=document.querySelector('input[name="q'+idx+'"]:checked'); answers[String(idx)] = sel?sel.value:null; }});
        const minutes = Math.max(0, Math.round((Date.now()-startedAt)/60000));

        const res = await fetch('/api/submit-quiz', {{
          method:'POST', headers:{{'Content-Type':'application/json'}},
          body: JSON.stringify({{
            quiz_type:'practice', domain: DOMAIN || 'general', questions: QUIZ.questions, answers: answers, time_taken: minutes
          }})
        }});
        const data = await res.json();
        const out = document.getElementById('results');
        if (data.error) {{ out.innerHTML = '<div class="alert alert-danger">'+data.error+'</div>'; return; }}

        // Build detailed results
        let html = '<div class="card border-0 shadow"><div class="card-body">';
        html += '<div class="text-center mb-3">';
        html += '<h3 class="'+(data.score>=80?'text-success':(data.score>=70?'text-warning':'text-danger'))+'">Score: '+data.score.toFixed(1)+'%</h3>';
        html += '<div class="text-muted">Correct: '+data.correct+' / '+data.total+(data.time_taken?(' • Time: '+data.time_taken+' min'):'')+'</div>';
        html += '</div>';
        html += '<h5 class="mb-2">Answer Review</h5>';
        (data.detailed_results||[]).forEach(r=>{{
          const ok = !!r.is_correct;
          html += '<div class="card mb-3 result-card '+(ok?'correct':'incorrect')+'"><div class="card-body">';
          html += '<h6 class="mb-2">'+(ok?'✅':'❌')+' Question '+r.index+'</h6>';
          html += '<div class="mb-2">'+(r.question||'')+'</div>';
          if (ok) {{
            html += '<div class="alert alert-success py-2 mb-2"><strong>Correct:</strong> '+r.correct_letter+') '+(r.correct_text||'')+'</div>';
          }} else {{
            html += '<div class="alert alert-danger py-2 mb-2"><strong>Your answer:</strong> '+(r.user_letter||'—')+(r.user_text?') '+r.user_text:'')+'</div>';
            html += '<div class="alert alert-success py-2 mb-2"><strong>Correct answer:</strong> '+(r.correct_letter||'?')+') '+(r.correct_text||'')+'</div>';
          }}
          if (r.explanation) html += '<div class="small text-muted">💡 '+r.explanation+'</div>';
          html += '</div></div>';
        }});
        html += '</div></div>';
        out.innerHTML = html;
        out.scrollIntoView({{behavior:'smooth', block:'start'}});
      }}

      // Start button
      document.getElementById('startBtn').addEventListener('click', () => {{
        QUIZ = buildQuiz();
        startedAt = Date.now();
        render();
      }});

      // Submit buttons
      submitTop.addEventListener('click', submitQuiz);
      submitBottom.addEventListener('click', submitQuiz);

      // Prev/Next controls + arrow keys
      prevBtn.addEventListener('click', ()=>{{ currentIndex = Math.max(0, currentIndex-1); scrollToIndex(currentIndex); }});
      nextBtn.addEventListener('click', ()=>{{ currentIndex = Math.min((QUIZ?.questions?.length||1)-1, currentIndex+1); scrollToIndex(currentIndex); }});
      document.addEventListener('keydown', (e)=>{{
        if (!QUIZ) return;
        if (e.key === 'ArrowLeft') {{ e.preventDefault(); prevBtn.click(); }}
        if (e.key === 'ArrowRight') {{ e.preventDefault(); nextBtn.click(); }}
      }});
    </script>
    """
    return base_layout("Quiz", body)

# --- Mock Exam (same UX as quiz, with 25/50/75/100) ---
@app.get("/mock-exam")
def mock_exam_page():
    chips = "".join([f'<span class="domain-chip" data-domain="{k}">{v}</span>' for k, v in DOMAINS.items()])
    body = f"""
    <div class="row"><div class="col-md-11 mx-auto">
      <div class="card border-0 shadow">
        <div class="card-header bg-warning text-dark"><h4 class="mb-0">🏁 Mock Exam</h4></div>
        <div class="card-body">
          <div class="sticky-head">
            <div class="row g-2 align-items-center">
              <div class="col-md-6">
                <div class="mb-1"><strong>Choose a domain (optional):</strong></div>
                {chips}
              </div>
              <div class="col-md-3">
                <div class="mb-1"><strong>Questions:</strong></div>
                <div class="btn-group" role="group">
                  <input type="radio" class="btn-check" name="mcount" id="mc25" value="25" checked>
                  <label class="btn btn-outline-primary btn-sm" for="mc25">25</label>
                  <input type="radio" class="btn-check" name="mcount" id="mc50" value="50">
                  <label class="btn btn-outline-primary btn-sm" for="mc50">50</label>
                  <input type="radio" class="btn-check" name="mcount" id="mc75" value="75">
                  <label class="btn btn-outline-primary btn-sm" for="mc75">75</label>
                  <input type="radio" class="btn-check" name="mcount" id="mc100" value="100">
                  <label class="btn btn-outline-primary btn-sm" for="mc100">100</label>
                </div>
              </div>
              <div class="col-md-3 text-end">
                <button id="startBtn" class="btn btn-success btn-sm btn-enhanced">Start Exam</button>
              </div>
            </div>
            <div class="d-flex justify-content-between align-items-center mt-2" id="navBar" style="display:none;">
              <div class="small text-muted">Use <strong>← / →</strong> or the buttons</div>
              <div>
                <button id="prevBtn" class="btn btn-outline-secondary btn-sm me-2">← Prev</button>
                <button id="nextBtn" class="btn btn-outline-secondary btn-sm">Next →</button>
              </div>
            </div>
          </div>
          <div id="quiz"></div>
        </div>
        <div class="card-footer d-flex justify-content-between">
          <button id="submitTop" class="btn btn-light btn-enhanced" disabled>Submit (top)</button>
          <button id="submitBottom" class="btn btn-success btn-lg btn-enhanced" disabled>Submit Exam</button>
        </div>
      </div>
      <div id="results" class="mt-4"></div>
    </div></div>

    <script>
      const ALL = {json.dumps(BASE_QUESTIONS)};
      let DOMAIN = 'all', COUNT = 25, QUIZ = null, currentIndex = 0, startedAt = null;

      document.querySelectorAll('.domain-chip').forEach(ch => {{
        ch.addEventListener('click', () => {{
          document.querySelectorAll('.domain-chip').forEach(c => c.classList.remove('active'));
          ch.classList.add('active');
          DOMAIN = ch.dataset.domain;
        }});
      }});
      document.querySelectorAll('input[name="mcount"]').forEach(r => {{ r.addEventListener('change', ()=>{{ COUNT = parseInt(document.querySelector('input[name="mcount"]:checked').value); }}); }});

      function buildQuiz() {{
        const pool = (DOMAIN==='all') ? ALL.slice() : ALL.filter(q => q.domain===DOMAIN);
        const out = [];
        while (out.length < COUNT) {{
          const shuffled = pool.slice().sort(()=>Math.random()-0.5);
          for (const q of shuffled) {{ if(out.length >= COUNT) break; out.push(structuredClone(q)); }}
        }}
        return {{title: 'Mock (' + COUNT + ' questions)', domain: DOMAIN, questions: out.slice(0, COUNT)}};
      }}

      const cont = document.getElementById('quiz');
      const navBar = document.getElementById('navBar');
      const prevBtn = document.getElementById('prevBtn');
      const nextBtn = document.getElementById('nextBtn');
      const submitTop = document.getElementById('submitTop');
      const submitBottom = document.getElementById('submitBottom');

      function render() {{
        cont.innerHTML = '';
        (QUIZ.questions||[]).forEach((qq, idx) => {{
          const card = document.createElement('div');
          card.className = 'mb-3 p-3 border rounded';
          card.id = 'q'+idx;
          card.innerHTML = '<div class="fw-bold text-primary mb-2">Question ' + (idx+1) + ' of ' + (QUIZ.questions||[]).length + '</div>'
                         + '<div class="mb-2">'+ qq.question + '</div>';
          const opts = qq.options || {{}};
          for (const k in opts) {{
            const id = 'q' + idx + '_' + k;
            const row = document.createElement('div');
            row.className = 'form-check mb-1';
            row.innerHTML = '<input class="form-check-input" type="radio" name="q'+idx+'" id="'+id+'" value="'+k+'">'
                          + '<label class="form-check-label" for="'+id+'">'+k+') '+opts[k]+'</label>';
            row.querySelector('input').addEventListener('change', () => enableSubmitIfAllAnswered());
            card.appendChild(row);
          }}
          cont.appendChild(card);
        }});
        currentIndex = 0;
        scrollToIndex(currentIndex);
        navBar.style.display = 'flex';
        enableSubmitIfAllAnswered();
      }}

      function scrollToIndex(i) {{ const el=document.getElementById('q'+i); if(el) el.scrollIntoView({{behavior:'smooth', block:'center'}}); }}
      function enableSubmitIfAllAnswered() {{
        const total=(QUIZ.questions||[]).length;
        let answered=0;
        for(let i=0;i<total;i++) if (document.querySelector('input[name="q'+i+'"]:checked')) answered++;
        const ready = (answered===total);
        submitTop.disabled=!ready; submitBottom.disabled=!ready;
      }}
      function firstUnanswered(){{ const total=(QUIZ.questions||[]).length; for(let i=0;i<total;i++) if(!document.querySelector('input[name="q'+i+'"]:checked')) return i; return -1; }}

      async function submitQuiz() {{
        const miss = firstUnanswered();
        if (miss >= 0) {{
          document.querySelectorAll('.missing').forEach(el => el.classList.remove('missing'));
          for (let i=0;i<(QUIZ.questions||[]).length;i++) {{
            const card=document.getElementById('q'+i);
            if (!document.querySelector('input[name="q'+i+'"]:checked')) card.classList.add('missing');
          }}
          currentIndex = miss; scrollToIndex(currentIndex);
          return;
        }}
        const answers={{}};
        (QUIZ.questions||[]).forEach((qq, idx)=>{{ const sel=document.querySelector('input[name="q'+idx+'"]:checked'); answers[String(idx)]=sel?sel.value:null; }});
        const minutes = Math.max(0, Math.round((Date.now()-startedAt)/60000));

        const res = await fetch('/api/submit-quiz', {{
          method:'POST', headers:{{'Content-Type':'application/json'}},
          body: JSON.stringify({{ quiz_type:'mock-exam', domain: DOMAIN||'general', questions: QUIZ.questions, answers, time_taken: minutes }})
        }});
        const data = await res.json();
        const out = document.getElementById('results');
        if (data.error) {{ out.innerHTML = '<div class="alert alert-danger">'+data.error+'</div>'; return; }}

        let html = '<div class="card border-0 shadow"><div class="card-body">';
        html += '<div class="text-center mb-3">';
        html += '<h3 class="'+(data.score>=80?'text-success':(data.score>=70?'text-warning':'text-danger'))+'">Score: '+data.score.toFixed(1)+'%</h3>';
        html += '<div class="text-muted">Correct: '+data.correct+' / '+data.total+(data.time_taken?(' • Time: '+data.time_taken+' min'):'')+'</div>';
        html += '</div>';
        html += '<h5 class="mb-2">Answer Review</h5>';
        (data.detailed_results||[]).forEach(r=>{{
          const ok = !!r.is_correct;
          html += '<div class="card mb-3 result-card '+(ok?'correct':'incorrect')+'"><div class="card-body">';
          html += '<h6 class="mb-2">'+(ok?'✅':'❌')+' Question '+r.index+'</h6>';
          html += '<div class="mb-2">'+(r.question||'')+'</div>';
          if (ok) {{
            html += '<div class="alert alert-success py-2 mb-2"><strong>Correct:</strong> '+r.correct_letter+') '+(r.correct_text||'')+'</div>';
          }} else {{
            html += '<div class="alert alert-danger py-2 mb-2"><strong>Your answer:</strong> '+(r.user_letter||'—')+(r.user_text?') '+r.user_text:'')+'</div>';
            html += '<div class="alert alert-success py-2 mb-2"><strong>Correct answer:</strong> '+(r.correct_letter||'?')+') '+(r.correct_text||'')+'</div>';
          }}
          if (r.explanation) html += '<div class="small text-muted">💡 '+r.explanation+'</div>';
          html += '</div></div>';
        }});
        html += '</div></div>';
        out.innerHTML = html;
        out.scrollIntoView({{behavior:'smooth', block:'start'}});
      }}

      document.getElementById('startBtn').addEventListener('click', () => {{ QUIZ=buildQuiz(); startedAt=Date.now(); render(); }});
      submitTop.addEventListener('click', submitQuiz);
      submitBottom.addEventListener('click', submitQuiz);
      prevBtn.addEventListener('click', ()=>{{ currentIndex=Math.max(0,currentIndex-1); scrollToIndex(currentIndex); }});
      nextBtn.addEventListener('click', ()=>{{ currentIndex=Math.min((QUIZ?.questions?.length||1)-1,currentIndex+1); scrollToIndex(currentIndex); }});
      document.addEventListener('keydown', (e)=>{{ if(!QUIZ) return; if(e.key==='ArrowLeft') {{e.preventDefault(); prevBtn.click();}} if(e.key==='ArrowRight') {{e.preventDefault(); nextBtn.click();}} }});
    </script>
    """
    return base_layout("Mock Exam", body)

# --- Submit Quiz API (returns detailed review) ---
@app.post("/api/submit-quiz")
def submit_quiz_api():
    data = request.get_json() or {}
    questions = data.get("questions") or []
    answers = data.get("answers") or {}
    quiz_type = data.get("quiz_type") or "practice"
    domain = (data.get("domain") or "general").strip().lower()
    time_taken = int(data.get("time_taken") or 0)

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

    # record in session for Progress (now includes domain)
    hist = session.get("quiz_history", [])
    hist.append({
        "type": quiz_type,
        "domain": domain,
        "date": datetime.utcnow().isoformat(),
        "score": pct,
        "total": total,
        "correct": correct,
        "time": time_taken,
    })
    session["quiz_history"] = hist[-200:]  # keep last 200 attempts

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
        "time_taken": time_taken,
        "performance_insights": insights,
        "detailed_results": detailed
    })

# --- Progress (session-based) ---
@app.get("/progress")
def progress_page():
    hist = session.get("quiz_history", [])
    avg = round(sum(h["score"] for h in hist)/len(hist), 1) if hist else 0.0

    # table rows (same as before)
    rows = "".join([
        f"<tr><td>{h['date'][:19].replace('T',' ')}</td><td>{h.get('type','')}</td><td>{h.get('correct',0)}/{h.get('total',0)}</td><td>{round(h.get('score',0.0),1)}%</td></tr>"
        for h in reversed(hist)
    ]) or '<tr><td colspan="4" class="text-center text-muted">No data yet — take a quiz!</td></tr>'

    body_top = """
    <div class="row"><div class="col-md-10 mx-auto">
      <div class="card border-0 shadow mb-3">
        <div class="card-header bg-info text-white"><h4 class="mb-0">📊 Progress</h4></div>
        <div class="card-body">
          <div class="row align-items-center">
            <div class="col-lg-6">
              <div id="gaugeProgress" class="mb-2"></div>
              <div class="text-muted small">Overall average of saved attempts</div>
            </div>
            <div class="col-lg-6">
              <div class="mb-2"><strong>Average Score:</strong> """
    body_avg = str(avg)
    body_mid = """%</div>
              <p class="mb-0 text-muted">Tip: aim for steady improvement. Review missed questions first.</p>
            </div>
          </div>
        </div>
      </div>

      <div class="card border-0 shadow">
        <div class="card-header bg-light"><strong>History</strong></div>
        <div class="card-body">
          <div class="table-responsive">
            <table class="table table-sm align-middle">
              <thead class="table-light"><tr><th>When (UTC)</th><th>Type</th><th>Correct</th><th>Score</th></tr></thead>
              <tbody>"""
    body_rows = rows
    body_mid2 = """</tbody>
            </table>
          </div>
          <div class="text-end">
            <form method="post" action="/progress/reset" onsubmit="return confirm('Clear session progress?');">
              <button class="btn btn-outline-danger btn-sm">Reset Session Progress</button>
            </form>
          </div>
        </div>
      </div>
    </div></div>

    <script>
      (function () {
        var pct = """
    body_pct = str(avg)
    body_bot = """;
        if (isNaN(pct)) { pct = 0; }
        if (pct < 0) pct = 0;
        if (pct > 100) pct = 100;

        var el = document.getElementById('gaugeProgress');
        var w = 360, h = 200;
        var cx = w/2, cy = h - 10, r = Math.min(w, h*2) * 0.46;
        var start = 180, end = 0;

        function polar(cx, cy, r, a) {
          var rad = (a - 90) * Math.PI/180;
          return {x: cx + r * Math.cos(rad), y: cy + r * Math.sin(rad)};
        }
        function arc(cx, cy, r, a0, a1) {
          var p0 = polar(cx,cy,r,a0), p1 = polar(cx,cy,r,a1);
          var large = ((a1 - a0 + 360) % 360) > 180 ? 1 : 0;
          var sweep = a1 > a0 ? 1 : 0;
          return 'M ' + p0.x.toFixed(1) + ' ' + p0.y.toFixed(1)
               + ' A ' + r + ' ' + r + ' 0 ' + large + ' ' + sweep + ' '
               + p1.x.toFixed(1) + ' ' + p1.y.toFixed(1);
        }

        var col = '#dc3545';
        if (pct >= 70) col = '#fd7e14';
        if (pct >= 80) col = '#ffc107';
        if (pct >= 90) col = '#28a745';

        var svg = '<svg width="' + w + '" height="' + h + '" viewBox="0 0 ' + w + ' ' + h + '">';
        svg += '<path d="' + arc(cx,cy,r,start,end) + '" fill="none" stroke="#e9ecef" stroke-width="18" stroke-linecap="round"/>';
        var sweep = (end - start) * (pct/100);
        svg += '<path d="' + arc(cx,cy,r,start,start+sweep) + '" fill="none" stroke="' + col + '" stroke-width="18" stroke-linecap="round"/>';

        for (var t = 0; t <= 10; t++) {
          var a = start + (end - start) * (t/10);
          var p0 = polar(cx,cy,r+2,a);
          var p1 = polar(cx,cy,r-12,a);
          svg += '<line x1="' + p0.x.toFixed(1) + '" y1="' + p0.y.toFixed(1)
              + '" x2="' + p1.x.toFixed(1) + '" y2="' + p1.y.toFixed(1)
              + '" stroke="#ced4da" stroke-width="2" />';
        }

        var na = start + (end - start) * (pct/100);
        var pn = polar(cx,cy,r-8,na);
        svg += '<line x1="' + cx.toFixed(1) + '" y1="' + cy.toFixed(1)
            + '" x2="' + pn.x.toFixed(1) + '" y2="' + pn.y.toFixed(1)
            + '" stroke="#343a40" stroke-width="3" />';
        svg += '<circle cx="' + cx.toFixed(1) + '" cy="' + cy.toFixed(1) + '" r="5" fill="#343a40" />';

        svg += '<text x="' + cx.toFixed(1) + '" y="' + (cy-20).toFixed(1) + '" text-anchor="middle" font-size="22" font-weight="700" fill="#212529">' + pct.toFixed(1) + '%</text>';
        svg += '</svg>';
        el.innerHTML = svg;
      })();
    </script>
    """
    body = body_top + body_avg + body_mid + body_rows + body_mid2 + body_pct + body_bot
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








