# app.py — MVP with domains on all blocks, speedometer gauge, bottom submit buttons, missing-answer jump, auto-scroll to review

from flask import Flask, request, jsonify, session, redirect, url_for
from datetime import datetime
import os, json, random, textwrap, requests
from urllib.parse import urlencode

app = Flask(__name__)

# --- Basic config ---
app.secret_key = os.environ.get("SECRET_KEY") or os.urandom(24)
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
OPENAI_CHAT_MODEL = os.environ.get("OPENAI_CHAT_MODEL", "gpt-4o-mini")
OPENAI_API_BASE = os.environ.get("OPENAI_API_BASE", "https://api.openai.com/v1")

# --- Questions (sample set; you can add more later) ---
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

# --- Helpers ---
def _session_average_score() -> float:
    hist = session.get("quiz_history", [])
    if not hist:
        return 0.0
    return round(sum(h["score"] for h in hist) / len(hist), 1)

def _domain_label(key: str) -> str:
    return DOMAINS.get(key, "All Domains")

def build_quiz(num: int, domain: str | None = None) -> dict:
    # Filter by domain if provided (not "all")
    if domain and domain != "all":
        pool = [q for q in BASE_QUESTIONS if q.get("domain") == domain]
    else:
        pool = BASE_QUESTIONS[:]
    if not pool:
        pool = BASE_QUESTIONS[:]
    out = []
    temp = pool[:]
    while len(out) < num:
        random.shuffle(temp)
        for q in temp:
            if len(out) >= num:
                break
            out.append(q.copy())
    return {"title": f"Practice ({num} questions)", "domain": domain or "all", "questions": out[:num]}

def chat_with_ai(msgs: list[str]) -> str:
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

def _domain_chips_as_links(base_path: str, selected: str, extra: dict) -> str:
    """Build clickable chips that reload the page with a domain selected."""
    items = [("all", "All Domains")] + list(DOMAINS.items())
    chips = []
    for key, label in items:
        qs = extra.copy()
        qs["domain"] = key
        href = f"{base_path}?{urlencode(qs)}" if qs else base_path
        cls = "domain-chip active" if key == (selected or "all") else "domain-chip"
        chips.append(f'<a class="{cls}" href="{href}">{label}</a>')
    return "".join(chips)

def base_layout(title: str, body_html: str) -> str:
    css = """
    <style>
      .domain-chip {
        display:inline-block; margin:4px 6px 4px 0; padding:8px 12px; border-radius:20px;
        background:#e3f2fd; color:#1976d2; border:1px solid #bbdefb; user-select:none; text-decoration:none;
      }
      .domain-chip.active { background:#1976d2; color:#fff; border-color:#1976d2; }
      .btn-enhanced { border-radius:8px; font-weight:600; }

      /* Review cards */
      .result-card { border-left: 4px solid; transition: all 0.2s ease; }
      .result-card.correct { border-left-color: #28a745; background: linear-gradient(90deg, rgba(40,167,69,0.07) 0%, transparent 100%); }
      .result-card.incorrect { border-left-color: #dc3545; background: linear-gradient(90deg, rgba(220,53,69,0.07) 0%, transparent 100%); }
      .unanswered { outline: 2px solid #dc3545; background:#fff5f5; }

      .small-muted { color:#6c757d; font-size:0.9rem; }

      /* SPEEDOMETER (needle + ticks) */
      .speedo { width: 240px; height: 120px; position: relative; margin: 8px auto; }
      .speedo-arc {
        width: 100%; height: 100%; border-radius: 240px 240px 0 0 / 120px 120px 0 0;
        background: conic-gradient(#dc3545 0deg 60deg, #ffc107 60deg 120deg, #28a745 120deg 180deg, transparent 180deg 360deg);
        clip-path: inset(0 0 50% 0);
        box-shadow: inset 0 0 0 8px #fff, 0 2px 8px rgba(0,0,0,0.08);
      }
      .speedo-ticks .tick {
        position: absolute; bottom: 0; left: 50%;
        width: 2px; height: 12px; background:#444;
        transform-origin: bottom center;
        opacity: 0.8;
      }
      .speedo-needle {
        position: absolute; bottom: 0; left: 50%;
        width: 3px; height: 95px; background: #111; transform-origin: bottom center;
        transform: rotate(-90deg) translateX(-50%);
        filter: drop-shadow(0 1px 1px rgba(0,0,0,0.4));
      }
      .speedo-hub {
        position: absolute; bottom: -6px; left: 50%; transform: translateX(-50%);
        width: 18px; height: 18px; background:#111; border-radius:50%; border:3px solid #fff;
      }
      .speedo-value {
        position: absolute; left: 50%; bottom: 10px; transform: translateX(-50%);
        background: #fff; padding: 4px 10px; border-radius: 12px; border:1px solid #e9ecef; font-weight: 700;
      }
    </style>
    <script>
      function setupGauge(rootId, percent) {
        const root = document.getElementById(rootId);
        if (!root) return;
        // ticks
        const ticksWrap = document.createElement('div');
        ticksWrap.className = 'speedo-ticks';
        for (let i=0; i<=10; i++) {
          const t = document.createElement('div');
          t.className = 'tick';
          const angle = -90 + i * 18; // 11 ticks -> 10 intervals
          t.style.transform = 'rotate(' + angle + 'deg) translateX(-50%)';
          ticksWrap.appendChild(t);
        }
        root.appendChild(ticksWrap);
        // needle
        const needle = root.querySelector('.speedo-needle');
        const p = Math.max(0, Math.min(100, percent || 0));
        const angle = -90 + (p/100) * 180;
        needle.style.transform = 'rotate(' + angle + 'deg) translateX(-50%)';
        const label = root.querySelector('.speedo-value');
        if (label) label.textContent = p.toFixed(1) + '%';
      }
      function scrollToEl(id) {
        const el = document.getElementById(id);
        if (el) el.scrollIntoView({behavior:'smooth', block:'start'});
      }
      function highlightAndScroll(cardId) {
        const el = document.getElementById(cardId);
        if (!el) return;
        el.classList.add('unanswered');
        el.scrollIntoView({behavior:'smooth', block:'center'});
        setTimeout(()=>el.classList.remove('unanswered'), 1500);
      }
    </script>
    """

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
    return textwrap.dedent(f"""
    <!DOCTYPE html>
    <html lang="en"><head>
      <meta charset="utf-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1" />
      <title>{title} - CPP Test Prep</title>
      <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
      <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
      {css}
    </head><body>
      {nav}
      <div class="container mt-4">
        {body_html}
      </div>
      {disclaimer}
    </body></html>
    """)

# --- Health/diagnostics ---
@app.get("/healthz")
def healthz():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}

@app.get("/diag/openai")
def diag_openai():
    msg = chat_with_ai(["Say 'pong' if you can hear me."])
    ok = "pong" in msg.lower()
    return jsonify({"success": ok, "preview": msg[:200]}), (200 if ok else 500)

# --- Home (with true speedometer) ---
@app.get("/")
def home():
    avg = _session_average_score()
    gauge = f"""
    <div class="speedo" id="homeGauge">
      <div class="speedo-arc"></div>
      <div class="speedo-needle"></div>
      <div class="speedo-hub"></div>
      <div class="speedo-value">{avg}%</div>
    </div>
    <script>setupGauge('homeGauge', {avg});</script>
    """
    body = f"""
    <div class="row justify-content-center">
      <div class="col-md-8 text-center">
        <h1 class="mb-2">CPP Test Prep</h1>
        <p class="lead text-muted">AI tutor, flashcards, quizzes, and mock exams.</p>
        <div class="my-2">{gauge}<div class="small-muted">Average score (this browser session)</div></div>
        <div class="d-flex gap-2 justify-content-center mt-3">
          <a class="btn btn-primary btn-lg btn-enhanced" href="/study">Open Tutor</a>
          <a class="btn btn-secondary btn-lg btn-enhanced" href="/flashcards">Flashcards</a>
          <a class="btn btn-success btn-lg btn-enhanced" href="/quiz">Practice Quiz</a>
          <a class="btn btn-warning btn-lg btn-enhanced" href="/mock-exam">Mock Exam</a>
        </div>
      </div>
    </div>
    """
    return base_layout("Home", body)

# --- Tutor (with domain chips already in-page) ---
@app.get("/study")
def study_page():
    chips = "".join([f'<span class="domain-chip" data-domain="{k}">{v}</span>' for k, v in DOMAINS.items()])
    body = f"""
    <div class="row">
      <div class="col-md-8 mx-auto">
        <div class="card border-0 shadow">
          <div class="card-header bg-primary text-white"><h4 class="mb-0">🤖 AI Tutor</h4></div>
          <div class="card-body">
            <div class="mb-3"><strong>Select a domain (optional):</strong><div class="mt-2">{chips}</div></div>
            <div id="chat" style="height: 360px; overflow-y:auto; border:1px solid #e9ecef; border-radius:8px; padding:12px; background:#fafafa;"></div>
            <div class="input-group mt-3">
              <input type="text" id="userInput" class="form-control" placeholder="Ask anything about CPP domains..." />
              <button id="sendBtn" class="btn btn-primary btn-enhanced">Send</button>
            </div>
            <div class="small text-muted mt-2 text-center">Tip: “Explain risk assessment steps with a quick example.”</div>
          </div>
        </div>
      </div>
    </div>
    <script>
      const chatDiv = document.getElementById('chat');
      const input = document.getElementById('userInput');
      const sendBtn = document.getElementById('sendBtn');
      let domain = null;
      document.querySelectorAll('.domain-chip').forEach(ch => {{
        ch.addEventListener('click', () => {{
          document.querySelectorAll('.domain-chip').forEach(c => c.classList.remove('active'));
          ch.classList.add('active');
          domain = ch.dataset.domain;
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
        }} catch(e) {{
          append('assistant', 'Network error.');
        }} finally {{
          sendBtn.disabled = false; sendBtn.textContent = 'Send'; input.focus();
        }}
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

# --- Flashcards (with domain choice) ---
@app.get("/flashcards")
def flashcards_page():
    selected = request.args.get("domain", "all")
    # filter by domain
    pool = BASE_QUESTIONS if selected == "all" else [q for q in BASE_QUESTIONS if q.get("domain") == selected]
    if not pool:
        pool = BASE_QUESTIONS[:]
    cards = []
    for q in pool:
        ans = q["options"].get(q["correct"], "")
        back = "✅ Correct: " + ans + "\\n\\n💡 " + q["explanation"]
        cards.append({"front": q["question"], "back": back})
    cards = (cards * 3)[:20]  # make it feel fuller
    random.shuffle(cards)
    chips = _domain_chips_as_links("/flashcards", selected, {})

    cards_json = json.dumps(cards)
    body = f"""
    <div class="row">
      <div class="col-md-9 mx-auto">
        <div class="card border-0 shadow">
          <div class="card-header bg-secondary text-white d-flex justify-content-between align-items-center">
            <div><h4 class="mb-0">🃏 Flashcards</h4><small>Pick a domain:</small><div class="mt-2">{chips}</div></div>
          </div>
          <div class="card-body">
            <div class="small-muted mb-2">Current: {_domain_label(selected)}</div>
            <div id="card" class="border rounded p-4" style="min-height:220px; background:#f8f9fa; cursor:pointer;"></div>
            <div class="d-flex gap-2 justify-content-center mt-3">
              <button id="btnDK" class="btn btn-outline-danger btn-enhanced">❌ Don't Know</button>
              <button id="btnK" class="btn btn-outline-success btn-enhanced">✅ Know</button>
            </div>
            <div class="text-center mt-2 small-muted">Press J to flip, K for next.</div>
          </div>
        </div>
      </div>
    </div>
    <script>
      const CARDS = {cards_json};
      let i = 0, back=false;
      const el = document.getElementById('card');
      function render() {{
        const c = CARDS[i] || {{front:'No cards', back:''}};
        const txt = (back ? c.back : c.front).replace(/\\n/g,'<br>');
        el.innerHTML = '<div style="font-size:1.1rem; line-height:1.6;">'+txt+'</div><div class="mt-2 small-muted">'+(back?'Back — click/J to see front':'Front — click/J to see back')+'</div>';
      }}
      function next() {{ back=false; i=(i+1)%CARDS.length; render(); }}
      el.addEventListener('click', ()=>{{ back=!back; render(); }});
      document.getElementById('btnDK').addEventListener('click', ()=>{{ next(); }});
      document.getElementById('btnK').addEventListener('click', ()=>{{ next(); }});
      document.addEventListener('keydown', (e)=>{{
        if(e.key.toLowerCase()==='j') {{ back=!back; render(); }}
        if(e.key.toLowerCase()==='k') {{ next(); }}
      }});
      render();
    </script>
    """
    return base_layout("Flashcards", body)

# --- Quiz (domain + count + review + missing jump + bottom submit) ---
@app.get("/quiz")
def quiz_page():
    # count
    try:
        count = int(request.args.get("count", "10"))
    except ValueError:
        count = 10
    if count not in (5, 10, 15, 20):
        count = 10
    # domain
    domain = request.args.get("domain", "all")
    q = build_quiz(count, domain)
    q_json = json.dumps(q)
    chips = _domain_chips_as_links("/quiz", domain, {"count": count})

    body = f"""
    <div class="row"><div class="col-md-10 mx-auto">
      <div class="card border-0 shadow">
        <div class="card-header bg-success text-white d-flex justify-content-between align-items-center">
          <div>
            <h4 class="mb-0">📝 Practice Quiz</h4>
            <div class="small">Pick a domain, then how many questions:</div>
            <div class="mt-2">{chips}</div>
            <div class="mt-2">
              <a class="btn btn-light btn-sm me-1" href="/quiz?{urlencode({'count':5,'domain':domain})}">5</a>
              <a class="btn btn-light btn-sm me-1" href="/quiz?{urlencode({'count':10,'domain':domain})}">10</a>
              <a class="btn btn-light btn-sm me-1" href="/quiz?{urlencode({'count':15,'domain':domain})}">15</a>
              <a class="btn btn-light btn-sm" href="/quiz?{urlencode({'count':20,'domain':domain})}">20</a>
              <span class="badge bg-dark ms-2">Selected: {count}</span>
            </div>
            <div class="small-muted mt-1">Current domain: {_domain_label(domain)}</div>
          </div>
          <button id="submitTop" class="btn btn-light btn-sm btn-enhanced">Submit</button>
        </div>
        <div class="card-body" id="quiz"></div>
        <div class="card-footer text-end">
          <button id="submitBottom" class="btn btn-success btn-lg btn-enhanced">Submit Quiz</button>
        </div>
      </div>
      <div id="results" class="mt-4"></div>
    </div></div>
    <script>
      const QUIZ = {q_json};
      const SELECTED_DOMAIN = {json.dumps(domain)};
      const cont = document.getElementById('quiz');

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
            card.appendChild(row);
          }}
          cont.appendChild(card);
        }});
      }}

      function findUnanswered() {{
        const missing = [];
        (QUIZ.questions||[]).forEach((_, idx) => {{
          const sel = document.querySelector('input[name="q'+idx+'"]:checked');
          if (!sel) missing.push(idx);
        }});
        return missing;
      }}

      async function submitQuiz() {{
        const answers = {{}};
        (QUIZ.questions||[]).forEach((qq, idx) => {{
          const sel = document.querySelector('input[name="q'+idx+'"]:checked');
          answers[String(idx)] = sel ? sel.value : null;
        }});

        const missing = findUnanswered();
        if (missing.length) {{
          // jump to first missing and highlight it
          highlightAndScroll('q' + missing[0]);
          return;
        }}

        const res = await fetch('/api/submit-quiz', {{
          method:'POST', headers:{{'Content-Type':'application/json'}},
          body: JSON.stringify({{ quiz_type:'practice', domain: SELECTED_DOMAIN, questions: QUIZ.questions, answers }})
        }});
        const data = await res.json();
        const out = document.getElementById('results');
        if (data.error) {{ out.innerHTML = '<div class="alert alert-danger">'+data.error+'</div>'; return; }}

        // Summary
        let html = '<a id="reviewTop"></a><div class="card border-0 shadow"><div class="card-body text-center">'
                 + '<h3 class="'+(data.score>=80?'text-success':(data.score>=70?'text-warning':'text-danger'))+'">Score: '+data.score.toFixed(1)+'%</h3>'
                 + '<div class="text-muted">Correct: '+data.correct+' / '+data.total+'</div>'
                 + '</div></div>';

        // Insights
        if (Array.isArray(data.performance_insights)) {{
          html += '<div class="alert alert-info border-0 mt-3"><strong>📈 Performance:</strong><ul class="mb-0">';
          data.performance_insights.forEach(i => {{ html += '<li>'+i+'</li>'; }});
          html += '</ul></div>';
        }}

        // Detailed review
        if (Array.isArray(data.detailed_results)) {{
          html += '<div class="mt-4"><h5>📝 Question Review</h5>';
          data.detailed_results.forEach(r => {{
            const cls = r.is_correct ? 'correct' : 'incorrect';
            html += '<div class="card mb-3 result-card '+cls+'"><div class="card-body">'
                 +  '<div class="fw-bold mb-2">' + (r.is_correct ? '✅ Correct' : '❌ Incorrect') + ' — Question ' + r.index + '</div>'
                 +  '<div class="mb-2">'+ (r.question || '') + '</div>';
            if (!r.is_correct) {{
              html += '<div class="alert alert-danger border-0 py-2 mb-2"><strong>Your answer:</strong> '
                   +  (r.user_letter ? (r.user_letter + ') ') : '') + (r.user_text || '—') + '</div>';
            }}
            html += '<div class="alert alert-success border-0 py-2"><strong>Correct answer:</strong> '
                 +  (r.correct_letter ? (r.correct_letter + ') ') : '') + (r.correct_text || '') + '</div>';
            if (r.explanation) {{
              html += '<div class="mt-2 p-2 bg-light rounded"><strong>💡 Why:</strong> ' + r.explanation + '</div>';
            }}
            html += '</div></div>';
          }});
          html += '</div>';
        }}
        out.innerHTML = html;
        // jump straight to the review
        scrollToEl('reviewTop');
      }}

      document.getElementById('submitTop').addEventListener('click', submitQuiz);
      document.getElementById('submitBottom').addEventListener('click', submitQuiz);
      render();
    </script>
    """
    return base_layout("Quiz", body)

# --- Mock Exam (domain + count + review + missing jump + bottom submit) ---
@app.get("/mock-exam")
def mock_exam_page():
    try:
        count = int(request.args.get("count", "25"))
    except ValueError:
        count = 25
    if count not in (25, 50, 75, 100):
        count = 25
    domain = request.args.get("domain", "all")
    q = build_quiz(count, domain)
    q_json = json.dumps(q)
    chips = _domain_chips_as_links("/mock-exam", domain, {"count": count})

    body = f"""
    <div class="row"><div class="col-md-11 mx-auto">
      <div class="card border-0 shadow">
        <div class="card-header bg-warning text-dark d-flex justify-content-between align-items-center">
          <div>
            <h4 class="mb-0">🏁 Mock Exam</h4>
            <div class="small">Pick a domain, then exam length:</div>
            <div class="mt-2">{chips}</div>
            <div class="mt-2">
              <a class="btn btn-light btn-sm me-1" href="/mock-exam?{urlencode({'count':25,'domain':domain})}">25</a>
              <a class="btn btn-light btn-sm me-1" href="/mock-exam?{urlencode({'count':50,'domain':domain})}">50</a>
              <a class="btn btn-light btn-sm me-1" href="/mock-exam?{urlencode({'count':75,'domain':domain})}">75</a>
              <a class="btn btn-light btn-sm" href="/mock-exam?{urlencode({'count':100,'domain':domain})}">100</a>
              <span class="badge bg-dark ms-2">Selected: {count}</span>
            </div>
            <div class="small-muted mt-1">Current domain: {_domain_label(domain)}</div>
          </div>
          <button id="submitTop" class="btn btn-success btn-sm btn-enhanced">Submit Exam</button>
        </div>
        <div class="card-body" id="quiz"></div>
        <div class="card-footer text-end">
          <button id="submitBottom" class="btn btn-success btn-lg btn-enhanced">Submit Exam</button>
        </div>
      </div>
      <div id="results" class="mt-4"></div>
    </div></div>
    <script>
      const QUIZ = {q_json};
      const SELECTED_DOMAIN = {json.dumps(domain)};
      const cont = document.getElementById('quiz');

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
            card.appendChild(row);
          }}
          cont.appendChild(card);
        }});
      }}

      function findUnanswered() {{
        const missing = [];
        (QUIZ.questions||[]).forEach((_, idx) => {{
          const sel = document.querySelector('input[name="q'+idx+'"]:checked');
          if (!sel) missing.push(idx);
        }});
        return missing;
      }}

      async function submitQuiz() {{
        const answers = {{}};
        const missing = [];
        (QUIZ.questions||[]).forEach((qq, idx) => {{
          const sel = document.querySelector('input[name="q'+idx+'"]:checked');
          if (!sel) missing.push(idx);
          answers[String(idx)] = sel ? sel.value : null;
        }});
        if (missing.length) {{ highlightAndScroll('q' + missing[0]); return; }}

        const res = await fetch('/api/submit-quiz', {{
          method:'POST', headers:{{'Content-Type':'application/json'}},
          body: JSON.stringify({{ quiz_type:'mock-exam', domain: SELECTED_DOMAIN, questions: QUIZ.questions, answers }})
        }});
        const data = await res.json();
        const out = document.getElementById('results');
        if (data.error) {{ out.innerHTML = '<div class="alert alert-danger">'+data.error+'</div>'; return; }}

        let html = '<a id="reviewTop"></a><div class="card border-0 shadow"><div class="card-body text-center">'
                 + '<h3 class="'+(data.score>=80?'text-success':(data.score>=70?'text-warning':'text-danger'))+'">Score: '+data.score.toFixed(1)+'%</h3>'
                 + '<div class="text-muted">Correct: '+data.correct+' / '+data.total+'</div>'
                 + '</div></div>';

        if (Array.isArray(data.performance_insights)) {{
          html += '<div class="alert alert-info border-0 mt-3"><strong>📈 Performance:</strong><ul class="mb-0">';
          data.performance_insights.forEach(i => {{ html += '<li>'+i+'</li>'; }});
          html += '</ul></div>';
        }}

        if (Array.isArray(data.detailed_results)) {{
          html += '<div class="mt-4"><h5>📝 Question Review</h5>';
          data.detailed_results.forEach(r => {{
            const cls = r.is_correct ? 'correct' : 'incorrect';
            html += '<div class="card mb-3 result-card '+cls+'"><div class="card-body">'
                 +  '<div class="fw-bold mb-2">' + (r.is_correct ? '✅ Correct' : '❌ Incorrect') + ' — Question ' + r.index + '</div>'
                 +  '<div class="mb-2">'+ (r.question || '') + '</div>';
            if (!r.is_correct) {{
              html += '<div class="alert alert-danger border-0 py-2 mb-2"><strong>Your answer:</strong> '
                   +  (r.user_letter ? (r.user_letter + ') ') : '') + (r.user_text || '—') + '</div>';
            }}
            html += '<div class="alert alert-success border-0 py-2"><strong>Correct answer:</strong> '
                 +  (r.correct_letter ? (r.correct_letter + ') ') : '') + (r.correct_text || '') + '</div>';
            if (r.explanation) {{
              html += '<div class="mt-2 p-2 bg-light rounded"><strong>💡 Why:</strong> ' + r.explanation + '</div>';
            }}
            html += '</div></div>';
          }});
          html += '</div>';
        }}
        out.innerHTML = html;
        scrollToEl('reviewTop');
      }}

      document.getElementById('submitTop').addEventListener('click', submitQuiz);
      document.getElementById('submitBottom').addEventListener('click', submitQuiz);
      render();
    </script>
    """
    return base_layout("Mock Exam", body)

# --- Submit API (stores domain too) ---
@app.post("/api/submit-quiz")
def submit_quiz_api():
    data = request.get_json() or {}
    questions = data.get("questions") or []
    answers = data.get("answers") or {}
    quiz_type = data.get("quiz_type") or "practice"
    domain = data.get("domain") or "all"

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

    # record in session for Progress
    hist = session.get("quiz_history", [])
    hist.append({
        "type": quiz_type,
        "domain": domain,
        "date": datetime.utcnow().isoformat(),
        "score": round(pct, 1),
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
        "performance_insights": insights,
        "detailed_results": detailed
    })

# --- Progress (with speedometer) ---
@app.get("/progress")
def progress_page():
    hist = session.get("quiz_history", [])
    avg = _session_average_score()
    rows = "".join([
        f"<tr><td>{h['date'][:19].replace('T',' ')}</td><td>{h.get('type','')}</td><td>{_domain_label(h.get('domain','all'))}</td><td>{h['correct']}/{h['total']}</td><td>{round(h['score'],1)}%</td></tr>"
        for h in reversed(hist)
    ]) or '<tr><td colspan="5" class="text-center text-muted">No data yet — take a quiz!</td></tr>'

    gauge_html = f"""
    <div class="speedo" id="progGauge">
      <div class="speedo-arc"></div>
      <div class="speedo-needle"></div>
      <div class="speedo-hub"></div>
      <div class="speedo-value">{avg}%</div>
    </div>
    <script>setupGauge('progGauge', {avg});</script>
    """

    body = f"""
    <div class="row"><div class="col-md-10 mx-auto">
      <div class="card border-0 shadow">
        <div class="card-header bg-info text-white d-flex justify-content-between align-items-center">
          <h4 class="mb-0">📊 Progress</h4>
          <div class="text-end">
            {gauge_html}
            <div class="small-muted">Average score (this browser session)</div>
          </div>
        </div>
        <div class="card-body">
          <div class="table-responsive">
            <table class="table table-sm align-middle">
              <thead class="table-light"><tr><th>When (UTC)</th><th>Type</th><th>Domain</th><th>Correct</th><th>Score</th></tr></thead>
              <tbody>{rows}</tbody>
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
    """
    return base_layout("Progress", body)

@app.post("/progress/reset")
def reset_progress():
    session.pop("quiz_history", None)
    return redirect(url_for("progress_page"))

# --- Errors ---
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

# --- Local run ---
if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=True)
