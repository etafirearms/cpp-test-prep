# app.py — Stable MVP (no DB), with Tutor, Flashcards, Quiz/Mock, Progress

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
      </style>
    </head><body>
      {nav}
      <div class="container mt-4">
        {body_html}
      </div>
      {disclaimer}
    </body></html>
    """)

def build_quiz(num: int) -> dict:
    # Expand the pool to hit the requested size (repeat shuffled blocks)
    out = []
    pool = BASE_QUESTIONS[:]
    while len(out) < num:
        random.shuffle(pool)
        for q in pool:
            if len(out) >= num:
                break
            out.append(q.copy())
    return {"title": f"Practice ({num} questions)", "questions": out[:num]}

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
        msg = chat_with_ai(["Say 'pong' if you can hear me."])
        ok = "pong" in msg.lower()
        return jsonify({"success": ok, "preview": msg[:200]}), (200 if ok else 500)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# --- Home ---
@app.get("/")
def home():
    body = """
    <div class="row justify-content-center">
      <div class="col-md-8 text-center">
        <h1 class="mb-3">CPP Test Prep</h1>
        <p class="lead text-muted">AI tutor, flashcards, quizzes, and mock exams — ready to go.</p>
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

# --- Tutor ---
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

# --- Flashcards ---
@app.get("/flashcards")
def flashcards_page():
    # Build ~20 cards from questions
    cards = []
    for q in BASE_QUESTIONS:
        ans = q["options"].get(q["correct"], "")
        back = "✅ Correct: " + ans + "\\n\\n💡 " + q["explanation"]
        cards.append({"front": q["question"], "back": back})
    # Duplicate/shuffle to feel fuller
    cards = (cards * 3)[:20]
    random.shuffle(cards)
    cards_json = json.dumps(cards)
    body = f"""
    <div class="row">
      <div class="col-md-9 mx-auto">
        <div class="card border-0 shadow">
          <div class="card-header bg-secondary text-white"><h4 class="mb-0">🃏 Flashcards</h4></div>
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
      const CARDS = {cards_json};
      let i = 0, back=false, dk=0, k=0;
      const el = document.getElementById('card');
      function render() {{
        const c = CARDS[i] || {{front:'No cards', back:''}};
        const txt = (back ? c.back : c.front).replace(/\\n/g,'<br>');
        el.innerHTML = '<div style="font-size:1.1rem; line-height:1.6;">'+txt+'</div><div class="mt-2 small text-muted">'+(back?'Back — click/J to see front':'Front — click/J to see back')+'</div>';
      }}
      function next() {{ back=false; i=(i+1)%CARDS.length; render(); }}
      el.addEventListener('click', ()=>{{ back=!back; render(); }});
      document.getElementById('btnDK').addEventListener('click', ()=>{{ dk++; next(); }});
      document.getElementById('btnK').addEventListener('click', ()=>{{ k++; next(); }});
      document.addEventListener('keydown', (e)=>{{
        if(e.key.toLowerCase()==='j') {{ back=!back; render(); }}
        if(e.key.toLowerCase()==='k') {{ next(); }}
      }});
      render();
    </script>
    """
    return base_layout("Flashcards", body)

# --- Quiz + Mock Exam ---
@app.get("/quiz")
def quiz_page():
    q = build_quiz(10)
    q_json = json.dumps(q)
    body = f"""
    <div class="row"><div class="col-md-10 mx-auto">
      <div class="card border-0 shadow">
        <div class="card-header bg-success text-white d-flex justify-content-between align-items-center">
          <div><h4 class="mb-0">📝 Practice Quiz</h4><small>10 questions</small></div>
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
      const cont = document.getElementById('quiz');
      function render() {{
        cont.innerHTML = '';
        (QUIZ.questions||[]).forEach((qq, idx) => {{
          const card = document.createElement('div');
          card.className = 'mb-3 p-3 border rounded';
          card.id = 'q'+idx;
          card.innerHTML = '<div class="fw-bold text-primary mb-2">Question ' + (idx+1) + '</div>'
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
      async function submitQuiz() {{
        const answers = {{}};
        (QUIZ.questions||[]).forEach((qq, idx) => {{
          const sel = document.querySelector('input[name="q'+idx+'"]:checked');
          answers[String(idx)] = sel ? sel.value : null;
        }});
        const res = await fetch('/api/submit-quiz', {{
          method:'POST', headers:{{'Content-Type':'application/json'}},
          body: JSON.stringify({{ quiz_type:'practice', domain:'general', questions: QUIZ.questions, answers }})
        }});
        const data = await res.json();
        const out = document.getElementById('results');
        if (data.error) {{ out.innerHTML = '<div class="alert alert-danger">'+data.error+'</div>'; return; }}
        // Save to session progress (display returned data)
        out.innerHTML = '<div class="card border-0 shadow"><div class="card-body text-center">'
                      + '<h3 class="'+(data.score>=80?'text-success':(data.score>=70?'text-warning':'text-danger'))+'">Score: '+data.score.toFixed(1)+'%</h3>'
                      + '<div class="text-muted">Correct: '+data.correct+' / '+data.total+'</div>'
                      + (data.time_taken ? '<div class="text-muted">Time: '+data.time_taken+' min</div>' : '')
                      + '</div></div>';
        window.scrollTo({{top: 0, behavior: 'smooth'}});
      }}
      document.getElementById('submitTop').addEventListener('click', submitQuiz);
      document.getElementById('submitBottom').addEventListener('click', submitQuiz);
      render();
    </script>
    """
    return base_layout("Quiz", body)

@app.get("/mock-exam")
def mock_exam_page():
    q = build_quiz(25)
    q_json = json.dumps(q)
    body = f"""
    <div class="row"><div class="col-md-11 mx-auto">
      <div class="card border-0 shadow">
        <div class="card-header bg-warning text-dark">
          <h4 class="mb-0">🏁 Mock Exam</h4><small>25 questions — answer all before submitting</small>
        </div>
        <div class="card-body" id="quiz"></div>
        <div class="card-footer text-end">
          <button id="submit" class="btn btn-success btn-lg btn-enhanced">Submit Exam</button>
        </div>
      </div>
      <div id="results" class="mt-4"></div>
    </div></div>
    <script>
      const QUIZ = {q_json};
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
      async function submitQuiz() {{
        const answers = {{}};
        const unanswered = [];
        (QUIZ.questions||[]).forEach((qq, idx) => {{
          const sel = document.querySelector('input[name="q'+idx+'"]:checked');
          if (!sel) unanswered.push(idx+1);
          answers[String(idx)] = sel ? sel.value : null;
        }});
        if (unanswered.length) {{
          alert('Please answer all questions. Missing: Q' + unanswered.join(', Q'));
          return;
        }}
        const res = await fetch('/api/submit-quiz', {{
          method:'POST', headers:{{'Content-Type':'application/json'}},
          body: JSON.stringify({{ quiz_type:'mock-exam', domain:'general', questions: QUIZ.questions, answers }})
        }});
        const data = await res.json();
        const out = document.getElementById('results');
        if (data.error) {{ out.innerHTML = '<div class="alert alert-danger">'+data.error+'</div>'; return; }}
        out.innerHTML = '<div class="card border-0 shadow"><div class="card-body text-center">'
                      + '<h3 class="'+(data.score>=80?'text-success':(data.score>=70?'text-warning':'text-danger'))+'">Score: '+data.score.toFixed(1)+'%</h3>'
                      + '<div class="text-muted">Correct: '+data.correct+' / '+data.total+'</div>'
                      + (data.time_taken ? '<div class="text-muted">Time: '+data.time_taken+' min</div>' : '')
                      + '</div></div>';
        window.scrollTo({{top: 0, behavior: 'smooth'}});
      }}
      document.getElementById('submit').addEventListener('click', submitQuiz);
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

    # record in session for Progress
    hist = session.get("quiz_history", [])
    hist.append({
        "type": quiz_type,
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
        "performance_insights": insights,
        "detailed_results": detailed
    })

# --- Progress (session-based for now) ---
@app.get("/progress")
def progress_page():
    hist = session.get("quiz_history", [])
    avg = round(sum(h["score"] for h in hist)/len(hist), 1) if hist else 0.0
    rows = "".join([
        f"<tr><td>{h['date'][:19].replace('T',' ')}</td><td>{h['type']}</td><td>{h['correct']}/{h['total']}</td><td>{round(h['score'],1)}%</td></tr>"
        for h in reversed(hist)
    ]) or '<tr><td colspan="4" class="text-center text-muted">No data yet — take a quiz!</td></tr>'
    body = f"""
    <div class="row"><div class="col-md-10 mx-auto">
      <div class="card border-0 shadow">
        <div class="card-header bg-info text-white"><h4 class="mb-0">📊 Progress</h4></div>
        <div class="card-body">
          <div class="mb-3"><strong>Average Score:</strong> {avg}%</div>
          <div class="table-responsive">
            <table class="table table-sm align-middle">
              <thead class="table-light"><tr><th>When (UTC)</th><th>Type</th><th>Correct</th><th>Score</th></tr></thead>
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
