import os
import json
import random
import re
from datetime import datetime, timedelta
from string import Template

from flask import (
    Flask, request, session, redirect, url_for, jsonify,
    flash, make_response
)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import func

# --------------------------------------------------------------------------------------
# App & DB Setup
# --------------------------------------------------------------------------------------

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev-secret-key")

db_url = os.getenv("DATABASE_URL", "sqlite:///app.db")
# Render/Heroku sometimes provides postgres://; SQLAlchemy needs postgresql+psycopg2://
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql+psycopg2://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

TRIAL_DAYS = 3  # strictly 3 days

# --------------------------------------------------------------------------------------
# Domain Catalog (stable names)
# --------------------------------------------------------------------------------------

CPP_DOMAINS = {
    "security-principles": {"name": "Security Principles & Practices"},
    "business-principles": {"name": "Business Principles & Practices"},
    "investigations": {"name": "Investigations"},
    "personnel-security": {"name": "Personnel Security"},
    "physical-security": {"name": "Physical Security"},
    "information-security": {"name": "Information Security"},
    "crisis-management": {"name": "Crisis Management"},
    "general": {"name": "General"}
}

QUIZ_TYPES = {
    "practice": {"title": "Practice Quiz", "questions": 10},
    "mock-exam": {"title": "Mock Exam", "questions": 100},
}

# --------------------------------------------------------------------------------------
# DB Models
# --------------------------------------------------------------------------------------

class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), nullable=True, unique=True)
    first_name = db.Column(db.String(80))
    last_name = db.Column(db.String(80))
    subscription_status = db.Column(db.String(20), default="trial")  # trial, active, expired
    trial_started_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class QuestionBank(db.Model):
    __tablename__ = "question_bank"
    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(80), nullable=False, default="general")
    difficulty = db.Column(db.String(20), nullable=False, default="medium")
    question = db.Column(db.Text, nullable=False)
    options_json = db.Column(db.Text, nullable=True)  # map of {"A": "...", "B": "..."}
    correct = db.Column(db.String(2), nullable=False, default="A")  # "A"/"B"/"C"/"D"
    explanation = db.Column(db.Text, nullable=True)
    source_name = db.Column(db.String(255), nullable=True)
    source_url = db.Column(db.Text, nullable=True)
    is_verified = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class UserProgress(db.Model):
    __tablename__ = "user_progress"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False, index=True)
    domain = db.Column(db.String(80), nullable=False, default="general")
    topic = db.Column(db.String(120), nullable=True)
    mastery_level = db.Column(db.String(32), nullable=True)  # mastered, good, needs_practice
    average_score = db.Column(db.Float, default=0.0)
    question_count = db.Column(db.Integer, default=0)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow)
    consecutive_good_scores = db.Column(db.Integer, default=0)

class QuizResult(db.Model):
    __tablename__ = "quiz_results"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False, index=True)
    quiz_type = db.Column(db.String(40), nullable=False)
    domain = db.Column(db.String(80), nullable=False, default="general")
    score = db.Column(db.Float, default=0.0)
    total_questions = db.Column(db.Integer, default=0)
    correct_count = db.Column(db.Integer, default=0)
    completed_at = db.Column(db.DateTime, default=datetime.utcnow)
    details_json = db.Column(db.Text, nullable=True)  # per-question review payload

# --------------------------------------------------------------------------------------
# Init & Utilities
# --------------------------------------------------------------------------------------

def init_db():
    db.create_all()
    # Ensure a default user exists (ID=1) for simple dev/testing flows
    u = User.query.get(1)
    if not u:
        u = User(
            id=1,
            email="student@example.com",
            first_name="CPP",
            last_name="Student",
            subscription_status="trial",
        )
        db.session.add(u)
        db.session.commit()
    if not u.trial_started_at:
        u.trial_started_at = datetime.utcnow()
        db.session.commit()

def ensure_user():
    if "user_id" not in session:
        # Auto sign-in as default user for simplicity
        session["user_id"] = 1
        user = User.query.get(1)
        session["user_name"] = f"{user.first_name or ''} {user.last_name or ''}".strip() or "Student"

def subscription_required(view_func):
    def inner(*args, **kwargs):
        ensure_user()
        user = User.query.get(session["user_id"])
        if user.subscription_status == "active":
            return view_func(*args, **kwargs)
        # trial logic
        if not user.trial_started_at:
            user.trial_started_at = datetime.utcnow()
            db.session.commit()
        if datetime.utcnow() <= (user.trial_started_at + timedelta(days=TRIAL_DAYS)):
            return view_func(*args, **kwargs)
        return redirect(url_for("subscribe"))
    inner.__name__ = view_func.__name__
    return inner

def _strip_choice_letter(s: str) -> str:
    """Remove a leading 'A) ' .. 'D) ' from an answer string."""
    if not s:
        return s
    return re.sub(r'^[A-D]\)\s*', '', s).strip()

def _safe_json(obj) -> str:
    try:
        return json.dumps(obj)
    except Exception:
        return "null"

# --------------------------------------------------------------------------------------
# Base Template
# --------------------------------------------------------------------------------------

def render_base_template(title, body_html, user=None):
    if user is None and "user_id" in session:
        user = User.query.get(session["user_id"])

    # Simple, stable design; Bootstrap via CDN
    tpl = Template("""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>$page_title</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet"/>
  <style>
    body { background:#f6f7fb; }
    .topbar { background: #0d6efd; color:#fff; }
    .brand { font-weight: 800; letter-spacing: .4px; }
    .nav-link, .navbar-brand { color:#fff !important; }
    .nav-link.active { text-decoration: underline; }
    .card { box-shadow: 0 8px 24px rgba(0,0,0,.06); border: none; }
    .badge-domain { background:#0d6efd; }
  </style>
</head>
<body>
  <nav class="navbar navbar-expand-lg topbar">
    <div class="container-fluid">
      <a class="navbar-brand brand" href="/dashboard">CPP Test Prep</a>
      <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#topnav">
        <span class="navbar-toggler-icon"></span>
      </button>
      <div class="collapse navbar-collapse" id="topnav">
        <ul class="navbar-nav me-auto mb-2 mb-lg-0">
          <li class="nav-item"><a class="nav-link" href="/study">Tutor</a></li>
          <li class="nav-item"><a class="nav-link" href="/flashcards">Flashcards</a></li>
          <li class="nav-item"><a class="nav-link" href="/quiz-selector">Quizzes</a></li>
          <li class="nav-item"><a class="nav-link" href="/mock-exam">Mock Exam</a></li>
          <li class="nav-item"><a class="nav-link" href="/progress">Progress</a></li>
        </ul>
        <div class="d-flex">
          <span class="me-3">$welcome</span>
          <a class="btn btn-light btn-sm" href="/subscribe">Subscribe</a>
        </div>
      </div>
    </div>
  </nav>
  <main class="container my-4">
    $content
  </main>
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
    """)
    welcome = f"Welcome, {session.get('user_name','Student')}"
    html = tpl.substitute(page_title=title, content=body_html, welcome=welcome)
    resp = make_response(html)
    # Tiny cache buster for scripts if needed: could set headers here.
    return resp

# --------------------------------------------------------------------------------------
# Fallback Quiz Generator (uses DB if present; otherwise synthetic)
# --------------------------------------------------------------------------------------

def db_questions(domain: str | None, difficulty: str, limit: int):
    q = QuestionBank.query.filter(QuestionBank.is_verified.is_(True))
    if domain and domain != "random":
        q = q.filter(QuestionBank.domain == domain)
    if difficulty:
        q = q.filter(QuestionBank.difficulty == difficulty)
    q = q.order_by(func.random()).limit(limit)
    rows = q.all()
    questions = []
    for r in rows:
        try:
            opts = json.loads(r.options_json or "{}")
        except Exception:
            opts = {}
        questions.append({
            "domain": r.domain,
            "difficulty": r.difficulty,
            "question": r.question,
            "options": opts,
            "correct": r.correct,
            "explanation": r.explanation or "",
            "source_name": r.source_name,
            "source_url": r.source_url
        })
    return questions

def synthetic_seed(domain: str | None):
    dn = domain or "general"
    name = CPP_DOMAINS.get(dn, {}).get("name", dn.capitalize())
    # Very small seed set for fallback only (prefer DB content!)
    bank = [
        {
            "question": f"Which statement best describes a core principle in {name}?",
            "options": {"A": "Random policy enforcement", "B": "Risk-based approach", "C": "Ignoring context", "D": "Checklist-only thinking"},
            "correct": "B",
            "explanation": f"In {name}, prioritizing controls based on risk is foundational."
        },
        {
            "question": f"In {name}, what is the primary purpose of incident containment?",
            "options": {"A": "Attribution", "B": "Reduce ongoing impact", "C": "Punishment", "D": "Public relations"},
            "correct": "B",
            "explanation": "Containment limits harm and sets conditions for eradication and recovery."
        },
        {
            "question": f"What is a common pitfall when implementing controls in {name}?",
            "options": {"A": "Continuous improvement", "B": "Overlooking change management", "C": "Documenting processes", "D": "Testing controls"},
            "correct": "B",
            "explanation": "Controls fail if people/process changes aren’t managed."
        },
    ]
    return bank

def generate_fallback_quiz(quiz_type: str, domain: str | None, difficulty: str, num_questions: int):
    # Try DB first
    pulled = db_questions(domain, difficulty, num_questions)
    if not pulled:
        seed = synthetic_seed(domain)
        # sample with replacement to requested size
        for _ in range(num_questions - len(seed)):
            seed.append(random.choice(seed))
        pulled = seed[:num_questions]

    title = QUIZ_TYPES.get(quiz_type, {}).get("title", "Quiz")
    return {
        "quiz_type": quiz_type,
        "title": title,
        "domain": domain or "general",
        "difficulty": difficulty,
        "questions": pulled
    }

# --------------------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------------------

@app.route("/")
def home():
    return redirect(url_for("dashboard"))

@app.route("/dashboard")
@subscription_required
def dashboard():
    user = User.query.get(session["user_id"])
    # Simple welcome + primary actions
    body = """
    <div class="row g-3">
      <div class="col-lg-8">
        <div class="card">
          <div class="card-body">
            <h3 class="mb-1">Welcome back!</h3>
            <p class="text-muted">Keep going—consistency beats cramming. Aim for 80%+ average.</p>
            <div class="d-flex gap-2 flex-wrap">
              <a href="/study" class="btn btn-primary">Open Tutor</a>
              <a href="/flashcards" class="btn btn-outline-primary">Practice Flashcards</a>
              <a href="/quiz-selector" class="btn btn-outline-primary">Start a Quiz</a>
              <a href="/mock-exam" class="btn btn-outline-primary">Mock Exam</a>
              <a href="/progress" class="btn btn-outline-secondary">View Progress</a>
            </div>
          </div>
        </div>
      </div>
      <div class="col-lg-4">
        <div class="card">
          <div class="card-header"><strong>Tips</strong></div>
          <div class="card-body">
            <ul class="mb-0">
              <li>Mix domains to strengthen recall.</li>
              <li>After each quiz, review <em>why</em> answers are right or wrong.</li>
              <li>Use flashcards daily (J=flip, K=next).</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
    """
    return render_base_template("Dashboard", body, user=user)

# --------------------------------------------------------------------------------------
# Subscribe (3-day trial messaging)
# --------------------------------------------------------------------------------------

@app.route("/subscribe")
def subscribe():
    ensure_user()
    user = User.query.get(session["user_id"])
    trial_start = user.trial_started_at or datetime.utcnow()
    trial_end = trial_start + timedelta(days=TRIAL_DAYS)
    remaining = (trial_end - datetime.utcnow()).days
    if remaining < 0:
        remaining = 0
    body = Template("""
    <div class="row">
      <div class="col-lg-8 mx-auto">
        <div class="card">
          <div class="card-body">
            <h3>Trial Ended</h3>
            <p>Your free trial is <strong>$days</strong> days (set to $trial_days). It appears your trial has ended.</p>
            <p>Please contact support to activate your subscription and keep going!</p>
            <a href="/dashboard" class="btn btn-secondary">Back to Dashboard</a>
          </div>
        </div>
      </div>
    </div>
    """).substitute(days=TRIAL_DAYS, trial_days=TRIAL_DAYS)
    return render_base_template("Subscribe", body, user=user)

# --------------------------------------------------------------------------------------
# Tutor
# --------------------------------------------------------------------------------------

@app.route("/study")
@subscription_required
def study():
    user = User.query.get(session["user_id"])
    session["study_start_time"] = datetime.utcnow().timestamp()

    body = """
    <style>
      .tutor-avatar { width: 56px; height: 56px; border-radius: 50%;
        background: linear-gradient(135deg,#a5d8ff,#eebefa);
        display:inline-flex; align-items:center; justify-content:center;
        font-weight:700; color:#123; }
      .chat-msg { white-space: pre-wrap; line-height: 1.45; }
      .suggestions { border-left: 1px solid #eee; padding-left: 12px; }
      .sugg-chip { display:block; background:#e7f5ff; color:#0b7285; padding:8px 10px;
        border-radius:8px; margin-bottom:8px; cursor:pointer; }
      .sugg-chip:hover { background:#d0ebff; }
    </style>

    <div class="row">
      <div class="col-lg-8">
        <div class="card">
          <div class="card-header d-flex align-items-center gap-2">
            <div class="tutor-avatar">AI</div>
            <div>
              <strong>AI Tutor</strong><br/>
              <small class="text-muted">Ask about any CPP topic.</small>
            </div>
          </div>
          <div class="card-body">
            <div id="chat" style="height: 420px; overflow-y: auto; border: 1px solid #eee; padding: 10px; margin-bottom: 12px;"></div>
            <div class="input-group">
              <input type="text" id="userInput" class="form-control" placeholder="Ask about any CPP topic..." />
              <button id="sendBtn" class="btn btn-primary">Send</button>
            </div>
          </div>
        </div>
      </div>

      <div class="col-lg-4">
        <div class="card">
          <div class="card-header"><strong>Suggestions</strong></div>
          <div class="card-body suggestions">
            <div class="sugg-chip">Summarize the Physical Security domain for me.</div>
            <div class="sugg-chip">Give me 3 scenario-based questions about Crisis Management.</div>
            <div class="sugg-chip">Explain CPTED vs traditional access control with examples.</div>
            <div class="sugg-chip">Make a 1-week study plan for Investigations.</div>
            <div class="sugg-chip">What are common mistakes on the CPP exam?</div>
          </div>
        </div>
      </div>
    </div>

    <script>
      const chatDiv = document.getElementById('chat');
      const input = document.getElementById('userInput');
      const sendBtn = document.getElementById('sendBtn');

      function append(role, text) {
        const el = document.createElement('div');
        el.className = role === 'user' ? 'text-end mb-3' : 'text-start mb-3';
        const badge = '<span class="badge ' + (role === 'user' ? 'bg-primary' : 'bg-secondary') + '">' + (role === 'user' ? 'You' : 'Tutor') + '</span>';
        const body = '<div class="mt-1 p-2 border rounded chat-msg">' + text.replace(/</g,'&lt;') + '</div>';
        el.innerHTML = badge + ' ' + body;
        chatDiv.appendChild(el);
        chatDiv.scrollTop = chatDiv.scrollHeight;
      }

      async function send() {
        const q = input.value.trim();
        if (!q) return;
        append('user', q);
        input.value = '';
        try {
          const res = await fetch('/chat', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({message: q})
          });
          const data = await res.json();
          if (data.response) append('assistant', data.response);
          else append('assistant', data.error || 'Sorry, something went wrong.');
        } catch (e) {
          append('assistant', 'Network error.');
        }
      }

      sendBtn.addEventListener('click', send);
      input.addEventListener('keydown', (e) => { if (e.key === 'Enter') send(); });

      // Suggestions click -> fill and send
      document.querySelectorAll('.sugg-chip').forEach(ch => {
        ch.addEventListener('click', () => {
          input.value = ch.textContent.trim();
          send();
        });
      });
    </script>
    """
    return render_base_template("Study", body, user=user)

@app.post("/chat")
@subscription_required
def chat_api():
    # Placeholder tutor logic (format with paragraphs & bullets when possible)
    data = request.get_json(silent=True) or {}
    msg = (data.get("message") or "").strip()
    if not msg:
        return jsonify({"error": "Empty message."})

    # simple canned formatter that produces readable output
    response_lines = []
    if "scenario" in msg.lower() or "real" in msg.lower():
        response_lines.append("**Scenario:**")
        response_lines.append("You are the security manager at a multi-tenant facility. A power outage has affected access control on two floors during a storm.")
        response_lines.append("")
        response_lines.append("**Questions to consider:**")
        response_lines.append("1) What is your immediate containment step?")
        response_lines.append("2) Which stakeholders do you notify and in what order?")
        response_lines.append("3) How do you maintain physical access while systems are restored?")
        response_lines.append("4) What corrective actions will you log for the after-action review?")
    else:
        response_lines.append("Here’s a structured explanation:")
        response_lines.append("")
        response_lines.append("• **Definition:** A brief, exam-focused definition of the topic.")
        response_lines.append("• **Why it matters:** Connect to risk, cost, and operations.")
        response_lines.append("• **How to apply:** Concrete steps or decision points.")
        response_lines.append("• **Exam tip:** Look for keywords and elimination strategies.")

    return jsonify({"response": "\n".join(response_lines)})

# --------------------------------------------------------------------------------------
# Flashcards
# --------------------------------------------------------------------------------------

@app.get("/api/flashcards")
@subscription_required
def api_flashcards():
    """
    Return flashcards from DB if present; else from fallback quiz generator.
    Strips leading letters from answers (A)/B)/C)/D)).
    """
    try:
        domain = (request.args.get("domain") or "random").strip()
        try:
            count = int(request.args.get("count", 100))
        except ValueError:
            count = 100
        count = max(20, min(500, count))

        cards = []

        # Prefer DB QuestionBank as source
        rows = db_questions(None if domain == "random" else domain, "medium", count)
        if rows:
            for r in rows:
                opts = r.get("options", {}) or {}
                correct_letter = r.get("correct")
                correct_text = _strip_choice_letter(str(opts.get(correct_letter, "")).strip())
                back = correct_text
                if r.get("explanation"):
                    back = f"{back}\n\n{str(r.get('explanation')).strip()}"
                cards.append({
                    "front": str(r.get("question", "")).strip(),
                    "back": back.strip(),
                    "domain": r.get("domain", "general")
                })
        else:
            # Fallback: synthesize
            synthesized = generate_fallback_quiz(
                quiz_type="practice",
                domain=None if domain == "random" else domain,
                difficulty="medium",
                num_questions=count
            )
            for q in synthesized.get("questions", []):
                front = str(q.get("question", "")).strip()
                correct_letter = q.get("correct")
                options = q.get("options", {}) or {}
                correct_text = _strip_choice_letter(str(options.get(correct_letter, "")).strip())
                back = correct_text
                if q.get("explanation"):
                    back = f"{back}\n\n{str(q.get('explanation')).strip()}"
                cards.append({
                    "front": front,
                    "back": back.strip(),
                    "domain": q.get("domain", "general")
                })

        return jsonify({"cards": cards})
    except Exception as e:
        print(f"/api/flashcards error: {e}")
        return jsonify({"cards": []})

@app.route("/flashcards")
@subscription_required
def flashcards_page():
    user = User.query.get(session["user_id"])
    body = """
    <style>
      .fc-wrap { max-width: 980px; margin: 0 auto; }
      .fc-instructions { background: #f8f9fa; border: 1px solid #eee; border-radius: 8px; padding: 12px; }
      .fc-chips { display: flex; flex-wrap: wrap; gap: 8px; margin: 12px 0 20px; }
      .chip { padding: 8px 12px; border-radius: 20px; background: #e8f0fe; color: #0d47a1; cursor: pointer; user-select: none; }
      .chip.active { background: #0d6efd; color: #fff; }
      .fc-card {
        width: 640px; max-width: 100%;
        aspect-ratio: 3/2;
        margin: 12px auto;
        border-radius: 16px;
        box-shadow: 0 8px 32px rgba(0,0,0,0.08);
        background: #fff4e6;
        color: #333;
        display: flex; align-items: center; justify-content: center;
        font-size: 1.35rem; font-weight: 500; padding: 22px; text-align: center;
        border: 2px solid #ffd8a8;
      }
      .fc-card.back { background: #e8f7ff; border-color: #a5d8ff; }
      .fc-ctr { display:flex; gap:10px; justify-content:center; align-items:center; margin-top: 12px; flex-wrap: wrap; }
      .fc-btn { border:none; border-radius:10px; padding:10px 16px; cursor:pointer; font-weight:600; }
      .fc-btn.primary { background:#0d6efd; color:#fff; }
      .fc-btn.secondary { background:#e9ecef; color:#222; }
      .fc-buckets small { color:#666; }
      .kbd { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace; background:#f1f3f5; padding:2px 6px; border-radius:6px; border:1px solid #dee2e6; }
    </style>

    <div class="fc-wrap">
      <h3 class="mb-2">Flashcards</h3>
      <div class="fc-instructions mb-3">
        <strong>How to use:</strong> Click the card to flip. Press <span class="kbd">J</span> to flip, <span class="kbd">K</span> for next.
        Mark <em>Don't know</em> or <em>Know</em> to help the system space repetitions. Domain counts appear on hover.
      </div>

      <div class="fc-chips" id="fcChips">
        <div class="chip active" data-domain="random" title="All domains">Random</div>
        <div class="chip" data-domain="security-principles" title="Security Principles & Practices">Security Principles</div>
        <div class="chip" data-domain="business-principles" title="Business Principles & Practices">Business</div>
        <div class="chip" data-domain="investigations" title="Investigations">Investigations</div>
        <div class="chip" data-domain="personnel-security" title="Personnel Security">Personnel</div>
        <div class="chip" data-domain="physical-security" title="Physical Security">Physical</div>
        <div class="chip" data-domain="information-security" title="Information Security">Information</div>
        <div class="chip" data-domain="crisis-management" title="Crisis Management">Crisis</div>
      </div>

      <div id="fcCard" class="fc-card" role="button" aria-label="Flashcard">Loading...</div>

      <div class="fc-ctr">
        <button id="btnFlip" class="fc-btn secondary">Flip (J)</button>
        <button id="btnDontKnow" class="fc-btn secondary">Don't know</button>
        <button id="btnKnow" class="fc-btn secondary">Know</button>
        <button id="btnNext" class="fc-btn primary">Next (K)</button>
      </div>

      <div class="fc-buckets text-center mt-2">
        <small>Spaced repetition buckets: <span id="bucketCounts">New: 0 • Learning: 0 • Review: 0</span></small>
      </div>

      <div class="text-center mt-3">
        <a href="/dashboard" class="btn btn-outline-secondary">Back to Dashboard</a>
      </div>
    </div>

    <script>
      const cardEl = document.getElementById('fcCard');
      const chipsEl = document.getElementById('fcChips');
      const btnFlip = document.getElementById('btnFlip');
      const btnNext = document.getElementById('btnNext');
      const btnKnow = document.getElementById('btnKnow');
      const btnDontKnow = document.getElementById('btnDontKnow');

      let state = {
        domain: 'random',
        deck: [],
        idx: 0,
        showBack: false,
        buckets: { new: 0, learning: 0, review: 0 }
      };

      function renderCard() {
        if (!state.deck.length) {
          cardEl.classList.remove('back');
          cardEl.textContent = 'No cards loaded yet.';
          return;
        }
        const c = state.deck[state.idx];
        cardEl.classList.toggle('back', state.showBack);
        cardEl.textContent = state.showBack ? c.back : c.front;
      }

      function loadDeck() {
        cardEl.textContent = 'Loading...';
        fetch(`/api/flashcards?domain=${state.domain}&count=100`)
          .then(r => r.json())
          .then(data => {
            state.deck = (data.cards || []);
            state.idx = 0;
            state.showBack = false;
            renderCard();
          }).catch(() => {
            cardEl.textContent = 'Failed to load cards.';
          });
      }

      chipsEl.addEventListener('click', (e) => {
        const el = e.target.closest('.chip');
        if (!el) return;
        document.querySelectorAll('.chip').forEach(ch => ch.classList.remove('active'));
        el.classList.add('active');
        state.domain = el.getAttribute('data-domain');
        loadDeck();
      });

      cardEl.addEventListener('click', () => { state.showBack = !state.showBack; renderCard(); });
      btnFlip.addEventListener('click', () => { state.showBack = !state.showBack; renderCard(); });
      btnNext.addEventListener('click', () => {
        if (!state.deck.length) return;
        state.idx = (state.idx + 1) % state.deck.length;
        state.showBack = false;
        renderCard();
      });

      btnKnow.addEventListener('click', () => {
        state.buckets.review++;
        updateBuckets();
        btnNext.click();
      });

      btnDontKnow.addEventListener('click', () => {
        state.buckets.learning++;
        updateBuckets();
        btnNext.click();
      });

      function updateBuckets() {
        const el = document.getElementById('bucketCounts');
        el.textContent = `New: ${state.buckets.new} • Learning: ${state.buckets.learning} • Review: ${state.buckets.review}`;
      }

      window.addEventListener('keydown', (e) => {
        if (e.key.toLowerCase() === 'j') { e.preventDefault(); btnFlip.click(); }
        if (e.key.toLowerCase() === 'k') { e.preventDefault(); btnNext.click(); }
      });

      loadDeck();
    </script>
    """
    return render_base_template("Flashcards", body, user=user)

# --------------------------------------------------------------------------------------
# Quiz Selector / Quiz / Submit
# --------------------------------------------------------------------------------------

@app.route("/quiz-selector")
@subscription_required
def quiz_selector():
    user = User.query.get(session["user_id"])
    # Simple selector with domain chips + question counts + difficulty
    body = """
    <style>
      .chip { padding: 8px 12px; border-radius: 20px; background: #0d6efd; color: #fff; cursor: pointer; user-select: none; display:inline-block; margin:4px; }
      .chip.outline { background:#eff3ff; color:#0d6efd; border:1px solid #cfe2ff; }
      .chip.active { outline: 2px solid #0b5ed7; }
    </style>

    <div class="card">
      <div class="card-header"><strong>Quick Start</strong></div>
      <div class="card-body">
        <div class="mb-2">Choose a domain:</div>
        <div id="domains">
          <span class="chip active" data-domain="random">Random</span>
          <span class="chip" data-domain="security-principles">Security Principles</span>
          <span class="chip" data-domain="business-principles">Business</span>
          <span class="chip" data-domain="investigations">Investigations</span>
          <span class="chip" data-domain="personnel-security">Personnel</span>
          <span class="chip" data-domain="physical-security">Physical</span>
          <span class="chip" data-domain="information-security">Information</span>
          <span class="chip" data-domain="crisis-management">Crisis</span>
        </div>

        <hr/>

        <div class="mb-2">How many questions?</div>
        <div id="counts">
          <span class="chip outline active" data-count="5">5</span>
          <span class="chip outline" data-count="10">10</span>
          <span class="chip outline" data-count="15">15</span>
          <span class="chip outline" data-count="20">20</span>
        </div>

        <hr/>

        <div class="mb-2">Difficulty</div>
        <div id="difficulty">
          <span class="chip outline active" data-diff="easy">Easy</span>
          <span class="chip outline" data-diff="medium">Medium</span>
          <span class="chip outline" data-diff="hard">Hard</span>
        </div>

        <hr/>
        <div class="d-flex gap-2">
          <a id="startPractice" class="btn btn-primary">Start Practice</a>
        </div>
      </div>
    </div>

    <script>
      let domain = 'random';
      let count = 5;
      let diff = 'easy';

      document.getElementById('domains').addEventListener('click', (e) => {
        const el = e.target.closest('.chip');
        if (!el) return;
        document.querySelectorAll('#domains .chip').forEach(c => c.classList.remove('active'));
        el.classList.add('active');
        domain = el.getAttribute('data-domain');
      });

      document.getElementById('counts').addEventListener('click', (e) => {
        const el = e.target.closest('.chip');
        if (!el) return;
        document.querySelectorAll('#counts .chip').forEach(c => c.classList.remove('active'));
        el.classList.add('active');
        count = el.getAttribute('data-count');
      });

      document.getElementById('difficulty').addEventListener('click', (e) => {
        const el = e.target.closest('.chip');
        if (!el) return;
        document.querySelectorAll('#difficulty .chip').forEach(c => c.classList.remove('active'));
        el.classList.add('active');
        diff = el.getAttribute('data-diff');
      });

      document.getElementById('startPractice').addEventListener('click', () => {
        window.location.href = `/quiz/practice?domain=${domain}&count=${count}&difficulty=${diff}`;
      });
    </script>
    """
    return render_base_template("Quiz Selector", body, user=user)

@app.route("/quiz/<quiz_type>")
@subscription_required
def quiz(quiz_type):
    user = User.query.get(session["user_id"])
    if quiz_type not in QUIZ_TYPES:
        flash("Invalid quiz type.", "danger")
        return redirect(url_for("quiz_selector"))

    domain = request.args.get("domain", "random")
    difficulty = request.args.get("difficulty", "medium")
    try:
        requested = int(request.args.get("count", QUIZ_TYPES.get(quiz_type, {}).get("questions", 10)))
    except ValueError:
        requested = QUIZ_TYPES.get(quiz_type, {}).get("questions", 10)
    requested = max(5, min(50, requested))
    session["quiz_start_time"] = datetime.utcnow().timestamp()

    quiz_data = generate_fallback_quiz(quiz_type, None if domain == "random" else domain, difficulty, requested)
    quiz_json = _safe_json(quiz_data)

    page = Template("""
    <div class="row">
      <div class="col-md-10 mx-auto">
        <div class="card">
          <div class="card-header d-flex justify-content-between align-items-center">
            <h4 class="mb-0">$title</h4>
            <button id="submitBtnTop" class="btn btn-success">Submit</button>
          </div>
          <div class="card-body" id="quizContainer"></div>
          <div class="card-footer text-end">
            <button id="submitBtnBottom" class="btn btn-success">Submit</button>
          </div>
        </div>
        <div class="mt-4" id="results"></div>
      </div>
    </div>
    <script>
      const QUIZ_DATA = $quiz_json;

      function renderQuiz() {
        const container = document.getElementById('quizContainer');
        container.innerHTML = '';
        (QUIZ_DATA.questions || []).forEach((q, idx) => {
          const card = document.createElement('div');
          card.className = 'mb-3 p-3 border rounded';
          const title = document.createElement('h5');
          title.textContent = 'Q' + (idx + 1) + '. ' + q.question;
          card.appendChild(title);

          const options = q.options || {};
          Object.keys(options).forEach((key) => {
            const optId = 'q' + idx + '_' + key;
            const div = document.createElement('div');
            div.className = 'form-check';
            const input = document.createElement('input');
            input.className = 'form-check-input';
            input.type = 'radio';
            input.name = 'q' + idx;
            input.id = optId;
            input.value = key;
            const label = document.createElement('label');
            label.className = 'form-check-label';
            label.htmlFor = optId;
            label.textContent = key + ') ' + options[key];
            div.appendChild(input);
            div.appendChild(label);
            card.appendChild(div);
          });
          container.appendChild(card);
        });
      }

      async function submitQuiz() {
        const answers = {};
        (QUIZ_DATA.questions || []).forEach((q, idx) => {
          const selected = document.querySelector('input[name="q' + idx + '"]:checked');
          answers[String(idx)] = selected ? selected.value : null;
        });
        try {
          const res = await fetch('/submit-quiz', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
              quiz_type: QUIZ_DATA.quiz_type,
              domain: QUIZ_DATA.domain,
              questions: QUIZ_DATA.questions,
              answers: answers
            })
          });
          const data = await res.json();
          const resultsDiv = document.getElementById('results');
          if (data.error) {
            resultsDiv.innerHTML = '<div class="alert alert-danger">' + data.error + '</div>';
            return;
          }

          let html = '<div class="card"><div class="card-body">';
          html += '<h4>Score: ' + data.score.toFixed(1) + '% (' + data.correct + '/' + data.total + ')</h4>';
          if (Array.isArray(data.performance_insights)) {
            html += '<ul>';
            data.performance_insights.forEach(p => { html += '<li>' + p + '</li>'; });
            html += '</ul>';
          }
          html += '</div></div>';

          if (Array.isArray(data.results)) {
            html += '<div class="mt-3">';
            data.results.forEach((r) => {
              const ok = !!r.is_correct;
              const cls = ok ? 'border-success bg-success-subtle' : 'border-danger bg-danger-subtle';
              html += '<div class="p-3 border rounded mb-2 ' + cls + '">';
              html += '<div><strong>Q' + r.index + '.</strong> ' + (r.question || '') + '</div>';
              if (ok) {
                html += '<div class="mt-1 text-success"><strong>Correct:</strong> ' + (r.user_letter || '') + ') ' + (r.user_text || '') + '</div>';
              } else {
                html += '<div class="mt-1 text-danger"><strong>Your answer:</strong> ' + ((r.user_letter || '—')) + (r.user_text ? (') ' + r.user_text) : '') + '</div>';
                html += '<div class="mt-1 text-success"><strong>Correct:</strong> ' + (r.correct_letter || '') + ') ' + (r.correct_text || '') + '</div>';
              }
              if (r.explanation) {
                html += '<div class="mt-2"><em>' + r.explanation + '</em></div>';
              }
              html += '</div>';
            });
            html += '</div>';
          }

          resultsDiv.innerHTML = html;
          window.scrollTo({ top: resultsDiv.offsetTop - 20, behavior: 'smooth' });
        } catch (e) {
          document.getElementById('results').innerHTML = '<div class="alert alert-danger">Submission failed.</div>';
        }
      }

      document.getElementById('submitBtnTop').addEventListener('click', submitQuiz);
      document.getElementById('submitBtnBottom').addEventListener('click', submitQuiz);
      renderQuiz();
    </script>
    """)
    content = page.substitute(title=quiz_data["title"], quiz_json=quiz_json)
    return render_base_template("Quiz", content, user=user)

@app.post("/submit-quiz")
@subscription_required
def submit_quiz():
    data = request.get_json(silent=True) or {}
    questions = data.get("questions") or []
    answers = data.get("answers") or {}
    quiz_type = data.get("quiz_type", "practice")
    domain = data.get("domain") or "general"

    results = []
    correct = 0
    total = len(questions)

    for idx, q in enumerate(questions):
        opts = q.get("options", {}) or {}
        correct_letter = q.get("correct")
        user_ans = answers.get(str(idx))
        is_ok = (user_ans == correct_letter)
        if is_ok:
            correct += 1
        results.append({
            "index": idx + 1,
            "question": q.get("question"),
            "is_correct": bool(is_ok),
            "user_letter": user_ans,
            "user_text": opts.get(user_ans) if user_ans else None,
            "correct_letter": correct_letter,
            "correct_text": opts.get(correct_letter),
            "explanation": q.get("explanation")
        })

    score_pct = (correct / total * 100) if total else 0.0

    # store QuizResult
    user_id = session["user_id"]
    qr = QuizResult(
        user_id=user_id,
        quiz_type=quiz_type,
        domain=domain if domain else "general",
        score=score_pct,
        total_questions=total,
        correct_count=correct,
        completed_at=datetime.utcnow(),
        details_json=json.dumps(results)
    )
    db.session.add(qr)

    # update UserProgress by domain
    up = UserProgress.query.filter_by(user_id=user_id, domain=domain if domain else "general", topic=None).first()
    if not up:
        up = UserProgress(
            user_id=user_id,
            domain=domain if domain else "general",
            topic=None,
            mastery_level="needs_practice",
            average_score=0.0,
            question_count=0,
            last_updated=datetime.utcnow(),
            consecutive_good_scores=0
        )
        db.session.add(up)

    # rolling average by question_count
    prev_total = up.question_count or 0
    prev_avg = up.average_score or 0.0
    new_total = prev_total + total
    new_avg = ((prev_avg * prev_total) + (score_pct * total)) / new_total if new_total else score_pct
    up.average_score = new_avg
    up.question_count = new_total
    up.last_updated = datetime.utcnow()
    # simple mastery heuristic
    if score_pct >= 85:
        up.mastery_level = "mastered"
    elif score_pct >= 70:
        up.mastery_level = "good"
    else:
        up.mastery_level = "needs_practice"
    # consecutive >=80 tracker
    if score_pct >= 80:
        up.consecutive_good_scores = (up.consecutive_good_scores or 0) + 1
    else:
        up.consecutive_good_scores = 0

    db.session.commit()

    # basic performance insights
    insights = []
    if score_pct < 80:
        insights.append("Focus on your weaker options; review the explanations for each incorrect question.")
    else:
        insights.append("Great job! Keep practicing to maintain >80% consistency.")

    return jsonify({
        "score": score_pct,
        "correct": correct,
        "total": total,
        "results": results,
        "performance_insights": insights
    })

# --------------------------------------------------------------------------------------
# Mock Exam
# --------------------------------------------------------------------------------------

@app.route("/mock-exam")
@subscription_required
def mock_exam():
    user = User.query.get(session["user_id"])
    try:
        requested = int(request.args.get("count", 0))
    except ValueError:
        requested = 0

    if requested not in (25, 50, 75, 100):
        content = """
        <div class="row">
          <div class="col-md-8 mx-auto">
            <div class="card">
              <div class="card-header"><h4 class="mb-0">Mock Exam</h4></div>
              <div class="card-body">
                <p>Select the number of questions:</p>
                <div class="d-flex gap-2 flex-wrap">
                  <a class="btn btn-primary" href="/mock-exam?count=25">25</a>
                  <a class="btn btn-primary" href="/mock-exam?count=50">50</a>
                  <a class="btn btn-primary" href="/mock-exam?count=75">75</a>
                  <a class="btn btn-primary" href="/mock-exam?count=100">100</a>
                </div>
                <hr/>
                <p class="text-muted mb-0">Questions are randomized across all domains.</p>
              </div>
            </div>
          </div>
        </div>
        """
        return render_base_template("Mock Exam", content, user=user)

    num_questions = requested
    session["quiz_start_time"] = datetime.utcnow().timestamp()
    quiz_data = generate_fallback_quiz("mock-exam", domain=None, difficulty="medium", num_questions=num_questions)
    quiz_json = _safe_json(quiz_data)

    page = Template("""
    <div class="row">
      <div class="col-md-10 mx-auto">
        <div class="card">
          <div class="card-header d-flex justify-content-between align-items-center">
            <h4 class="mb-0">Mock Exam ($num Q)</h4>
            <button id="submitBtnTop" class="btn btn-success">Submit</button>
          </div>
          <div class="card-body" id="quizContainer"></div>
          <div class="card-footer text-end">
            <button id="submitBtnBottom" class="btn btn-success">Submit</button>
          </div>
        </div>
        <div class="mt-4" id="results"></div>
      </div>
    </div>
    <script>
      const QUIZ_DATA = $quiz_json;

      function renderQuiz() {
        const container = document.getElementById('quizContainer');
        container.innerHTML = '';
        (QUIZ_DATA.questions || []).forEach((q, idx) => {
          const card = document.createElement('div');
          card.className = 'mb-3 p-3 border rounded';
          const title = document.createElement('h5');
          title.textContent = 'Q' + (idx + 1) + '. ' + q.question;
          card.appendChild(title);

          const options = q.options || {};
          for (const key in options) {
            const optId = 'q' + idx + '_' + key;
            const div = document.createElement('div');
            div.className = 'form-check';
            const input = document.createElement('input');
            input.className = 'form-check-input';
            input.type = 'radio';
            input.name = 'q' + idx;
            input.id = optId;
            input.value = key;
            const label = document.createElement('label');
            label.className = 'form-check-label';
            label.htmlFor = optId;
            label.textContent = key + ') ' + options[key];
            div.appendChild(input);
            div.appendChild(label);
            card.appendChild(div);
          }
          container.appendChild(card);
        });
      }

      async function submitQuiz() {
        const answers = {};
        (QUIZ_DATA.questions || []).forEach((q, idx) => {
          const selected = document.querySelector('input[name="q' + idx + '"]:checked');
          answers[String(idx)] = selected ? selected.value : null;
        });
        try {
          const res = await fetch('/submit-quiz', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
              quiz_type: 'mock-exam',
              domain: 'general',
              questions: QUIZ_DATA.questions,
              answers: answers
            })
          });
          const data = await res.json();
          const resultsDiv = document.getElementById('results');
          if (data.error) {
            resultsDiv.innerHTML = '<div class="alert alert-danger">' + data.error + '</div>';
            return;
          }

          let html = '<div class="card"><div class="card-body">';
          html += '<h4>Score: ' + data.score.toFixed(1) + '% (' + data.correct + '/' + data.total + ')</h4>';
          if (Array.isArray(data.performance_insights)) {
            html += '<ul>';
            data.performance_insights.forEach(p => { html += '<li>' + p + '</li>'; });
            html += '</ul>';
          }
          html += '</div></div>';

          if (Array.isArray(data.results)) {
            html += '<div class="mt-3">';
            data.results.forEach((r) => {
              const ok = !!r.is_correct;
              const cls = ok ? 'border-success bg-success-subtle' : 'border-danger bg-danger-subtle';
              html += '<div class="p-3 border rounded mb-2 ' + cls + '">';
              html += '<div><strong>Q' + r.index + '.</strong> ' + (r.question || '') + '</div>';
              if (ok) {
                html += '<div class="mt-1 text-success"><strong>Correct:</strong> ' + (r.user_letter || '') + ') ' + (r.user_text || '') + '</div>';
              } else {
                html += '<div class="mt-1 text-danger"><strong>Your answer:</strong> ' + ((r.user_letter || '—')) + (r.user_text ? (') ' + r.user_text) : '') + '</div>';
                html += '<div class="mt-1 text-success"><strong>Correct:</strong> ' + (r.correct_letter || '') + ') ' + (r.correct_text || '') + '</div>';
              }
              if (r.explanation) {
                html += '<div class="mt-2"><em>' + r.explanation + '</em></div>';
              }
              html += '</div>';
            });
            html += '</div>';
          }

          resultsDiv.innerHTML = html;
          window.scrollTo({ top: resultsDiv.offsetTop - 20, behavior: 'smooth' });
        } catch (e) {
          document.getElementById('results').innerHTML = '<div class="alert alert-danger">Submission failed.</div>';
        }
      }

      document.getElementById('submitBtnTop').addEventListener('click', submitQuiz);
      document.getElementById('submitBtnBottom').addEventListener('click', submitQuiz);
      renderQuiz();
    </script>
    """)
    content = page.substitute(num=num_questions, quiz_json=quiz_json)
    return render_base_template("Mock Exam", content, user=user)

# --------------------------------------------------------------------------------------
# Progress (speedometer dial + table)
# --------------------------------------------------------------------------------------

@app.route("/progress")
@subscription_required
def progress_page():
    user = User.query.get(session["user_id"])

    rows = UserProgress.query.filter_by(user_id=user.id).order_by(UserProgress.domain.asc()).all()

    last10 = QuizResult.query.filter_by(user_id=user.id).order_by(QuizResult.completed_at.desc()).limit(10).all()
    if last10:
        overall_avg = sum([(r.score or 0.0) for r in last10]) / len(last10)
    else:
        overall_avg = 0.0

    target = 80.0
    dial_pct = 0 if target <= 0 else max(0, min(100, round((overall_avg / target) * 100)))
    dial_deg = (dial_pct * 1.8)  # 0..180deg

    def mastery_color(m):
        if (m or "").lower() == "mastered":
            return "bg-success text-white"
        if (m or "").lower() == "good":
            return "bg-warning text-dark"
        return "bg-danger text-white"

    tr_html = []
    for r in rows:
        color_cls = mastery_color(r.mastery_level or "needs_practice")
        dom_name = CPP_DOMAINS.get(r.domain, {}).get("name", r.domain)
        tr_html.append(
            f"<tr>"
            f"<td>{dom_name}</td>"
            f"<td><span class='badge {color_cls}'>{(r.mastery_level or 'needs_practice')}</span></td>"
            f"<td>{(r.average_score or 0):.1f}%</td>"
            f"<td>{int(r.question_count or 0)}</td>"
            f"<td>{(r.last_updated or datetime.utcnow()).strftime('%Y-%m-%d')}</td>"
            f"</tr>"
        )

    gauge = Template("""
    <style>
      .gauge-wrap { position: relative; width: 220px; height: 120px; margin-left: auto; }
      .gauge-arc {
        width: 100%; height: 100%;
        background:
          conic-gradient(#e03131 0 ${red_end}deg,
                         #f08c00 ${red_end}deg ${orange_end}deg,
                         #2f9e44 ${orange_end}deg ${green_end}deg,
                         #e9ecef ${green_end}deg 180deg);
        border-radius: 0 0 220px 220px / 0 0 120px 120px;
        transform: rotate(-90deg);
      }
      .gauge-center {
        position: absolute; left: 50%; bottom: 0; transform: translateX(-50%);
        width: 10px; height: 10px; background: #495057; border-radius: 50%;
      }
      .needle {
        position: absolute; left: 50%; bottom: 0; transform-origin: bottom center;
        transform: translateX(-50%) rotate(${deg}deg);
        width: 2px; height: 100px; background: #212529;
      }
    </style>
    <div class="d-flex align-items-start mb-3">
      <div><h3 class="mb-0">Your Progress</h3><div class="text-muted">Toward consistent 80% performance</div></div>
      <div class="gauge-wrap ms-auto">
        <div class="gauge-arc"></div>
        <div class="needle"></div>
        <div class="gauge-center"></div>
        <div class="text-center mt-2"><strong>${avg}%</strong> avg (last 10)</div>
      </div>
    </div>
    """).substitute(
        red_end=min(33, dial_pct) * 1.8,
        orange_end=min(66, dial_pct) * 1.8,
        green_end=dial_deg,
        deg=(dial_deg - 90),  # needle
        avg=f"{overall_avg:.1f}"
    )

    table_html = """
    <div class="card">
      <div class="card-header"><strong>Domain Mastery</strong></div>
      <div class="card-body">
        <div class="table-responsive">
          <table class="table align-middle">
            <thead>
              <tr><th>Domain</th><th>Mastery</th><th>Avg Score</th><th>Questions</th><th>Last Updated</th></tr>
            </thead>
            <tbody>
              {rows}
            </tbody>
          </table>
        </div>
      </div>
    </div>
    """.format(rows=("".join(tr_html) if tr_html else "<tr><td colspan='5' class='text-muted'>No data yet. Take some quizzes!</td></tr>"))

    content = gauge + table_html
    return render_base_template("Progress", content, user=user)

# --------------------------------------------------------------------------------------
# Run
# --------------------------------------------------------------------------------------

if __name__ == "__main__":
    # For local testing; Render uses Gunicorn
    init_db()
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=False)

