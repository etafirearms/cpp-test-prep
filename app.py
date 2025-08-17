# app.py — Minimal, stable base you can build on
from flask import Flask, request, redirect, url_for, flash, session, jsonify, Response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from string import Template
from functools import wraps
import json
import os
import random

# -----------------------------------------------------------------------------
# App & Config
# -----------------------------------------------------------------------------
app = Flask(__name__)

# Secret key (sessions)
SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    # Safe fallback for local/dev, but prefer setting SECRET_KEY in Render
    SECRET_KEY = os.urandom(32).hex()
app.config["SECRET_KEY"] = SECRET_KEY

# Database
DB_URL = os.environ.get("DATABASE_URL", "").strip()
if DB_URL.startswith("postgres://"):
    # SQLAlchemy expects postgresql://
    DB_URL = DB_URL.replace("postgres://", "postgresql://", 1)

# Fallback to SQLite if no DATABASE_URL set (useful locally)
if not DB_URL:
    DB_URL = "sqlite:///app.db"

app.config["SQLALCHEMY_DATABASE_URI"] = DB_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Render/Postgres SSL hint (harmless for SQLite)
if DB_URL.startswith("postgresql://"):
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "pool_pre_ping": True,
        "pool_recycle": 300,
        "connect_args": {"sslmode": "require"},
    }

db = SQLAlchemy(app)

# -----------------------------------------------------------------------------
# Models (explicit table names to avoid confusion)
# -----------------------------------------------------------------------------
class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(128), nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    # Light progress data we can expand later
    study_time = db.Column(db.Integer, default=0)
    quiz_scores = db.Column(db.Text, default="[]")  # JSON list of previous scores


class QuizResult(db.Model):
    __tablename__ = "quiz_results"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    quiz_type = db.Column(db.String(50), nullable=False)           # practice | mock-exam
    domain = db.Column(db.String(50), default="general")
    questions = db.Column(db.Text, nullable=False)                 # JSON array
    answers = db.Column(db.Text, nullable=False)                   # JSON dict
    score = db.Column(db.Float, nullable=False)
    total_questions = db.Column(db.Integer, nullable=False)
    time_taken = db.Column(db.Integer)                             # minutes
    completed_at = db.Column(db.DateTime, default=datetime.utcnow)

# Create tables on boot (idempotent)
with app.app_context():
    db.create_all()

# -----------------------------------------------------------------------------
# Data for quizzes (you can add more later)
# -----------------------------------------------------------------------------
QUIZ_TYPES = {
    "practice": {"name": "Practice Quiz", "questions": 10},
    "mock-exam": {"name": "Mock Exam", "questions": 50},
}

CPP_DOMAINS = {
    "security-principles": {"name": "Security Principles & Practices"},
    "business-principles": {"name": "Business Principles & Practices"},
    "investigations": {"name": "Investigations"},
    "personnel-security": {"name": "Personnel Security"},
    "physical-security": {"name": "Physical Security"},
    "information-security": {"name": "Information Security"},
    "crisis-management": {"name": "Crisis Management"},
}

BASE_QUESTIONS = [
    {
        "question": "What is the primary purpose of a security risk assessment?",
        "options": {
            "A": "Identify all threats",
            "B": "Determine cost-effective mitigation",
            "C": "Eliminate all risks",
            "D": "Satisfy compliance"
        },
        "correct": "B",
        "explanation": "It balances risk, cost, and impact to choose best mitigations.",
        "domain": "security-principles",
        "difficulty": "medium",
    },
    {
        "question": "In CPTED, natural surveillance primarily accomplishes what?",
        "options": {
            "A": "Reduces guard costs",
            "B": "Increases observation likelihood",
            "C": "Eliminates cameras",
            "D": "Provides legal protection"
        },
        "correct": "B",
        "explanation": "It makes potential offenders feel observed.",
        "domain": "physical-security",
        "difficulty": "medium",
    },
    {
        "question": "Which concept means applying multiple security layers so if one fails others still protect?",
        "options": {"A": "Security by Obscurity", "B": "Defense in Depth", "C": "Zero Trust", "D": "Least Privilege"},
        "correct": "B",
        "explanation": "Layered controls prevent single-point failure.",
        "domain": "security-principles",
        "difficulty": "medium",
    },
    {
        "question": "In incident response, what is usually the FIRST priority?",
        "options": {"A": "Notify law enforcement", "B": "Contain the incident", "C": "Eradicate malware", "D": "Lessons learned"},
        "correct": "B",
        "explanation": "Containment limits further damage before eradication.",
        "domain": "information-security",
        "difficulty": "medium",
    },
]

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        uid = session.get("user_id")
        if not uid:
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        user = User.query.get(uid)
        if not user:
            session.clear()
            flash("Your session expired. Please log in again.", "warning")
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper

def render_base_template(title, content_html, user=None):
    nav = ""
    if user:
        nav = (
            '<nav class="navbar navbar-expand-lg navbar-dark bg-primary">'
            '  <div class="container">'
            '    <a class="navbar-brand" href="/dashboard">CPP Test Prep</a>'
            '    <div class="navbar-nav ms-auto">'
            '      <a class="nav-link" href="/dashboard">Dashboard</a>'
            '      <a class="nav-link" href="/quiz-selector">Quizzes</a>'
            '      <a class="nav-link" href="/logout">Logout</a>'
            '    </div>'
            '  </div>'
            '</nav>'
        )
    css = """
    <style>
      .domain-chip{display:inline-block;margin:4px 6px 4px 0;padding:8px 12px;border-radius:20px;background:#e3f2fd;color:#1976d2;border:1px solid #bbdefb;cursor:pointer;}
      .domain-chip.active,.domain-chip:hover{background:#1976d2;color:#fff;}
      .btn-enhanced{border-radius:8px;font-weight:600}
    </style>
    """
    page = Template("""<!doctype html>
<html><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1" />
<title>$title</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
$css
</head>
<body>
  $nav
  <div class="container mt-4">$content</div>
</body></html>""")
    return page.substitute(title=title, nav=nav, css=css, content=content_html)

def generate_quiz(quiz_type, domain="random", difficulty="medium", count=10):
    # Choose pool by domain; repeat/shuffle to fill count
    if domain and domain not in ("random", "general"):
        pool = [q for q in BASE_QUESTIONS if q.get("domain") == domain] or BASE_QUESTIONS[:]
    else:
        pool = BASE_QUESTIONS[:]
    out = []
    while len(out) < count:
        batch = pool[:]
        random.shuffle(batch)
        for q in batch:
            if len(out) >= count:
                break
            out.append(q.copy())
    return {
        "title": f"CPP {quiz_type.replace('-', ' ').title()}",
        "quiz_type": quiz_type,
        "domain": (domain or "general"),
        "difficulty": difficulty,
        "questions": out[:count],
    }

# -----------------------------------------------------------------------------
# Health & basics
# -----------------------------------------------------------------------------
@app.get("/favicon.ico")
def favicon():
    return Response("", status=204)

@app.get("/healthz")
def healthz():
    try:
        db.session.execute(db.text("SELECT 1"))
        return {"status": "healthy", "time": datetime.utcnow().isoformat()}, 200
    except Exception as e:
        return {"status": "unhealthy", "error": str(e)}, 500

@app.route("/")
def home():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    content = """
    <div class="row justify-content-center">
      <div class="col-md-8 text-center">
        <h1 class="mb-3">CPP Test Prep</h1>
        <p class="lead text-muted">A simple, working base you can build on.</p>
        <div class="mt-4">
          <a href="/register" class="btn btn-primary btn-lg me-2 btn-enhanced">Create Account</a>
          <a href="/login" class="btn btn-outline-primary btn-lg btn-enhanced">Login</a>
        </div>
      </div>
    </div>
    """
    return render_base_template("Home", content)

# -----------------------------------------------------------------------------
# Auth
# -----------------------------------------------------------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = (request.form.get("email") or "").lower().strip()
        password = request.form.get("password") or ""
        first_name = (request.form.get("first_name") or "").strip()
        last_name = (request.form.get("last_name") or "").strip()

        if not all([email, password, first_name, last_name]):
            flash("All fields are required.", "danger")
            return redirect(url_for("register"))
        if len(password) < 8:
            flash("Password must be at least 8 characters.", "danger")
            return redirect(url_for("register"))
        if User.query.filter_by(email=email).first():
            flash("Email already registered. Please log in.", "warning")
            return redirect(url_for("login"))

        user = User(
            email=email,
            password_hash=generate_password_hash(password),
            first_name=first_name,
            last_name=last_name,
            study_time=0,
            quiz_scores="[]",
        )
        db.session.add(user)
        db.session.commit()

        session["user_id"] = user.id
        flash(f"Welcome, {first_name}!", "success")
        return redirect(url_for("dashboard"))

    content = """
    <div class="row justify-content-center">
      <div class="col-md-6">
        <div class="card border-0 shadow">
          <div class="card-header bg-primary text-white"><h3 class="mb-0">Create Account</h3></div>
          <div class="card-body">
            <form method="POST">
              <div class="mb-3"><label class="form-label">First Name</label>
                <input name="first_name" class="form-control" required></div>
              <div class="mb-3"><label class="form-label">Last Name</label>
                <input name="last_name" class="form-control" required></div>
              <div class="mb-3"><label class="form-label">Email</label>
                <input type="email" name="email" class="form-control" required></div>
              <div class="mb-3"><label class="form-label">Password</label>
                <input type="password" name="password" class="form-control" required></div>
              <button class="btn btn-primary w-100 btn-enhanced">Create Account</button>
            </form>
            <div class="text-center mt-3">Already have an account? <a href="/login">Login</a></div>
          </div>
        </div>
      </div>
    </div>
    """
    return render_base_template("Register", content)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = (request.form.get("email") or "").lower().strip()
        password = request.form.get("password") or ""
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password_hash, password):
            session["user_id"] = user.id
            flash(f"Welcome back, {user.first_name}!", "success")
            return redirect(url_for("dashboard"))
        flash("Invalid email or password.", "danger")

    content = """
    <div class="row justify-content-center">
      <div class="col-md-5">
        <div class="card border-0 shadow">
          <div class="card-header bg-primary text-white"><h3 class="mb-0">Login</h3></div>
          <div class="card-body">
            <form method="POST">
              <div class="mb-3"><label class="form-label">Email</label>
                <input type="email" name="email" class="form-control" required></div>
              <div class="mb-3"><label class="form-label">Password</label>
                <input type="password" name="password" class="form-control" required></div>
              <button class="btn btn-primary w-100 btn-enhanced">Login</button>
            </form>
            <div class="text-center mt-3">No account? <a href="/register">Register</a></div>
          </div>
        </div>
      </div>
    </div>
    """
    return render_base_template("Login", content)

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("home"))

# -----------------------------------------------------------------------------
# Dashboard
# -----------------------------------------------------------------------------
@app.route("/dashboard")
@login_required
def dashboard():
    user = User.query.get(session["user_id"])

    # Parse quiz_scores safely
    try:
        history = json.loads(user.quiz_scores) if user.quiz_scores else []
    except Exception:
        history = []

    last_score = (history[-1]["score"] if history else None)
    last_label = (f"{last_score:.1f}%" if isinstance(last_score, (int, float)) else "—")

    content = Template("""
    <div class="row g-3">
      <div class="col-12"><h2>Welcome back, $name!</h2></div>
      <div class="col-md-4">
        <div class="card border-0 shadow-sm">
          <div class="card-body">
            <h6 class="text-muted mb-1">📚 Study Time</h6>
            <h3 class="mb-0">$minutes mins</h3>
          </div>
        </div>
      </div>
      <div class="col-md-4">
        <div class="card border-0 shadow-sm">
          <div class="card-body">
            <h6 class="text-muted mb-1">🧮 Last Score</h6>
            <h3 class="mb-0">$last_score</h3>
          </div>
        </div>
      </div>
      <div class="col-md-4">
        <div class="card border-0 shadow-sm">
          <div class="card-body">
            <h6 class="text-muted mb-2">🚀 Quick Start</h6>
            <a href="/quiz-selector" class="btn btn-primary btn-enhanced">Start a Quiz</a>
          </div>
        </div>
      </div>
    </div>
    """).substitute(
        name=f"{user.first_name}",
        minutes=(user.study_time or 0),
        last_score=last_label,
    )
    return render_base_template("Dashboard", content, user=user)

# -----------------------------------------------------------------------------
# Quizzes
# -----------------------------------------------------------------------------
@app.route("/quiz-selector")
@login_required
def quiz_selector():
    user = User.query.get(session["user_id"])

    chips = ['<span class="domain-chip active" data-domain="random">🎲 All Domains</span>'] + [
        f'<span class="domain-chip" data-domain="{k}">{v["name"]}</span>'
        for k, v in CPP_DOMAINS.items()
    ]
    chips_html = "".join(chips)

    content = Template("""
    <div class="card border-0 shadow">
      <div class="card-header bg-success text-white">
        <h4 class="mb-0">📝 Build Your Quiz</h4>
        <small>Choose a domain & question count</small>
      </div>
      <div class="card-body">
        <div class="mb-3"><strong>Domain:</strong><div class="mt-2">$chips</div></div>

        <div class="mb-3">
          <label class="form-label me-2"><strong>Questions:</strong></label>
          <div class="btn-group" role="group">
            <input type="radio" class="btn-check" name="qcount" id="qc5" value="5">
            <label class="btn btn-outline-primary" for="qc5">5</label>
            <input type="radio" class="btn-check" name="qcount" id="qc10" value="10" checked>
            <label class="btn btn-outline-primary" for="qc10">10</label>
            <input type="radio" class="btn-check" name="qcount" id="qc15" value="15">
            <label class="btn btn-outline-primary" for="qc15">15</label>
            <input type="radio" class="btn-check" name="qcount" id="qc20" value="20">
            <label class="btn btn-outline-primary" for="qc20">20</label>
          </div>
        </div>

        <button id="startQuiz" class="btn btn-success btn-enhanced">Start Quiz</button>
      </div>
    </div>
    <script>
      let domain = 'random';
      document.querySelectorAll('.domain-chip').forEach(chip => {
        chip.addEventListener('click', () => {
          document.querySelectorAll('.domain-chip').forEach(c => c.classList.remove('active'));
          chip.classList.add('active');
          domain = chip.getAttribute('data-domain');
        });
      });
      document.getElementById('startQuiz').addEventListener('click', () => {
        const count = document.querySelector('input[name="qcount"]:checked').value;
        window.location.href = '/quiz/practice?domain=' + encodeURIComponent(domain) + '&count=' + encodeURIComponent(count);
      });
    </script>
    """).substitute(chips=chips_html)

    return render_base_template("Quizzes", content, user=user)

@app.route("/quiz/<quiz_type>")
@login_required
def quiz(quiz_type):
    if quiz_type not in QUIZ_TYPES:
        flash("Invalid quiz type.", "danger")
        return redirect(url_for("quiz_selector"))

    domain = request.args.get("domain", "random")
    count = request.args.get("count", str(QUIZ_TYPES[quiz_type]["questions"]))
    try:
        count = int(count)
    except Exception:
        count = QUIZ_TYPES[quiz_type]["questions"]
    count = max(1, min(100, count))

    # Start timer
    session["quiz_start_time"] = datetime.utcnow().timestamp()

    quiz_data = generate_quiz(quiz_type, domain=domain, difficulty="medium", count=count)
    quiz_json = json.dumps(quiz_data)

    page = Template("""
    <div class="card border-0 shadow">
      <div class="card-header bg-primary text-white d-flex justify-content-between align-items-center">
        <div><h4 class="mb-0">📝 $title</h4><small>$count questions</small></div>
        <button id="submitTop" class="btn btn-success btn-enhanced">Submit</button>
      </div>
      <div class="card-body" id="quizContainer"></div>
      <div class="card-footer text-end">
        <button id="submitBottom" class="btn btn-success btn-enhanced">Submit</button>
      </div>
    </div>
    <div class="mt-4" id="results"></div>

    <script>
      const QUIZ_DATA = $quiz_json;

      function renderQuiz(){
        const c = document.getElementById('quizContainer');
        c.innerHTML = '';
        (QUIZ_DATA.questions || []).forEach((q, idx) => {
          const card = document.createElement('div');
          card.className = 'mb-4 p-3 border rounded-3';
          card.id = 'q-' + idx;

          const h = document.createElement('h6');
          h.className = 'fw-bold text-primary';
          h.textContent = 'Question ' + (idx+1) + ' of ' + QUIZ_DATA.questions.length;
          card.appendChild(h);

          const p = document.createElement('p');
          p.textContent = q.question || '';
          card.appendChild(p);

          const opts = q.options || {};
          for (const key in opts){
            const line = document.createElement('div');
            line.className = 'form-check mb-2';
            const id = 'o-' + idx + '-' + key;

            const input = document.createElement('input');
            input.type = 'radio'; input.className='form-check-input';
            input.name = 'q' + idx; input.id = id; input.value = key;

            const label = document.createElement('label');
            label.className = 'form-check-label';
            label.setAttribute('for', id);
            label.textContent = key + ') ' + (opts[key] || '');

            line.appendChild(input); line.appendChild(label);
            card.appendChild(line);
          }

          c.appendChild(card);
        });
      }

      async function submitQuiz(){
        const answers = {};
        const unanswered = [];
        (QUIZ_DATA.questions || []).forEach((q, idx) => {
          const sel = document.querySelector('input[name="q' + idx + '"]:checked');
          answers[String(idx)] = sel ? sel.value : null;
          if (!sel) unanswered.push(idx+1);
        });
        if (unanswered.length){
          alert('Please answer all questions. Missing: ' + unanswered.join(', '));
          const first = document.getElementById('q-' + (unanswered[0]-1));
          if (first) first.scrollIntoView({behavior:'smooth'});
          return;
        }

        document.getElementById('submitTop').disabled = true;
        document.getElementById('submitBottom').disabled = true;

        const res = await fetch('/submit-quiz', {
          method:'POST',
          headers:{'Content-Type':'application/json'},
          body: JSON.stringify({
            quiz_type: QUIZ_DATA.quiz_type,
            domain: QUIZ_DATA.domain,
            questions: QUIZ_DATA.questions,
            answers: answers
          })
        });
        const data = await res.json();
        const out = document.getElementById('results');

        if (data.error){
          out.innerHTML = '<div class="alert alert-danger"><strong>Error:</strong> ' + data.error + '</div>';
          return;
        }

        // Summary
        let html = '<div class="card border-0 shadow"><div class="card-body">';
        const cls = data.score >= 80 ? 'text-success' : (data.score >= 70 ? 'text-warning' : 'text-danger');
        html += '<h3 class="' + cls + '">Final Score: ' + data.score.toFixed(1) + '%</h3>';
        html += '<p class="text-muted">' + data.correct + ' of ' + data.total + ' correct'
        if (data.time_taken){ html += ' • ' + data.time_taken + ' min'; }
        html += '</p>';

        if (Array.isArray(data.performance_insights)){
          html += '<div class="alert alert-info"><strong>Insights</strong><ul>';
          data.performance_insights.forEach(i => { html += '<li>' + i + '</li>'; });
          html += '</ul></div>';
        }
        html += '</div></div>';

        // Detail
        if (Array.isArray(data.detailed_results)){
          html += '<div class="mt-4"><h5>Review</h5>';
          data.detailed_results.forEach(r => {
            const ok = r.is_correct;
            html += '<div class="card mb-2"><div class="card-body">';
            html += '<div class="fw-bold">' + (ok ? '✅' : '❌') + ' Question ' + r.index + '</div>';
            html += '<div class="mb-2">' + (r.question || '') + '</div>';
            if (!ok){
              html += '<div class="text-danger mb-1"><strong>Your answer:</strong> ' + (r.user_letter || '—') + (r.user_text ? (') ' + r.user_text) : '') + '</div>';
            }
            html += '<div class="text-success mb-1"><strong>Correct:</strong> ' + (r.correct_letter || '?') + ') ' + (r.correct_text || '') + '</div>';
            if (r.explanation){
              html += '<div class="small text-muted">💡 ' + r.explanation + '</div>';
            }
            html += '</div></div>';
          });
          html += '</div>';
        }

        out.innerHTML = html;
        out.scrollIntoView({behavior:'smooth'});
      }

      document.getElementById('submitTop').addEventListener('click', submitQuiz);
      document.getElementById('submitBottom').addEventListener('click', submitQuiz);
      renderQuiz();
    </script>
    """)
    content = page.substitute(
        title=quiz_data["title"],
        count=len(quiz_data["questions"]),
        quiz_json=quiz_json
    )
    user = User.query.get(session["user_id"])
    return render_base_template("Quiz", content, user=user)

# Submit quiz (saves result and returns analysis)
@app.route("/submit-quiz", methods=["POST"])
@login_required
def submit_quiz():
    try:
        data = request.get_json() or {}
        quiz_type = (data.get("quiz_type") or "").strip()
        answers = data.get("answers") or {}
        questions = data.get("questions") or []
        domain = (data.get("domain") or "general").strip()

        if not quiz_type or not questions:
            return jsonify({"error": "Invalid quiz data"}), 400

        # Time used (minutes)
        time_taken = 0
        if "quiz_start_time" in session:
            try:
                start = datetime.fromtimestamp(session["quiz_start_time"])
                time_taken = int((datetime.utcnow() - start).total_seconds() / 60)
            except Exception:
                time_taken = 0
            finally:
                session.pop("quiz_start_time", None)

        correct_count = 0
        total = len(questions)
        detailed_results = []

        for i, q in enumerate(questions):
            user_letter = answers.get(str(i))
            correct_letter = q.get("correct")
            opts = q.get("options") or {}
            is_correct = (user_letter == correct_letter)
            if is_correct:
                correct_count += 1

            detailed_results.append({
                "index": i + 1,
                "question": q.get("question", ""),
                "correct_letter": correct_letter,
                "correct_text": opts.get(correct_letter, ""),
                "user_letter": user_letter,
                "user_text": opts.get(user_letter, "") if user_letter else None,
                "explanation": q.get("explanation", ""),
                "is_correct": bool(is_correct),
                "domain": q.get("domain", domain),
            })

        score = round((correct_count / total) * 100, 1) if total else 0.0

        # Save to DB
        qr = QuizResult(
            user_id=session["user_id"],
            quiz_type=quiz_type,
            domain=domain,
            questions=json.dumps(questions),
            answers=json.dumps(answers),
            score=float(score),
            total_questions=total,
            time_taken=time_taken,
        )
        db.session.add(qr)

        # Save rolling history (keep last 50)
        user = User.query.get(session["user_id"])
        try:
            history = json.loads(user.quiz_scores) if user.quiz_scores else []
            if not isinstance(history, list):
                history = []
        except Exception:
            history = []
        history.append({
            "score": score,
            "date": datetime.utcnow().isoformat(),
            "type": quiz_type,
            "domain": domain,
            "time_taken": time_taken,
        })
        user.quiz_scores = json.dumps(history[-50:])

        db.session.commit()

        # Insights (simple, clear)
        insights = []
        if score >= 90:
            insights.append("🎯 Excellent—mastery showing.")
        elif score >= 80:
            insights.append("✅ Strong result—review missed items to polish.")
        elif score >= 70:
            insights.append("📚 Decent—focus on missed concepts.")
        else:
            insights.append("⚠️ Keep practicing before a full exam.")

        if time_taken > 0 and total > 0:
            avg = time_taken / total
            if avg < 1:
                insights.append("⚡ Great pace per question.")
            elif avg > 3:
                insights.append("🐌 Speed up a bit with timed practice.")

        return jsonify({
            "success": True,
            "score": score,
            "correct": correct_count,
            "total": total,
            "time_taken": time_taken,
            "performance_insights": insights,
            "detailed_results": detailed_results
        })
    except Exception as e:
        print(f"/submit-quiz error: {e}")
        db.session.rollback()
        return jsonify({"error": "Error processing quiz results."}), 500

# -----------------------------------------------------------------------------
# Error pages (friendly)
# -----------------------------------------------------------------------------
@app.errorhandler(404)
def not_found(e):
    content = """
    <div class="text-center">
      <h1 class="display-4">404</h1>
      <p class="text-muted">That page wasn’t found.</p>
      <a class="btn btn-primary btn-enhanced" href="/dashboard">Go to Dashboard</a>
    </div>
    """
    return render_base_template("Not Found", content), 404

@app.errorhandler(500)
def server_error(e):
    content = """
    <div class="text-center">
      <h1 class="display-4">500</h1>
      <p class="text-muted">Something went wrong on our end. Please try again.</p>
      <a class="btn btn-primary btn-enhanced" href="/dashboard">Go to Dashboard</a>
    </div>
    """
    return render_base_template("Server Error", content), 500

# -----------------------------------------------------------------------------
# Run (local dev); on Render, Gunicorn runs this module
# -----------------------------------------------------------------------------
def create_app():
    return app
# === Feature Restore (Lite) — paste this ABOVE: if __name__ == '__main__': ===

from markupsafe import Markup

def _make_quiz(quiz_type='practice', domain='random', difficulty='medium', count=10):
    # Use BASE_QUESTIONS if present; otherwise fall back to a tiny built-in pool
    pool = []
    try:
        pool = BASE_QUESTIONS[:]  # defined earlier in this file
    except Exception:
        pool = [{
            "question": "What is defense in depth?",
            "options": {"A": "Single control", "B": "Layered controls", "C": "No controls", "D": "Outsourcing"},
            "correct": "B",
            "explanation": "Multiple layers ensure no single point of failure.",
            "source_name": "Security Basics",
            "domain": "security-principles",
            "difficulty": "medium",
        }]
    # domain filter
    if domain and domain not in ('random', 'general'):
        filtered = [q for q in pool if q.get('domain') == domain]
        if filtered:
            pool = filtered
    # build list
    if not count or count <= 0:
        count = 10
    random.shuffle(pool)
    out = []
    while len(out) < count:
        for q in pool:
            if len(out) >= count:
                break
            out.append(q.copy())
        if not pool:
            break
    title = f"CPP {quiz_type.title().replace('-', ' ')}"
    return {
        "title": title,
        "quiz_type": quiz_type,
        "domain": domain or 'general',
        "difficulty": difficulty,
        "questions": out[:count],
    }

def _safe_chat_call(messages):
    # Use your existing chat_with_ai if present; otherwise return a helpful stub
    try:
        if 'chat_with_ai' in globals() and callable(chat_with_ai):
            return chat_with_ai(messages)
    except Exception as e:
        print(f"AI call error: {e}")
    return ("I’m up and running! The full AI tutor will answer as soon as your API is reachable. "
            "Meanwhile, ask me about CPP domains, and I’ll give quick notes.")

def _render_pill(text):
    return f'<span class="domain-chip" data-domain="{text}">{text}</span>'

# --------------------------- Tutor (Study) ---------------------------
@app.route('/study')
@login_required
def study_page():
    # Chips from CPP_DOMAINS if available
    try:
        chips = ''.join([f'<span class="domain-chip" data-domain="{k}">{v["name"]}</span>' for k, v in CPP_DOMAINS.items()])
    except Exception:
        chips = ''.join([_render_pill(k) for k in ["security-principles","business-principles","investigations",
                                                   "personnel-security","physical-security","information-security","crisis-management"]])

    content = f"""
    <div class="row">
      <div class="col-md-8 mx-auto">
        <div class="card border-0 shadow">
          <div class="card-header bg-primary text-white d-flex align-items-center gap-2">
            <h4 class="mb-0">🤖 AI Tutor</h4>
            <small class="ms-2">Pick a domain or just ask a question</small>
          </div>
          <div class="card-body">
            <div class="mb-2"><strong>Domains:</strong></div>
            <div class="mb-3">{chips}</div>

            <div id="chat" style="height: 360px; overflow-y: auto; border:1px solid #e9ecef; border-radius:8px; padding:12px; background:#fafafa; margin-bottom:12px;"></div>
            <div class="input-group">
              <input id="userInput" class="form-control" placeholder="Ask about any CPP topic..." />
              <button id="sendBtn" class="btn btn-primary btn-enhanced">Send</button>
            </div>
            <div class="small text-muted mt-2">Tip: Try “Explain incident response phases.”</div>
          </div>
        </div>
      </div>
    </div>
    <script>
      const chatDiv = document.getElementById('chat');
      const input = document.getElementById('userInput');
      const btn = document.getElementById('sendBtn');
      function add(role, text) {{
        const wrap = document.createElement('div');
        wrap.className = 'mb-2';
        wrap.innerHTML = '<div class="small text-muted">{role}</div><div class="p-2 bg-white border rounded">{text}</div>'
          .replace('{{role}}', role)
          .replace('{{text}}', (text||'').replace(/</g,'&lt;').replace(/\\n/g,'<br>'));
        chatDiv.appendChild(wrap);
        chatDiv.scrollTop = chatDiv.scrollHeight;
      }}
      async function send() {{
        const q = input.value.trim();
        if(!q) return;
        add('You', q);
        input.value = '';
        btn.disabled = true; btn.textContent = 'Thinking...';
        try {{
          const r = await fetch('/chat', {{method:'POST', headers:{{'Content-Type':'application/json'}}, body: JSON.stringify({{message:q}})}} );
          const data = await r.json();
          add('Tutor', data.response || data.error || 'Sorry, something went wrong.');
        }} catch(e) {{
          add('Tutor', 'Network error, please try again.');
        }} finally {{
          btn.disabled = false; btn.textContent = 'Send';
        }}
      }}
      btn.addEventListener('click', send);
      input.addEventListener('keydown', (e)=>{{ if(e.key==='Enter'&&!btn.disabled) send(); }});
      document.querySelectorAll('.domain-chip').forEach(chip => {{
        chip.addEventListener('click', () => {{
          input.value = 'Explain key topics in ' + chip.textContent;
          input.focus();
        }});
      }});
    </script>
    """
    return render_base_template("AI Tutor", content, user=User.query.get(session['user_id']))

@app.route('/chat', methods=['POST'])
@login_required
def chat_endpoint():
    try:
        data = request.get_json() or {}
        msg = (data.get('message') or '').strip()
        if not msg:
            return jsonify({'error': 'Empty message'}), 400
        # keep a tiny session chat log (no DB needed)
        history = session.get('chat_history', [])
        history.append({'role': 'user', 'content': msg})
        # call AI (or stub)
        ai = _safe_chat_call([{'role':'user','content':msg}])
        history.append({'role': 'assistant', 'content': ai})
        session['chat_history'] = history[-20:]
        return jsonify({'response': ai})
    except Exception as e:
        print(f"/chat error: {e}")
        return jsonify({'error': 'Tutor error. Please try again.'}), 500

# --------------------------- Flashcards ---------------------------
@app.route('/flashcards')
@login_required
def flashcards_page():
    # Domain chips
    try:
        chips = ['<div class="domain-chip active" data-domain="random">🎲 Random</div>'] + \
                [f'<div class="domain-chip" data-domain="{k}">{v["name"]}</div>' for k, v in CPP_DOMAINS.items()]
    except Exception:
        chips = ['<div class="domain-chip active" data-domain="random">🎲 Random</div>']
    chips_html = ''.join(chips)

    content = f"""
    <div class="row">
      <div class="col-md-3">
        <div class="card border-0 shadow-sm">
          <div class="card-header bg-info text-white"><strong>📂 Domains</strong></div>
          <div class="card-body">{chips_html}</div>
        </div>
      </div>
      <div class="col-md-9">
        <div class="card border-0 shadow-sm">
          <div class="card-body">
            <div id="card" class="flashcard" style="height:300px; display:flex; align-items:center; justify-content:center;">
              Loading...
            </div>
            <div class="text-center mt-3">
              <button id="flip" class="btn btn-outline-primary btn-enhanced me-2">Flip</button>
              <button id="next" class="btn btn-primary btn-enhanced">Next</button>
            </div>
          </div>
        </div>
      </div>
    </div>
    <script>
      let domain = 'random', cards=[], i=0, back=false;
      function render(){{
        const c = cards[i] || {{front:'No cards yet', back:''}};
        document.getElementById('card').innerHTML = (back?c.back:c.front).replace(/</g,'&lt;').replace(/\\n/g,'<br>');
      }}
      async function load(){{
        document.getElementById('card').textContent='Loading...';
        const r = await fetch('/api/flashcards?domain='+encodeURIComponent(domain)+'&count=50');
        const data = await r.json();
        cards = data.cards || []; i=0; back=false; render();
      }}
      document.getElementById('flip').addEventListener('click', ()=>{{back=!back; render();}});
      document.getElementById('next').addEventListener('click', ()=>{{back=false; i=(i+1)%Math.max(1,cards.length); render();}});
      document.querySelectorAll('.domain-chip').forEach(ch=>{{
        ch.addEventListener('click', ()=>{
          document.querySelectorAll('.domain-chip').forEach(x=>x.classList.remove('active'));
          ch.classList.add('active');
          domain = ch.getAttribute('data-domain'); load();
        });
      }});
      load();
    </script>
    """
    return render_base_template("Flashcards", content, user=User.query.get(session['user_id']))

@app.get('/api/flashcards')
@login_required
def api_flashcards():
    try:
        domain = (request.args.get('domain') or 'random').strip().lower()
        try:
            cnt = int(request.args.get('count', '50'))
        except ValueError:
            cnt = 50
        cnt = max(1, min(200, cnt))
        base = BASE_QUESTIONS[:] if 'BASE_QUESTIONS' in globals() else []
        if not base:
            base = [{
                "question":"What is risk assessment?",
                "options":{"A":"Guessing","B":"Identifying & prioritizing risks","C":"Eliminating risk","D":"Blaming others"},
                "correct":"B",
                "explanation":"Identify, analyze, evaluate; choose cost-effective mitigations.",
                "source_name":"CPP Intro",
                "domain":"security-principles",
                "difficulty":"easy"
            }]
        if domain not in ('random', 'general'):
            filtered = [q for q in base if q.get('domain') == domain]
            base = filtered or base
        random.shuffle(base)
        out=[]
        for q in base[:cnt]:
            opts = q.get('options', {}) or {}
            corr = q.get('correct')
            corr_text = opts.get(corr, '')
            back_lines=[]
            if corr_text: back_lines.append(f"✅ Correct: {corr_text}")
            if q.get('explanation'): back_lines.append(f"💡 {q['explanation']}")
            if q.get('source_name'): back_lines.append(f"📚 Source: {q['source_name']}")
            out.append({"front": (q.get('question') or '').strip(),
                        "back": "\\n\\n".join(back_lines) or "Correct answer available."})
        return jsonify({"cards": out, "domain": domain, "count": len(out)})
    except Exception as e:
        print(f"/api/flashcards error: {e}")
        return jsonify({"error":"Could not load flashcards."}), 500

# --------------------------- Quizzes + Mock Exam ---------------------------
@app.route('/quiz-selector')
@login_required
def quiz_selector():
    try:
        chips = ['<span class="domain-chip active" data-domain="random">🎲 All Domains</span>'] + \
                [f'<span class="domain-chip" data-domain="{k}">{v["name"]}</span>' for k, v in CPP_DOMAINS.items()]
    except Exception:
        chips = ['<span class="domain-chip active" data-domain="random">🎲 All Domains</span>']
    chips_html = ''.join(chips)
    content = f"""
    <div class="card border-0 shadow">
      <div class="card-header bg-success text-white">
        <h4 class="mb-0">📝 Build Your Quiz</h4>
      </div>
      <div class="card-body">
        <div class="mb-3"><strong>Domain:</strong> {chips_html}</div>
        <div class="mb-3">
          <label class="form-label me-2">Questions:</label>
          <select id="qcount" class="form-select" style="max-width:160px; display:inline-block;">
            <option>5</option><option selected>10</option><option>15</option><option>20</option>
          </select>
        </div>
        <div class="mb-3">
          <label class="form-label me-2">Difficulty:</label>
          <select id="diff" class="form-select" style="max-width:200px; display:inline-block;">
            <option value="easy">Easy</option>
            <option value="medium" selected>Medium</option>
            <option value="hard">Hard</option>
          </select>
        </div>
        <button id="start" class="btn btn-success btn-enhanced">Start Quiz</button>
        <a href="/mock-exam" class="btn btn-outline-warning btn-enhanced ms-2">Mock Exam</a>
      </div>
    </div>
    <script>
      let domain='random';
      document.querySelectorAll('.domain-chip').forEach(c=>{
        c.addEventListener('click',()=>{
          document.querySelectorAll('.domain-chip').forEach(x=>x.classList.remove('active'));
          c.classList.add('active');
          domain = c.getAttribute('data-domain');
        });
      });
      document.getElementById('start').addEventListener('click', ()=>{
        const count = document.getElementById('qcount').value;
        const diff = document.getElementById('diff').value;
        window.location.href = '/quiz/practice?domain='+encodeURIComponent(domain)+'&count='+count+'&difficulty='+diff;
      });
    </script>
    """
    return render_base_template("Quizzes", content, user=User.query.get(session['user_id']))

@app.route('/quiz/<quiz_type>')
@login_required
def quiz_page(quiz_type):
    domain = request.args.get('domain','random')
    difficulty = request.args.get('difficulty','medium')
    try:
        count = int(request.args.get('count','10'))
    except Exception:
        count = 10
    session['quiz_start_time'] = datetime.utcnow().timestamp()
    data = _make_quiz(quiz_type, domain, difficulty, count)
    qjson = json.dumps(data)

    content = f"""
    <div class="card border-0 shadow">
      <div class="card-header bg-primary text-white d-flex justify-content-between align-items-center">
        <div>
          <h5 class="mb-0">📝 {data['title']}</h5>
          <small>{len(data['questions'])} questions • {difficulty.title()}</small>
        </div>
        <button id="submitTop" class="btn btn-success btn-enhanced">Submit</button>
      </div>
      <div class="card-body" id="quizContainer"></div>
      <div class="card-footer text-end">
        <button id="submitBottom" class="btn btn-success btn-enhanced">Submit</button>
      </div>
    </div>
    <div class="mt-3" id="results"></div>
    <script>
      const QUIZ_DATA = {qjson};
      function render(){{
        const c = document.getElementById('quizContainer');
        c.innerHTML = '';
        (QUIZ_DATA.questions||[]).forEach((q,i)=>{{
          const card=document.createElement('div');
          card.className='mb-3 p-3 border rounded';
          card.id='q-'+i;
          const h=document.createElement('h6');
          h.textContent='Question '+(i+1)+' of '+(QUIZ_DATA.questions.length);
          const p=document.createElement('p'); p.textContent=q.question||'';
          card.appendChild(h); card.appendChild(p);
          const opts=q.options||{{}};
          Object.keys(opts).forEach(k=>{{
            const id='i'+i+'_'+k;
            const wrap=document.createElement('div'); wrap.className='form-check';
            const inp=document.createElement('input'); inp.type='radio'; inp.className='form-check-input';
            inp.name='q'+i; inp.id=id; inp.value=k;
            const lab=document.createElement('label'); lab.className='form-check-label'; lab.htmlFor=id;
            lab.textContent=k+') '+opts[k];
            wrap.appendChild(inp); wrap.appendChild(lab); card.appendChild(wrap);
          }});
          c.appendChild(card);
        }});
      }}
      async function submit(){{
        const ans = {{}};
        (QUIZ_DATA.questions||[]).forEach((q,i)=>{{
          const sel=document.querySelector('input[name="q'+i+'"]:checked');
          ans[String(i)] = sel? sel.value : null;
        }});
        const r = await fetch('/submit-quiz', {{
          method:'POST', headers:{{'Content-Type':'application/json'}},
          body: JSON.stringify({{
            quiz_type: QUIZ_DATA.quiz_type,
            domain: QUIZ_DATA.domain,
            questions: QUIZ_DATA.questions,
            answers: ans
          }})
        }});
        const data = await r.json();
        const div = document.getElementById('results');
        if(data.error) {{ div.innerHTML = '<div class="alert alert-danger">'+data.error+'</div>'; return; }}
        let html = '<div class="card border-0 shadow"><div class="card-body">';
        html += '<h4 class="mb-2">Result: '+data.score.toFixed(1)+'%</h4>';
        html += '<div class="text-muted mb-3">'+data.correct+' / '+data.total+' correct</div>';
        if(Array.isArray(data.performance_insights)) {{
          html += '<ul>'+data.performance_insights.map(x=>'<li>'+x+'</li>').join('')+'</ul>';
        }}
        html += '</div></div>';
        div.innerHTML = html;
        window.scrollTo({{top: div.offsetTop-40, behavior:'smooth'}});
      }}
      document.getElementById('submitTop').addEventListener('click', submit);
      document.getElementById('submitBottom').addEventListener('click', submit);
      render();
    </script>
    """
    return render_base_template("Quiz", content, user=User.query.get(session['user_id']))

@app.route('/submit-quiz', methods=['POST'])
@login_required
def submit_quiz_lite():
    try:
        data = request.get_json() or {}
        quiz_type = data.get('quiz_type') or 'practice'
        answers = data.get('answers', {})
        questions = data.get('questions', [])
        domain = data.get('domain', 'general')

        if not questions:
            return jsonify({'error':'Invalid quiz data'}), 400

        # time taken (minutes)
        time_taken = 0
        if 'quiz_start_time' in session:
            try:
                start = datetime.fromtimestamp(session['quiz_start_time'])
                time_taken = int((datetime.utcnow() - start).total_seconds()/60)
            except Exception:
                time_taken = 0
            session.pop('quiz_start_time', None)

        correct = 0
        total = len(questions)
        for i, q in enumerate(questions):
            u = answers.get(str(i))
            if u and u == q.get('correct'):
                correct += 1

        score = (correct/total)*100 if total else 0.0

        # store a tiny progress snapshot in session for the Progress page
        prog = session.get('progress_events', [])
        for i, q in enumerate(questions):
            u = answers.get(str(i))
            is_ok = bool(u and u == q.get('correct'))
            prog.append({"domain": q.get('domain', domain), "ok": is_ok})
        session['progress_events'] = prog[-500:]  # cap

        # simple feedback
        insights = []
        if score >= 90: insights.append("🎯 Excellent! You're demonstrating mastery.")
        elif score >= 80: insights.append("✅ Good job! Review explanations to polish.")
        elif score >= 70: insights.append("📚 Fair performance — focus on missed concepts.")
        else: insights.append("⚠️ Consider focused study before the real exam.")
        if time_taken and total:
            avg = time_taken/total
            if avg < 1: insights.append("⚡ Great pace! Very efficient.")
            elif avg > 3: insights.append("🐌 Try to increase speed a bit.")

        try:
            # non-fatal activity log
            log_activity(session['user_id'], 'quiz_completed',
                         f'{quiz_type}: {correct}/{total} in {time_taken} min')
        except Exception as e:
            print(f"activity log (non-fatal): {e}")

        return jsonify({
            "success": True,
            "score": round(score, 1),
            "correct": correct,
            "total": total,
            "time_taken": time_taken,
            "performance_insights": insights
        })
    except Exception as e:
        print(f"/submit-quiz error: {e}")
        return jsonify({"error":"Error processing quiz results."}), 500

@app.route('/mock-exam')
@login_required
def mock_exam_page():
    # Simple chooser; then links to quiz with chosen size
    content = """
    <div class="card border-0 shadow">
      <div class="card-header bg-warning text-dark">
        <h4 class="mb-0">🏁 Mock Exam</h4>
        <small>Full simulation across domains</small>
      </div>
      <div class="card-body">
        <div class="row g-3">
          %BTN%
        </div>
      </div>
    </div>
    """
    btn = lambda n: f"""<div class="col-6 col-md-3">
      <a class="btn btn-{('primary','success','warning','danger')[(n//25)-1]} w-100 btn-enhanced"
         href="/quiz/mock-exam?domain=random&count={n}&difficulty=medium">{n} Questions</a>
    </div>"""
    grid = ''.join([btn(n) for n in (25,50,75,100)])
    return render_base_template("Mock Exam", content.replace('%BTN%', grid), user=User.query.get(session['user_id']))

# --------------------------- Progress (session-based) ---------------------------
@app.route('/progress')
@login_required
def progress_page_lite():
    events = session.get('progress_events', [])
    # aggregate by domain
    stats = {}
    for e in events:
        d = e.get('domain','general') or 'general'
        s = stats.setdefault(d, {"ok":0,"n":0})
        s["n"] += 1
        s["ok"] += 1 if e.get('ok') else 0
    rows = []
    for d, s in stats.items():
        pct = int(round(100.0 * (s["ok"]/s["n"])) if s["n"] else 0)
        level = "mastered" if pct>=90 else ("good" if pct>=75 else "needs practice")
        rows.append(f"<tr><td><strong>{d}</strong></td><td>{pct}%</td><td>{level.title()}</td><td class='text-center'>{s['n']}</td></tr>")
    rows_html = ''.join(rows) or "<tr><td colspan='4' class='text-center text-muted py-3'>No data yet. Take a quiz to see progress.</td></tr>"
    overall = int(round(sum(int(r.split('<td>')[1].split('%')[0]) for r in rows)/len(rows))) if rows else 0

    content = f"""
    <div class="card border-0 shadow">
      <div class="card-header bg-primary text-white"><h4 class="mb-0">📊 Progress by Domain</h4></div>
      <div class="card-body">
        <div class="table-responsive">
          <table class="table align-middle">
            <thead class="table-light"><tr><th>Domain</th><th>Average</th><th>Level</th><th class="text-center">Questions</th></tr></thead>
            <tbody>{rows_html}</tbody>
          </table>
        </div>
        <div class="mt-3 text-center">
          <div class="gauge-wrap" style="--p:{overall}%;">
            <span>{overall}%</span>
          </div>
          <div class="small text-muted mt-2">Overall Progress (goal: 80%+)</div>
        </div>
      </div>
    </div>
    """
    return render_base_template("Progress", content, user=User.query.get(session['user_id']))
# === End Feature Restore (Lite) ===

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)


