<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>{% block title %}CPP Test Prep{% endblock %}</title>
  <link rel="stylesheet" href="https://unpkg.com/modern-normalize/modern-normalize.css">
  <style>
    body{font-family:system-ui,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:#0b1220;color:#e6e9ef;margin:0}
    header,footer{background:#0f1626;border-bottom:1px solid #1e2a44}
    <style>
header {
  padding: 1rem;
}
</style>
    main{max-width:960px;margin:0 auto;padding:1.25rem}
    a{color:#80b3ff;text-decoration:none}
    .card{background:#111a2b;border:1px solid #1e2a44;border-radius:16px;padding:1rem;margin:1rem 0}
    .btn{display:inline-block;background:#1f6feb;color:#fff;padding:.6rem 1rem;border-radius:10px}
    .disclaimer{font-size:.9rem;opacity:.9;margin-top:1rem}
    .flash{padding:.75rem 1rem;border-radius:10px;margin:.5rem 0}
    .flash.success{background:#17381d;border:1px solid #2a8a3a}
    .flash.warning{background:#3a2b0f;border:1px solid #b07d2b}
    .flash.danger{background:#3a1515;border:1px solid #a33}
    .flash.info{background:#11314a;border:1px solid #2a5c8a}
  </style>
</head>
<body>
  <header>
    <main style="display:flex;align-items:center;gap:1rem">
      <a href="{{ url_for('home') }}" class="btn">Home</a>
      {% if session.get('user_id') %}
        <a href="{{ url_for('dashboard') }}">Dashboard</a>
        <a href="{{ url_for('study') }}">Study</a>
        <a href="{{ url_for('progress') }}">Progress</a>
        <a href="{{ url_for('subscribe') }}">Subscribe</a>
        <a href="{{ url_for('logout') }}" style="margin-left:auto">Logout</a>
      {% else %}
        <a href="{{ url_for('login') }}" style="margin-left:auto">Login</a>
        <a href="{{ url_for('register') }}">Register</a>
      {% endif %}
    </main>
  </header>

  <main>
    {% with messages = get_flashed_messages(with_categories=true) %}
      {% if messages %}
        {% for category, message in messages %}
          <div class="flash {{category}}">{{ message }}</div>
        {% endfor %}
      {% endif %}
    {% endwith %}

    {% block content %}{% endblock %}
  </main>

  <footer>
    <main>
      <div class="disclaimer">
        <strong>Important Notice</strong><br>
        This service is NOT affiliated with, endorsed by, or approved by ASIS International.<br><br>
        CPP® (Certified Protection Professional) is a registered certification mark of ASIS International, Inc. This course is an independent study aid created to help candidates prepare for the CPP exam.<br><br>
        We do not guarantee that using this course will result in passing the CPP exam. Exam success depends on individual study habits, prior knowledge, exam performance, and other factors beyond our control.
      </div>
      <p style="margin-top:1rem">
        <a href="{{ url_for('terms') }}">Terms</a> ·
        <a href="{{ url_for('privacy') }}">Privacy</a>
      </p>
    </main>
  </footer>
</body>
</html>

