def base_layout(title: str, body_html: str) -> str:
    user_name = session.get('name', '')
    user_email = session.get('email', '')
    is_logged_in = 'user_id' in session

    # Generate CSRF token for template replacement
    if HAS_CSRF:
        try:
            from flask_wtf.csrf import generate_csrf
            csrf_token_value = generate_csrf()
        except:
            csrf_token_value = ""
    else:
        csrf_token_value = ""

    if is_logged_in:
        user = _find_user(user_email)
        subscription = user.get('subscription', 'inactive') if user else 'inactive'
        badge_text = _plan_badge_text(subscription)
        plan_badge = f'<span class="badge plan-{subscription}">{badge_text}</span>'
        user_menu = f"""
        <li class="nav-item dropdown">
          <a class="nav-link dropdown-toggle" href="#" id="userDropdown" role="button" data-bs-toggle="dropdown">
            {html.escape(user_name or user_email)} {plan_badge}
          </a>
          <ul class="dropdown-menu" aria-labelledby="userDropdown">
            <li><a class="dropdown-item" href="/usage">Usage Dashboard</a></li>
            <li><a class="dropdown-item" href="/billing">Billing</a></li>
            <li><a class="dropdown-item" href="/settings">Settings</a></li>
            <li><hr class="dropdown-divider"></li>
            <li>
              <form method="POST" action="/logout" class="d-inline">
                <input type="hidden" name="csrf_token" value="{csrf_token_value}"/>
                <button type="submit" class="dropdown-item">Logout</button>
              </form>
            </li>
          </ul>
        </li>
        """
    else:
        user_menu = """
        <li class="nav-item">
          <a class="nav-link" href="/login">Login</a>
        </li>
        <li class="nav-item">
          <a class="nav-link btn btn-outline-primary ms-2" href="/signup">Create Account</a>
        </li>
        """

    nav = f"""
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark sticky-top">
      <div class="container">
        <a class="navbar-brand fw-bold" href="/">
          <i class="bi bi-shield-check"></i> CPP Test Prep
        </a>
        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
          <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="navbarNav">
          <ul class="navbar-nav me-auto">
            {'<li class="nav-item"><a class="nav-link" href="/study">Tutor</a></li>' if is_logged_in else ''}
            {'<li class="nav-item"><a class="nav-link" href="/flashcards">Flashcards</a></li>' if is_logged_in else ''}
            {'<li class="nav-item"><a class="nav-link" href="/quiz">Quiz</a></li>' if is_logged_in else ''}
            {'<li class="nav-item"><a class="nav-link" href="/mock-exam">Mock Exam</a></li>' if is_logged_in else ''}
            {'<li class="nav-item"><a class="nav-link" href="/progress">Progress</a></li>' if is_logged_in else ''}
          </ul>
          <ul class="navbar-nav">
            {user_menu}
          </ul>
        </div>
      </div>
    </nav>
    """

    disclaimer = f"""
    <footer class="bg-light py-3 mt-5">
      <div class="container">
        <div class="row">
          <div class="col-md-8">
            <small class="text-muted">
              <strong>Notice:</strong> This platform is independent and not affiliated with ASIS International.
              CPP® is a mark of ASIS International, Inc.
            </small>
          </div>
          <div class="col-md-4 text-end">
            <small class="text-muted">Version {APP_VERSION}</small>
          </div>
        </div>
      </div>
    </footer>
    """

    stage_banner = ("""
    <div class="alert alert-warning alert-dismissible fade show" role="alert">
      <div class="container text-center">
        <strong>STAGING ENVIRONMENT</strong> — Not for production use.
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
      </div>
    </div>
    """ if IS_STAGING else "")

    style_css = """
    <style>
      .card { box-shadow: 0 2px 4px rgba(0,0,0,0.1); border: none; }
      .btn-primary { background: linear-gradient(45deg, #007bff, #0056b3); border: none; }
      .progress { height: 8px; }
      .navbar-brand i { color: #28a745; }
      .alert-success { border-left: 4px solid #28a745; }
      .alert-warning { border-left: 4px solid #ffc107; }
      .alert-danger { border-left: 4px solid #dc3545; }
      .badge { font-size: 0.8em; }
      .plan-monthly { background: linear-gradient(45deg, #007bff, #0056b3); }
      .plan-sixmonth { background: linear-gradient(45deg, #6f42c1, #3d2a73); }
      .plan-inactive { background: #6c757d; }
      @media (max-width: 768px) {
        .container { padding: 0 15px; }
        .card { margin-bottom: 1rem; }
      }
    </style>
    """

    # Replace all CSRF token placeholders in the body_html with actual token
    body_html = body_html.replace('{{ csrf_token() }}', csrf_token_value)

    return f"""<!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <meta name="csrf-token" content="{csrf_token_value}">
      <title>{html.escape(title)} - CPP Test Prep</title>
      <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
      <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.7.2/font/bootstrap-icons.css" rel="stylesheet">
      {style_css}
    </head>
    <body class="d-flex flex-column min-vh-100">
      {nav}
      {stage_banner}
      <main class="flex-grow-1">
        {body_html}
      </main>
      {disclaimer}
      <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    </body>
    </html>"""
