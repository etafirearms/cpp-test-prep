# ------------------------ Billing ------------------------
@app.get("/billing")
@login_required
def billing_page():
    user = _find_user(session.get('email', ''))
    if not user:
        return redirect(url_for('login_page'))
    
    subscription = user.get('subscription', 'inactive')
    exp_html = ""
    if subscription == 'sixmonth' and user.get('subscription_expires_at'):
        try:
            exp_date = datetime.fromisoformat(user['subscription_expires_at'].replace('Z', '+00:00'))
            formatted_date = exp_date.strftime('%B %d, %Y')
            exp_html = f'<p class="text-muted mb-0">Expires: {formatted_date}</p>'
        except:
            pass

    if subscription == 'inactive':
        plans_html = """
        <div class="row mt-4 g-4">
          <div class="col-md-6">
            <div class="card border-primary h-100">
              <div class="card-header bg-primary text-white text-center">
                <h4 class="mb-0">Monthly Plan</h4>
              </div>
              <div class="card-body text-center p-4">
                <div class="mb-3">
                  <span class="display-4 fw-bold text-primary">$39.99</span>
                  <span class="text-muted fs-5">/month</span>
                </div>
                <p class="text-muted mb-4">Perfect for focused study periods</p>
                <ul class="list-unstyled mb-4">
                  <li class="mb-2"><i class="bi bi-check-circle-fill text-success me-2"></i>Unlimited practice quizzes</li>
                  <li class="mb-2"><i class="bi bi-check-circle-fill text-success me-2"></i>AI tutor with instant help</li>
                  <li class="mb-2"><i class="bi bi-check-circle-fill text-success me-2"></i>Progress tracking & analytics</li>
                  <li class="mb-2"><i class="bi bi-check-circle-fill text-success me-2"></i>Mobile-friendly access</li>
                  <li class="mb-2"><i class="bi bi-check-circle-fill text-success me-2"></i>Cancel anytime</li>
                </ul>
                <a href="/billing/checkout/monthly" class="btn btn-primary btn-lg w-100">Choose Monthly</a>
              </div>
            </div>
          </div>
          <div class="col-md-6">
            <div class="card border-success h-100 position-relative">
              <div class="badge bg-warning text-dark position-absolute top-0 start-50 translate-middle px-3 py-2">
                <i class="bi bi-star-fill"></i> Best Value
              </div>
              <div class="card-header bg-success text-white text-center">
                <h4 class="mb-0">6-Month Plan</h4>
              </div>
              <div class="card-body text-center p-4">
                <div class="mb-3">
                  <span class="display-4 fw-bold text-success">$99.00</span>
                  <span class="text-muted fs-6 d-block">One-time payment</span>
                </div>
                <p class="text-muted mb-4">Complete preparation program</p>
                <ul class="list-unstyled mb-4">
                  <li class="mb-2"><i class="bi bi-check-circle-fill text-success me-2"></i>Everything in Monthly</li>
                  <li class="mb-2"><i class="bi bi-check-circle-fill text-success me-2"></i>6 full months of access</li>
                  <li class="mb-2"><i class="bi bi-check-circle-fill text-success me-2"></i>No auto-renewal</li>
                  <li class="mb-2"><i class="bi bi-check-circle-fill text-success me-2"></i>Save $140+ vs monthly</li>
                  <li class="mb-2"><i class="bi bi-check-circle-fill text-success me-2"></i>Extended study time</li>
                </ul>
                <a href="/billing/checkout/sixmonth" class="btn btn-success btn-lg w-100">Choose 6-Month</a>
              </div>
            </div>
          </div>
        </div>
        """
    else:
        status_icon = "check-circle-fill" if subscription in ['monthly', 'sixmonth'] else "exclamation-triangle-fill"
        status_color = "success" if subscription in ['monthly', 'sixmonth'] else "warning"
        
        plans_html = f"""
        <div class="alert alert-{status_color} border-0 mt-4">
          <div class="d-flex align-items-center">
            <i class="bi bi-{status_icon} text-{status_color} fs-4 me-3"></i>
            <div>
              <h5 class="alert-heading mb-1">{_plan_badge_text(subscription)} Plan Active</h5>
              <p class="mb-0">You have unlimited access to all features. Thank you for your support!</p>
              {exp_html}
            </div>
          </div>
        </div>
        """

    body = f"""
    <div class="container">
      <div class="row justify-content-center">
        <div class="col-lg-10">
          <div class="card border-0 shadow-sm mb-4">
            <div class="card-body p-4">
              <div class="d-flex align-items-center mb-4">
                <div class="me-3">
                  <div class="rounded-circle bg-success bg-opacity-10 p-3">
                    <i class="bi bi-credit-card text-success fs-2"></i>
                  </div>
                </div>
                <div>
                  <h2 class="mb-1">Billing & Subscription</h2>
                  <p class="text-muted mb-0">Manage your plan and billing information</p>
                </div>
              </div>
              
              <div class="card border-0 bg-light mb-4">
                <div class="card-body p-4">
                  <h5 class="d-flex align-items-center">
                    Current Plan: 
                    <span class="badge plan-{subscription} ms-2">{_plan_badge_text(subscription)}</span>
                  </h5>
                  {plans_html}
                </div>
              </div>
              
              <div class="card border-0 bg-light">
                <div class="card-body p-4">
                  <h5 class="mb-3">Billing History</h5>
                  <div class="text-center py-4">
                    <i class="bi bi-receipt text-muted display-6 mb-3"></i>
                    <p class="text-muted mb-3">Billing history and invoices will appear here</p>
                    <small class="text-muted">Payment processing is handled securely by Stripe</small>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
    """
    return base_layout("Billing", body)

@app.get('/billing/checkout/<plan>')
@login_required
def billing_checkout(plan):
    user = _find_user(session.get('email', ''))
    if not user:
        return redirect(url_for('login_page'))
    if plan not in ['monthly', 'sixmonth']:
        return redirect(url_for('billing_page'))
    
    checkout_url = create_stripe_checkout_session(user['email'], plan)
    if checkout_url:
        return redirect(checkout_url)
    else:
        return redirect(url_for('billing_page'))

@app.get('/billing/success')
@login_required
def billing_success():
    session_id = request.args.get('session_id')
    plan = request.args.get('plan', '')
    
    if not session_id:
        return redirect(url_for('billing_page'))
    
    try:
        cs = stripe.checkout.Session.retrieve(session_id)
        if cs.customer_email != session.get('email'):
            return redirect(url_for('billing_page'))
    except Exception:
        return redirect(url_for('billing_page'))
    
    plan_names = {'monthly': 'Monthly Plan', 'sixmonth': '6-Month Plan'}
    title = plan_names.get(plan, 'Plan Activated')
    
    body = f"""
    <div class="container">
      <div class="row justify-content-center">
        <div class="col-md-8 text-center">
          <div class="card border-0 shadow-sm">
            <div class="card-body p-5">
              <div class="mb-4">
                <i class="bi bi-check-circle-fill text-success display-1"></i>
              </div>
              <h1 class="h3 text-success mb-3">Payment Successful!</h1>
              <h2 class="h4 mb-4">{html.escape(title)} Activated</h2>
              <div class="alert alert-success border-0 mb-4">
                <p class="mb-0">Your plan is now active with unlimited access to all features. Start learning immediately!</p>
              </div>
              <div class="d-grid gap-2 col-6 mx-auto">
                <a href="/quiz" class="btn btn-primary btn-lg">
                  <i class="bi bi-rocket-takeoff me-2"></i>Start Learning
                </a>
                <a href="/progress" class="btn btn-outline-primary">
                  <i class="bi bi-graph-up me-2"></i>View Progress
                </a>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
    """
    return base_layout(title, body)

@app.post('/stripe/webhook')
def stripe_webhook():
    payload = request.get_data()
    sig_header = request.headers.get('Stripe-Signature')
    
    if not STRIPE_WEBHOOK_SECRET:
        return '', 400
        
    try:
        event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
    except ValueError:
        logger.error("Invalid Stripe webhook payload")
        return '', 400
    except stripe.error.SignatureVerificationError:
        logger.error("Invalid Stripe webhook signature")
        return '', 400

    if event['type'] == 'checkout.session.completed':
        session_obj = event['data']['object']
        customer_email = session_obj.get('customer_email')
        mode = session_obj.get('mode')
        
        if customer_email:
            user = _find_user(customer_email)
            if user:
                if mode == 'subscription':
                    user['subscription'] = 'monthly'
                    user['stripe_customer_id'] = session_obj.get('customer')
                    user.pop('subscription_expires_at', None)
                else:
                    duration_days = 180
                    user['subscription'] = 'sixmonth'
                    user['subscription_expires_at'] = (datetime.utcnow() + timedelta(days=duration_days)).isoformat(timespec="seconds") + "Z"
                
                _save_json("users.json", USERS)
                logger.info(f"Updated subscription for {customer_email} to {user['subscription']}")

    elif event['type'] == 'customer.subscription.deleted':
        subscription_obj = event['data']['object']
        customer_id = subscription_obj['customer']
        
        for user in USERS:
            if user.get('stripe_customer_id') == customer_id:
                user['subscription'] = 'inactive'
                _save_json("users.json", USERS)
                logger.info(f"Downgraded subscription for {user['email']} to inactive")
                break
                
    return '', 200

# ------------------------ Settings ------------------------
@app.get("/settings")
@login_required
def settings_page():
    name = session.get("name", "")
    email = session.get("email", "")
    tz = session.get("timezone", "UTC")
    
    body = f"""
    <div class="container">
      <div class="row justify-content-center">
        <div class="col-md-8">
          <div class="card border-0 shadow-sm">
            <div class="card-body p-4">
              <div class="d-flex align-items-center mb-4">
                <div class="me-3">
                  <div class="rounded-circle bg-secondary bg-opacity-10 p-3">
                    <i class="bi bi-gear text-secondary fs-2"></i>
                  </div>
                </div>
                <div>
                  <h2 class="mb-1">Account Settings</h2>
                  <p class="text-muted mb-0">Manage your profile and preferences</p>
                </div>
              </div>
              
              <form method="POST" action="/settings">
                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
                <div class="row g-4">
                  <div class="col-md-6">
                    <label class="form-label fw-semibold">Email Address</label>
                    <input type="email" class="form-control" name="email" value="{html.escape(email or '')}" required>
                    <div class="form-text">Used for account access and notifications</div>
                  </div>
                  <div class="col-md-6">
                    <label class="form-label fw-semibold">Full Name</label>
                    <input type="text" class="form-control" name="name" value="{html.escape(name or '')}" required>
                    <div class="form-text">Displayed in your dashboard</div>
                  </div>
                </div>
                <div class="row g-4 mt-2">
                  <div class="col-md-6">
                    <label class="form-label fw-semibold">Timezone</label>
                    <select class="form-select" name="timezone">
                      <option value="UTC" {'selected' if tz == 'UTC' else ''}>UTC (Coordinated Universal Time)</option>
                      <option value="US/Eastern" {'selected' if tz == 'US/Eastern' else ''}>Eastern Time (US & Canada)</option>
                      <option value="US/Central" {'selected' if tz == 'US/Central' else ''}>Central Time (US & Canada)</option>
                      <option value="US/Mountain" {'selected' if tz == 'US/Mountain' else ''}>Mountain Time (US & Canada)</option>
                      <option value="US/Pacific" {'selected' if tz == 'US/Pacific' else ''}>Pacific Time (US & Canada)</option>
                    </select>
                    <div class="form-text">Used for activity timestamps</div>
                  </div>
                </div>
                <div class="d-flex justify-content-between align-items-center mt-4 pt-3 border-top">
                  <a href="/" class="btn btn-outline-secondary">
                    <i class="bi bi-arrow-left me-1"></i>Back to Dashboard
                  </a>
                  <button type="submit" class="btn btn-primary">
                    <i class="bi bi-check-circle me-1"></i>Save Changes
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      </div>
    </div>
    """
    return base_layout("Settings", body)

@app.post("/settings")
@login_required
def settings_save():
    name = (request.form.get("name") or "").strip()
    email = (request.form.get("email") or "").strip().lower()
    tz = (request.form.get("timezone") or "").strip() or "UTC"
    
    if not name or not email:
        return redirect(url_for('settings_page'))

    # Prevent email collision
    if email != session.get('email','') and _find_user(email):
        return redirect(url_for('settings_page'))

    user = _find_user(session.get('email', ''))
    if user:
        user['name'] = name
        user['email'] = email
        _save_json("users.json", USERS)

    session["name"] = name
    session["email"] = email
    session["timezone"] = tz
    return redirect(url_for('settings_page'))

# ------------------------ Admin ------------------------
@app.post("/admin/login")
def admin_login():
    if _rate_limited("admin-login", limit=5, per_seconds=300):
        return redirect(url_for("admin_login_page", error="ratelimited"))
    
    pwd = (request.form.get("password") or "").strip()
    nxt = request.form.get("next") or url_for("admin_home")
    
    if ADMIN_PASSWORD and pwd == ADMIN_PASSWORD:
        session["admin_ok"] = True
        return redirect(nxt)
    
    return redirect(url_for("admin_login_page", error=("nopass" if not ADMIN_PASSWORD else "badpass")))

@app.get("/admin/login")
def admin_login_page():
    if is_admin():
        return redirect(url_for("admin_home"))
    
    error = request.args.get("error")
    body = f"""
    <div class="container">
      <div class="row justify-content-center">
        <div class="col-md-6">
          <div class="card border-0 shadow-sm">
            <div class="card-body p-4">
              <div class="text-center mb-4">
                <i class="bi bi-shield-lock text-warning display-4 mb-3"></i>
                <h2>Admin Access</h2>
                <p class="text-muted">Administrative portal login</p>
              </div>
              
              {'<div class="alert alert-danger border-0">Incorrect password. Access denied.</div>' if error=="badpass" else ''}
              {'<div class="alert alert-danger border-0">Too many attempts. Please wait 5 minutes.</div>' if error=="ratelimited" else ''}
              {'<div class="alert alert-warning border-0">Admin access is not configured.</div>' if (not ADMIN_PASSWORD or error=="nopass") else ''}
              
              <form method="POST" action="/admin/login">
                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
                <input type="hidden" name="next" value="{request.args.get('next', '')}">
                <div class="mb-3">
                  <label class="form-label fw-semibold">Password</label>
                  <input type="password" class="form-control" name="password" required placeholder="Enter admin password">
                </div>
                <button type="submit" class="btn btn-warning w-100" {'disabled' if not ADMIN_PASSWORD else ''}>
                  <i class="bi bi-unlock me-1"></i>Access Admin Panel
                </button>
              </form>
            </div>
          </div>
        </div>
      </div>
    </div>
    """
    return base_layout("Admin Login", body)

@app.post("/admin/logout")
def admin_logout():
    session.pop("admin_ok", None)
    return redirect(url_for("admin_login_page"))

@app.get("/admin")
def admin_home():
    if not is_admin():
        return redirect(url_for("admin_login_page", next=request.path))
    
    tab = request.args.get("tab", "overview")

    # Overview stats
    total_users = len(USERS)
    active_users = len([u for u in USERS if u.get('subscription') != 'inactive'])
    total_questions = len(ALL_QUESTIONS)

    body = f"""
    <div class="container-fluid">
      <div class="d-flex justify-content-between align-items-center mb-4">
        <div class="d-flex align-items-center">
          <i class="bi bi-shield-check text-warning fs-1 me-3"></i>
          <div>
            <h1 class="mb-1">Admin Dashboard</h1>
            <p class="text-muted mb-0">System management and oversight</p>
          </div>
        </div>
        <form method="POST" action="/admin/logout" class="d-inline">
          <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
          <button type="submit" class="btn btn-outline-danger">
            <i class="bi bi-box-arrow-right me-1"></i>Logout
          </button>
        </form>
      </div>
      
      <ul class="nav nav-tabs mb-4">
        <li class="nav-item">
          <a class="nav-link {'active' if tab == 'overview' else ''}" href="?tab=overview">
            <i class="bi bi-speedometer2 me-1"></i>Overview
          </a>
        </li>
        <li class="nav-item">
          <a class="nav-link {'active' if tab == 'users' else ''}" href="?tab=users">
            <i class="bi bi-people me-1"></i>Users ({total_users})
          </a>
        </li>
        <li class="nav-item">
          <a class="nav-link {'active' if tab == 'questions' else ''}" href="?tab=questions">
            <i class="bi bi-question-circle me-1"></i>Questions ({total_questions})
          </a>
        </li>
      </ul>
      
      {'<div>' if tab == 'overview' else '<div style="display:none;">'}
        <div class="row g-4 mb-4">
          <div class="col-md-3">
            <div class="card border-0 shadow-sm">
              <div class="card-body text-center p-4">
                <i class="bi bi-people text-primary fs-1 mb-2"></i>
                <h3 class="text-primary">{total_users}</h3>
                <p class="text-muted mb-0">Total Users</p>
              </div>
            </div>
          </div>
          <div class="col-md-3">
            <div class="card border-0 shadow-sm">
              <div class="card-body text-center p-4">
                <i class="bi bi-person-check text-success fs-1 mb-2"></i>
                <h3 class="text-success">{active_users}</h3>
                <p class="text-muted mb-0">Active Subscriptions</p>
              </div>
            </div>
          </div>
          <div class="col-md-3">
            <div class="card border-0 shadow-sm">
              <div class="card-body text-center p-4">
                <i class="bi bi-question-circle text-info fs-1 mb-2"></i>
                <h3 class="text-info">{total_questions}</h3>
                <p class="text-muted mb-0">Questions Available</p>
              </div>
            </div>
          </div>
          <div class="col-md-3">
            <div class="card border-0 shadow-sm">
              <div class="card-body text-center p-4">
                <i class="bi bi-graph-up text-warning fs-1 mb-2"></i>
                <h3 class="text-warning">{len(DOMAINS)}</h3>
                <p class="text-muted mb-0">Study Domains</p>
              </div>
            </div>
          </div>
        </div>
      </div>
      
      {'<div>' if tab == 'users' else '<div style="display:none;">'}
        <div class="card border-0 shadow-sm">
          <div class="card-header border-0 bg-light">
            <h4 class="mb-0">User Management</h4>
          </div>
          <div class="card-body">
            <div class="table-responsive">
              <table class="table">
                <thead class="table-light">
                  <tr>
                    <th>User</th>
                    <th>Plan</th>
                    <th>Usage This Month</th>
                    <th>Last Active</th>
                  </tr>
                </thead>
                <tbody>
                  {''.join([f'''
                  <tr>
                    <td>
                      <div>
                        <div class="fw-semibold">{html.escape(u.get("name","Unknown"))}</div>
                        <small class="text-muted">{html.escape(u.get("email",""))}</small>
                      </div>
                    </td>
                    <td>
                      <span class="badge plan-{u.get("subscription","inactive")}">
                        {_plan_badge_text(u.get("subscription","inactive"))}
                      </span>
                    </td>
                    <td>
                      <small>
                        Q: {u.get("usage", {}).get("monthly", {}).get(datetime.utcnow().strftime('%Y-%m'), {}).get("quizzes", 0)} • 
                        A: {u.get("usage", {}).get("monthly", {}).get(datetime.utcnow().strftime('%Y-%m'), {}).get("questions", 0)}
                      </small>
                    </td>
                    <td>
                      <small class="text-muted">{u.get("usage", {}).get("last_active", "Never")[:16]}</small>
                    </td>
                  </tr>
                  ''' for u in USERS]) or '<tr><td colspan="4" class="text-center text-muted py-4">No users registered</td></tr>'}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
      
      {'<div>' if tab == 'questions' else '<div style="display:none;">'}
        <div class="row g-4">
          <div class="col-12">
            <div class="card border-0 shadow-sm mb-4">
              <div class="card-header border-0 bg-light">
                <h4 class="mb-0">Add New Question</h4>
              </div>
              <div class="card-body">
                <form method="POST" action="/admin/questions/add">
                  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
                  <div class="row g-3">
                    <div class="col-md-3">
                      <label class="form-label fw-semibold">Domain</label>
                      <select name="domain" class="form-select">
                        {''.join([f'<option value="{k}">{v}</option>' for k, v in DOMAINS.items()])}
                      </select>
                    </div>
                    <div class="col-md-9">
                      <label class="form-label fw-semibold">Question</label>
                      <input type="text" name="question" class="form-control" required placeholder="Enter question text">
                    </div>
                  </div>
                  <div class="row g-3 mt-2">
                    <div class="col-md-3">
                      <label class="form-label fw-semibold">Option A</label>
                      <input type="text" name="opt1" class="form-control" required>
                    </div>
                    <div class="col-md-3">
                      <label class="form-label fw-semibold">Option B</label>
                      <input type="text" name="opt2" class="form-control" required>
                    </div>
                    <div class="col-md-3">
                      <label class="form-label fw-semibold">Option C</label>
                      <input type="text" name="opt3" class="form-control" required>
                    </div>
                    <div class="col-md-3">
                      <label class="form-label fw-semibold">Option D</label>
                      <input type="text" name="opt4" class="form-control" required>
                    </div>
                  </div>
                  <div class="row g-3 mt-2">
                    <div class="col-md-2">
                      <label class="form-label fw-semibold">Correct Answer</label>
                      <select name="answer" class="form-select" required>
                        <option value="1">A</option>
                        <option value="2">B</option>
                        <option value="3">C</option>
                        <option value="4">D</option>
                      </select>
                    </div>
                    <div class="col-md-10">
                      <label class="form-label fw-semibold">Explanation</label>
                      <input type="text" name="explanation" class="form-control" placeholder="Why is this answer correct?">
                    </div>
                  </div>
                  <button type="submit" class="btn btn-primary mt-3">
                    <i class="bi bi-plus-circle me-1"></i>Add Question
                  </button>
                </form>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
    """
    return base_layout("Admin Dashboard", body)

# Admin CRUD operations  
@app.post("/admin/questions/add")
def admin_questions_add():
    if not is_admin():
        return redirect("/admin")
    
    form = request.form
    dom = (form.get("domain") or "security-principles").strip()

    num_to_letter = {1:"A", 2:"B", 3:"C", 4:"D"}
    try:
        ans_num = int(form.get("answer") or 1)
        correct_letter = num_to_letter.get(ans_num, "A")
    except Exception:
        correct_letter = "A"

    q = {
        "id": str(uuid.uuid4()),
        "domain": dom,
        "question": (form.get("question") or "").strip(),
        "options": {
            "A": (form.get("opt1") or "").strip(),
            "B": (form.get("opt2") or "").strip(), 
            "C": (form.get("opt3") or "").strip(),
            "D": (form.get("opt4") or "").strip(),
        },
        "correct": correct_letter,
        "explanation": (form.get("explanation") or "").strip(),
        "created_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
    }
    
    if q["question"] and all(q["options"].get(L) for L in ("A","B","C","D")):
        QUESTIONS.append(q)
        _save_json("questions.json", QUESTIONS)
        global ALL_QUESTIONS
        ALL_QUESTIONS = _build_all_questions()

    return redirect("/admin?tab=questions")

# Error handlers
@app.errorhandler(403)
def forbidden(e):
    return base_layout("Access Denied", """
    <div class="container">
      <div class="row justify-content-center">
        <div class="col-md-6 text-center">
          <div class="mb-4">
            <i class="bi bi-shield-x text-danger display-1"></i>
          </div>
          <h1 class="display-4 text-muted mb-3">403</h1>
          <h3 class="mb-3">Access Denied</h3>
          <p class="text-muted mb-4">You don't have permission to access this resource.</p>
          <a href="/" class="btn btn-primary">
            <i class="bi bi-house me-1"></i>Go Home
          </a>
        </div>
      </div>
    </div>
    """), 403

@app.errorhandler(404)
def not_found(e):
    return base_layout("Not Found", """
    <div class="container">
      <div class="row justify-content-center">
        <div class="col-md-6 text-center">
          <div class="mb-4">
            <i class="bi bi-compass text-warning display-1"></i>
          </div>
          <h1 class="display-4 text-muted mb-3">404</h1>
          <h3 class="mb-3">Page Not Found</h3>
          <p class="text-muted mb-4">The page you're looking for doesn't exist or has been moved.</p>
          <a href="/" class="btn btn-primary">
            <i class="bi bi-house me-1"></i>Go Home
          </a>
        </div>
      </div>
    </div>
    """), 404

@app.errorhandler(500)
def server_error(e):
    logger.error(f"Server error: {str(e)}", exc_info=True)
    return base_layout("Server Error", """
    <div class="container">
      <div class="row justify-content-center">
        <div class="col-md-6 text-center">
          <div class="mb-4">
            <i class="bi bi-exclamation-triangle text-danger display-1"></i>
          </div>
          <h1 class="display-4 text-muted mb-3">500</h1>
          <h3 class="mb-3">Something Went Wrong</h3>
          <p class="text-muted mb-# app.py
# NOTE: Ensure "stripe" is listed in requirements.txt to avoid ModuleNotFoundError.

from flask import Flask, request, jsonify, session, redirect, url_for, Response
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime, timedelta
import os, json, random, requests, html, csv, uuid, logging, time, hashlib, re
import stripe
import sqlite3
from contextlib import contextmanager
from werkzeug.middleware.proxy_fix import ProxyFix

# Optional CSRF import - only if available
try:
    from flask_wtf.csrf import CSRFProtect
    HAS_CSRF = True
except ImportError:
    HAS_CSRF = False

# Add fcntl import for file locking (with fallback for Windows)
try:
    import fcntl
    HAS_FCNTL = True
except ImportError:
    HAS_FCNTL = False

# ------------------------ Logging ------------------------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ------------------------ Flask / Config ------------------------
app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)
app.secret_key = os.environ.get("SECRET_KEY") or os.urandom(24)

# CSRF Protection - only if flask-wtf is available
if HAS_CSRF:
    csrf = CSRFProtect(app)

OPENAI_API_KEY       = os.environ.get("OPENAI_API_KEY", "")
OPENAI_CHAT_MODEL    = os.environ.get("OPENAI_CHAT_MODEL", "gpt-4o-mini")
OPENAI_API_BASE      = os.environ.get("OPENAI_API_BASE", "https://api.openai.com/v1")

stripe.api_key               = os.environ.get('STRIPE_SECRET_KEY', '')
STRIPE_WEBHOOK_SECRET       = os.environ.get('STRIPE_WEBHOOK_SECRET', '')
STRIPE_MONTHLY_PRICE_ID     = os.environ.get('STRIPE_MONTHLY_PRICE_ID', '')
STRIPE_SIXMONTH_PRICE_ID    = os.environ.get('STRIPE_SIXMONTH_PRICE_ID', '')
ADMIN_PASSWORD              = os.environ.get("ADMIN_PASSWORD", "").strip()

APP_VERSION = os.environ.get("APP_VERSION", "1.0.0")
IS_STAGING  = os.environ.get("RENDER_SERVICE_NAME", "").endswith("-staging")
DEBUG       = os.environ.get("FLASK_DEBUG", "0") == "1"

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=(os.environ.get("SESSION_COOKIE_SECURE", "1") == "1"),
    MESSAGE_FLASHING=True
)

# ------------------------ Data Storage ------------------------
DATA_DIR = os.environ.get("DATA_DIR", "data")
os.makedirs(DATA_DIR, exist_ok=True)
DATABASE_PATH = os.path.join(DATA_DIR, "app.db")

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
        if HAS_FCNTL:
            try:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            except:
                pass
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)

QUESTIONS   = _load_json("questions.json", [])
FLASHCARDS  = _load_json("flashcards.json", [])
USERS       = _load_json("users.json", [])

# ------------------------ Optional DB (not required) ------------------------
@contextmanager
def get_db_connection():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

def init_database():
    with get_db_connection() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            subscription TEXT DEFAULT 'inactive',
            subscription_expires_at TEXT,
            discount_code TEXT,
            stripe_customer_id TEXT,
            created_at TEXT DEFAULT (datetime('now', 'utc')),
            updated_at TEXT DEFAULT (datetime('now', 'utc'))
        );
        """)
        conn.commit()

if os.environ.get('USE_DATABASE') == '1':
    init_database()

# ------------------------ Security & Rate Limiting ------------------------
_RATE_BUCKETS = {}

@app.after_request
def add_security_headers(resp):
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    resp.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'

    csp = (
        "default-src 'self' https: data: blob:; "
        "img-src 'self' https: data:; "
        "script-src 'self' https://cdn.jsdelivr.net https://js.stripe.com; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "font-src 'self' https: data:; "
        "connect-src 'self' https://api.openai.com https://js.stripe.com https://api.stripe.com; "
        "frame-src https://js.stripe.com; "
        "frame-ancestors 'none'"
    )
    resp.headers["Content-Security-Policy"] = csp
    return resp

def _client_token():
    el = (session.get("email") or "").strip().lower()
    ip = request.remote_addr or "unknown"
    return f"{el}|{ip}"

def _rate_limited(route: str, limit: int = 10, per_seconds: int = 60) -> bool:
    global _RATE_BUCKETS
    now = time.time()
    key = (route, _client_token())
    window = [t for t in _RATE_BUCKETS.get(key, []) if now - t < per_seconds]
    if len(window) >= limit:
        _RATE_BUCKETS[key] = window
        return True
    window.append(now)
    _RATE_BUCKETS[key] = window
    
    if len(_RATE_BUCKETS) > 1000:
        cutoff = now - (per_seconds * 2)
        _RATE_BUCKETS = {k: [t for t in v if t > cutoff] 
                        for k, v in _RATE_BUCKETS.items() 
                        if any(t > cutoff for t in v)}
    
    return False

def _submission_sig(payload: dict) -> str:
    try:
        blob = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    except Exception:
        blob = str(payload)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()

# ------------------------ Auth Helpers ------------------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated_function

def is_admin():
    return session.get("admin_ok") is True

def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def _find_user(email: str):
    if not email:
        return None
    el = email.strip().lower()
    for u in USERS:
        if (u.get("email","").strip().lower() == el):
            return u
    return None

# ------------------------ Usage Management ------------------------
def check_usage_limit(user, action_type):
    if not user:
        return False, "Please log in to continue"

    subscription = user.get('subscription', 'inactive')
    expires_at = user.get('subscription_expires_at')

    if subscription == 'sixmonth' and expires_at:
        try:
            expires_dt = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
            if expires_dt.replace(tzinfo=None) < datetime.utcnow():
                user['subscription'] = 'inactive'
                user.pop('subscription_expires_at', None)
                _save_json("users.json", USERS)
                subscription = 'inactive'
        except Exception:
            pass

    limits = {
        'monthly':   {'quizzes': -1, 'questions': -1, 'tutor_msgs': -1, 'flashcards': -1},
        'sixmonth':  {'quizzes': -1, 'questions': -1, 'tutor_msgs': -1, 'flashcards': -1},
        'inactive':  {'quizzes': 0,  'questions': 0,  'tutor_msgs': 0,  'flashcards': 0},
    }

    today = datetime.utcnow()
    month_key = today.strftime('%Y-%m')

    usage = user.setdefault('usage', {})
    monthly_usage = usage.setdefault('monthly', {}).get(month_key, {})

    user_limits = limits.get(subscription, limits['inactive'])
    limit = user_limits.get(action_type, 0)
    used = monthly_usage.get(action_type, 0)

    if limit == -1:
        return True, ""
    if used >= limit:
        return False, "Your current plan has reached its limit. Please purchase a plan for unlimited access."
    return True, ""

def increment_usage(user_email, action_type, count=1):
    user = _find_user(user_email)
    if not user:
        return
    today = datetime.utcnow()
    month_key = today.strftime('%Y-%m')

    usage = user.setdefault('usage', {})
    monthly = usage.setdefault('monthly', {})
    month_usage = monthly.setdefault(month_key, {})
    month_usage[action_type] = month_usage.get(action_type, 0) + count
    usage['last_active'] = today.isoformat(timespec="seconds") + "Z"
    _save_json("users.json", USERS)

def _append_user_history(email: str, entry: dict, cap: int = 200):
    if not email:
        return
    u = _find_user(email)
    if not u:
        logger.warning(f"Cannot append history for non-existent user: {email}")
        return
    hist = u.setdefault("history", [])
    hist.append(entry)
    if len(hist) > cap:
        del hist[:-cap]
    _save_json("users.json", USERS)

# ------------------------ Questions ------------------------
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

def _normalize_question(q: dict):
    if not q or not q.get("question"):
        return None
    nq = {
        "question": q.get("question", "").strip(),
        "explanation": q.get("explanation", "").strip(),
        "domain": q.get("domain", "security-principles"),
        "difficulty": q.get("difficulty", "medium"),
    }
    opts = q.get("options")
    correct_letter = q.get("correct")
    if isinstance(opts, dict):
        letters = ["A", "B", "C", "D"]
        clean = {}
        for i, L in enumerate(letters):
            if L in opts:
                clean[L] = str(opts[L])
            elif str(i+1) in opts:
                clean[L] = str(opts[str(i+1)])
        if len(clean) != 4:
            return None
        nq["options"] = clean
        if correct_letter and isinstance(correct_letter, str) and correct_letter.upper() in ("A","B","C","D"):
            nq["correct"] = correct_letter.upper()
        else:
            try:
                idx = int(correct_letter)
                nq["correct"] = ["A","B","C","D"][idx-1]
            except Exception:
                return None
    elif isinstance(opts, list) and q.get("answer"):
        letters = ["A", "B", "C", "D"]
        if len(opts) < 4:
            return None
        nq["options"] = {letters[i]: str(opts[i]) for i in range(4)}
        try:
            ans_idx = int(q.get("answer"))
            nq["correct"] = letters[ans_idx - 1]
        except Exception:
            return None
    else:
        return None
    if nq.get("correct") not in ("A","B","C","D"):
        return None
    return nq

def _build_all_questions():
    merged = []
    seen = set()
    def add_many(src):
        for q in src:
            nq = _normalize_question(q)
            if not nq:
                continue
            key = (nq["question"], nq["domain"], nq["correct"])
            if key in seen:
                continue
            seen.add(key)
            merged.append(nq)
    add_many(QUESTIONS)
    add_many(BASE_QUESTIONS)
    return merged

ALL_QUESTIONS = _build_all_questions()

# ------------------------ Helpers ------------------------
def safe_json_response(data, status_code=200):
    try:
        return jsonify(data), status_code
    except Exception as e:
        logger.error(f"JSON serialization error: {e}")
        return jsonify({"error": "Internal server error"}), 500

def validate_quiz_submission(data):
    errors = []
    if not data:
        errors.append("No data received")
        return errors
    questions = data.get('questions', [])
    if not questions:
        errors.append("No questions provided")
    if len(questions) > 100:
        errors.append("Too many questions (max 100)")
    for i, q in enumerate(questions):
        if not q.get('question'):
            errors.append(f"Question {i+1} missing question text")
        options = q.get('options', {})
        if not all(options.get(letter) for letter in ['A', 'B', 'C', 'D']):
            errors.append(f"Question {i+1} missing options")
        if q.get('correct') not in ['A', 'B', 'C', 'D']:
            errors.append(f"Question {i+1} has invalid correct answer")
    return errors

def filter_questions(domain_key: str | None):
    pool = ALL_QUESTIONS
    if not domain_key or domain_key == "random":
        return pool[:]
    return [q for q in pool if q.get("domain") == domain_key]

def build_quiz(num: int, domain_key: str | None):
    pool = filter_questions(domain_key)
    out = []
    if not pool:
        pool = ALL_QUESTIONS[:]
    while len(out) < num:
        random.shuffle(pool)
        for q in pool:
            if len(out) >= num:
                break
            out.append(q.copy())
    title = f"Practice ({num} questions)"
    return {"title": title, "domain": domain_key or "random", "questions": out[:num]}

def chat_with_ai(msgs: list[str]) -> str:
    try:
        if not OPENAI_API_KEY:
            return "OpenAI key is not configured. Please set OPENAI_API_KEY."
        payload = {
            "model": OPENAI_CHAT_MODEL,
            "messages": [{"role": "system", "content": "You are a helpful CPP exam tutor. Format your answers for easy reading with short sections and bullet points where helpful."}]
                        + [{"role": "user", "content": m} for m in msgs][-10:],
            "temperature": 0.7,
            "max_tokens": 500,
        }
        r = requests.post(
            f"{OPENAI_API_BASE}/chat/completions",
            headers={"Authorization": f"Bearer {OPENAI_API_KEY}", "Content-Type": "application/json"},
            json=payload,
            timeout=30,
        )
        if r.status_code != 200:
            logger.error(f"OpenAI API error {r.status_code}: {r.text[:200]}")
            return f"AI error ({r.status_code}). Please try again."
        data = r.json()
        return data["choices"][0]["message"]["content"]
    except Exception as e:
        return f"AI request failed: {e}"

def _plan_badge_text(sub):
    if sub == 'monthly':
        return 'Monthly'
    if sub == 'sixmonth':
        return '6-Month'
    return 'Inactive'

def base_layout(title: str, body_html: str) -> str:
    user_name = session.get('name', '')
    user_email = session.get('email', '')
    is_logged_in = 'user_id' in session

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
    <nav class="navbar navbar-expand-lg navbar-light bg-gradient-primary sticky-top shadow-sm">
      <div class="container">
        <a class="navbar-brand fw-bold text-white" href="/">
          <i class="bi bi-shield-check text-warning"></i> CPP Test Prep
        </a>
        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
          <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="navbarNav">
          <ul class="navbar-nav me-auto">
            {'<li class="nav-item"><a class="nav-link text-white-75" href="/study"><i class="bi bi-robot me-1"></i>Tutor</a></li>' if is_logged_in else ''}
            {'<li class="nav-item"><a class="nav-link text-white-75" href="/flashcards"><i class="bi bi-card-list me-1"></i>Flashcards</a></li>' if is_logged_in else ''}
            {'<li class="nav-item"><a class="nav-link text-white-75" href="/quiz"><i class="bi bi-card-text me-1"></i>Quiz</a></li>' if is_logged_in else ''}
            {'<li class="nav-item"><a class="nav-link text-white-75" href="/mock-exam"><i class="bi bi-clipboard-check me-1"></i>Mock Exam</a></li>' if is_logged_in else ''}
            {'<li class="nav-item"><a class="nav-link text-white-75" href="/progress"><i class="bi bi-graph-up me-1"></i>Progress</a></li>' if is_logged_in else ''}
          </ul>
          <ul class="navbar-nav">
            {user_menu}
          </ul>
        </div>
      </div>
    </nav>
    """

    disclaimer = f"""
    <footer class="bg-light py-4 mt-5 border-top">
      <div class="container">
        <div class="row">
          <div class="col-md-8">
            <small class="text-muted">
              <strong>Notice:</strong> This platform is independent and not affiliated with ASIS International.
              CPP&reg; is a mark of ASIS International, Inc.
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

    # Enhanced psychology-based CSS for adult learning
    style_css = """
    <style>
      :root {
        --primary-blue: #2563eb;
        --success-green: #059669;
        --warning-orange: #d97706;
        --danger-red: #dc2626;
        --purple-accent: #7c3aed;
        --soft-gray: #f8fafc;
        --warm-white: #fefefe;
        --text-dark: #1f2937;
        --text-light: #6b7280;
      }
      
      body {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
        background: linear-gradient(135deg, #f8fafc 0%, #e2e8f0 100%);
        color: var(--text-dark);
        line-height: 1.6;
      }
      
      .bg-gradient-primary {
        background: linear-gradient(135deg, var(--primary-blue) 0%, var(--purple-accent) 100%) !important;
      }
      
      .text-white-75 {
        color: rgba(255, 255, 255, 0.85) !important;
      }
      
      .text-white-75:hover {
        color: white !important;
      }
      
      /* Cards with warm, encouraging feel */
      .card {
        box-shadow: 0 4px 12px rgba(0,0,0,0.08);
        border: none;
        border-radius: 16px;
        background: var(--warm-white);
        transition: all 0.3s ease;
        overflow: hidden;
      }
      
      .card:hover {
        transform: translateY(-2px);
        box-shadow: 0 8px 24px rgba(0,0,0,0.12);
      }
      
      /* Buttons with encouraging psychology */
      .btn {
        border-radius: 12px;
        font-weight: 600;
        letter-spacing: 0.025em;
        padding: 0.75rem 1.5rem;
        transition: all 0.2s ease;
      }
      
      .btn-primary {
        background: linear-gradient(135deg, var(--primary-blue), var(--purple-accent));
        border: none;
        box-shadow: 0 4px 12px rgba(37, 99, 235, 0.25);
      }
      
      .btn-primary:hover {
        transform: translateY(-1px);
        box-shadow: 0 6px 20px rgba(37, 99, 235, 0.35);
      }
      
      .btn-success {
        background: linear-gradient(135deg, var(--success-green), #10b981);
        border: none;
        box-shadow: 0 4px 12px rgba(5, 150, 105, 0.25);
      }
      
      .btn-warning {
        background: linear-gradient(135deg, var(--warning-orange), #f59e0b);
        border: none;
        box-shadow: 0 4px 12px rgba(217, 119, 6, 0.25);
      }
      
      /* Progress bars with motivational colors */
      .progress {
        height: 12px;
        border-radius: 8px;
        background: #e5e7eb;
        overflow: hidden;
      }
      
      .progress-bar {
        border-radius: 8px;
        transition: width 0.6s ease;
      }
      
      .bg-success {
        background: linear-gradient(90deg, var(--success-green), #10b981) !important;
      }
      
      .bg-warning {
        background: linear-gradient(90deg, var(--warning-orange), #f59e0b) !important;
      }
      
      .bg-danger {
        background: linear-gradient(90deg, var(--danger-red), #ef4444) !important;
      }
      
      /* Plan badges */
      .badge {
        font-size: 0.8em;
        padding: 0.5em 0.8em;
        border-radius: 8px;
        font-weight: 600;
      }
      
      .plan-monthly {
        background: linear-gradient(45deg, var(--primary-blue), var(--purple-accent));
        color: white;
      }
      
      .plan-sixmonth {
        background: linear-gradient(45deg, var(--purple-accent), #8b5cf6);
        color: white;
      }
      
      .plan-inactive {
        background: #6b7280;
        color: white;
      }
      
      /* Encouraging alert styles */
      .alert {
        border-radius: 12px;
        border: none;
        padding: 1.25rem;
      }
      
      .alert-success {
        background: linear-gradient(135deg, #d1fae5, #a7f3d0);
        color: #065f46;
        border-left: 4px solid var(--success-green);
      }
      
      .alert-info {
        background: linear-gradient(135deg, #dbeafe, #bfdbfe);
        color: #1e3a8a;
        border-left: 4px solid var(--primary-blue);
      }
      
      .alert-warning {
        background: linear-gradient(135deg, #fef3c7, #fed7aa);
        color: #92400e;
        border-left: 4px solid var(--warning-orange);
      }
      
      /* Form improvements */
      .form-control, .form-select {
        border-radius: 10px;
        border: 2px solid #e5e7eb;
        padding: 0.75rem 1rem;
        transition: all 0.2s ease;
      }
      
      .form-control:focus, .form-select:focus {
        border-color: var(--primary-blue);
        box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.1);
      }
      
      /* Navigation improvements */
      .navbar-brand {
        font-size: 1.5rem;
        font-weight: 700;
      }
      
      /* Motivational elements */
      .progress-dial-container, .mini-dial-container, .main-dial-container {
        display: flex;
        justify-content: center;
        align-items: center;
      }
      
      .progress-dial, .mini-dial, .main-dial {
        transform: rotate(-90deg);
        filter: drop-shadow(0 4px 8px rgba(0,0,0,0.1));
      }
      
      .dial-score, .mini-score, .main-score {
        transform: rotate(90deg);
        font-weight: 700;
      }
      
      /* Responsive improvements */
      @media (max-width: 768px) {
        .container {
          padding: 0 20px;
        }
        
        .card {
          margin-bottom: 1.5rem;
          border-radius: 12px;
        }
        
        .btn {
          padding: 0.6rem 1.2rem;
        }
      }
      
      /* Micro-interactions */
      .domain-chip {
        cursor: pointer;
        transition: all 0.2s ease;
        border-radius: 20px;
        padding: 0.5rem 1rem;
      }
      
      .domain-chip:hover {
        transform: translateY(-1px);
      }
      
      /* Flash message styling */
      .flash-message {
        position: fixed;
        top: 80px;
        right: 20px;
        z-index: 1050;
        min-width: 300px;
        animation: slideInRight 0.3s ease;
      }
      
      @keyframes slideInRight {
        from {
          transform: translateX(100%);
          opacity: 0;
        }
        to {
          transform: translateX(0);
          opacity: 1;
        }
      }
      
      /* Encouraging color scheme for results */
      .text-success { 
        color: var(--success-green) !important;
        fill: var(--success-green);
      }
      .text-warning { 
        color: var(--warning-orange) !important;
        fill: var(--warning-orange);
      }
      .text-danger { 
        color: var(--danger-red) !important;
        fill: var(--danger-red);
      }
    </style>
    """

    body_html = body_html.replace('{{ csrf_token() }}', csrf_token_value)

    return f"""<!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <meta name="csrf-token" content="{csrf_token_value}">
      <title>{html.escape(title)} - CPP Test Prep</title>
      <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
      <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css" rel="stylesheet">
      <link rel="preconnect" href="https://fonts.googleapis.com">
      <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
      <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
      {style_css}
    </head>
    <body class="d-flex flex-column min-vh-100">
      {nav}
      {stage_banner}
      <main class="flex-grow-1 py-4">
        {body_html}
      </main>
      {disclaimer}
      <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
    </body>
    </html>"""

@app.template_global()
def csrf_token():
    if HAS_CSRF:
        from flask_wtf.csrf import generate_csrf
        return generate_csrf()
    return ""

# ------------------------ Stripe ------------------------
def create_stripe_checkout_session(user_email, plan='monthly'):
    try:
        if plan == 'monthly':
            if not STRIPE_MONTHLY_PRICE_ID:
                logger.error("Monthly price ID not configured")
                return None
            checkout_session = stripe.checkout.Session.create(
                payment_method_types=['card'],
                line_items=[{'price': STRIPE_MONTHLY_PRICE_ID, 'quantity': 1}],
                mode='subscription',
                customer_email=user_email,
                success_url=request.url_root + 'billing/success?session_id={CHECKOUT_SESSION_ID}&plan=monthly',
                cancel_url=request.url_root + 'billing',
                metadata={'user_email': user_email, 'plan': 'monthly'}
            )
        elif plan == 'sixmonth':
            if not STRIPE_SIXMONTH_PRICE_ID:
                logger.error("Six-month price ID not configured")
                return None
            checkout_session = stripe.checkout.Session.create(
                payment_method_types=['card'],
                line_items=[{'price': STRIPE_SIXMONTH_PRICE_ID, 'quantity': 1}],
                mode='payment',
                customer_email=user_email,
                success_url=request.url_root + 'billing/success?session_id={CHECKOUT_SESSION_ID}&plan=sixmonth',
                cancel_url=request.url_root + 'billing',
                metadata={'user_email': user_email, 'plan': 'sixmonth', 'duration_days': 180}
            )
        else:
            return None
        return checkout_session.url
    except Exception as e:
        logger.error(f"Stripe session creation failed: {e}")
        return None

# ------------------------ Routes: Health ------------------------
@app.get("/healthz")
def healthz():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}

# ------------------------ Auth ------------------------
@app.get("/login")
def login_page():
    if 'user_id' in session:
        return redirect(url_for('home'))
    body = """
    <div class="container">
      <div class="row justify-content-center">
        <div class="col-md-6 col-lg-4">
          <div class="card shadow-lg">
            <div class="card-body p-4">
              <div class="text-center mb-4">
                <i class="bi bi-shield-check text-primary display-4 mb-3"></i>
                <h2 class="card-title fw-bold text-primary">Welcome Back</h2>
                <p class="text-muted">Sign in to continue your CPP journey</p>
              </div>
              <form method="POST" action="/login">
                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
                <div class="mb-3">
                  <label for="email" class="form-label fw-semibold">Email</label>
                  <input type="email" class="form-control" name="email" required placeholder="your.email@example.com">
                </div>
                <div class="mb-4">
                  <label for="password" class="form-label fw-semibold">Password</label>
                  <input type="password" class="form-control" name="password" required placeholder="Enter your password">
                </div>
                <button type="submit" class="btn btn-primary w-100 mb-3">Sign In</button>
              </form>
              <div class="text-center">
                <p class="text-muted mb-2">Don't have an account?</p>
                <a href="/signup" class="btn btn-outline-primary">Create Account</a>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
    """
    return base_layout("Sign In", body)

@app.post("/login")
def login_post():
    if _rate_limited("login", limit=5, per_seconds=300):
        return redirect(url_for('login_page'))
    
    email = request.form.get('email', '').strip().lower()
    password = request.form.get('password', '')
    
    if not email or not password:
        return redirect(url_for('login_page'))
    
    user = _find_user(email)
    if user and check_password_hash(user.get('password_hash', ''), password):
        try:
            session.regenerate()
        except AttributeError:
            old_data = dict(session)
            session.clear()
            session.permanent = True
        
        session['user_id'] = user['id']
        session['email'] = user['email']
        session['name'] = user.get('name', '')
        return redirect(url_for('home'))
    
    return redirect(url_for('login_page'))

@app.get("/signup")
def signup_page():
    body = """
    <div class="container">
      <div class="row justify-content-center">
        <div class="col-lg-10">
          <div class="text-center mb-5">
            <i class="bi bi-mortarboard text-primary display-4 mb-3"></i>
            <h1 class="display-5 fw-bold text-primary">Start Your CPP Journey</h1>
            <p class="lead text-muted">Choose your path to certification success</p>
          </div>
          
          <div class="row mb-5">
            <div class="col-md-6 mb-4">
              <div class="card h-100 border-primary position-relative">
                <div class="card-header bg-primary text-white text-center">
                  <h4 class="mb-0">Monthly Plan</h4>
                </div>
                <div class="card-body text-center p-4">
                  <div class="mb-3">
                    <span class="display-4 fw-bold text-primary">$39.99</span>
                    <span class="text-muted fs-5">/month</span>
                  </div>
                  <p class="text-muted mb-4">Perfect for focused study periods</p>
                  <ul class="list-unstyled mb-4">
                    <li class="mb-2"><i class="bi bi-check-circle-fill text-success me-2"></i>Unlimited practice quizzes</li>
                    <li class="mb-2"><i class="bi bi-check-circle-fill text-success me-2"></i>AI tutor with instant help</li>
                    <li class="mb-2"><i class="bi bi-check-circle-fill text-success me-2"></i>Progress tracking & analytics</li>
                    <li class="mb-2"><i class="bi bi-check-circle-fill text-success me-2"></i>Mobile-friendly study</li>
                    <li class="mb-2"><i class="bi bi-check-circle-fill text-success me-2"></i>Cancel anytime</li>
                  </ul>
                  <button class="btn btn-primary btn-lg w-100" onclick="selectPlan('monthly')">Choose Monthly</button>
                </div>
              </div>
            </div>
            <div class="col-md-6 mb-4">
              <div class="card h-100 border-success position-relative">
                <div class="badge bg-warning text-dark position-absolute top-0 start-50 translate-middle px-3 py-2">
                  <i class="bi bi-star-fill"></i> Best Value
                </div>
                <div class="card-header bg-success text-white text-center">
                  <h4 class="mb-0">6-Month Plan</h4>
                </div>
                <div class="card-body text-center p-4">
                  <div class="mb-3">
                    <span class="display-4 fw-bold text-success">$99.00</span>
                    <span class="text-muted fs-6 d-block">One-time payment</span>
                  </div>
                  <p class="text-muted mb-4">Complete preparation program</p>
                  <ul class="list-unstyled mb-4">
                    <li class="mb-2"><i class="bi bi-check-circle-fill text-success me-2"></i>Everything in Monthly</li>
                    <li class="mb-2"><i class="bi bi-check-circle-fill text-success me-2"></i>6 full months of access</li>
                    <li class="mb-2"><i class="bi bi-check-circle-fill text-success me-2"></i>No auto-renewal</li>
                    <li class="mb-2"><i class="bi bi-check-circle-fill text-success me-2"></i>Save $140+ vs monthly</li>
                    <li class="mb-2"><i class="bi bi-check-circle-fill text-success me-2"></i>Extended study time</li>
                  </ul>
                  <button class="btn btn-success btn-lg w-100" onclick="selectPlan('sixmonth')">Choose 6-Month</button>
                </div>
              </div>
            </div>
          </div>
          
          <div class="card shadow-lg">
            <div class="card-body p-4">
              <h3 class="card-title text-center mb-4">Create Your Account</h3>
              <form method="POST" action="/signup" id="signupForm">
                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
                <input type="hidden" name="plan" id="selectedPlan" value="monthly">
                <div class="row">
                  <div class="col-md-6 mb-3">
                    <label class="form-label fw-semibold">Full Name</label>
                    <input type="text" class="form-control" name="name" required placeholder="John Doe">
                  </div>
                  <div class="col-md-6 mb-3">
                    <label class="form-label fw-semibold">Email</label>
                    <input type="email" class="form-control" name="email" required placeholder="john@example.com">
                  </div>
                </div>
                <div class="mb-4">
                  <label class="form-label fw-semibold">Password</label>
                  <input type="password" class="form-control" name="password" required minlength="8" placeholder="At least 8 characters">
                  <div class="form-text">Choose a strong password with at least 8 characters</div>
                </div>
                <button type="submit" class="btn btn-success btn-lg w-100">
                  <i class="bi bi-rocket-takeoff me-2"></i>Create Account & Start Learning
                </button>
              </form>
            </div>
          </div>
        </div>
      </div>
    </div>
    
    <script>
      let selectedPlanType = 'monthly';
      
      function selectPlan(plan) {
        selectedPlanType = plan;
        document.getElementById('selectedPlan').value = plan;
        
        // Update visual feedback
        document.querySelectorAll('.card').forEach(card => {
          card.classList.remove('border-primary', 'border-success', 'shadow-lg');
        });
        
        if (plan === 'monthly') {
          document.querySelector('[onclick="selectPlan(\'monthly\')"]').closest('.card').classList.add('border-primary', 'shadow-lg');
        } else {
          document.querySelector('[onclick="selectPlan(\'sixmonth\')"]').closest('.card').classList.add('border-success', 'shadow-lg');
        }
        
        // Update submit button text
        const submitBtn = document.querySelector('button[type="submit"]');
        const planName = plan === 'monthly' ? 'Monthly' : '6-Month';
        submitBtn.innerHTML = `<i class="bi bi-rocket-takeoff me-2"></i>Create Account & Choose ${planName}`;
      }
      
      // Pre-select monthly plan
      selectPlan('monthly');
    </script>
    """
    return base_layout("Create Account", body)

@app.post("/signup")
def signup_post():
    name = request.form.get('name', '').strip()
    email = request.form.get('email', '').strip().lower()
    password = request.form.get('password', '')
    plan = (request.form.get('plan') or 'monthly').strip()
    
    # Validation
    if not name or not email or not password:
        return redirect(url_for('signup_page'))
    if not validate_email(email):
        return redirect(url_for('signup_page'))
    if len(password) < 8:
        return redirect(url_for('signup_page'))
    if _find_user(email):
        return redirect(url_for('signup_page'))

    # Create user
    user = {
        "id": str(uuid.uuid4()),
        "name": name,
        "email": email,
        "password_hash": generate_password_hash(password),
        "subscription": "inactive",
        "usage": {"monthly": {}, "last_active": ""},
        "created_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "history": []
    }
    USERS.append(user)
    _save_json("users.json", USERS)

    # Login user
    try:
        session.regenerate()
    except AttributeError:
        session.clear()
        session.permanent = True
    
    session['user_id'] = user['id']
    session['email'] = user['email']
    session['name'] = user['name']

    # Redirect to checkout
    return redirect(url_for('billing_checkout', plan=plan))

@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for('login_page'))

# ------------------------ Home ------------------------
@app.get("/")
def home():
    if 'user_id' not in session:
        body = """
        <div class="container">
          <div class="row justify-content-center text-center">
            <div class="col-lg-10">
              <div class="mb-5">
                <i class="bi bi-mortarboard text-primary display-1 mb-4"></i>
                <h1 class="display-3 fw-bold mb-4">Master the CPP Exam</h1>
                <p class="lead fs-4 text-muted mb-5">
                  Transform your security career with AI-powered learning, 
                  comprehensive practice tests, and personalized progress tracking.
                </p>
              </div>
              
              <div class="row mb-5 g-4">
                <div class="col-md-4">
                  <div class="card border-0 h-100">
                    <div class="card-body text-center p-4">
                      <i class="bi bi-robot display-4 text-primary mb-3"></i>
                      <h4 class="fw-bold">AI Study Tutor</h4>
                      <p class="text-muted">Get instant explanations, clarifications, and study guidance tailored to your learning style.</p>
                    </div>
                  </div>
                </div>
                <div class="col-md-4">
                  <div class="card border-0 h-100">
                    <div class="card-body text-center p-4">
                      <i class="bi bi-card-text display-4 text-success mb-3"></i>
                      <h4 class="fw-bold">Practice Quizzes</h4>
                      <p class="text-muted">Test your knowledge across all CPP domains with unlimited practice questions and detailed explanations.</p>
                    </div>
                  </div>
                </div>
                <div class="col-md-4">
                  <div class="card border-0 h-100">
                    <div class="card-body text-center p-4">
                      <i class="bi bi-graph-up display-4 text-warning mb-3"></i>
                      <h4 class="fw-bold">Smart Analytics</h4>
                      <p class="text-muted">Track your progress, identify weak areas, and focus your study time where it matters most.</p>
                    </div>
                  </div>
                </div>
              </div>
              
              <div class="mb-5">
                <a href="/signup" class="btn btn-primary btn-lg me-3 px-5 py-3">
                  <i class="bi bi-rocket-takeoff me-2"></i>Start Learning Now
                </a>
                <a href="/login" class="btn btn-outline-primary btn-lg px-5 py-3">
                  <i class="bi bi-box-arrow-in-right me-2"></i>Sign In
                </a>
              </div>
              
              <div class="row text-start g-4">
                <div class="col-md-6">
                  <div class="d-flex">
                    <i class="bi bi-check-circle-fill text-success fs-4 me-3 mt-1"></i>
                    <div>
                      <h5 class="fw-bold">Exam-Ready Content</h5>
                      <p class="text-muted mb-0">Questions designed to mirror the real CPP certification exam format and difficulty.</p>
                    </div>
                  </div>
                </div>
                <div class="col-md-6">
                  <div class="d-flex">
                    <i class="bi bi-check-circle-fill text-success fs-4 me-3 mt-1"></i>
                    <div>
                      <h5 class="fw-bold">Flexible Learning</h5>
                      <p class="text-muted mb-0">Study at your own pace with mobile-friendly access anywhere, anytime.</p>
                    </div>
                  </div>
                </div>
                <div class="col-md-6">
                  <div class="d-flex">
                    <i class="bi bi-check-circle-fill text-success fs-4 me-3 mt-1"></i>
                    <div>
                      <h5 class="fw-bold">Proven Methods</h5>
                      <p class="text-muted mb-0">Built on adult learning principles and spaced repetition for maximum retention.</p>
                    </div>
                  </div>
                </div>
                <div class="col-md-6">
                  <div class="d-flex">
                    <i class="bi bi-check-circle-fill text-success fs-4 me-3 mt-1"></i>
                    <div>
                      <h5 class="fw-bold">Instant Feedback</h5>
                      <p class="text-muted mb-0">Learn from mistakes immediately with detailed explanations for every question.</p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
        """
        return base_layout("CPP Test Prep - Master Your Certification", body)

    # Dashboard for logged-in users
    user_name = session.get('name', '').split(' ')[0] or 'there'
    hist = session.get("quiz_history", [])
    avg = round(sum(h.get("score", 0.0) for h in hist) / len(hist), 1) if hist else 0.0
    
    # Progress dial colors
    if avg >= 80:
        dial_color = "success"
        dial_bg = "#059669"
    elif avg >= 60:
        dial_color = "warning" 
        dial_bg = "#d97706"
    else:
        dial_color = "danger"
        dial_bg = "#dc2626"
    
    # Encouraging tips based on psychology
    tips = [
        "Small wins build momentum — try a focused 15-minute session today.",
        "Active recall beats passive reading — quiz yourself regularly.",
        "Mix different topics to strengthen long-term memory connections.",
        "Practice under time pressure to build exam-day confidence.",
        "Teach concepts out loud — if you can explain it, you truly know it.",
        "Celebrate progress, not just perfection — every question counts.",
        "Take breaks between study sessions for better information processing."
    ]
    tip = random.choice(tips)
    
    body = f"""
    <div class="container">
      <div class="row">
        <div class="col-lg-8">
          <div class="card mb-4 border-0 shadow-sm">
            <div class="card-body p-4">
              <div class="d-flex align-items-center mb-3">
                <div class="me-3">
                  <div class="rounded-circle bg-primary bg-opacity-10 p-3">
                    <i class="bi bi-person-check text-primary fs-3"></i>
                  </div>
                </div>
                <div>
                  <h1 class="h3 mb-1">Welcome back, {html.escape(user_name)}!</h1>
                  <p class="text-muted mb-0">Ready to advance your CPP preparation?</p>
                </div>
              </div>
            </div>
          </div>
          
          <div class="card mb-4 border-0 bg-gradient-primary text-white">
            <div class="card-body p-4">
              <div class="d-flex align-items-start">
                <i class="bi bi-lightbulb text-warning fs-2 me-3 mt-1"></i>
                <div>
                  <h5 class="card-title text-white mb-2">Today's Learning Tip</h5>
                  <p class="card-text opacity-90 mb-0">{html.escape(tip)}</p>
                </div>
              </div>
            </div>
          </div>
          
          <div class="row g-3">
            <div class="col-md-6">
              <a href="/study" class="text-decoration-none">
                <div class="card h-100 border-0 shadow-sm study-card">
                  <div class="card-body text-center p-4">
                    <i class="bi bi-robot text-primary display-6 mb-3"></i>
                    <h5 class="card-title">AI Study Tutor</h5>
                    <p class="text-muted small">Get instant help and explanations</p>
                  </div>
                </div>
              </a>
            </div>
            <div class="col-md-6">
              <a href="/quiz" class="text-decoration-none">
                <div class="card h-100 border-0 shadow-sm study-card">
                  <div class="card-body text-center p-4">
                    <i class="bi bi-card-text text-success display-6 mb-3"></i>
                    <h5 class="card-title">Practice Quiz</h5>
                    <p class="text-muted small">Test your knowledge</p>
                  </div>
                </div>
              </a>
            </div>
            <div class="col-md-6">
              <a href="/flashcards" class="text-decoration-none">
                <div class="card h-100 border-0 shadow-sm study-card">
                  <div class="card-body text-center p-4">
                    <i class="bi bi-card-list text-info display-6 mb-3"></i>
                    <h5 class="card-title">Flashcards</h5>
                    <p class="text-muted small">Quick review sessions</p>
                  </div>
                </div>
              </a>
            </div>
            <div class="col-md-6">
              <a href="/mock-exam" class="text-decoration-none">
                <div class="card h-100 border-0 shadow-sm study-card">
                  <div class="card-body text-center p-4">
                    <i class="bi bi-clipboard-check text-warning display-6 mb-3"></i>
                    <h5 class="card-title">Mock Exam</h5>
                    <p class="text-muted small">Simulate exam conditions</p>
                  </div>
                </div>
              </a>
            </div>
          </div>
        </div>
        
        <div class="col-lg-4">
          <div class="card border-0 shadow-sm">
            <div class="card-body text-center p-4">
              <h5 class="card-title mb-4">Your Progress</h5>
              <div class="progress-dial-container mb-3">
                <svg width="180" height="180" viewBox="0 0 180 180" class="progress-dial">
                  <defs>
                    <linearGradient id="dialGrad" x1="0%" y1="0%" x2="100%" y2="0%">
                      <stop offset="0%" style="stop-color:{dial_bg};stop-opacity:0.3" />
                      <stop offset="100%" style="stop-color:{dial_bg};stop-opacity:1" />
                    </linearGradient>
                  </defs>
                  <path d="M 30 90 A 60 60 0 1 1 150 90" fill="none" stroke="#e9ecef" stroke-width="8" stroke-linecap="round"/>
                  <path d="M 30 90 A 60 60 0 {1 if avg > 50 else 0} 1 {30 + (120 * avg / 100)} {90 - (60 * (1 - abs(((avg / 100) * 2) - 1)))}" 
                        fill="none" stroke="url(#dialGrad)" stroke-width="8" stroke-linecap="round"
                        class="progress-arc" data-score="{avg}"/>
                  <text x="90" y="85" text-anchor="middle" class="dial-score text-{dial_color}" font-size="28" font-weight="bold">{avg}%</text>
                  <text x="90" y="105" text-anchor="middle" class="dial-label" font-size="14" fill="#6c757d">Average Score</text>
                </svg>
              </div>
              <div class="row g-2 text-center">
                <div class="col-6">
                  <div class="small text-muted">Attempts</div>
                  <div class="fw-bold text-primary">{len(hist)}</div>
                </div>
                <div class="col-6">
                  <div class="small text-muted">Best Score</div>
                  <div class="fw-bold text-success">{max([h.get('score', 0) for h in hist], default=0):.0f}%</div>
                </div>
              </div>
              <a href="/progress" class="btn btn-outline-primary btn-sm mt-3">View Details</a>
            </div>
          </div>
        </div>
      </div>
    </div>
    
    <style>
      .study-card {{
        transition: all 0.3s ease;
        border: 2px solid transparent;
      }}
      
      .study-card:hover {{
        transform: translateY(-4px);
        border-color: var(--primary-blue);
        box-shadow: 0 8px 25px rgba(37, 99, 235, 0.15) !important;
      }}
      
      .text-decoration-none:hover {{
        text-decoration: none !important;
      }}
    </style>
    """
    return base_layout("Dashboard", body)

# ------------------------ Study / Chat ------------------------
@app.get("/study")
@login_required
def study_page():
    chips = ['<span class="badge bg-secondary me-2 mb-2 domain-chip" data-domain="random">All Topics</span>']
    chips.extend([f'<span class="badge bg-primary me-2 mb-2 domain-chip" data-domain="{k}">{v}</span>' for k, v in DOMAINS.items()])
    
    SUGGESTIONS = {
        "security-principles": [
            "Explain defense in depth with examples",
            "Risk assessment methodology steps", 
            "Least privilege vs. zero trust differences",
            "Security control categories overview"
        ],
        "business-principles": [
            "Risk-based security budgeting approach",
            "Building business case for security upgrades",
            "ROI calculation for security investments",
            "Key performance indicators for security programs"
        ],
        "investigations": [
            "Chain of custody best practices checklist",
            "Interview vs. interrogation techniques",
            "Digital evidence handling procedures", 
            "Crime scene preservation essentials"
        ],
        "personnel-security": [
            "Employee termination security checklist",
            "Pre-employment screening best practices",
            "Insider threat warning indicators",
            "Visitor and contractor access controls"
        ],
        "physical-security": [
            "CPTED principles for office environments",
            "Perimeter vs. internal security controls",
            "Access control system levels",
            "Lock and key management basics"
        ],
        "information-security": [
            "Incident response process phases",
            "Multi-layered phishing protection strategy",
            "Backup strategy: 3-2-1 rule explained",
            "Security awareness training ideas"
        ],
        "crisis-management": [
            "Business continuity vs. disaster recovery",
            "Crisis communication plan essentials",
            "Tabletop exercise planning guide",
            "Critical business function identification"
        ]
    }
    sugg_json = json.dumps(SUGGESTIONS)
    
    body = f"""
    <div class="container">
      <div class="row justify-content-center">
        <div class="col-lg-10">
          <div class="card border-0 shadow-sm">
            <div class="card-body p-4">
              <div class="d-flex align-items-center mb-4">
                <div class="me-3">
                  <div class="rounded-circle bg-primary bg-opacity-10 p-3">
                    <i class="bi bi-robot text-primary fs-2"></i>
                  </div>
                </div>
                <div>
                  <h2 class="mb-1">AI Study Tutor</h2>
                  <p class="text-muted mb-0">Get instant, personalized help with CPP exam topics</p>
                </div>
              </div>
              
              <div class="mb-4">
                <label class="form-label fw-semibold mb-3">Choose your focus area:</label>
                <div class="domain-chips">{''.join(chips)}</div>
              </div>
              
              <div class="chat-container">
                <div class="input-group mb-3">
                  <input type="text" class="form-control" id="chatInput" placeholder="Ask your question or request an explanation...">
                  <button class="btn btn-primary" type="button" id="sendBtn">
                    <i class="bi bi-send me-1"></i>Send
                  </button>
                </div>
                
                <div class="alert alert-info border-0 mb-4">
                  <div class="d-flex">
                    <i class="bi bi-info-circle text-info fs-5 me-2"></i>
                    <div>
                      <strong>Pro tip:</strong> Ask specific questions like "Explain risk assessment with a manufacturing example" 
                      or request practice scenarios for better understanding.
                    </div>
                  </div>
                </div>
                
                <div class="card border-0 bg-light mb-4">
                  <div class="card-body p-3">
                    <h6 class="card-title">How to get the most from your AI Tutor:</h6>
                    <ol class="small mb-0">
                      <li>Select a domain above or keep "All Topics" for general questions</li>
                      <li>Click a suggested topic below or type your own question</li>
                      <li>Ask follow-up questions to deepen your understanding</li>
                      <li>Request examples, scenarios, or practice problems</li>
                    </ol>
                  </div>
                </div>
                
                <div id="chatHistory" class="chat-history mb-4"></div>
                
                <div id="suggestions">
                  <h6 class="fw-semibold mb-3">Suggested topics for your selected domain:</h6>
                  <div id="suggestionList" class="suggestion-chips"></div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
    
    <style>
      .domain-chips .badge {{
        cursor: pointer;
        transition: all 0.2s ease;
        border: 2px solid transparent;
      }}
      
      .domain-chips .badge:hover {{
        transform: translateY(-1px);
      }}
      
      .suggestion-chips .badge {{
        cursor: pointer;
        transition: all 0.2s ease;
        margin: 0.25rem;
        padding: 0.5rem 1rem;
      }}
      
      .suggestion-chips .badge:hover {{
        transform: translateY(-1px);
        box-shadow: 0 2px 8px rgba(0,0,0,0.15);
      }}
      
      .chat-history {{
        min-height: 200px;
        max-height: 400px;
        overflow-y: auto;
        background: #f8fafc;
        border-radius: 12px;
        padding: 1rem;
      }}
      
      .chat-history:empty {{
        display: flex;
        align-items: center;
        justify-content: center;
        color: #6b7280;
        font-style: italic;
      }}
      
      .chat-history:empty::before {{
        content: "Your conversation will appear here...";
      }}
    </style>
    """
    
    # JavaScript for the tutor interface
    body += f"""
    <script>
      const suggestions = {sugg_json};
      let currentDomain = 'random';
      
      function escapeHtml(text) {{
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
      }}
      
      function updateSuggestions(domain) {{
        const list = document.getElementById('suggestionList');
        const domainSuggestions = suggestions[domain] || suggestions['security-principles'];
        list.innerHTML = domainSuggestions.map(s =>
          `<span class="badge bg-light text-dark suggestion-item" onclick="askQuestion('${{s}}')">${{s}}</span>`
        ).join('');
      }}
      
      function askQuestion(question) {{
        document.getElementById('chatInput').value = question;
        sendMessage();
      }}
      
      function sendMessage() {{
        const input = document.getElementById('chatInput');
        const message = input.value.trim();
        if (!message) return;
        
        const chatHistory = document.getElementById('chatHistory');
        const sendBtn = document.getElementById('sendBtn');
        
        // Add user message
        chatHistory.innerHTML += `
          <div class="mb-3 d-flex justify-content-end">
            <div class="bg-primary text-white rounded-3 p-3" style="max-width: 80%;">
              <strong>You:</strong><br>${{escapeHtml(message)}}
            </div>
          </div>
        `;
        
        // Add thinking indicator
        const thinkingId = 'thinking-' + Date.now();
        chatHistory.innerHTML += `
          <div class="mb-3" id="${{thinkingId}}">
            <div class="bg-light rounded-3 p-3" style="max-width: 80%;">
              <div class="d-flex align-items-center">
                <div class="spinner-border spinner-border-sm text-primary me-2" role="status"></div>
                <em class="text-muted">AI Tutor is thinking...</em>
              </div>
            </div>
          </div>
        `;
        
        input.value = '';
        sendBtn.disabled = true;
        chatHistory.scrollTop = chatHistory.scrollHeight;
        
        // Send to API
        fetch('/api/chat', {{
          method: 'POST',
          headers: {{
            'Content-Type': 'application/json',
            'X-CSRFToken': document.querySelector('meta[name=csrf-token]').getAttribute('content')
          }},
          body: JSON.stringify({{message: message, domain: currentDomain}})
        }})
        .then(r => r.json())
        .then(data => {{
          const thinkingEl = document.getElementById(thinkingId);
          
          if (data.error) {{
            thinkingEl.outerHTML = `
              <div class="mb-3">
                <div class="bg-danger text-white rounded-3 p-3" style="max-width: 80%;">
                  <i class="bi bi-exclamation-triangle me-1"></i>
                  ${{escapeHtml(data.error)}}
                </div>
              </div>
            `;
          }} else {{
            const formattedResponse = escapeHtml(data.response || '').replace(/\\n/g, '<br>');
            thinkingEl.outerHTML = `
              <div class="mb-3">
                <div class="bg-light rounded-3 p-3" style="max-width: 80%;">
                  <div class="d-flex align-items-start">
                    <i class="bi bi-robot text-primary fs-5 me-2 mt-1"></i>
                    <div>
                      <strong class="text-primary">AI Tutor:</strong><br>
                      ${{formattedResponse}}
                    </div>
                  </div>
                </div>
              </div>
            `;
          }}
          
          chatHistory.scrollTop = chatHistory.scrollHeight;
          sendBtn.disabled = false;
        }})
        .catch(() => {{
          document.getElementById(thinkingId).outerHTML = `
            <div class="mb-3">
              <div class="bg-warning text-dark rounded-3 p-3" style="max-width: 80%;">
                <i class="bi bi-exclamation-triangle me-1"></i>
                Connection error. Please try again.
              </div>
            </div>
          `;
          sendBtn.disabled = false;
        }});
      }}
      
      // Domain selection
      document.querySelectorAll('.domain-chip').forEach(chip => {{
        chip.addEventListener('click', function() {{
          document.querySelectorAll('.domain-chip').forEach(c => {{
            c.classList.remove('bg-success');
            c.classList.add('bg-primary');
          }});
          
          if (this.dataset.domain === 'random') {{
            this.classList.remove('bg-primary');
            this.classList.add('bg-secondary');
          }} else {{
            this.classList.remove('bg-primary');
            this.classList.add('bg-success');
          }}
          
          currentDomain = this.dataset.domain;
          updateSuggestions(currentDomain);
        }});
      }});
      
      // Event listeners
      document.getElementById('sendBtn').addEventListener('click', sendMessage);
      document.getElementById('chatInput').addEventListener('keypress', function(e) {{
        if (e.key === 'Enter' && !e.shiftKey) {{
          e.preventDefault();
          sendMessage();
        }}
      }});
      
      // Initialize
      updateSuggestions('random');
    </script>
    """
    return base_layout("AI Study Tutor", body)

@app.post("/api/chat")
@login_required
def api_chat():
    user = _find_user(session.get('email', ''))
    can_chat, error_msg = check_usage_limit(user, 'tutor_msgs')
    if not can_chat:
        return safe_json_response({"error": error_msg, "upgrade_required": True}, 403)
    if _rate_limited("chat", limit=10, per_seconds=60):
        return safe_json_response({"error": "Too many requests. Please wait a moment."}, 429)

    data = request.get_json() or {}
    user_msg = (data.get("message") or "").strip()
    dom = data.get("domain")
    if not user_msg:
        return safe_json_response({"error": "Empty message"}, 400)
    
    prefix = f"Focus on the CPP domain: {DOMAINS[dom]}.\n" if dom and dom in DOMAINS else ""
    reply = chat_with_ai([prefix + user_msg])
    increment_usage(user['email'], 'tutor_msgs')
    return safe_json_response({"response": reply, "timestamp": datetime.utcnow().isoformat()})

# ------------------------ Quiz ------------------------
@app.get("/quiz")
@login_required
def quiz_page():
    chips = ['<span class="badge bg-secondary me-2 mb-2 domain-chip" data-domain="random">All Topics</span>']
    chips.extend([f'<span class="badge bg-primary me-2 mb-2 domain-chip" data-domain="{k}">{v}</span>' for k, v in DOMAINS.items()])
    q = build_quiz(10, "random")
    q_json = json.dumps(q)
    
    body = f"""
    <div class="container">
      <div class="card border-0 shadow-sm">
        <div class="card-body p-4">
          <div class="row align-items-center mb-4">
            <div class="col-md-8">
              <div class="d-flex align-items-center">
                <div class="me-3">
                  <div class="rounded-circle bg-success bg-opacity-10 p-3">
                    <i class="bi bi-card-text text-success fs-2"></i>
                  </div>
                </div>
                <div>
                  <h2 class="mb-1">Practice Quiz</h2>
                  <p class="text-muted mb-0" id="quizInfo">10 questions • Domain: All Topics</p>
                </div>
              </div>
            </div>
            <div class="col-md-4 text-end">
              <div class="d-flex gap-2">
                <select class="form-select" id="questionCount" style="max-width: 100px;">
                  <option value="5">5</option>
                  <option value="10" selected>10</option>
                  <option value="15">15</option>
                  <option value="20">20</option>
                </select>
                <button class="btn btn-outline-primary" id="buildQuiz">
                  <i class="bi bi-arrow-clockwise me-1"></i>New Quiz
                </button>
              </div>
            </div>
          </div>
          
          <div class="mb-4">
            <label class="form-label fw-semibold mb-3">Choose domain:</label>
            <div class="domain-chips">{''.join(chips)}</div>
          </div>
          
          <div id="quizContainer">
            <div id="quizQuestions"></div>
            <div class="text-center mt-4">
              <button class="btn btn-success btn-lg px-5" id="submitQuiz" style="display:none">
                <i class="bi bi-check-circle me-2"></i>Submit Quiz
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
    
    <!-- Results Modal -->
    <div id="resultsModal" class="modal fade" tabindex="-1">
      <div class="modal-dialog modal-lg">
        <div class="modal-content border-0 shadow">
          <div class="modal-header border-0 pb-0">
            <h5 class="modal-title fw-bold">Quiz Results</h5>
            <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
          </div>
          <div class="modal-body" id="resultsContent"></div>
          <div class="modal-footer border-0">
            <button type="button" class="btn btn-primary" data-bs-dismiss="modal">
              <i class="bi bi-arrow-left me-1"></i>Continue Learning
            </button>
          </div>
        </div>
      </div>
    </div>
    
    <style>
      .quiz-question {{
        transition: all 0.3s ease;
      }}
      
      .quiz-question:hover {{
        transform: translateY(-1px);
        box-shadow: 0 4px 12px rgba(0,0,0,0.1);
      }}
      
      .form-check-input:checked {{
        background-color: var(--success-green);
        border-color: var(--success-green);
      }}
      
      .domain-chips .badge {{
        cursor: pointer;
        transition: all 0.2s ease;
        border: 2px solid transparent;
      }}
      
      .domain-chips .badge:hover {{
        transform: translateY(-1px);
      }}
    </style>
    """
    
    # JavaScript for quiz functionality
    body += f"""
    <script>
      let currentQuiz = {q_json};
      let currentDomain = 'random';
      let userAnswers = {{}};
      
      function escapeHtml(text) {{
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
      }}
      
      function renderQuiz() {{
        const container = document.getElementById('quizQuestions');
        const questions = currentQuiz.questions || [];
        
        container.innerHTML = questions.map((q, i) => `
          <div class="card mb-4 border-0 shadow-sm quiz-question">
            <div class="card-body p-4">
              <div class="d-flex justify-content-between align-items-start mb-3">
                <h6 class="text-primary mb-0">Question ${{i + 1}} of ${{questions.length}}</h6>
                <span class="badge bg-light text-dark">${{q.domain.replace('-', ' ').replace(/\\b\\w/g, l => l.toUpperCase())}}</span>
              </div>
              <p class="fw-semibold mb-4">${{escapeHtml(q.question)}}</p>
              <div class="row">
                ${{Object.entries(q.options).map(([letter, text]) => `
                  <div class="col-12 mb-2">
                    <div class="form-check p-3 border rounded-3 option-card">
                      <input class="form-check-input" type="radio" name="q${{i}}" value="${{letter}}" id="q${{i}}${{letter}}">
                      <label class="form-check-label w-100 cursor-pointer" for="q${{i}}${{letter}}">
                        <strong>${{letter}})</strong> ${{escapeHtml(text)}}
                      </label>
                    </div>
                  </div>
                `).join('')}}
              </div>
            </div>
          </div>
        `).join('');
        
        document.getElementById('submitQuiz').style.display = questions.length > 0 ? 'block' : 'none';
        
        // Add event listeners for answer selection
        container.querySelectorAll('input[type="radio"]').forEach(input => {{
          input.addEventListener('change', function() {{
            const questionIndex = this.name.replace('q', '');
            userAnswers[questionIndex] = this.value;
            
            // Visual feedback
            const card = this.closest('.option-card');
            card.parentElement.parentElement.querySelectorAll('.option-card').forEach(c => {{
              c.classList.remove('border-primary', 'bg-primary', 'bg-opacity-10');
            }});
            card.classList.add('border-primary', 'bg-primary', 'bg-opacity-10');
          }});
        }});
      }}
      
      function showResults(data) {{
        const content = document.getElementById('resultsContent');
        const insights = (data.performance_insights || []).join('<br>');
        const detailedResults = data.detailed_results || [];
        
        // Determine performance level and message
        let performanceMsg = "";
        let performanceColor = "";
        if (data.score >= 80) {{
          performanceMsg = "Excellent work! You're showing strong mastery.";
          performanceColor = "success";
        }} else if (data.score >= 70) {{
          performanceMsg = "Good progress! A few more areas to strengthen.";
          performanceColor = "warning";
        }} else {{
          performanceMsg = "Keep studying! Focus on the areas below.";
          performanceColor = "info";
        }}
        
        content.innerHTML = `
          <div class="text-center mb-5">
            <div class="mb-3">
              <i class="bi bi-award text-${{performanceColor}} display-4"></i>
            </div>
            <h2 class="display-4 fw-bold text-${{data.score >= 70 ? 'success' : 'warning'}}">${{data.score}}%</h2>
            <p class="lead mb-3">You got ${{data.correct}} out of ${{data.total}} questions correct</p>
            <div class="alert alert-${{performanceColor}} border-0">
              <strong>${{performanceMsg}}</strong><br>
              ${{insights}}
            </div>
          </div>
          
          <h5 class="mb-4">Detailed Review</h5>
          <div style="max-height: 400px; overflow-y: auto;">
            ${{detailedResults.map((result) => `
              <div class="card mb-3 border-0 shadow-sm ${{result.is_correct ? 'border-start border-success border-4' : 'border-start border-danger border-4'}}">
                <div class="card-body">
                  <div class="d-flex justify-content-between align-items-start mb-2">
                    <strong>Question ${{result.index}}</strong>
                    <span class="badge bg-${{result.is_correct ? 'success' : 'danger'}}">
                      <i class="bi bi-${{result.is_correct ? 'check' : 'x'}}-circle me-1"></i>
                      ${{result.is_correct ? 'Correct' : 'Incorrect'}}
                    </span>
                  </div>
                  <p class="mb-3">${{escapeHtml(result.question)}}</p>
                  <div class="row g-3">
                    <div class="col-md-6">
                      <div class="p-2 rounded-3 bg-light">
                        <small class="text-muted d-block">Your answer:</small>
                        <strong>${{result.user_letter || 'None'}})</strong> ${{escapeHtml(result.user_text || 'No answer selected')}}
                      </div>
                    </div>
                    <div class="col-md-6">
                      <div class="p-2 rounded-3 bg-success bg-opacity-10">
                        <small class="text-muted d-block">Correct answer:</small>
                        <strong>${{result.correct_letter}})</strong> ${{escapeHtml(result.correct_text)}}
                      </div>
                    </div>
                  </div>
                  ${{result.explanation ? `
                    <div class="mt-3 p-3 bg-info bg-opacity-10 rounded-3">
                      <small class="text-muted d-block mb-1">Explanation:</small>
                      ${{escapeHtml(result.explanation)}}
                    </div>
                  ` : ''}}
                </div>
              </div>
            `).join('')}}
          </div>
        `;
        
        new bootstrap.Modal(document.getElementById('resultsModal')).show();
      }}
      
      function buildQuiz() {{
        const count = parseInt(document.getElementById('questionCount').value);
        const buildBtn = document.getElementById('buildQuiz');
        buildBtn.disabled = true;
        buildBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>Building...';
        
        fetch('/api/build-quiz', {{
          method: 'POST',
          headers: {{
            'Content-Type': 'application/json',
            'X-CSRFToken': document.querySelector('meta[name=csrf-token]').getAttribute('content')
          }},
          body: JSON.stringify({{domain: currentDomain, count}})
        }})
        .then(r => r.json())
        .then(data => {{
          currentQuiz = data;
          userAnswers = {{}};
          const domainName = currentDomain === 'random' ? 'All Topics' : 
                           currentDomain.replace('-', ' ').replace(/\\b\\w/g, l => l.toUpperCase());
          document.getElementById('quizInfo').textContent = `${{count}} questions • Domain: ${{domainName}}`;
          renderQuiz();
        }})
        .finally(() => {{
          buildBtn.disabled = false;
          buildBtn.innerHTML = '<i class="bi bi-arrow-clockwise me-1"></i>New Quiz';
        }});
      }}

      function submitQuiz() {{
        const questions = currentQuiz.questions || [];
        const unanswered = questions.length - Object.keys(userAnswers).length;
        
        if (unanswered > 0) {{
          const proceed = confirm(`You have ${{unanswered}} unanswered question${{unanswered > 1 ? 's' : ''}}. Submit anyway?`);
          if (!proceed) return;
        }}
        
        const submitBtn = document.getElementById('submitQuiz');
        submitBtn.disabled = true;
        submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Submitting...';
        
        fetch('/api/submit-quiz', {{
          method: 'POST',
          headers: {{
            'Content-Type': 'application/json',
            'X-CSRFToken': document.querySelector('meta[name=csrf-token]').getAttribute('content')
          }},
          body: JSON.stringify({{
            quiz_type: 'practice',
            domain: currentDomain,
            questions: questions,
            answers: userAnswers
          }})
        }})
        .then(r => r.json())
        .then(data => {{
          if (data.success) {{
            showResults(data);
          }} else {{
            alert(data.error || 'Submission failed. Please try again.');
          }}
        }})
        .finally(() => {{
          submitBtn.disabled = false;
          submitBtn.innerHTML = '<i class="bi bi-check-circle me-2"></i>Submit Quiz';
        }});
      }}
      
      // Domain selection
      document.querySelectorAll('.domain-chip').forEach(chip => {{
        chip.addEventListener('click', function() {{
          document.querySelectorAll('.domain-chip').forEach(c => {{
            c.classList.remove('bg-success');
            if (c.dataset.domain === 'random') {{
              c.classList.remove('bg-primary');
              c.classList.add('bg-secondary');
            }} else {{
              c.classList.remove('bg-secondary');
              c.classList.add('bg-primary');
            }}
          }});
          
          if (this.dataset.domain === 'random') {{
            this.classList.remove('bg-secondary');
            this.classList.add('bg-success');
          }} else {{
            this.classList.remove('bg-primary');
            this.classList.add('bg-success');
          }}
          
          currentDomain = this.dataset.domain;
        }});
      }});
      
      // Event listeners
      document.getElementById('buildQuiz').addEventListener('click', buildQuiz);
      document.getElementById('submitQuiz').addEventListener('click', submitQuiz);
      
      // Initialize
      renderQuiz();
    </script>
    """
    return base_layout("Practice Quiz", body)

