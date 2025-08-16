scores.append({
            'score': score,
            'date': datetime.utcnow().isoformat(),
            'type': quiz_type,
            'domain': domain,
            'time_taken': time_taken
        })
        user.quiz_scores = json.dumps(scores[-50:])  # Keep last 50 scores
        db.session.commit()

        # Enhanced performance insights
        insights = []
        if score >= 90:
            insights.append("🎯 Excellent! You're demonstrating mastery of this material.")
        elif score >= 80:
            insights.append("✅ Good job! Review the explanations below to strengthen weak areas.")
        elif score >= 70:
            insights.append("📚 Fair performance. Focus study time on the missed concepts.")
        else:
            insights.append("⚠️ Consider more focused study before attempting the real exam.")
        
        # Time feedback
        if time_taken > 0 and total > 0:
            avg_per_q = time_taken / total
            if avg_per_q < 1:
                insights.append("⚡ Great pace! You answered efficiently.")
            elif avg_per_q > 3:
                insights.append("🐌 Consider practicing to improve your speed.")
        
        # Domain-specific insights
        wrong_count = total - correct_count
        if wrong_count > 0:
            insights.append("📖 Review the {} explanations below to improve your understanding.".format(wrong_count))

        log_activity(session['user_id'], 'quiz_completed',
                     '{}: {}/{} in {} min'.format(quiz_type, correct_count, total, time_taken))

        return jsonify({
            'success': True,
            'score': round(score, 1),
            'correct': correct_count,
            'total': total,
            'time_taken': time_taken,
            'performance_insights': insights,
            'detailed_results': detailed_results
        })
    except Exception as e:
        print("Submit quiz error: {}".format(e))
        db.session.rollback()
        return jsonify({'error': 'Error processing quiz results.'}), 500

# ----------------------------- Enhanced Mock Exam -----------------------------
@app.route('/mock-exam')
@subscription_required
def mock_exam():
    user = User.query.get(session['user_id'])
    requested = request.args.get('count')
    count = None
    if requested:
        try:
            count = int(requested)
        except Exception:
            count = None

    if not count or count not in [25, 50, 75, 100]:
        # Enhanced selection UI
        content = """
        <div class="row">
          <div class="col-md-10 mx-auto">
            <div class="card border-0 shadow">
              <div class="card-header bg-warning text-dark">
                <h4 class="mb-0">🏁 Mock Exam</h4>
                <p class="mb-0 small">Simulate the real CPP exam experience</p>
              </div>
              <div class="card-body">
                <div class="alert alert-info border-0 mb-4">
                  <h6 class="mb-2">📋 Exam Format</h6>
                  <ul class="mb-0 small">
                    <li><strong>Random questions</strong> across all CPP domains</li>
                    <li><strong>All questions required</strong> before submission</li>
                    <li><strong>Detailed feedback</strong> provided after completion</li>
                    <li><strong>Target score:</strong> 80%+ demonstrates exam readiness</li>
                  </ul>
                </div>
                
                <h5 class="mb-3">Choose Your Exam Length:</h5>
                <div class="row g-3">
                  <div class="col-md-6 col-lg-3">
                    <div class="card h-100 border-primary hover-card">
                      <div class="card-body text-center">
                        <h5 class="card-title text-primary">25 Questions</h5>
                        <p class="card-text small text-muted">Quick assessment<br>~25-30 minutes</p>
                        <a class="btn btn-primary btn-enhanced" href="/mock-exam?count=25">Start 25Q Exam</a>
                      </div>
                    </div>
                  </div>
                  <div class="col-md-6 col-lg-3">
                    <div class="card h-100 border-success hover-card">
                      <div class="card-body text-center">
                        <h5 class="card-title text-success">50 Questions</h5>
                        <p class="card-text small text-muted">Comprehensive test<br>~50-60 minutes</p>
                        <a class="btn btn-success btn-enhanced" href="/mock-exam?count=50">Start 50Q Exam</a>
                      </div>
                    </div>
                  </div>
                  <div class="col-md-6 col-lg-3">
                    <div class="card h-100 border-warning hover-card">
                      <div class="card-body text-center">
                        <h5 class="card-title text-warning">75 Questions</h5>
                        <p class="card-text small text-muted">Extended practice<br>~75-90 minutes</p>
                        <a class="btn btn-warning btn-enhanced" href="/mock-exam?count=75">Start 75Q Exam</a>
                      </div>
                    </div>
                  </div>
                  <div class="col-md-6 col-lg-3">
                    <div class="card h-100 border-danger hover-card">
                      <div class="card-body text-center">
                        <h5 class="card-title text-danger">100 Questions</h5>
                        <p class="card-text small text-muted">Full simulation<br>~100-120 minutes</p>
                        <a class="btn btn-danger btn-enhanced" href="/mock-exam?count=100">Start 100Q Exam</a>
                      </div>
                    </div>
                  </div>
                </div>
                
                <div class="mt-4 text-center">
                  <small class="text-muted">💡 <strong>Tip:</strong> Start with 25-50 questions to gauge your readiness, then work up to 100 questions for full exam simulation.</small>
                </div>
              </div>
            </div>
          </div>
        </div>
        
        <style>
        .hover-card {
          transition: transform 0.2s ease, box-shadow 0.2s ease;
        }
        .hover-card:hover {
          transform: translateY(-4px);
          box-shadow: 0 8px 25px rgba(0,0,0,0.15);
        }
        </style>
        """
        return render_base_template("Mock Exam", content, user=user)

    # Create exam
    num_questions = max(25, min(100, count))
    session['quiz_start_time'] = datetime.utcnow().timestamp()
    quiz_data = generate_fallback_quiz('mock-exam', domain='general', difficulty='medium', num_questions=num_questions)
    quiz_json = json.dumps(quiz_data)

    # Enhanced exam interface with progress tracking
    page = Template("""
    <div class="row">
      <div class="col-md-11 mx-auto">
        <!-- Enhanced Progress Header -->
        <div class="card border-0 shadow-sm mb-3">
          <div class="card-body py-3">
            <div class="d-flex justify-content-between align-items-center">
              <div>
                <h5 class="mb-1">🏁 Mock Exam ($num Questions)</h5>
                <small class="text-muted">Answer all questions before submitting</small>
              </div>
              <div class="text-end">
                <div class="badge bg-secondary fs-6 mb-1">
                  <span id="answeredCount">0</span> / $num answered
                </div>
                <div>
                  <button id="submitBtnTop" class="btn btn-success btn-sm btn-enhanced" disabled>Submit Exam</button>
                </div>
              </div>
            </div>
            <!-- Enhanced Progress bar -->
            <div class="progress mt-2" style="height: 6px;">
              <div id="progressBar" class="progress-bar bg-gradient" role="progressbar" style="width: 0%; background: linear-gradient(90deg, #ffc107 0%, #28a745 100%);"></div>
            </div>
          </div>
        </div>

        <!-- Questions Container -->
        <div class="card border-0 shadow">
          <div class="card-body" id="quizContainer"></div>
          <div class="card-footer d-flex justify-content-between align-items-center bg-light">
            <div class="text-muted">
              <strong>Progress:</strong> <span id="answeredCountBottom">0</span> of $num questions answered
            </div>
            <button id="submitBtnBottom" class="btn btn-success btn-lg btn-enhanced" disabled>Submit Exam</button>
          </div>
        </div>
        
        <!-- Results Container -->
        <div class="mt-4" id="results"></div>
      </div>
    </div>
    
    <script>
      const QUIZ_DATA = $quiz_json;
      let answeredCount = 0;

      function updateProgress() {
        const total = (QUIZ_DATA.questions || []).length;
        answeredCount = 0;
        
        // Count answered questions
        for (let i = 0; i < total; i++) {
          const selected = document.querySelector('input[name="q' + i + '"]:checked');
          if (selected) answeredCount++;
        }
        
        // Update UI elements
        document.getElementById('answeredCount').textContent = answeredCount;
        document.getElementById('answeredCountBottom').textContent = answeredCount;
        
        const progress = (answeredCount / total) * 100;
        document.getElementById('progressBar').style.width = progress + '%';
        
        // Enable/disable submit buttons based on completion
        const canSubmit = (answeredCount === total);
        document.getElementById('submitBtnTop').disabled = !canSubmit;
        document.getElementById('submitBtnBottom').disabled = !canSubmit;
        
        if (canSubmit) {
          document.getElementById('submitBtnTop').classList.remove('btn-secondary');
          document.getElementById('submitBtnTop').classList.add('btn-success');
          document.getElementById('submitBtnBottom').classList.remove('btn-secondary');
          document.getElementById('submitBtnBottom').classList.add('btn-success');
          document.getElementById('submitBtnTop').innerHTML = '✅ Submit Exam';
          document.getElementById('submitBtnBottom').innerHTML = '✅ Submit Exam';
        } else {
          document.getElementById('submitBtnTop').innerHTML = '⏳ Submit (' + (total - answeredCount) + ' remaining)';
          document.getElementById('submitBtnBottom').innerHTML = '⏳ Submit (' + (total - answeredCount) + ' remaining)';
        }
      }

      function renderQuiz() {
        const container = document.getElementById('quizContainer');
        container.innerHTML = '';
        
        (QUIZ_DATA.questions || []).forEach((q, idx) => {
          const card = document.createElement('div');
          card.className = 'mb-4 p-4 border rounded-3 shadow-sm';
          card.id = 'question-' + idx;
          card.style.transition = 'border-color 0.3s ease, background-color 0.3s ease';
          
          const title = document.createElement('h6');
          title.className = 'fw-bold mb-3 text-primary';
          title.innerHTML = '📝 Question ' + (idx + 1) + ' of ' + QUIZ_DATA.questions.length;
          card.appendChild(title);
          
          const questionText = document.createElement('p');
          questionText.className = 'mb-3 fs-6 lh-base';
          questionText.textContent = q.question;
          card.appendChild(questionText);

          const options = q.options || {};
          for (const key in options) {
            const optId = 'q' + idx + '_' + key;
            const div = document.createElement('div');
            div.className = 'form-check mb-2 p-2 rounded';
            div.style.transition = 'background-color 0.2s ease';
            
            const input = document.createElement('input');
            input.className = 'form-check-input';
            input.type = 'radio';
            input.name = 'q' + idx;
            input.id = optId;
            input.value = key;
            input.addEventListener('change', updateProgress);
            
            const label = document.createElement('label');
            label.className = 'form-check-label w-100 cursor-pointer';
            label.htmlFor = optId;
            label.textContent = key + ') ' + options[key];
            
            // Enhanced hover effects
            div.addEventListener('mouseenter', () => div.style.backgroundColor = '#f8f9fa');
            div.addEventListener('mouseleave', () => div.style.backgroundColor = 'transparent');
            
            div.appendChild(input);
            div.appendChild(label);
            card.appendChild(div);
          }
          container.appendChild(card);
        });
        
        updateProgress();
      }

      async function submitQuiz() {
        const total = (QUIZ_DATA.questions || []).length;
        const answers = {};
        const unanswered = [];
        
        for (let i = 0; i < total; i++) {
          const selected = document.querySelector('input[name="q' + i + '"]:checked');
          answers[String(i)] = selected ? selected.value : null;
          if (!selected) {
            unanswered.push(i + 1);
          }
        }
        
        if (unanswered.length > 0) {
          // Highlight unanswered questions
          unanswered.forEach(qNum => {
            const card = document.getElementById('question-' + (qNum - 1));
            if (card) {
              card.style.borderColor = '#dc3545';
              card.style.borderWidth = '2px';
              card.style.backgroundColor = '#fff5f5';
            }
          });
          alert('⚠️ Please answer all questions before submitting.\\n\\nMissing: Q' + unanswered.join(', Q'));
          // Scroll to first unanswered
          const firstUnanswered = document.getElementById('question-' + (unanswered[0] - 1));
          if (firstUnanswered) {
            firstUnanswered.scrollIntoView({ behavior: 'smooth', block: 'center' });
          }
          return;
        }
        
        // Disable buttons during submission
        document.getElementById('submitBtnTop').disabled = true;
        document.getElementById('submitBtnBottom').disabled = true;
        document.getElementById('submitBtnTop').innerHTML = '⏳ Processing...';
        document.getElementById('submitBtnBottom').innerHTML = '⏳ Processing...';
        
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
            resultsDiv.innerHTML = '<div class="alert alert-danger border-0"><strong>❌ Error:</strong> ' + data.error + '</div>';
            return;
          }

          // Enhanced mock exam results display
          let html = '<div class="card border-0 shadow"><div class="card-body">';
          html += '<h3 class="text-center mb-4">🏁 Mock Exam Results</h3>';
          
          // Score dashboard
          html += '<div class="row text-center mb-4">';
          const scoreClass = data.score >= 80 ? 'text-success' : (data.score >= 70 ? 'text-warning' : 'text-danger');
          const readiness = data.score >= 80 ? '✅ Exam Ready' : (data.score >= 70 ? '📚 More Study Needed' : '⚠️ Needs Significant Study');
          
          html += '<div class="col-md-4"><div class="card border-0 bg-light"><div class="card-body">';
          html += '<h4 class="' + scoreClass + '">' + data.score.toFixed(1) + '%</h4>';
          html += '<p class="text-muted mb-0">Overall Score</p>';
          html += '</div></div></div>';
          
          html += '<div class="col-md-4"><div class="card border-0 bg-light"><div class="card-body">';
          html += '<h4 class="text-primary">' + data.correct + '/' + data.total + '</h4>';
          html += '<p class="text-muted mb-0">Questions Correct</p>';
          html += '</div></div></div>';
          
          html += '<div class="col-md-4"><div class="card border-0 bg-light"><div class="card-body">';
          html += '<h4 class="' + scoreClass + '">' + readiness + '</h4>';
          html += '<p class="text-muted mb-0">Exam Readiness</p>';
          html += '</div></div></div>';
          
          html += '</div>';
          
          if (data.time_taken) {
            html += '<div class="text-center mb-3">';
            html += '<p class="text-muted">⏱️ <strong>Time taken:</strong> ' + data.time_taken + ' minutes</p>';
            html += '</div>';
          }
          
          // Performance insights
          if (Array.isArray(data.performance_insights)) {
            html += '<div class="alert alert-info border-0"><h6 class="mb-2">📈 Performance Analysis</h6>';
            html += '<ul class="mb-0">';
            data.performance_insights.forEach(insight => { 
              html += '<li>' + insight + '</li>'; 
            });
            html += '</ul></div>';
          }
          html += '</div></div>';

          // Detailed question review (same as quiz)
          if (Array.isArray(data.detailed_results)) {
            html += '<div class="mt-4">';
            html += '<h5 class="mb-3">📝 Complete Question Review</h5>';
            
            data.detailed_results.forEach((result) => {
              const isCorrect = result.is_correct;
              const cardClass = isCorrect ? 'result-card correct' : 'result-card incorrect';
              const iconClass = isCorrect ? '✅' : '❌';
              
              html += '<div class="card mb-3 ' + cardClass + '">';
              html += '<div class="card-body">';
              
              html += '<h6 class="card-title">' + iconClass + ' Question ' + result.index + '</h6>';
              html += '<p class="card-text mb-3">' + (result.question || 'Question text not available') + '</p>';
              
              if (isCorrect) {
                html += '<div class="alert alert-success border-0 py-2">';
                html += '<strong>✅ Correct!</strong> ';
                html += result.correct_letter + ') ' + (result.correct_text || 'Correct answer');
                html += '</div>';
              } else {
                html += '<div class="alert alert-danger border-0 py-2 mb-2">';
                html += '<strong>❌ Your answer:</strong> ';
                html += (result.user_letter || '—') + (result.user_text ? (') ' + result.user_text) : ' (No answer selected)');
                html += '</div>';
                html += '<div class="alert alert-success border-0 py-2">';
                html += '<strong>✅ Correct answer:</strong> ';
                html += (result.correct_letter || '?') + ') ' + (result.correct_text || 'Correct answer not available');
                html += '</div>';
              }
              
              if (result.explanation) {
                html += '<div class="mt-2 p-3 bg-light rounded">';
                html += '<strong>💡 Explanation:</strong> ' + result.explanation;
                html += '</div>';
              }
              
              if (result.source_name) {
                html += '<div class="mt-2">';
                html += '<small class="text-muted"><strong>📚 Source:</strong> ' + result.source_name;
                if (result.source_url) {
                  html += ' <a href="' + result.source_url + '" target="_blank" rel="noopener" class="text-decoration-none">🔗 View Source</a>';
                }
                html += '</small>';
                html += '</div>';
              }
              
              html += '</div></div>';
            });
            html += '</div>';
          }

          // Action buttons
          html += '<div class="text-center mt-4">';
          html += '<a href="/mock-exam" class="btn btn-warning btn-lg me-3 btn-enhanced">🏁 Take Another Mock Exam</a>';
          html += '<a href="/quiz-selector" class="btn btn-primary btn-lg me-3 btn-enhanced">📝 Practice Quiz</a>';
          html += '<a href="/dashboard" class="btn btn-outline-secondary btn-lg btn-enhanced">🏠 Back to Dashboard</a>';
          html += '</div>';

          resultsDiv.innerHTML = html;
          resultsDiv.scrollIntoView({ behavior: 'smooth', block: 'start' });
          
        } catch (e) {
          console.error('Mock exam submission error:', e);
          document.getElementById('results').innerHTML = 
            '<div class="alert alert-danger border-0"><strong>🌐 Network Error:</strong> Could not submit exam. Please check your connection and try again.</div>';
        }
      }

      document.getElementById('submitBtnTop').addEventListener('click', submitQuiz);
      document.getElementById('submitBtnBottom').addEventListener('click', submitQuiz);
      
      renderQuiz();
    </script>
    """)
    
    content = page.substitute(num=num_questions, quiz_json=quiz_json)
    return render_base_template("Mock Exam", content, user=user)

# ----------------------------- Enhanced Progress ------------------------------
@app.route('/progress')
@subscription_required
def progress_page():
    user = User.query.get(session['user_id'])
    rows = UserProgress.query.filter_by(user_id=user.id, topic=None).all()

    def color_for(level: str) -> str:
        if level == 'mastered':
            return 'bg-success text-white'
        if level == 'good':
            return 'bg-warning text-dark'
        return 'bg-danger text-white'

    tr_html = []
    strengths = []
    improvements = []
    
    for r in rows:
        dmeta = CPP_DOMAINS.get(r.domain, {})
        dname = dmeta.get('name', r.domain)
        pct = int(round(r.average_score or 0))
        level = r.mastery_level or 'needs_practice'
        bar_class = 'bg-success' if level == 'mastered' else ('bg-warning' if level == 'good' else 'bg-danger')
        
        # Collect for insights
        if pct >= 85:
            strengths.append(dname)
        elif pct < 70:
            improvements.append(dname)
            
        tr_html.append(
            '<tr>'
            '<td><strong>{}</strong></td>'.format(dname) +
            '<td><div class="progress" style="height: 20px;"><div class="progress-bar {} text-dark fw-bold" role="progressbar" style="width: {}%;" aria-valuenow="{}" aria-valuemin="0" aria-valuemax="100">{}%</div></div></td>'.format(bar_class, pct, pct, pct) +
            '<td><span class="badge {}">{}</span></td>'.format(color_for(level), level.replace("_"," ").title()) +
            '<td class="text-center">{}</td>'.format(r.question_count or 0) +
            '<td class="text-center">{}</td>'.format((r.last_updated or datetime.utcnow()).strftime("%m/%d/%y")) +
            '</tr>'
        )

    overall_pct = 0
    if rows:
        overall_pct = int(round(sum([(p.average_score or 0.0) for p in rows]) / len(rows)))

    # Performance summary
    summary_html = ""
    if strengths:
        summary_html += '<div class="alert alert-success border-0"><strong>🎯 Strong Areas:</strong> {}</div>'.format(", ".join(strengths))
    if improvements:
        summary_html += '<div class="alert alert-warning border-0"><strong>📚 Focus Areas:</strong> {}</div>'.format(", ".join(improvements))
    if not strengths and not improvements:
        summary_html += '<div class="alert alert-info border-0"><strong>🚀 Getting Started:</strong> Take some quizzes to see your progress across domains!</div>'

    content = Template("""
    <div class="row">
      <div class="col-md-8">
        <div class="card border-0 shadow">
          <div class="card-header bg-primary text-white">
            <h4 class="mb-0">📊 Progress by Domain</h4>
          </div>
          <div class="card-body">
            <div class="table-responsive">
              <table class="table align-middle mb-0">
                <thead class="table-light">
                  <tr>
                    <th>Domain</th>
                    <th width="35%">Average Score</th>
                    <th>Level</th>
                    <th class="text-center">Questions</th>
                    <th class="text-center">Updated</th>
                  </tr>
                </thead>
                <tbody>$rows</tbody>
              </table>
            </div>
            <div class="mt-3 small text-muted text-center">
              🟢 <strong>Mastered:</strong> 90%+ avg, 3+ good streaks | 
              🟡 <strong>Good:</strong> 75%+ avg, 2+ streaks | 
              🔴 <strong>Needs Practice:</strong> Below thresholds
            </div>
          </div>
        </div>
        
        <div class="mt-4">
          $summary
        </div>
      </div>
      
      <div class="col-md-4">
        <div class="card border-0 shadow h-100">
          <div class="card-header bg-success text-white text-center">
            <h5 class="mb-0">🎯 Overall Progress</h5>
          </div>
          <div class="card-body d-flex flex-column align-items-center justify-content-center">
            <div class="gauge-wrap mb-3" style="--p:$overall%;">
              <span>$overall%</span>
            </div>
            <div class="text-center">
              <h6 class="text-muted">Goal: 80%+ Across All Domains</h6>
              <div class="mt-3">
                <div class="small mb-2">
                  <strong>Progress Breakdown:</strong>
                </div>
                <div class="small">
                  🎯 Target: 80%+ (Exam Ready)<br>
                  📚 Current: $overall%<br>
                  💪 Keep practicing consistently!
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
    """)
    
    rows_content = ''.join(tr_html) if tr_html else '<tr><td colspan="5" class="text-muted text-center py-4">🎯 No progress data yet.<br><small>Take some quizzes to see your domain progress!</small></td></tr>'
    
    return render_base_template("Progress", content.substitute(
        rows=rows_content,
        summary=summary_html,
        overall=overall_pct
    ), user=user)

# ----------------------------- Subscription & Stripe --------------------------
@app.route('/subscribe')
@login_required
def subscribe():
    user = User.query.get(session['user_id'])
    trial_days_left = None
    if user and user.subscription_status == 'trial' and user.subscription_end_date:
        trial_days_left = max((user.subscription_end_date - datetime.utcnow()).days, 0)

    plans_html = """
    <div class="row g-4">
      <div class="col-md-6">
        <div class="card h-100 border-primary shadow">
          <div class="card-body text-center">
            <h4 class="text-primary">💳 Monthly Plan</h4>
            <div class="display-6 text-primary mb-3">$39.99<small class="fs-6 text-muted">/month</small></div>
            <ul class="list-unstyled mb-4">
              <li>✅ Unlimited AI tutor access</li>
              <li>✅ All quiz types & domains</li>
              <li>✅ Progress tracking</li>
              <li>✅ Mock exams</li>
            </ul>
            <form method="POST" action="/create-checkout-session">
              <input type="hidden" name="plan_type" value="monthly" />
              <div class="mb-3">
                <input type="text" class="form-control" name="discount_code" placeholder="Discount code (optional)">
              </div>
              <button class="btn btn-primary btn-lg btn-enhanced w-100">Choose Monthly</button>
            </form>
          </div>
        </div>
      </div>
      <div class="col-md-6">
        <div class="card h-100 border-success shadow position-relative">
          <div class="position-absolute top-0 start-50 translate-middle">
            <span class="badge bg-success fs-6 px-3 py-2">💰 Best Value</span>
          </div>
          <div class="card-body text-center pt-4">
            <h4 class="text-success">🎯 6-Month Plan</h4>
            <div class="display-6 text-success mb-3">$99<small class="fs-6 text-muted">/6 months</small></div>
            <div class="small text-success mb-3"><strong>Save $140!</strong> Only $16.50/month</div>
            <ul class="list-unstyled mb-4">
              <li>✅ Everything in Monthly</li>
              <li>✅ Extended study period</li>
              <li>✅ Better value per month</li>
              <li>✅ Ideal for exam prep timeline</li>
            </ul>
            <form method="POST" action="/create-checkout-session">
              <input type="hidden" name="plan_type" value="6month" />
              <div class="mb-3">
                <input type="text" class="form-control" name="discount_code" placeholder="Discount code (optional)">
              </div>
              <button class="btn btn-success btn-lg btn-enhanced w-100">Choose 6 Months</button>
            </form>
          </div>
        </div>
      </div>
    </div>
    """
    
    header = ""
    if trial_days_left is not None:
        if trial_days_left > 0:
            header = '<div class="alert alert-info border-0 mb-4">⏰ <strong>Trial Status:</strong> {} days remaining in your free trial</div>'.format(trial_days_left)
        else:
            header = '<div class="alert alert-warning border-0 mb-4">⚠️ <strong>Trial Expired:</strong> Please choose a plan to continue studying</div>'

    content = """
    <div class="row">
      <div class="col-md-10 mx-auto">
        <div class="text-center mb-5">
          <h2>🚀 Choose Your Study Plan</h2>
          <p class="lead text-muted">Unlock full access to AI tutoring, unlimited quizzes, and progress tracking</p>
        </div>
        {}
        {}
        <div class="text-center mt-4">
          <small class="text-muted">
            💡 <strong>Discount codes:</strong> LAUNCH50 (50% off) • STUDENT20 (20% off)<br>
            🔒 Secure payment powered by Stripe • Cancel anytime
          </small>
        </div>
      </div>
    </div>
    """.format(header, plans_html)
    return render_base_template("Subscribe", content, user=user)

@app.route('/create-checkout-session', methods=['POST'])
@login_required
def create_checkout_session():
    try:
        user = User.query.get(session['user_id'])
        plan_type = request.form.get('plan_type')
        discount_code = (request.form.get('discount_code') or '').strip().upper()

        plans = {
            'monthly': {'amount': 3999, 'name': 'CPP Test Prep - Monthly Plan', 'interval': 'month', 'interval_count': 1},
            '6month': {'amount': 9900, 'name': 'CPP Test Prep - 6 Month Plan', 'interval': 'month', 'interval_count': 6}
        }
        if plan_type not in plans:
            flash('Invalid plan selected.', 'danger')
            return redirect(url_for('subscribe'))

        selected = plans[plan_type]
        final_amount = selected['amount']
        discount_applied = False
        if discount_code == 'LAUNCH50':
            final_amount = int(selected['amount'] * 0.5)
            discount_applied = True
        elif discount_code == 'STUDENT20':
            final_amount = int(selected['amount'] * 0.8)
            discount_applied = True

        price = stripe.Price.create(
            unit_amount=final_amount,
            currency='usd',
            recurring={'interval': selected['interval'], 'interval_count': selected['interval_count']},
            product_data={
                'name': selected['name'] + (' ({} DISCOUNT)'.format(discount_code) if discount_applied else ''),
                'description': 'AI tutor, unlimited quizzes, and comprehensive study tools for CPP exam preparation'
            }
        )

        checkout_session = stripe.checkout.Session.create(
            customer=user.stripe_customer_id,
            payment_method_types=['card'],
            line_items=[{'price': price.id, 'quantity': 1}],
            mode='subscription',
            success_url=url_for('subscription_success', _external=True) + '?session_id={{CHECKOUT_SESSION_ID}}&plan={}'.format(plan_type),
            cancel_url=url_for('subscribe', _external=True),
            metadata={
                'user_id': user.id,
                'plan_type': plan_type,
                'discount_code': discount_code if discount_applied else '',
                'original_amount': selected['amount'],
                'final_amount': final_amount
            },
            allow_promotion_codes=True
        )

        log_activity(user.id, 'subscription_attempt', 'Plan: {}, Discount: {}, Amount: ${:.2f}'.format(plan_type, discount_code, final_amount/100))
        return redirect(checkout_session.url, code=303)
    except Exception as e:
        print("Checkout session error: {}".format(e))
        flash('Error creating payment session. Please try again.', 'danger')
        return redirect(url_for('subscribe'))

@app.route('/subscription-success')
@login_required
def subscription_success():
    session_id = request.args.get('session_id')
    plan_type = request.args.get('plan', 'monthly')
    if session_id:
        try:
            cs = stripe.checkout.Session.retrieve(session_id)
            if cs.payment_status == 'paid':
                user = User.query.get(session['user_id'])
                user.subscription_status = 'active'
                user.subscription_plan = plan_type
                user.stripe_subscription_id = cs.subscription
                # Set user-facing end date for dashboard countdown
                if plan_type == '6month':
                    user.subscription_end_date = datetime.utcnow() + timedelta(days=180)
                else:
                    user.subscription_end_date = datetime.utcnow() + timedelta(days=30)
                meta = cs.metadata or {}
                if meta.get('discount_code'):
                    user.discount_code_used = meta['discount_code']
                db.session.commit()
                log_activity(user.id, 'subscription_activated', 'Plan: {}'.format(plan_type))
                flash('🎉 Subscription activated successfully! Welcome to CPP Test Prep!', 'success')
            else:
                flash('⚠️ Payment verification failed. Please contact support.', 'danger')
        except Exception as e:
            print("Subscription verification error: {}".format(e))
            flash('❌ Subscription verification error. Please contact support.', 'danger')
    return redirect(url_for('dashboard'))

@app.post("/webhook")
def stripe_webhook():
    if not STRIPE_WEBHOOK_SECRET:
        print("Webhook secret not configured")
        return 'Webhook not configured', 200

    payload = request.get_data(as_text=True)
    sig_header = request.headers.get('Stripe-Signature')
    try:
        event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
    except ValueError as e:
        print("Invalid payload: {}".format(e))
        return 'Invalid payload', 400
    except stripe.error.SignatureVerificationError as e:
        print("Invalid signature: {}".format(e))
        return 'Invalid signature', 400

    event_type = event.get('type')
    data_object = event.get('data', {}).get('object', {})
    customer_id = data_object.get('customer')
    subscription_id = data_object.get('subscription') or data_object.get('id')

    def set_user_subscription_by_customer(customer_id, status, subscription_id=None):
        if not customer_id:
            return
        try:
            user = User.query.filter_by(stripe_customer_id=customer_id).first()
            if not user:
                print("No user found for Stripe customer: {}".format(customer_id))
                return
            user.subscription_status = status
            if subscription_id:
                user.stripe_subscription_id = subscription_id
            if status == 'active' and not user.subscription_end_date:
                user.subscription_end_date = datetime.utcnow() + timedelta(days=30)
            elif status in ('canceled', 'expired'):
                user.subscription_status = 'expired'
            db.session.commit()
            log_activity(user.id, 'subscription_status_update', 'status={}'.format(status))
        except Exception as e:
            print("Error updating subscription: {}".format(e))
            db.session.rollback()

    try:
        if event_type == 'invoice.payment_succeeded':
            set_user_subscription_by_customer(customer_id, 'active', subscription_id)
        elif event_type == 'invoice.payment_failed':
            set_user_subscription_by_customer(customer_id, 'past_due', subscription_id)
        elif event_type in ('customer.subscription.created', 'customer.subscription.updated'):
            status = data_object.get('status', 'active')
            normalized = 'active' if status in ('active', 'trialing') else ('past_due' if status == 'past_due' else 'expired')
            set_user_subscription_by_customer(customer_id, normalized, subscription_id)
        elif event_type == 'customer.subscription.deleted':
            set_user_subscription_by_customer(customer_id, 'expired', subscription_id)
    except Exception as e:
        print("Webhook processing error for {}: {}".format(event_type, e))
        return 'Webhook processing error', 500

    return 'Success', 200

# ----------------------------- Study Session Tracking -------------------------
@app.route('/end-study-session', methods=['POST'])
@login_required
def end_study_session():
    try:
        if 'study_start_time' in session:
            start_time = datetime.fromtimestamp(session['study_start_time'])
            duration = int((datetime.utcnow() - start_time).total_seconds() / 60)
            db.session.add(StudySession(
                user_id=session['user_id'],
                duration=duration,
                session_type='chat',
                started_at=start_time,
                ended_at=datetime.utcnow()
            ))
            user = User.query.get(session['user_id'])
            if user:
                user.study_time = (user.study_time or 0) + duration
            db.session.commit()
            session.pop('study_start_time', None)
            log_activity(session['user_id'], 'study_session_completed', 'Duration: {} minutes'.format(duration))
            return jsonify({'success': True, 'duration': duration})
        return jsonify({'success': False, 'error': 'No active session'})
    except Exception as e:
        print("Error ending study session: {}".format(e))
        db.session.rollback()
        return jsonify({'success': False, 'error': 'Session end error'})

# --------------------------------- Diagnostics --------------------------------
@app.get("/diag/openai")
def diag_openai():
    has_key = bool(os.environ.get("OPENAI_API_KEY"))
    model = os.environ.get("OPENAI_CHAT_MODEL", OPENAI_CHAT_MODEL)
    try:
        headers = {
            'Authorization': 'Bearer {}'.format(os.environ.get("OPENAI_API_KEY","")),
            'Content-Type': 'application/json'
        }
        data = {
            'model': model,
            'messages': [{"role": "user", "content": "Say 'pong' if you can hear me."}],
            'max_tokens': 10,
            'temperature': 0
        }
        response = requests.post('{}/chat/completions'.format(OPENAI_API_BASE), headers=headers, json=data, timeout=20)
        success = (response.status_code == 200)
        return jsonify({
            "has_key": has_key,
            "model": model,
            "status_code": response.status_code,
            "success": success,
            "response_preview": response.text[:300],
            "timestamp": datetime.utcnow().isoformat()
        }), (200 if success else 500)
    except Exception as e:
        return jsonify({
            "has_key": has_key,
            "model": model,
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }), 500

@app.get("/diag/database")
def diag_database():
    try:
        db.session.execute(text('SELECT 1'))
        user_count = db.session.query(User).count()
        quiz_count = db.session.query(QuizResult).count()
        return jsonify({
            "status": "healthy",
            "user_count": user_count,
            "quiz_count": quiz_count,
            "timestamp": datetime.utcnow().isoformat()
        }), 200
    except Exception as e:
        return jsonify({
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }), 500

# ----------------------------- Error Handlers --------------------------------
@app.errorhandler(404)
def not_found(error):
    content = """
    <div class="row">
      <div class="col-md-6 mx-auto text-center">
        <div class="card border-0 shadow">
          <div class="card-body py-5">
            <h1 class="display-1 text-muted">404</h1>
            <h4 class="mb-3">Page Not Found</h4>
            <p class="text-muted mb-4">The page you're looking for doesn't exist or has been moved.</p>
            <a href="/dashboard" class="btn btn-primary btn-lg btn-enhanced">🏠 Go to Dashboard</a>
          </div>
        </div>
      </div>
    </div>
    """
    return render_base_template("Page Not Found", content), 404

@app.errorhandler(500)
def server_error(error):
    content = """
    <div class="row">
      <div class="col-md-6 mx-auto text-center">
        <div class="card border-0 shadow">
          <div class="card-body py-5">
            <h1 class="display-1 text-muted">500</h1>
            <h4 class="mb-3">Server Error</h4>
            <p class="text-muted mb-4">Something went wrong on our end. Please try again in a moment.</p>
            <a href="/dashboard" class="btn btn-primary btn-lg btn-enhanced">🏠 Go to Dashboard</a>
          </div>
        </div>
      </div>
    </div>
    """
    return render_base_template("Server Error", content), 500

# ----------------------------- App Factory / Run ------------------------------
def create_app(config_name='default'):
    return app

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    print("Starting Enhanced CPP Test Prep on port {}".format(port))
    print("Debug: {}".format(debug))
    print("DB configured: {}".format(bool(app.config.get('SQLALCHEMY_DATABASE_URI'))))
    print("OpenAI configured: {}".format(bool(OPENAI_API_KEY)))
    print("Stripe configured: {}".format(bool(stripe.api_key)))
    app.run(host='0.0.0.0', port=port, debug=debug)        ch.messages = json.dumps(messages)
        ch.updated_at = datetime.utcnow()
        db.session.commit()

        log_activity(user_id, 'chat_message', f'Asked: {user_message[:50]}...')
        return jsonify({'response': ai_response, 'timestamp': datetime.utcnow().isoformat()})
    except Exception as e:
        print(f"Chat error: {e}")
        return jsonify({'error': 'Sorry, I encountered an error processing your message.'}), 500

# --------------------------------- Flashcards ---------------------------------
@app.route('/flashcards')
@subscription_required
def flashcards_page():
    user = User.query.get(session['user_id'])
    # Domain sidebar with enhanced styling
    chips = ['<div class="domain-chip active" data-domain="random">🎲 Random (All Domains)</div>'] + [
        '<div class="domain-chip" data-domain="{}">{}</div>'.format(k, v["name"])
        for k, v in CPP_DOMAINS.items()
    ]
    chips_html = ''.join(chips)

    content = Template("""
    <div class="row">
      <div class="col-md-3">
        <div class="card mb-3 border-0 shadow-sm">
          <div class="card-header bg-info text-white"><strong>📂 Domains</strong></div>
          <div class="card-body">
            $chips
          </div>
        </div>

        <div class="card border-0 shadow-sm">
          <div class="card-header bg-secondary text-white"><strong>📖 How to Use</strong></div>
          <div class="card-body">
            <ul class="mb-2 small">
              <li>Click the card to flip (<span class="kbd">J</span>)</li>
              <li>Next card: <span class="kbd">K</span></li>
              <li>Mark <em>Know</em> or <em>Don't know</em> for spaced repetition</li>
            </ul>
            <div class="small text-muted">"Know" helps reduce future repetition of mastered content.</div>
          </div>
        </div>
      </div>

      <div class="col-md-9">
        <div class="fc-container">
          <div id="fcCard" class="flashcard">
            <div id="fcText">
              <div class="text-center">
                <div class="spinner-border text-primary mb-3" role="status"></div>
                <div>Loading flashcards...</div>
              </div>
            </div>
          </div>
          
          <div class="d-flex justify-content-center gap-3 mb-3">
            <button id="btnDontKnow" class="btn btn-outline-danger btn-enhanced">❌ Don't Know</button>
            <button id="btnKnow" class="btn btn-outline-success btn-enhanced">✅ Know</button>
          </div>
          
          <div class="d-flex justify-content-between align-items-center">
            <div class="small">
              <strong>Progress:</strong> 
              <span class="text-danger">Don't know: <span id="cntDK">0</span></span> | 
              <span class="text-success">Know: <span id="cntK">0</span></span>
            </div>
            <div class="small text-muted">
              <strong>Cards loaded:</strong> <span id="cntLoaded">0</span>
            </div>
          </div>
          
          <div class="text-center mt-3">
            <small class="text-muted">
              💡 <strong>Keyboard shortcuts:</strong> <span class="kbd">J</span> = Flip, <span class="kbd">K</span> = Next
            </small>
          </div>
        </div>
      </div>
    </div>

    <script>
      let domain = 'random';
      let cards = [];
      let idx = 0;
      let showingBack = false;
      let cntDK = 0, cntK = 0;

      function renderCard() {
        const el = document.getElementById('fcText');
        const cardEl = document.getElementById('fcCard');
        
        if (!cards.length) {
          el.innerHTML = '<div class="text-center text-muted"><h5>📭 No Cards Available</h5><p>Try selecting a different domain or check back later.</p></div>';
          cardEl.classList.remove('flipped');
          return;
        }
        
        const c = cards[idx];
        const content = showingBack ? c.back : c.front;
        
        el.innerHTML = '<div style="font-size: 1.1rem; line-height: 1.5;">' + content.replace(/</g,'&lt;').replace(/\\n/g, '<br>') + '</div>' +
          '<div class="small-muted">💡 ' + (showingBack ? 'Back - Click or press J to see front' : 'Front - Click or press J to see answer') + '</div>';
        
        cardEl.classList.toggle('flipped', showingBack);
        document.getElementById('cntLoaded').textContent = String(cards.length);
      }

      function nextCard() {
        showingBack = false;
        if (!cards.length) return;
        idx = (idx + 1) % cards.length;
        renderCard();
      }

      async function loadCards() {
        document.getElementById('fcText').innerHTML = '<div class="text-center"><div class="spinner-border text-primary mb-2"></div><div>Loading cards...</div></div>';
        try {
          const res = await fetch('/api/flashcards?domain=' + encodeURIComponent(domain) + '&count=100');
          const data = await res.json();
          if (data.cards && data.cards.length > 0) {
            cards = data.cards;
            idx = 0; 
            showingBack = false;
            renderCard();
          } else {
            cards = []; 
            idx = 0; 
            showingBack = false; 
            renderCard();
          }
        } catch (e) {
          cards = []; 
          idx = 0; 
          showingBack = false; 
          document.getElementById('fcText').innerHTML = '<div class="text-center text-danger"><h5>⚠️ Loading Error</h5><p>Could not load flashcards. Please try again.</p></div>';
        }
      }

      document.getElementById('fcCard').addEventListener('click', () => {
        showingBack = !showingBack; 
        renderCard();
      });

      document.getElementById('btnDontKnow').addEventListener('click', () => {
        cntDK += 1; 
        document.getElementById('cntDK').textContent = String(cntDK);
        nextCard();
      });
      
      document.getElementById('btnKnow').addEventListener('click', () => {
        cntK += 1; 
        document.getElementById('cntK').textContent = String(cntK);
        nextCard();
      });

      document.addEventListener('keydown', (e) => {
        if (e.key.toLowerCase() === 'j') { 
          e.preventDefault(); 
          showingBack = !showingBack; 
          renderCard(); 
        }
        if (e.key.toLowerCase() === 'k') { 
          e.preventDefault(); 
          nextCard(); 
        }
      });

      document.querySelectorAll('.domain-chip').forEach(chip => {
        chip.addEventListener('click', () => {
          document.querySelectorAll('.domain-chip').forEach(c => c.classList.remove('active'));
          chip.classList.add('active');
          domain = chip.getAttribute('data-domain');
          loadCards();
        });
      });

      loadCards();
    </script>
    """)
    return render_base_template("Flashcards", content.substitute(chips=chips_html), user=user)

@app.get("/api/flashcards")
@subscription_required
def api_flashcards():
    """
    Returns flashcards with 'front' and 'back' text.
    Back text does NOT include letter prefixes.
    Accepts ?domain=<key|random>&count=50 (max 200).
    """
    try:
        domain = (request.args.get("domain") or "random").strip().lower()
        try:
            count = int(request.args.get("count", "50"))
        except ValueError:
            count = 50
        count = max(1, min(200, count))

        def build_from_pool(pool, desired_count):
            cards = []
            while len(cards) < desired_count:
                batch = pool[:]
                random.shuffle(batch)
                for b in batch:
                    if len(cards) >= desired_count:
                        break
                    opts = b.get("options", {}) or {}
                    correct_text = (opts.get(b.get("correct"), "") or "").strip()
                    back_lines = []
                    if correct_text:
                        back_lines.append("✅ Correct: {}".format(correct_text))
                    if b.get("explanation"):
                        back_lines.append("💡 Explanation: {}".format(b["explanation"].strip()))
                    if b.get("source_name"):
                        back_lines.append("📚 Source: {}".format(b["source_name"]))
                    cards.append({
                        "id": "fb_{}".format(len(cards)+1),
                        "front": (b.get("question") or "").strip(),
                        "back": "\\n\\n".join([x for x in back_lines if x]) or "Correct answer available.",
                        "domain": b.get("domain", "general"),
                        "difficulty": b.get("difficulty", "medium")
                    })
            return cards

        base_pool = BASE_QUESTIONS[:]

        # Try DB first (if table exists)
        cards = []
        try:
            rows = []
            if 'question_bank' in inspect(db.engine).get_table_names():
                q = QuestionBank.query.filter_by(is_verified=True)
                if domain not in ("random", "", None):
                    q = q.filter(QuestionBank.domain == domain)
                rows = q.order_by(func.random()).limit(count).all()
            if rows:
                for r in rows:
                    try:
                        opts = json.loads(r.options_json or "{}")
                        if not isinstance(opts, dict):
                            opts = {}
                    except Exception:
                        opts = {}
                    correct_text = (opts.get(r.correct, "") or "").strip()
                    back_lines = []
                    if correct_text:
                        back_lines.append("✅ Correct: {}".format(correct_text))
                    if r.explanation:
                        back_lines.append("💡 Explanation: {}".format(r.explanation.strip()))
                    if r.source_name:
                        back_lines.append("📚 Source: {}".format(r.source_name))
                    back = "\\n\\n".join([x for x in back_lines if x])

                    cards.append({
                        "id": "qb_{}".format(r.id),
                        "front": (r.question or "").strip(),
                        "back": back if back else "Correct answer available.",
                        "domain": (r.domain or "general"),
                        "difficulty": (r.difficulty or "medium")
                    })
        except Exception as e:
            print("/api/flashcards DB error: {}".format(e))

        # Fallback if DB empty
        if not cards:
            pool = base_pool if domain in ("random", "", None) else [b for b in base_pool if b.get("domain") == domain] or base_pool
            cards = build_from_pool(pool, count)

        return jsonify({"cards": cards, "domain": domain, "count": len(cards)}), 200
    except Exception as e:
        print("/api/flashcards error: {}".format(e))
        return jsonify({"error": "Could not load flashcards."}), 500

# ------------------------------ Quizzes ---------------------------------------
@app.route('/quiz-selector')
@subscription_required
def quiz_selector():
    user = User.query.get(session['user_id'])

    chips = ['<span class="domain-chip active" data-domain="random">🎲 All Domains</span>'] + [
        '<span class="domain-chip" data-domain="{}">{}</span>'.format(k, v["name"])
        for k, v in CPP_DOMAINS.items()
    ]
    chips_html = ''.join(chips)

    content = Template("""
    <div class="row">
      <div class="col-md-10 mx-auto">
        <div class="card border-0 shadow">
          <div class="card-header bg-success text-white">
            <h4 class="mb-0">📝 Build Your Quiz</h4>
            <small>Customize your practice session</small>
          </div>
          <div class="card-body">
            <div class="mb-4">
              <label class="form-label fw-bold">🎯 Choose a domain:</label>
              <div class="mt-2">$chips</div>
            </div>

            <div class="mb-4">
              <label class="form-label fw-bold me-3">📊 Number of questions:</label>
              <div class="btn-group" role="group">
                <input type="radio" class="btn-check" name="qcount" id="qc5" autocomplete="off" value="5">
                <label class="btn btn-outline-primary" for="qc5">5</label>
                <input type="radio" class="btn-check" name="qcount" id="qc10" autocomplete="off" value="10" checked>
                <label class="btn btn-outline-primary" for="qc10">10</label>
                <input type="radio" class="btn-check" name="qcount" id="qc15" autocomplete="off" value="15">
                <label class="btn btn-outline-primary" for="qc15">15</label>
                <input type="radio" class="btn-check" name="qcount" id="qc20" autocomplete="off" value="20">
                <label class="btn btn-outline-primary" for="qc20">20</label>
              </div>
            </div>

            <div class="mb-4">
              <label class="form-label fw-bold me-3">⚡ Difficulty level:</label>
              <select id="difficulty" class="form-select" style="max-width: 240px; display: inline-block;">
                <option value="easy">🟢 Easy</option>
                <option value="medium" selected>🟡 Medium</option>
                <option value="hard">🔴 Hard</option>
              </select>
            </div>

            <div class="d-grid gap-2 d-md-flex">
              <button id="startQuiz" class="btn btn-success btn-lg btn-enhanced">🚀 Start Quiz</button>
              <a href="/mock-exam" class="btn btn-outline-warning btn-lg btn-enhanced">🏁 Mock Exam Instead</a>
            </div>
          </div>
        </div>
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
        const diff = document.getElementById('difficulty').value;
        window.location.href = '/quiz/practice?domain=' + encodeURIComponent(domain) + '&count=' + encodeURIComponent(count) + '&difficulty=' + encodeURIComponent(diff);
      });
    </script>
    """)
    return render_base_template("Quizzes", content.substitute(chips=chips_html), user=user)

@app.route('/quiz/<quiz_type>')
@subscription_required
def quiz(quiz_type):
    user = User.query.get(session['user_id'])
    if quiz_type not in QUIZ_TYPES:
        flash('Invalid quiz type.', 'danger')
        return redirect(url_for('quiz_selector'))

    domain = request.args.get('domain', 'random')
    difficulty = request.args.get('difficulty', 'medium')
    try:
        count = int(request.args.get('count', QUIZ_TYPES[quiz_type]['questions']))
    except Exception:
        count = QUIZ_TYPES[quiz_type]['questions']

    # Start quiz timer
    session['quiz_start_time'] = datetime.utcnow().timestamp()

    quiz_data = generate_quiz(quiz_type, domain, difficulty, count)
    quiz_json = json.dumps(quiz_data)

    page = Template("""
    <div class="row">
      <div class="col-md-10 mx-auto">
        <div class="card border-0 shadow">
          <div class="card-header d-flex justify-content-between align-items-center bg-primary text-white">
            <div>
              <h4 class="mb-0">📝 $title</h4>
              <small>$count questions • $difficulty difficulty</small>
            </div>
            <button id="submitBtnTop" class="btn btn-success btn-enhanced">Submit Quiz</button>
          </div>
          <div class="card-body" id="quizContainer"></div>
          <div class="card-footer text-end">
            <button id="submitBtnBottom" class="btn btn-success btn-lg btn-enhanced">Submit Quiz</button>
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
          card.className = 'mb-4 p-4 border rounded-3 shadow-sm';
          card.id = 'question-' + idx;
          
          const title = document.createElement('h5');
          title.className = 'fw-bold mb-3 text-primary';
          title.textContent = 'Question ' + (idx + 1) + ' of ' + QUIZ_DATA.questions.length;
          card.appendChild(title);
          
          const questionText = document.createElement('p');
          questionText.className = 'mb-3 fs-6';
          questionText.textContent = q.question;
          card.appendChild(questionText);

          const options = q.options || {};
          for (const key in options) {
            const optId = 'q' + idx + '_' + key;
            const div = document.createElement('div');
            div.className = 'form-check mb-2 p-2 rounded';
            div.style.transition = 'background-color 0.2s ease';
            
            const input = document.createElement('input');
            input.className = 'form-check-input';
            input.type = 'radio';
            input.name = 'q' + idx;
            input.id = optId;
            input.value = key;
            
            const label = document.createElement('label');
            label.className = 'form-check-label w-100';
            label.htmlFor = optId;
            label.textContent = key + ') ' + options[key];
            
            // Add hover effect
            div.addEventListener('mouseenter', () => div.style.backgroundColor = '#f8f9fa');
            div.addEventListener('mouseleave', () => div.style.backgroundColor = 'transparent');
            
            div.appendChild(input);
            div.appendChild(label);
            card.appendChild(div);
          }
          container.appendChild(card);
        });
      }

      async function submitQuiz() {
        const answers = {};
        const unanswered = [];
        
        (QUIZ_DATA.questions || []).forEach((q, idx) => {
          const selected = document.querySelector('input[name="q' + idx + '"]:checked');
          answers[String(idx)] = selected ? selected.value : null;
          if (!selected) {
            unanswered.push(idx + 1);
          }
        });
        
        // Validate all answered
        if (unanswered.length > 0) {
          unanswered.forEach(qNum => {
            const card = document.getElementById('question-' + (qNum - 1));
            if (card) {
              card.style.borderColor = '#dc3545';
              card.style.borderWidth = '2px';
              card.style.backgroundColor = '#fff5f5';
            }
          });
          alert('⚠️ Please answer all questions before submitting.\\n\\nMissing: Q' + unanswered.join(', Q'));
          const firstUnanswered = document.getElementById('question-' + (unanswered[0] - 1));
          if (firstUnanswered) {
            firstUnanswered.scrollIntoView({ behavior: 'smooth', block: 'center' });
          }
          return;
        }
        
        // Disable buttons during submission
        document.getElementById('submitBtnTop').disabled = true;
        document.getElementById('submitBtnBottom').disabled = true;
        document.getElementById('submitBtnTop').innerHTML = '⏳ Submitting...';
        document.getElementById('submitBtnBottom').innerHTML = '⏳ Submitting...';
        
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
            resultsDiv.innerHTML = '<div class="alert alert-danger border-0"><strong>❌ Error:</strong> ' + data.error + '</div>';
            return;
          }

          // Enhanced results display
          let html = '<div class="card border-0 shadow"><div class="card-body">';
          
          // Score header with visual indicators
          const scoreClass = data.score >= 80 ? 'text-success' : (data.score >= 70 ? 'text-warning' : 'text-danger');
          const scoreIcon = data.score >= 80 ? '🎯' : (data.score >= 70 ? '📚' : '⚠️');
          
          html += '<div class="text-center mb-4">';
          html += '<h3 class="' + scoreClass + '">' + scoreIcon + ' Final Score: ' + data.score.toFixed(1) + '%</h3>';
          html += '<h5 class="text-muted">(' + data.correct + ' out of ' + data.total + ' questions correct)</h5>';
          if (data.time_taken) {
            html += '<p class="text-muted">⏱️ Time taken: ' + data.time_taken + ' minutes</p>';
          }
          html += '</div>';
          
          // Performance insights
          if (Array.isArray(data.performance_insights)) {
            html += '<div class="alert alert-info border-0"><h6 class="mb-2">📈 Performance Summary</h6>';
            html += '<ul class="mb-0">';
            data.performance_insights.forEach(insight => { 
              html += '<li>' + insight + '</li>'; 
            });
            html += '</ul></div>';
          }
          html += '</div></div>';

          // Detailed question results
          if (Array.isArray(data.detailed_results)) {
            html += '<div class="mt-4">';
            html += '<h5 class="mb-3">📝 Question-by-Question Review</h5>';
            
            data.detailed_results.forEach((result) => {
              const isCorrect = result.is_correct;
              const cardClass = isCorrect ? 'result-card correct' : 'result-card incorrect';
              const iconClass = isCorrect ? '✅' : '❌';
              
              html += '<div class="card mb-3 ' + cardClass + '">';
              html += '<div class="card-body">';
              
              // Question text
              html += '<h6 class="card-title">' + iconClass + ' Question ' + result.index + '</h6>';
              html += '<p class="card-text mb-3">' + (result.question || 'Question text not available') + '</p>';
              
              // Answer feedback
              if (isCorrect) {
                html += '<div class="alert alert-success border-0 py-2">';
                html += '<strong>✅ Correct!</strong> ';
                html += result.correct_letter + ') ' + (result.correct_text || 'Correct answer');
                html += '</div>';
              } else {
                html += '<div class="alert alert-danger border-0 py-2 mb-2">';
                html += '<strong>❌ Your answer:</strong> ';
                html += (result.user_letter || '—') + (result.user_text ? (') ' + result.user_text) : ' (No answer selected)');
                html += '</div>';
                html += '<div class="alert alert-success border-0 py-2">';
                html += '<strong>✅ Correct answer:</strong> ';
                html += (result.correct_letter || '?') + ') ' + (result.correct_text || 'Correct answer not available');
                html += '</div>';
              }
              
              // Explanation
              if (result.explanation) {
                html += '<div class="mt-2 p-3 bg-light rounded">';
                html += '<strong>💡 Explanation:</strong> ' + result.explanation;
                html += '</div>';
              }
              
              // Source attribution
              if (result.source_name) {
                html += '<div class="mt-2">';
                html += '<small class="text-muted"><strong>📚 Source:</strong> ' + result.source_name;
                if (result.source_url) {
                  html += ' <a href="' + result.source_url + '" target="_blank" rel="noopener" class="text-decoration-none">🔗 View Source</a>';
                }
                html += '</small>';
                html += '</div>';
              }
              
              html += '</div></div>';
            });
            html += '</div>';
          }

          // Action buttons
          html += '<div class="text-center mt-4">';
          html += '<a href="/quiz-selector" class="btn btn-primary btn-lg me-3 btn-enhanced">📝 Take Another Quiz</a>';
          html += '<a href="/dashboard" class="btn btn-outline-secondary btn-lg btn-enhanced">🏠 Back to Dashboard</a>';
          html += '</div>';

          resultsDiv.innerHTML = html;
          resultsDiv.scrollIntoView({ behavior: 'smooth', block: 'start' });
          
        } catch (e) {
          console.error('Quiz submission error:', e);
          document.getElementById('results').innerHTML = 
            '<div class="alert alert-danger border-0"><strong>🌐 Network Error:</strong> Could not submit quiz. Please check your connection and try again.</div>';
        }
      }

      document.getElementById('submitBtnTop').addEventListener('click', submitQuiz);
      document.getElementById('submitBtnBottom').addEventListener('click', submitQuiz);
      renderQuiz();
    </script>
    """)
    content = page.substitute(
        title=quiz_data['title'], 
        count=len(quiz_data['questions']),
        difficulty=difficulty.title(),
        quiz_json=quiz_json
    )
    return render_base_template("Quiz", content, user=user)

# ----------------- Enhanced Submit Quiz Route -----------------
@app.route('/submit-quiz', methods=['POST'])
@subscription_required
def submit_quiz():
    try:
        data = request.get_json() or {}
        quiz_type = data.get('quiz_type')
        answers = data.get('answers', {})
        questions = data.get('questions', [])
        domain = data.get('domain', 'general')

        if not quiz_type or not questions:
            return jsonify({'error': 'Invalid quiz data'}), 400

        # Duration calculation
        time_taken = 0
        if 'quiz_start_time' in session:
            start = datetime.fromtimestamp(session['quiz_start_time'])
            time_taken = int((datetime.utcnow() - start).total_seconds() / 60)
            session.pop('quiz_start_time', None)

        correct_count = 0
        total = len(questions)

        detailed_results = []
        for i, q in enumerate(questions):
            user_letter = answers.get(str(i))
            correct_letter = q.get('correct')
            options = q.get('options', {}) or {}
            is_correct = (user_letter == correct_letter)
            if is_correct:
                correct_count += 1

            # Record event & update progress
            q_domain = q.get('domain', domain)
            record_question_event(session['user_id'], q, domain=q_domain, topic=None, is_correct=is_correct, source=('mock' if quiz_type == 'mock-exam' else 'quiz'))
            update_user_progress_on_answer(session['user_id'], q_domain, None, is_correct)

            detailed_results.append({
                'index': i + 1,
                'question': q.get('question', ''),
                'correct_letter': correct_letter,
                'correct_text': options.get(correct_letter, ''),
                'user_letter': user_letter,
                'user_text': options.get(user_letter, '') if user_letter else None,
                'explanation': q.get('explanation', ''),
                'source_name': q.get('source_name', ''),
                'source_url': q.get('source_url', ''),
                'is_correct': bool(is_correct),
                'domain': q_domain
            })

        score = (correct_count / total) * 100 if total else 0.0

        # Save result
        qr = QuizResult(
            user_id=session['user_id'],
            quiz_type=quiz_type,
            domain=domain,
            questions=json.dumps(questions),
            answers=json.dumps(answers),
            score=score,
            total_questions=total,
            time_taken=time_taken
        )
        db.session.add(qr)
        db.session.commit()

        # Update user quiz score history
        user = User.query.get(session['user_id'])
        try:
            scores = json.loads(user.quiz_scores) if user.quiz_scores else []
        except Exception:
            scores = []
        scores.append({
            'score': score,
            'date': datetime.utcnow().isoformat(),
            'type': quiz_type,
            'domain': domain,
            'time_taken': time_taken# app.py - Enhanced CPP Test Prep with upgraded features
from flask import Flask, request, redirect, url_for, flash, session, jsonify, Response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from string import Template
from functools import wraps
import json
import os
import requests
import stripe
import time
import hashlib
import random

# For SQL text/inspection helpers
from sqlalchemy import text, inspect, func

# -----------------------------------------------------------------------------
# App & Config
# -----------------------------------------------------------------------------
app = Flask(__name__)

def require_env(name: str) -> str:
    val = os.environ.get(name)
    if not val:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return val

# Required env vars
app.config['SECRET_KEY'] = require_env('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = require_env('DATABASE_URL')

# Render sometimes provides postgres://; SQLAlchemy expects postgresql://
if app.config['SQLALCHEMY_DATABASE_URI'].startswith('postgres://'):
    app.config['SQLALCHEMY_DATABASE_URI'] = app.config['SQLALCHEMY_DATABASE_URI'].replace('postgres://', 'postgresql://')

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_recycle': 300,
    'connect_args': {
        'sslmode': 'require',
        'connect_timeout': 10,
    }
}
db = SQLAlchemy(app)

# OpenAI config
OPENAI_API_KEY = require_env('OPENAI_API_KEY')
OPENAI_CHAT_MODEL = os.environ.get('OPENAI_CHAT_MODEL', 'gpt-4o-mini')
OPENAI_API_BASE = os.environ.get('OPENAI_API_BASE', 'https://api.openai.com/v1')

# Stripe config
stripe.api_key = require_env('STRIPE_SECRET_KEY')
STRIPE_PUBLISHABLE_KEY = require_env('STRIPE_PUBLISHABLE_KEY')
STRIPE_WEBHOOK_SECRET = os.environ.get('STRIPE_WEBHOOK_SECRET')

# Simple rate limiter for AI calls
last_api_call = None

# -----------------------------------------------------------------------------
# Quiz Types & Domains
# -----------------------------------------------------------------------------
QUIZ_TYPES = {
    'practice': {'name': 'Practice Quiz', 'description': 'General practice questions', 'questions': 10},
    'mock-exam': {'name': 'Mock Exam', 'description': 'Full exam simulation', 'questions': 50},
    'domain-specific': {'name': 'Domain-Specific Quiz', 'description': 'Focus on specific domains', 'questions': 15},
    'quick-review': {'name': 'Quick Review', 'description': 'Short 5-question review', 'questions': 5},
    'difficult': {'name': 'Advanced Challenge', 'description': 'Challenging questions', 'questions': 20}
}

CPP_DOMAINS = {
    'security-principles': {'name': 'Security Principles & Practices', 'topics': ['Risk Management', 'Security Governance']},
    'business-principles': {'name': 'Business Principles & Practices', 'topics': ['Budgeting', 'Contracts']},
    'investigations': {'name': 'Investigations', 'topics': ['Investigation Planning', 'Evidence Collection']},
    'personnel-security': {'name': 'Personnel Security', 'topics': ['Background Screening', 'Insider Threat']},
    'physical-security': {'name': 'Physical Security', 'topics': ['CPTED', 'Access Control']},
    'information-security': {'name': 'Information Security', 'topics': ['Data Protection', 'Cybersecurity']},
    'crisis-management': {'name': 'Crisis Management', 'topics': ['Business Continuity', 'Emergency Response']}
}

# -----------------------------------------------------------------------------
# Database Models
# -----------------------------------------------------------------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    subscription_status = db.Column(db.String(20), default='trial')
    subscription_plan = db.Column(db.String(20), default='trial')
    subscription_end_date = db.Column(db.DateTime)
    stripe_customer_id = db.Column(db.String(100))
    stripe_subscription_id = db.Column(db.String(100))
    discount_code_used = db.Column(db.String(50))
    study_time = db.Column(db.Integer, default=0)
    quiz_scores = db.Column(db.Text, default='[]')
    terms_accepted = db.Column(db.Boolean, default=False)
    terms_accepted_date = db.Column(db.DateTime)

class ChatHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    messages = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)

class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    activity = db.Column(db.String(100), nullable=False)
    details = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class QuizResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    quiz_type = db.Column(db.String(50), nullable=False)
    domain = db.Column(db.String(50))
    questions = db.Column(db.Text, nullable=False)
    answers = db.Column(db.Text, nullable=False)
    score = db.Column(db.Float, nullable=False)
    total_questions = db.Column(db.Integer, nullable=False)
    time_taken = db.Column(db.Integer)
    completed_at = db.Column(db.DateTime, default=datetime.utcnow)

class StudySession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    topic = db.Column(db.String(100))
    duration = db.Column(db.Integer)
    session_type = db.Column(db.String(50))
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    ended_at = db.Column(db.DateTime)

class UserProgress(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    domain = db.Column(db.String(50), nullable=False, index=True)
    topic = db.Column(db.String(100), nullable=True, index=True)
    mastery_level = db.Column(db.String(20), default='needs_practice')  # needs_practice | good | mastered
    average_score = db.Column(db.Float, default=0.0)  # 0-100
    question_count = db.Column(db.Integer, default=0)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow)
    consecutive_good_scores = db.Column(db.Integer, default=0)

    __table_args__ = (
        db.UniqueConstraint('user_id', 'domain', 'topic', name='uq_userprogress_user_domain_topic'),
    )

class QuestionEvent(db.Model):
    """
    One row per answered card/question.
    source: 'quiz' | 'mock' | 'flashcard' | 'tutor'
    """
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    question_hash = db.Column(db.String(64), nullable=False, index=True)  # sha256 of content
    domain = db.Column(db.String(50), nullable=True, index=True)
    topic = db.Column(db.String(100), nullable=True, index=True)
    source = db.Column(db.String(20), nullable=False)  # quiz/mock/flashcard/tutor
    is_correct = db.Column(db.Boolean, nullable=True)  # flashcards can be Know/Don't Know
    response_time_s = db.Column(db.Integer)  # optional
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    __table_args__ = (
        db.Index('ix_question_event_user_created', 'user_id', 'created_at'),
    )

class QuestionBank(db.Model):
    """
    Optional seed bank for verified questions/flashcards.
    """
    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(50), index=True)
    difficulty = db.Column(db.String(20), index=True)
    question = db.Column(db.Text, nullable=False)
    options_json = db.Column(db.Text)         # JSON dict of options
    correct = db.Column(db.String(5))         # e.g., "B"
    explanation = db.Column(db.Text)
    source_name = db.Column(db.String(120))
    source_url = db.Column(db.Text)
    is_verified = db.Column(db.Boolean, default=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

# -----------------------------------------------------------------------------
# Database Initialization / Migrations (safe, idempotent)
# -----------------------------------------------------------------------------
def init_database():
    try:
        db.create_all()

        insp = inspect(db.engine)

        # Ensure QuizResult has 'domain' and 'time_taken'
        if 'quiz_result' in insp.get_table_names():
            existing_cols = {c['name'] for c in insp.get_columns('quiz_result')}
            if 'domain' not in existing_cols:
                try:
                    db.session.execute(text("ALTER TABLE quiz_result ADD COLUMN domain VARCHAR(50)"))
                    db.session.commit()
                except Exception:
                    db.session.rollback()
            if 'time_taken' not in existing_cols:
                try:
                    db.session.execute(text("ALTER TABLE quiz_result ADD COLUMN time_taken INTEGER"))
                    db.session.commit()
                except Exception:
                    db.session.rollback()

        # Ensure User has terms columns
        if 'user' in insp.get_table_names():
            existing_cols = {c['name'] for c in insp.get_columns('user')}
            if 'terms_accepted' not in existing_cols:
                try:
                    db.session.execute(text('ALTER TABLE "user" ADD COLUMN terms_accepted BOOLEAN DEFAULT FALSE'))
                    db.session.commit()
                except Exception:
                    db.session.rollback()
            if 'terms_accepted_date' not in existing_cols:
                try:
                    db.session.execute(text('ALTER TABLE "user" ADD COLUMN terms_accepted_date TIMESTAMP'))
                    db.session.commit()
                except Exception:
                    db.session.rollback()

        print("Database initialized successfully")
    except Exception as e:
        print(f"Database initialization error: {e}")

with app.app_context():
    init_database()

# -----------------------------------------------------------------------------
# Helpers & Decorators
# -----------------------------------------------------------------------------
def login_required(f):
    @wraps(f)
    def inner(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this feature.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return inner

def subscription_required(f):
    @wraps(f)
    def inner(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        try:
            user = User.query.get(session['user_id'])
            if not user:
                session.clear()
                return redirect(url_for('login'))

            if user.subscription_status == 'expired':
                flash('Your subscription has expired. Please renew to continue.', 'danger')
                return redirect(url_for('subscribe'))

            if user.subscription_status == 'trial' and user.subscription_end_date:
                if datetime.utcnow() > user.subscription_end_date:
                    user.subscription_status = 'expired'
                    db.session.commit()
                    flash('Your trial has expired. Please subscribe to continue.', 'warning')
                    return redirect(url_for('subscribe'))
        except Exception as e:
            print(f"Subscription check error: {e}")
            flash('Authentication error. Please log in again.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return inner

def log_activity(user_id, activity, details=None):
    try:
        db.session.add(ActivityLog(user_id=user_id, activity=activity, details=details))
        db.session.commit()
    except Exception as e:
        print(f"Activity logging error: {e}")
        db.session.rollback()

# ---------- tracking helpers (hash, record event, update progress, seen) ----------
def _hash_question_payload(question_obj: dict) -> str:
    """
    Stable SHA256 hash for a question so we can detect repeats.
    Uses question text + sorted options.
    """
    q_text = (question_obj or {}).get('question', '') or ''
    opts = (question_obj or {}).get('options', {}) or {}
    parts = [q_text.strip()]
    for key in sorted(opts.keys()):
        parts.append("{}:{}".format(key, str(opts.get(key, '')).strip()))
    raw = "||".join(parts)
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()

def record_question_event(
    user_id: int,
    question_obj: dict,
    domain: str = None,
    topic: str = None,
    is_correct: bool = None,
    response_time_s: int = None,
    source: str = 'quiz'
) -> None:
    """Insert one QuestionEvent row safely."""
    try:
        qhash = _hash_question_payload(question_obj)
        evt = QuestionEvent(
            user_id=user_id,
            question_hash=qhash,
            domain=domain,
            topic=topic,
            source=source,
            is_correct=is_correct,
            response_time_s=response_time_s,
        )
        db.session.add(evt)
        db.session.commit()
    except Exception as e:
        print(f"record_question_event error: {e}")
        db.session.rollback()

def _mastery_from_stats(avg: float, streak: int) -> str:
    """
    Mastery banding:
    - mastered: avg >= 90 and streak >= 3
    - good:     avg >= 75 and streak >= 2
    - needs_practice: otherwise
    """
    if (avg or 0) >= 90 and (streak or 0) >= 3:
        return 'mastered'
    if (avg or 0) >= 75 and (streak or 0) >= 2:
        return 'good'
    return 'needs_practice'

def update_user_progress_on_answer(
    user_id: int,
    domain: str,
    topic: str,
    is_correct: bool
) -> None:
    """
    Lightweight rolling update for UserProgress.
    Call this per answer (wired in /submit-quiz).
    """
    try:
        if not domain:
            return

        row = UserProgress.query.filter_by(user_id=user_id, domain=domain, topic=topic).first()
        if not row:
            row = UserProgress(
                user_id=user_id,
                domain=domain,
                topic=topic,
                average_score=0.0,
                question_count=0,
                consecutive_good_scores=0,
                mastery_level='needs_practice'
            )
            db.session.add(row)

        earned = 100.0 if bool(is_correct) else 0.0
        old_count = row.question_count or 0
        new_count = old_count + 1

        row.average_score = ((row.average_score or 0.0) * old_count + earned) / new_count
        row.question_count = new_count

        if earned >= 75.0:
            row.consecutive_good_scores = (row.consecutive_good_scores or 0) + 1
        else:
            row.consecutive_good_scores = 0

        row.mastery_level = _mastery_from_stats(row.average_score, row.consecutive_good_scores)
        row.last_updated = datetime.utcnow()

        db.session.commit()
    except Exception as e:
        print(f"update_user_progress_on_answer error: {e}")
        db.session.rollback()

def get_seen_hashes(user_id: int, domain: str = None, topic: str = None, window_days: int = 30) -> set:
    """
    Return a set of question_hash values the user has seen recently.
    (Use this for non-repeating flashcards later.)
    """
    try:
        cutoff = datetime.utcnow() - timedelta(days=window_days)
        q = QuestionEvent.query.filter(
            QuestionEvent.user_id == user_id,
            QuestionEvent.created_at >= cutoff
        )
        if domain:
            q = q.filter(QuestionEvent.domain == domain)
        if topic:
            q = q.filter(QuestionEvent.topic == topic)
        return {row.question_hash for row in q.with_entities(QuestionEvent.question_hash).all()}
    except Exception as e:
        print(f"get_seen_hashes error: {e}")
        return set()

# -----------------------------------------------------------------------------
# AI chat wrapper
# -----------------------------------------------------------------------------
def chat_with_ai(messages, user_id=None):
    """Thin wrapper to OpenAI Chat Completions with basic rate limiting and robust error handling."""
    global last_api_call
    try:
        # Friendly rate limit
        if last_api_call:
            delta = datetime.utcnow() - last_api_call
            if delta.total_seconds() < 2:
                time.sleep(2 - delta.total_seconds())

        system_message = {
            "role": "system",
            "content": (
                "You are an expert tutor for the ASIS Certified Protection Professional (CPP) exam. "
                "Focus on the seven CPP domains: Security Principles & Practices, Business Principles & Practices, "
                "Investigations, Personnel Security, Physical Security, Information Security, and Crisis Management. "
                "Provide clear explanations, practical examples, and do not claim affiliation with ASIS."
            )
        }
        if not messages or messages[0].get('role') != 'system':
            messages.insert(0, system_message)

        headers = {
            'Authorization': 'Bearer {}'.format(OPENAI_API_KEY),
            'Content-Type': 'application/json'
        }
        data = {
            'model': OPENAI_CHAT_MODEL,
            'messages': messages,
            'max_tokens': 1500,
            'temperature': 0.7
        }

        last_api_call = datetime.utcnow()
        resp = requests.post('{}/chat/completions'.format(OPENAI_API_BASE), headers=headers, json=data, timeout=45)
        if resp.status_code == 200:
            payload = resp.json()
            return payload['choices'][0]['message']['content']
        elif resp.status_code in (401, 403):
            return "I'm having trouble authenticating right now. Please try again."
        elif resp.status_code == 429:
            return "I'm receiving a lot of requests at the moment. Please try again shortly."
        elif resp.status_code >= 500:
            return "The AI service is experiencing issues. Please try again in a bit."
        else:
            print("OpenAI Unexpected status: {} body={}".format(resp.status_code, resp.text[:300]))
            return "I hit an unexpected issue. Please rephrase and try again."
    except Exception as e:
        print(f"AI chat error: {e}")
        return "I encountered a technical issue. Please try again."

# -----------------------------------------------------------------------------
# Quiz generation
# -----------------------------------------------------------------------------
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
        "explanation": "Risk assessments help determine cost-effective mitigation strategies by balancing risk, cost, and operational impact.",
        "source_name": "CPP Study Guide",
        "domain": "security-principles",
        "difficulty": "medium"
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
        "explanation": "Natural surveillance increases the likelihood that criminal activity will be observed by legitimate users of the space.",
        "source_name": "CPTED Guidelines",
        "domain": "physical-security",
        "difficulty": "medium"
    },
    {
        "question": "Which concept means applying multiple security layers so if one fails others still protect?",
        "options": {
            "A": "Security by Obscurity",
            "B": "Defense in Depth",
            "C": "Zero Trust",
            "D": "Least Privilege"
        },
        "correct": "B",
        "explanation": "Defense in Depth uses layered controls to maintain protection despite single-point failures.",
        "source_name": "Security Architecture Principles",
        "domain": "security-principles",
        "difficulty": "medium"
    },
    {
        "question": "In incident response, what is usually the FIRST priority?",
        "options": {
            "A": "Notify law enforcement",
            "B": "Contain the incident",
            "C": "Eradicate malware",
            "D": "Perform lessons learned"
        },
        "correct": "B",
        "explanation": "Containment prevents further damage and is the immediate priority before eradication and recovery phases.",
        "source_name": "Incident Response Framework",
        "domain": "information-security",
        "difficulty": "medium"
    },
    {
        "question": "Background investigations primarily support which objective?",
        "options": {
            "A": "Regulatory compliance only",
            "B": "Improving marketing outcomes",
            "C": "Personnel Security risk reduction",
            "D": "Disaster response coordination"
        },
        "correct": "C",
        "explanation": "Background investigations help reduce personnel security risks such as insider threat and ensure suitability for positions.",
        "source_name": "Personnel Security Standards",
        "domain": "personnel-security",
        "difficulty": "medium"
    },
    {
        "question": "What is the primary goal of business continuity planning?",
        "options": {
            "A": "Prevent all disasters",
            "B": "Maintain critical operations during disruption",
            "C": "Reduce insurance costs",
            "D": "Satisfy regulatory requirements"
        },
        "correct": "B",
        "explanation": "Business continuity planning ensures critical business functions can continue during and after a disruptive event.",
        "source_name": "BCP Best Practices",
        "domain": "crisis-management",
        "difficulty": "medium"
    },
    {
        "question": "In security investigations, what establishes the legal admissibility of evidence?",
        "options": {
            "A": "Chain of custody documentation",
            "B": "Digital timestamps",
            "C": "Witness statements only",
            "D": "Management approval"
        },
        "correct": "A",
        "explanation": "Chain of custody documentation establishes the integrity and legal admissibility of evidence by tracking its handling.",
        "source_name": "Investigation Procedures Manual",
        "domain": "investigations",
        "difficulty": "medium"
    },
    {
        "question": "When developing security budgets, what approach is most effective?",
        "options": {
            "A": "Historical spending patterns",
            "B": "Risk-based budget allocation",
            "C": "Industry average percentages",
            "D": "Available funding limits"
        },
        "correct": "B",
        "explanation": "Risk-based budget allocation ensures resources are directed toward the highest-impact security investments.",
        "source_name": "Security Financial Management",
        "domain": "business-principles",
        "difficulty": "medium"
    }
]

def generate_fallback_quiz(quiz_type, domain, difficulty, num_questions):
    # Filter pool by domain if provided (and not random)
    if domain and domain not in ('general', 'random'):
        pool = [q for q in BASE_QUESTIONS if q.get('domain') == domain]
        if not pool:
            pool = BASE_QUESTIONS[:]
    else:
        pool = BASE_QUESTIONS[:]

    # Randomize and repeat to fill up
    questions = []
    while len(questions) < num_questions:
        batch = pool[:]
        random.shuffle(batch)
        for q in batch:
            if len(questions) >= num_questions:
                break
            questions.append(q.copy())

    return {
        "title": "CPP {} Quiz".format(quiz_type.title().replace('-', ' ')),
        "quiz_type": quiz_type,
        "domain": domain or 'general',
        "difficulty": difficulty,
        "questions": questions[:num_questions]
    }

def generate_quiz(quiz_type, domain=None, difficulty='medium', count=None):
    config = QUIZ_TYPES.get(quiz_type, {'questions': 10})
    n = count if isinstance(count, int) and count > 0 else config['questions']
    return generate_fallback_quiz(quiz_type, domain, difficulty, n)

# -----------------------------------------------------------------------------
# HTML Base Template
# -----------------------------------------------------------------------------
def render_base_template(title, content_html, user=None):
    disclaimer = """
    <div class="bg-light border-top mt-4 py-3">
        <div class="container">
            <div class="row">
                <div class="col-12">
                    <div class="alert alert-info mb-0">
                        <strong>Important Notice:</strong> This service is NOT affiliated with, endorsed by, or approved by ASIS International.
                        CPP® (Certified Protection Professional) is a registered certification mark of ASIS International, Inc.
                        This platform is an independent study aid and does not guarantee exam success.
                    </div>
                </div>
            </div>
        </div>
    </div>
    """

    nav_html = ""
    if user:
        nav_html = (
            '<nav class="navbar navbar-expand-lg navbar-dark bg-primary">'
            '  <div class="container">'
            '    <a class="navbar-brand" href="/dashboard">CPP Test Prep</a>'
            '    <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navcol" aria-controls="navcol" aria-expanded="false" aria-label="Toggle navigation">'
            '      <span class="navbar-toggler-icon"></span>'
            '    </button>'
            '    <div class="collapse navbar-collapse" id="navcol">'
            '      <div class="navbar-nav ms-auto">'
            '        <a class="nav-link" href="/dashboard">Dashboard</a>'
            '        <a class="nav-link" href="/study">Tutor</a>'
            '        <a class="nav-link" href="/flashcards">Flashcards</a>'
            '        <a class="nav-link" href="/quiz-selector">Quizzes</a>'
            '        <a class="nav-link" href="/mock-exam">Mock Exam</a>'
            '        <a class="nav-link" href="/progress">Progress</a>'
            '        <a class="nav-link" href="/subscribe">Subscribe</a>'
            '        <a class="nav-link" href="/logout">Logout</a>'
            '      </div>'
            '    </div>'
            '  </div>'
            '</nav>'
        )

    # Enhanced CSS with improved styling
    css = """
    <style>
      .gauge-wrap {
        --p: 0%;
        width: 140px; height: 140px;
        border-radius: 50%;
        background:
          radial-gradient(farthest-side, white 79%, transparent 80% 100%),
          conic-gradient(#28a745 var(--p), #e9ecef 0);
        display:flex; align-items:center; justify-content:center;
        font-weight:700; font-size:1.2rem; color:#28a745;
        position:relative;
        box-shadow: 0 4px 12px rgba(0,0,0,0.1);
      }
      .gauge-wrap::before {
        content: '';
        position: absolute;
        width: 100%; height: 100%;
        border-radius: 50%;
        background: conic-gradient(#dc3545 0 33%, #ffc107 33% 66%, #28a745 66% 100%);
        opacity: 0.1;
      }
      .domain-chip {
        display:inline-block; margin:4px 6px 4px 0; padding:8px 12px;
        border-radius:20px; background:#e3f2fd; color:#1976d2; cursor:pointer; user-select:none;
        border:1px solid #bbdefb; transition: all 0.2s ease;
      }
      .domain-chip:hover {
        background:#1976d2; color:#fff; transform: translateY(-1px);
        box-shadow: 0 2px 8px rgba(25,118,210,0.3);
      }
      .domain-chip.active {
        background:#1976d2; color:#fff; border-color:#1976d2;
        box-shadow: 0 2px 8px rgba(25,118,210,0.3);
      }
      /* Enhanced flashcard styling */
      .fc-container { max-width: 640px; margin: 0 auto; }
      .flashcard {
        width: 100%; max-width: 580px;
        height: 360px;
        border-radius: 16px;
        box-shadow: 0 8px 32px rgba(0,0,0,0.12);
        background: linear-gradient(135deg, #fff 0%, #f8f9fa 100%);
        padding: 24px 28px;
        margin: 16px auto;
        display:flex; align-items:center; justify-content:center;
        text-align:center; font-size:1.15rem; line-height:1.5;
        border: 2px solid #e9ecef;
        transition: all 0.3s ease;
        cursor: pointer;
      }
      .flashcard:hover {
        transform: translateY(-4px);
        box-shadow: 0 12px 40px rgba(0,0,0,0.15);
      }
      .flashcard.flipped {
        background: linear-gradient(135deg, #e3f2fd 0%, #f3e5f5 100%);
        border-color: #2196f3;
      }
      .flashcard .small-muted { color:#6c757d; font-size:0.9rem; margin-top:12px; }
      .kbd { 
        border:1px solid #ced4da; padding:2px 8px; border-radius:4px; 
        font-family:Monaco,Consolas,monospace; font-size:0.85rem;
        background:#f8f9fa; color:#495057;
      }
      
      /* Enhanced quiz results styling */
      .result-card {
        border-left: 4px solid;
        transition: all 0.2s ease;
      }
      .result-card.correct {
        border-left-color: #28a745;
        background: linear-gradient(90deg, rgba(40,167,69,0.05) 0%, transparent 100%);
      }
      .result-card.incorrect {
        border-left-color: #dc3545;
        background: linear-gradient(90deg, rgba(220,53,69,0.05) 0%, transparent 100%);
      }
      
      /* Progress indicators */
      .progress-ring {
        width: 120px;
        height: 120px;
        transform: rotate(-90deg);
      }
      .progress-ring-circle {
        fill: transparent;
        stroke: #e9ecef;
        stroke-width: 8;
        stroke-dasharray: 314;
        stroke-dashoffset: 314;
        transition: stroke-dashoffset 0.5s ease;
      }
      .progress-ring-circle.active {
        stroke: #28a745;
      }
      
      /* Enhanced button styling */
      .btn-enhanced {
        border-radius: 8px;
        font-weight: 600;
        transition: all 0.2s ease;
        border: none;
        position: relative;
        overflow: hidden;
      }
      .btn-enhanced:before {
        content: '';
        position: absolute;
        top: 50%;
        left: 50%;
        width: 0;
        height: 0;
        background: rgba(255,255,255,0.2);
        border-radius: 50%;
        transition: all 0.3s ease;
        transform: translate(-50%, -50%);
      }
      .btn-enhanced:hover:before {
        width: 300px;
        height: 300px;
      }
    </style>
    """)

    page = Template("""\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>$title - CPP Test Prep</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
  $css
</head>
<body>
  $nav
  <div class="container mt-4">
    $content
  </div>
  $disclaimer
</body>
</html>
""")
    return page.substitute(title=title, nav=nav_html, content=content_html, disclaimer=disclaimer, css=css)

# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------
@app.route('/favicon.ico')
def favicon():
    return Response('', status=204, mimetype='image/x-icon')

@app.get("/healthz")
def healthz():
    try:
        db.session.execute(text('SELECT 1'))
        return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}, 200
    except Exception as e:
        return {"status": "unhealthy", "error": str(e)}, 500

@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    content = """
    <div class="row justify-content-center">
      <div class="col-md-8">
        <div class="text-center mb-5">
          <h1 class="display-5">CPP Test Prep</h1>
          <p class="lead">AI-powered study platform for the Certified Protection Professional exam</p>
        </div>
        <div class="row g-3">
          <div class="col-md-6">
            <div class="card h-100 border-0 shadow-sm"><div class="card-body">
              <h5 class="card-title">🎯 Smart Quizzes</h5>
              <p class="card-text">Practice with questions across all CPP domains with detailed feedback.</p>
            </div></div>
          </div>
          <div class="col-md-6">
            <div class="card h-100 border-0 shadow-sm"><div class="card-body">
              <h5 class="card-title">🤖 AI Tutor</h5>
              <p class="card-text">Get explanations, examples, and personalized study guidance.</p>
            </div></div>
          </div>
        </div>
        <div class="text-center mt-4">
          <a href="/register" class="btn btn-primary btn-lg me-3 btn-enhanced">Start Free Trial</a>
          <a href="/login" class="btn btn-outline-primary btn-lg btn-enhanced">Login</a>
        </div>
      </div>
    </div>
    """
    return render_base_template("Home", content)

# ----------------------------- Auth: Register/Login/Logout --------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email', '').lower().strip()
        password = request.form.get('password', '')
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        terms_accepted = (request.form.get('terms_accepted') == 'on')

        if not all([email, password, first_name, last_name]):
            flash('All fields are required.', 'danger')
            return redirect(url_for('register'))
        if len(password) < 8:
            flash('Password must be at least 8 characters long.', 'danger')
            return redirect(url_for('register'))
        if not terms_accepted:
            flash('You must accept the terms and conditions to register.', 'danger')
            return redirect(url_for('register'))
        if User.query.filter_by(email=email).first():
            flash('Email already registered. Please log in.', 'warning')
            return redirect(url_for('login'))

        try:
            # Create Stripe customer
            stripe_customer = stripe.Customer.create(
                email=email,
                name="{} {}".format(first_name, last_name),
                metadata={'source': 'cpp_test_prep'}
            )

            user = User(
                email=email,
                password_hash=generate_password_hash(password),
                first_name=first_name,
                last_name=last_name,
                subscription_status='trial',
                subscription_plan='trial',
                subscription_end_date=datetime.utcnow() + timedelta(days=7),
                stripe_customer_id=stripe_customer.id,
                terms_accepted=True,
                terms_accepted_date=datetime.utcnow()
            )
            db.session.add(user)
            db.session.commit()

            log_activity(user.id, 'user_registered', 'New user: {} {}'.format(first_name, last_name))

            session['user_id'] = user.id
            session['user_name'] = "{} {}".format(first_name, last_name)
            flash('Welcome {}! You have a 7-day free trial.'.format(first_name), 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            print(f"Registration error: {e}")
            db.session.rollback()
            flash('Registration error. Please try again.', 'danger')

    # GET form
    content = """
    <div class="row justify-content-center">
      <div class="col-md-6">
        <div class="card border-0 shadow">
          <div class="card-header bg-primary text-white"><h3 class="mb-0">Create Account</h3></div>
          <div class="card-body">
            <form method="POST">
              <div class="mb-3">
                <label for="first_name" class="form-label">First Name</label>
                <input type="text" class="form-control" id="first_name" name="first_name" required>
              </div>
              <div class="mb-3">
                <label for="last_name" class="form-label">Last Name</label>
                <input type="text" class="form-control" id="last_name" name="last_name" required>
              </div>
              <div class="mb-3">
                <label for="email" class="form-label">Email</label>
                <input type="email" class="form-control" id="email" name="email" required>
              </div>
              <div class="mb-3">
                <label for="password" class="form-label">Password</label>
                <input type="password" class="form-control" id="password" name="password" required>
                <div class="form-text">Must be at least 8 characters long.</div>
              </div>
              <div class="mb-3">
                <div class="card bg-light">
                  <div class="card-body">
                    <h6 class="card-title">Terms and Conditions</h6>
                    <div style="max-height: 200px; overflow-y: auto; font-size: 0.9em;">
                      <p><strong>1. Service Description</strong><br>
                      This platform provides study materials and practice tests for CPP exam preparation.</p>
                      <p><strong>2. User Responsibilities</strong><br>
                      Use this service for legitimate study purposes and keep your account secure.</p>
                      <p><strong>3. Payment Terms</strong><br>
                      Subscription fees and cancellation policies apply as stated during checkout.</p>
                      <p><strong>4. Intellectual Property</strong><br>
                      All content is proprietary and protected by copyright.</p>
                      <p><strong>5. Disclaimer</strong><br>
                      We do not guarantee exam success; results depend on individual preparation.</p>
                      <p><strong>6. Privacy</strong><br>
                      We protect personal information per our privacy policy.</p>
                    </div>
                    <div class="form-check mt-3">
                      <input class="form-check-input" type="checkbox" id="terms_accepted" name="terms_accepted" required>
                      <label class="form-check-label" for="terms_accepted"><strong>I agree to the Terms and Conditions</strong></label>
                    </div>
                  </div>
                </div>
              </div>
              <button type="submit" class="btn btn-primary w-100 btn-enhanced">Create Account</button>
            </form>
            <div class="text-center mt-3">
              <p>Already have an account? <a href="/login">Login here</a></p>
            </div>
          </div>
        </div>
      </div>
    </div>
    """
    return render_base_template("Register", content)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').lower().strip()
        password = request.form.get('password', '')
        try:
            user = User.query.filter_by(email=email).first()
            if user and check_password_hash(user.password_hash, password):
                session['user_id'] = user.id
                session['user_name'] = "{} {}".format(user.first_name, user.last_name)
                log_activity(user.id, 'user_login', 'User logged in')
                flash('Welcome back, {}!'.format(user.first_name), 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid email or password.', 'danger')
        except Exception as e:
            print(f"Login error: {e}")
            flash('Login error. Please try again.', 'danger')

    content = """
    <div class="row justify-content-center">
      <div class="col-md-5">
        <div class="card border-0 shadow">
          <div class="card-header bg-primary text-white"><h3 class="mb-0">Login</h3></div>
          <div class="card-body">
            <form method="POST">
              <div class="mb-3">
                <label for="email" class="form-label">Email</label>
                <input type="email" class="form-control" id="email" name="email" required>
              </div>
              <div class="mb-3">
                <label for="password" class="form-label">Password</label>
                <input type="password" class="form-control" id="password" name="password" required>
              </div>
              <button type="submit" class="btn btn-primary w-100 btn-enhanced">Login</button>
            </form>
            <div class="text-center mt-3">
              <p>Don't have an account? <a href="/register">Register here</a></p>
            </div>
          </div>
        </div>
      </div>
    </div>
    """
    return render_base_template("Login", content)

@app.route('/logout')
def logout():
    if 'user_id' in session:
        log_activity(session['user_id'], 'user_logout', 'User logged out')
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

# --------------------------------- Dashboard ----------------------------------
@app.route('/dashboard')
@login_required
def dashboard():
    user = User.query.get(session['user_id'])
    days_left = 0
    if user.subscription_end_date:
        days_left = max(0, (user.subscription_end_date - datetime.utcnow()).days)

    # Compute overall progress (simple average of domain averages)
    user_progress = UserProgress.query.filter_by(user_id=user.id).all()
    if user_progress:
        avg_sum = sum([(p.average_score or 0.0) for p in user_progress])
        overall_pct = int(round(avg_sum / len(user_progress)))
    else:
        overall_pct = 0

    tmpl = Template("""
    <div class="row">
      <div class="col-12"><h1>Welcome back, $first_name!</h1></div>
      <div class="col-12">
        <div class="row mt-4 g-3">
          <div class="col-md-3">
            <div class="card bg-primary text-white h-100 border-0 shadow-sm"><div class="card-body">
              <h6 class="mb-1">⏰ Trial/Plan</h6>
              <h3 class="mb-0">$days_left days left</h3>
            </div></div>
          </div>
          <div class="col-md-3">
            <div class="card bg-success text-white h-100 border-0 shadow-sm"><div class="card-body">
              <h6 class="mb-1">📚 Study Time</h6>
              <h3 class="mb-0">$study_time mins</h3>
            </div></div>
          </div>
          <div class="col-md-3">
            <div class="card h-100 d-flex align-items-center justify-content-center border-0 shadow-sm">
              <div class="gauge-wrap" style="--p:$overall_pct%;">
                <span>$overall_pct%</span>
              </div>
              <div class="small text-muted mt-2 text-center">Overall Progress<br>(Goal: 80%+)</div>
            </div>
          </div>
          <div class="col-md-3">
            <div class="card bg-warning text-dark h-100 border-0 shadow-sm"><div class="card-body text-center">
              <h6 class="mb-1">🎯 Quick Start</h6>
              <div class="mt-2">
                <a href="/quiz-selector" class="btn btn-dark btn-sm">Take Quiz</a>
              </div>
            </div></div>
          </div>
        </div>

        <div class="row mt-4 g-3">
          <div class="col-md-6">
            <div class="card h-100 border-0 shadow-sm">
              <div class="card-body d-flex flex-column">
                <h5 class="mb-2">🤖 AI Tutor</h5>
                <p class="text-muted">Ask questions across CPP domains, get clear explanations and study guidance.</p>
                <a href="/study" class="btn btn-primary mt-auto btn-enhanced">Open Tutor</a>
              </div>
            </div>
          </div>
          <div class="col-md-6">
            <div class="card h-100 border-0 shadow-sm">
              <div class="card-body d-flex flex-column">
                <h5 class="mb-2">🃏 Flashcards</h5>
                <p class="text-muted">Spaced practice with instant flip (<span class="kbd">J</span>) and next (<span class="kbd">K</span>). Unlimited per session.</p>
                <a href="/flashcards" class="btn btn-secondary mt-auto btn-enhanced">Open Flashcards</a>
              </div>
            </div>
          </div>

          <div class="col-md-6">
            <div class="card h-100 border-0 shadow-sm">
              <div class="card-body d-flex flex-column">
                <h5 class="mb-2">📝 Practice Quizzes</h5>
                <p class="text-muted">Build custom quizzes: choose domain, difficulty, and question count.</p>
                <a href="/quiz-selector" class="btn btn-success mt-auto btn-enhanced">Start a Quiz</a>
              </div>
            </div>
          </div>

          <div class="col-md-6">
            <div class="card h-100 border-0 shadow-sm">
              <div class="card-body d-flex flex-column">
                <h5 class="mb-2">🏁 Mock Exam</h5>
                <p class="text-muted">Full exam simulation with 25/50/75/100 questions across all domains.</p>
                <a href="/mock-exam" class="btn btn-warning mt-auto btn-enhanced">Start Mock Exam</a>
              </div>
            </div>
          </div>
        </div>

      </div>
    </div>
    """)
    content = tmpl.substitute(
        first_name=user.first_name,
        days_left=days_left,
        study_time=(user.study_time or 0),
        overall_pct=overall_pct
    )
    return render_base_template("Dashboard", content, user=user)

# --------------------------------- Study Chat ---------------------------------
@app.route('/study')
@subscription_required
def study():
    user = User.query.get(session['user_id'])
    session['study_start_time'] = datetime.utcnow().timestamp()

    domain_chips_html = ''.join([
        '<span class="domain-chip" data-domain="{}">{}</span>'.format(k, v["name"])
        for k, v in CPP_DOMAINS.items()
    ])

    content = Template("""
    <div class="row">
      <div class="col-md-8 mx-auto">
        <div class="card border-0 shadow">
          <div class="card-header d-flex align-items-center gap-3 bg-primary text-white">
            <img src="https://robohash.org/ai-tutor?set=set3&size=120x120" alt="AI Tutor" class="rounded-circle" width="48" height="48" />
            <div>
              <h4 class="mb-0">🤖 AI Tutor</h4>
              <small>Expert guidance across all CPP domains</small>
            </div>
          </div>
          <div class="card-body">
            <div class="mb-3">
              <div class="mb-2"><strong>Select a domain for focused discussion:</strong></div>
              <div class="mb-3">$chips</div>
            </div>
            <div id="intro" class="alert alert-info border-0" style="display:none;"></div>

            <div id="chat" style="height: 400px; overflow-y: auto; border: 1px solid #e9ecef; border-radius: 8px; padding: 12px; margin-bottom: 16px; background: #fafafa;"></div>

            <div class="row">
              <div class="col-md-9">
                <div class="input-group">
                  <input type="text" id="userInput" class="form-control" placeholder="Ask about any CPP topic..." />
                  <button id="sendBtn" class="btn btn-primary btn-enhanced">Send</button>
                </div>
              </div>
              <div class="col-md-3">
                <div class="card border-0 bg-light">
                  <div class="card-body py-2">
                    <div class="fw-bold mb-2 small">💡 Quick Suggestions</div>
                    <div id="sugs">
                      <div class="small text-muted">Select a domain above to see topic suggestions</div>
                      <ul id="sugList" class="mt-2 mb-0 small" style="padding-left:16px; line-height:1.6;"></ul>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <div class="small text-muted mt-3 text-center">
              💡 <strong>Tip:</strong> Start with "Explain like I'm new to..." for gentle introductions to complex topics.
            </div>
          </div>
        </div>
      </div>
    </div>
    <script>
      const chatDiv = document.getElementById('chat');
      const input = document.getElementById('userInput');
      const sendBtn = document.getElementById('sendBtn');
      const introDiv = document.getElementById('intro');
      const sugList = document.getElementById('sugList');

      const domainSnippets = {
        "security-principles": "Security Principles & Practices: risk management, governance, defense-in-depth, and security program development.",
        "business-principles": "Business Principles & Practices: budgeting, contracts, vendor management, and aligning security with business objectives.",
        "investigations": "Investigations: planning, evidence collection, interviewing techniques, and reporting procedures.",
        "personnel-security": "Personnel Security: background screening, onboarding, insider threat mitigation, and termination processes.",
        "physical-security": "Physical Security: CPTED principles, access control systems, barriers, lighting, and surveillance technologies.",
        "information-security": "Information Security: data protection, incident response, cyber risk management, and security awareness.",
        "crisis-management": "Crisis Management: business continuity planning, disaster recovery, emergency response, and crisis communications."
      };

      const domainSuggestions = {
        "security-principles": ["What is defense in depth and why is it important?", "How do I conduct a basic risk assessment?", "What KPIs should I track for a security program?"],
        "business-principles": ["How do I build a security budget from scratch?", "What's the difference between CapEx and OpEx in security?", "How do I manage security vendors effectively?"],
        "investigations": ["What are chain of custody best practices?", "How do interview and interrogation differ?", "What are key sources for open-source intelligence?"],
        "personnel-security": ["How do I design an effective background check program?", "What are early indicators of insider threats?", "What should be included in a termination checklist?"],
        "physical-security": ["What are the key layers of physical protection?", "How can I implement CPTED principles cost-effectively?", "What access control model fits my organization?"],
        "information-security": ["What are the phases of incident response?", "How do password policies compare to MFA?", "What makes an effective phishing awareness program?"],
        "crisis-management": ["What's the difference between BCP and DR?", "How do I create a crisis communications plan?", "What makes a good tabletop exercise?"]
      };

      function append(role, text) {
        const el = document.createElement('div');
        el.className = role === 'user' ? 'text-end mb-3' : 'text-start mb-3';
        const badgeClass = role === 'user' ? 'bg-primary' : 'bg-secondary';
        const badgeText = role === 'user' ? 'You' : '🤖 Tutor';
        el.innerHTML = '<span class="badge ' + badgeClass + ' mb-1">' + badgeText + '</span>' +
                       '<div class="p-3 border rounded shadow-sm bg-white" style="max-width: 85%; margin-' + (role === 'user' ? 'left' : 'right') + ': auto;">' + 
                       text.replace(/\\*\\*([^*]+)\\*\\*/g, '<strong>$1</strong>').replace(/</g,'&lt;').replace(/&lt;strong&gt;/g, '<strong>').replace(/&lt;\/strong&gt;/g, '</strong>') + 
                       '</div>';
        chatDiv.appendChild(el);
        chatDiv.scrollTop = chatDiv.scrollHeight;
      }

      async function send() {
        const q = input.value.trim();
        if (!q) return;
        append('user', q);
        input.value = '';
        sendBtn.disabled = true;
        sendBtn.textContent = 'Thinking...';
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
          append('assistant', 'Network error. Please check your connection and try again.');
        } finally {
          sendBtn.disabled = false;
          sendBtn.textContent = 'Send';
        }
      }
      sendBtn.addEventListener('click', send);
      input.addEventListener('keydown', (e) => { if (e.key === 'Enter' && !sendBtn.disabled) send(); });

      document.querySelectorAll('.domain-chip').forEach(chip => {
        chip.addEventListener('click', () => {
          document.querySelectorAll('.domain-chip').forEach(c => c.classList.remove('active'));
          chip.classList.add('active');
          const dom = chip.getAttribute('data-domain');
          introDiv.style.display = 'block';
          introDiv.innerHTML = '<strong>📖 ' + chip.textContent + '</strong><br>' + (domainSnippets[dom] || 'General CPP domain overview.');
          const list = domainSuggestions[dom] || [];
          sugList.innerHTML = '';
          list.forEach(s => {
            const li = document.createElement('li');
            const a = document.createElement('a');
            a.href = '#'; a.textContent = s; a.className = 'text-decoration-none';
            a.addEventListener('click', (ev) => { ev.preventDefault(); input.value = s; input.focus(); });
            li.appendChild(a);
            sugList.appendChild(li);
          });
        });
      });
    </script>
    """)
    return render_base_template("Study", content.substitute(chips=domain_chips_html), user=user)

@app.route('/chat', methods=['POST'])
@subscription_required
def chat():
    try:
        data = request.get_json() or {}
        user_message = (data.get('message') or '').strip()
        if not user_message:
            return jsonify({'error': 'Empty message'}), 400

        user_id = session['user_id']

        # Load or create chat history
        ch = ChatHistory.query.filter_by(user_id=user_id).first()
        if not ch:
            ch = ChatHistory(user_id=user_id, messages='[]')
            db.session.add(ch)
            db.session.commit()

        try:
            messages = json.loads(ch.messages) if ch.messages else []
        except json.JSONDecodeError:
            messages = []

        # Trim history for safety
        if len(messages) > 20:
            messages = messages[-20:]

        messages.append({'role': 'user', 'content': user_message, 'timestamp': datetime.utcnow().isoformat()})
        openai_messages = [{'role': m['role'], 'content': m['content']} for m in messages]

        ai_response = chat_with_ai(openai_messages, user_id=user_id)
        messages.append({'role': 'assistant', 'content': ai_response, 'timestamp': datetime.utcnow().isoformat()})

        ch.messages = json.dumps(messages)
