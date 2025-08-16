# ------------------------------ Flashcards API -------------------------------
@app.get("/api/flashcards")
@subscription_required
def api_flashcards():
    """
    Returns a batch of flashcards as JSON.
    - domain: specific domain slug or 'random'
    - count:  number of cards to fetch (bounded 1..100); sessions can request again for 'unlimited'
    Behavior:
      1) Try pulling verified items from QuestionBank (random order).
      2) On any DB/model error or empty result, fall back to the static generator.
    """
    domain = (request.args.get("domain") or "random").strip().lower()
    try:
        count = int(request.args.get("count", 50))
    except ValueError:
        count = 50
    count = max(1, min(100, count))

    cards = []

    # Try database-backed questions first (if the model exists & query succeeds).
    rows = []
    try:
        QuestionBank = globals().get("QuestionBank")  # may not exist in all deployments
        if QuestionBank is not None:
            q = QuestionBank.query.filter_by(is_verified=True)
            if domain and domain != "random":
                q = q.filter(QuestionBank.domain == domain)
            # Random order; works on Postgres
            q = q.order_by(text("random()")).limit(count)
            rows = q.all()
    except Exception as e:
        print(f"DB question fetch error: {e}")
        rows = []

    # Convert DB rows to cards
    for r in rows:
        front = getattr(r, "question", "") or ""
        back = getattr(r, "explanation", "") or ""
        # options_json may not parse; guard with try/except (THIS WAS THE MISSING EXCEPT)
        try:
            opts_json = getattr(r, "options_json", None)
            opts = json.loads(opts_json) if opts_json else {}
        except Exception:
            opts = {}
        corr = getattr(r, "correct", None)
        if corr and opts.get(corr):
            if back:
                back = back + "\n\nCorrect: " + corr + ") " + str(opts.get(corr))
            else:
                back = "Correct: " + corr + ") " + str(opts.get(corr))
        cards.append({
            "q": front,
            "a": back or "See reference materials.",
            "domain": getattr(r, "domain", "general"),
        })

    # If nothing came from DB, fall back to the static generator
    if not cards:
        fb = generate_fallback_quiz(
            quiz_type="practice",
            domain=None if domain == "random" else domain,
            difficulty="medium",
            num_questions=count
        )
        for q in fb.get("questions", []):
            back = q.get("explanation", "") or ""
            opts = q.get("options", {}) or {}
            corr = q.get("correct")
            if corr and opts.get(corr):
                if back:
                    back = back + "\n\nCorrect: " + corr + ") " + str(opts.get(corr))
                else:
                    back = "Correct: " + corr + ") " + str(opts.get(corr))
            cards.append({
                "q": q.get("question", ""),
                "a": back or "See reference materials.",
                "domain": q.get("domain", "general"),
            })

    return jsonify({"cards": cards, "count": len(cards)})
