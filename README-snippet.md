# CPP Exam Prep – Deployment Snippet

## Required environment
- SECRET_KEY=... (non-default in prod)
- SESSION_COOKIE_SECURE=1 (recommended in prod)
- APP_VERSION=1.0.0
- Data_Dir or DATA_DIR (fallback to ./data)
- OPENAI_API_KEY, OPENAI_API_BASE, OPENAI_CHAT_MODEL (optional; tutor degrades gracefully if missing)
- STRIPE_SECRET_KEY, STRIPE_PUBLISHABLE_KEY, STRIPE_MONTHLY_PRICE_ID, STRIPE_SIXMONTH_PRICE_ID, STRIPE_WEBHOOK_SECRET (optional but required for billing)
- ADMIN_PASSWORD=...
- FLASK_DEBUG=0
- WEB_CONCURRENCY (Render)

## Local run
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export FLASK_DEBUG=1 SECRET_KEY="dev-not-default" SESSION_COOKIE_SECURE=0
export DATA_DIR="$(pwd)/data"
gunicorn "app:app" --reload
