# CHANGELOG

## 2025-09-02
- Env hardening: DATA_DIR fallback, _env_bool(), SECRET_KEY safety check.
- Cookies: SESSION_COOKIE_SECURE, SESSION_COOKIE_SAMESITE=Lax; WTF_CSRF_TIME_LIMIT=None.
- ProxyFix enabled for Render (X-Forwarded-*).
- CSRF: exempted /stripe/webhook when Flask-WTF present.
- Stripe: robust webhook guard when STRIPE_WEBHOOK_SECRET missing; safer logging.
- JSON I/O: atomic _save_json with fsync + os.replace.
- /healthz: added app_version, data_dir_exists, data_dir_writable probe.
- Logging: request timing logger (method, path, status, duration, X-Request-ID).
- requirements.txt: deduped requests pin to 2.32.3.
