# -*- coding: utf-8 -*-
"""
Complete CPP Test Prep Platform
A comprehensive Flask application for ASIS CPP exam preparation
"""

import os
import re
import json
import time
import uuid
import hashlib
import random
import html
import logging
import math
import io
import difflib
from datetime import datetime, timedelta
from typing import Any, Dict, List, Tuple, Optional
from urllib.parse import quote as _urlquote
import urllib.request as _urlreq
import urllib.error as _urlerr

from flask import (
    Flask, request, session, redirect, url_for, abort, jsonify, make_response, g
)
from flask import render_template_string
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix

# ====================================================================================================
# APPLICATION SETUP & CONFIGURATION
# ====================================================================================================

APP_VERSION = "2.0.0"

def _env_bool(val: str | None, default: bool = False) -> bool:
    s = (val if val is not None else ("1" if default else "0")).strip().lower()
    return s in ("1", "true", "yes", "y", "on")

IS_STAGING = _env_bool(os.environ.get("STAGING", "0"), default=False)
DEBUG = _env_bool(os.environ.get("DEBUG", "0"), default=False)

SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-change-me")
SESSION_COOKIE_SECURE_FLAG = _env_bool(os.environ.get("SESSION_COOKIE_SECURE", "1"), default=True)

if (SESSION_COOKIE_SECURE_FLAG or not DEBUG) and SECRET_KEY == "dev-secret-change-me":
    raise RuntimeError(
        "SECURITY: SECRET_KEY must be set to a non-default value when running with "
        "SESSION_COOKIE_SECURE=1 or when DEBUG is false."
    )

app = Flask(__name__)
app.secret_key = SECRET_KEY

app.config.update(
    SESSION_COOKIE_SECURE=SESSION_COOKIE_SECURE_FLAG,
    SESSION_COOKIE_SAMESITE="Lax",
    WTF_CSRF_TIME_LIMIT=None,
)

app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

# Logging setup
logger = logging.getLogger("cpp_prep")
handler = logging.StreamHandler()
fmt = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
handler.setFormatter(fmt)
logger.setLevel(logging.INFO)
logger.addHandler(handler)

# Paths & Data
DATA_DIR = (
    os.environ.get("DATA_DIR")
    or os.environ.get("Data_Dir")
    or os.path.join(os.getcwd(), "data")
)
os.makedirs(DATA_DIR, exist_ok=True)

BANK_DIR = os.path.join(DATA_DIR, "bank")
os.makedirs(BANK_DIR, exist_ok=True)

# OpenAI Configuration
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
OPENAI_API_BASE = os.environ.get("OPENAI_API_BASE", "https://api.openai.com/v1")
OPENAI_CHAT_MODEL = os.environ.get("OPENAI_CHAT_MODEL", "gpt-4o-mini")

# Admin Configuration
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")

# CSRF Protection
try:
    from flask_wtf import CSRFProtect
    from flask_wtf.csrf import generate_csrf
    csrf = CSRFProtect(app)
    HAS_CSRF = True
except Exception:
    csrf = None
    HAS_CSRF = False
    def generate_csrf() -> str:
        return ""

def csrf_token() -> str:
    if HAS_CSRF:
        return generate_csrf()
    val = session.get("_csrf_token")
    if not val:
        val = uuid.uuid4().hex
        session["_csrf_token"] = val
    return val

def _csrf_ok() -> bool:
    if HAS_CSRF:
        return True
    return (request.form.get("csrf_token") == session.get("_csrf_token"))

# Rate limiting
_RATE = {}
def _rate_ok(key: str, per_sec: float = 1.0) -> bool:
    t = time.time()
    last = _RATE.get(key, 0.0)
    if (t - last) < (1.0 / per_sec):
        return False
    _RATE[key] = t
    return True

# Security Headers
CSP = (
    "default-src 'self' https:; "
    "img-src 'self' data: https:; "
    "style-src 'self' 'unsafe-inline' https:; "
    "script-src 'self' 'unsafe-inline' https:; "
    "font-src 'self' https: data:; "
    "connect-src 'self' https:; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "form-action 'self'"
)

@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer-when-downgrade"
    resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    resp.headers.setdefault("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
    resp.headers["Content-Security-Policy"] = CSP
    return resp

# Request logging
@app.before_request
def _reqlog_start():
    g._req_t0 = time.time()

@app.after_request
def _reqlog_end(resp):
    try:
        p = request.path or ""
        if p.startswith("/static") or p == "/favicon.ico":
            return resp
        dur_ms = int((time.time() - getattr(g, "_req_t0", time.time())) * 1000)
        rid = request.headers.get("X-Request-ID", "")
        rid_sfx = f" req_id={rid}" if rid else ""
        logger.info("REQ %s %s -> %s %dms%s", request.method, p, resp.status_code, dur_ms, rid_sfx)
    except Exception:
        pass
    return resp

# ====================================================================================================
# DATA LAYER & UTILITIES
# ====================================================================================================

def _path(name: str) -> str:
    return os.path.join(DATA_DIR, name)

def _load_json(name: str, default):
    p = _path(name)
    try:
        if not os.path.exists(p):
            return default
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.warning("load_json %s failed: %s", name, e)
        return default

def _save_json(name: str, data):
    p = _path(name)
    tmp = f"{p}.tmp"
    try:
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, p)
    except Exception as e:
        logger.warning("save_json %s failed: %s", name, e)
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except Exception:
            pass

def _atomic_write_bytes(path: str, data: bytes) -> None:
    d = os.path.dirname(path) or "."
    os.makedirs(d, exist_ok=True)
    tmp_path = path + ".tmp"
    with open(tmp_path, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_path, path)

def _atomic_write_text(path: str, text: str) -> None:
    _atomic_write_bytes(path, text.encode("utf-8"))

def _read_jsonl(path: str) -> List[Dict[str, Any]]:
    if not os.path.exists(path):
        return []
    out: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except Exception:
                continue
    return out

def _write_jsonl(path: str, rows: List[Dict[str, Any]]) -> None:
    buf = io.StringIO()
    for r in rows:
        buf.write(json.dumps(r, ensure_ascii=False))
        buf.write("\n")
    _atomic_write_text(path, buf.getvalue())

# ====================================================================================================
# USER MANAGEMENT
# ====================================================================================================

def _users_all() -> List[dict]:
    return _load_json("users.json", [])

def _find_user(email: str) -> dict | None:
    email = (email or "").strip().lower()
    for u in _users_all():
        if (u.get("email") or "").lower() == email:
            return u
    return None

def _update_user(uid: str, patch: dict):
    users = _users_all()
    for u in users:
        if u.get("id") == uid:
            u.update(patch or {})
            break
    _save_json("users.json", users)

def _create_user(email: str, password: str) -> Tuple[bool, str]:
    email = (email or "").strip().lower()
    if not email or not password or len(password) < 8:
        return False, "Please provide a valid email and a password with at least 8 characters."
    if _find_user(email):
        return False, "User already exists."
    users = _users_all()
    uid = uuid.uuid4().hex
    users.append({
        "id": uid,
        "email": email,
        "password_hash": generate_password_hash(password),
        "subscription": "inactive",
        "terms_accept_version": "",
        "terms_accept_ts": ""
    })
    _save_json("users.json", users)
    return True, uid

def validate_password(pw: str) -> Tuple[bool, str]:
    if not pw or len(pw) < 8:
        return False, "Password must be at least 8 characters."
    return True, ""

def _user_id() -> str:
    return session.get("uid", "")

def _login_redirect_url(next_path: str | None = None) -> str:
    next_val = next_path or request.path or "/"
    return f"/login?next={_urlquote(next_val)}"

def login_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not _user_id():
            return redirect(_login_redirect_url(request.path))
        return fn(*args, **kwargs)
    return wrapper

def is_admin() -> bool:
    return bool(session.get("admin_ok"))

# ====================================================================================================
# CPP DOMAIN DEFINITIONS & WEIGHTINGS
# ====================================================================================================

# CPP Exam Domains with official weightings
CPP_DOMAINS = {
    "domain1": {
        "name": "Security Principles & Practices", 
        "weight": 0.22,
        "code": "D1"
    },
    "domain2": {
        "name": "Business Principles & Practices", 
        "weight": 0.15,
        "code": "D2"
    },
    "domain3": {
        "name": "Investigations", 
        "weight": 0.09,
        "code": "D3"
    },
    "domain4": {
        "name": "Personnel Security", 
        "weight": 0.11,
        "code": "D4"
    },
    "domain5": {
        "name": "Physical Security", 
        "weight": 0.16,
        "code": "D5"
    },
    "domain6": {
        "name": "Information Security", 
        "weight": 0.14,
        "code": "D6"
    },
    "domain7": {
        "name": "Crisis Management", 
        "weight": 0.13,
        "code": "D7"
    }
}

# Question type distributions
QUESTION_TYPE_MIX = {
    "mc": 0.50,        # 50% Multiple Choice
    "tf": 0.25,        # 25% True/False  
    "scenario": 0.25,  # 25% Scenario
}

# File paths for content bank
_QUESTIONS_FILE = os.path.join(BANK_DIR, "questions.jsonl")
_FLASHCARDS_FILE = os.path.join(BANK_DIR, "flashcards.jsonl")
_WEIGHTS_FILE = os.path.join(BANK_DIR, "weights.json")

# ====================================================================================================
# CONTENT BANK MANAGEMENT
# ====================================================================================================

def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"

def _norm_text(s: str) -> str:
    return " ".join(str(s).strip().lower().split())

def _q_signature(q: Dict[str, Any]) -> str:
    """Generate signature for question deduplication"""
    t = q.get("type", "").lower()
    stem = _norm_text(q.get("stem", ""))
    if t == "mc":
        choices = [_norm_text(c) for c in q.get("choices", [])]
        choices.sort()
        base = stem + "||" + "|".join(choices)
    elif t in ("tf", "truefalse", "true_false"):
        base = stem + "||tf"
    else:  # scenario
        opts = [_norm_text(c) for c in q.get("options", [])]
        opts.sort()
        base = stem + "||" + "|".join(opts)
    return hashlib.sha256(base.encode("utf-8")).hexdigest()

def _looks_like_dup(a: str, b: str, threshold: float = 0.92) -> bool:
    """Fuzzy duplicate detection"""
    ra = _norm_text(a); rb = _norm_text(b)
    if not ra or not rb:
        return False
    return difflib.SequenceMatcher(a=ra, b=rb).ratio() >= threshold

def get_domain_weights() -> Dict[str, float]:
    """Get domain weights, create defaults if missing"""
    default = {f"Domain {i+1}": info["weight"] for i, info in enumerate(CPP_DOMAINS.values())}
    data = _load_json(_WEIGHTS_FILE, None)
    if not data:
        _save_json(_WEIGHTS_FILE, default)
        return default
    try:
        total = float(sum(float(v) for v in data.values())) or 1.0
        return {k: float(v)/total for k, v in data.items()}
    except Exception:
        return default

def get_all_questions(domains: Optional[List[str]] = None,
                      types: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    rows = _read_jsonl(_QUESTIONS_FILE)
    if domains:
        dset = set([d.lower() for d in domains])
        rows = [r for r in rows if str(r.get("domain","")).lower() in dset]
    if types:
        tset = set([t.lower() for t in types])
        rows = [r for r in rows if str(r.get("type","")).lower() in tset]
    return rows

def get_all_flashcards(domains: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    rows = _read_jsonl(_FLASHCARDS_FILE)
    if domains:
        dset = set([d.lower() for d in domains])
        rows = [r for r in rows if str(r.get("domain","")).lower() in dset]
    return rows

def ingest_questions(new_items: List[Dict[str, Any]], source: str = "upload") -> Tuple[int,int]:
    """Ingest questions with deduplication"""
    existing = _read_jsonl(_QUESTIONS_FILE)
    seen_sigs = { _q_signature(q) for q in existing }
    existing_stems = [ _norm_text(q.get("stem","")) for q in existing ]

    added, skipped = 0, 0
    out = list(existing)
    now = int(time.time())
    
    for raw in new_items:
        q = dict(raw)
        q.setdefault("id", _new_id("q"))
        q.setdefault("source", source)
        q.setdefault("created_at", now)

        # Normalize type
        t = str(q.get("type","")).lower().strip()
        if t in ("truefalse", "true_false"):
            t = "tf"
        elif t in ("multiplechoice", "multiple_choice"):
            t = "mc"
        elif t in ("scenario", "scn"):
            t = "scenario"
        q["type"] = t

        # Validate
        if not q.get("stem") or not q.get("domain") or t not in ("mc","tf","scenario"):
            skipped += 1
            continue

        sig = _q_signature(q)
        stem_norm = _norm_text(q.get("stem",""))

        if sig in seen_sigs:
            skipped += 1
            continue
        if any(_looks_like_dup(stem_norm, s) for s in existing_stems):
            skipped += 1
            continue

        out.append(q)
        seen_sigs.add(sig)
        existing_stems.append(stem_norm)
        added += 1

    _write_jsonl(_QUESTIONS_FILE, out)
    logger.info("Bank ingest: questions added=%s skipped=%s total=%s", added, skipped, len(out))
    return added, skipped

def ingest_flashcards(new_items: List[Dict[str, Any]], source: str = "upload") -> Tuple[int,int]:
    """Ingest flashcards with deduplication"""
    existing = _read_jsonl(_FLASHCARDS_FILE)
    
    def f_sig(fc: Dict[str, Any]) -> str:
        base = _norm_text(fc.get("front","")) + "||" + _norm_text(fc.get("back",""))
        return hashlib.sha256(base.encode("utf-8")).hexdigest()

    seen = { f_sig(x) for x in existing }
    existing_fronts = [ _norm_text(x.get("front","")) for x in existing ]

    added, skipped = 0, 0
    out = list(existing)
    now = int(time.time())

    for raw in new_items:
        fc = dict(raw)
        if not fc.get("front") or not fc.get("back") or not fc.get("domain"):
            skipped += 1
            continue
        fc.setdefault("id", _new_id("fc"))
        fc.setdefault("source", source)
        fc.setdefault("created_at", now)
        sig = f_sig(fc)
        if sig in seen:
            skipped += 1
            continue
        if any(_looks_like_dup(_norm_text(fc.get("front","")), s) for s in existing_fronts):
            skipped += 1
            continue
        out.append(fc)
        seen.add(sig)
        existing_fronts.append(_norm_text(fc.get("front","")))
        added += 1

    _write_jsonl(_FLASHCARDS_FILE, out)
    logger.info("Bank ingest: flashcards added=%s skipped=%s total=%s", added, skipped, len(out))
    return added, skipped

# ====================================================================================================
# SELECTION ENGINE
# ====================================================================================================

def _canonical_type(t: str) -> str:
    t = (t or "").lower().strip()
    if t in ("multiplechoice","multiple_choice"): return "mc"
    if t in ("truefalse","true_false"): return "tf"
    if t in ("scn",): return "scenario"
    return t

def _rng_for_user_context(user_id: Optional[str]) -> random.Random:
    """Deterministic RNG per user/day for stable question sets"""
    try:
        day = int(time.time() // 86400)
        seed_str = f"{user_id or 'anon'}::{day}"
        seed = int(hashlib.sha256(seed_str.encode("utf-8")).hexdigest(), 16) % (2**31)
        return random.Random(seed)
    except Exception:
        return random.Random()

def _weighted_domain_allocation(domains: List[str], weights: Dict[str, float], total: int) -> Dict[str, int]:
    """Allocate questions across domains by weight"""
    if not domains:
        return {}
    
    # Normalize weights for selected domains
    local = {d: float(weights.get(d, 0.0)) for d in domains}
    if sum(local.values()) <= 0:
        # Equal split if no weights
        eq = max(1, total // max(1, len(domains)))
        alloc = {d: eq for d in domains}
        rem = total - sum(alloc.values())
        for d in domains[:rem]:
            alloc[d] += 1
        return alloc
    
    # Proportional allocation
    raw = {d: weights.get(d, 0.0) for d in domains}
    s = sum(raw.values()) or 1.0
    target = {d: (raw[d]/s)*total for d in domains}
    alloc = {d: int(math.floor(target[d])) for d in domains}
    rem = total - sum(alloc.values())
    
    # Distribute remainder by largest fractional parts
    fr = sorted(domains, key=lambda d: target[d]-alloc[d], reverse=True)
    for d in fr[:rem]:
        alloc[d] += 1
    return alloc

def _split_type_mix(n: int, mix: Dict[str, float]) -> Dict[str, int]:
    """Split questions by type according to mix percentages"""
    mix = { _canonical_type(k): float(v) for k, v in mix.items() }
    alloc = {k: int(math.floor(n * mix.get(k, 0.0))) for k in mix}
    rem = n - sum(alloc.values())
    
    residuals = sorted(mix.keys(), key=lambda k: (n*mix[k]) - alloc[k], reverse=True)
    for k in residuals[:rem]:
        alloc[k] += 1
    
    out = {"mc": alloc.get("mc",0), "tf": alloc.get("tf",0), "scenario": alloc.get("scenario",0)}
    delta = n - sum(out.values())
    for k in ("mc","tf","scenario"):
        if delta == 0: break
        out[k] += 1
        delta -= 1
    return out

def _filter_by_type(rows: List[Dict[str, Any]], t: str) -> List[Dict[str, Any]]:
    t = _canonical_type(t)
    return [r for r in rows if _canonical_type(r.get("type","")) == t]

def select_questions(domains: List[str],
                     count: int,
                     mix: Optional[Dict[str, float]] = None,
                     user_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Core question selection engine"""
    mix = mix or dict(QUESTION_TYPE_MIX)
    weights = get_domain_weights()
    rng = _rng_for_user_context(user_id)

    domains = list(domains or [])
    if not domains:
        domains = list(weights.keys())

    per_domain = _weighted_domain_allocation(domains, weights, count)
    inventory_by_domain = {d: get_all_questions(domains=[d]) for d in domains}

    selected: List[Dict[str, Any]] = []

    for d, n_d in per_domain.items():
        if n_d <= 0:
            continue
        pool = inventory_by_domain.get(d, [])
        if not pool:
            continue
        
        t_alloc = _split_type_mix(n_d, mix)

        for t, need in t_alloc.items():
            if need <= 0: 
                continue
            sub = _filter_by_type(pool, t)
            if len(sub) <= need:
                selected.extend(sub)
            else:
                selected.extend(rng.sample(sub, need))

    # Backfill if short
    short = count - len(selected)
    if short > 0:
        remaining = [q for d in domains for q in inventory_by_domain.get(d, []) if q not in selected]
        if len(remaining) >= short:
            selected.extend(rng.sample(remaining, short))
        else:
            selected.extend(remaining)
            all_pool = get_all_questions()
            extra = [q for q in all_pool if q not in selected]
            extra_need = count - len(selected)
            if extra_need > 0 and len(extra) > 0:
                take = min(extra_need, len(extra))
                selected.extend(rng.sample(extra, take))

    if len(selected) > count:
        selected = selected[:count]

    return selected

# ====================================================================================================
# AI TUTOR SYSTEM
# ====================================================================================================

def _ai_enabled() -> bool:
    return bool(OPENAI_API_KEY)

def _openai_chat_completion(user_prompt: str) -> Tuple[bool, str]:
    """Call OpenAI API for tutor responses"""
    if not _ai_enabled():
        return False, ("Tutor is currently in offline mode. "
                       "No API key configured. You can still study with flashcards, quizzes, and mock exams.")
    
    url = f"{OPENAI_API_BASE.rstrip('/')}/chat/completions"
    sys_prompt = (
        "You are an expert CPP (Certified Protection Professional) study tutor. "
        "Explain clearly, cite general best practices, and avoid proprietary or member-only ASIS content. "
        "Keep answers concise and actionable. When useful, give short bullet points or an example scenario. "
        "Never claim this platform is ASIS-approved. "
        "Always include this disclaimer: 'This program is not affiliated with or approved by ASIS International.'"
    )
    
    payload = {
        "model": OPENAI_CHAT_MODEL,
        "messages": [
            {"role": "system", "content": sys_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": 0.2,
        "max_tokens": 700,
    }
    
    data = json.dumps(payload).encode("utf-8")
    req = _urlreq.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {OPENAI_API_KEY}",
        },
        method="POST",
    )
    
    try:
        with _urlreq.urlopen(req, timeout=25) as resp:
            raw = resp.read().decode("utf-8", "ignore")
            obj = json.loads(raw)
            msg = (obj.get("choices") or [{}])[0].get("message", {}).get("content", "")
            if not msg:
                return False, "The Tutor did not return a response. Please try again."
            return True, msg.strip()
    except _urlerr.HTTPError as e:
        try:
            err_body = e.read().decode("utf-8", "ignore")
        except Exception:
            err_body = str(e)
        logger.warning("Tutor HTTPError: %s %s", e, err_body)
        return False, "Tutor request failed. Please try again."
    except Exception as e:
        logger.warning("Tutor error: %s", e)
        return False, "Tutor is temporarily unavailable. Please try again."

# ====================================================================================================
# EVENT LOGGING
# ====================================================================================================

def _log_event(uid: str, name: str, data: dict | None = None):
    evts = _load_json("events.json", [])
    evts.append({
        "ts": datetime.utcnow().isoformat() + "Z",
        "user_id": uid,
        "name": name,
        "data": data or {}
    })
    _save_json("events.json", evts)

def _append_attempt(uid: str, mode: str, score: int = None, total: int = None, 
                   domain: str = None, question: str = None, answer: str = None):
    rec = {
        "ts": datetime.utcnow().isoformat() + "Z",
        "user_id": uid,
        "mode": mode,
        "score": score,
        "total": total,
        "domain": domain,
        "question": question,
        "answer": answer
    }
    attempts = _load_json("attempts.json", [])
    attempts.append(rec)
    _save_json("attempts.json", attempts)

# ====================================================================================================
# UI HELPERS & BASE LAYOUT
# ====================================================================================================

def _footer_html():
    return """
    <footer class="mt-5 py-3 border-top text-center small text-muted">
      <div>
        Educational use only. Not affiliated with ASIS International. No legal, safety, or professional advice.
        Use official sources to verify. No guarantee of results. &copy; CPP-Exam-Prep
        &nbsp;•&nbsp;<a class="text-decoration-none" href="/terms">Terms &amp; Conditions</a>
      </div>
    </footer>
    """

def base_layout(title: str, body_html: str) -> str:
    tpl = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{ title }} — CPP Exam Prep</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css" rel="stylesheet">
  <style>
    .fc-card .front, .fc-card .back { min-height: 120px; padding: 1rem; border: 1px solid #ddd; border-radius: .5rem; }
    .fc-card .front { background: #f8f9fa; }
  </style>
</head>
<body>
  <nav class="navbar navbar-expand-lg bg-light border-bottom">
    <div class="container">
      <a class="navbar-brand" href="/"><i class="bi bi-shield-lock"></i> CPP Prep</a>
      <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navContent">
        <span class="navbar-toggler-icon"></span>
      </button>
      <div id="navContent" class="collapse navbar-collapse">
        <div class="ms-auto d-flex align-items-center gap-3">
          <a class="text-decoration-none" href="/flashcards">Flashcards</a>
          <a class="text-decoration-none" href="/quiz">Quiz</a>
          <a class="text-decoration-none" href="/mock">Mock Exam</a>
          <a class="text-decoration-none" href="/tutor">Tutor</a>
          <a class="text-decoration-none" href="/progress">Progress</a>
          {% if session.get('uid') %}
            <a class="btn btn-outline-danger btn-sm" href="/logout">Logout</a>
          {% else %}
            <a class="btn btn-outline-primary btn-sm" href="/login">Login</a>
          {% endif %}
        </div>
      </div>
    </div>
  </nav>

  <main class="py-4">
    {{ body_html | safe }}
  </main>

  {{ footer | safe }}

  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
    """
    return render_template_string(tpl, title=(title or "CPP Exam Prep"), body_html=body_html, footer=_footer_html())

def domain_buttons_html(selected_key="all", field_name="domain"):
    """Generate domain selection buttons"""
    buttons = []
    domains = ["all"] + [f"domain{i+1}" for i in range(7)]
    labels = {
        "all": "All Domains",
        "domain1": "D1: Security Principles",
        "domain2": "D2: Business Principles", 
        "domain3": "D3: Investigations",
        "domain4": "D4: Personnel Security",
        "domain5": "D5: Physical Security",
        "domain6": "D6: Information Security",
        "domain7": "D7: Crisis Management"
    }
    
    for domain in domains:
        active = " active" if selected_key == domain else ""
        label = labels.get(domain, domain)
        buttons.append(
            f'<button type="button" class="btn btn-outline-success domain-btn{active}" '
            f'data-value="{html.escape(domain)}">{html.escape(label)}</button>'
        )
    
    hidden = f'<input type="hidden" id="domain_val" name="{html.escape(field_name)}" value="{html.escape(selected_key)}"/>'
    return f'<div class="d-flex flex-wrap gap-2">{"".join(buttons)}</div>{hidden}'

# ====================================================================================================
# CONTENT GENERATION SYSTEM
# ====================================================================================================

class CPPContentGenerator:
    """Generate comprehensive CPP study content"""
    
    DOMAIN_CONTENT = {
        "Domain 1": {
            "name": "Security Principles & Practices",
            "topics": [
                "Risk Management", "Security Controls", "Physical Security Concepts",
                "Security Program Management", "Legal and Regulatory Compliance",
                "Professional Ethics", "Security Awareness", "Threat Assessment"
            ]
        },
        "Domain 2": {
            "name": "Business Principles & Practices", 
            "topics": [
                "Business Continuity", "Financial Management", "Procurement",
                "Contract Management", "Strategic Planning", "Performance Metrics",
                "Quality Assurance", "Vendor Management"
            ]
        },
        "Domain 3": {
            "name": "Investigations",
            "topics": [
                "Investigation Planning", "Evidence Collection", "Interview Techniques",
                "Report Writing", "Legal Considerations", "Surveillance",
                "Digital Forensics", "Case Management"
            ]
        },
        "Domain 4": {
            "name": "Personnel Security",
            "topics": [
                "Background Investigations", "Security Clearances", "Insider Threats",
                "Personnel Screening", "Access Controls", "Training Programs",
                "Behavioral Indicators", "Termination Procedures"
            ]
        },
        "Domain 5": {
            "name": "Physical Security",
            "topics": [
                "Perimeter Security", "Access Control Systems", "CCTV Systems",
                "Intrusion Detection", "Security Lighting", "Barriers",
                "Lock and Key Control", "Visitor Management"
            ]
        },
        "Domain 6": {
            "name": "Information Security",
            "topics": [
                "Data Classification", "Access Controls", "Encryption",
                "Network Security", "Incident Response", "Vulnerability Management",
                "Security Policies", "Awareness Training"
            ]
        },
        "Domain 7": {
            "name": "Crisis Management",
            "topics": [
                "Emergency Planning", "Incident Command", "Business Continuity",
                "Disaster Recovery", "Communications", "Evacuation Procedures",
                "Risk Assessment", "Recovery Operations"
            ]
        }
    }

    @classmethod
    def generate_flashcards(cls, target_count: int = 300) -> List[Dict[str, Any]]:
        """Generate comprehensive flashcard set"""
        flashcards = []
        
        # Calculate per-domain allocation
        total_weight = sum(CPP_DOMAINS[k]["weight"] for k in CPP_DOMAINS)
        allocations = {}
        for domain_key, domain_info in CPP_DOMAINS.items():
            allocations[f"Domain {int(domain_key[-1])}"] = int(target_count * domain_info["weight"] / total_weight)
        
        # Generate flashcards by domain
        for domain_name, count in allocations.items():
            domain_flashcards = cls._generate_domain_flashcards(domain_name, count)
            flashcards.extend(domain_flashcards)
        
        return flashcards

    @classmethod
    def _generate_domain_flashcards(cls, domain: str, count: int) -> List[Dict[str, Any]]:
        """Generate flashcards for specific domain"""
        flashcards = []
        domain_info = cls.DOMAIN_CONTENT.get(domain, {})
        topics = domain_info.get("topics", [])
        
        # Sample flashcard content by domain
        templates = cls._get_flashcard_templates(domain)
        
        for i in range(count):
            template = templates[i % len(templates)]
            flashcard = {
                "id": _new_id("fc"),
                "domain": domain,
                "front": template["front"],
                "back": template["back"], 
                "tags": template.get("tags", []),
                "source": "generated",
                "created_at": int(time.time())
            }
            flashcards.append(flashcard)
        
        return flashcards

    @classmethod
    def _get_flashcard_templates(cls, domain: str) -> List[Dict[str, Any]]:
        """Get flashcard templates by domain"""
        templates = {
            "Domain 1": [
                {"front": "What are the three primary categories of security controls?", 
                 "back": "Administrative (policies, procedures, training), Physical (barriers, locks, surveillance), and Technical (access controls, encryption, firewalls)", 
                 "tags": ["controls", "fundamentals"]},
                {"front": "Define Defense in Depth", 
                 "back": "A layered security strategy using multiple controls at different points to protect assets. If one layer fails, others continue to provide protection.", 
                 "tags": ["strategy", "layered-defense"]},
                {"front": "What is the CIA Triad?", 
                 "back": "Confidentiality (preventing unauthorized disclosure), Integrity (preventing unauthorized modification), Availability (ensuring authorized access when needed)", 
                 "tags": ["fundamentals", "CIA"]},
                {"front": "What is risk appetite?", 
                 "back": "The amount and type of risk an organization is willing to accept in pursuit of its objectives", 
                 "tags": ["risk-management"]},
                {"front": "Define residual risk", 
                 "back": "The risk that remains after controls have been implemented to reduce the inherent risk", 
                 "tags": ["risk-management"]},
            ],
            "Domain 2": [
                {"front": "What is ROI in security context?", 
                 "back": "Return on Investment - measures the financial benefit of security investments relative to their cost. Calculated as (Benefit - Cost) / Cost × 100%", 
                 "tags": ["business-case", "metrics"]},
                {"front": "Define Business Impact Analysis (BIA)", 
                 "back": "A process to identify critical business functions and assess the impact of their disruption over time, used to prioritize continuity planning efforts.", 
                 "tags": ["continuity", "analysis"]},
                {"front": "What is Maximum Tolerable Downtime (MTD)?", 
                 "back": "The longest period a business function can be unavailable before the organization suffers unacceptable consequences", 
                 "tags": ["continuity", "metrics"]},
                {"front": "Define Total Cost of Ownership (TCO)", 
                 "back": "The complete cost of a security solution including acquisition, implementation, operation, maintenance, and disposal costs", 
                 "tags": ["financial", "procurement"]},
            ],
            "Domain 3": [
                {"front": "What is Chain of Custody?", 
                 "back": "Documentation that tracks the seizure, custody, control, transfer, analysis, and disposition of evidence to ensure its integrity and admissibility.", 
                 "tags": ["evidence", "legal"]},
                {"front": "Name the four types of interview questions", 
                 "back": "Open-ended (broad, exploratory), Closed-ended (specific facts), Leading (suggests answer), and Hypothetical (what-if scenarios)", 
                 "tags": ["interviews", "techniques"]},
                {"front": "What is the Miranda Warning?", 
                 "back": "A legal requirement to inform suspects of their rights before custodial interrogation, including the right to remain silent and right to an attorney", 
                 "tags": ["legal", "interviews"]},
                {"front": "Define circumstantial evidence", 
                 "back": "Evidence that relies on inference to connect it to a conclusion of fact, as opposed to direct evidence which directly proves a fact", 
                 "tags": ["evidence", "legal"]},
            ],
            "Domain 4": [
                {"front": "What are the three phases of employment screening?", 
                 "back": "Pre-employment (background checks, reference verification), During employment (ongoing monitoring, performance reviews), Post-employment (exit procedures, access revocation)", 
                 "tags": ["screening", "lifecycle"]},
                {"front": "Define Insider Threat", 
                 "back": "A security risk posed by individuals within an organization who have authorized access and may use it to harm the organization intentionally or unintentionally.", 
                 "tags": ["insider-threat", "risk"]},
                {"front": "What is the purpose of a security clearance?", 
                 "back": "To ensure individuals with access to classified information are trustworthy and reliable based on background investigation", 
                 "tags": ["clearance", "screening"]},
                {"front": "List common insider threat indicators", 
                 "back": "Sudden financial difficulties, disgruntlement, unusual work hours, accessing unnecessary information, copying files, policy violations", 
                 "tags": ["insider-threat", "indicators"]},
            ],
            "Domain 5": [
                {"front": "What is CPTED?", 
                 "back": "Crime Prevention Through Environmental Design - using architecture and urban planning to reduce crime opportunities through natural surveillance, access control, territorial reinforcement, and maintenance.", 
                 "tags": ["CPTED", "design"]},
                {"front": "List the four protection rings in concentric security", 
                 "back": "1) Perimeter (outer boundary), 2) Building envelope (walls, doors, windows), 3) Interior spaces (rooms, areas), 4) Asset protection (safes, vaults)", 
                 "tags": ["layered-defense", "perimeter"]},
                {"front": "What are the three types of lighting for security?", 
                 "back": "Continuous (constant illumination), Standby (activated when needed), and Emergency (backup power systems)", 
                 "tags": ["lighting", "systems"]},
                {"front": "Define mantrap", 
                 "back": "A small space with two interlocking doors where only one can be open at a time, used to control access and prevent tailgating", 
                 "tags": ["access-control", "design"]},
            ],
            "Domain 6": [
                {"front": "What is the principle of Least Privilege?", 
                 "back": "Users should be granted only the minimum access rights necessary to perform their job functions, reducing the risk of unauthorized access or misuse.", 
                 "tags": ["access-control", "principles"]},
                {"front": "Define Multi-Factor Authentication (MFA)", 
                 "back": "A security method requiring two or more verification factors: something you know (password), something you have (token), something you are (biometric).", 
                 "tags": ["authentication", "access-control"]},
                {"front": "What are the three states of data?", 
                 "back": "Data at Rest (stored), Data in Transit (being transmitted), and Data in Use (being processed)", 
                 "tags": ["data-protection", "encryption"]},
                {"front": "Define data classification", 
                 "back": "The process of organizing data by relevant categories so it may be used and protected more efficiently according to its value and sensitivity", 
                 "tags": ["data-protection", "classification"]},
            ],
            "Domain 7": [
                {"front": "What are the four phases of emergency management?", 
                 "back": "Mitigation (reducing risks), Preparedness (planning and training), Response (immediate actions during crisis), Recovery (returning to normal operations)", 
                 "tags": ["emergency-management", "phases"]},
                {"front": "Define Incident Command System (ICS)", 
                 "back": "A standardized management framework for coordinating emergency response across multiple agencies, with clear command structure and unified objectives.", 
                 "tags": ["ICS", "coordination"]},
                {"front": "What is the difference between crisis and emergency?", 
                 "back": "Emergency is an unexpected event requiring immediate action; Crisis is a situation that threatens the organization's survival or reputation", 
                 "tags": ["definitions", "planning"]},
                {"front": "List the five ICS functional areas", 
                 "back": "Command, Operations, Planning, Logistics, Finance/Administration", 
                 "tags": ["ICS", "structure"]},
            ]
        }
        
        return templates.get(domain, [])

    @classmethod  
    def generate_questions(cls, target_count: int = 900) -> List[Dict[str, Any]]:
        """Generate comprehensive question bank"""
        questions = []
        
        # Calculate per-domain allocation based on CPP weights
        total_weight = sum(CPP_DOMAINS[k]["weight"] for k in CPP_DOMAINS)
        allocations = {}
        for domain_key, domain_info in CPP_DOMAINS.items():
            domain_name = f"Domain {int(domain_key[-1])}"
            allocations[domain_name] = int(target_count * domain_info["weight"] / total_weight)
        
        # Generate questions by domain
        for domain_name, count in allocations.items():
            domain_questions = cls._generate_domain_questions(domain_name, count)
            questions.extend(domain_questions)
        
        return questions

    @classmethod
    def _generate_domain_questions(cls, domain: str, count: int) -> List[Dict[str, Any]]:
        """Generate questions for specific domain"""
        questions = []
        
        # Type distribution: 50% MC, 25% TF, 25% Scenario
        mc_count = int(count * 0.50)
        tf_count = int(count * 0.25) 
        scenario_count = count - mc_count - tf_count
        
        # Generate each type
        questions.extend(cls._generate_mc_questions(domain, mc_count))
        questions.extend(cls._generate_tf_questions(domain, tf_count))
        questions.extend(cls._generate_scenario_questions(domain, scenario_count))
        
        return questions

    @classmethod
    def _generate_mc_questions(cls, domain: str, count: int) -> List[Dict[str, Any]]:
        """Generate multiple choice questions"""
        templates = cls._get_mc_templates(domain)
        questions = []
        
        for i in range(count):
            template = templates[i % len(templates)]
            question = {
                "id": _new_id("q"),
                "type": "mc",
                "domain": domain,
                "stem": template["stem"],
                "choices": template["choices"],
                "answer": template["answer"],
                "explanation": template["explanation"],
                "tags": template.get("tags", []),
                "source": "generated",
                "created_at": int(time.time())
            }
            questions.append(question)
        
        return questions

    @classmethod
    def _generate_tf_questions(cls, domain: str, count: int) -> List[Dict[str, Any]]:
        """Generate true/false questions"""
        templates = cls._get_tf_templates(domain)
        questions = []
        
        for i in range(count):
            template = templates[i % len(templates)]
            question = {
                "id": _new_id("q"),
                "type": "tf", 
                "domain": domain,
                "stem": template["stem"],
                "answer": template["answer"],
                "explanation": template["explanation"],
                "tags": template.get("tags", []),
                "source": "generated",
                "created_at": int(time.time())
            }
            questions.append(question)
        
        return questions

    @classmethod
    def _generate_scenario_questions(cls, domain: str, count: int) -> List[Dict[str, Any]]:
        """Generate scenario-based questions"""
        templates = cls._get_scenario_templates(domain)
        questions = []
        
        for i in range(count):
            template = templates[i % len(templates)]
            question = {
                "id": _new_id("q"),
                "type": "scenario",
                "domain": domain,
                "stem": template["stem"],
                "options": template["options"],
                "answers": template["answers"],
                "explanation": template["explanation"],
                "tags": template.get("tags", []),
                "source": "generated",
                "created_at": int(time.time())
            }
            questions.append(question)
        
        return questions

    @classmethod
    def _get_mc_templates(cls, domain: str) -> List[Dict[str, Any]]:
        """Get MC question templates by domain"""
        # Sample templates - would be much larger in production
        templates = {
            "Domain 1": [
                {
                    "stem": "Which control type is MOST effective at deterring unauthorized access before it occurs?",
                    "choices": ["Detective controls", "Preventive controls", "Corrective controls", "Compensating controls"],
                    "answer": 1,
                    "explanation": "Preventive controls are designed to stop incidents before they happen, making them most effective at deterring unauthorized access.",
                    "tags": ["controls", "prevention"]
                },
                {
                    "stem": "What is the PRIMARY purpose of a vulnerability assessment?",
                    "choices": ["To identify threats", "To identify weaknesses", "To calculate risk", "To implement controls"],
                    "answer": 1,
                    "explanation": "Vulnerability assessments identify weaknesses that could be exploited by threats.",
                    "tags": ["vulnerability", "assessment"]
                }
            ],
            "Domain 2": [
                {
                    "stem": "When calculating Annual Loss Expectancy (ALE), which formula is correct?",
                    "choices": ["ALE = Asset Value × Threat Frequency", "ALE = Single Loss Expectancy × Annual Rate of Occurrence", "ALE = Risk × Vulnerability × Asset Value", "ALE = Impact × Likelihood × Controls"],
                    "answer": 1,
                    "explanation": "ALE = SLE × ARO. Single Loss Expectancy represents the dollar loss from one incident, and Annual Rate of Occurrence is how often it happens per year.",
                    "tags": ["risk-calculation", "metrics"]
                }
            ],
            "Domain 3": [
                {
                    "stem": "During an investigation interview, what is the PRIMARY purpose of open-ended questions?",
                    "choices": ["To get specific yes/no answers", "To challenge the subject's credibility", "To gather detailed information and encourage narrative", "To conclude the interview quickly"],
                    "answer": 2,
                    "explanation": "Open-ended questions encourage subjects to provide detailed information and tell their story in their own words.",
                    "tags": ["interview-techniques", "information-gathering"]
                }
            ],
            "Domain 4": [
                {
                    "stem": "Which background check component is MOST important for positions with access to classified information?",
                    "choices": ["Education verification", "Credit history review", "Security clearance investigation", "Employment history verification"],
                    "answer": 2,
                    "explanation": "Security clearance investigations are specifically designed for classified access positions.",
                    "tags": ["clearance", "screening"]
                }
            ],
            "Domain 5": [
                {
                    "stem": "In CPTED principles, what does 'natural surveillance' refer to?",
                    "choices": ["Security cameras placed throughout the facility", "Positioning windows and lighting to maximize visibility", "Having security guards patrol regularly", "Installing motion-detection sensors"],
                    "answer": 1,
                    "explanation": "Natural surveillance in CPTED refers to designing spaces so people can easily observe their surroundings through proper placement of windows, lighting, and landscaping.",
                    "tags": ["CPTED", "design-principles"]
                }
            ],
            "Domain 6": [
                {
                    "stem": "What is the PRIMARY security benefit of implementing role-based access control (RBAC)?",
                    "choices": ["Reduces password complexity requirements", "Simplifies user access management and enforces least privilege", "Eliminates the need for user authentication", "Increases system processing speed"],
                    "answer": 1,
                    "explanation": "RBAC groups permissions by job functions, making it easier to manage access while ensuring users only get permissions needed for their roles.",
                    "tags": ["access-control", "RBAC"]
                }
            ],
            "Domain 7": [
                {
                    "stem": "In the Incident Command System (ICS), who has the authority to establish objectives and priorities?",
                    "choices": ["Operations Chief", "Planning Chief", "Incident Commander", "Safety Officer"],
                    "answer": 2,
                    "explanation": "The Incident Commander has overall authority and responsibility for incident management, including establishing objectives, priorities, and strategy.",
                    "tags": ["ICS", "command-structure"]
                }
            ]
        }
        
        # Return templates, cycling if needed
        domain_templates = templates.get(domain, templates["Domain 1"])
        return domain_templates * 20  # Repeat to ensure enough content

    @classmethod
    def _get_tf_templates(cls, domain: str) -> List[Dict[str, Any]]:
        """Get True/False question templates by domain"""
        templates = {
            "Domain 1": [
                {
                    "stem": "Risk can be completely eliminated through proper security controls.",
                    "answer": False,
                    "explanation": "Risk can be reduced, transferred, or accepted, but never completely eliminated. There is always residual risk remaining after implementing security controls.",
                    "tags": ["risk-management", "fundamentals"]
                }
            ],
            "Domain 2": [
                {
                    "stem": "A cost-benefit analysis should always recommend the security control with the lowest implementation cost.",
                    "answer": False,
                    "explanation": "Cost-benefit analysis should recommend controls where benefits exceed costs by the greatest margin, not necessarily the cheapest option.",
                    "tags": ["cost-benefit", "decision-making"]
                }
            ],
            "Domain 3": [
                {
                    "stem": "Chain of custody documentation must record every person who handles evidence.",
                    "answer": True,
                    "explanation": "Chain of custody requires documenting every transfer and handling of evidence to maintain its integrity and legal admissibility.",
                    "tags": ["evidence", "legal"]
                }
            ],
            "Domain 4": [
                {
                    "stem": "Insider threat indicators are always obvious and easy to detect.",
                    "answer": False,
                    "explanation": "Insider threat indicators can be subtle and may resemble normal behavior variations. Effective programs use multiple indicators.",
                    "tags": ["insider-threat", "detection"]
                }
            ],
            "Domain 5": [
                {
                    "stem": "Physical security controls are only effective if they work independently of each other.",
                    "answer": False,
                    "explanation": "Physical security is most effective when controls work together in a layered defense approach, providing redundancy and mutual support.",
                    "tags": ["layered-defense", "integration"]
                }
            ],
            "Domain 6": [
                {
                    "stem": "Encryption in transit protects data while it is being transmitted over networks.",
                    "answer": True,
                    "explanation": "Encryption in transit (like HTTPS, VPN) protects data as it moves between systems over networks, preventing interception and eavesdropping.",
                    "tags": ["encryption", "data-protection"]
                }
            ],
            "Domain 7": [
                {
                    "stem": "Emergency response plans should be kept confidential and only shared with senior management.",
                    "answer": False,
                    "explanation": "Emergency response plans should be shared with all relevant personnel who need to implement them during an emergency.",
                    "tags": ["emergency-planning", "communication"]
                }
            ]
        }
        
        domain_templates = templates.get(domain, templates["Domain 1"])
        return domain_templates * 15  # Repeat to ensure enough content

    @classmethod
    def _get_scenario_templates(cls, domain: str) -> List[Dict[str, Any]]:
        """Get scenario question templates by domain"""
        templates = {
            "Domain 1": [
                {
                    "stem": "Your organization experienced a data breach due to an unpatched server. Management wants to prevent similar incidents. Which combination of controls would provide the BEST layered defense?",
                    "options": ["Automated patch management only", "Employee training and incident response plan", "Patch management, network segmentation, and intrusion detection", "Firewall configuration and antivirus software"],
                    "answers": [2],
                    "explanation": "Option C provides multiple layers of protection: patch management prevents vulnerabilities, network segmentation limits breach scope, and intrusion detection identifies threats.",
                    "tags": ["layered-defense", "incident-prevention"]
                }
            ],
            "Domain 2": [
                {
                    "stem": "A security program needs justification for budget increases. Which metrics would BEST demonstrate program value to executives?",
                    "options": ["Number of security incidents detected", "Cost savings from incident prevention", "Security awareness training completion rates", "Number of security policies updated"],
                    "answers": [1],
                    "explanation": "Cost savings from incident prevention directly translates to business value that executives can understand and appreciate.",
                    "tags": ["metrics", "business-case"]
                }
            ],
            "Domain 3": [
                {
                    "stem": "You discover potential evidence of employee theft on a company computer. The employee is currently at lunch. What should be your FIRST action?",
                    "options": ["Immediately question the employee when they return", "Make copies of all files for evidence", "Secure the computer and document the scene", "Contact law enforcement"],
                    "answers": [2],
                    "explanation": "Securing the scene and documenting it preserves evidence integrity and maintains chain of custody. Taking action before proper securing could compromise evidence.",
                    "tags": ["evidence-preservation", "investigation-procedures"]
                }
            ],
            "Domain 4": [
                {
                    "stem": "An employee shows signs of financial stress and begins accessing files outside their normal job duties. What actions should be taken?",
                    "options": ["Immediately terminate the employee", "Increase monitoring and document behaviors", "Transfer employee to different department", "Ignore unless criminal activity is confirmed"],
                    "answers": [1],
                    "explanation": "Increased monitoring and documentation allows for evidence gathering while maintaining legal protections for both employee and organization.",
                    "tags": ["insider-threat", "monitoring"]
                }
            ],
            "Domain 5": [
                {
                    "stem": "A facility has experienced several vehicle break-ins in the parking lot. Which CPTED principle would MOST effectively address this problem?",
                    "options": ["Install more security cameras", "Hire additional security guards", "Improve lighting and remove visual obstructions", "Add more parking spaces"],
                    "answers": [2],
                    "explanation": "Improving lighting and removing visual obstructions applies CPTED's natural surveillance principle, making criminal activity more visible and likely to be observed.",
                    "tags": ["CPTED", "parking-security"]
                }
            ],
            "Domain 6": [
                {
                    "stem": "A company discovers that sensitive customer data was accessed by unauthorized personnel. What should be the IMMEDIATE priorities?",
                    "options": ["Contain the breach and preserve evidence", "Notify customers immediately", "Conduct internal investigation", "Implement new access controls"],
                    "answers": [0],
                    "explanation": "Immediate containment prevents further damage, and evidence preservation is critical for investigation and potential legal proceedings.",
                    "tags": ["incident-response", "data-breach"]
                }
            ],
            "Domain 7": [
                {
                    "stem": "During a facility evacuation, employees are gathering in the parking lot but emergency responders need that space for equipment. What should the Emergency Coordinator do?",
                    "options": ["Tell employees to go home immediately", "Move employees to the designated alternate assembly area", "Have employees wait in their vehicles", "Keep employees in the parking lot until authorities arrive"],
                    "answers": [1],
                    "explanation": "Emergency plans should include alternate assembly areas for situations where the primary area becomes unavailable.",
                    "tags": ["evacuation", "emergency-procedures"]
                }
            ]
        }
        
        domain_templates = templates.get(domain, templates["Domain 1"])
        return domain_templates * 10  # Repeat to ensure enough content

def ensure_content_seeded():
    """Ensure content bank has sufficient material"""
    # Check current content levels
    questions = get_all_questions()
    flashcards = get_all_flashcards()
    
    # Generate content if below thresholds
    if len(questions) < 100:
        logger.info("Generating question bank...")
        new_questions = CPPContentGenerator.generate_questions(900)
        ingest_questions(new_questions, source="seed")
    
    if len(flashcards) < 50:
        logger.info("Generating flashcard bank...")
        new_flashcards = CPPContentGenerator.generate_flashcards(300)
        ingest_flashcards(new_flashcards, source="seed")

# ====================================================================================================
# ROUTES - AUTHENTICATION
# ====================================================================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        next_url = request.args.get("next", "/")
        content = f"""
        <div class="container" style="max-width: 480px;">
          <div class="card shadow-sm my-4">
            <div class="card-header">
              <h4 class="mb-0">Sign In</h4>
            </div>
            <div class="card-body">
              <form method="post">
                <input type="hidden" name="csrf_token" value="{csrf_token()}"/>
                <input type="hidden" name="next" value="{html.escape(next_url)}"/>
                <div class="mb-3">
                  <label class="form-label">Email</label>
                  <input type="email" name="email" class="form-control" required/>
                </div>
                <div class="mb-3">
                  <label class="form-label">Password</label>
                  <input type="password" name="password" class="form-control" required/>
                </div>
                <div class="d-flex gap-2">
                  <button type="submit" class="btn btn-primary">Sign In</button>
                  <a href="/register" class="btn btn-outline-secondary">Create Account</a>
                </div>
              </form>
            </div>
          </div>
        </div>
        """
        return base_layout("Sign In", content)
    
    # POST - process login
    if not _csrf_ok():
        abort(403)
    
    email = (request.form.get("email") or "").strip().lower()
    password = request.form.get("password") or ""
    next_url = request.form.get("next") or "/"
    
    user = _find_user(email)
    if not user or not check_password_hash(user.get("password_hash", ""), password):
        content = f"""
        <div class="container" style="max-width: 480px;">
          <div class="alert alert-danger">Invalid email or password.</div>
          <a href="/login" class="btn btn-primary">Try Again</a>
        </div>
        """
        return base_layout("Sign In Failed", content)
    
    # Success
    session["uid"] = user["id"]
    session["email"] = user["email"]
    _log_event(user["id"], "login.success")
    
    return redirect(next_url)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        next_url = request.args.get("next", "/")
        content = f"""
        <div class="container" style="max-width: 480px;">
          <div class="card shadow-sm my-4">
            <div class="card-header">
              <h4 class="mb-0">Create Account</h4>
            </div>
            <div class="card-body">
              <form method="post">
                <input type="hidden" name="csrf_token" value="{csrf_token()}"/>
                <input type="hidden" name="next" value="{html.escape(next_url)}"/>
                <div class="mb-3">
                  <label class="form-label">Email</label>
                  <input type="email" name="email" class="form-control" required/>
                </div>
                <div class="mb-3">
                  <label class="form-label">Password</label>
                  <input type="password" name="password" class="form-control" required minlength="8"/>
                  <div class="form-text">Minimum 8 characters</div>
                </div>
                <div class="mb-3">
                  <label class="form-label">Confirm Password</label>
                  <input type="password" name="confirm_password" class="form-control" required/>
                </div>
                <div class="d-flex gap-2">
                  <button type="submit" class="btn btn-primary">Create Account</button>
                  <a href="/login" class="btn btn-outline-secondary">Sign In Instead</a>
                </div>
              </form>
            </div>
          </div>
        </div>
        """
        return base_layout("Create Account", content)
    
    # POST - process registration
    if not _csrf_ok():
        abort(403)
    
    email = (request.form.get("email") or "").strip().lower()
    password = request.form.get("password") or ""
    confirm_password = request.form.get("confirm_password") or ""
    next_url = request.form.get("next") or "/"
    
    # Validation
    if password != confirm_password:
        content = """
        <div class="container" style="max-width: 480px;">
          <div class="alert alert-danger">Passwords do not match.</div>
          <a href="/register" class="btn btn-primary">Try Again</a>
        </div>
        """
        return base_layout("Registration Failed", content)
    
    valid, msg = validate_password(password)
    if not valid:
        content = f"""
        <div class="container" style="max-width: 480px;">
          <div class="alert alert-danger">{html.escape(msg)}</div>
          <a href="/register" class="btn btn-primary">Try Again</a>
        </div>
        """
        return base_layout("Registration Failed", content)
    
    success, result = _create_user(email, password)
    if not success:
        content = f"""
        <div class="container" style="max-width: 480px;">
          <div class="alert alert-danger">{html.escape(result)}</div>
          <a href="/register" class="btn btn-primary">Try Again</a>
        </div>
        """
        return base_layout("Registration Failed", content)
    
    # Success - auto login
    session["uid"] = result
    session["email"] = email
    _log_event(result, "register.success")
    
    return redirect(next_url)

@app.route("/logout")
def logout():
    uid = _user_id()
    if uid:
        _log_event(uid, "logout")
    session.clear()
    return redirect("/")

# ====================================================================================================
# ROUTES - MAIN APPLICATION
# ====================================================================================================

@app.route("/")
def home():
    """Main dashboard"""
    content = """
    <div class="container">
      <div class="py-4">
        <div class="row align-items-center mb-4">
          <div class="col">
            <h1 class="h3 mb-2"><i class="bi bi-shield-lock"></i> CPP Exam Prep</h1>
            <p class="text-muted mb-0">
              Comprehensive study platform for the ASIS Certified Protection Professional exam.
            </p>
          </div>
        </div>
        
        <div class="alert alert-info mb-4">
          <strong>Disclaimer:</strong> This program is not affiliated with or approved by ASIS International. 
          It uses only open-source and publicly available study materials. No ASIS-protected content is included.
        </div>

        <div class="row g-4">
          <div class="col-md-6">
            <div class="card h-100 shadow-sm">
              <div class="card-body">
                <h2 class="h5 mb-3"><i class="bi bi-layers me-2"></i>Flashcards</h2>
                <p class="text-muted mb-3">Study key concepts and definitions across all CPP domains.</p>
                <a class="btn btn-success" href="/flashcards">Start Flashcards</a>
              </div>
            </div>
          </div>
          
          <div class="col-md-6">
            <div class="card h-100 shadow-sm">
              <div class="card-body">
                <h2 class="h5 mb-3"><i class="bi bi-ui-checks-grid me-2"></i>Practice Quiz</h2>
                <p class="text-muted mb-3">Quick practice sessions with immediate feedback.</p>
                <a class="btn btn-primary" href="/quiz">Take Quiz</a>
              </div>
            </div>
          </div>
          
          <div class="col-md-6">
            <div class="card h-100 shadow-sm">
              <div class="card-body">
                <h2 class="h5 mb-3"><i class="bi bi-journal-check me-2"></i>Mock Exam</h2>
                <p class="text-muted mb-3">Full-length practice exams with CPP domain weighting.</p>
                <a class="btn btn-warning" href="/mock">Start Mock Exam</a>
              </div>
            </div>
          </div>
          
          <div class="col-md-6">
            <div class="card h-100 shadow-sm">
              <div class="card-body">
                <h2 class="h5 mb-3"><i class="bi bi-chat-dots me-2"></i>AI Tutor</h2>
                <p class="text-muted mb-3">Get explanations and guidance on complex topics.</p>
                <a class="btn btn-secondary" href="/tutor">Ask Tutor</a>
              </div>
            </div>
          </div>
        </div>

        <div class="mt-4 pt-4 border-top">
          <div class="row">
            <div class="col-md-8">
              <h3 class="h6 mb-2">CPP Exam Domains</h3>
              <div class="row g-2 small">
                <div class="col-sm-6">
                  <div class="border rounded p-2">
                    <strong>Domain 1:</strong> Security Principles & Practices (22%)
                  </div>
                </div>
                <div class="col-sm-6">
                  <div class="border rounded p-2">
                    <strong>Domain 2:</strong> Business Principles & Practices (15%)
                  </div>
                </div>
                <div class="col-sm-6">
                  <div class="border rounded p-2">
                    <strong>Domain 3:</strong> Investigations (9%)
                  </div>
                </div>
                <div class="col-sm-6">
                  <div class="border rounded p-2">
                    <strong>Domain 4:</strong> Personnel Security (11%)
                  </div>
                </div>
                <div class="col-sm-6">
                  <div class="border rounded p-2">
                    <strong>Domain 5:</strong> Physical Security (16%)
                  </div>
                </div>
                <div class="col-sm-6">
                  <div class="border rounded p-2">
                    <strong>Domain 6:</strong> Information Security (14%)
                  </div>
                </div>
                <div class="col-sm-6">
                  <div class="border rounded p-2">
                    <strong>Domain 7:</strong> Crisis Management (13%)
                  </div>
                </div>
              </div>
            </div>
            <div class="col-md-4">
              <h3 class="h6 mb-2">Quick Links</h3>
              <div class="d-flex flex-column gap-1">
                <a href="/progress" class="btn btn-outline-secondary btn-sm">View Progress</a>
                <a href="/terms" class="btn btn-outline-secondary btn-sm">Terms & Conditions</a>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
    """
    return base_layout("CPP Exam Prep", content)

# ====================================================================================================
# ROUTES - FLASHCARDS
# ====================================================================================================

@app.route("/flashcards")
@login_required
def flashcards():
    """Flashcard study interface"""
    domain_filter = request.args.get("domain", "all")
    
    # Get flashcards
    if domain_filter == "all":
        cards = get_all_flashcards()
    else:
        domain_name = f"Domain {domain_filter[-1]}" if domain_filter.startswith("domain") else domain_filter
        cards = get_all_flashcards(domains=[domain_name])
    
    if not cards:
        content = f"""
        <div class="container">
          <h1 class="h4 mb-3">Flashcards</h1>
          <div class="alert alert-warning">
            No flashcards available for the selected domain. 
            <a href="/admin/generate" class="alert-link">Generate content</a> or select a different domain.
          </div>
          {domain_buttons_html(domain_filter)}
        </div>
        """
        return base_layout("Flashcards", content)
    
    # Prepare cards for JavaScript
    cards_json = json.dumps([{
        "id": c.get("id"),
        "front": c.get("front"),
        "back": c.get("back"),
        "domain": c.get("domain")
    } for c in cards], ensure_ascii=False)
    
    content = f"""
    <div class="container">
      <div class="d-flex justify-content-between align-items-center mb-3">
        <h1 class="h4 mb-0">Flashcards</h1>
        <div class="text-muted small">
          <span id="card-counter">0 / 0</span>
        </div>
      </div>
      
      <div class="mb-3">
        {domain_buttons_html(domain_filter)}
      </div>
      
      <div class="row justify-content-center">
        <div class="col-lg-8">
          <div id="flashcard-container" class="fc-card mb-3" style="min-height: 300px;">
            <div id="card-front" class="front d-flex align-items-center justify-content-center text-center">
              <div>
                <h5 class="mb-0">Loading...</h5>
              </div>
            </div>
            <div id="card-back" class="back d-none d-flex align-items-center justify-content-center text-center">
              <div>
                <p class="mb-0">Answer will appear here</p>
              </div>
            </div>
          </div>
          
          <div class="d-flex justify-content-center gap-2 mb-3">
            <button id="prev-btn" class="btn btn-outline-secondary" disabled>
              <i class="bi bi-arrow-left"></i> Previous
            </button>
            <button id="flip-btn" class="btn btn-primary">
              <i class="bi bi-arrow-repeat"></i> Flip
            </button>
            <button id="next-btn" class="btn btn-outline-secondary">
              Next <i class="bi bi-arrow-right"></i>
            </button>
          </div>
          
          <div class="text-center">
            <button id="shuffle-btn" class="btn btn-outline-success btn-sm">
              <i class="bi bi-shuffle"></i> Shuffle
            </button>
          </div>
        </div>
      </div>
    </div>
    
    <script>
    (function() {{
      const cards = {cards_json};
      let currentIndex = 0;
      let isFlipped = false;
      
      const frontEl = document.getElementById('card-front');
      const backEl = document.getElementById('card-back');
      const counterEl = document.getElementById('card-counter');
      const prevBtn = document.getElementById('prev-btn');
      const nextBtn = document.getElementById('next-btn');
      const flipBtn = document.getElementById('flip-btn');
      const shuffleBtn = document.getElementById('shuffle-btn');
      
      function updateCard() {{
        if (cards.length === 0) {{
          frontEl.innerHTML = '<div><h5 class="text-muted">No cards available</h5></div>';
          return;
        }}
        
        const card = cards[currentIndex];
        frontEl.innerHTML = `<div><h5 class="mb-2">${{escapeHtml(card.front)}}</h5><div class="text-muted small">${{escapeHtml(card.domain)}}</div></div>`;
        backEl.innerHTML = `<div><p class="mb-2">${{escapeHtml(card.back)}}</p><div class="text-muted small">${{escapeHtml(card.domain)}}</div></div>`;
        
        counterEl.textContent = `${{currentIndex + 1}} / ${{cards.length}}`;
        
        prevBtn.disabled = currentIndex === 0;
        nextBtn.disabled = currentIndex === cards.length - 1;
        
        // Reset to front
        frontEl.classList.remove('d-none');
        backEl.classList.add('d-none');
        isFlipped = false;
        flipBtn.innerHTML = '<i class="bi bi-arrow-repeat"></i> Flip';
      }}
      
      function flip() {{
        if (isFlipped) {{
          frontEl.classList.remove('d-none');
          backEl.classList.add('d-none');
          flipBtn.innerHTML = '<i class="bi bi-arrow-repeat"></i> Flip';
        }} else {{
          frontEl.classList.add('d-none');
          backEl.classList.remove('d-none');
          flipBtn.innerHTML = '<i class="bi bi-arrow-repeat"></i> Back';
        }}
        isFlipped = !isFlipped;
      }}
      
      function shuffle() {{
        for (let i = cards.length - 1; i > 0; i--) {{
          const j = Math.floor(Math.random() * (i + 1));
          [cards[i], cards[j]] = [cards[j], cards[i]];
        }}
        currentIndex = 0;
        updateCard();
      }}
      
      function escapeHtml(text) {{
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
      }}
      
      // Event listeners
      prevBtn.addEventListener('click', () => {{
        if (currentIndex > 0) {{
          currentIndex--;
          updateCard();
        }}
      }});
      
      nextBtn.addEventListener('click', () => {{
        if (currentIndex < cards.length - 1) {{
          currentIndex++;
          updateCard();
        }}
      }});
      
      flipBtn.addEventListener('click', flip);
      shuffleBtn.addEventListener('click', shuffle);
      
      // Keyboard support
      document.addEventListener('keydown', (e) => {{
        if (e.code === 'Space') {{
          e.preventDefault();
          flip();
        }} else if (e.code === 'ArrowLeft' && currentIndex > 0) {{
          currentIndex--;
          updateCard();
        }} else if (e.code === 'ArrowRight' && currentIndex < cards.length - 1) {{
          currentIndex++;
          updateCard();
        }}
      }});
      
      // Domain buttons
      document.querySelectorAll('.domain-btn').forEach(btn => {{
        btn.addEventListener('click', function() {{
          document.querySelectorAll('.domain-btn').forEach(b => b.classList.remove('active'));
          this.classList.add('active');
          const domain = this.dataset.value;
          window.location.href = `/flashcards?domain=${{encodeURIComponent(domain)}}`;
        }});
      }});
      
      // Initialize
      updateCard();
    }})();
    </script>
    """
    
    _log_event(_user_id(), "flashcards.view", {"domain": domain_filter, "count": len(cards)})
    return base_layout("Flashcards", content)

# ====================================================================================================
# ROUTES - QUIZ & MOCK EXAMS
# ====================================================================================================

def _render_question_picker(title: str, action_url: str, default_count: int = 20):
    """Render question picker interface"""
    content = f"""
    <div class="container" style="max-width: 960px;">
      <div class="card shadow-sm my-4">
        <div class="card-header">
          <h4 class="mb-0">{html.escape(title)}</h4>
          <div class="text-muted small">Select domains and number of questions for your practice session.</div>
        </div>
        <div class="card-body">
          <form method="post" action="{html.escape(action_url)}">
            <input type="hidden" name="csrf_token" value="{csrf_token()}"/>
            
            <div class="mb-4">
              <label class="form-label">Domain Selection</label>
              {domain_buttons_html("all", "domain")}
              <div class="form-text">Select a specific domain or choose "All Domains" for mixed practice following CPP exam weightings.</div>
            </div>

            <div class="mb-4">
              <label class="form-label">Number of Questions</label>
              <input type="number" class="form-control" name="count" min="5" max="500" value="{default_count}" style="max-width: 200px;">
              <div class="form-text">Choose between 5-500 questions for your session.</div>
            </div>

            <div class="d-flex gap-2">
              <button type="submit" class="btn btn-primary">Start {html.escape(title)}</button>
              <a href="/" class="btn btn-outline-secondary">Cancel</a>
            </div>
          </form>
        </div>
      </div>
    </div>
    
    <script>
      document.querySelectorAll('.domain-btn').forEach(btn => {{
        btn.addEventListener('click', function() {{
          document.querySelectorAll('.domain-btn').forEach(b => b.classList.remove('active'));
          this.classList.add('active');
          document.getElementById('domain_val').value = this.dataset.value;
        }});
      }});
    </script>
    """
    return base_layout(title, content)

def _render_question_session(title: str, questions: List[Dict[str, Any]]):
    """Render question practice session"""
    if not questions:
        content = """
        <div class="container">
          <div class="alert alert-warning">
            No questions available for the selected criteria. Please try different settings or 
            <a href="/admin/generate" class="alert-link">generate more content</a>.
          </div>
          <a href="/" class="btn btn-primary">Back to Home</a>
        </div>
        """
        return base_layout(title, content)
    
    questions_json = json.dumps([{
        "id": q.get("id"),
        "type": q.get("type"),
        "domain": q.get("domain"),
        "stem": q.get("stem"),
        "choices": q.get("choices", []),
        "options": q.get("options", []),
        "answer": q.get("answer"),
        "answers": q.get("answers", []),
        "explanation": q.get("explanation", "")
    } for q in questions], ensure_ascii=False)
    
    content = f"""
    <div class="container" style="max-width: 960px;">
      <div class="card shadow-sm my-4">
        <div class="card-header d-flex justify-content-between align-items-center">
          <div>
            <h4 class="mb-0">{html.escape(title)}</h4>
            <div class="text-muted small" id="progress-text">Question 1 of {len(questions)}</div>
          </div>
          <div class="text-muted small">Use ← → keys to navigate</div>
        </div>
        <div class="card-body">
          <div id="question-container" style="min-height: 300px;">
            <!-- Question content will be inserted here -->
          </div>
          
          <div class="d-flex justify-content-between align-items-center mt-4">
            <button id="prev-btn" class="btn btn-outline-secondary" disabled>
              <i class="bi bi-arrow-left"></i> Previous
            </button>
            
            <div class="d-flex gap-2">
              <button id="reveal-btn" class="btn btn-success">Show Answer</button>
              <button id="next-btn" class="btn btn-primary">
                Next <i class="bi bi-arrow-right"></i>
              </button>
            </div>
          </div>
          
          <div id="answer-section" class="mt-3 d-none">
            <div class="border-top pt-3">
              <div id="answer-content"></div>
            </div>
          </div>
        </div>
      </div>
    </div>
    
    <script>
    (function() {{
      const questions = {questions_json};
      let currentIndex = 0;
      let answerRevealed = false;
      
      const questionContainer = document.getElementById('question-container');
      const progressText = document.getElementById('progress-text');
      const prevBtn = document.getElementById('prev-btn');
      const nextBtn = document.getElementById('next-btn');
      const revealBtn = document.getElementById('reveal-btn');
      const answerSection = document.getElementById('answer-section');
      const answerContent = document.getElementById('answer-content');
      
      function renderQuestion() {{
        const q = questions[currentIndex];
        let html = '';
        
        // Question stem
        html += `<div class="mb-4"><h5>${{escapeHtml(q.stem)}}</h5>`;
        html += `<div class="text-muted small">${{escapeHtml(q.domain)}} • ${{q.type.toUpperCase()}}</div></div>`;
        
        // Answer choices based on type
        if (q.type === 'mc') {{
          html += '<div class="mb-3">';
          q.choices.forEach((choice, i) => {{
            const letter = String.fromCharCode(65 + i);
            html += `<div class="mb-2"><strong>${{letter}}.</strong> ${{escapeHtml(choice)}}</div>`;
          }});
          html += '</div>';
        }} else if (q.type === 'tf') {{
          html += '<div class="mb-3">';
          html += '<div class="mb-2"><strong>A.</strong> True</div>';
          html += '<div class="mb-2"><strong>B.</strong> False</div>';
          html += '</div>';
        }} else if (q.type === 'scenario') {{
          html += '<div class="mb-3"><em>Select all that apply:</em></div>';
          html += '<div class="mb-3">';
          q.options.forEach((option, i) => {{
            const letter = String.fromCharCode(65 + i);
            html += `<div class="mb-2"><strong>${{letter}}.</strong> ${{escapeHtml(option)}}</div>`;
          }});
          html += '</div>';
        }}
        
        questionContainer.innerHTML = html;
        progressText.textContent = `Question ${{currentIndex + 1}} of ${{questions.length}}`;
        
        // Update buttons
        prevBtn.disabled = currentIndex === 0;
        nextBtn.disabled = currentIndex === questions.length - 1;
        
        // Reset answer state
        answerRevealed = false;
        answerSection.classList.add('d-none');
        revealBtn.textContent = 'Show Answer';
        revealBtn.classList.remove('btn-outline-success');
        revealBtn.classList.add('btn-success');
      }}
      
      function revealAnswer() {{
        const q = questions[currentIndex];
        let answerHtml = '';
        
        if (q.type === 'mc') {{
          const correctLetter = String.fromCharCode(65 + q.answer);
          answerHtml = `<div class="alert alert-success"><strong>Correct Answer: ${{correctLetter}}</strong></div>`;
        }} else if (q.type === 'tf') {{
          const correct = q.answer ? 'True' : 'False';
          answerHtml = `<div class="alert alert-success"><strong>Correct Answer: ${{correct}}</strong></div>`;
        }} else if (q.type === 'scenario') {{
          const correctLetters = q.answers.map(i => String.fromCharCode(65 + i)).join(', ');
          answerHtml = `<div class="alert alert-success"><strong>Correct Answers: ${{correctLetters}}</strong></div>`;
        }}
        
        if (q.explanation) {{
          answerHtml += `<div class="mt-2"><strong>Explanation:</strong> ${{escapeHtml(q.explanation)}}</div>`;
        }}
        
        answerContent.innerHTML = answerHtml;
        answerSection.classList.remove('d-none');
        answerRevealed = true;
        
        revealBtn.textContent = 'Answer Shown';
        revealBtn.classList.remove('btn-success');
        revealBtn.classList.add('btn-outline-success');
      }}
      
      function escapeHtml(text) {{
        const div = document.createElement('div');
        div.textContent = text || '';
        return div.innerHTML;
      }}
      
      // Event listeners
      prevBtn.addEventListener('click', () => {{
        if (currentIndex > 0) {{
          currentIndex--;
          renderQuestion();
        }}
      }});
      
      nextBtn.addEventListener('click', () => {{
        if (currentIndex < questions.length - 1) {{
          currentIndex++;
          renderQuestion();
        }}
      }});
      
      revealBtn.addEventListener('click', () => {{
        if (!answerRevealed) {{
          revealAnswer();
        }}
      }});
      
      // Keyboard navigation
      document.addEventListener('keydown', (e) => {{
        if (e.code === 'ArrowLeft' && currentIndex > 0) {{
          currentIndex--;
          renderQuestion();
        }} else if (e.code === 'ArrowRight' && currentIndex < questions.length - 1) {{
          currentIndex++;
          renderQuestion();
        }} else if (e.code === 'Space' && !answerRevealed) {{
          e.preventDefault();
          revealAnswer();
        }}
      }});
      
      // Initialize
      renderQuestion();
    }})();
    </script>
    """
    
    return base_layout(title, content)

@app.route("/quiz", methods=["GET"])
@login_required
def quiz_picker():
    """Quiz setup page"""
    return _render_question_picker("Practice Quiz", "/quiz/start", 20)

@app.route("/quiz/start", methods=["POST"])
@login_required
def quiz_start():
    """Start quiz session"""
    if not _csrf_ok():
        abort(403)
    
    domain = request.form.get("domain", "all")
    count = int(request.form.get("count", 20))
    count = max(5, min(500, count))  # Clamp to reasonable range
    
    # Select questions
    domains = [] if domain == "all" else [f"Domain {domain[-1]}"] if domain.startswith("domain") else [domain]
    questions = select_questions(domains=domains, count=count, user_id=_user_id())
    
    # Log attempt
    _log_event(_user_id(), "quiz.start", {
        "domain": domain,
        "count": count,
        "actual_count": len(questions)
    })
    
    return _render_question_session("Practice Quiz", questions)

@app.route("/mock", methods=["GET"])
@login_required
def mock_picker():
    """Mock exam setup page"""
    return _render_question_picker("Mock Exam", "/mock/start", 225)

@app.route("/mock/start", methods=["POST"])
@login_required
def mock_start():
    """Start mock exam session"""
    if not _csrf_ok():
        abort(403)
    
    domain = request.form.get("domain", "all")
    count = int(request.form.get("count", 225))
    count = max(10, min(500, count))  # Clamp to reasonable range
    
    # Select questions
    domains = [] if domain == "all" else [f"Domain {domain[-1]}"] if domain.startswith("domain") else [domain]
    questions = select_questions(domains=domains, count=count, user_id=_user_id())
    
    # Log attempt
    _log_event(_user_id(), "mock.start", {
        "domain": domain,
        "count": count,
        "actual_count": len(questions)
    })
    
    return _render_question_session("Mock Exam", questions)

# ====================================================================================================
# ROUTES - AI TUTOR
# ====================================================================================================

@app.route("/tutor", methods=["GET"])
@login_required
def tutor():
    """AI Tutor interface"""
    offline_note = ""
    if not _ai_enabled():
        offline_note = """
        <div class="alert alert-warning mb-3">
          <i class="bi bi-wifi-off me-1"></i>
          Tutor is in offline mode (no API key configured). 
          You can still use Flashcards, Quiz, and Mock Exam.
        </div>
        """
    
    # Suggested questions for quick access
    suggestions = [
        "Explain the three lines of defense in corporate risk governance.",
        "How do you calculate risk using likelihood and impact? Give an example.",
        "What are common CPTED principles and how do they reduce incidents?",
        "Outline an incident response plan for a data breach at HQ.",
        "What is the purpose of due diligence in vendor management?",
        "Compare proprietary vs. contract security forces—pros and cons.",
        "What is a vulnerability assessment vs. a threat assessment?",
        "How should evidence be preserved during an internal investigation?",
        "What are common access control models (DAC, MAC, RBAC)?",
        "Define business continuity vs. disaster recovery with examples."
    ]
    
    suggestions_html = ""
    for i, suggestion in enumerate(suggestions[:6]):  # Show first 6
        suggestions_html += f"""
        <button type="button" class="btn btn-outline-secondary btn-sm mb-2 suggestion-btn" 
                style="text-align: left; white-space: normal;" 
                data-question="{html.escape(suggestion)}">
          {html.escape(suggestion)}
        </button>
        """
    
    content = f"""
    <div class="container">
      <div class="mb-3">
        <h1 class="h4 mb-1"><i class="bi bi-chat-dots"></i> AI Tutor</h1>
        <p class="text-muted mb-0">
          Get explanations and guidance on CPP exam topics. Click a suggested question or ask your own.
        </p>
      </div>

      {offline_note}

      <div class="row g-3">
        <div class="col-lg-8">
          <div class="card shadow-sm">
            <div class="card-body">
              <div id="chat-log" class="mb-3" style="min-height: 200px; max-height: 600px; overflow-y: auto;">
                <div class="text-muted small">Ask a question to get started, or click a suggestion on the right.</div>
              </div>
              
              <form id="tutor-form" method="post" action="/tutor/ask">
                <input type="hidden" name="csrf_token" value="{csrf_token()}"/>
                <div class="mb-2">
                  <label for="question" class="form-label">Your Question</label>
                  <textarea id="question" name="question" class="form-control" rows="3" 
                            placeholder="e.g., How should I structure a workplace violence prevention program?"></textarea>
                </div>
                <div class="d-flex gap-2 align-items-center">
                  <button id="ask-btn" type="submit" class="btn btn-primary">
                    <i class="bi bi-send"></i> Ask Tutor
                  </button>
                  <div id="loading" class="text-muted small d-none">
                    <span class="spinner-border spinner-border-sm me-1"></span> Thinking...
                  </div>
                </div>
              </form>
            </div>
          </div>
        </div>

        <div class="col-lg-4">
          <div class="card shadow-sm">
            <div class="card-body">
              <h2 class="h6 mb-3"><i class="bi bi-lightbulb"></i> Suggested Questions</h2>
              <div class="d-grid gap-1">
                {suggestions_html}
              </div>
              <div class="text-muted small mt-2">
                Click any suggestion to ask automatically.
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <script>
      document.addEventListener('DOMContentLoaded', function() {{
        const form = document.getElementById('tutor-form');
        const questionInput = document.getElementById('question');
        const askBtn = document.getElementById('ask-btn');
        const loading = document.getElementById('loading');
        const chatLog = document.getElementById('chat-log');
        
        // Handle suggestion clicks
        document.querySelectorAll('.suggestion-btn').forEach(btn => {{
          btn.addEventListener('click', function() {{
            const question = this.dataset.question;
            questionInput.value = question;
            submitQuestion();
          }});
        }});
        
        // Handle form submission
        form.addEventListener('submit', function(e) {{
          e.preventDefault();
          submitQuestion();
        }});
        
        async function submitQuestion() {{
          const question = questionInput.value.trim();
          if (!question) return;
          
          // Show loading state
          askBtn.disabled = true;
          loading.classList.remove('d-none');
          
          // Add user message to chat
          addMessage('You', question, 'user');
          
          try {{
            const formData = new FormData(form);
            const response = await fetch('/tutor/ask', {{
              method: 'POST',
              body: formData
            }});
            
            const data = await response.json();
            
            if (data.ok) {{
              addMessage('Tutor', data.answer, 'assistant');
            }} else {{
              addMessage('System', data.error || 'An error occurred. Please try again.', 'error');
            }}
            
            questionInput.value = '';
          }} catch (error) {{
            addMessage('System', 'Failed to get response. Please check your connection and try again.', 'error');
          }} finally {{
            askBtn.disabled = false;
            loading.classList.add('d-none');
          }}
        }}
        
        function addMessage(sender, content, type) {{
          const messageDiv = document.createElement('div');
          messageDiv.className = 'mb-3 p-3 border rounded';
          
          if (type === 'user') {{
            messageDiv.classList.add('bg-light');
          }} else if (type === 'error') {{
            messageDiv.classList.add('bg-danger', 'bg-opacity-10', 'border-danger');
          }}
          
          messageDiv.innerHTML = `
            <div class="fw-bold mb-1">${{escapeHtml(sender)}}</div>
            <div>${{formatContent(content)}}</div>
          `;
          
          chatLog.appendChild(messageDiv);
          chatLog.scrollTop = chatLog.scrollHeight;
        }}
        
        function formatContent(content) {{
          // Simple formatting - convert newlines to breaks
          return escapeHtml(content).replace(/\\n/g, '<br>');
        }}
        
        function escapeHtml(text) {{
          const div = document.createElement('div');
          div.textContent = text;
          return div.innerHTML;
        }}
      }});
    </script>
    """
    
    _log_event(_user_id(), "tutor.view")
    return base_layout("AI Tutor", content)

@app.route("/tutor/ask", methods=["POST"])
@login_required
def tutor_ask():
    """Process tutor question"""
    if not _csrf_ok():
        return jsonify({"ok": False, "error": "Invalid request"}), 403
    
    question = (request.form.get("question") or "").strip()
    if not question:
        return jsonify({"ok": False, "error": "Please provide a question"}), 400
    
    # Rate limiting
    rate_key = f"tutor:{_user_id()}"
    if not _rate_ok(rate_key, per_sec=0.1):  # Max 1 request per 10 seconds
        return jsonify({"ok": False, "error": "Please wait before asking another question"}), 429
    
    # Get AI response
    ok, answer = _openai_chat_completion(question)
    
    # Log the interaction
    _log_event(_user_id(), "tutor.ask", {
        "question_length": len(question),
        "success": ok
    })
    
    _append_attempt(_user_id(), "tutor", question=question, answer=answer if ok else None)
    
    return jsonify({
        "ok": ok,
        "answer": answer,
        "question": question
    })

# ====================================================================================================
# ROUTES - PROGRESS & ADMIN
# ====================================================================================================

@app.route("/progress")
@login_required
def progress():
    """User progress dashboard"""
    attempts = _load_json("attempts.json", [])
    user_attempts = [a for a in attempts if a.get("user_id") == _user_id()]
    
    # Group by mode
    by_mode = {}
    for attempt in user_attempts[-50:]:  # Last 50 attempts
        mode = attempt.get("mode", "unknown")
        if mode not in by_mode:
            by_mode[mode] = []
        by_mode[mode].append(attempt)
    
    content = f"""
    <div class="container">
      <h1 class="h4 mb-3"><i class="bi bi-graph-up"></i> Your Progress</h1>
      
      <div class="row g-3 mb-4">
        <div class="col-md-3">
          <div class="card text-center">
            <div class="card-body">
              <h5 class="card-title">{len(user_attempts)}</h5>
              <p class="card-text text-muted">Total Sessions</p>
            </div>
          </div>
        </div>
        <div class="col-md-3">
          <div class="card text-center">
            <div class="card-body">
              <h5 class="card-title">{len(by_mode.get('quiz', []))}</h5>
              <p class="card-text text-muted">Quiz Sessions</p>
            </div>
          </div>
        </div>
        <div class="col-md-3">
          <div class="card text-center">
            <div class="card-body">
              <h5 class="card-title">{len(by_mode.get('mock', []))}</h5>
              <p class="card-text text-muted">Mock Exams</p>
            </div>
          </div>
        </div>
        <div class="col-md-3">
          <div class="card text-center">
            <div class="card-body">
              <h5 class="card-title">{len(by_mode.get('tutor', []))}</h5>
              <p class="card-text text-muted">Tutor Questions</p>
            </div>
          </div>
        </div>
      </div>
      
      <div class="card">
        <div class="card-header">
          <h5 class="mb-0">Recent Activity</h5>
        </div>
        <div class="card-body">
          {"<div class='text-muted'>No activity yet. Start studying to track your progress!</div>" if not user_attempts else ""}
          {"".join([f'''
          <div class="d-flex justify-content-between align-items-center py-2 border-bottom">
            <div>
              <strong>{attempt.get("mode", "").title()}</strong>
              {f" - {attempt.get('domain', '')}" if attempt.get('domain') else ""}
              {f" - {attempt.get('question', '')[:60]}..." if attempt.get('question') and len(attempt.get('question', '')) > 60 else f" - {attempt.get('question', '')}" if attempt.get('question') else ""}
            </div>
            <div class="text-muted small">
              {attempt.get("ts", "").split("T")[0] if attempt.get("ts") else ""}
            </div>
          </div>
          ''' for attempt in user_attempts[-10:]])}
        </div>
      </div>
    </div>
    """
    
    return base_layout("Progress", content)

@app.route("/admin", methods=["GET", "POST"])
def admin():
    """Admin panel for content management"""
    if request.method == "POST":
        # Admin login
        password = request.form.get("password", "")
        if ADMIN_PASSWORD and password == ADMIN_PASSWORD:
            session["admin_ok"] = True
            return redirect("/admin")
        else:
            content = """
            <div class="container" style="max-width: 480px;">
              <div class="alert alert-danger">Invalid admin password.</div>
              <a href="/admin" class="btn btn-primary">Try Again</a>
            </div>
            """
            return base_layout("Admin Access Denied", content)
    
    # Check admin access
    if not is_admin():
        if not ADMIN_PASSWORD:
            content = """
            <div class="container" style="max-width: 480px;">
              <div class="alert alert-warning">
                Admin access is not configured. Set ADMIN_PASSWORD environment variable.
              </div>
              <a href="/" class="btn btn-primary">Back to Home</a>
            </div>
            """
            return base_layout("Admin Not Available", content)
        
        # Show login form
        content = f"""
        <div class="container" style="max-width: 480px;">
          <div class="card shadow-sm">
            <div class="card-header">
              <h4 class="mb-0">Admin Access</h4>
            </div>
            <div class="card-body">
              <form method="post">
                <div class="mb-3">
                  <label class="form-label">Admin Password</label>
                  <input type="password" name="password" class="form-control" required/>
                </div>
                <button type="submit" class="btn btn-primary">Access Admin Panel</button>
              </form>
            </div>
          </div>
        </div>
        """
        return base_layout("Admin Login", content)
    
    # Admin dashboard
    questions = get_all_questions()
    flashcards = get_all_flashcards()
    users = _users_all()
    
    content = f"""
    <div class="container">
      <h1 class="h4 mb-3"><i class="bi bi-gear"></i> Admin Panel</h1>
      
      <div class="row g-3 mb-4">
        <div class="col-md-3">
          <div class="card text-center">
            <div class="card-body">
              <h5 class="card-title">{len(questions)}</h5>
              <p class="card-text text-muted">Questions in Bank</p>
            </div>
          </div>
        </div>
        <div class="col-md-3">
          <div class="card text-center">
            <div class="card-body">
              <h5 class="card-title">{len(flashcards)}</h5>
              <p class="card-text text-muted">Flashcards in Bank</p>
            </div>
          </div>
        </div>
        <div class="col-md-3">
          <div class="card text-center">
            <div class="card-body">
              <h5 class="card-title">{len(users)}</h5>
              <p class="card-text text-muted">Registered Users</p>
            </div>
          </div>
        </div>
        <div class="col-md-3">
          <div class="card text-center">
            <div class="card-body">
              <h5 class="card-title">v{APP_VERSION}</h5>
              <p class="card-text text-muted">App Version</p>
            </div>
          </div>
        </div>
      </div>
      
      <div class="row g-3">
        <div class="col-md-6">
          <div class="card">
            <div class="card-header">
              <h5 class="mb-0">Content Management</h5>
            </div>
            <div class="card-body">
              <div class="d-grid gap-2">
                <a href="/admin/generate" class="btn btn-primary">Generate Content</a>
                <a href="/admin/export" class="btn btn-outline-secondary">Export Data</a>
                <a href="/admin/stats" class="btn btn-outline-info">View Statistics</a>
              </div>
            </div>
          </div>
        </div>
        
        <div class="col-md-6">
          <div class="card">
            <div class="card-header">
              <h5 class="mb-0">System Health</h5>
            </div>
            <div class="card-body">
              <div class="mb-2">
                <span class="badge bg-{'success' if _ai_enabled() else 'warning'}">
                  AI Tutor: {'Online' if _ai_enabled() else 'Offline'}
                </span>
              </div>
              <div class="mb-2">
                <span class="badge bg-success">Data Directory: OK</span>
              </div>
              <div class="mb-2">
                <span class="badge bg-{'success' if len(questions) > 50 else 'warning'}">
                  Content Bank: {'Sufficient' if len(questions) > 50 else 'Low'}
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>
      
      <div class="mt-3">
        <a href="/admin/logout" class="btn btn-outline-danger">Logout Admin</a>
        <a href="/" class="btn btn-outline-secondary">Back to Home</a>
      </div>
    </div>
    """
    
    return base_layout("Admin Panel", content)

@app.route("/admin/generate", methods=["GET", "POST"])
def admin_generate():
    """Generate content"""
    if not is_admin():
        return redirect("/admin")
    
    if request.method == "POST":
        action = request.form.get("action")
        
        if action == "questions":
            count = int(request.form.get("count", 100))
            new_questions = CPPContentGenerator.generate_questions(count)
            added, skipped = ingest_questions(new_questions, source="admin_generated")
            
            content = f"""
            <div class="container">
              <div class="alert alert-success">
                Generated {added} new questions ({skipped} skipped as duplicates)
              </div>
              <a href="/admin/generate" class="btn btn-primary">Generate More</a>
              <a href="/admin" class="btn btn-outline-secondary">Back to Admin</a>
            </div>
            """
            return base_layout("Content Generated", content)
        
        elif action == "flashcards":
            count = int(request.form.get("count", 50))
            new_flashcards = CPPContentGenerator.generate_flashcards(count)
            added, skipped = ingest_flashcards(new_flashcards, source="admin_generated")
            
            content = f"""
            <div class="container">
              <div class="alert alert-success">
                Generated {added} new flashcards ({skipped} skipped as duplicates)
              </div>
              <a href="/admin/generate" class="btn btn-primary">Generate More</a>
              <a href="/admin" class="btn btn-outline-secondary">Back to Admin</a>
            </div>
            """
            return base_layout("Content Generated", content)
    
    # Show generation form
    content = f"""
    <div class="container">
      <h1 class="h4 mb-3">Generate Content</h1>
      
      <div class="row g-3">
        <div class="col-md-6">
          <div class="card">
            <div class="card-header">
              <h5 class="mb-0">Generate Questions</h5>
            </div>
            <div class="card-body">
              <form method="post">
                <input type="hidden" name="action" value="questions"/>
                <div class="mb-3">
                  <label class="form-label">Number of Questions</label>
                  <input type="number" name="count" class="form-control" value="100" min="10" max="1000"/>
                  <div class="form-text">Questions will be distributed across CPP domains according to exam weightings.</div>
                </div>
                <button type="submit" class="btn btn-primary">Generate Questions</button>
              </form>
            </div>
          </div>
        </div>
        
        <div class="col-md-6">
          <div class="card">
            <div class="card-header">
              <h5 class="mb-0">Generate Flashcards</h5>
            </div>
            <div class="card-body">
              <form method="post">
                <input type="hidden" name="action" value="flashcards"/>
                <div class="mb-3">
                  <label class="form-label">Number of Flashcards</label>
                  <input type="number" name="count" class="form-control" value="50" min="10" max="500"/>
                  <div class="form-text">Flashcards will be distributed across CPP domains according to exam weightings.</div>
                </div>
                <button type="submit" class="btn btn-primary">Generate Flashcards</button>
              </form>
            </div>
          </div>
        </div>
      </div>
      
      <div class="mt-3">
        <a href="/admin" class="btn btn-outline-secondary">Back to Admin</a>
      </div>
    </div>
    """
    
    return base_layout("Generate Content", content)

@app.route("/admin/logout")
def admin_logout():
    """Admin logout"""
    session.pop("admin_ok", None)
    return redirect("/admin")

# ====================================================================================================
# ROUTES - TERMS & MISC
# ====================================================================================================

@app.route("/terms")
def terms():
    """Terms and conditions page"""
    content = """
    <div class="container" style="max-width:960px;">
      <h1 class="mb-2">CPP_Test_Prep — Terms and Conditions</h1>
      <div class="text-muted mb-4">Effective Date: 2025-09-04</div>

      <div class="alert alert-warning mb-4">
        <strong>Important Disclaimer:</strong> This program is not affiliated with or approved by ASIS International. 
        It uses only open-source and publicly available study materials. No ASIS-protected content is included.
      </div>

      <ol class="lh-base" style="padding-left: 1.2rem;">
        <li id="t1"><strong>Who we are</strong><br>
          CPP_Test_Prep is a study platform owned and operated by Strategic Security Advisors, LLC ("SSA," "we," "us," "our").
          Contact: <a href="mailto:cpptestprep@gmail.com">cpptestprep@gmail.com</a>.
        </li>

        <li id="t2" class="mt-3"><strong>What we do and what we do not do</strong><br>
          CPP_Test_Prep provides study tools for candidates preparing for the ASIS Certified Protection Professional examination.
          We are not affiliated with, endorsed by, or sponsored by ASIS International. We do not use or reproduce ASIS
          International protected, proprietary, or member-only materials. The platform is for education and training. It does not
          guarantee that you will pass any exam or achieve any certification.
        </li>

        <li id="t3" class="mt-3"><strong>Eligibility and accounts</strong><br>
          You must be at least 18 and able to form a binding contract. Keep your login secure and notify us of any unauthorized use.
          You are responsible for activity on your account.
        </li>

        <li id="t4" class="mt-3"><strong>Your license to use CPP_Test_Prep</strong><br>
          We grant you a limited, personal, non-exclusive, non-transferable license to access and use the platform for your own study.
          You may not resell, sublicense, share, copy at scale, scrape, or otherwise exploit the content or software.
        </li>

        <li id="t5" class="mt-3"><strong>Intellectual property</strong><br>
          All platform content that we create or license, including questions, explanations, flashcards, text, code, and UI,
          belongs to SSA or its licensors. All rights reserved. Any trademarks, service marks, and logos displayed are the
          property of their respective owners. "ASIS," "CPP," and other marks are the property of ASIS International. Use of the
          platform does not grant you any ownership in our IP.
        </li>
      </ol>

      <div class="mt-4">
        <a class="btn btn-primary" href="/">Back to Home</a>
      </div>
    </div>
    """
    return base_layout("Terms & Conditions", content)

@app.route("/healthz")
def health_check():
    """Health check endpoint"""
    return jsonify({
        "service": "cpp-exam-prep",
        "version": APP_VERSION,
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat() + "Z"
    })

# ====================================================================================================
# APPLICATION INITIALIZATION
# ====================================================================================================

def initialize_app():
    """Initialize application with sample data"""
    try:
        # Ensure data directories exist
        for path in [DATA_DIR, BANK_DIR]:
            os.makedirs(path, exist_ok=True)
        
        # Initialize data files
        for name, default in [
            ("users.json", []),
            ("events.json", []),
            ("attempts.json", []),
        ]:
            if not os.path.exists(_path(name)):
                _save_json(name, default)
        
        # Ensure weights file exists
        if not os.path.exists(_WEIGHTS_FILE):
            get_domain_weights()  # This will create the file
        
        # Seed content if needed
        ensure_content_seeded()
        
        logger.info("Application initialized successfully")
        
    except Exception as e:
        logger.error("Failed to initialize application: %s", e)
        raise

# Initialize on import
initialize_app()

# ====================================================================================================
# MAIN ENTRY POINT
# ====================================================================================================

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(
        host="0.0.0.0",
        port=port,
        debug=DEBUG
    )
