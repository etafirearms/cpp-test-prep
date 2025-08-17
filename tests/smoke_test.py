import os, sys, json

# Make sure Python can see your repo root (the folder that contains app.py)
REPO_ROOT = os.path.dirname(os.path.dirname(__file__))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from app import app  # now this import will work
# tests/smoke_test.py
# This file checks that the app starts and key pages work.
# It does NOT call the AI endpoint, so no real API key needed.

import json
from app import app

def must_200(resp, path):
    assert resp.status_code == 200, f"{path} returned {resp.status_code}"

def test_pages_and_quiz():
    client = app.test_client()

    # Main pages open
    must_200(client.get("/"), "/")
    must_200(client.get("/healthz"), "/healthz")
    must_200(client.get("/study"), "/study")
    must_200(client.get("/flashcards"), "/flashcards")
    must_200(client.get("/quiz"), "/quiz")
    must_200(client.get("/mock-exam"), "/mock-exam")
    must_200(client.get("/progress"), "/progress")

    # Simple quiz submit (1 question)
    sample_questions = [{
        "question": "2+2=?",
        "options": {"A": "3", "B": "4", "C": "5", "D": "22"},
        "correct": "B",
        "explanation": "Basic math: 2 plus 2 equals 4."
    }]
    payload = {
        "quiz_type": "practice",
        "domain": "general",
        "questions": sample_questions,
        "answers": {"0": "B"}  # pick the right answer
    }
    r = client.post("/api/submit-quiz", json=payload)
    must_200(r, "/api/submit-quiz")
    data = r.get_json() or {}
    assert data.get("success") is True
    assert "score" in data and "detailed_results" in data
    assert data["detailed_results"][0]["is_correct"] is True
