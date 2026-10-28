import os
import re
import time
from collections import defaultdict, deque
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory

import ai
import db
import engine

ROOT = Path(__file__).resolve().parent.parent
app = Flask(__name__, static_folder=str(ROOT / "frontend"), static_url_path="")

_hits = defaultdict(deque)

def limited(limit=30, window=60):
    ip = (request.headers.get("X-Forwarded-For", request.remote_addr) or "?").split(",")[0].strip()
    now = time.time()
    q = _hits[ip]
    while q and now - q[0] > window:
        q.popleft()
    if len(q) >= limit:
        return True
    q.append(now)
    return False

def bearer():
    auth = request.headers.get("Authorization", "")
    return auth[7:] if auth.startswith("Bearer ") else None

def current_user():
    t = bearer()
    return db.verify_token(t) if t else None

def redact(text: str) -> str:
    return engine.SENSITIVE_RE.sub("[number removed]", text or "")

@app.get("/")
def index():
    return send_from_directory(app.static_folder, "index.html")

@app.get("/data/<path:name>")
def data_files(name):
    return send_from_directory(ROOT / "data", name)

@app.get("/api/health")
def health():
    return jsonify(ok=True, ai=bool(os.getenv("GEMINI_API_KEY")), db=db.enabled())

@app.get("/api/config")
def config():
    return jsonify(
        supabaseUrl=db.URL,
        supabaseAnonKey=db.ANON,
        aiEnabled=bool(os.getenv("GEMINI_API_KEY")),
        dbEnabled=db.enabled(),
    )

@app.get("/api/scenarios")
def scenarios():
    return jsonify(engine.scenario_list())

@app.post("/api/analyze")
def analyze():
    if limited():
        return jsonify(error="Too many requests. Please wait a minute."), 429
    body = request.get_json(silent=True) or {}
    text = str(body.get("text", ""))[:1200]
    if not text.strip():
        return jsonify(error="Please describe what happened."), 400

    result = engine.analyze(text)
    user = current_user()

    result["ai"] = None
    result["aiLocked"] = False
    if os.getenv("GEMINI_API_KEY"):
        result["ai"] = ai.explain(redact(text), result, body.get("history"))

    db.rpc("log_check", {
        "p_scenario": result["scenario"]["id"] if result["scenario"] else None,
        "p_level": result["level"],
        "p_risk": result["risk"],
        "p_ai": bool(result["ai"]),
    }, token=bearer() if user else None)
    return jsonify(result)

@app.post("/api/quiz")
def quiz_result():
    if limited(20):
        return jsonify(error="Too many requests."), 429
    body = request.get_json(silent=True) or {}
    phase = body.get("phase")
    try:
        score, total = int(body.get("score")), int(body.get("total"))
    except (TypeError, ValueError):
        return jsonify(error="Invalid score."), 400
    if phase not in ("before", "after", "practice") or not (0 <= score <= total <= 50):
        return jsonify(error="Invalid quiz result."), 400
    alias = re.sub(r"[^A-Za-z0-9 ]", "", str(body.get("alias", "")))[:24] or "Guest"
    user = current_user()
    saved = db.rpc("save_quiz", {"p_alias": alias, "p_phase": phase, "p_score": score, "p_total": total},
                   token=bearer() if user else None)
    return jsonify(saved=bool(saved))

@app.get("/api/stats")
def stats():
    data = db.rpc("vigilpay_stats")
    return jsonify(data or {"total_checks": 0, "scams": 0, "caution": 0, "safe": 0,
                            "top": [], "before_avg": None, "after_avg": None, "testers": 0, "improved": 0,
                            "live": False})

@app.get("/api/history")
def history():
    user = current_user()
    if not user:
        return jsonify(error="Sign in to see your history."), 401
    return jsonify(db.rpc("my_history", token=bearer()) or [])

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=os.getenv("FLASK_DEBUG") == "1")
