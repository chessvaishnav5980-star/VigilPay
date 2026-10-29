import hashlib
import os
import re
import time
import uuid
from urllib.parse import urlparse
from collections import defaultdict, deque
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory

import ai
import db
import engine
import requests

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
        linkCheck=bool(os.getenv("SAFE_BROWSING_API_KEY")),
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

def normalize(kind, value):
    v = (value or "").strip().lower()
    if kind == "phone":
        d = re.sub(r"\D", "", v)
        return d[-10:] if len(d) >= 10 else None
    if kind == "upi":
        return v if re.fullmatch(r"[a-z0-9.\-_]{2,50}@[a-z]{2,30}", v) else None
    if kind == "url":
        host = urlparse(v if "//" in v else "http://" + v).hostname or ""
        host = re.sub(r"^www\.", "", host)
        return host if "." in host and len(host) < 80 else None
    return None

def mask(kind, n):
    if kind == "phone":
        return n[:2] + "\u2022" * 6 + n[-2:]
    if kind == "upi":
        name, handle = n.split("@")
        return name[:2] + "\u2022\u2022\u2022\u2022@" + handle
    return n

def ihash(kind, n):
    salt = os.getenv("REPORT_SALT") or db.URL or "vigilpay"
    return hashlib.sha256(f"{salt}|{kind}|{n}".encode()).hexdigest()

@app.post("/api/lookup")
def lookup():
    if limited(40):
        return jsonify(error="Too many requests."), 429
    b = request.get_json(silent=True) or {}
    kind, n = b.get("kind"), normalize(b.get("kind"), b.get("value"))
    if not n:
        return jsonify(error="That does not look like a valid " + str(kind) + "."), 400
    res = db.rpc("lookup_indicator", {"p_hash": ihash(kind, n)})
    return jsonify(live=res is not None, display=mask(kind, n), **(res or {"reporters": 0, "flags": 0, "categories": [], "linked": []}))

@app.post("/api/report")
def report():
    if limited(10):
        return jsonify(error="Too many requests."), 429
    token = bearer()
    if not current_user():
        return jsonify(error="Sign in to report."), 401
    b = request.get_json(silent=True) or {}
    items, case, saved = (b.get("items") or [])[:4], str(uuid.uuid4()), 0
    for it in items:
        n = normalize(it.get("kind"), it.get("value"))
        if n and db.rpc("submit_report", {"p_kind": it["kind"], "p_hash": ihash(it["kind"], n), "p_display": mask(it["kind"], n),
                                           "p_category": str(b.get("category", "other")), "p_case": case}, token=token):
            saved += 1
    return jsonify(saved=saved) if saved else (jsonify(error="Nothing saved. Check the details, or you may have reached today's limit."), 400)

@app.post("/api/flag")
def flag():
    if limited(10) or not current_user():
        return jsonify(error="Sign in to flag a report."), 401
    b = request.get_json(silent=True) or {}
    n = normalize(b.get("kind"), b.get("value"))
    return jsonify(ok=bool(n and db.rpc("flag_indicator", {"p_hash": ihash(b["kind"], n)}, token=bearer())))

@app.post("/api/link")
def link_check():
    key = os.getenv("SAFE_BROWSING_API_KEY")
    if not key:
        return jsonify(checked=False)
    if limited(20):
        return jsonify(error="Too many requests."), 429
    url = str((request.get_json(silent=True) or {}).get("url", ""))[:1000]
    body = {"client": {"clientId": "vigilpay", "clientVersion": "1.0"},
            "threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                           "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"], "threatEntries": [{"url": url}]}}
    try:
        r = requests.post("https://safebrowsing.googleapis.com/v4/threatMatches:find", params={"key": key}, json=body, timeout=8)
        r.raise_for_status()
        m = r.json().get("matches", [])
        return jsonify(checked=True, flagged=bool(m), threats=sorted({x.get("threatType", "") for x in m}))
    except (requests.RequestException, ValueError):
        return jsonify(checked=False)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=os.getenv("FLASK_DEBUG") == "1")
