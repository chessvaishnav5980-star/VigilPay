import gzip
import hashlib
import json
import mimetypes
import os
import re
import threading
import time
import uuid
from urllib.parse import urlparse
from collections import defaultdict, deque
from pathlib import Path

from flask import Flask, Response, jsonify, request, send_from_directory

import accounts
import ai
import db
import engine
import intel
import linktrace
import requests

ROOT = Path(__file__).resolve().parent.parent
app = Flask(__name__, static_folder=str(ROOT / "frontend"), static_url_path="")
mimetypes.add_type("application/manifest+json", ".webmanifest")

BUILD = "2026-11-05"
STARTED = time.time()

_hits = defaultdict(deque)
_hits_lock = threading.Lock()

def limited(limit=30, window=60, key="", everyone=False):
    """True when this IP has made `limit` calls in the last `window` seconds. A `key` gives an endpoint its own counter.

    A whole school can share one public IP address, so per-IP limits are generous. `everyone=True` counts all visitors
    together instead, which protects a free service (such as Gemini) that has its own limit."""
    ip = "*" if everyone else (request.headers.get("X-Forwarded-For", request.remote_addr) or "?").split(",")[0].strip()
    now = time.time()
    with _hits_lock:
        if len(_hits) > 4000:  # forget old visitors so memory cannot grow forever
            for k in [k for k, q in _hits.items() if not q or now - q[-1] > 3600]:
                _hits.pop(k, None)
        q = _hits[(ip, key)]
        while q and now - q[0] > window:
            q.popleft()
        if len(q) >= limit:
            return True
        q.append(now)
        return False

_trace_slots = threading.BoundedSemaphore(6)  # at most 6 links being followed at once, so health checks and chats never wait behind them

def bearer():
    auth = request.headers.get("Authorization", "")
    return auth[7:] if auth.startswith("Bearer ") else None

def current_user():
    t = bearer()
    return db.verify_token(t) if t else None

def redact(text: str) -> str:
    return engine.SENSITIVE_RE.sub("[number removed]", text or "")

def public_config():
    """Settings the browser may know. The Supabase anon key is public by design; no secret ever goes in here."""
    return dict(
        supabaseUrl=db.URL,
        supabaseAnonKey=db.ANON,
        aiEnabled=bool(os.getenv("GEMINI_API_KEY")),
        dbEnabled=db.enabled(),
        linkCheck=bool(os.getenv("SAFE_BROWSING_API_KEY")),
        googleClientId=accounts.GOOGLE_CLIENT_ID if accounts.google_ready() else "",
        instantSignup=accounts.instant_signup(),
        build=BUILD,
    )

_page = {"sig": None, "etag": "", "raw": b"", "gz": b""}

def _page_bytes():
    """index.html with the settings written into it, so the page never has to wait for a second request to know them.
    That second request used to fail while a sleeping free server was waking up, which left sign-in, AI and link checks off."""
    f = ROOT / "frontend" / "index.html"
    cfg = public_config()
    sig = (f.stat().st_mtime_ns, json.dumps(cfg, sort_keys=True))
    if _page["sig"] != sig:
        text = f.read_text(encoding="utf-8")
        tag = "<script>window.VP_CONFIG=" + json.dumps(cfg).replace("</", "<\\/") + ";</script>"
        raw = text.replace("<!--VP_CONFIG-->", tag, 1).encode("utf-8")
        _page.update(sig=sig, raw=raw, gz=gzip.compress(raw, 6), etag='"' + hashlib.sha1(raw).hexdigest()[:20] + '"')
    return _page

@app.get("/")
def index():
    p = _page_bytes()
    headers = {"ETag": p["etag"], "Cache-Control": "no-cache", "Vary": "Accept-Encoding"}
    if request.headers.get("If-None-Match") == p["etag"]:
        return Response(status=304, headers=headers)
    if "gzip" in request.headers.get("Accept-Encoding", ""):
        return Response(p["gz"], mimetype="text/html", headers={**headers, "Content-Encoding": "gzip"})
    return Response(p["raw"], mimetype="text/html", headers=headers)

@app.get("/data/<path:name>")
def data_files(name):
    return send_from_directory(ROOT / "data", name)

_CACHE_RULES = (("/api/", "no-store"), ("/sw.js", "no-cache"), ("/data/", "public, max-age=600"), ("/lang/", "public, max-age=3600"),
                ("/manifest.webmanifest", "public, max-age=86400"), ("/icon", "public, max-age=86400"), ("/apple-touch-icon", "public, max-age=86400"),
                ("/favicon", "public, max-age=86400"), ("/shot", "public, max-age=86400"))
_SQUEEZE = ("text/", "application/json", "application/javascript", "application/manifest+json", "image/svg+xml")

@app.after_request
def polish(resp):
    """Say how long each kind of file may be kept, and shrink big text replies. Both make a slow connection feel faster."""
    path = request.path
    if "Cache-Control" not in resp.headers:
        for prefix, value in _CACHE_RULES:
            if path.startswith(prefix):
                resp.headers["Cache-Control"] = value
                break
    if (request.method == "GET" and resp.status_code == 200 and not resp.direct_passthrough and "Content-Encoding" not in resp.headers
            and resp.mimetype.startswith(_SQUEEZE) and "gzip" in request.headers.get("Accept-Encoding", "")):
        data = resp.get_data()
        if len(data) > 1200:
            resp.set_data(gzip.compress(data, 6))
            resp.headers["Content-Encoding"] = "gzip"
            etag = resp.headers.get("ETag")
            if etag:
                resp.headers["ETag"] = etag.rstrip('"') + '-gz"'
    if resp.mimetype.startswith(_SQUEEZE):
        resp.headers.add("Vary", "Accept-Encoding")
    return resp

@app.get("/api/health")
def health():
    return jsonify(ok=True, ai=bool(os.getenv("GEMINI_API_KEY")), db=db.enabled(), t=int(time.time()))

@app.get("/api/config")
def config():
    return jsonify(public_config())

@app.get("/api/status")
def status():
    """What is switched on, for the in-page 'Site status' panel. ?deep=1 also tests each outside service once."""
    out = {"ok": True, "build": BUILD, "uptime": int(time.time() - STARTED), "now": int(time.time()),
           "features": {"database": db.enabled(), "ai": bool(os.getenv("GEMINI_API_KEY")), "safeBrowsing": bool(os.getenv("SAFE_BROWSING_API_KEY")), "dns": True,
                    "instantSignup": accounts.instant_signup(), "googleSignIn": accounts.google_ready()}}
    if request.args.get("deep") == "1":
        if limited(4, 60, "statusdeep"):
            out["deep"] = {"error": "rate"}
        else:
            out["deep"] = intel.self_test(os.getenv("SAFE_BROWSING_API_KEY"))
            out["deep"]["database"] = {"ok": bool(db.rpc("vigilpay_stats") is not None), "code": None} if db.enabled() else {"ok": False, "code": "off"}
            out["deep"]["accounts"] = accounts.self_test()
    return jsonify(out)

@app.post("/api/auth/signup")
def auth_signup():
    """Make an account that is already confirmed, so the person can sign in at once. Needs SUPABASE_SERVICE_KEY on the server."""
    if limited(15, 60, "signup"):
        return jsonify(ok=False, reason="rate"), 429
    if not accounts.instant_signup():
        return jsonify(ok=False, reason="not_configured")
    d = request.get_json(silent=True) or {}
    email = str(d.get("email", "")).strip().lower()
    password = str(d.get("password", ""))
    if not accounts.EMAIL_RE.match(email) or len(email) > 254:
        return jsonify(ok=False, reason="bad_email"), 400
    if len(password) < 8 or len(password) > 72:
        return jsonify(ok=False, reason="weak"), 400
    state, info = accounts.create_user(email, password, d.get("name", ""))
    if state == "ok":
        return jsonify(ok=True)
    if state in ("exists", "weak"):
        return jsonify(ok=False, reason=state)
    app.logger.warning("signup failed: %s", info)
    return jsonify(ok=False, reason="error", code=str(info)[:40]), 502

@app.post("/api/auth/google")
def auth_google():
    """Check a Google sign-in token and hand back a normal session (with the Google name and picture)."""
    if limited(30, 60, "googlein"):
        return jsonify(ok=False, reason="rate"), 429
    if not accounts.google_ready():
        return jsonify(ok=False, reason="not_configured")
    d = request.get_json(silent=True) or {}
    state, out = accounts.google_login(str(d.get("credential", ""))[:5000])
    if state == "ok":
        return jsonify(ok=True, session=out)
    app.logger.warning("google sign-in failed: %s", out)
    return jsonify(ok=False, reason=str(out)[:40]), (400 if out in ("bad_token", "wrong_client", "email_not_verified") else 502)

@app.get("/api/scenarios")
def scenarios():
    return jsonify(engine.scenario_list())

@app.post("/api/analyze")
def analyze():
    if limited(60) or limited(240, 60, "analyze", everyone=True):
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
        result["ai"] = ai.explain(redact(text), result, body.get("history"), str(body.get("lang", "en"))[:8])

    db.rpc("log_check", {
        "p_scenario": result["scenario"]["id"] if result["scenario"] else None,
        "p_level": result["level"],
        "p_risk": result["risk"],
        "p_ai": bool(result["ai"]),
    }, token=bearer() if user else None)
    return jsonify(result)

@app.post("/api/quiz")
def quiz_result():
    if limited(60, 60, "quiz"):
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
    if limited(120, 60, "lookup"):
        return jsonify(error="Too many requests."), 429
    b = request.get_json(silent=True) or {}
    kind, n = b.get("kind"), normalize(b.get("kind"), b.get("value"))
    if not n:
        return jsonify(error="That does not look like a valid " + str(kind) + "."), 400
    res = db.rpc("lookup_indicator", {"p_hash": ihash(kind, n)})
    return jsonify(live=res is not None, display=mask(kind, n), **(res or {"reporters": 0, "flags": 0, "categories": [], "linked": []}))

@app.post("/api/report")
def report():
    if limited(30, 60, "report"):
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
    if limited(30, 60, "flag") or not current_user():
        return jsonify(error="Sign in to flag a report."), 401
    b = request.get_json(silent=True) or {}
    n = normalize(b.get("kind"), b.get("value"))
    return jsonify(ok=bool(n and db.rpc("flag_indicator", {"p_hash": ihash(b["kind"], n)}, token=bearer())))

@app.post("/api/linkcheck")
def link_check_live():
    """Is this link already known to be dangerous? Google Safe Browsing (if a key is set) plus two public security DNS filters.
    Accepts {"url": "..."} or {"urls": [...]} (up to 6, for example every step of a redirect chain)."""
    if limited(90, 60, "linkcheck") or limited(400, 60, "linkcheck", everyone=True):
        return jsonify(error="Too many link checks. Please wait a minute."), 429
    b = request.get_json(silent=True) or {}
    urls = b.get("urls") if isinstance(b.get("urls"), list) else [b.get("url")]
    res = intel.check_links([str(u) for u in urls if u][:intel.MAX_URLS], os.getenv("SAFE_BROWSING_API_KEY"))
    return jsonify(res), (200 if res.get("ok") else 400)

@app.post("/api/link")
def link_check():
    """Older single-link answer, kept so an older cached page keeps working."""
    key = os.getenv("SAFE_BROWSING_API_KEY")
    if not key:
        return jsonify(checked=False)
    if limited(90, 60, "linkcheck"):
        return jsonify(error="Too many requests."), 429
    res = intel.check_links([str((request.get_json(silent=True) or {}).get("url", ""))[:1000]], key)
    it = (res.get("items") or [None])[0]
    gsb = next((s for s in (it or {}).get("sources", []) if s["id"] == "gsb"), None)
    if not gsb or gsb["state"] not in ("clear", "flagged"):
        return jsonify(checked=False)
    return jsonify(checked=True, flagged=gsb["state"] == "flagged", threats=gsb.get("threats", []))

@app.post("/api/trace")
def trace_link():
    """Follow a link's redirects on the server and say where it ends up (see linktrace.py for the safety rules)."""
    if limited(40, 60, "trace") or limited(240, 60, "trace", everyone=True):
        return jsonify(error="Too many link checks. Please wait a minute."), 429
    url = str((request.get_json(silent=True) or {}).get("url", "")).strip()[:1000]
    if not url:
        return jsonify(error="Send a link to follow."), 400
    if not _trace_slots.acquire(timeout=3):
        return jsonify(ok=False, kind="rate", error="Many people are checking links right now. Please try again in a moment.", hops=[]), 200
    try:
        return jsonify(linktrace.follow(url))
    finally:
        _trace_slots.release()

@app.post("/api/review")
def review_text():
    """Optional second opinion from Gemini on a message. The rules still decide the verdict; the AI only points out clues."""
    if not os.getenv("GEMINI_API_KEY"):
        return jsonify(ok=False, reason="ai_off")
    if limited(20, 60, "review") or limited(10, 60, "review", everyone=True):
        return jsonify(ok=False, reason="busy"), 429
    b = request.get_json(silent=True) or {}
    text = str(b.get("text", ""))[:1500]
    if not text.strip():
        return jsonify(error="Paste a message first."), 400
    res = ai.review(redact(text), str(b.get("lang", "en"))[:8])
    return jsonify(ok=bool(res), review=res, reason=None if res else "busy")


# ---------------------------------------------------------------- Robo Run leaderboard
NICK_RE = re.compile(r"^[A-Za-z][A-Za-z0-9 _.\-]{1,15}$")
# Not exhaustive. It is a first filter; the leaderboard also hides anything that looks like contact details.
BLOCKED = ("fuck", "shit", "bitch", "bastard", "asshole", "dick", "pussy", "cunt", "slut", "whore", "nigg", "rape", "porn", "sex",
           "chutiya", "madarchod", "bhenchod", "behenchod", "gandu", "randi", "harami", "kutta", "bhosd", "lund", "gaand")

def clean_nick(raw):
    nick = re.sub(r"\s+", " ", str(raw or "")).strip()
    if not NICK_RE.match(nick):
        return None
    low = nick.lower()
    # check the plain name and two "leetspeak" readings (1 can stand for i or l)
    flats = [re.sub(r"[^a-z]", "", low.translate(str.maketrans("0134578@$", "o" + one + "eastbas"))) for one in ("i", "l")] + [re.sub(r"[^a-z]", "", low)]
    if any(b in f for b in BLOCKED for f in flats) or len(re.findall(r"\d", nick)) > 4:
        return None
    return nick

def plausible_run(distance, coins, bosses, score, seconds):
    """The game's own formula and speed limits. A browser game cannot be made cheat-proof, but wild numbers are rejected."""
    return (0 <= distance <= 100000 and 0 <= coins <= distance // 2 + 25 and 0 <= bosses <= distance // 150 + 1
            and 1 <= seconds <= 7200 and distance <= seconds * 32 + 60
            and score == distance + coins * 5 + bosses * 200)

@app.post("/api/game/score")
def game_score():
    if limited(40, 60, "game"):
        return jsonify(error="Too many submissions. Please wait a minute."), 429
    b = request.get_json(silent=True) or {}
    try:
        distance, coins, bosses, score, seconds = (int(b.get(k)) for k in ("distance", "coins", "bosses", "score", "seconds"))
    except (TypeError, ValueError):
        return jsonify(error="Invalid run."), 400
    nick = clean_nick(b.get("nick"))
    if not nick:
        return jsonify(error="Pick a nickname of 2 to 16 letters or numbers. Please do not use a real full name, phone number or rude words."), 400
    if not plausible_run(distance, coins, bosses, score, seconds):
        return jsonify(error="That run does not look possible, so it was not saved."), 400
    user = current_user()
    ok = db.rpc("submit_game_score", {"p_nick": nick, "p_score": score, "p_distance": distance, "p_coins": coins,
                                      "p_bosses": bosses, "p_seconds": seconds}, token=bearer() if user else None)
    return jsonify(saved=ok is True, live=db.enabled())

@app.get("/api/game/leaderboard")
def game_leaderboard():
    if limited(240, 60, "board"):
        return jsonify(error="Too many requests."), 429
    by = request.args.get("by", "score")
    period = request.args.get("period", "all")
    if by not in ("score", "distance", "coins", "bosses") or period not in ("all", "week"):
        return jsonify(error="Invalid board."), 400
    rows = db.rpc("game_leaderboard", {"p_by": by, "p_period": period, "p_limit": 20})
    return jsonify(live=rows is not None, rows=rows if isinstance(rows, list) else [])


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=os.getenv("FLASK_DEBUG") == "1")
