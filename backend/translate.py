"""AI translation of the page text.

The page is written in English. Every sentence has a short id (the browser works it out from the sentence itself), and a language
file is just a map from ids to translations. This module translates any missing ids with Gemini, checks the answer, and keeps it:

  * the server (/api/translate) translates on demand and remembers the answers for every visitor
    (Supabase table lang_cache when the service key is set, otherwise in memory until the server restarts);
  * tools/build_lang.py translates everything once and writes frontend/lang/<code>.json, which then needs no server at all.

Only ids of sentences that are already on the page are accepted, so the endpoint cannot be used as a free general translator.
Nothing a visitor types is ever sent here."""

from __future__ import annotations

import json
import os
import re
import threading
import time
from collections import deque

import requests

import ai

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MASTER_FILE = os.path.join(ROOT, "backend", "i18n_master.json")
LANG_DIR = os.path.join(ROOT, "frontend", "lang")
GEMINI_URL = os.getenv("VP_GEMINI_URL") or ai.GEMINI_URL
MODELS = ai.MODELS
LANGS = {k: v for k, v in ai.LANG_NAMES.items()}
BATCH = int(os.getenv("TRANSLATE_BATCH", "60"))          # sentences per Gemini call
RPM = int(os.getenv("TRANSLATE_RPM", "12"))              # Gemini calls per minute for this server (free tiers allow about 10 to 15)
DAILY = int(os.getenv("TRANSLATE_DAILY", "1500"))        # Gemini calls per day for this server

SUPABASE_URL = os.getenv("SUPABASE_URL", "").rstrip("/")
SERVICE = os.getenv("SUPABASE_SERVICE_KEY", "") or os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")

TOKENS = re.compile(r"\{\d+\}|\{v\}|</?\d+/?>|&(?:amp|lt|gt);")

SYSTEM = """You translate the text of VigilPay, a free website that teaches Indian school students (about 14 years old) and their families how to avoid UPI payment scams, from English into {language}.
Rules:
1. Be faithful and natural: short, clear, friendly sentences, using the polite form of "you" that public-information websites use in {language}. Do not add, drop or soften anything. Keep button and menu text short.
2. Write in the language's own script with its own punctuation (no romanisation).
3. Keep these exactly as written, in Latin letters: UPI, UPI ID, OTP, PIN, CVV, KYC, QR, SMS, NPCI, RBI, TRAI, PAN, Aadhaar, AnyDesk, TeamViewer, WhatsApp, Telegram, Google, Google Pay, PhonePe, Paytm, BHIM, VigilPay, Sanchar Saathi, Chakshu, web addresses, email addresses and emergency numbers. Use the digits 0-9 only. Keep the rupee sign.
4. Copy placeholders and tags exactly, each the same number of times as in the English: {{0}} {{1}} ... (numbers filled in later; never replace them with digits), {{v}} (a value filled in later), <1>...</1> (markup around some words: keep the tags, translate the words inside, keep them nested), <1/> (an icon: keep it in place), &amp; &lt; &gt;.
5. The safety meaning must not change: never share a PIN or OTP; a PIN is only for paying, never for receiving; call 1930 or 112; "Never type your real PIN or OTP on any website, including ours". Never call anything "safe" unless the English does. Keep "Likely scam", "Suspicious", "No obvious warning signs" and "No known threat found" clearly different.
6. Example scam messages are translated as realistic messages in {language}, keeping the urgency, threat, fee or link that make them scams.
7. Use one word for one idea throughout (scam, fraud, phishing, link, bank, helpline, report, block, refund, collect request).
8. No emojis, notes or alternatives.
The input is a JSON object that maps numbers to English strings. Reply with ONLY a JSON object that maps the same numbers to the translations."""


# ---------------------------------------------------------------- the list of sentences the page contains
_master = {"mtime": 0.0, "data": {}}


def master() -> dict:
    """{id: english sentence}. Rebuilt by tools/export_master.py whenever the page text changes."""
    try:
        m = os.path.getmtime(MASTER_FILE)
        if m != _master["mtime"]:
            with open(MASTER_FILE, encoding="utf-8") as fh:
                _master["data"] = json.load(fh)
            _master["mtime"] = m
    except (OSError, ValueError):
        pass
    return _master["data"]


def valid(en: str, tr) -> bool:
    """True when a translation kept every placeholder and tag, nested the tags properly, and looks like a real answer."""
    if not isinstance(tr, str):
        return False
    tr = tr.strip()
    if not tr or "\t" in tr or "\n" in tr or len(tr) > 4 * len(en) + 60:
        return False
    a, b = TOKENS.findall(en), TOKENS.findall(tr)
    if sorted(a) != sorted(b):
        return False
    stack = []
    for t in b:
        m = re.fullmatch(r"<(\d+)>", t)
        if m:
            stack.append(m.group(1))
            continue
        m = re.fullmatch(r"</(\d+)>", t)
        if m and (not stack or stack.pop() != m.group(1)):
            return False
    return not stack


# ---------------------------------------------------------------- Gemini
class _Pace:
    """Keeps this server inside the free Gemini limits (calls per minute and per day)."""

    def __init__(self):
        self.calls = deque()
        self.day = time.strftime("%Y-%m-%d")
        self.today = 0
        self.lock = threading.Lock()

    def take(self) -> float:
        """0 when a call may go now, otherwise seconds to wait (or -1 when today's allowance is used up)."""
        with self.lock:
            now = time.time()
            d = time.strftime("%Y-%m-%d")
            if d != self.day:
                self.day, self.today = d, 0
            if self.today >= DAILY:
                return -1
            while self.calls and now - self.calls[0] > 60:
                self.calls.popleft()
            if len(self.calls) >= RPM:
                return max(1.0, 60 - (now - self.calls[0]))
            self.calls.append(now)
            self.today += 1
            return 0


pace = _Pace()


def _ask(language: str, numbered: dict, key: str, timeout: int = 60):
    body = {
        "systemInstruction": {"parts": [{"text": SYSTEM.format(language=language)}]},
        "contents": [{"role": "user", "parts": [{"text": json.dumps(numbered, ensure_ascii=False)}]}],
        "generationConfig": {"temperature": 0.2, "responseMimeType": "application/json", "maxOutputTokens": 16384},
    }
    for model in MODELS:
        try:
            r = requests.post(GEMINI_URL.format(model=model), headers={"x-goog-api-key": key, "Content-Type": "application/json"}, json=body, timeout=timeout)
            if r.status_code in (429, 500, 503):
                continue
            r.raise_for_status()
            text = r.json()["candidates"][0]["content"]["parts"][0]["text"].strip()
            text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text)
            data = json.loads(text)
            if isinstance(data, dict):
                return data
        except (requests.RequestException, KeyError, IndexError, ValueError):
            continue
    return None


def translate_batch(code: str, items: dict, key: str, depth: int = 0) -> dict:
    """items = {id: english}. Returns {id: translation} for the ones that came back correct (anything wrong is left out)."""
    language = LANGS.get(code)
    if not language or not items:
        return {}
    ids = list(items)
    numbered = {str(i + 1): items[x] for i, x in enumerate(ids)}
    data = _ask(language, numbered, key)
    if data is None and len(ids) > 12 and depth < 2:        # answer cut off or malformed: ask for each half on its own
        half = len(ids) // 2
        out = translate_batch(code, {x: items[x] for x in ids[:half]}, key, depth + 1)
        out.update(translate_batch(code, {x: items[x] for x in ids[half:]}, key, depth + 1))
        return out
    data = data or {}
    out, redo = {}, {}
    for i, x in enumerate(ids):
        tr = data.get(str(i + 1))
        if valid(items[x], tr):
            out[x] = tr.strip()
        else:
            redo[x] = items[x]
    if redo and len(redo) <= len(ids) // 2 + 3:            # one more try for the few that broke a placeholder
        numbered = {str(i + 1): redo[x] for i, x in enumerate(redo)}
        data = _ask(language, numbered, key) or {}
        for i, x in enumerate(redo):
            tr = data.get(str(i + 1))
            if valid(redo[x], tr):
                out[x] = tr.strip()
    return out


# ---------------------------------------------------------------- what is already translated
_mem: dict = {}                  # code -> {id: text}, remembered since the server started
_mem_lock = threading.Lock()
_db_seen: dict = {}              # code -> (time fetched, {id: text})
_lang_locks: dict = {}
_static: dict = {}               # code -> (mtime, {id: text})
_bad: dict = {}                  # (code, id) -> how many times Gemini failed to translate it correctly


def _lock_for(code: str) -> threading.Lock:
    with _mem_lock:
        return _lang_locks.setdefault(code, threading.Lock())


def db_enabled() -> bool:
    return bool(SUPABASE_URL and SERVICE)


def _head() -> dict:
    return {"apikey": SERVICE, "Authorization": f"Bearer {SERVICE}", "Content-Type": "application/json"}


def static_file(code: str) -> dict:
    path = os.path.join(LANG_DIR, f"{code}.json")
    try:
        m = os.path.getmtime(path)
        hit = _static.get(code)
        if not hit or hit[0] != m:
            with open(path, encoding="utf-8") as fh:
                _static[code] = (m, json.load(fh))
        return _static[code][1]
    except (OSError, ValueError):
        return {}


def db_load(code: str, fresh: bool = False) -> dict:
    if not db_enabled():
        return {}
    hit = _db_seen.get(code)
    if hit and not fresh and time.time() - hit[0] < 45:
        return hit[1]
    try:
        r = requests.get(f"{SUPABASE_URL}/rest/v1/lang_cache", params={"lang": f"eq.{code}", "select": "id,text", "limit": "6000"}, headers=_head(), timeout=8)
        if r.status_code == 200:
            rows = {x["id"]: x["text"] for x in r.json()}
            _db_seen[code] = (time.time(), rows)
            return rows
    except (requests.RequestException, ValueError):
        pass
    _db_seen[code] = (time.time() - 30, hit[1] if hit else {})      # database unreachable: use what we have and look again in about 15 seconds
    return hit[1] if hit else {}


def db_save(code: str, rows: dict) -> None:
    if not db_enabled() or not rows:
        return
    try:
        requests.post(f"{SUPABASE_URL}/rest/v1/lang_cache", params={"on_conflict": "lang,id"},
                      headers={**_head(), "Prefer": "resolution=merge-duplicates,return=minimal"},
                      json=[{"lang": code, "id": i, "text": t} for i, t in rows.items()], timeout=8)
        _db_seen.pop(code, None)
    except requests.RequestException:
        pass


def have(code: str) -> dict:
    """Everything already translated for a language: the static file, the database and this server's memory."""
    out = dict(static_file(code))
    out.update(db_load(code))
    with _mem_lock:
        out.update(_mem.get(code, {}))
    return out


def remember(code: str, rows: dict) -> None:
    with _mem_lock:
        _mem.setdefault(code, {}).update(rows)
    threading.Thread(target=db_save, args=(code, rows), daemon=True).start()


# ---------------------------------------------------------------- the endpoint's work
def serve(code: str, ids: list, key: str | None, limit: int = 0) -> dict:
    """Return translations for the ids that are known, translating one batch of new ones when needed.

    {"tr": {...}, "remaining": n, "unknown": [...], "error": "no-key" | "busy" | "failed" | "off", "wait": seconds}"""
    m = master()
    known = [i for i in dict.fromkeys(ids) if i in m]
    unknown = [i for i in dict.fromkeys(ids) if i not in m]
    got = have(code)
    out = {i: got[i] for i in known if i in got}
    gave_up = [i for i in known if i not in got and _bad.get((code, i), 0) >= 2]      # Gemini could not get these right: leave them in English
    todo = [i for i in known if i not in got and i not in gave_up]
    info = {"tr": out, "remaining": len(todo), "unknown": unknown, "failed": gave_up}
    if not todo:
        return info
    if not m:
        info["error"] = "off"
        return info
    if not key:
        info["error"] = "no-key"
        return info
    with _lock_for(code):
        got = have(code)                                   # another visitor may have just filled some
        batch = [i for i in todo if i not in got][:max(1, min(BATCH, limit or BATCH))]
        if batch:
            w = pace.take()
            if w < 0:
                info["error"] = "busy"
                info["wait"] = 3600
                return info
            if w > 0:
                info["error"] = "busy"
                info["wait"] = int(w) + 1
                return info
            new = translate_batch(code, {i: m[i] for i in batch}, key)
            if new:
                remember(code, new)
            else:
                info["error"] = "failed"
            for i in batch:
                if i not in new:
                    _bad[(code, i)] = _bad.get((code, i), 0) + 1
            out.update(new)
        got = have(code)
        out.update({i: got[i] for i in known if i in got})
    info["failed"] = gave_up + [i for i in todo if i not in out and _bad.get((code, i), 0) >= 2]
    info["remaining"] = len([i for i in todo if i not in out and i not in info["failed"]])
    return info


# ---------------------------------------------------------------- background pre-building (PREWARM_LANGS=hi,te,ur or "all")
progress: dict = {}              # code -> {"have": n, "total": n, "state": "running" | "done" | "stopped"}


def _prewarm(codes: list, key: str) -> None:
    time.sleep(15)
    for code in codes:
        m = master()
        st = progress[code] = {"have": 0, "total": len(m), "state": "running"}
        stuck = 0
        while True:
            got = have(code)
            todo = [i for i in m if i not in got and _bad.get((code, i), 0) < 2]
            st["have"] = len(m) - len(todo)
            if not todo or stuck >= 4:
                break
            w = pace.take()
            if w < 0:
                st["state"] = "stopped"
                return
            if w > 0:
                time.sleep(min(w, 30))
                continue
            with _lock_for(code):
                new = translate_batch(code, {i: m[i] for i in todo[:BATCH]}, key)
                if new:
                    remember(code, new)
                for i in todo[:BATCH]:
                    if i not in new:
                        _bad[(code, i)] = _bad.get((code, i), 0) + 1
            stuck = 0 if new else stuck + 1
        st["state"] = "done"


def start_prewarm(spec: str, key: str) -> list:
    codes = list(LANGS) if spec.strip().lower() == "all" else [c.strip() for c in spec.split(",") if c.strip() in LANGS]
    codes = [c for c in codes if c != "en"]
    if codes and key and (db_enabled() or os.getenv("PREWARM_FORCE")):
        threading.Thread(target=_prewarm, args=(codes, key), daemon=True).start()
        return codes
    return []
