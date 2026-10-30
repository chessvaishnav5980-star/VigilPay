import os
import re

import requests

GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
MODELS = [m for m in [os.getenv("GEMINI_MODEL", "gemini-3.6-flash"), "gemini-3.5-flash-lite"] if m]

SYSTEM_PROMPT = """You are VigilPay, a calm, friendly UPI safety coach for Indian users, including school students and elders.
Reply directly to what the user actually said. Never give a canned or repeated answer: mention the specific details they gave (who contacted them, what was asked, the amount, the app).
Rules you must never break:
- NEVER ask the user for a UPI PIN, OTP, password, CVV, card number or account number. If they typed one, tell them not to.
- Our rule engine gives a hint verdict (SCAM / BE CAREFUL / NOT CLEAR). Use it as a guide, but you may add detail. If the message is unclear, ask ONE short question that would settle it (did they ask for a PIN/OTP, a link, a payment, or to install an app?).
- You can also answer general questions about UPI safety, how a scam works, or what to do after a fraud. If asked something unrelated to UPI, banking or scams, say politely that you only help with UPI safety.
- Reply in at most 110 words, simple English (or the user's language if they wrote in Hindi or Telugu).
- When it is a likely scam, give 2-3 short action steps and end with: Helpline 1930, cybercrime.gov.in.
- Never be scary or preachy. Never invent laws, numbers or bank policies. No legal or financial advice."""

BANNED = re.compile(r"(send|share|enter|tell|give|type).{0,20}(your )?(upi pin|otp|cvv|password|card number)", re.I)

def _safe(reply: str) -> bool:
    if not reply or len(reply) > 1100:
        return False
    for m in BANNED.finditer(reply):
        before = reply[max(0, m.start() - 12):m.start()].lower()
        if not re.search(r"(never|not|n't|don't|do not)\s*$", before):
            return False
    return True

def explain(user_text: str, result: dict, history=None):
    key = os.getenv("GEMINI_API_KEY")
    if not key:
        return None

    unclear = result["level"] == "safe" and not result["signals"] and not result["safeSignals"]
    verdict = "NOT CLEAR YET" if unclear else {"scam": "SCAM", "caution": "BE CAREFUL", "safe": "NO SCAM SIGNS FOUND"}[result["level"]]
    scenario = result.get("scenario") or {}
    facts = (
        f"Verdict: {verdict}. Matched pattern: {scenario.get('name', 'none')}. "
        f"Red flags found: {', '.join(s['label'] for s in result['signals']) or 'none'}. "
        f"Official reasoning: {scenario.get('why', 'No known scam pattern matched.')}"
    )
    prompt = f"{facts}\n\nUser said: {user_text[:800]}\n\nWrite the reply."
    contents = []
    for h in (history or [])[-6:]:
        if not str(h.get("text", "")).strip():
            continue  # Gemini rejects empty parts
        contents.append({"role": "user" if h.get("role") == "user" else "model",
                         "parts": [{"text": str(h.get("text", ""))[:500]}]})
    contents.append({"role": "user", "parts": [{"text": prompt}]})

    body = {
        "systemInstruction": {"parts": [{"text": SYSTEM_PROMPT}]},
        "contents": contents,
        "generationConfig": {"temperature": 0.6, "maxOutputTokens": 320},
    }
    for model in MODELS:
        try:
            r = requests.post(
                GEMINI_URL.format(model=model),
                headers={"x-goog-api-key": key, "Content-Type": "application/json"},
                json=body,
                timeout=12,
            )
            if r.status_code == 429:
                continue  # free tier limit hit, try the lighter model
            r.raise_for_status()
            text = r.json()["candidates"][0]["content"]["parts"][0]["text"].strip()
            if _safe(text):
                return {"text": text, "model": model}
        except Exception:
            continue
    return None
