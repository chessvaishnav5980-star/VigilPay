"""Optional VigilPay Python risk engine.

The browser-side engine remains the private default. This service is used only
when a visitor explicitly enables Python deep scan in the interface.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from fastapi import FastAPI
from pydantic import BaseModel, Field

app = FastAPI(title="VigilPay Python Risk Engine", version="1.0.0")


class AnalysisRequest(BaseModel):
    text: str = Field(min_length=8, max_length=20_000)


@dataclass(frozen=True)
class Rule:
    category: str
    weight: int
    icon: str
    pattern: re.Pattern[str]
    message: str


RULES = (
    Rule("Credential theft", 34, "••", re.compile(r"\b(otp|one[ -]?time password|upi pin|cvv|card pin|password|passcode|security code)\b", re.I), "A secret credential is being requested."),
    Rule("Remote access", 35, "⌁", re.compile(r"\b(anydesk|teamviewer|quicksupport|remote access|screen share|share your screen)\b", re.I), "Remote control can expose the device and banking activity."),
    Rule("Forced urgency", 16, "⌛", re.compile(r"\b(urgent|immediately|act now|within \d+ (minute|hour)|account (will be )?blocked|disconnect(ed|ion)? tonight)\b", re.I), "A deadline is being used to prevent independent verification."),
    Rule("Fear & authority", 24, "!", re.compile(r"\b(police|cbi|customs|court|arrest|illegal (parcel|package|drugs)|cyber cell|warrant|money laundering)\b", re.I), "Authority or punishment is being used to create panic."),
    Rule("Secrecy & isolation", 22, "◌", re.compile(r"\b(do not tell|don'?t tell|keep (this|it) secret|stay on (the )?(call|line)|do not hang up)\b", re.I), "The sender is trying to isolate the target from help."),
    Rule("Payment to receive", 38, "▦", re.compile(r"(scan (this|the|my) qr|enter (your )?upi pin).{0,80}(receive|get|refund)|\b(receive|get|refund).{0,80}(scan (this|the|my) qr|enter (your )?upi pin)", re.I), "A payment action is being falsely described as receiving money."),
    Rule("Advance fee", 24, "₹", re.compile(r"\b(registration fee|processing fee|security deposit|refundable (fee|deposit)|unlock (the )?(task|payment|withdrawal)|clearance fee)\b", re.I), "Money is demanded before a reward, job, refund or withdrawal."),
    Rule("Too-good-to-be-true offer", 14, "✦", re.compile(r"\b(guaranteed (profit|return|income)|earn ₹?\s?[\d,]+ (daily|per day)|lottery|prize|double your money)\b", re.I), "The offer promises unusually easy or guaranteed money."),
)


@app.get("/health")
def health() -> dict[str, object]:
    return {"ok": True, "engine": "python", "rules": len(RULES)}


@app.post("/analyze")
def analyze(payload: AnalysisRequest) -> dict[str, object]:
    matches = [rule for rule in RULES if rule.pattern.search(payload.text)]
    score = min(100, sum(rule.weight for rule in matches) + (8 if len(matches) >= 3 else 0))
    level = "high" if score >= 70 else "suspicious" if score >= 30 else "low"
    title = {"high": "High-risk scam pattern", "suspicious": "Suspicious—verify first", "low": "No strong scam pattern detected"}[level]
    summary = {
        "high": "Stop contact and do not send money, codes or documents. Verify through an official channel.",
        "suspicious": "Pause the transaction and verify every claim independently.",
        "low": "No strong rule matched, but this does not prove the situation is safe.",
    }[level]
    actions = ["Stop and verify the sender through an official channel you find independently."]
    categories = {rule.category for rule in matches}
    if "Payment to receive" in categories:
        actions.insert(0, "Do not scan the QR or enter a UPI PIN to receive money.")
    if "Credential theft" in categories:
        actions.append("Do not share an OTP, PIN, CVV or password; use Emergency Mode if already shared.")
    if "Remote access" in categories:
        actions.append("Do not install remote-access software; disconnect the device if it is already active.")
    return {
        "engine": "python",
        "score": score,
        "level": level,
        "title": title,
        "summary": summary,
        "matches": [{"category": r.category, "weight": r.weight, "icon": r.icon, "message": r.message} for r in matches],
        "actions": actions[:4],
    }
