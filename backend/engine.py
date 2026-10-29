import json
import re
from pathlib import Path

DATA_FILE = Path(__file__).resolve().parent.parent / "data" / "scenarios.json"

SCAM_THRESHOLD = 6.0
CAUTION_THRESHOLD = 3.0

SENSITIVE_RE = re.compile(r"(?<!\d)\d{4,6}(?!\d)|\b\d{9,18}\b")

def _load():
    with open(DATA_FILE, encoding="utf-8") as f:
        data = json.load(f)
    flags = re.IGNORECASE
    for s in data["signals"] + data["safeSignals"]:
        s["_re"] = re.compile(s["p"], flags)
    for sc in data["scenarios"]:
        for t in sc["triggers"]:
            t["_re"] = re.compile(t["p"], flags)
    return data

DATA = _load()
SCENARIOS = {s["id"]: s for s in DATA["scenarios"]}

def contains_sensitive_number(text: str) -> bool:
    return bool(SENSITIVE_RE.search(text or ""))

def _public_scenario(sc):
    return {k: sc[k] for k in ("id", "icon", "name", "category", "redFlags", "why", "actions", "source")}

def analyze(text: str) -> dict:
    text = (text or "").strip()[:1200]
    norm = re.sub(r"\s+", " ", text.lower())

    safe = [s for s in DATA["safeSignals"] if s["_re"].search(norm)]
    for s in safe:
        norm = s["_re"].sub(" ", norm)
    signals = [s for s in DATA["signals"] if s["_re"].search(norm)]
    signal_score = sum(s["w"] for s in signals)
    safe_score = sum(s["w"] for s in safe)  # negative numbers

    best, best_score = None, 0.0
    ranking = []
    for sc in DATA["scenarios"]:
        score = sum(t["w"] for t in sc["triggers"] if t["_re"].search(norm))
        if score > 0:
            ranking.append((score, sc))
        if score > best_score:
            best, best_score = sc, score
    ranking.sort(key=lambda x: -x[0])

    risk = best_score + 0.5 * signal_score + safe_score
    if best is None:
        risk = min(risk, 0.5 * signal_score + safe_score)

    if best and risk >= SCAM_THRESHOLD:
        level = "scam"
    elif (best and risk >= CAUTION_THRESHOLD) or signal_score + safe_score >= 3:
        level = "caution"
    else:
        level = "safe"

    percent = max(3, min(99, round(risk * 8))) if level != "safe" else max(2, min(25, round(max(risk, 0) * 8)))

    result = {
        "level": level,
        "risk": percent,
        "signals": [{"id": s["id"], "label": s["label"]} for s in signals],
        "safeSignals": [{"id": s["id"], "label": s["label"]} for s in safe],
        "scenario": _public_scenario(best) if best and level != "safe" else None,
        "alternatives": [_public_scenario(sc)["id"] for _, sc in ranking[1:3]] if level != "safe" else [],
        "question": best["question"] if best and level == "caution" else None,
        "helpline": DATA["helpline"],
        "portal": DATA["portal"],
        "sensitiveWarning": contains_sensitive_number(text),
    }
    return result

def scenario_list():
    return [
        {**_public_scenario(s), "example": s["example"]}
        for s in DATA["scenarios"]
    ]
