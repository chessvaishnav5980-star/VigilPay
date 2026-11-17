"""Extra reputation lookups for phone numbers and websites. Every source is optional and keyed by an env var.

  VIRUSTOTAL_API_KEY   website verdict from many security scanners
  IPQS_API_KEY         IPQualityScore: website and phone risk score
  NUMVERIFY_API_KEY    carrier, line type and country of a phone number
  TWILIO_ACCOUNT_SID + TWILIO_AUTH_TOKEN   Twilio Lookup: line type and carrier
  (RDAP domain age needs no key)

Airtel, Jio, Vi and Truecaller keep their spam lists private; no public API exists for them, so we never claim to read them.
Every function returns a small dict and never raises. Numbers are sent only to the provider asked, never stored here.
"""
import base64
import datetime as dt
import os
from urllib.parse import quote

import requests

T = 5.0


def _get(url, **kw):
    kw.setdefault("headers", {"User-Agent": "VigilPay/3"})
    return requests.get(url, timeout=T, **kw)


def vt_url(url):
    key = os.getenv("VIRUSTOTAL_API_KEY")
    if not key:
        return {"id": "virustotal", "state": "off"}
    try:
        uid = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        r = _get(f"https://www.virustotal.com/api/v3/urls/{uid}", headers={"x-apikey": key})
        if r.status_code == 404:
            return {"id": "virustotal", "state": "unseen"}
        if r.status_code != 200:
            return {"id": "virustotal", "state": "error"}
        s = r.json()["data"]["attributes"]["last_analysis_stats"]
        bad = int(s.get("malicious", 0)) + int(s.get("suspicious", 0))
        return {"id": "virustotal", "state": "flagged" if bad >= 2 else ("weak" if bad == 1 else "clear"),
                "bad": bad, "total": sum(int(v) for v in s.values())}
    except Exception:  # noqa: BLE001
        return {"id": "virustotal", "state": "error"}


def ipqs_url(url):
    key = os.getenv("IPQS_API_KEY")
    if not key:
        return {"id": "ipqs", "state": "off"}
    try:
        j = _get(f"https://www.ipqualityscore.com/api/json/url/{key}/{quote(url, safe='')}").json()
        if not j.get("success"):
            return {"id": "ipqs", "state": "error"}
        bad = j.get("phishing") or j.get("malware") or int(j.get("risk_score", 0)) >= 85
        return {"id": "ipqs", "state": "flagged" if bad else "clear", "score": int(j.get("risk_score", 0))}
    except Exception:  # noqa: BLE001
        return {"id": "ipqs", "state": "error"}


def domain_age(host):
    """Days since the domain was registered, from public RDAP. Very new domains are a common scam sign."""
    try:
        r = _get(f"https://rdap.org/domain/{quote(host)}")
        if r.status_code != 200:
            return None
        for ev in r.json().get("events", []):
            if ev.get("eventAction") == "registration":
                d = dt.datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
                return max(0, (dt.datetime.now(dt.timezone.utc) - d).days)
    except Exception:  # noqa: BLE001
        pass
    return None


def site(url, host):
    return {"sources": [vt_url(url), ipqs_url(url)], "ageDays": domain_age(host)}


def phone(num):
    """num: digits with country code, for example 919876543210."""
    out = []
    key = os.getenv("NUMVERIFY_API_KEY")
    if key:
        try:
            j = _get("http://apilayer.net/api/validate", params={"access_key": key, "number": num}).json()
            out.append({"id": "numverify", "state": ("ok" if j["valid"] else "invalid") if "valid" in j else "error",
                        "carrier": j.get("carrier") or "", "lineType": j.get("line_type") or "", "country": j.get("country_name") or ""})
        except Exception:  # noqa: BLE001
            out.append({"id": "numverify", "state": "error"})
    sid, tok = os.getenv("TWILIO_ACCOUNT_SID"), os.getenv("TWILIO_AUTH_TOKEN")
    if sid and tok:
        try:
            r = _get(f"https://lookups.twilio.com/v2/PhoneNumbers/+{num}", params={"Fields": "line_type_intelligence"}, auth=(sid, tok))
            j = r.json()
            lt = j.get("line_type_intelligence") or {}
            out.append({"id": "twilio", "state": ("ok" if j.get("valid") else "invalid") if r.status_code == 200 else "error",
                        "carrier": lt.get("carrier_name") or "", "lineType": lt.get("type") or "", "country": j.get("country_code") or ""})
        except Exception:  # noqa: BLE001
            out.append({"id": "twilio", "state": "error"})
    key = os.getenv("IPQS_API_KEY")
    if key:
        try:
            j = _get(f"https://www.ipqualityscore.com/api/json/phone/{key}/{num}").json()
            if j.get("success"):
                out.append({"id": "ipqs", "state": "flagged" if (j.get("fraud_score", 0) >= 85 or j.get("recent_abuse")) else "clear",
                            "score": int(j.get("fraud_score", 0)), "carrier": j.get("carrier") or "",
                            "lineType": j.get("line_type") or "", "voip": bool(j.get("VOIP"))})
            else:
                out.append({"id": "ipqs", "state": "error"})
        except Exception:  # noqa: BLE001
            out.append({"id": "ipqs", "state": "error"})
    return out


def configured():
    return {"virustotal": bool(os.getenv("VIRUSTOTAL_API_KEY")), "ipqs": bool(os.getenv("IPQS_API_KEY")),
            "numverify": bool(os.getenv("NUMVERIFY_API_KEY")),
            "twilio": bool(os.getenv("TWILIO_ACCOUNT_SID") and os.getenv("TWILIO_AUTH_TOKEN"))}
