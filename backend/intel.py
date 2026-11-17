"""Live reputation checks for web links.

VigilPay asks independent sources whether a website is already known to be dangerous:

  1. Google Safe Browsing (needs a free API key in SAFE_BROWSING_API_KEY). The whole link is sent to Google.
  2. Cloudflare's security DNS (blocks known malware and phishing websites).
  3. Quad9's threat-blocking DNS (blocks websites listed by many security companies).
     Only the website NAME goes to the two DNS services, never the full link, and nothing is stored here.

"No known threat found" is never the same as "safe": new scam sites appear every hour and no list has them yet.
The browser therefore words a clean result carefully, and says so when a source could not be reached.

Every function returns plain dicts and never raises, so a failing source cannot break the page.
"""
import concurrent.futures as cf
import re
import threading
import time
from urllib.parse import urlsplit

import requests

GSB_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
GSB_THREATS = ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"]
UA = "VigilPay-LinkCheck/2.0"
DNS_TIMEOUT = 3.2
GSB_TIMEOUT = 5.0
MAX_URLS = 6
MAX_HOSTS = 4

DOH_CLOUDFLARE = "https://security.cloudflare-dns.com/dns-query"
DOH_QUAD9 = "https://dns.quad9.net:5053/dns-query"
DOH_CONTROL = "https://dns.google/resolve"  # an unfiltered resolver, only used to tell "blocked" from "does not exist"

_POOL = cf.ThreadPoolExecutor(max_workers=10, thread_name_prefix="intel")
_CACHE = {}
_LOCK = threading.Lock()


# ---------------------------------------------------------------- helpers
def _cache_get(key):
    with _LOCK:
        hit = _CACHE.get(key)
    if hit and hit[0] > time.time():
        return hit[1]
    return None


def _cache_put(key, value, ttl):
    with _LOCK:
        if len(_CACHE) > 600:
            now = time.time()
            for k in [k for k, v in _CACHE.items() if v[0] < now]:
                _CACHE.pop(k, None)
            if len(_CACHE) > 600:
                _CACHE.clear()
        _CACHE[key] = (time.time() + ttl, value)


def split_url(raw):
    """Return (url_with_scheme, ascii_host) for something that looks like a web link, else None."""
    raw = str(raw or "").strip()[:1000]
    if not raw or re.search(r"\s", raw):
        return None
    if not re.match(r"^[a-z][a-z0-9+.-]*://", raw, re.I):
        raw = "http://" + raw
    try:
        sp = urlsplit(raw)
        host = (sp.hostname or "").rstrip(".").lower()
        sp.port  # noqa: B018 - raises ValueError for a bad port
    except ValueError:
        return None
    if sp.scheme.lower() not in ("http", "https") or not host or len(host) > 253:
        return None
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if not (re.fullmatch(r"[a-z0-9._-]+", host) and "." in host) and ":" not in host:
        return None  # a real web address has a dot in its name (or is an IPv6 number)
    return raw, host


def is_ip(host):
    return bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host)) or ":" in host


# ---------------------------------------------------------------- Google Safe Browsing
def _google_problem(resp):
    """Turn Google's error reply into a short code the page can explain. The key itself is never logged or returned."""
    try:
        err = resp.json().get("error", {})
    except ValueError:
        err = {}
    msg = str(err.get("message", "")).lower()
    reasons = " ".join(str(d.get("reason", "")) for d in err.get("details", []) if isinstance(d, dict)).lower()
    if resp.status_code == 429 or "quota" in msg or "rate" in reasons:
        return "quota"
    if "api key not valid" in msg or "api_key_invalid" in reasons or "key" in msg and "invalid" in msg:
        return "bad_key"
    if "has not been used" in msg or "disabled" in msg or "service_disabled" in reasons:
        return "api_disabled"
    if resp.status_code == 403 or "referer" in msg or "restriction" in msg or "blocked" in reasons:
        return "restricted"
    return "unavailable"


def gsb_lookup(urls, key):
    """Ask Google Safe Browsing about several URLs at once.

    Returns ("ok", {url: [threat types]}) or ("error", code)."""
    body = {
        "client": {"clientId": "vigilpay", "clientVersion": "2.0"},
        "threatInfo": {"threatTypes": GSB_THREATS, "platformTypes": ["ANY_PLATFORM"],
                       "threatEntryTypes": ["URL"], "threatEntries": [{"url": u} for u in urls]},
    }
    try:
        r = requests.post(GSB_URL, params={"key": key}, json=body, timeout=GSB_TIMEOUT, headers={"User-Agent": UA})
    except requests.RequestException:
        return "error", "unavailable"
    if r.status_code != 200:
        return "error", _google_problem(r)
    try:
        matches = r.json().get("matches", [])
    except ValueError:
        return "error", "unavailable"
    found = {u: set() for u in urls}
    plain = {re.sub(r"^https?://", "", u).rstrip("/").lower(): u for u in urls}
    for m in matches:
        got = str((m.get("threat") or {}).get("url", ""))
        target = got if got in found else plain.get(re.sub(r"^https?://", "", got).rstrip("/").lower())
        if target is None and len(urls) == 1:
            target = urls[0]
        if target is not None and m.get("threatType") in GSB_THREATS:
            found[target].add(m["threatType"])
    return "ok", {u: sorted(t) for u, t in found.items()}


# ---------------------------------------------------------------- public DNS filters
def _doh(endpoint, host, headers=None):
    r = requests.get(endpoint, params={"name": host, "type": "A"}, headers={"accept": "application/dns-json", "User-Agent": UA, **(headers or {})}, timeout=DNS_TIMEOUT)
    r.raise_for_status()
    return r.json()


def _answers(j):
    return [str(a.get("data", "")) for a in (j.get("Answer") or []) if a.get("type") in (1, 5, 28)]


def dns_states(host):
    """{'cloudflare': state, 'quad9': state} where state is blocked, ok, nx (no such website name) or error."""
    if is_ip(host):
        return {}
    futs = {name: _POOL.submit(_doh, ep, host) for name, ep in (("cloudflare", DOH_CLOUDFLARE), ("quad9", DOH_QUAD9), ("control", DOH_CONTROL))}
    res = {}
    for name, f in futs.items():
        try:
            res[name] = f.result(timeout=DNS_TIMEOUT + 1.5)
        except Exception:  # noqa: BLE001 - any failure just means this source did not answer
            res[name] = None
    control = res.get("control")
    control_status = control.get("Status") if control else None
    exists = bool(control and control_status == 0 and _answers(control))
    out = {}
    cfj = res.get("cloudflare")
    if cfj is None:
        out["cloudflare"] = "error"
    else:
        ans = [a for a in _answers(cfj) if re.fullmatch(r"[\d.]+|[0-9a-f:]+", a)]
        comment = " ".join(cfj.get("Comment") or []) if isinstance(cfj.get("Comment"), list) else str(cfj.get("Comment") or "")
        if cfj.get("Status") == 0 and ans and all(a in ("0.0.0.0", "::") for a in ans) or "filtered" in comment.lower():
            out["cloudflare"] = "blocked"
        elif cfj.get("Status") == 3:
            out["cloudflare"] = "blocked" if exists else "nx"
        else:
            out["cloudflare"] = "ok"
    q9 = res.get("quad9")
    if q9 is None:
        out["quad9"] = "error"
    elif q9.get("Status") == 3:
        out["quad9"] = "blocked" if exists else "nx"
    else:
        out["quad9"] = "ok"
    # a filter that returns 0.0.0.0 or NXDOMAIN for a site an unfiltered resolver can find has blocked it on purpose
    if control is not None and control_status == 3:
        out = {k: ("nx" if v in ("blocked", "nx") else v) for k, v in out.items()}
    return out


# ---------------------------------------------------------------- putting it together
def verdict(sources):
    """flagged: a source says it is dangerous. nx: the name does not exist. clear: nothing found. unknown: nothing could be checked."""
    st = {s["id"]: s["state"] for s in sources}
    if st.get("gsb") == "flagged" or "blocked" in st.values():
        return "flagged", False
    dns = [v for k, v in st.items() if k != "gsb"]
    if dns and all(v == "nx" for v in dns):
        return "nx", False
    if st.get("gsb") == "clear":
        return "clear", True
    if "ok" in dns:
        return "clear", False
    return "unknown", False


def check_links(raw_urls, key=None):
    """Check up to six links. Returns {'ok', 'checkedAt', 'gsb': 'on|off', 'items': [...]}. Never raises."""
    pairs, seen = [], set()
    for raw in raw_urls or []:
        s = split_url(raw)
        if s and s[0] not in seen:
            seen.add(s[0])
            pairs.append(s)
    pairs = pairs[:MAX_URLS]
    if not pairs:
        return {"ok": False, "error": "invalid", "items": []}
    ckey = ("links", key is not None, tuple(sorted(p[0] for p in pairs)))
    hit = _cache_get(ckey)
    if hit:
        return hit

    urls = [p[0] for p in pairs]
    hosts = list(dict.fromkeys(p[1] for p in pairs))[:MAX_HOSTS]
    gsb_f = _POOL.submit(gsb_lookup, urls, key) if key else None
    dns_f = {h: _POOL.submit(dns_states, h) for h in hosts}

    gsb_state, gsb_data = "off", {}
    if gsb_f is not None:
        try:
            gsb_state, gsb_data = gsb_f.result(timeout=GSB_TIMEOUT + 2)
        except Exception:  # noqa: BLE001
            gsb_state, gsb_data = "error", "unavailable"
    dns = {}
    for h, f in dns_f.items():
        try:
            dns[h] = f.result(timeout=DNS_TIMEOUT + 3)
        except Exception:  # noqa: BLE001
            dns[h] = {"cloudflare": "error", "quad9": "error"}

    items, any_error = [], False
    for url, host in pairs:
        sources = []
        if gsb_state == "off":
            sources.append({"id": "gsb", "state": "off"})
        elif gsb_state == "error":
            sources.append({"id": "gsb", "state": "error", "code": gsb_data})
            any_error = True
        else:
            threats = gsb_data.get(url, [])
            sources.append({"id": "gsb", "state": "flagged" if threats else "clear", "threats": threats})
        if is_ip(host):
            sources.append({"id": "dns", "state": "skipped"})
        elif host in dns:
            for name in ("cloudflare", "quad9"):
                if name in dns[host]:
                    sources.append({"id": name, "state": dns[host][name]})
                    any_error = any_error or dns[host][name] == "error"
        v, strong = verdict(sources)
        items.append({"url": url[:300], "host": host, "verdict": v, "strong": strong, "sources": sources})
    out = {"ok": True, "checkedAt": int(time.time()), "gsb": "on" if key else "off", "items": items}
    _cache_put(ckey, out, 30 if any_error else 600)
    return out


def self_test(key=None):
    """For the admin status page: does each source answer right now? Never returns the key."""
    res = {}
    if key:
        state, data = gsb_lookup(["https://testsafebrowsing.appspot.com/s/phishing.html"], key)
        res["gsb"] = {"ok": state == "ok", "code": None if state == "ok" else data,
                      "sawTestPage": state == "ok" and any(data.values())}
    else:
        res["gsb"] = {"ok": False, "code": "off"}
    for name, st in dns_states("example.com").items():
        res[name] = {"ok": st == "ok", "code": None if st == "ok" else st}
    return res
