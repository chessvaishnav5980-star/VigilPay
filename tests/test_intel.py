"""Tests for the live link checks (Google Safe Browsing + DNS filters), the status page and the speed fixes.
Everything outside is faked, so no internet and no Google key are needed:  python tests/run_all.py"""
import gzip
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))
import requests as real_requests  # noqa: E402
import ai  # noqa: E402
import app as vigil  # noqa: E402
import intel  # noqa: E402


class Resp:
    def __init__(self, status=200, data=None):
        self.status_code, self._d = status, data if data is not None else {}
        self.content = b"x"

    def json(self):
        return self._d

    def raise_for_status(self):
        if self.status_code >= 400:
            raise real_requests.HTTPError(str(self.status_code))


class Fake:
    """Stands in for the `requests` module. `dns` maps host -> (cloudflare, quad9, control) replies; `gsb` is a callable or a Resp."""
    RequestException = real_requests.RequestException

    def __init__(self, dns=None, gsb=None):
        self.dns, self.gsb, self.calls = dns or {}, gsb, []

    def post(self, url, params=None, json=None, **kw):
        self.calls.append(("post", url, json))
        if "safebrowsing" in url:
            return self.gsb(json) if callable(self.gsb) else (self.gsb or Resp(200, {}))
        return Resp(404)

    def get(self, url, params=None, **kw):
        self.calls.append(("get", url, params))
        name = (params or {}).get("name", "")
        which = 0 if "cloudflare" in url and "security" in url else 1 if "quad9" in url else 2
        got = self.dns.get(name)
        if got is None:
            return Resp(200, {"Status": 0, "Answer": [{"type": 1, "data": "93.184.216.34"}]})
        reply = got[which]
        if isinstance(reply, Exception):
            raise reply
        return Resp(200, reply)


OK = {"Status": 0, "Answer": [{"type": 1, "data": "93.184.216.34"}]}
SINK = {"Status": 0, "Answer": [{"type": 1, "data": "0.0.0.0"}]}
NX = {"Status": 3}


def use(fake):
    intel.requests = fake
    intel._CACHE.clear()


def done():
    intel.requests = real_requests
    intel._CACHE.clear()


def test_split_url_accepts_links_and_rejects_junk():
    assert intel.split_url("sbi-kyc.xyz/login") == ("http://sbi-kyc.xyz/login", "sbi-kyc.xyz")
    assert intel.split_url("HTTPS://Bad.Example.COM./a")[1] == "bad.example.com"
    assert intel.split_url("http://münchen.de/x")[1] == "xn--mnchen-3ya.de"
    for bad in ("", "two words", "ftp://x.com", "http://", "javascript:alert(1)", "http://a.com:99999/"):
        assert intel.split_url(bad) is None, bad


def test_google_match_is_reported_per_link():
    def gsb(body):
        urls = [e["url"] for e in body["threatInfo"]["threatEntries"]]
        assert body["threatInfo"]["threatEntryTypes"] == ["URL"] and "SOCIAL_ENGINEERING" in body["threatInfo"]["threatTypes"]
        return Resp(200, {"matches": [{"threatType": "SOCIAL_ENGINEERING", "threat": {"url": urls[0]}}]})
    use(Fake(gsb=gsb))
    try:
        r = intel.check_links(["http://bad-bank-login.xyz/a", "http://fine.example.com/"], "KEY")
    finally:
        done()
    a, b = r["items"]
    assert a["verdict"] == "flagged" and a["sources"][0] == {"id": "gsb", "state": "flagged", "threats": ["SOCIAL_ENGINEERING"]}
    assert b["verdict"] == "clear" and b["strong"] and r["gsb"] == "on"


def test_dns_filter_block_is_flagged_even_without_a_google_key():
    use(Fake(dns={"evil.test": (SINK, NX, OK), "gone.test": (NX, NX, NX), "good.test": (OK, OK, OK)}))
    try:
        evil = intel.check_links(["http://evil.test/"], None)["items"][0]
        gone = intel.check_links(["http://gone.test/"], None)["items"][0]
        good = intel.check_links(["http://good.test/"], None)["items"][0]
    finally:
        done()
    assert evil["verdict"] == "flagged"
    assert {s["id"]: s["state"] for s in evil["sources"]} == {"gsb": "off", "cloudflare": "blocked", "quad9": "blocked"}
    assert gone["verdict"] == "nx"
    assert good["verdict"] == "clear" and good["strong"] is False  # DNS filters alone are a weaker check


def test_nothing_reachable_is_unknown_never_clear():
    boom = real_requests.ConnectionError("down")
    use(Fake(dns={"x.test": (boom, boom, boom)}, gsb=Resp(500)))
    try:
        it = intel.check_links(["http://x.test/"], "KEY")["items"][0]
    finally:
        done()
    assert it["verdict"] == "unknown"
    assert [s["state"] for s in it["sources"]] == ["error", "error", "error"]


def test_google_errors_become_short_codes():
    cases = [(400, {"error": {"message": "API key not valid. Please pass a valid API key.", "details": [{"reason": "API_KEY_INVALID"}]}}, "bad_key"),
             (403, {"error": {"message": "Safe Browsing API has not been used in project 1 before or it is disabled.", "details": [{"reason": "SERVICE_DISABLED"}]}}, "api_disabled"),
             (403, {"error": {"message": "Requests from referer <empty> are blocked.", "details": [{"reason": "API_KEY_HTTP_REFERRER_BLOCKED"}]}}, "restricted"),
             (429, {"error": {"message": "Quota exceeded"}}, "quota"), (503, {}, "unavailable")]
    for status, body, code in cases:
        use(Fake(gsb=Resp(status, body)))
        try:
            state, got = intel.gsb_lookup(["http://a.test/"], "KEY")
        finally:
            done()
        assert (state, got) == ("error", code), (status, got)


def test_results_are_cached_and_ip_hosts_skip_dns():
    f = Fake()
    use(f)
    try:
        intel.check_links(["http://cache.test/"], None)
        n = len(f.calls)
        intel.check_links(["http://cache.test/"], None)
        assert len(f.calls) == n
        ip = intel.check_links(["http://203.0.113.9/login"], None)["items"][0]
    finally:
        done()
    assert ip["sources"] == [{"id": "gsb", "state": "off"}, {"id": "dns", "state": "skipped"}] and ip["verdict"] == "unknown"


def test_review_keeps_only_real_quotes_and_safe_text():
    data = {"verdict": "likely_phishing", "next": "Call 1930.",
            "clues": [{"quote": "KYC expires TODAY", "why": "It rushes you."}, {"quote": "words that are not there", "why": "Made up."},
                      {"quote": "click here", "why": "Share your OTP with the agent."}]}

    class G(Fake):
        def post(self, url, **kw):
            return Resp(200, {"candidates": [{"content": {"parts": [{"text": "```json\n" + json.dumps(data) + "\n```"}]}}]})
    old, ai.requests = ai.requests, G()
    import os
    os.environ["GEMINI_API_KEY"] = "x"
    try:
        r = ai.review("Dear customer your kyc expires today. Click here now", "en")
    finally:
        ai.requests = old
        os.environ.pop("GEMINI_API_KEY", None)
    assert r["verdict"] == "likely_phishing" and [c["quote"] for c in r["clues"]] == ["KYC expires TODAY"]


def test_pages_work_without_keys_and_carry_their_settings():
    c = vigil.app.test_client()
    h = c.get("/", headers={"Accept-Encoding": "gzip"})
    assert h.status_code == 200 and h.headers["Content-Encoding"] == "gzip" and h.headers["Cache-Control"] == "no-cache"
    html = gzip.decompress(h.data).decode()
    assert "window.VP_CONFIG=" in html and "<!--VP_CONFIG-->" not in html
    assert c.get("/", headers={"If-None-Match": h.headers["ETag"]}).status_code == 304
    plain = c.get("/").data.decode()
    assert "window.VP_CONFIG=" in plain
    s = c.get("/api/status").get_json()
    assert s["ok"] and set(s["features"]) == {"database", "ai", "safeBrowsing", "dns", "instantSignup", "googleSignIn"} and s["build"] == vigil.BUILD
    assert c.get("/api/health").headers["Cache-Control"] == "no-store"
    assert c.get("/manifest.webmanifest").mimetype == "application/manifest+json"
    sc = c.get("/api/scenarios", headers={"Accept-Encoding": "gzip"})
    assert sc.headers.get("Content-Encoding") == "gzip" and len(json.loads(gzip.decompress(sc.data))) >= 15


def test_linkcheck_endpoint_validates_and_answers():
    use(Fake(dns={"evil.test": (SINK, NX, OK)}))
    try:
        c = vigil.app.test_client()
        assert c.post("/api/linkcheck", json={"url": "two words"}).status_code == 400
        j = c.post("/api/linkcheck", json={"urls": ["evil.test/pay", "evil.test/pay", 5]}).get_json()
        assert j["ok"] and len(j["items"]) == 1 and j["items"][0]["verdict"] == "flagged"
        assert c.post("/api/review", json={"text": "hello"}).get_json() == {"ok": False, "reason": "ai_off"}
    finally:
        done()


def test_shared_school_ip_is_not_locked_out_by_a_few_students():
    c = vigil.app.test_client()
    vigil._hits.clear()
    use(Fake())
    try:
        codes = [c.post("/api/linkcheck", json={"url": f"http://site{i}.test/"}).status_code for i in range(40)]
    finally:
        done()
    assert set(codes) == {200}
    vigil._hits.clear()
    assert [vigil.limited(3, 60, "t", everyone=True) for _ in range(4)] == [False, False, False, True]
    vigil._hits.clear()
