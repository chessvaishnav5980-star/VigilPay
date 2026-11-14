"""Tests for the safe link follower and the game-score checks. They use a throw-away local web server, so no internet is needed."""
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))
import linktrace  # noqa: E402
import app as vigil  # noqa: E402


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):  # keep test output quiet
        pass

    def do_GET(self):
        p = self.path
        if p == "/a":
            self.send_response(302); self.send_header("Location", "/b"); self.end_headers()
        elif p == "/b":
            self.send_response(301); self.send_header("Location", "/final?x=1"); self.end_headers()
        elif p.startswith("/final"):
            body = b"<html><head><title>  Pay &amp; Win   Bank </title></head><body>hello</body></html>"
            self.send_response(200); self.send_header("Content-Type", "text/html; charset=utf-8"); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
        elif p == "/loop":
            self.send_response(302); self.send_header("Location", "/loop"); self.end_headers()
        elif p == "/meta":
            body = b'<html><head><meta http-equiv="refresh" content="0; url=/final"></head></html>'
            self.send_response(200); self.send_header("Content-Type", "text/html"); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
        elif p.startswith("/chain"):
            n = int(p.split("/chain")[1] or 0)
            self.send_response(302); self.send_header("Location", f"/chain{n + 1}"); self.end_headers()
        else:
            self.send_response(404); self.end_headers()


def serve():
    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def test_follows_redirects_and_reads_title():
    srv, port = serve()
    linktrace.ALLOW_PRIVATE = True
    try:
        r = linktrace._follow(f"http://127.0.0.1:{port}/a")
    finally:
        linktrace.ALLOW_PRIVATE = False
        srv.shutdown()
    assert r["ok"] and len(r["hops"]) == 3
    assert r["final"]["title"] == "Pay & Win Bank"
    assert r["final"]["status"] == 200


def test_loop_and_too_many_hops_are_reported():
    srv, port = serve()
    linktrace.ALLOW_PRIVATE = True
    try:
        loop = linktrace._follow(f"http://127.0.0.1:{port}/loop")
        many = linktrace._follow(f"http://127.0.0.1:{port}/chain0")
        meta = linktrace._follow(f"http://127.0.0.1:{port}/meta")
    finally:
        linktrace.ALLOW_PRIVATE = False
        srv.shutdown()
    assert not loop["ok"] and loop["kind"] == "loop"
    assert not many["ok"] and many["kind"] == "too-many"
    assert meta["ok"] and meta["hops"][0].get("via") == "meta refresh" and meta["final"]["title"]


def test_private_and_internal_addresses_are_never_opened():
    srv, port = serve()  # a real server is listening, but the follower must refuse before connecting
    try:
        for url in (f"http://127.0.0.1:{port}/a", f"http://localhost:{port}/a", "http://169.254.169.254/latest/meta-data/",
                    "http://10.0.0.5/", "http://192.168.1.1/", "http://[::1]/", "http://0.0.0.0/", "http://service.internal/"):
            r = linktrace._follow(url)
            assert not r["ok"] and r["kind"] == "blocked", url
    finally:
        srv.shutdown()


def test_odd_ports_and_schemes_are_refused():
    assert linktrace._follow("http://example.com:22/")["kind"] == "blocked"
    assert linktrace._follow("ftp://example.com/")["kind"] == "invalid"
    assert linktrace._follow("file:///etc/passwd")["kind"] == "invalid"
    assert linktrace._follow("")["kind"] == "invalid"


def test_public_ip_rules():
    for ip in ("8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"):
        assert linktrace.is_public(ip), ip
    for ip in ("127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.0.1", "169.254.1.1", "::1", "fe80::1", "fc00::1", "0.0.0.0", "224.0.0.1", "::ffff:10.0.0.1", "100.64.0.1"):
        assert not linktrace.is_public(ip), ip


def test_registered_domain_and_free_hosts():
    assert linktrace.registered_domain("secure.login.hdfcbank.com") == "hdfcbank.com"
    assert linktrace.registered_domain("www.incometax.gov.in") == "incometax.gov.in"
    assert linktrace.registered_domain("a.b.example.co.uk") == "example.co.uk"
    assert linktrace.free_host("sbi-kyc.vercel.app") == "vercel.app"
    assert linktrace.free_host("vercel.app.evil.com") is None


def test_rdap_parsing():
    from datetime import datetime, timezone
    j = {"events": [{"eventAction": "registration", "eventDate": "2026-10-20T10:00:00Z"}, {"eventAction": "expiration", "eventDate": "2027-10-20T10:00:00Z"}],
         "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Example Registrar Inc."]]]}]}
    d = linktrace.parse_rdap(j, now=datetime(2026, 10, 30, tzinfo=timezone.utc))
    assert d == {"registered": "2026-10-20", "age_days": 9, "registrar": "Example Registrar Inc."}
    assert linktrace.parse_rdap({}) is None


def test_page_facts_ignores_scripts_and_decodes():
    t, r = linktrace.page_facts(b"<title>a &lt;b&gt;\n c</title><script>location='http://evil'</script>", "text/html")
    assert t == "a <b> c" and r is None


def test_nickname_rules():
    assert vigil.clean_nick("RoboFan 7") == "RoboFan 7"
    assert vigil.clean_nick("a") is None  # too short
    assert vigil.clean_nick("9876543210") is None  # starts with a digit and looks like a phone number
    assert vigil.clean_nick("Ravi 98765 43210") is None  # too many digits
    assert vigil.clean_nick("name@bank") is None and vigil.clean_nick("http://x.y") is None
    assert vigil.clean_nick("Sh1t head") is None and vigil.clean_nick("f u c k") is None
    assert vigil.clean_nick("Vigi Runner") == "Vigi Runner" and vigil.clean_nick("Class9A.Team") == "Class9A.Team"


def test_run_plausibility():
    ok = lambda d, c, b, s: vigil.plausible_run(d, c, b, d + c * 5 + b * 200, s)  # noqa: E731
    assert ok(1200, 40, 3, 90)
    assert not ok(5000, 10, 0, 20)  # 250 m per second is impossible
    assert not ok(300, 900, 0, 60)  # too many coins for the distance
    assert not ok(200, 0, 20, 60)  # too many bosses for the distance
    assert not vigil.plausible_run(500, 0, 0, 99999, 60)  # score does not follow the formula


def test_endpoints_validate_input():
    c = vigil.app.test_client()
    assert c.post("/api/trace", json={}).status_code == 400
    assert c.post("/api/game/score", json={"nick": "Bot", "distance": 1, "coins": 0, "bosses": 0, "score": 1, "seconds": 1}).status_code in (200, 400)
    assert c.post("/api/game/score", json={"nick": "x", "distance": 1}).status_code == 400
    assert c.get("/api/game/leaderboard?by=hack").status_code == 400
    r = c.get("/api/game/leaderboard?by=bosses&period=week")
    assert r.status_code == 200 and r.get_json()["rows"] == []
