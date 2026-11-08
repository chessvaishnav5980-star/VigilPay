"""Tests for instant sign-up and Google sign-in. Supabase and Google are faked, so no keys or internet are needed:  python tests/run_all.py"""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))
import requests as real_requests  # noqa: E402
import accounts  # noqa: E402
import app as vigil  # noqa: E402


class Resp:
    def __init__(self, status=200, data=None):
        self.status_code, self._d, self.content = status, data if data is not None else {}, b"x"

    def json(self):
        return self._d


class Fake:
    """Stands in for `requests`: routes each call by URL and records them."""
    RequestException = real_requests.RequestException

    def __init__(self, routes):
        self.routes, self.calls = routes, []

    def _go(self, method, url, **kw):
        self.calls.append((method, url, kw))
        for (m, frag), reply in self.routes.items():
            if m == method and frag in url:
                return reply(kw) if callable(reply) else reply
        return Resp(404, {})

    def get(self, url, **kw):
        return self._go("GET", url, **kw)

    def post(self, url, **kw):
        return self._go("POST", url, **kw)

    def put(self, url, **kw):
        return self._go("PUT", url, **kw)


def configure(fake, google=True):
    accounts.URL, accounts.ANON, accounts.SERVICE = "https://x.supabase.co", "anon", "service"
    accounts.GOOGLE_CLIENT_ID = "client-123.apps.googleusercontent.com" if google else ""
    accounts.requests = fake
    vigil.db.URL, vigil.db.ANON = accounts.URL, accounts.ANON
    vigil._hits.clear()


def reset():
    accounts.URL = accounts.ANON = accounts.SERVICE = accounts.GOOGLE_CLIENT_ID = ""
    accounts.requests = real_requests
    vigil.db.URL = vigil.db.ANON = ""
    vigil._hits.clear()


GOOD = {"aud": "client-123.apps.googleusercontent.com", "iss": "https://accounts.google.com", "email": "Asha@Example.com",
        "email_verified": "true", "name": "Asha Rao", "picture": "https://lh3.googleusercontent.com/a/pic=s96-c", "exp": str(int(time.time()) + 600)}
SESSION = {"access_token": "AT", "refresh_token": "RT", "expires_in": 3600, "token_type": "bearer", "user": {"id": "u1", "email": "asha@example.com", "user_metadata": {}}}


def google_routes(claims=GOOD, create=Resp(200, {"id": "u1"})):
    return {("GET", "tokeninfo"): Resp(200, claims), ("POST", "admin/users"): create,
            ("POST", "generate_link"): Resp(200, {"hashed_token": "HASH", "action_link": "https://x"}),
            ("POST", "/verify"): Resp(200, SESSION),
            ("PUT", "/auth/v1/user"): lambda kw: Resp(200, {"id": "u1", "email": "asha@example.com", "user_metadata": kw["json"]["data"]})}


def test_signup_creates_a_confirmed_account_and_reports_the_other_cases():
    f = Fake({("POST", "admin/users"): Resp(200, {"id": "u1"})})
    configure(f)
    try:
        c = vigil.app.test_client()
        r = c.post("/api/auth/signup", json={"email": "Kid@School.in", "password": "longenough1", "name": "  Kid <b> "})
        assert r.get_json() == {"ok": True}
        sent = f.calls[0][2]["json"]
        assert sent["email"] == "kid@school.in" and sent["email_confirm"] is True and sent["user_metadata"] == {"full_name": "Kid b"}
        assert f.calls[0][2]["headers"]["Authorization"] == "Bearer service"
        assert c.post("/api/auth/signup", json={"email": "nope", "password": "longenough1"}).status_code == 400
        assert c.post("/api/auth/signup", json={"email": "a@b.co", "password": "short"}).get_json()["reason"] == "weak"
        f.routes[("POST", "admin/users")] = Resp(422, {"error_code": "email_exists", "msg": "A user with this email address has already been registered"})
        assert c.post("/api/auth/signup", json={"email": "a@b.co", "password": "longenough1"}).get_json() == {"ok": False, "reason": "exists"}
    finally:
        reset()


def test_signup_says_so_when_the_server_has_no_service_key():
    c = vigil.app.test_client()
    reset()
    assert c.post("/api/auth/signup", json={"email": "a@b.co", "password": "longenough1"}).get_json() == {"ok": False, "reason": "not_configured"}
    assert c.post("/api/auth/google", json={"credential": "a.b.c"}).get_json() == {"ok": False, "reason": "not_configured"}


def test_google_sign_in_returns_a_session_carrying_the_google_name_and_picture():
    f = Fake(google_routes())
    configure(f)
    try:
        j = vigil.app.test_client().post("/api/auth/google", json={"credential": "aaa.bbb.ccc"}).get_json()
        assert j["ok"] and j["session"]["access_token"] == "AT" and j["session"]["refresh_token"] == "RT"
        meta = j["session"]["user"]["user_metadata"]
        assert meta["full_name"] == "Asha Rao" and meta["avatar_url"].startswith("https://lh3.googleusercontent.com/")
        urls = [u for _, u, _ in f.calls]
        assert any("admin/users" in u for u in urls) and any("generate_link" in u for u in urls) and any(u.endswith("/verify") for u in urls)
        link_body = [kw for _, u, kw in f.calls if "generate_link" in u][0]["json"]
        assert link_body == {"type": "magiclink", "email": "asha@example.com"}
        assert accounts.SERVICE not in str(j)
    finally:
        reset()


def test_google_tokens_that_are_not_ours_or_not_verified_are_refused():
    bad = [dict(GOOD, aud="someone-elses-app"), dict(GOOD, email_verified="false"), dict(GOOD, iss="https://evil.example"), dict(GOOD, exp="1000")]
    for claims in bad:
        f = Fake(google_routes(claims))
        configure(f)
        try:
            j = vigil.app.test_client().post("/api/auth/google", json={"credential": "aaa.bbb.ccc"}).get_json()
            assert j["ok"] is False, claims
            assert not any("admin" in u or "verify" in u for _, u, _ in f.calls), "no account may be touched for a refused token"
        finally:
            reset()
    f = Fake({("GET", "tokeninfo"): Resp(400, {"error": "invalid_token"})})
    configure(f)
    try:
        assert vigil.app.test_client().post("/api/auth/google", json={"credential": "not-a-token"}).get_json()["ok"] is False
    finally:
        reset()


def test_page_settings_tell_the_browser_what_is_available_and_hide_secrets():
    configure(Fake({}))
    try:
        cfg = vigil.public_config()
        assert cfg["googleClientId"].startswith("client-123") and cfg["instantSignup"] is True
        assert "service" not in str(cfg).replace("instantSignup", "")
        accounts.GOOGLE_CLIENT_ID = ""
        assert vigil.public_config()["googleClientId"] == ""
    finally:
        reset()


def test_status_reports_what_the_project_allows():
    f = Fake({("GET", "/auth/v1/settings"): Resp(200, {"external": {"google": True, "email": True}, "mailer_autoconfirm": False}), ("GET", "admin/users"): Resp(200, {"users": []})})
    configure(f)
    try:
        t = accounts.self_test()
        assert t["settings"] == {"google": True, "email": True, "autoconfirm": False, "signupOff": False} and t["serviceKeyWorks"] is True
        assert "service" not in str(t).replace("serviceKeyWorks", "")
    finally:
        reset()
