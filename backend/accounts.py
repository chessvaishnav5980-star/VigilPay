"""Sign-up and Google sign-in that work without waiting for email links.

Why this file exists: Supabase asks every new account to click a link sent by email, and its free built-in mailer is allowed to
send only a few emails per hour for the whole project. In a classroom that means most sign-ups never arrive. With the project's
service key (kept only here, on the server, never sent to a browser) a new account is created already confirmed, and the
browser then signs in with the normal password request. The same key lets a verified Google sign-in become a normal Supabase
session, so the profile name and picture of the Google account show up in the page.

Nothing in this file is needed for the rest of the site. Without SUPABASE_SERVICE_KEY the page falls back to Supabase's own
sign-up, and without GOOGLE_CLIENT_ID it falls back to Supabase's Google provider when that has been switched on.
Every function returns plain values and never raises, and nothing secret is ever put in a reply or a log line.
"""
import os
import re
import secrets
import time

import requests

URL = os.getenv("SUPABASE_URL", "").rstrip("/")
ANON = os.getenv("SUPABASE_ANON_KEY", "")
SERVICE = os.getenv("SUPABASE_SERVICE_KEY", "") or os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "").strip()
TIMEOUT = 8

EMAIL_RE = re.compile(r"^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{2,}$")
GOOGLE_ISSUERS = ("accounts.google.com", "https://accounts.google.com")


def instant_signup() -> bool:
    return bool(URL and ANON and SERVICE)


def google_ready() -> bool:
    return bool(instant_signup() and GOOGLE_CLIENT_ID)


def _head(key):
    return {"apikey": key, "Authorization": f"Bearer {key}", "Content-Type": "application/json"}


def _json(resp):
    try:
        data = resp.json()
        return data if isinstance(data, dict) else {}
    except ValueError:
        return {}


def _code(resp):
    j = _json(resp)
    return str(j.get("error_code") or j.get("code") or j.get("error") or resp.status_code), str(j.get("msg") or j.get("message") or "")


def clean_name(name) -> str:
    name = re.sub(r"[\x00-\x1f<>]", "", str(name or "")).strip()
    return re.sub(r"\s+", " ", name)[:60]


def create_user(email: str, password: str, name: str = ""):
    """Create an account that is already confirmed. Returns ("ok", user) | ("exists", None) | ("weak", None) | ("error", code)."""
    if not instant_signup():
        return "error", "not_configured"
    body = {"email": email, "password": password, "email_confirm": True, "user_metadata": {"full_name": clean_name(name)} if name else {}}
    try:
        r = requests.post(f"{URL}/auth/v1/admin/users", headers=_head(SERVICE), json=body, timeout=TIMEOUT)
    except requests.RequestException:
        return "error", "unreachable"
    if r.status_code in (200, 201):
        return "ok", _json(r)
    code, msg = _code(r)
    low = (code + " " + msg).lower()
    if "exist" in low or "already" in low or "registered" in low:
        return "exists", None
    if "weak" in low or "password" in low:
        return "weak", None
    return "error", code[:40]


def _claims_from_google(credential: str):
    """Ask Google whether this sign-in token is real. Returns (claims | None, problem code)."""
    if not credential or credential.count(".") != 2:
        return None, "bad_token"
    try:
        r = requests.get("https://oauth2.googleapis.com/tokeninfo", params={"id_token": credential}, timeout=TIMEOUT)
    except requests.RequestException:
        return None, "google_unreachable"
    if r.status_code != 200:
        return None, "bad_token"
    c = _json(r)
    if c.get("aud") != GOOGLE_CLIENT_ID:
        return None, "wrong_client"
    if c.get("iss") not in GOOGLE_ISSUERS:
        return None, "bad_token"
    if str(c.get("email_verified")).lower() != "true" or not EMAIL_RE.match(str(c.get("email", ""))):
        return None, "email_not_verified"
    try:
        if int(c.get("exp", 0)) < time.time() - 30:
            return None, "bad_token"
    except (TypeError, ValueError):
        return None, "bad_token"
    return c, ""


def _session_from(resp):
    j = _json(resp)
    if not j.get("access_token"):
        return None
    exp = j.get("expires_at") or int(time.time()) + int(j.get("expires_in") or 3600)
    return {"access_token": j["access_token"], "refresh_token": j.get("refresh_token", ""), "expires_at": int(exp), "user": j.get("user") or {}}


def google_login(credential: str):
    """Turn a Google sign-in token into a Supabase session. Returns ("ok", session) | ("error", code)."""
    if not google_ready():
        return "error", "not_configured"
    claims, problem = _claims_from_google(credential)
    if not claims:
        return "error", problem
    email = str(claims["email"]).lower()
    name = clean_name(claims.get("name") or claims.get("given_name") or email.split("@")[0])
    picture = str(claims.get("picture") or "")
    if not picture.startswith("https://"):
        picture = ""
    state, _ = create_user(email, secrets.token_urlsafe(32), name)  # an existing account is fine
    if state in ("weak", "error"):
        return "error", "create_failed"
    try:
        link = requests.post(f"{URL}/auth/v1/admin/generate_link", headers=_head(SERVICE), json={"type": "magiclink", "email": email}, timeout=TIMEOUT)
        j = _json(link)
        token_hash = j.get("hashed_token") or (j.get("properties") or {}).get("hashed_token")
        if link.status_code != 200 or not token_hash:
            return "error", "link_failed"
        ver = requests.post(f"{URL}/auth/v1/verify", headers=_head(ANON), json={"type": "magiclink", "token_hash": token_hash}, timeout=TIMEOUT)
    except requests.RequestException:
        return "error", "unreachable"
    session = _session_from(ver) if ver.status_code == 200 else None
    if not session:
        return "error", "verify_failed"
    meta = {"full_name": name, "name": name, "provider": "google"}
    if picture:
        meta.update(avatar_url=picture, picture=picture)
    try:  # show the Google name and picture in the page, also for accounts that were first made with an email
        up = requests.put(f"{URL}/auth/v1/user", headers={**_head(ANON), "Authorization": f"Bearer {session['access_token']}"}, json={"data": meta}, timeout=TIMEOUT)
        if up.status_code == 200 and _json(up).get("id"):
            session["user"] = _json(up)
    except requests.RequestException:
        pass
    if not session["user"]:
        session["user"] = {"email": email, "user_metadata": meta}
    return "ok", session


def public_settings():
    """What the project allows (read from Supabase itself): is Google switched on, do new accounts need an email link?"""
    if not (URL and ANON):
        return None
    try:
        r = requests.get(f"{URL}/auth/v1/settings", headers={"apikey": ANON}, timeout=5)
    except requests.RequestException:
        return None
    if r.status_code != 200:
        return None
    j = _json(r)
    ext = j.get("external") or {}
    return {"google": bool(ext.get("google")), "email": ext.get("email", True) is not False, "autoconfirm": bool(j.get("mailer_autoconfirm")), "signupOff": bool(j.get("disable_signup"))}


def self_test():
    """For the owner's status page. Says what works; never returns a key."""
    out = {"settings": public_settings(), "instantSignup": instant_signup(), "googleClient": bool(GOOGLE_CLIENT_ID)}
    if SERVICE and URL:
        try:
            r = requests.get(f"{URL}/auth/v1/admin/users", params={"per_page": 1}, headers=_head(SERVICE), timeout=5)
            out["serviceKeyWorks"] = r.status_code == 200
        except requests.RequestException:
            out["serviceKeyWorks"] = None
    return out
