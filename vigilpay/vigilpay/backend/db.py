import os

import requests

URL = os.getenv("SUPABASE_URL", "").rstrip("/")
ANON = os.getenv("SUPABASE_ANON_KEY", "")

def enabled() -> bool:
    return bool(URL and ANON)

def verify_token(token: str):
    if not (enabled() and token):
        return None
    try:
        r = requests.get(f"{URL}/auth/v1/user",
                         headers={"apikey": ANON, "Authorization": f"Bearer {token}"}, timeout=6)
        return r.json() if r.status_code == 200 else None
    except requests.RequestException:
        return None

def rpc(name: str, payload=None, token=None):
    if not enabled():
        return None
    try:
        r = requests.post(
            f"{URL}/rest/v1/rpc/{name}",
            headers={"apikey": ANON, "Authorization": f"Bearer {token or ANON}", "Content-Type": "application/json"},
            json=payload or {}, timeout=6)
        if r.status_code in (200, 201, 204):
            return r.json() if r.content else True
        return None
    except (requests.RequestException, ValueError):
        return None
