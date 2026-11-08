"""Follow a link's redirects safely and read basic facts about where it ends up.

Used by /api/trace so VigilPay can show the real website behind a QR code or a short link.
Safety rules: only http and https, only ports 80/443/8080/8443, only public internet addresses (checked on the
address we actually connect to, so a DNS trick cannot point us at an internal service), no cookies, no scripts,
at most 64 KB read, a hard time limit, and nothing is stored."""
import http.client
import ipaddress
import re
import socket
import ssl
import time
from datetime import datetime, timezone
from html import unescape
from urllib.parse import urljoin, urlsplit

import requests

ALLOW_PRIVATE = False  # tests switch this on to talk to a local server
MAX_HOPS = 6
MAX_BODY = 65536
CONNECT_TIMEOUT = 3.5
DEADLINE = 9.0
OK_PORTS = (80, 443, 8080, 8443)
UA = "Mozilla/5.0 (compatible; VigilPay-LinkCheck/1.0)"

SLD = ("co.in", "gov.in", "nic.in", "org.in", "ac.in", "net.in", "res.in", "com.au", "co.uk", "org.uk")
FREE_HOSTS = ("vercel.app", "netlify.app", "web.app", "firebaseapp.com", "github.io", "pages.dev", "workers.dev", "blogspot.com",
              "wixsite.com", "weebly.com", "herokuapp.com", "glitch.me", "onrender.com", "000webhostapp.com", "webflow.io",
              "carrd.co", "godaddysites.com", "sites.google.com", "repl.co", "replit.app", "framer.app", "surge.sh")


class Blocked(Exception):
    """The link must not be opened by the server."""


def registered_domain(host: str) -> str:
    parts = host.lower().strip(".").split(".")
    if len(parts) <= 2:
        return ".".join(parts)
    return ".".join(parts[-3:]) if ".".join(parts[-2:]) in SLD else ".".join(parts[-2:])


def free_host(host: str):
    return next((h for h in FREE_HOSTS if host == h or host.endswith("." + h)), None)


def is_public(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return False
    if a.version == 6 and a.ipv4_mapped:
        a = a.ipv4_mapped
    return a.is_global and not a.is_multicast


def resolve(host: str, port: int):
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError):
        raise LookupError("That website name does not exist, or the site is down.")
    ips = []
    for info in infos:
        ip = info[4][0]
        if ip not in ips:
            ips.append(ip)
    if not ips:
        raise LookupError("That website name does not exist, or the site is down.")
    if not ALLOW_PRIVATE and not all(is_public(ip) for ip in ips):
        raise Blocked("This link points to a private or internal address, so VigilPay did not open it. A public QR code or message should never do that.")
    return ips


def _connect(host: str, port: int, secure: bool, ips, deadline: float):
    last = None
    sock = None
    for ip in ips:
        left = deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError("The website took too long to answer.")
        try:
            sock = socket.create_connection((ip, port), timeout=min(CONNECT_TIMEOUT, left))
            break
        except OSError as e:
            last = e
    if sock is None:
        raise ConnectionError(str(last or "could not connect"))
    if secure:
        try:
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
        except ssl.SSLError as e:
            sock.close()
            raise ssl.SSLError("This website's security certificate is not valid (" + (getattr(e, "reason", None) or "TLS error") + "). Real banks and shops keep a valid certificate.")
    return sock


def fetch_once(url: str, deadline: float):
    """One request, no redirect following. Returns (status, headers, body, content_type)."""
    sp = urlsplit(url)
    scheme = sp.scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError("Only web links (http or https) can be followed.")
    host = (sp.hostname or "").rstrip(".").lower()
    if not host:
        raise ValueError("That does not look like a web address.")
    try:
        port = sp.port or (443 if scheme == "https" else 80)
    except ValueError:
        raise ValueError("That web address has an invalid port number.")
    if not ALLOW_PRIVATE:
        if host == "localhost" or host.endswith((".local", ".localhost", ".internal", ".lan")):
            raise Blocked("This link points to an internal name, so VigilPay did not open it.")
        if port not in OK_PORTS:
            raise Blocked("This link uses an unusual network port, so VigilPay did not open it. That is itself a warning sign.")
    ips = resolve(host, port)
    sock = _connect(host, port, scheme == "https", ips, deadline)
    conn = None
    try:
        shown = "[" + host + "]" if ":" in host else host
        conn = (http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection)(shown, port, timeout=CONNECT_TIMEOUT)
        conn.sock = sock  # we already connected to a checked address; http.client will reuse it
        path = (sp.path or "/") + ("?" + sp.query if sp.query else "")
        conn.putrequest("GET", path, skip_accept_encoding=True)
        conn.putheader("User-Agent", UA)
        conn.putheader("Accept", "text/html,*/*;q=0.5")
        conn.putheader("Accept-Encoding", "identity")
        conn.putheader("Connection", "close")
        conn.endheaders()
        resp = conn.getresponse()
        headers = {k.lower(): v for k, v in resp.getheaders()}
        ctype = headers.get("content-type", "")
        body = resp.read(MAX_BODY) if resp.status == 200 and "html" in ctype.lower() else b""
        return resp.status, headers, body, ctype
    finally:
        for c in (conn, sock):
            try:
                if c:
                    c.close()
            except Exception:
                pass


def page_facts(body: bytes, ctype: str):
    """Title and any <meta refresh> target from the first part of an HTML page. Nothing is executed."""
    if not body:
        return None, None
    m = re.search(r"charset=([\w-]+)", ctype or "", re.I)
    try:
        text = body.decode(m.group(1) if m else "utf-8", "replace")
    except LookupError:
        text = body.decode("utf-8", "replace")
    t = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
    title = None
    if t:
        title = unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "", t.group(1)))).strip()[:140] or None
    r = re.search(r"<meta[^>]+http-equiv=[\"']?refresh[\"']?[^>]*content=[\"']?\s*\d+\s*;\s*url=['\"]?([^\"'>\s]+)", text, re.I)
    return title, (unescape(r.group(1)) if r else None)


_BOOT = {"t": 0.0, "data": None}


def _bootstrap():
    if _BOOT["data"] and time.time() - _BOOT["t"] < 43200:
        return _BOOT["data"]
    r = requests.get("https://data.iana.org/rdap/dns.json", timeout=4, headers={"User-Agent": UA})
    r.raise_for_status()
    _BOOT.update(t=time.time(), data=r.json())
    return _BOOT["data"]


def parse_rdap(j: dict, now=None):
    reg = None
    for e in j.get("events", []):
        if e.get("eventAction") == "registration":
            reg = e.get("eventDate")
    registrar = None
    for ent in j.get("entities", []):
        if "registrar" in (ent.get("roles") or []):
            for item in ((ent.get("vcardArray") or [None, []])[1] or []):
                if item and item[0] == "fn":
                    registrar = str(item[3])[:80]
                    break
    age = None
    if reg:
        try:
            d = datetime.fromisoformat(reg.replace("Z", "+00:00"))
            if d.tzinfo is None:
                d = d.replace(tzinfo=timezone.utc)
            age = max(0, ((now or datetime.now(timezone.utc)) - d).days)
        except ValueError:
            reg = None
    return {"registered": reg[:10] if reg else None, "age_days": age, "registrar": registrar} if (reg or registrar) else None


def domain_info(reg: str):
    """When the website name was first registered (public RDAP data). None when it cannot be found."""
    try:
        tld = reg.rsplit(".", 1)[-1]
        base = next((next((u for u in urls if u.startswith("https://")), None) for names, urls in _bootstrap().get("services", []) if tld in names), None)
        if not base:
            return None
        r = requests.get(base.rstrip("/") + "/domain/" + reg, timeout=4, headers={"Accept": "application/rdap+json", "User-Agent": UA})
        return parse_rdap(r.json()) if r.status_code == 200 else None
    except (requests.RequestException, ValueError, KeyError, TypeError):
        return None


_CACHE = {}


def follow(raw: str) -> dict:
    """Follow redirects from a link and describe where it ends up. Never raises."""
    raw = (raw or "").strip()[:1000]
    now = time.time()
    hit = _CACHE.get(raw)
    if hit and now - hit[0] < 600:
        return hit[1]
    res = _follow(raw)
    if len(_CACHE) > 300:
        _CACHE.clear()
    _CACHE[raw] = (now, res)
    return res


def _follow(raw: str) -> dict:
    if not raw:
        return {"ok": False, "kind": "invalid", "error": "Send a link to follow.", "hops": []}
    starts = [raw] if re.match(r"^[a-z][a-z0-9+.-]*://", raw, re.I) else ["https://" + raw, "http://" + raw]
    deadline = time.monotonic() + DEADLINE
    hops, seen, cur, last_err = [], set(), None, None
    for start in starts:
        cur, hops, seen = start, [], set()
        try:
            for _ in range(MAX_HOPS + 1):
                if cur in seen:
                    return {"ok": False, "kind": "loop", "error": "The link keeps redirecting in a circle.", "hops": hops}
                seen.add(cur)
                status, headers, body, ctype = fetch_once(cur, deadline)
                sp = urlsplit(cur)
                hops.append({"url": cur[:300], "host": (sp.hostname or "").lower(), "status": status})
                nxt = headers.get("location") if status in (301, 302, 303, 307, 308) else None
                title, refresh = page_facts(body, ctype)
                if not nxt and refresh:
                    nxt = refresh
                    hops[-1]["via"] = "meta refresh"
                if not nxt:
                    return _result(raw, hops, title, status)
                cur = urljoin(cur, nxt)
            return {"ok": False, "kind": "too-many", "error": f"The link redirects more than {MAX_HOPS} times, which is unusual and often used to hide the real website.", "hops": hops}
        except Blocked as e:
            return {"ok": False, "kind": "blocked", "error": str(e), "hops": hops}
        except ValueError as e:
            return {"ok": False, "kind": "invalid", "error": str(e), "hops": hops}
        except LookupError as e:
            last_err = ("dns", str(e))
        except ssl.SSLError as e:
            last_err = ("tls", str(e))
        except TimeoutError as e:
            last_err = ("timeout", str(e))
        except (OSError, http.client.HTTPException) as e:
            last_err = ("connect", "VigilPay could not connect to that website (" + type(e).__name__ + "). It may be down, or it may block automatic visits.")
        if last_err and last_err[0] == "dns":
            break
    kind, msg = last_err or ("connect", "Could not open that link.")
    return {"ok": False, "kind": kind, "error": msg, "hops": hops}


def _result(raw: str, hops, title, status):
    final = hops[-1]
    host = final["host"]
    is_ip = bool(re.fullmatch(r"[\d.]+|[0-9a-f:]+", host))
    reg = host if is_ip else registered_domain(host)
    first = urlsplit(raw if "://" in raw else "http://" + raw).hostname or ""
    hosted = None if is_ip else free_host(host)
    dom = None if (is_ip or hosted) else domain_info(reg)
    return {
        "ok": True, "start": raw[:300], "hops": hops,
        "final": {"url": final["url"], "host": host, "reg": reg, "status": status, "title": title},
        "crossDomain": registered_domain(first.lower()) != reg if first and not is_ip else False,
        "freeHost": hosted, "domain": dom, "error": None,
    }
