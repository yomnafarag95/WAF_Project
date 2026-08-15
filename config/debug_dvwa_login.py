"""debug_dvwa_login.py - isolate WHY the scripted DVWA login is rejected.

Run from the repo root with the attack proxy up and the venv active:
    python debug_dvwa_login.py

Prints the status + Location + cookies at every step so we can see whether the
login POST redirects to index.php (success) or bounces back to login.php
(failure), and whether DVWA complains about the CSRF token or the credentials.
Everything is sent with X-Capture-Skip so nothing lands in data/raw_attack.
"""
import re
import sys
from urllib.parse import urlparse

import requests
import yaml

requests.packages.urllib3.disable_warnings()

CFG = "config/sources.yaml"
SKIP = {"X-Capture-Skip": "1"}
# tolerant: matches name/value in either order, single or double quotes
_A = re.compile(r"name=['\"]user_token['\"]\s+value=['\"]([0-9a-fA-F]+)['\"]")
_B = re.compile(r"value=['\"]([0-9a-fA-F]+)['\"][^>]*name=['\"]user_token['\"]")


def tok(html):
    m = _A.search(html) or _B.search(html)
    return m.group(1) if m else ""


def grep(html, words):
    low = html.lower()
    return [w for w in words if w.lower() in low]


def main():
    cfg = yaml.safe_load(open(CFG, encoding="utf-8"))
    proxy = cfg["proxy_attack"]
    proxies = {"http": proxy, "https": proxy}
    base = cfg["apps"]["dvwa"]["base_url"]
    host = urlparse(base).hostname
    print(f"base={base}  host={host}  proxy={proxy}\n")

    s = requests.Session()

    # --- 1. setup.php (create/reset DB) ---
    r = s.get(f"{base}/setup.php", proxies=proxies, headers=SKIP, verify=False,
              timeout=20, allow_redirects=False)
    print(f"[1] GET  /setup.php     -> {r.status_code}  Location={r.headers.get('Location')}  token={'yes' if tok(r.text) else 'NO'}")
    st = tok(r.text)
    r = s.post(f"{base}/setup.php", data={"create_db": "Create / Reset Database", "user_token": st},
               proxies=proxies, headers=SKIP, verify=False, timeout=60, allow_redirects=False)
    print(f"[2] POST /setup.php     -> {r.status_code}  Location={r.headers.get('Location')}  hits={grep(r.text, ['Setup successful','Database has been created','error'])}")

    # --- 2. login.php GET (issue a fresh token) ---
    r = s.get(f"{base}/login.php", proxies=proxies, headers=SKIP, verify=False,
              timeout=20, allow_redirects=False)
    lt = tok(r.text)
    print(f"[3] GET  /login.php     -> {r.status_code}  Location={r.headers.get('Location')}  token={lt[:16]}")
    print(f"    cookies now: {s.cookies.get_dict()}")

    # --- 3. login.php POST (the step that is failing) ---
    r = s.post(f"{base}/login.php",
               data={"username": "admin", "password": "password", "Login": "Login", "user_token": lt},
               proxies=proxies, headers=SKIP, verify=False, timeout=20, allow_redirects=False)
    print(f"[4] POST /login.php     -> {r.status_code}  Location={r.headers.get('Location')}")
    print(f"    body mentions: {grep(r.text, ['CSRF','token','Login failed','incorrect','password'])}")
    print(f"    cookies now: {s.cookies.get_dict()}")

    # --- 4. verify authenticated ---
    r = s.get(f"{base}/index.php", proxies=proxies, headers=SKIP, verify=False,
              timeout=20, allow_redirects=False)
    print(f"[5] GET  /index.php     -> {r.status_code}  Location={r.headers.get('Location')}  (200 = AUTHENTICATED)")

    # --- 5. set security=low + hit a vuln page ---
    s.cookies.set("security", "low", domain=host, path="/")
    r = s.get(f"{base}/vulnerabilities/sqli/", params={"id": "1", "Submit": "Submit"},
              proxies=proxies, headers=SKIP, verify=False, timeout=20, allow_redirects=False)
    print(f"[6] GET  /vulnerabilities/sqli/ -> {r.status_code}  Location={r.headers.get('Location')}  (200 = attack surface reachable)")


if __name__ == "__main__":
    main()
