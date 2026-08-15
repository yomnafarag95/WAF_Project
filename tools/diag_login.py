#!/usr/bin/env python3
"""
diag_login.py - find out WHY dvwa/webgoat attacks stay at 302 (login failing).

By default this hits the PUBLISHED ports directly (no proxy) so it can NEVER
pollute data/raw_attack, and it isolates whether login works at the application
level at all. It prints the status code + redirect Location at every step.

  published ports (default, safe):
    python tools/diag_login.py

  exact driver path (through the attack proxy + docker hostnames):
    python tools/diag_login.py --proxy http://127.0.0.1:8889 \
        --dvwa http://dvwa:80 --webgoat http://webgoat:8080/WebGoat
  (proxy mode adds X-Capture-Skip so it is not recorded)

Interpretation:
  * login works on published ports but fails via --proxy  -> proxy path problem
  * fails BOTH ways                                       -> app-level:
       DVWA  -> needs /setup.php 'Create / Reset Database', or bad CSRF/creds
       WebGoat -> registration/login endpoint differs in your version
"""
import argparse
import re
import requests

try:
    requests.packages.urllib3.disable_warnings()
except Exception:
    pass


def show(name, r):
    loc = r.headers.get("Location", "")
    extra = f"  -> Location: {loc}" if loc else ""
    print(f"  {name:26s} HTTP {r.status_code}  len={len(r.text):<6d} final={r.url}{extra}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--proxy", default=None, help="e.g. http://127.0.0.1:8889 (omit = direct)")
    ap.add_argument("--dvwa", default="http://localhost:8081")
    ap.add_argument("--webgoat", default="http://localhost:8080/WebGoat")
    args = ap.parse_args()

    proxies = {"http": args.proxy, "https": args.proxy} if args.proxy else None
    hdr = {"X-Capture-Skip": "1"} if args.proxy else {}
    kw = dict(timeout=20, verify=False, proxies=proxies, headers=hdr)

    print(f"mode: {'PROXY ' + args.proxy if args.proxy else 'DIRECT (published ports)'}\n")

    print("=== DVWA ===")
    s = requests.Session()
    try:
        r = s.get(f"{args.dvwa}/login.php", allow_redirects=True, **kw)
        show("GET /login.php", r)
        m = re.search(r"user_token'\s*value='([0-9a-f]+)'", r.text)
        print(f"  user_token found: {bool(m)}")
        tok = m.group(1) if m else ""
        r = s.post(f"{args.dvwa}/login.php",
                   data={"username": "admin", "password": "password",
                         "Login": "Login", "user_token": tok},
                   allow_redirects=False, **kw)
        show("POST /login.php", r)
        s.cookies.set("security", "low")
        r = s.get(f"{args.dvwa}/vulnerabilities/sqli/", allow_redirects=False, **kw)
        show("GET /vuln/sqli/", r)
        r = s.get(f"{args.dvwa}/setup.php", allow_redirects=True, **kw)
        needs = "Create / Reset Database" in r.text
        show("GET /setup.php", r)
        print(f"  DVWA DB setup needed?: {needs}")
    except Exception as e:
        print(f"  DVWA ERROR: {e!r}")

    print("\n=== WEBGOAT ===")
    s = requests.Session()
    try:
        r = s.get(f"{args.webgoat}/login", allow_redirects=True, **kw)
        show("GET /login", r)
        r = s.post(f"{args.webgoat}/register.mvc",
                   data={"username": "benign-user", "password": "Benign123!",
                         "matchingPassword": "Benign123!", "agree": "agree"},
                   allow_redirects=False, **kw)
        show("POST /register.mvc", r)
        r = s.post(f"{args.webgoat}/login",
                   data={"username": "benign-user", "password": "Benign123!"},
                   allow_redirects=False, **kw)
        show("POST /login", r)
        r = s.get(f"{args.webgoat}/PathTraversal", allow_redirects=False, **kw)
        show("GET /PathTraversal", r)
    except Exception as e:
        print(f"  WEBGOAT ERROR: {e!r}")


if __name__ == "__main__":
    main()
