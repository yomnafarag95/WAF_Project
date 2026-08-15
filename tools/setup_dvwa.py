#!/usr/bin/env python3
"""
setup_dvwa.py (v3) - create DVWA DB, log in, and PROPERLY set the security level,
then pinpoint why /vulnerabilities/sqli/ redirects. Direct to published port (no proxy).

  python tools/setup_dvwa.py
  python tools/setup_dvwa.py --dvwa http://localhost:8081 --password password
"""
import argparse
import re
import sys
import requests

try:
    requests.packages.urllib3.disable_warnings()
except Exception:
    pass

TOKEN_RE = re.compile(r"user_token'\s*value='([0-9a-f]+)'")


def token(session, url, **kw):
    r = session.get(url, timeout=20, verify=False, **kw)
    m = TOKEN_RE.search(r.text)
    return r, (m.group(1) if m else "")


def vuln_status(session, b):
    r = session.get(f"{b}/vulnerabilities/sqli/", timeout=20, verify=False,
                    allow_redirects=False)
    return r.status_code, r.headers.get("Location", "")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dvwa", default="http://localhost:8081")
    ap.add_argument("--user", default="admin")
    ap.add_argument("--password", default="password")
    args = ap.parse_args()
    b = args.dvwa.rstrip("/")

    s = requests.Session()
    try:
        # 1) create / reset DB
        r, tok = token(s, f"{b}/setup.php")
        s.post(f"{b}/setup.php",
               data={"create_db": "Create / Reset Database", "user_token": tok},
               timeout=60, verify=False, allow_redirects=True)
        print("[1] create_db done")

        # 2) login
        r, tok = token(s, f"{b}/login.php")
        r = s.post(f"{b}/login.php",
                   data={"username": args.user, "password": args.password,
                         "Login": "Login", "user_token": tok},
                   timeout=20, verify=False, allow_redirects=True)
        print(f"[2] login  -> final HTTP {r.status_code}  url={r.url}")
        print(f"    cookies: {s.cookies.get_dict()}")

        # 3a) BEFORE setting level
        st, loc = vuln_status(s, b)
        print(f"[3a] /vuln/sqli/ before security set -> HTTP {st}  Location: {loc}")

        # 3b) set security level the PROPER way: POST /security.php
        r, tok = token(s, f"{b}/security.php")
        s.post(f"{b}/security.php",
               data={"security": "low", "seclev_submit": "Submit",
                     "user_token": tok},
               timeout=20, verify=False, allow_redirects=True)
        print("[3b] POST /security.php (security=low) done")
        print(f"     cookies: {s.cookies.get_dict()}")

        # 3c) AFTER setting level
        st, loc = vuln_status(s, b)
        ok = st == 200
        print(f"[3c] /vuln/sqli/ after security set  -> HTTP {st}  Location: {loc}  "
              f"{'[OK]' if ok else '[STILL FAILING]'}")

        print("\n==== VERDICT ====")
        if ok:
            print("Login + DB are fine. The fix is: set the security level via")
            print("POST /security.php (security=low, seclev_submit=Submit, user_token)")
            print("instead of session.cookies.set('security','low') in login_dvwa().")
        else:
            print("Still 302 even after proper security POST. Send me the Location")
            print("values above (login.php = auth issue; security.php = level issue).")
        sys.exit(0 if ok else 2)
    except Exception as e:
        print(f"ERROR: {e!r}")
        sys.exit(1)


if __name__ == "__main__":
    main()
