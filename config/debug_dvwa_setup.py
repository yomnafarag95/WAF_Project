"""debug_dvwa_setup.py - read DVWA's setup.php DB status directly.

Run from the repo root with the attack proxy up and venv active:
    python config/debug_dvwa_setup.py

Strips HTML and prints the 'Database' status section of setup.php BEFORE and
AFTER clicking Create/Reset Database, plus any status banners. This tells us
whether DVWA can actually reach MySQL and whether the tables get created.
Everything uses X-Capture-Skip so nothing lands in data/raw_attack.
"""
import re
from urllib.parse import urlparse

import requests
import yaml

requests.packages.urllib3.disable_warnings()

CFG = "config/sources.yaml"
SKIP = {"X-Capture-Skip": "1"}
_A = re.compile(r"name=['\"]user_token['\"]\s+value=['\"]([0-9a-fA-F]+)['\"]")
_B = re.compile(r"value=['\"]([0-9a-fA-F]+)['\"][^>]*name=['\"]user_token['\"]")


def tok(html):
    m = _A.search(html) or _B.search(html)
    return m.group(1) if m else ""


def plain(html):
    t = re.sub(r"<script[\s\S]*?</script>", " ", html, flags=re.I)
    t = re.sub(r"<style[\s\S]*?</style>", " ", t, flags=re.I)
    t = re.sub(r"<[^>]+>", " ", t)
    t = re.sub(r"&nbsp;", " ", t)
    t = re.sub(r"\s+", " ", t)
    return t.strip()


def status_section(html):
    t = plain(html)
    low = t.lower()
    for anchor in ("database will be created", "setup check", "database", "mysql"):
        i = low.find(anchor)
        if i != -1:
            start = max(0, i - 120)
            return t[start:start + 1100]
    return t[:1100]


def banners(html):
    t = plain(html)
    return [w for w in ("Setup successful", "Database has been created",
                        "Could not connect", "Unable to connect",
                        "Access denied", "Unknown database",
                        "does not exist", "failed") if w.lower() in t.lower()]


def main():
    cfg = yaml.safe_load(open(CFG, encoding="utf-8"))
    proxy = cfg["proxy_attack"]
    proxies = {"http": proxy, "https": proxy}
    base = cfg["apps"]["dvwa"]["base_url"]
    print(f"base={base}  host={urlparse(base).hostname}  proxy={proxy}\n")

    s = requests.Session()

    r = s.get(f"{base}/setup.php", proxies=proxies, headers=SKIP, verify=False,
              timeout=20, allow_redirects=True)
    t = tok(r.text)
    print(f"[1] GET  /setup.php -> {r.status_code}  token={'yes' if t else 'NO'}")
    print("    --- DB status BEFORE create_db ---")
    print("    " + status_section(r.text))
    print()

    r = s.post(f"{base}/setup.php",
               data={"create_db": "Create / Reset Database", "user_token": t},
               proxies=proxies, headers=SKIP, verify=False, timeout=90,
               allow_redirects=True)
    print(f"[2] POST create_db  -> {r.status_code}  final_url={r.url}  banners={banners(r.text)}")
    print("    --- DB status AFTER create_db ---")
    print("    " + status_section(r.text))
    print()

    r = s.get(f"{base}/login.php", proxies=proxies, headers=SKIP, verify=False,
              timeout=20, allow_redirects=False)
    print(f"[3] GET  /login.php -> {r.status_code}  Location={r.headers.get('Location')}")


if __name__ == "__main__":
    main()
