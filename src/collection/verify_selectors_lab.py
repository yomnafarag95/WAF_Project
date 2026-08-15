"""
Selector smoke-test for WebGoat + DVWA (the lab-app counterpart of
src/collection/personas/verify_selectors.py, which already covers Juice Shop).

WHY: benign_driver.py's login_webgoat()/setup_dvwa() rely on hard-coded CSS
selectors (input[name='username'], etc.) that were never checked against a
live container. If a selector is wrong, the driver does not crash - it just
silently falls back to guest browsing - so you would not notice a login
failure until you looked at how many benign records had auth_state missing.
Run this once, against your running containers, before a full collection run.

Run (containers must be up; no proxy needed - this hits them directly):
  WEBGOAT_URL=http://localhost:8080/WebGoat DVWA_URL=http://localhost:8081 \
      python3 src/collection/verify_selectors_lab.py

DVWA flow mirrors setup_dvwa() in benign_driver.py exactly:
  1. open /setup.php and click Create/Reset Database (needs a real DB - see
     docker-compose.yml's dvwa-db service; without it this whole flow fails
     with a mysqli "Connection refused" error, which is a docker-compose
     issue, not a selector issue).
  2. open /login.php, check the form fields, then actually submit valid
     admin/password credentials (a plain field-existence check is not
     enough here: /security.php requires an authenticated session, so
     checking it without first logging in always fails, DVWA just redirects
     back to /login.php).
  3. open /security.php and check the security-level selector.

On any FAIL, this prints the current URL, page title, and the start of the
page's visible text so you can paste that back for a selector fix, without
needing to open DevTools yourself.

Exit code is 0 only if every critical selector was found.
"""
import os
import sys

from playwright.sync_api import sync_playwright

WEBGOAT_URL = os.getenv("WEBGOAT_URL", "http://localhost:8080/WebGoat")
DVWA_URL = os.getenv("DVWA_URL", "http://localhost:8081")
DVWA_USER = os.getenv("DVWA_USER", "admin")
DVWA_PASS = os.getenv("DVWA_PASS", "password")

# (label, path, selector) - what login_webgoat() depends on.
WEBGOAT_CHECKS = [
    ("registration: username field", "/registration", "input[name='username']"),
    ("registration: password field", "/registration", "input[name='password']"),
    ("registration: confirm-password field", "/registration", "input[name='matchingPassword']"),
    ("registration: submit button", "/registration", "button[type='submit'], input[type='submit']"),
    ("login: username field", "/login", "input[name='username']"),
    ("login: password field", "/login", "input[name='password']"),
    ("login: submit button", "/login", "button[type='submit'], input[type='submit']"),
]


def _dump_diagnostics(page) -> None:
    print(f"           -> current URL: {page.url}")
    try:
        print(f"           -> page title : {page.title()!r}")
    except Exception:
        pass
    try:
        snippet = page.inner_text("body")[:300].replace("\n", " ").strip()
        print(f"           -> body starts: {snippet}")
    except Exception:
        print("           -> (could not read body text)")


def _check(page, label: str, path: str, selector: str) -> bool:
    try:
        found = page.locator(selector).count() > 0
    except Exception:
        found = False
    status = "PASS" if found else "FAIL"
    print(f"  [{status}] {label:32s} {path:14s} {selector}")
    if not found:
        _dump_diagnostics(page)
    return found


def check_webgoat(page, base_url: str) -> int:
    print(f"\n[webgoat] base_url={base_url}")
    failures = 0
    last_path = None
    for label, path, selector in WEBGOAT_CHECKS:
        if path != last_path:
            try:
                page.goto(base_url + path, wait_until="domcontentloaded", timeout=15000)
            except Exception as e:
                print(f"  [FAIL] could not open {path} -> {e}")
                failures += 1
                last_path = path
                continue
            last_path = path
        if not _check(page, label, path, selector):
            failures += 1
    return failures


def check_dvwa(page, base_url: str) -> int:
    print(f"\n[dvwa] base_url={base_url}")
    failures = 0

    # 1) setup.php - check the button, then actually click it (needs dvwa-db up).
    page.goto(base_url + "/setup.php", wait_until="domcontentloaded", timeout=15000)
    if not _check(page, "setup: create/reset DB button", "/setup.php", "input[name='create_db']"):
        failures += 1
    try:
        page.click("input[name='create_db']", timeout=5000)
        page.wait_for_timeout(2000)
        print("  [info] clicked Create/Reset DB - waiting for DVWA to initialize")
    except Exception as e:
        print(f"  [warn] could not click create_db -> {e}")

    # 2) login.php - check fields, then actually submit real credentials.
    # (security.php in step 3 needs a logged-in session; a field-existence
    # check alone would leave us unauthenticated and security.php would just
    # redirect back to /login.php.)
    page.goto(base_url + "/login.php", wait_until="domcontentloaded", timeout=15000)
    for label, selector in [
        ("login: username field", "input[name='username']"),
        ("login: password field", "input[name='password']"),
        ("login: submit button", "input[name='Login'], button[type='submit']"),
    ]:
        if not _check(page, label, "/login.php", selector):
            failures += 1
    try:
        page.fill("input[name='username']", DVWA_USER)
        page.fill("input[name='password']", DVWA_PASS)
        page.click("input[name='Login'], button[type='submit']")
        page.wait_for_load_state("domcontentloaded", timeout=10000)
        print(f"  [info] submitted DVWA login as '{DVWA_USER}'")
    except Exception as e:
        print(f"  [warn] could not submit DVWA login -> {e}")

    # 3) security.php - only reachable now that we are actually logged in.
    page.goto(base_url + "/security.php", wait_until="domcontentloaded", timeout=15000)
    if not _check(page, "security page: level selector", "/security.php",
                  "select[name='security'], input[name='security']"):
        failures += 1

    return failures


def main() -> int:
    total_failures = 0
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(ignore_https_errors=True)
        total_failures += check_webgoat(page, WEBGOAT_URL)
        total_failures += check_dvwa(page, DVWA_URL)
        browser.close()

    print()
    if total_failures:
        print(f"{total_failures} selector(s) not found - see the diagnostics above (URL/title/body) "
              "and share them so login_webgoat()/setup_dvwa() in benign_driver.py can be updated.")
        return 1
    print("All critical WebGoat/DVWA selectors present. Safe to run benign_driver.py.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
