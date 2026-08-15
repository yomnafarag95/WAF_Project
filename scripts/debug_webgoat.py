"""
Standalone WebGoat auth diagnostic (NOT part of the collection pipeline).

Tests the register+login flow TWICE:
  1) with the fixed username 'benign_user' (what the driver uses now)
  2) with a fresh RANDOM username

For each attempt it prints the exact on-page error text and a final AUTH
verdict (did /start.mvc stay put, or bounce to /login?). If the random
username succeeds while the fixed one fails, the root cause is 'username
already exists' and the fix is to register a unique user per run.

Run (through the benign proxy, same as the real driver):
  python scripts/debug_webgoat.py
"""
import random
import string
import time

from playwright.sync_api import sync_playwright

PROXY = "http://127.0.0.1:8888"
BASE = "http://webgoat:8080/WebGoat"
PW = "Benign123!"


def extract_error(page):
    """Print the human-readable text of any error/alert element on the page."""
    found = False
    for sel in (".has-error", ".alert", ".text-danger", ".error"):
        try:
            for el in page.query_selector_all(sel):
                txt = (el.inner_text() or "").strip().replace("\n", " ")
                if txt:
                    print(f"    error[{sel}]: {txt[:200]}")
                    found = True
        except Exception:
            pass
    if not found:
        print("    (no error element found)")


def submit(page, label):
    try:
        with page.expect_navigation(wait_until="domcontentloaded", timeout=10000):
            page.click("button[type='submit'], input[type='submit']")
    except Exception as e:
        print(f"    [{label}] no navigation after submit -> {e}")
    time.sleep(1)


def try_flow(browser, user):
    print(f"\n=========== username = '{user}' ===========")
    ctx = browser.new_context(ignore_https_errors=True)
    page = ctx.new_page()

    print("-- REGISTER --")
    page.goto(f"{BASE}/registration", wait_until="domcontentloaded")
    page.fill("input[name='username']", user)
    page.fill("input[name='password']", PW)
    page.fill("input[name='matchingPassword']", PW)
    try:
        page.check("input[name='agree']")
    except Exception:
        pass
    submit(page, "register")
    print("    after-register url:", page.url)
    extract_error(page)

    print("-- LOGIN --")
    page.goto(f"{BASE}/login", wait_until="domcontentloaded")
    page.fill("input[name='username']", user)
    page.fill("input[name='password']", PW)
    submit(page, "login")
    print("    after-login url:", page.url)
    extract_error(page)

    print("-- PROTECTED PAGE (verdict) --")
    r = page.goto(f"{BASE}/start.mvc", wait_until="domcontentloaded")
    ok = page.url.rstrip("/").endswith("/start.mvc")
    print("    start.mvc final url:", page.url, "status:", r.status if r else None)
    print("    VERDICT:", "AUTH OK \u2705" if ok else "AUTH FAILED \u274c")
    ctx.close()
    return ok


def main():
    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True,
            proxy={"server": PROXY},
            args=["--ignore-certificate-errors"],
        )
        try_flow(browser, "benign-user")
        uniq = "benign-" + "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
        try_flow(browser, uniq)
        browser.close()


if __name__ == "__main__":
    main()
