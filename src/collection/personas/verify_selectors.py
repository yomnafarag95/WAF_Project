"""
Selector smoke-test for OWASP Juice Shop.

WHY: the CSS selectors in juice_shop_actions.py are accurate for Juice
Shop v14-v17, but every version can shift the DOM. Instead of checking by
hand in DevTools, run this once against YOUR instance: it opens the site
and reports PASS/FAIL for each critical selector so you know the benign
generator will actually click things before you launch a large run.

Run (needs the app up; no proxy required):
  JUICE_SHOP_URL=http://localhost:3000 \
      python3 -m src.collection.personas.verify_selectors
"""

import os

from playwright.sync_api import sync_playwright

BASE_URL = os.getenv("JUICE_SHOP_URL", "http://localhost:3000")

# (label, selector) - the elements the benign actions depend on.
CRITICAL_SELECTORS = [
    ("close welcome banner", "button[aria-label='Close Welcome Banner']"),
    ("dismiss cookie", "a[aria-label='dismiss cookie message']"),
    ("product card", "mat-card, .mat-grid-tile"),
    ("search box", "#searchQuery"),
    ("account menu", "#navbarAccount"),
    ("basket", "button[aria-label='Show the shopping cart'], #navbarBasket"),
]


def main() -> int:
    print(f"Verifying selectors against {BASE_URL}\n")
    failures = 0
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.goto(BASE_URL, wait_until="networkidle")
        # dismiss the banners so downstream elements become reachable
        for sel in ("button[aria-label='Close Welcome Banner']", "a[aria-label='dismiss cookie message']"):
            try:
                page.click(sel, timeout=3000)
            except Exception:
                pass
        for label, selector in CRITICAL_SELECTORS:
            try:
                found = page.locator(selector).count() > 0
            except Exception:
                found = False
            status = "PASS" if found else "FAIL"
            if not found:
                failures += 1
            print(f"  [{status}] {label:22s} {selector}")
        browser.close()

    print()
    if failures:
        print(f"{failures} selector(s) not found - update juice_shop_actions.py for your version.")
        return 1
    print("All critical selectors present.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
