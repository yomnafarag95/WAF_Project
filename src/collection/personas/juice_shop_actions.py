"""
Playwright actions for OWASP Juice Shop (benign browsing).

Each action has the signature `action(page: Page) -> None` and is wrapped
in a lambda inside scenarios.py so it matches ScenarioStep.action.

FIXES vs. the original playwright_actions.py:
1. Removed the NetworkCapture class entirely. It duplicated capture logic
   AND leaked memory: _on_request stored a start time for every request
   (including images/fonts/css), but _on_response returned early for those
   resource types WITHOUT popping them, so the dict grew without bound.
   Capture is now done on the wire by the shared mitmproxy addon, so no
   per-page capture is needed here.
2. Corrected the selectors to match Juice Shop's real Angular DOM
   (navbarAccount / navbarLoginButton / navbarLogoutButton / navbarBasket /
   searchQuery / aria-label='Add to Basket'). The original [data-test=...]
   selectors do not exist in Juice Shop and would have failed every click.
3. Every interaction is wrapped in a soft try/except so a single missing
   element does not kill the whole session (realistic + robust).

NOTE: selectors are accurate for Juice Shop v14-v17 based on its public
Cypress e2e suite, but you should still confirm them against YOUR running
version with browser DevTools before a large-scale run.
"""

from __future__ import annotations

import os
import random

from playwright.sync_api import Page, BrowserContext, sync_playwright

BASE_URL = os.getenv("JUICE_SHOP_URL", "http://juice-shop:3000")


def _safe(fn, *args, **kwargs) -> None:
    """Run a Playwright interaction, swallowing element-not-found errors."""
    try:
        fn(*args, **kwargs)
    except Exception as exc:  # noqa: BLE001 - intentional soft-fail per step
        print(f"    [skip] {getattr(fn, '__name__', fn)} -> {exc}")


def _dismiss_banners(page: Page) -> None:
    """Close the welcome dialog + cookie banner that Juice Shop shows first."""
    _safe(page.click, "button[aria-label='Close Welcome Banner']", timeout=3000)
    _safe(page.click, "a[aria-label='dismiss cookie message']", timeout=3000)


def goto_homepage(page: Page) -> None:
    page.goto(BASE_URL, wait_until="networkidle")
    _dismiss_banners(page)


def browse_products(page: Page) -> None:
    """Wait for the product grid to be present (a plain catalog view)."""
    _safe(page.wait_for_selector, "mat-card, .mat-grid-tile", timeout=5000)


def view_product_details(page: Page) -> None:
    """Open a random product card from the catalog."""
    products = page.locator("mat-card, .mat-grid-tile")
    try:
        count = products.count()
    except Exception:
        count = 0
    if count > 0:
        _safe(products.nth(random.randint(0, count - 1)).click, timeout=5000)
        _safe(page.wait_for_load_state, "networkidle")


def search_products(page: Page, query: str = "juice") -> None:
    """Search using the toolbar search field."""
    _safe(page.click, "#searchQuery, mat-icon:has-text('search')", timeout=5000)
    _safe(page.fill, "#searchQuery input, #searchQuery", query, timeout=5000)
    _safe(page.press, "#searchQuery input, #searchQuery", "Enter")
    _safe(page.wait_for_load_state, "networkidle")


def add_to_cart(page: Page) -> None:
    _safe(page.click, "button[aria-label='Add to Basket']", timeout=5000)
    _safe(page.wait_for_timeout, 500)


def view_cart(page: Page) -> None:
    _safe(page.click, "button[aria-label='Show the shopping cart'], #navbarBasket", timeout=5000)
    _safe(page.wait_for_load_state, "networkidle")


def login(page: Page, email: str, password: str) -> None:
    _safe(page.click, "#navbarAccount", timeout=5000)
    _safe(page.click, "#navbarLoginButton", timeout=5000)
    _safe(page.fill, "#email", email, timeout=5000)
    _safe(page.fill, "#password", password, timeout=5000)
    _safe(page.click, "#loginButton")
    _safe(page.wait_for_load_state, "networkidle")


def logout(page: Page) -> None:
    _safe(page.click, "#navbarAccount", timeout=5000)
    _safe(page.click, "#navbarLogoutButton", timeout=5000)
    _safe(page.wait_for_load_state, "networkidle")


def go_back(page: Page) -> None:
    """Browser back button - used heavily by the 'compare' scenario."""
    _safe(page.go_back, wait_until="networkidle")


def run_persona_session(
    session_runner,
    scenario_id: str,
    scenario_name: str,
    step_builder,
    device_type: str,
    trace_output_dir: str,
    proxy_server: str,
    capture_headers: dict,
) -> str:
    """
    Launch a browser through the mitmproxy capture proxy, tag every request
    with the X-Capture-* headers, run the session, and save a Playwright
    trace. Returns the trace file path.

    Capture happens on the wire (mitmproxy addon) - this function does not
    read or write any dataset record itself.
    """
    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True,
            proxy={"server": proxy_server},
            args=["--ignore-certificate-errors"],
        )

        context_options = {"ignore_https_errors": True}
        if device_type == "mobile":
            context_options.update(p.devices["iPhone 13"])

        context: BrowserContext = browser.new_context(**context_options)
        context.set_extra_http_headers(capture_headers)
        context.tracing.start(screenshots=True, snapshots=True, sources=True)

        page = context.new_page()
        trace_path = f"{trace_output_dir}/{session_runner.session_id}.zip"
        try:
            goto_homepage(page)
            steps = step_builder(page)
            session_runner.run_scenario(
                scenario_id=scenario_id,
                scenario_name=scenario_name,
                steps=steps,
                sleep_fn=page.wait_for_timeout,
            )
        finally:
            _safe(context.tracing.stop, path=trace_path)
            context.close()
            browser.close()

    return trace_path
