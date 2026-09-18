"""
Benign traffic generator for WebGoat + DVWA.

Uses the SAME 6 named personas as Juice Shop (src/collection/personas/configs.py)
so persona_id values are comparable across all 3 apps. Each persona runs one
or more sessions per app; each session tags every request with
X-Capture-Persona=<persona_id> so metadata.persona_id is populated correctly
(this used to be silently lost - see the module note below).

usage:
  pip install playwright pyyaml && playwright install chromium
  # docker-compose up mitmproxy-benign (port 8888)
  python3 benign_driver.py --config ../config/sources.yaml --only webgoat
  python3 benign_driver.py --config ../config/sources.yaml --only dvwa
  python3 benign_driver.py --config ../config/sources.yaml --only dvwa --sessions-per-persona 2

FIX (vs. the original version): the original looped over a generic numeric
index (`count_per_app`, e.g. 1..8) and stuffed that index into the
X-Capture-Tool header as "persona:N". capture_addon.py never reads
X-Capture-Tool for persona identity - it reads X-Capture-Persona - so every
WebGoat/DVWA record silently got metadata.persona_id = null. Meanwhile Juice
Shop (run_benign_generation.py) already used 6 named, behaviorally distinct
personas and set X-Capture-Persona correctly. This rewrite makes WebGoat and
DVWA use the identical 6 persona identities (same speed/goal/device/auth/
depth axes), so persona coverage is meaningful and comparable across apps.
"""
import argparse
import random
import sys
import time
import uuid

import yaml
from playwright.sync_api import sync_playwright

from journeys import (JOURNEYS, PRODUCT_IDS, SEARCH_TERMS, BENIGN_NAMES,
                       MUTILLIDAE_AUTHORS, MUTILLIDAE_TEXTFILES)
from personas.configs import PERSONAS, Device, PersonaConfig

# A journey run more than this many times in ONE session used to be the
# dominant source of exact-duplicate raw_request records (confirmed via
# merge_jsonl.py: 64% of all raw records were byte-identical dupes) because
# apps only have ~4-5 journeys but sessions run 10-25 actions. Capping
# repeats - and ending the session early once every journey has hit the cap,
# rather than forcing more literal repeats - keeps sessions realistic
# (a real visitor doesn't reload the same static page 5+ times) and keeps
# raw_request diversity high.
# Raised from 2 -> 4 once the randomized value pools (journeys.py
# SEARCH_TERMS/PRODUCT_IDS/BENIGN_NAMES) were expanded: repeats of the
# PARAMETERIZED journeys now produce genuinely different requests, so more
# repeats = more volume AND more diversity (not byte-identical dupes). The
# few literal journeys (browse_home/api_products/etc.) still collapse at
# merge time, which is harmless.
MAX_REPEATS_PER_JOURNEY = 4


def sample_delay_ms(persona: PersonaConfig) -> int:
    """Delay for this persona's speed profile (same axis Juice Shop uses)."""
    lo, hi = persona.speed_profile.min_delay_ms, persona.speed_profile.max_delay_ms
    return random.randint(lo, hi)


def pick_user_agent(persona: PersonaConfig, user_agents: list) -> str:
    """Match the UA to the persona's device axis instead of picking fully at random."""
    mobile_uas = [ua for ua in user_agents if "iPhone" in ua or "Mobile" in ua or "Android" in ua]
    desktop_uas = [ua for ua in user_agents if ua not in mobile_uas]
    pool = mobile_uas if persona.device == Device.MOBILE else desktop_uas
    return random.choice(pool or user_agents)


def capture_headers(app_name, source_type, session_id, persona: PersonaConfig):
    """Headers read (and stripped) by the shared mitmproxy addon."""
    return {
        "X-Capture-Source": app_name,
        "X-Capture-App": app_name,
        "X-Capture-Type": source_type,
        "X-Capture-Mode": "browser",
        "X-Capture-Label": "benign",
        "X-Capture-Session": session_id,
        "X-Capture-Persona": persona.persona_id,
        "X-Capture-Scenario": persona.goal.value,
        "X-Capture-Tool": "benign_driver",
    }


# ------------------- per-app setup / login handlers -------------------
def setup_dvwa(page, base_url, app_cfg):
    """Create/reset the DVWA DB, log in, and set security level to low
    (benign traffic only - attacks are captured through a separate proxy)."""
    page.goto(f"{base_url}/setup.php", wait_until="domcontentloaded")
    try:
        page.click("input[name='create_db']", timeout=4000)
    except Exception:
        pass
    page.goto(f"{base_url}/login.php", wait_until="domcontentloaded")
    page.fill("input[name='username']", app_cfg.get("login_user", "admin"))
    page.fill("input[name='password']", app_cfg.get("login_pass", "password"))
    page.click("input[name='Login'], button[type='submit']")
    page.goto(f"{base_url}/security.php", wait_until="domcontentloaded")


def login_webgoat(page, base_url, app_cfg):
    """Register (once) then log in to WebGoat.

    NOTE: WebGoat/DVWA selectors below have not been live-verified against a
    running container the way Juice Shop's were (see personas/verify_selectors.py).
    If registration/login silently fails, run_persona still continues (it
    degrades to unauthenticated browsing) but you should manually check the
    /registration and /login forms once before a full run.
    """
    user = app_cfg.get("login_user", "benign_user")
    pw = app_cfg.get("login_pass", "Benign123!")
    if app_cfg.get("register"):
        page.goto(f"{base_url}/registration", wait_until="domcontentloaded")
        try:
            page.fill("input[name='username']", user)
            page.fill("input[name='password']", pw)
            page.fill("input[name='matchingPassword']", pw)
            # WebGoat registration REQUIRES agreeing to the terms. Confirmed
            # against the live form:
            #   <input type="checkbox" name="agree" value="agree"/>
            # Without checking it the POST is rejected and the user is NEVER
            # created, so every later lesson request redirects to
            # /WebGoat/login (and /login?error -> 500), polluting the data
            # with login pages instead of real authenticated browsing. This
            # single missing check was the root cause of the WebGoat 500 spam.
            try:
                page.check("input[name='agree']")
            except Exception:
                pass  # checkbox absent on some WebGoat builds - harmless
            page.click("button[type='submit'], input[type='submit']")
            page.wait_for_load_state("domcontentloaded")
        except Exception:
            pass  # already registered, or form differs - continue anyway
    page.goto(f"{base_url}/login", wait_until="domcontentloaded")
    try:
        page.fill("input[name='username']", user)
        page.fill("input[name='password']", pw)
        page.click("button[type='submit'], input[type='submit']")
        page.wait_for_load_state("domcontentloaded")
    except Exception:
        pass


def do_login(page, app_name, base_url, app_cfg):
    if app_name == "dvwa":
        if app_cfg.get("setup_db"):
            setup_dvwa(page, base_url, app_cfg)
    elif app_name == "webgoat":
        login_webgoat(page, base_url, app_cfg)


# ------------------- journey execution -------------------
def _fill_path_params(path: str) -> str:
    """Substitute {term}/{id}/{name}/{author}/{textfile} placeholders (see
    journeys.py) with a fresh random value each time a step runs, so
    repeated visits to the same journey within a session produce
    genuinely different requests instead of literal repeats. Applied to
    BOTH goto paths and fill/select step values (see run_step)."""
    if "{term}" in path:
        path = path.replace("{term}", random.choice(SEARCH_TERMS))
    if "{id}" in path:
        path = path.replace("{id}", str(random.choice(PRODUCT_IDS)))
    if "{name}" in path:
        path = path.replace("{name}", random.choice(BENIGN_NAMES))
    if "{author}" in path:
        path = path.replace("{author}", random.choice(MUTILLIDAE_AUTHORS))
    if "{textfile}" in path:
        path = path.replace("{textfile}", random.choice(MUTILLIDAE_TEXTFILES))
    return path


def run_step(page, base_url, step):
    action = step["do"]
    try:
        if action == "goto":
            path = _fill_path_params(step["path"])
            page.goto(base_url + path, wait_until="domcontentloaded", timeout=15000)
        elif action == "fill":
            page.fill(step["selector"], _fill_path_params(step["value"]), timeout=5000)
        elif action == "select":
            page.select_option(step["selector"], _fill_path_params(step["value"]), timeout=5000)
        elif action == "click":
            page.click(step["selector"], timeout=5000)
    except Exception as e:
        print(f"    [skip] {action} -> {e}", file=sys.stderr)


def run_persona(context, app_name, base_url, app_cfg, cfg, persona: PersonaConfig):
    session_id = str(uuid.uuid4())
    src_type = "scripted"
    page = context.new_page()
    page.set_extra_http_headers(
        capture_headers(app_name, src_type, session_id, persona)
    )

    if app_cfg.get("requires_login"):
        do_login(page, app_name, base_url, app_cfg)
        time.sleep(sample_delay_ms(persona) / 1000.0)

    # Depth/patience shape session length the same way they do for Juice
    # Shop: deep personas browse longer, low-patience personas may cut the
    # session short (mirrors abandon_session_prob without needing the full
    # SessionRunner machinery, since these journeys are simple goto lists).
    lo, hi = cfg["personas"]["session_len"]
    if persona.depth.value == "deep":
        lo, hi = lo + 5, hi + 5
    else:
        lo, hi = max(3, lo - 3), max(lo, hi - 5)
    n_actions = random.randint(lo, hi)

    available = app_cfg["journeys"]
    used = {j: 0 for j in available}
    for _ in range(n_actions):
        if random.random() < persona.jitter.abandon_session_prob:
            break  # early abandonment, same behavior as the Juice Shop personas
        # Only pick from journeys not yet at the per-session repeat cap.
        # Once every journey has hit the cap, end the session instead of
        # forcing more literal repeats (see MAX_REPEATS_PER_JOURNEY note).
        candidates = [j for j in available if used[j] < MAX_REPEATS_PER_JOURNEY]
        if not candidates:
            break
        jname = random.choice(candidates)
        used[jname] += 1
        for step in JOURNEYS.get(jname, []):
            if step["do"] == "login":
                continue  # already handled above via do_login()
            run_step(page, base_url, step)
            time.sleep(sample_delay_ms(persona) / 1000.0)
    page.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--only", help="run a single app only (webgoat|dvwa|juice_shop)", default=None)
    ap.add_argument("--sessions-per-persona", type=int, default=1,
                     help="how many sessions to run per persona, per app (default 1 = 6 sessions/app)")
    args = ap.parse_args()

    with open(args.config, encoding="utf-8") as f:
        cfg = yaml.safe_load(f)

    proxy_url = cfg["proxy_benign"]
    uas = cfg["personas"]["user_agents"]
    apps = cfg["apps"]
    if args.only:
        apps = {args.only: apps[args.only]}

    persona_list = list(PERSONAS.values())  # same 6 identities as Juice Shop

    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True,
            proxy={"server": proxy_url},
            args=["--ignore-certificate-errors"],
        )
        for app_name, app_cfg in apps.items():
            base_url = app_cfg["base_url"]
            print(f"[+] {app_name} ({app_cfg['tech_stack']}) -> {base_url}")
            for persona in persona_list:
                for s in range(args.sessions_per_persona):
                    ua = pick_user_agent(persona, uas)
                    context = browser.new_context(user_agent=ua, ignore_https_errors=True)
                    print(f"  - persona={persona.persona_id} session {s + 1}/{args.sessions_per_persona} (UA={ua[:30]}...)")
                    run_persona(context, app_name, base_url, app_cfg, cfg, persona)
                    context.close()
        browser.close()
    print("[done] benign collection finished -> data/raw/*_raw.jsonl")


if __name__ == "__main__":
    main()
