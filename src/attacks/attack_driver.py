"""
attack_driver.py - persona/scenario-driven ATTACK traffic generator.
=====================================================================
The attack analogue of src/collection/benign_driver.py. It replays curated
payloads through the ATTACK proxy (proxy_attack, port 8889) so the shared
mitmproxy addon (src/capture/capture_addon.py) captures every request with the
SAME schema_v2 shape as benign traffic.

The driver sets EVERY X-Capture-* control header explicitly, which is why it -
unlike dotdotpwn / XSStrike - never relies on the attack proxy's default_label.

--------------------------------------------------------------------------
AUTH FIX (2026-08): DVWA attacks were 100%% 302 because login_dvwa() never ran
the /setup.php 'Create / Reset Database' step that the working benign path
(setup_dvwa in benign_driver.py) performs. On a fresh/rebuilt container DVWA
redirects EVERYTHING (including /login.php) to /setup.php until the DB is
created, so the CSRF token GET returned a redirect page, token extraction
failed, login failed, and every attack 302'd to login.php. login_dvwa() now:
  1. creates/resets the DB once per run (module-level guard),
  2. extracts the CSRF user_token with a quote/attribute-order agnostic regex,
  3. attaches the security=low cookie to the correct host, and
  4. verifies the session is actually authenticated (and warns loudly if not).
A new --probe mode logs in and fires ONE canary request per (app, attack) so
you can confirm real 200s (and non-302/404) in seconds before a full re-run.
Probe traffic carries X-Capture-Skip so it never pollutes data/raw_attack.
--------------------------------------------------------------------------

usage:
  pip install requests pyyaml
  # bring up the attack proxy first (writes to the SEPARATE data/raw_attack dir):
  #   docker compose up -d --force-recreate mitmproxy-attack
  python3 src/attacks/attack_driver.py --config config/sources.yaml --probe        # pre-flight
  python3 src/attacks/attack_driver.py --config config/sources.yaml
  python3 src/attacks/attack_driver.py --config config/sources.yaml --only-app dvwa --only-attack sqli
  python3 src/attacks/attack_driver.py --config config/sources.yaml --dry-run       # preview only
"""

import argparse
import random
import re
import sys
import time
import uuid
from urllib.parse import urlparse

import requests
import yaml

from attacker_personas import ATTACKER_PERSONAS
from attack_scenarios import build_attack_steps, endpoint_for


def rate_delay_s(persona, jitter_pct: float = 25.0) -> float:
    """Think-time between attack requests (seconds)."""
    lo, hi = persona.rate_policy.min_delay_ms, persona.rate_policy.max_delay_ms
    base = random.randint(lo, hi)
    if jitter_pct:
        base *= 1.0 + random.uniform(-jitter_pct / 100.0, jitter_pct / 100.0)
    return max(0.0, base) / 1000.0


def capture_headers(app, attack_type, session_id, persona, step) -> dict:
    """All X-Capture-* control headers (read and stripped by the addon)."""
    return {
        "X-Capture-Source": app,
        "X-Capture-App": app,
        "X-Capture-Type": "scripted",
        "X-Capture-Mode": "tool",         # generation_mode=tool -> label_source=tool_confirmed
        "X-Capture-Label": attack_type,   # sqli|xss|path_traversal|code_injection
        "X-Capture-Session": session_id,
        "X-Capture-Persona": persona.persona_id,
        "X-Capture-Scenario": f"{attack_type}:{persona.goal.value}:{step.vector}",
        "X-Capture-Tool": "attack_driver",
        "X-Capture-Variant": step.variant_type,
        "X-Capture-Parent": step.parent_id,
    }


# ------------------------- best-effort per-app auth -------------------------
SKIP = {"X-Capture-Skip": "1"}   # keep auth/probe traffic out of the dataset

# quote- and attribute-order-agnostic DVWA CSRF token extraction
_TOKEN_A = re.compile(r"name=['\"]user_token['\"]\s+value=['\"]([0-9a-fA-F]+)['\"]")
_TOKEN_B = re.compile(r"value=['\"]([0-9a-fA-F]+)['\"][^>]*name=['\"]user_token['\"]")

_DVWA_DB_READY = False   # create/reset the DB only once per driver run


def _dvwa_token(html: str) -> str:
    m = _TOKEN_A.search(html) or _TOKEN_B.search(html)
    return m.group(1) if m else ""


def _ensure_dvwa_db(session, base_url, proxies, verbose=False):
    """Create/reset the DVWA DB once (mirrors benign setup_dvwa). Fresh
    containers 302 every request to /setup.php until this runs."""
    global _DVWA_DB_READY
    if _DVWA_DB_READY:
        return
    r = session.get(f"{base_url}/setup.php", timeout=15, verify=False,
                    proxies=proxies, headers=SKIP, allow_redirects=True)
    tok = _dvwa_token(r.text)
    session.post(f"{base_url}/setup.php", timeout=45, verify=False,
                 proxies=proxies, headers=SKIP, allow_redirects=True,
                 data={"create_db": "Create / Reset Database", "user_token": tok})
    _DVWA_DB_READY = True
    if verbose:
        print("    [dvwa] create_db done (once per run)", file=sys.stderr)


def login_dvwa(session, base_url, proxies, verbose=False):
    """DVWA: ensure DB exists, grab a fresh CSRF user_token, log in, set
    security=low, then verify the session is really authenticated."""
    host = urlparse(base_url).hostname or ""
    session.cookies.set("security", "low", domain=host, path="/")
    try:
        _ensure_dvwa_db(session, base_url, proxies, verbose)
        r = session.get(f"{base_url}/login.php", timeout=15, verify=False,
                        proxies=proxies, headers=SKIP, allow_redirects=True)
        tok = _dvwa_token(r.text)
        lr = session.post(
            f"{base_url}/login.php",
            data={"username": "admin", "password": "password",
                  "Login": "Login", "user_token": tok},
            timeout=15, verify=False, proxies=proxies, headers=SKIP,
            allow_redirects=True,
        )
        # authenticated sessions keep /index.php at 200 and do NOT redirect to login
        chk = session.get(f"{base_url}/index.php", timeout=15, verify=False,
                          proxies=proxies, headers=SKIP, allow_redirects=False)
        ok = chk.status_code == 200 and "login.php" not in chk.headers.get("Location", "")
        if verbose:
            print(f"    [dvwa] token={'yes' if tok else 'NO'} "
                  f"login_post={lr.status_code} index={chk.status_code} auth_ok={ok}",
                  file=sys.stderr)
        if not ok:
            print("    [dvwa] WARNING: not authenticated - attacks will 302 to login.php",
                  file=sys.stderr)
    except Exception as e:
        print(f"    [dvwa login skipped] {e}", file=sys.stderr)


def login_webgoat(session, base_url, proxies, verbose=False):
    """Register (idempotent, REQUIRES agree=agree) then log in to WebGoat.

    NOTE: auth here is best-effort. Even when login succeeds, the lesson
    ENDPOINTS in attack_scenarios.py must match your WebGoat build's real
    routes/params or requests still 404/400 (see --probe output). Discover the
    real routes from the running lesson's Network tab before a full re-run."""
    try:
        session.post(
            f"{base_url}/register.mvc",
            data={"username": "benign-user", "password": "Benign123!",
                  "matchingPassword": "Benign123!", "agree": "agree"},
            timeout=15, verify=False, proxies=proxies, headers=SKIP,
        )
        lr = session.post(
            f"{base_url}/login",
            data={"username": "benign-user", "password": "Benign123!"},
            timeout=15, verify=False, proxies=proxies, headers=SKIP,
        )
        if verbose:
            print(f"    [webgoat] login_post={lr.status_code}", file=sys.stderr)
    except Exception as e:
        print(f"    [webgoat login skipped] {e}", file=sys.stderr)


def login_bwapp(session, base_url, proxies, verbose=False):
    """bWAPP: default creds bee/bug, no CSRF token on login (unlike DVWA).
    Also sets security_level=0 (low) so the bug pages behave predictably -
    matches the "low" level already set manually in the UI, made explicit
    here so a freshly-recreated container doesn't silently default elsewhere.
    Best-effort, same caveat as login_webgoat: verify real routes/params via
    --probe before a full run."""
    try:
        lr = session.post(
            f"{base_url}/login.php",
            data={"login": "bee", "password": "bug", "security_level": "0", "form": "submit"},
            timeout=15, verify=False, proxies=proxies, headers=SKIP,
        )
        session.post(
            f"{base_url}/security_level.php",
            data={"security_level": "0", "form": "submit"},
            timeout=15, verify=False, proxies=proxies, headers=SKIP,
        )
        if verbose:
            print(f"    [bwapp] login_post={lr.status_code}", file=sys.stderr)
    except Exception as e:
        print(f"    [bwapp login skipped] {e}", file=sys.stderr)


def do_login(session, app, base_url, proxies, verbose=False):
    if app == "dvwa":
        login_dvwa(session, base_url, proxies, verbose)
    elif app == "webgoat":
        login_webgoat(session, base_url, proxies, verbose)
    elif app == "bwapp":
        login_bwapp(session, base_url, proxies, verbose)
    # juice_shop search is public; SSTI /profile runs best-effort as guest.


# ------------------------- send one attack step -------------------------
def send_step(session, base_url, step, headers, proxies, dry_run) -> bool:
    url = base_url + step.path
    params = dict(step.extra_params)
    data = None
    hdrs = dict(headers)
    cookies = None
    method = step.method

    if step.vector == "query":
        params[step.param] = step.payload
    elif step.vector == "body":
        data = {step.param: step.payload}
        if method == "GET":
            method = "POST"
    elif step.vector == "header":
        hdrs["User-Agent"] = step.payload   # header injection point
        if step.param:                       # some endpoints (e.g. bwapp's
            params[step.param] = "test"      # xss_user_agent.php) have no
                                              # form param at all - payload-
                                              # only-in-header, nothing to fill
    elif step.vector == "cookie":
        cookies = {"inj": step.payload}      # cookie injection point
        params[step.param] = "test"

    if dry_run:
        loc = {"query": f"?{step.param}=<payload>", "body": "[body]",
               "header": "[User-Agent]", "cookie": "[cookie inj]"}[step.vector]
        print(f"    [{step.attack_type}/{step.variant_type}] {method} "
              f"{step.path} {loc}  payload={step.payload[:70]!r}")
        return True

    try:
        session.request(method, url, params=params, data=data, headers=hdrs,
                        cookies=cookies, proxies=proxies, timeout=20,
                        allow_redirects=False, verify=False)
        return True
    except Exception as e:
        print(f"    [skip] {method} {step.path} -> {e}", file=sys.stderr)
        return False


def run_persona_attack(persona, app, base_url, attack_types, proxies,
                       sessions, dry_run, rng, jitter_pct=25.0,
                       session_pause_ms=0):
    for attack_type in attack_types:
        if not endpoint_for(app, attack_type):
            continue
        for s in range(sessions):
            session_id = str(uuid.uuid4())
            sess = requests.Session()
            if not dry_run:
                do_login(sess, app, base_url, proxies)
            steps = build_attack_steps(persona, app, attack_type, rng)
            if not steps:
                continue
            rp = persona.rate_policy
            print(f"  - persona={persona.persona_id} attack={attack_type} "
                  f"session {s + 1}/{sessions} steps={len(steps)} "
                  f"delay={rp.min_delay_ms}-{rp.max_delay_ms}ms +/-{jitter_pct:.0f}%")
            for step in steps:
                headers = capture_headers(app, attack_type, session_id, persona, step)
                send_step(sess, base_url, step, headers, proxies, dry_run)
                if not dry_run:
                    time.sleep(rate_delay_s(persona, jitter_pct))
            sess.close()
            if not dry_run and session_pause_ms and s < sessions - 1:
                time.sleep(session_pause_ms / 1000.0)


def _attack_types_for(app_cfg, only_attack=None):
    train_attacks = list(app_cfg.get("attacks", []))
    heldout = ["code_injection"] if app_cfg.get("code_injection") else []
    attack_types = train_attacks + heldout
    if only_attack:
        attack_types = [a for a in attack_types if a == only_attack]
    return attack_types


def run_probe(apps, proxies, only_attack=None):
    """Log in per app and fire ONE canary request per (app, attack, endpoint
    VARIANT) - when an (app, attack_type) has multiple real endpoint variants
    (e.g. bwapp's sqli has 6), every one of them is probed individually, not
    just one representative. Prints the real status code so you can confirm
    200s (auth OK, endpoint OK) BEFORE a full run. Uses X-Capture-Skip so
    nothing lands in data/raw_attack."""
    print("[probe] logging in + one canary request per (app, attack, variant) "
          "(X-Capture-Skip -> not captured)")
    canary = {"sqli": "1' OR '1'='1", "xss": "<script>1</script>",
              "command_injection": "; id", "code_injection": "#{7*7}"}
    for app_name, app_cfg in apps.items():
        base_url = app_cfg["base_url"]
        attack_types = _attack_types_for(app_cfg, only_attack)
        print(f"\n[+] {app_name} -> {base_url}")
        sess = requests.Session()
        do_login(sess, app_name, base_url, proxies, verbose=True)
        for at in attack_types:
            specs = endpoint_for(app_name, at)
            for spec in specs:
                params = dict(spec.get("extra", {}))
                data = None
                hdrs = dict(SKIP)
                method = spec["method"]
                payload = canary.get(at, "canary123")
                if spec.get("force_vector") == "header":
                    hdrs["User-Agent"] = payload
                elif method == "GET":
                    params[spec["param"]] = payload
                else:
                    data = {spec["param"]: payload}
                try:
                    r = sess.request(method, base_url + spec["path"], params=params,
                                     data=data, proxies=proxies, timeout=20,
                                     allow_redirects=False, verify=False, headers=hdrs)
                    flag = "OK" if r.status_code < 400 and r.status_code != 302 else "<-- FAIL"
                    print(f"    {at:16} {method:4} {spec['path']:32} -> {r.status_code} {flag}")
                except Exception as e:
                    print(f"    {at:16} {method:4} {spec['path']:32} -> ERROR {e}")
        sess.close()
    print("\n[probe] done. Want: 200 (or 500 for juice sqli/ssti = injection landed). "
          "302=auth broken, 404=wrong path, 400=wrong method/params.")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--only-app", default=None, help="dvwa|webgoat|juice_shop")
    ap.add_argument("--only-attack", default=None,
                    help="sqli|xss|path_traversal|code_injection")
    ap.add_argument("--only-persona", default=None)
    ap.add_argument("--sessions-per-persona", type=int, default=1)
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--dry-run", action="store_true",
                    help="print planned requests, send nothing")
    ap.add_argument("--probe", action="store_true",
                    help="login + one canary request per (app, attack), print status, exit")
    ap.add_argument("--jitter-pct", type=float, default=25.0,
                    help="random variance on think-time delays (benign-style). 0 disables")
    ap.add_argument("--session-pause-ms", type=int, default=0,
                    help="extra pause between sessions, in milliseconds")
    args = ap.parse_args()

    rng = random.Random(args.seed)
    if args.seed is not None:
        random.seed(args.seed)

    with open(args.config, encoding="utf-8") as f:
        cfg = yaml.safe_load(f)

    proxy_url = cfg["proxy_attack"]
    proxies = {"http": proxy_url, "https": proxy_url}

    apps = cfg["apps"]
    if args.only_app:
        apps = {args.only_app: apps[args.only_app]}

    personas = list(ATTACKER_PERSONAS.values())
    if args.only_persona:
        personas = [ATTACKER_PERSONAS[args.only_persona]]

    try:
        import urllib3
        urllib3.disable_warnings()
    except Exception:
        pass

    if args.probe:
        run_probe(apps, proxies, args.only_attack)
        return

    for app_name, app_cfg in apps.items():
        base_url = app_cfg["base_url"]
        attack_types = _attack_types_for(app_cfg, args.only_attack)
        if not attack_types:
            continue
        print(f"[+] {app_name} -> {base_url}  attacks={attack_types}")
        for persona in personas:
            run_persona_attack(persona, app_name, base_url, attack_types,
                               proxies, args.sessions_per_persona, args.dry_run,
                               rng, args.jitter_pct, args.session_pause_ms)

    print("[done] dry-run complete (no traffic sent)" if args.dry_run
          else "[done] attack collection finished -> data/raw_attack/*_raw.jsonl")


if __name__ == "__main__":
    main()
