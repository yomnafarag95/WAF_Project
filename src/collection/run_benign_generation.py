"""
Persona-based benign traffic generator for OWASP Juice Shop.

Richer replacement for the Juice Shop portion of benign_driver.py: adds
human realism (6 personas x jitter: variable delays, optional-step skips,
backtrack, revisit, early abandonment).

CRITICAL: routes through the SAME mitmproxy capture proxy as
benign_driver.py (WebGoat/DVWA) and run_attacks.sh, and tags every request
with X-Capture-* headers. So all traffic - benign or attack - is written
once by src/capture/capture_addon.py in the single locked schema_v2 format.

Credentials for logged-in personas are read from (in priority order):
  1. env vars JUICE_BENIGN_EMAIL / JUICE_BENIGN_PASSWORD
  2. config: apps.juice_shop.benign_login.{email,password}
If none are found, logged-in personas gracefully run as guests.

Usage (from project root, so `src` imports as a package):
  pip install -r requirements.txt && playwright install chromium
  python3 -m src.collection.run_benign_generation \
      --config config/sources.yaml --sessions-per-persona 20 --seed 42
"""

import argparse
import os
import random
import uuid
from pathlib import Path

import yaml

from src.collection.personas.configs import get_persona, list_personas
from src.collection.personas.session_runner import SessionRunner
from src.collection.personas.scenarios import build_scenario_for_persona
from src.collection.personas import juice_shop_actions as actions


# Multiple accounts - rotate per session so no single email becomes a model shortcut.
# Register ALL three on Juice Shop once (Step 0 in RUN_GUIDE).
BENIGN_ACCOUNTS = [
    ("benign_user@juice-sh.op",  "Benign123!"),
    ("test_shopper@juice-sh.op", "Benign123!"),
    ("demo_buyer@juice-sh.op",   "Benign123!"),
]


def resolve_credentials(js_cfg: dict) -> list:
    """Return list of (email, password) tuples from config/env or defaults."""
    env_email = os.getenv("JUICE_BENIGN_EMAIL")
    env_pass  = os.getenv("JUICE_BENIGN_PASSWORD")
    if env_email and env_pass:
        return [(env_email, env_pass)]
    login_cfg = js_cfg.get("benign_login", {}) or {}
    cfg_email = login_cfg.get("email")
    cfg_pass  = login_cfg.get("password")
    if cfg_email and cfg_pass:
        return BENIGN_ACCOUNTS  # use all three when config provides base creds
    return []  # no creds -> all personas run as guests


def capture_headers(session_id: str, persona) -> dict:
    """X-Capture-* headers the mitmproxy addon reads then strips."""
    return {
        "X-Capture-Source": "juice_shop",
        "X-Capture-App": "juice_shop",
        "X-Capture-Stack": "node_angular",
        "X-Capture-Type": "scripted",
        "X-Capture-Mode": "browser",
        "X-Capture-Label": "benign",
        "X-Capture-Session": session_id,
        "X-Capture-Persona": persona.persona_id,
        "X-Capture-Scenario": persona.goal.value,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Persona-based benign traffic (Juice Shop)")
    ap.add_argument("--config", required=True, help="path to config/sources.yaml")
    ap.add_argument("--sessions-per-persona", type=int, default=10)
    ap.add_argument("--only-persona", default=None, help="run a single persona id")
    ap.add_argument("--trace-dir", default="data/traces")
    ap.add_argument("--seed", type=int, default=None, help="base seed for reproducibility")
    args = ap.parse_args()

    with open(args.config, encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    proxy_server = cfg["proxy_benign"]

    js_cfg = cfg.get("apps", {}).get("juice_shop", {})
    if js_cfg.get("base_url"):
        actions.BASE_URL = js_cfg["base_url"]
    accounts = resolve_credentials(js_cfg)
    if not accounts:
        print("[warn] no Juice Shop benign credentials found -> logged-in personas will run as guests")

    Path(args.trace_dir).mkdir(parents=True, exist_ok=True)

    persona_ids = [args.only_persona] if args.only_persona else list_personas()
    total = 0
    for persona_id in persona_ids:
        persona = get_persona(persona_id)
        print(f"[+] persona={persona_id} ({persona.persona_name})")
        for i in range(args.sessions_per_persona):
            session_id = str(uuid.uuid4())
            run_id = f"run_{persona_id}_{i}"
            seed = None if args.seed is None else args.seed + i
            runner = SessionRunner(persona, session_id=session_id, run_id=run_id, seed=seed)

            # Rotate accounts per session so no single email dominates.
            _email, _password = random.choice(accounts) if accounts else (None, None)

            def step_builder(page, _persona=persona, _e=_email, _p=_password):
                return build_scenario_for_persona(_persona, page, email=_e, password=_p)

            print(f"    - session {i + 1}/{args.sessions_per_persona} (id={session_id[:8]})")
            actions.run_persona_session(
                session_runner=runner,
                scenario_id=persona.goal.value,
                scenario_name=persona.persona_name,
                step_builder=step_builder,
                device_type=persona.device.value,
                trace_output_dir=args.trace_dir,
                proxy_server=proxy_server,
                capture_headers=capture_headers(session_id, persona),
            )
            total += 1

    print(f"[done] {total} persona sessions -> captured to data/raw/juice_shop_raw.jsonl")


if __name__ == "__main__":
    main()
