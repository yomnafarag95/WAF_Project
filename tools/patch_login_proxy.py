#!/usr/bin/env python3
"""
patch_login_proxy.py - route the auth/login bootstrap through the SAME proxy as
the attack traffic (so it can resolve the docker-internal hostnames), while
tagging those requests with X-Capture-Skip so the mitmproxy addon never records
them (no login pollution).

Fixes: dvwa/webgoat attacks returning 302 because do_login() was called without
proxies -> the host cannot resolve `dvwa`/`webgoat` -> login silently failed.

Edits (with .bak backups, aborts cleanly if any anchor is missing):
  src/attacks/attack_driver.py   (login_dvwa, login_webgoat, do_login, call site)
  src/capture/capture_addon.py   (skip X-Capture-Skip requests)

usage:  python tools/patch_login_proxy.py
        python tools/patch_login_proxy.py --dry-run
"""
import argparse
import os
import shutil
import sys

DRIVER = os.path.join("src", "attacks", "attack_driver.py")
ADDON = os.path.join("src", "capture", "capture_addon.py")

DRIVER_EDITS = [
    # R1: login_dvwa signature
    (
        "def login_dvwa(session, base_url):",
        "def login_dvwa(session, base_url, proxies):",
    ),
    # R2: dvwa GET through proxy + skip header
    (
        '        r = session.get(f"{base_url}/login.php", timeout=15, verify=False)',
        '        r = session.get(f"{base_url}/login.php", timeout=15, verify=False,\n'
        '                        proxies=proxies, headers={"X-Capture-Skip": "1"})',
    ),
    # R3: dvwa POST through proxy + skip header
    (
        '            data={"username": "admin", "password": "password",\n'
        '                  "Login": "Login", "user_token": token},\n'
        '            timeout=15, verify=False,\n'
        '        )',
        '            data={"username": "admin", "password": "password",\n'
        '                  "Login": "Login", "user_token": token},\n'
        '            timeout=15, verify=False,\n'
        '            proxies=proxies, headers={"X-Capture-Skip": "1"},\n'
        '        )',
    ),
    # R4: replace whole login_webgoat (register + login, both through proxy)
    (
        'def login_webgoat(session, base_url):\n'
        '    try:\n'
        '        session.post(\n'
        '            f"{base_url}/login",\n'
        '            data={"username": "benign-user", "password": "Benign123!"},\n'
        '            timeout=15, verify=False,\n'
        '        )\n'
        '    except Exception as e:\n'
        '        print(f"    [webgoat login skipped] {e}", file=sys.stderr)',
        'def login_webgoat(session, base_url, proxies):\n'
        '    skip = {"X-Capture-Skip": "1"}\n'
        '    try:\n'
        '        # make sure the account exists (idempotent; harmless if already there)\n'
        '        session.post(\n'
        '            f"{base_url}/register.mvc",\n'
        '            data={"username": "benign-user", "password": "Benign123!",\n'
        '                  "matchingPassword": "Benign123!", "agree": "agree"},\n'
        '            timeout=15, verify=False, proxies=proxies, headers=skip,\n'
        '        )\n'
        '        session.post(\n'
        '            f"{base_url}/login",\n'
        '            data={"username": "benign-user", "password": "Benign123!"},\n'
        '            timeout=15, verify=False, proxies=proxies, headers=skip,\n'
        '        )\n'
        '    except Exception as e:\n'
        '        print(f"    [webgoat login skipped] {e}", file=sys.stderr)',
    ),
    # R5: do_login signature + inner calls
    (
        "def do_login(session, app, base_url):\n"
        '    if app == "dvwa":\n'
        "        login_dvwa(session, base_url)\n"
        '    elif app == "webgoat":\n'
        "        login_webgoat(session, base_url)",
        "def do_login(session, app, base_url, proxies):\n"
        '    if app == "dvwa":\n'
        "        login_dvwa(session, base_url, proxies)\n"
        '    elif app == "webgoat":\n'
        "        login_webgoat(session, base_url, proxies)",
    ),
    # R6: call site inside run_persona_attack
    (
        "                do_login(sess, app, base_url)",
        "                do_login(sess, app, base_url, proxies)",
    ),
]

ADDON_EDITS = [
    (
        "    if _is_static_asset(flow.request.path):\n"
        "        return\n"
        "\n"
        "    h = flow.request.headers",
        "    if _is_static_asset(flow.request.path):\n"
        "        return\n"
        "\n"
        "    # skip login/bootstrap requests (carry X-Capture-Skip; never recorded)\n"
        '    if "X-Capture-Skip" in flow.request.headers:\n'
        '        del flow.request.headers["X-Capture-Skip"]\n'
        "        return\n"
        "\n"
        "    h = flow.request.headers",
    ),
]


def patch_file(path, edits, dry_run):
    if not os.path.exists(path):
        print(f"[MISS] file not found: {path}")
        return False
    src = open(path, encoding="utf-8").read()
    out = src
    ok = True
    for i, (old, new) in enumerate(edits, 1):
        n = out.count(old)
        if n != 1:
            print(f"[MISS] {os.path.basename(path)} edit #{i}: anchor found {n} times (want 1)")
            ok = False
            continue
        out = out.replace(old, new, 1)
        print(f"[ ok ] {os.path.basename(path)} edit #{i}")
    if not ok:
        print(f"  -> {path} NOT written (fix anchors first)")
        return False
    if out == src:
        print(f"  -> {path} already patched (no change)")
        return True
    if not dry_run:
        shutil.copy2(path, path + ".bak")
        open(path, "w", encoding="utf-8").write(out)
        print(f"  -> {path} written (backup {os.path.basename(path)}.bak)")
    else:
        print(f"  -> {path} would be written (dry-run)")
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    a = patch_file(DRIVER, DRIVER_EDITS, args.dry_run)
    b = patch_file(ADDON, ADDON_EDITS, args.dry_run)
    if a and b:
        print("\nALL PATCHES APPLIED. next: --force-recreate mitmproxy-attack, then re-collect.")
    else:
        print("\nSOME ANCHORS DID NOT MATCH - nothing half-written. paste me the failing function.")
        sys.exit(1)


if __name__ == "__main__":
    main()
