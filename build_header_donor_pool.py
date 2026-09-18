"""
build_header_donor_pool.py - step 1 of the attack-header realism fix.

Scans data/raw/*.jsonl for BENIGN records (real Playwright-browser captures)
and extracts their header blocks, grouped by app, into a reusable donor pool.
patch_attack_headers.py (step 2) samples from this pool to replace the
minimal python-requests-library headers on scripted attack_driver.py
captures with realistic, real-browser header sets - fixing the source-
artifact shortcut found in eda_stage1_stage2.py (header_count/
header_payload_length alone achieved AUC=1.0000 separating benign/malicious).

Excludes X-Capture-* control headers (already stripped from raw_request by
the mitmproxy addon, but excluded here defensively too) and the Host header
(patch_attack_headers.py must set Host to match the ACTUAL attack target,
never the donor's).

usage:
  python3 build_header_donor_pool.py
"""
import glob
import json
import os

RAW_DIR = "data/raw"
OUT_PATH = "data/header_donor_pool.json"

# Excluded from the donor pool, not just from display:
#   "unknown" - confirmed (2026-09-11) to be Chrome's own internal telemetry
#   traffic (/domainreliability/upload), inconsistently tagged
#   source_type=scripted despite generation_mode=browser - not genuine
#   page-visit traffic, would pollute the pool with an atypical distribution.
EXCLUDED_APPS = {"unknown"}
# DVWA/Juice Shop/WebGoat's OWN benign headers (median 7-8, range 6-12) sit
# too close to the malicious range (~5-6) to work as same-app donors - see
# reports/PROGRESS_LOG.md 2026-09-11. Cross-app random sampling from the
# richer pool (facebook/pinterest/amazon/youtube/x) is used instead by
# patch_attack_headers.py, specifically BECAUSE the goal is breaking a
# statistical shortcut, not app-specific plausibility.


def split_raw(raw_request):
    head, _, _ = (raw_request or "").partition("\r\n\r\n")
    lines = head.split("\r\n")
    return lines[1:] if lines else []  # drop the request line


def parse_headers(header_lines):
    headers = []
    for line in header_lines:
        if ":" not in line:
            continue
        name, val = line.split(":", 1)
        name = name.strip()
        if name.lower().startswith("x-capture-") or name.lower() == "host":
            continue
        headers.append([name, val.strip()])
    return headers


def main():
    pool = {}  # app -> list of header-line lists (each a full donor set, minus Host/X-Capture-*)
    total_benign = 0
    for path in sorted(glob.glob(os.path.join(RAW_DIR, "*.jsonl"))):
        if path.endswith((".bak", ".pretest_noisy")):
            continue
        app_counts = {}
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if rec.get("label", {}).get("level1") != "benign":
                    continue
                app = (rec.get("metadata") or {}).get("app", "unknown")
                if app in EXCLUDED_APPS:
                    continue
                headers = parse_headers(split_raw(rec.get("content", {}).get("raw_request", "")))
                if not headers:
                    continue
                pool.setdefault(app, []).append(headers)
                app_counts[app] = app_counts.get(app, 0) + 1
                total_benign += 1
        if app_counts:
            print(f"[{os.path.basename(path)}] " +
                  ", ".join(f"{a}={n}" for a, n in app_counts.items()))

    print(f"\n[summary] {total_benign} benign header sets collected across {len(pool)} apps")
    for app, sets in sorted(pool.items(), key=lambda kv: -len(kv[1])):
        avg_len = sum(len(h) for h in sets) / len(sets)
        avg_hdr_chars = sum(sum(len(v) for _, v in h) for h in sets) / len(sets)
        print(f"  {app:16} n={len(sets):5d}  avg_header_count={avg_len:.1f}  "
              f"avg_header_payload_chars={avg_hdr_chars:.0f}")

    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(pool, f)
    print(f"\n[done] -> {OUT_PATH}")


if __name__ == "__main__":
    main()
