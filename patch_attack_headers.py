"""
patch_attack_headers.py - step 2 of the Stage-1 source-artifact fix.

Replaces the bare python-requests header set (User-Agent, Accept-Encoding,
Accept, Connection - ~5 headers, ~23 bytes) on every attack_driver.py-captured
malicious record with a realistic, randomly-sampled REAL browser header set
(from build_header_donor_pool.py's rich-app pool: pinterest/amazon/facebook/
x/youtube - apps confirmed to have substantial, diverse real header sets,
unlike dvwa/juice_shop/webgoat's own thin benign traffic or the excluded
"unknown" Chrome-telemetry bucket). This is the fix for the shortcut found in
eda_stage1_stage2.py: header_payload_length alone achieved AUC=1.0000
separating benign/malicious, because 100% of malicious traffic in val/test
came from this one bare-header-set tool.

The attack PAYLOAD is never touched - only the header block... except that
for two of the six attacker personas, the payload IS a header:
"polyglot_specialist" (vector=HEADER) puts it in User-Agent, and
"script_kiddie_defaults" (vector=COOKIE) puts it in Cookie. Blindly replacing
every header for those records was DESTROYING the attack signal itself -
found 2026-09-17 via tests/test_attacks.py's payload-signature check failing
on 21 bwapp XSS rows, which traced to ~1,758 records project-wide (1,343
header-vector + 415 cookie-vector, ~16% of all malicious data) whose real
payload had been silently overwritten by a donor's benign User-Agent/Cookie.
Fixed by preserving the ORIGINAL User-Agent line for header-vector records
and the ORIGINAL Cookie line for cookie-vector records, while still replacing
every other header with a donor value (so the shortcut fix still applies to
the rest of the header block).

IMPORTANT: the effective vector is NOT reliably metadata.persona_id. Most
personas have a fixed default vector, but attack_scenarios.py's
force_vector (e.g. bwapp's xss_user_agent.php forces "header" regardless of
which persona lands on it - see build_attack_steps()) can override it per
step. The only field that reflects the ACTUAL per-step vector after that
override is metadata.scenario_id, formatted "{attack_type}:{goal}:{vector}" -
its last colon-separated component is used here, not the persona's own
default.

Host is always set to the record's own real target (dvwa/juice-shop/webgoat),
never the donor's, so the request stays structurally valid for its actual
application.

Reads data/raw_attack/*.jsonl, writes patched copies to
data/raw_attack_patched/*.jsonl (non-destructive - originals untouched).

usage:
  python3 patch_attack_headers.py
"""
import glob
import json
import os
import random
import re

DONOR_POOL_PATH = "data/header_donor_pool.json"
RICH_APPS = ["pinterest", "amazon", "facebook", "x", "youtube"]
IN_DIR = "data/raw_attack"
OUT_DIR = "data/raw_attack_patched"
SEED = 42

# effective vector (last component of metadata.scenario_id) -> which header
# actually carries the attack payload for that vector. These headers must
# survive the donor-header rewrite untouched, or the payload is lost.
PAYLOAD_HEADER_BY_VECTOR = {
    "header": "user-agent",
    "cookie": "cookie",
}


def effective_vector(rec):
    sid = rec.get("metadata", {}).get("scenario_id") or ""
    return sid.split(":")[-1] if sid else None


def split_raw(raw_request):
    head, sep, body = (raw_request or "").partition("\r\n\r\n")
    lines = head.split("\r\n")
    return lines[0], lines[1:], body


def get_host(header_lines):
    for line in header_lines:
        if line.lower().startswith("host:"):
            return line.split(":", 1)[1].strip()
    return None


def get_header_line(header_lines, name):
    for line in header_lines:
        if line.lower().startswith(name.lower() + ":"):
            return line
    return None


def rebuild_raw(request_line, header_lines, body):
    return "\r\n".join([request_line] + header_lines) + "\r\n\r\n" + (body or "")


def main():
    with open(DONOR_POOL_PATH, encoding="utf-8") as f:
        pool = json.load(f)

    rich_donors = []
    for app in RICH_APPS:
        rich_donors.extend(pool.get(app, []))
    print(f"[load] {len(rich_donors)} rich donor header sets from {RICH_APPS}")
    if not rich_donors:
        print("[!] empty donor pool - run build_header_donor_pool.py first")
        return 1

    rng = random.Random(SEED)
    os.makedirs(OUT_DIR, exist_ok=True)

    for path in sorted(glob.glob(os.path.join(IN_DIR, "*_raw.jsonl"))):
        if path.endswith(".bak"):
            continue
        app = os.path.basename(path).replace("_raw.jsonl", "")
        n_total, n_patched, n_preserved = 0, 0, 0
        out_path = os.path.join(OUT_DIR, os.path.basename(path))
        with open(path, encoding="utf-8") as fin, open(out_path, "w", encoding="utf-8") as fout:
            for line in fin:
                line = line.strip()
                if not line:
                    continue
                n_total += 1
                rec = json.loads(line)
                if rec.get("label", {}).get("level1") != "malicious":
                    fout.write(json.dumps(rec, ensure_ascii=False) + "\n")
                    continue

                raw = rec["content"].get("raw_request", "")
                request_line, header_lines, body = split_raw(raw)
                host = get_host(header_lines)

                vector = effective_vector(rec)
                payload_header = PAYLOAD_HEADER_BY_VECTOR.get(vector)
                preserved_line = get_header_line(header_lines, payload_header) if payload_header else None

                donor = rich_donors[rng.randrange(len(rich_donors))]
                donor_headers = [f"{n}: {v}" for n, v in donor
                                  if not (payload_header and n.lower() == payload_header)]
                new_headers = ([f"Host: {host}"] if host else [])
                if preserved_line:
                    new_headers.append(preserved_line)
                new_headers += donor_headers
                rec["content"]["raw_request"] = rebuild_raw(request_line, new_headers, body)
                fout.write(json.dumps(rec, ensure_ascii=False) + "\n")
                n_patched += 1
                if preserved_line:
                    n_preserved += 1
        print(f"[{app}] {n_total} records, {n_patched} malicious patched "
              f"({n_preserved} with a preserved payload-carrying header) -> {out_path}")

    print(f"\n[done] patched raw files -> {OUT_DIR}/")
    print("Next: rebuild the pipeline with --raw data/raw data/raw_attack_patched "
          "(NOT data/raw_attack) so extract_features/make_splits/inject_payloads "
          "see the patched headers.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
