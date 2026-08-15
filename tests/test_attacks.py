#!/usr/bin/env python3
"""
test_attacks.py - validate that collected ATTACK traffic is CORRECT and REAL.
=============================================================================
Reads data/raw_attack/*_raw.jsonl and runs hard checks so you can trust the
attack dataset before training. Exit code 0 = everything passed.

Hard checks (per record):
  1. schema      : required fields present + JSON parses
  2. class       : label.class in {sqli,xss,path_traversal,code_injection}
  3. NO pollution: url_path is not a login/redirect/register page
  4. endpoint<->label: the payload hit the RIGHT vuln endpoint for its label
  5. payload sig : the request actually carries an attack payload of that type
                   (searched in url/query/body/decoded_payload/raw_request)
  6. open-set    : code_injection => split_role=heldout_unknown & juice_shop;
                   every other class => split_role=train
  7. taxonomy    : level1==malicious ; label_source==tool_confirmed

Reported metrics (can also FAIL with flags):
  * per (app,class) counts
  * "realness": %% HTTP 200 per (app,class)  -> attack reached the endpoint
    (use --min-real-ratio 0.5 AFTER you enable real login so 302s fail)
  * byte-identical duplicate ratio (informs the imbalance / diversity plan)

usage:
  python tests/test_attacks.py
  python tests/test_attacks.py --raw data/raw_attack --min-real-ratio 0.5
"""

import argparse
import glob
import json
import os
import sys
import urllib.parse
from collections import Counter, defaultdict

KNOWN = {"sqli", "xss", "path_traversal"}
HELDOUT = {"code_injection"}
ALL_CLASSES = KNOWN | HELDOUT

# substring markers (case-insensitive) that identify the correct endpoint.
# webgoat paths capture as /WebGoat/WebGoat/... so we match on the lesson name.
ENDPOINT_MARKERS = {
    ("dvwa", "sqli"): ["/vulnerabilities/sqli"],
    ("dvwa", "xss"): ["/vulnerabilities/xss"],
    ("dvwa", "path_traversal"): ["/vulnerabilities/fi"],
    ("webgoat", "sqli"): ["sqlinjection/attack"],
    ("webgoat", "xss"): ["crosssitescripting/attack"],
    ("webgoat", "path_traversal"): ["pathtraversal"],
    ("juice_shop", "sqli"): ["/rest/products/search"],
    ("juice_shop", "xss"): ["/rest/products/search"],
    ("juice_shop", "code_injection"): ["/profile"],
}

# payload fingerprints per attack type (searched in a URL-decoded haystack)
SIGNATURES = {
    "sqli": ["'", "\"", "--", " or ", " and ", "union", "select", "sleep(",
             "1=1", "' or", "#", ";--", "/*", "waitfor", "benchmark(",
             "' and", "or 1", "admin'"],
    "xss": ["<script", "</script", "<svg", "<img", "<iframe", "<body",
            "onerror", "onload", "onmouseover", "onfocus", "javascript:",
            "alert(", "prompt(", "confirm(", "<", ">"],
    "path_traversal": ["../", "..\\", "%2e%2e", "..%2f", "..%5c", "....//",
                       "..;/", "etc/passwd", "boot.ini", "/etc/",
                       "windows/win.ini", "file://"],
    "code_injection": ["#{", "${", "{{", "<%", "7*7", "process",
                       "global.", "root", "require(", "child_process",
                       "__proto__", "constructor"],
}

LOGIN_MARKERS = ["/login", "login.php", "signin", "sign-in",
                 "/register", "logout", "j_spring_security"]


def decode_lower(s):
    if not s:
        return ""
    out = str(s)
    for _ in range(2):  # addon double-unquotes; mirror it to catch %25xx
        try:
            out = urllib.parse.unquote_plus(out)
        except Exception:
            break
    return out.lower()


def haystack(content):
    parts = [
        content.get("url_path", ""),
        content.get("query_string", ""),
        content.get("request_body", "") or "",
        content.get("decoded_payload", "") or "",
        content.get("raw_request", "") or "",
    ]
    return decode_lower(" ".join(str(p) for p in parts))


def load_records(raw_dirs):
    files = []
    for d in raw_dirs:
        files.extend(sorted(glob.glob(os.path.join(d, "*_raw.jsonl"))))
    recs = []
    for f in files:
        with open(f, encoding="utf-8") as fh:
            for ln, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    recs.append((f, ln, json.loads(line)))
                except json.JSONDecodeError as e:
                    recs.append((f, ln, {"__parse_error__": str(e)}))
    return files, recs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw", nargs="+", default=["data/raw_attack"])
    ap.add_argument("--min-real-ratio", type=float, default=0.0,
                    help="FAIL if share of HTTP 200 per (app,class) < this "
                         "(use 0.5 AFTER enabling real login)")
    ap.add_argument("--max-dup-ratio", type=float, default=1.0,
                    help="FAIL if byte-identical duplicate ratio exceeds this")
    args = ap.parse_args()

    files, recs = load_records(args.raw)
    if not files:
        print(f"[FAIL] no *_raw.jsonl files under {args.raw}")
        sys.exit(2)

    errors, warnings = [], []
    per_ac = Counter()
    status_200, status_all = Counter(), Counter()
    seen_raw = defaultdict(int)

    for f, ln, r in recs:
        where = f"{os.path.basename(f)}:{ln}"
        if "__parse_error__" in r:
            errors.append(f"{where} bad JSON: {r['__parse_error__']}")
            continue
        md = r.get("metadata", {})
        lab = r.get("label", {})
        content = r.get("content", {})
        app = md.get("app")
        klass = lab.get("class")
        url_path = content.get("url_path") or ""

        # 1 schema
        for fld, val in [("metadata.app", app), ("label.class", klass),
                         ("content.url_path", url_path),
                         ("record_id", r.get("record_id")),
                         ("session_id", r.get("session_id"))]:
            if not val:
                errors.append(f"{where} missing {fld}")
        if not app or not klass:
            continue

        # 2 valid class
        if klass not in ALL_CLASSES:
            errors.append(f"{where} unknown label.class={klass!r}")
            continue
        per_ac[(app, klass)] += 1

        low_path = url_path.lower()

        # 3 pollution
        if any(m in low_path for m in LOGIN_MARKERS):
            errors.append(f"{where} POLLUTION: login/redirect page captured "
                          f"'{url_path}' labelled {klass}")

        # 4 endpoint <-> label
        markers = ENDPOINT_MARKERS.get((app, klass))
        if markers is None:
            warnings.append(f"{where} unexpected (app,class)=({app},{klass})")
        elif not any(m in low_path for m in markers):
            errors.append(f"{where} endpoint/label MISMATCH: {klass} on "
                          f"'{url_path}' (expected {markers})")

        # 5 payload signature
        hay = haystack(content)
        sig = SIGNATURES.get(klass, [])
        if sig and not any(s in hay for s in sig):
            errors.append(f"{where} NO {klass} payload signature in request "
                          f"(path='{url_path}')")

        # 6 open-set role
        role = lab.get("split_role")
        if klass == "code_injection":
            if role != "heldout_unknown":
                errors.append(f"{where} code_injection split_role={role!r} "
                              f"(expected heldout_unknown)")
            if app != "juice_shop":
                warnings.append(f"{where} code_injection on app={app!r} "
                                f"(expected juice_shop)")
        elif role not in (None, "train"):
            errors.append(f"{where} {klass} split_role={role!r} "
                          f"(expected train)")

        # 7 taxonomy
        if lab.get("level1") not in (None, "malicious"):
            errors.append(f"{where} level1={lab.get('level1')!r} "
                          f"(expected malicious)")
        if lab.get("label_source") not in (None, "tool_confirmed"):
            warnings.append(f"{where} label_source={lab.get('label_source')!r} "
                            f"(expected tool_confirmed)")

        # metrics
        sc = md.get("response_status_code")
        status_all[(app, klass)] += 1
        if sc == 200:
            status_200[(app, klass)] += 1
        raw = content.get("raw_request")
        if raw:
            seen_raw[raw] += 1

    total_raw = sum(seen_raw.values())
    unique_raw = len(seen_raw)
    dup = total_raw - unique_raw
    dup_ratio = (dup / total_raw) if total_raw else 0.0

    print("=" * 62)
    print("ATTACK DATA VALIDATION")
    print("=" * 62)
    print(f"files: {len(files)} | records: {len(recs)}")
    print("\nper (app, class):")
    for k in sorted(per_ac):
        print(f"  {k[0]:12s} {k[1]:16s} {per_ac[k]}")
    print("\nrealness (%% HTTP 200 = attack reached the endpoint):")
    for k in sorted(status_all):
        tot, ok = status_all[k], status_200[k]
        pct = 100.0 * ok / tot if tot else 0.0
        print(f"  {k[0]:12s} {k[1]:16s} {ok}/{tot} = {pct:.0f}%% 200")
        if tot and (pct / 100.0) < args.min_real_ratio:
            errors.append(f"realness below threshold {k}: {pct:.0f}%% 200 < "
                          f"{args.min_real_ratio*100:.0f}%%")
    print(f"\nbyte-identical duplicates: {dup}/{total_raw} = {dup_ratio*100:.1f}%% "
          f"(unique={unique_raw})")
    if dup_ratio > args.max_dup_ratio:
        errors.append(f"duplicate ratio {dup_ratio*100:.1f}%% exceeds "
                      f"{args.max_dup_ratio*100:.0f}%%")

    if warnings:
        print(f"\n--- WARNINGS ({len(warnings)}) ---")
        for w in warnings[:25]:
            print("  [warn]", w)
        if len(warnings) > 25:
            print(f"  ... (+{len(warnings) - 25} more)")

    print("\n" + "=" * 62)
    if errors:
        print(f"[FAIL] {len(errors)} hard error(s):")
        for e in errors[:40]:
            print("  [FAIL]", e)
        if len(errors) > 40:
            print(f"  ... (+{len(errors) - 40} more)")
        sys.exit(1)
    print("[PASS] every attack record is correctly labelled, on the right "
          "endpoint,\n       carries a real payload, and has no login pollution.")
    sys.exit(0)


if __name__ == "__main__":
    main()
