#!/usr/bin/env python3
"""
show_failing.py - explain WHY records fail the payload-signature check.
=======================================================================
For every record whose labelled attack payload is NOT found in any captured
field, this prints:
  * a breakdown of failures by (app, class, VECTOR)  <-- the key diagnostic
  * a few full example records (all payload fields + raw_request)

VECTOR is read from metadata.scenario_id (e.g. 'sqli:exploit:header' -> header).
If failures cluster on header/cookie/body vectors, the payload is being injected
somewhere the capture is NOT storing -> a capture-completeness bug.
If failures are on the 'query' vector with exotic payloads, the TEST signature
list is simply too narrow (valid attacks) and we widen it.

usage:
  python tools/show_failing.py
  python tools/show_failing.py --raw data/raw_attack --examples 3
"""

import argparse
import glob
import json
import os
import urllib.parse
from collections import Counter

# must mirror tests/test_attacks.py
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


def decode_lower(s):
    if not s:
        return ""
    out = str(s)
    for _ in range(2):
        try:
            out = urllib.parse.unquote_plus(out)
        except Exception:
            break
    return out.lower()


def haystack(content):
    parts = [content.get("url_path", ""), content.get("query_string", ""),
             content.get("request_body", "") or "",
             content.get("decoded_payload", "") or "",
             content.get("raw_request", "") or ""]
    return decode_lower(" ".join(str(p) for p in parts))


def vector_of(md):
    sid = md.get("scenario_id") or ""
    parts = str(sid).split(":")
    return parts[-1] if len(parts) >= 2 else "unknown"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw", nargs="+", default=["data/raw_attack"])
    ap.add_argument("--examples", type=int, default=2,
                    help="full example records to print per (app,class,vector)")
    args = ap.parse_args()

    files = []
    for d in args.raw:
        files.extend(sorted(glob.glob(os.path.join(d, "*_raw.jsonl"))))

    fail_by_group = Counter()
    total_by_group = Counter()
    examples = {}

    for f in files:
        with open(f, encoding="utf-8") as fh:
            for ln, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line)
                except json.JSONDecodeError:
                    continue
                md = r.get("metadata", {})
                lab = r.get("label", {})
                content = r.get("content", {})
                app, klass = md.get("app"), lab.get("class")
                if not app or not klass:
                    continue
                vec = vector_of(md)
                total_by_group[(app, klass, vec)] += 1
                sig = SIGNATURES.get(klass, [])
                if sig and not any(s in haystack(content) for s in sig):
                    key = (app, klass, vec)
                    fail_by_group[key] += 1
                    examples.setdefault(key, [])
                    if len(examples[key]) < args.examples:
                        examples[key].append((os.path.basename(f), ln, content, md))

    print("=" * 66)
    print("FAILING-SIGNATURE BREAKDOWN  by (app, class, VECTOR)")
    print("=" * 66)
    print(f"{'app':12s} {'class':15s} {'vector':10s} {'fail':>6s} {'total':>6s}")
    for key in sorted(total_by_group):
        fails = fail_by_group.get(key, 0)
        if fails:
            app, klass, vec = key
            print(f"{app:12s} {klass:15s} {vec:10s} "
                  f"{fails:6d} {total_by_group[key]:6d}")
    print("\n(if 'fail' == 'total' for a vector -> that whole vector is the "
          "cause; if failures are only on query -> widen test signatures)")

    print("\n" + "=" * 66)
    print("EXAMPLE FAILING RECORDS")
    print("=" * 66)
    for key in sorted(examples):
        app, klass, vec = key
        print(f"\n### {app} / {klass} / vector={vec}")
        for fname, ln, content, md in examples[key]:
            print(f"  {fname}:{ln}  scenario_id={md.get('scenario_id')!r}")
            print(f"    url_path      = {content.get('url_path')!r}")
            print(f"    query_string  = {content.get('query_string')!r}")
            print(f"    request_body  = {content.get('request_body')!r}")
            print(f"    decoded_payload = {content.get('decoded_payload')!r}")
            raw = str(content.get('raw_request') or '')
            print(f"    raw_request[:300] = {raw[:300]!r}")


if __name__ == "__main__":
    main()
