#!/usr/bin/env python3
"""
fix_decoded_payload.py - repair the duplicated-query decoded_payload in already
collected *_raw.jsonl, so you don't have to re-collect benign traffic.

Root cause: mitmproxy req.path already contains the query string, and the addon
appended '?' + query_string again -> '/p?q=1?q=1'. This rebuilds decoded_payload
from the clean content.url_path + content.query_string (same logic as the fixed
addon: double urllib.unquote).

Makes a .bak copy of every file it touches. Idempotent (safe to re-run).

usage:
  python tools/fix_decoded_payload.py --raw data/raw data/raw_attack
  python tools/fix_decoded_payload.py --raw data/raw_attack --dry-run
"""

import argparse
import glob
import json
import os
import shutil
import urllib.parse


def rebuild(url_path, query_string):
    base = (url_path or "").split("?")[0]
    full = base + (("?" + query_string) if query_string else "")
    return urllib.parse.unquote(urllib.parse.unquote(full))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw", nargs="+", default=["data/raw", "data/raw_attack"])
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    files = []
    for d in args.raw:
        files.extend(sorted(glob.glob(os.path.join(d, "*_raw.jsonl"))))
    if not files:
        print(f"no *_raw.jsonl under {args.raw}")
        return

    grand_changed = grand_total = 0
    for f in files:
        out_lines = []
        changed = total = 0
        with open(f, encoding="utf-8") as fh:
            for line in fh:
                s = line.strip()
                if not s:
                    out_lines.append(line)
                    continue
                try:
                    r = json.loads(s)
                except json.JSONDecodeError:
                    out_lines.append(line)
                    continue
                total += 1
                c = r.get("content", {})
                new_dp = rebuild(c.get("url_path", ""), c.get("query_string", ""))
                if c.get("decoded_payload") != new_dp:
                    c["decoded_payload"] = new_dp
                    r["content"] = c
                    changed += 1
                out_lines.append(json.dumps(r, ensure_ascii=False) + "\n")
        grand_changed += changed
        grand_total += total
        print(f"{os.path.basename(f):28s} {changed:5d} / {total:5d} fixed")
        if changed and not args.dry_run:
            shutil.copy2(f, f + ".bak")
            with open(f, "w", encoding="utf-8") as fh:
                fh.writelines(out_lines)

    tag = " (dry-run, nothing written)" if args.dry_run else ""
    print(f"\nTOTAL: {grand_changed} / {grand_total} records fixed{tag}")
    if not args.dry_run and grand_changed:
        print("backups saved as *.jsonl.bak")


if __name__ == "__main__":
    main()
