#!/usr/bin/env python3
"""
daily_qa_check.py

Run this ONCE PER DAY, per site file, right after you finish browsing.
It tells you if today's captured data is well-tagged, sufficiently unique,
and not dominated by a handful of repeated noise/telemetry endpoints.

Usage:
    python daily_qa_check.py data/raw/<yoursite>_raw.jsonl

Then copy the ENTIRE printed report and send it to Yomna.
"""

import sys
import json
import hashlib
import collections
from pathlib import Path


def get(record, *key_paths, default=None):
    """Try several dotted key paths (e.g. "content.url_path") against a
    record, checking both top-level and nested locations. Returns the first
    match found, or `default` if none match. This makes the checker robust
    even if the exact JSON shape changes slightly between capture versions.
    """
    for key_path in key_paths:
        node = record
        found = True
        for part in key_path.split("."):
            if isinstance(node, dict) and part in node:
                node = node[part]
            else:
                found = False
                break
        if found:
            return node
    return default


def record_signature(record):
    """Build a stable fingerprint for duplicate detection based on the
    method + path + query + body, ignoring things like timestamps or
    headers that naturally differ between otherwise-identical requests."""
    method = get(record, "content.http_method", "method", default="")
    path = get(record, "content.url_path", "url_path", "path", default="")
    query = get(record, "content.query_string", "query", default="")
    body = get(record, "content.request_body", "body", default="")
    raw = f"{method}|{path}|{query}|{body}"
    return hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()


def main():
    if len(sys.argv) < 2:
        print("Usage: python daily_qa_check.py <path-to-jsonl-file>")
        sys.exit(1)

    file_path = Path(sys.argv[1])
    if not file_path.exists():
        print(f"File not found: {file_path}")
        sys.exit(1)

    total = 0
    bad_json = 0
    signatures = collections.Counter()
    app_tags = collections.Counter()
    source_type_tags = collections.Counter()
    path_counts = collections.Counter()
    missing_core_fields = 0

    with file_path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            total += 1
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                bad_json += 1
                continue

            app = get(record, "app", "metadata.app", default="MISSING")
            source_type = get(record, "source_type", "metadata.source_type", default="MISSING")
            path = get(record, "content.url_path", "url_path", "path", default="MISSING")

            app_tags[app] += 1
            source_type_tags[source_type] += 1
            path_counts[path] += 1
            signatures[record_signature(record)] += 1

            if app == "MISSING" or source_type == "MISSING" or path == "MISSING":
                missing_core_fields += 1

    unique_count = len(signatures)
    duplicate_count = total - unique_count
    duplicate_rate = (duplicate_count / total * 100) if total else 0

    print("=" * 64)
    print(f"DAILY QA REPORT: {file_path.name}")
    print("=" * 64)
    print(f"Total records:              {total}")
    print(f"Unreadable lines:           {bad_json}")
    print(f"Unique records:             {unique_count}")
    print(f"Duplicate records:          {duplicate_count} ({duplicate_rate:.1f}%)")
    print(f"Records missing a core tag: {missing_core_fields}")
    print()
    print("App tag breakdown:", dict(app_tags))
    print("Source-type breakdown:", dict(source_type_tags))
    print()
    print("Top 15 paths by frequency:")
    for path, count in path_counts.most_common(15):
        pct = count / total * 100 if total else 0
        flag = "  <-- possible noise (>25% of all traffic)" if pct > 25 else ""
        print(f"  {count:5d}  ({pct:4.1f}%)  {path}{flag}")

    print()
    print("-" * 64)
    checks_passed = True

    if total == 0:
        print("[FAIL] File is empty -- capture may not be running.")
        checks_passed = False

    if bad_json > 0:
        print(f"[FAIL] {bad_json} unreadable line(s) -- capture may be corrupted.")
        checks_passed = False

    if missing_core_fields > 0:
        print(
            f"[FAIL] {missing_core_fields} record(s) missing app/source_type/path -- "
            f"you may be running an outdated capture_addon.py. Re-check Section 2 "
            f"of the team guide."
        )
        checks_passed = False

    if duplicate_rate > 10:
        print(
            f"[WARN] Duplicate rate is {duplicate_rate:.1f}% (over the 10% threshold) -- "
            f"try varying your search terms, pages, and actions more tomorrow."
        )
        checks_passed = False

    if path_counts:
        top_path, top_count = path_counts.most_common(1)[0]
        top_pct = (top_count / total * 100) if total else 0
        if top_pct > 30:
            print(
                f"[WARN] '{top_path}' makes up {top_pct:.1f}% of all traffic -- "
                f"this is likely a background/telemetry endpoint, not real browsing. "
                f"Send this report to Yomna so a filter can be added."
            )
            checks_passed = False

    if checks_passed:
        print("[PASS] Data looks unique, well-tagged, and free of dominant noise paths.")

    print("=" * 64)
    print("Copy this ENTIRE report and send it to Yomna at the end of each day.")


if __name__ == "__main__":
    main()
