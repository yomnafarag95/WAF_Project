#!/usr/bin/env python3
"""
merge_and_dedup.py

Merges everyone's uploaded raw-capture files into your main data/raw/ files,
and dedups on the `raw_request` field so re-running this safely handles new
uploads without creating duplicate records.

Usage:
    python merge_and_dedup.py <incoming_folder> <data_raw_folder>

Example:
    python merge_and_dedup.py ~/Downloads/team_uploads data/raw

Expects incoming files named like:
    facebook_nour_2026-09-01.jsonl
    amazon_alaa_2026-09-01.jsonl
    x_yasmeen_2026-09-01.jsonl

(the part before the first underscore is used as the site name)
"""
import sys
import os
import glob
import json
import collections
import shutil


def main():
    if len(sys.argv) != 3:
        print("Usage: python merge_and_dedup.py <incoming_folder> <data_raw_folder>")
        sys.exit(1)

    incoming_dir = sys.argv[1]
    raw_dir = sys.argv[2]

    incoming_files = glob.glob(os.path.join(incoming_dir, "*.jsonl"))
    if not incoming_files:
        print(f"No .jsonl files found in {incoming_dir}")
        return

    by_site = collections.defaultdict(list)
    for path in incoming_files:
        name = os.path.basename(path)
        site = name.split("_")[0].lower()
        by_site[site].append(path)

    print(f"Found {len(incoming_files)} incoming file(s) across {len(by_site)} site(s): {', '.join(sorted(by_site))}\n")

    for site, files in sorted(by_site.items()):
        target = os.path.join(raw_dir, f"{site}_raw.jsonl")
        print(f"== {site} ==")
        print(f"  merging {len(files)} incoming file(s) into {target}")

        # Load existing records (if the target already exists)
        existing_lines = []
        if os.path.exists(target):
            with open(target, encoding="utf-8") as f:
                existing_lines = f.readlines()

        # Load new records
        new_lines = []
        for path in files:
            with open(path, encoding="utf-8") as f:
                file_lines = f.readlines()
            new_lines.extend(file_lines)
            print(f"    + {os.path.basename(path)} ({len(file_lines)} lines)")

        all_lines = existing_lines + new_lines
        before_count = len([l for l in all_lines if l.strip()])

        # Dedup on the raw_request field (falls back to the whole line if missing/unparseable)
        seen = set()
        deduped = []
        for line in all_lines:
            line = line.rstrip("\n")
            if not line.strip():
                continue
            try:
                record = json.loads(line)
                key = record.get("raw_request", line)
            except json.JSONDecodeError:
                key = line
            if key not in seen:
                seen.add(key)
                deduped.append(line)

        after_count = len(deduped)
        dupes_removed = before_count - after_count

        # Back up the old target file before overwriting, if it existed
        if os.path.exists(target):
            backup = target + ".bak"
            shutil.copy2(target, backup)
            print(f"  (backed up previous version to {backup})")

        os.makedirs(raw_dir, exist_ok=True)
        with open(target, "w", encoding="utf-8") as f:
            f.write("\n".join(deduped) + ("\n" if deduped else ""))

        print(f"  {before_count} total -> {after_count} unique ({dupes_removed} duplicate(s) removed)\n")


if __name__ == "__main__":
    main()
