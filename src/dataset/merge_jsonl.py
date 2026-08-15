"""
Merge step (Phase 1C) —   data/raw/*_raw.jsonl  dataset_v2.jsonl
 deduplication    variants (parent_id).

:          raw files  
 —   .

usage: python3 merge_jsonl.py --raw ../data/raw --out ../data/merged/dataset_v2.jsonl
"""
import argparse
import glob
import hashlib
import json
import os


def norm_key(rec):
    """ dedup — exact match   raw_request ( trim)."""
    raw = (rec.get("content", {}) or {}).get("raw_request", "") or ""
    return hashlib.sha256(raw.strip().encode("utf-8", "ignore")).hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw", nargs="+", default=["../data/raw"],
                    help="one or more raw dirs, e.g. --raw data/raw data/raw_attack")
    ap.add_argument("--out", default="../data/merged/dataset_v2.jsonl")
    args = ap.parse_args()

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    seen = set()
    kept, dropped = 0, 0
    class_counts = {}

    skipped_unknown = 0
    raw_dirs = args.raw if isinstance(args.raw, list) else [args.raw]
    all_paths = []
    for _d in raw_dirs:
        all_paths.extend(glob.glob(os.path.join(_d, "*_raw.jsonl")))
    with open(args.out, "w", encoding="utf-8") as out:
        for path in sorted(all_paths):
            # unknown_raw.jsonl only exists because capture_addon.py routes any
            # request that arrived with NO X-Capture-App header into its own
            # file (browser/tool traffic that never went through our capture
            # header logic - e.g. stray favicon/OPTIONS/background requests).
            # It has no reliable app/source_type/label metadata, so it must
            # never enter the training dataset.
            if os.path.basename(path) == "unknown_raw.jsonl":
                with open(path, encoding="utf-8") as f:
                    skipped_unknown += sum(1 for line in f if line.strip())
                continue
            with open(path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    rec = json.loads(line)
                    if (rec.get("metadata", {}) or {}).get("app") == "unknown":
                        skipped_unknown += 1
                        continue
                    k = norm_key(rec)
                    if k in seen:
                        dropped += 1
                        continue
                    seen.add(k)
                    out.write(json.dumps(rec, ensure_ascii=False) + "\n")
                    kept += 1
                    c = rec.get("label", {}).get("class", "?")
                    class_counts[c] = class_counts.get(c, 0) + 1

    print(f"[✓] kept={kept} dropped_dupes={dropped} skipped_unknown_app={skipped_unknown}")
    print("[class distribution]")
    for c, n in sorted(class_counts.items()):
        print(f"    {c:16s} {n}")


if __name__ == "__main__":
    main()
