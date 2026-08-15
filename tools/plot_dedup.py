"""
Before/after merge (dedup) chart - DATA-DRIVEN.
===============================================
Reads the ACTUAL run output, computes the distribution, then plots:
  * RAW    counts  = per-app line counts across the raw jsonl dirs
  * UNIQUE counts  = per-app line counts in the merged (deduped) file

Usage (from project root, inside your venv):
  pip install matplotlib          # once, if not already installed
  python tools/plot_dedup.py
  python tools/plot_dedup.py --raw data/raw data/raw_attack \
         --merged data/merged/dataset_v2.jsonl --out data/merged/dedup_chart.png

Nothing is hard-coded: change the run, re-run this, the chart updates.
"""
import argparse
import glob
import json
import os
from collections import Counter

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np


def _app_of(rec: dict) -> str:
    md = rec.get("metadata", {}) or {}
    return md.get("app") or rec.get("app") or "unknown"


def count_apps(paths) -> Counter:
    """Count records per app across one or more jsonl file globs."""
    c = Counter()
    for p in paths:
        if not os.path.exists(p):
            print(f"[warn] not found: {p}")
            continue
        with open(p, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    c[_app_of(json.loads(line))] += 1
                except json.JSONDecodeError:
                    continue
    return c


def expand_raw_dirs(raw_dirs):
    files = []
    for d in raw_dirs:
        files.extend(sorted(glob.glob(os.path.join(d, "*_raw.jsonl"))))
    return files


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw", nargs="+", default=["data/raw"],
                    help="one or more raw dirs holding *_raw.jsonl")
    ap.add_argument("--merged", default="data/merged/dataset_v2.jsonl",
                    help="deduped merged jsonl file")
    ap.add_argument("--out", default="data/merged/dedup_chart.png")
    ap.add_argument("--drop-apps", nargs="*", default=["unknown"],
                    help="apps to exclude from the chart (junk)")
    args = ap.parse_args()

    raw_files = expand_raw_dirs(args.raw)
    if not raw_files:
        raise SystemExit(f"No *_raw.jsonl found under: {args.raw}")
    raw_c = count_apps(raw_files)
    uniq_c = count_apps([args.merged])

    apps = sorted(set(raw_c) | set(uniq_c), key=lambda a: raw_c.get(a, 0),
                  reverse=True)
    apps = [a for a in apps if a not in set(args.drop_apps)]
    if not apps:
        raise SystemExit("No apps left to plot after --drop-apps.")

    raw = np.array([raw_c.get(a, 0) for a in apps], dtype=float)
    uniq = np.array([uniq_c.get(a, 0) for a in apps], dtype=float)
    dup_pct = np.where(raw > 0, (raw - uniq) / raw * 100, 0)

    total_raw = int(raw.sum())
    total_uniq = int(uniq.sum())
    total_dup_pct = (total_raw - total_uniq) / total_raw * 100 if total_raw else 0

    print("[per-app]")
    for a, r, u, d in zip(apps, raw, uniq, dup_pct):
        print(f"  {a:16s} raw={int(r):6d} unique={int(u):6d} dup={d:4.1f}%")
    print(f"[total] raw={total_raw} unique={total_uniq} dup={total_dup_pct:.1f}%")

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6.2),
                                   gridspec_kw={"width_ratios": [2.4, 1]})

    x = np.arange(len(apps))
    w = 0.38
    ax1.bar(x - w/2, raw,  w, label="Raw (before dedup)", color="#94a3b8")
    ax1.bar(x + w/2, uniq, w, label="Unique (after merge)", color="#2563eb")
    top = raw.max() if raw.max() > 0 else 1
    for xi, r, u, d in zip(x, raw, uniq, dup_pct):
        ax1.text(xi - w/2, r + top*0.01, f"{int(r)}", ha="center", va="bottom",
                 fontsize=9, color="#475569")
        ax1.text(xi + w/2, u + top*0.01, f"{int(u)}", ha="center", va="bottom",
                 fontsize=9, color="#1e40af", fontweight="bold")
        ax1.text(xi, max(r, u) + top*0.05, f"-{d:.0f}% dup", ha="center",
                 va="bottom", fontsize=8.5, color="#dc2626", fontweight="bold")
    ax1.set_xticks(x)
    ax1.set_xticklabels(apps, rotation=20, ha="right", fontsize=10)
    ax1.set_ylabel("HTTP requests")
    ax1.set_title("Per app: before vs after dedup", fontweight="bold")
    ax1.legend(loc="upper right")
    ax1.set_ylim(0, top * 1.18)
    ax1.grid(axis="y", alpha=0.3)

    bars = ax2.bar(["Raw", "Unique"], [total_raw, total_uniq],
                   color=["#94a3b8", "#2563eb"], width=0.55)
    ax2.bar_label(bars, fmt="%d", padding=4, fontweight="bold")
    ax2.set_title(f"Overall  (-{total_dup_pct:.0f}% duplicates)", fontweight="bold")
    ax2.set_ylabel("HTTP requests")
    ax2.set_ylim(0, (total_raw or 1) * 1.18)
    ax2.grid(axis="y", alpha=0.3)
    if total_raw:
        ax2.annotate(f"{total_raw - total_uniq} dupes\nremoved",
                     xy=(0, total_raw), xytext=(0.5, total_raw * 0.75),
                     ha="center", fontsize=10, color="#dc2626", fontweight="bold")

    fig.suptitle("WAF dataset - merge / dedup result (from actual run)",
                 fontsize=13, fontweight="bold")
    fig.tight_layout(rect=[0, 0, 1, 0.96])
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    fig.savefig(args.out, dpi=150)
    print("[saved]", args.out)


if __name__ == "__main__":
    main()
