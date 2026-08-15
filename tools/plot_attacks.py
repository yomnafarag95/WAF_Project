"""
Attack DATA charts - DATA-DRIVEN. Reads the ACTUAL collected attack records
and plots distributions so anyone understands the attack dataset.

Panels:
  1. Records per attack class (known vs held-out)
  2. Per-app x class (stacked)
  3. Evasion variant distribution (original/encoded/mutated/polyglot)
  4. Records per attacker persona
  5. Injection vector distribution (query/body/header/cookie)
  6. Benign vs Attack overall (needs --merged; else per split_role)

Usage (from project root, after collecting attacks):
  python tools/plot_attacks.py
  python tools/plot_attacks.py --raw data/raw_attack \
         --merged data/merged/dataset_v2.jsonl --out data/merged/attacks_chart.png

Nothing hard-coded: change the run, re-run, charts update.
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

KNOWN = ["sqli", "xss", "path_traversal"]
HELDOUT = "code_injection"
CLASS_ORDER = KNOWN + [HELDOUT]
VAR_ORDER = ["original", "encoded", "mutated", "polyglot"]
VEC_ORDER = ["query", "body", "header", "cookie"]


def read_records(paths):
    recs = []
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
                    recs.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return recs


def expand(raw_dirs):
    files = []
    for d in raw_dirs:
        files.extend(sorted(glob.glob(os.path.join(d, "*_raw.jsonl"))))
    return files


def _cls(r):
    return (r.get("label", {}) or {}).get("class", "?")


def _vec(r):
    # scenario_id is "class:goal:vector"
    sc = (r.get("metadata", {}) or {}).get("scenario_id") or ""
    parts = sc.split(":")
    return parts[2] if len(parts) == 3 else "?"


def _bar(ax, labels, values, title, colors=None, rotate=15):
    bars = ax.bar(range(len(labels)), values, 0.6, color=colors or "#2563eb")
    ax.bar_label(bars, fmt="%d", padding=2, fontsize=9, fontweight="bold")
    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(labels, rotation=rotate, ha="right", fontsize=9)
    ax.set_title(title, fontweight="bold", fontsize=11)
    ax.grid(axis="y", alpha=0.3)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw", nargs="+", default=["data/raw_attack"])
    ap.add_argument("--merged", default=None,
                    help="optional merged benign+attack file for the benign-vs-attack panel")
    ap.add_argument("--out", default="data/merged/attacks_chart.png")
    args = ap.parse_args()

    files = expand(args.raw)
    if not files:
        raise SystemExit(f"No *_raw.jsonl under {args.raw}. Collect attacks first.")
    recs = read_records(files)
    if not recs:
        raise SystemExit("No attack records found.")
    print(f"[info] {len(recs)} attack records from {len(files)} files")

    cls_c = Counter(_cls(r) for r in recs)
    var_c = Counter((r.get("variant", {}) or {}).get("variant_type", "?") for r in recs)
    per_c = Counter((r.get("metadata", {}) or {}).get("persona_id", "?") for r in recs)
    vec_c = Counter(_vec(r) for r in recs)
    apps = sorted({(r.get("metadata", {}) or {}).get("app", "?") for r in recs})
    app_cls = Counter(((r.get("metadata", {}) or {}).get("app", "?"), _cls(r)) for r in recs)

    fig, axes = plt.subplots(2, 3, figsize=(18, 10))
    (a1, a2, a3), (a4, a5, a6) = axes

    # 1. class distribution
    classes = [c for c in CLASS_ORDER if c in cls_c] + \
              [c for c in cls_c if c not in CLASS_ORDER]
    cvals = [cls_c[c] for c in classes]
    ccolors = ["#dc2626" if c == HELDOUT else "#2563eb" for c in classes]
    _bar(a1, classes, cvals, "1. Records per attack class", ccolors)
    from matplotlib.patches import Patch
    a1.legend(handles=[Patch(color="#2563eb", label="known (train)"),
                       Patch(color="#dc2626", label="held-out")], fontsize=8)

    # 2. per-app x class stacked
    ax = np.arange(len(apps))
    bottom = np.zeros(len(apps))
    cmap = {"sqli": "#2563eb", "xss": "#16a34a", "path_traversal": "#f59e0b",
            HELDOUT: "#dc2626"}
    for c in classes:
        vals = np.array([app_cls.get((app, c), 0) for app in apps])
        a2.bar(ax, vals, 0.6, bottom=bottom, label=c,
               color=cmap.get(c, "#6b7280"))
        bottom += vals
    a2.set_title("2. Per-app x class", fontweight="bold", fontsize=11)
    a2.set_xticks(ax)
    a2.set_xticklabels(apps, rotation=15, ha="right", fontsize=9)
    a2.legend(fontsize=8)
    a2.grid(axis="y", alpha=0.3)

    # 3. variant distribution
    variants = [v for v in VAR_ORDER if v in var_c] + \
               [v for v in var_c if v not in VAR_ORDER]
    _bar(a3, variants, [var_c[v] for v in variants],
         "3. Evasion variant distribution", "#7c3aed")

    # 4. persona distribution
    personas = [p for p, _ in per_c.most_common()]
    _bar(a4, personas, [per_c[p] for p in personas],
         "4. Records per attacker persona", "#0891b2", rotate=25)

    # 5. vector distribution
    vectors = [v for v in VEC_ORDER if v in vec_c] + \
              [v for v in vec_c if v not in VEC_ORDER]
    _bar(a5, vectors, [vec_c[v] for v in vectors],
         "5. Injection vector distribution", "#db2777")

    # 6. benign vs attack
    if args.merged and os.path.exists(args.merged):
        m = read_records([args.merged])
        lvl = Counter((r.get("label", {}) or {}).get("level1", "?") for r in m)
        labels = ["benign", "malicious"]
        vals = [lvl.get("benign", 0), lvl.get("malicious", 0)]
        _bar(a6, labels, vals, "6. Benign vs Attack (merged, deduped)",
             ["#16a34a", "#dc2626"], rotate=0)
    else:
        split_c = Counter((r.get("label", {}) or {}).get("split_role", "?") for r in recs)
        ks = list(split_c)
        _bar(a6, ks, [split_c[k] for k in ks],
             "6. Split role (pass --merged for benign-vs-attack)", "#64748b", rotate=0)

    fig.suptitle("WAF attack dataset - distributions (from actual run)",
                 fontsize=15, fontweight="bold")
    fig.tight_layout(rect=[0, 0, 1, 0.96])
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    fig.savefig(args.out, dpi=150)
    print("[saved]", args.out)
    print("[class]", dict(cls_c))
    print("[variant]", dict(var_c))
    print("[vector]", dict(vec_c))


if __name__ == "__main__":
    main()
