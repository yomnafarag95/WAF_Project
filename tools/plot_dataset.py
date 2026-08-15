#!/usr/bin/env python3
"""
plot_dataset.py - clean dataset charts, two phases:
  PHASE A (attacks, before merge):  --attacks data/raw_attack
  PHASE B (full data, after merge):  --merged  data/merged/dataset_v2.jsonl

  python tools/plot_dataset.py --attacks data/raw_attack
  python tools/plot_dataset.py --merged data/merged/dataset_v2.jsonl
  python tools/plot_dataset.py --attacks data/raw_attack --merged data/merged/dataset_v2.jsonl

Handles the nested label schema ({'level1':..,'class':..}) and auto-detects
fields by value, so it is robust to key-name differences.
"""
import argparse
import glob
import json
import os
import sys
from collections import Counter, defaultdict

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# ---- known vocab (used for value-based detection) ----
CLASS_VALUES = {"sqli", "xss", "path_traversal", "code_injection", "benign"}
APP_VALUES = {"dvwa", "webgoat", "juice_shop", "jsonplaceholder",
              "pokeapi", "wikipedia"}
KNOWN = {"sqli", "xss", "path_traversal"}
HELDOUT = {"code_injection"}
CLASS_ORDER = ["sqli", "xss", "path_traversal", "code_injection", "benign"]

# ---- calm palette ----
CLASS_COLOR = {
    "sqli": "#6C8EBF",           # soft blue
    "xss": "#82B366",           # soft green
    "path_traversal": "#D6A55C",  # soft amber
    "code_injection": "#9673A6",  # soft purple
    "benign": "#AAB2BD",        # soft grey
    "unknown": "#CCCCCC",
}
BLUE, RED, GREY, AMBER = "#6C8EBF", "#C08A8A", "#AAB2BD", "#D6A55C"

plt.rcParams.update({
    "figure.figsize": (11, 6.2),
    "figure.dpi": 150,
    "savefig.dpi": 150,
    "font.size": 13,
    "axes.titlesize": 16,
    "axes.titleweight": "bold",
    "axes.labelsize": 13,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "axes.grid": True,
    "axes.axisbelow": True,
    "grid.alpha": 0.25,
    "grid.linewidth": 0.8,
})


def flatten(obj, prefix=""):
    out = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.update(flatten(v, f"{prefix}{k}."))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out.update(flatten(v, f"{prefix}{i}."))
    else:
        out[prefix[:-1]] = obj
    return out


def last(k):
    return k.split(".")[-1].lower()


def find_class(flat):
    # 1) any key literally 'class' whose value is a known class
    for k, v in flat.items():
        if last(k) == "class" and str(v) in CLASS_VALUES:
            return str(v)
    # 2) any string value that is a known class (skip label_source etc.)
    for k, v in flat.items():
        if isinstance(v, str) and v in CLASS_VALUES and "source" not in last(k):
            return v
    # 3) benign via level1 / label
    for k, v in flat.items():
        if last(k) in ("level1", "label") and str(v).lower() == "benign":
            return "benign"
    return "unknown"


def find_app(flat):
    for k, v in flat.items():
        if last(k) in ("app", "application", "app_name", "target_app") \
                and str(v) in APP_VALUES:
            return str(v)
    for k, v in flat.items():
        if isinstance(v, str) and v in APP_VALUES:
            return v
    for k, v in flat.items():  # substring / hyphen variants
        if isinstance(v, str):
            for a in APP_VALUES:
                if a in v or a.replace("_", "-") in v:
                    return a
    return "unknown"


def find_status(flat):
    for k, v in flat.items():
        if last(k) in ("status", "status_code", "response_status", "resp_status",
                       "code") and isinstance(v, (int, float)) and 100 <= v <= 599:
            return int(v)
    for k, v in flat.items():
        if "status" in last(k) and isinstance(v, (int, float)) and 100 <= v <= 599:
            return int(v)
    return None


def find_str(flat, names):
    for k, v in flat.items():
        if last(k) in names and isinstance(v, str) and v:
            return v
    return ""


def find_persona(flat):
    for k, v in flat.items():
        if "persona" in last(k) and isinstance(v, str) and v:
            return v
    return None


def norm(rec):
    flat = flatten(rec)
    payload = find_str(flat, {"decoded_payload", "payload", "url_payload"})
    plen = None
    for k, v in flat.items():
        if last(k) in ("payload_length", "payload_len") and isinstance(v, (int, float)):
            plen = int(v)
    if plen is None:
        plen = len(payload)
    return {
        "cls": find_class(flat),
        "app": find_app(flat),
        "status": find_status(flat),
        "persona": find_persona(flat),
        "plen": plen,
        "dedup": f"{find_str(flat, {'method','http_method','verb'})}|"
                 f"{find_str(flat, {'url_path','path','endpoint'})}|{payload}",
    }


def load(path):
    if os.path.isdir(path):
        files = sorted(glob.glob(os.path.join(path, "*.jsonl")))
    elif os.path.isfile(path):
        files = [path]
    else:
        print(f"  !! path not found: {path}")
        return []
    recs = []
    for f in files:
        with open(f, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        recs.append(json.loads(line))
                    except Exception:
                        pass
    return recs


def order_classes(present):
    o = [c for c in CLASS_ORDER if c in present]
    return o + sorted(c for c in present if c not in CLASS_ORDER)


def bar_labels(ax, xs, ys):
    for x, y in zip(xs, ys):
        ax.text(x, y, f"{y:,}", ha="center", va="bottom",
                fontsize=11, color="#444444")


def savefig(fig, out, name):
    os.makedirs(out, exist_ok=True)
    p = os.path.join(out, name)
    fig.savefig(p, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print(f"  saved {p}")


def phase_attacks(recs, out):
    print("\n=== PHASE A: attacks (before merge) ===")
    R = [norm(r) for r in recs]
    classes = order_classes({r["cls"] for r in R})
    apps = [a for a in ["dvwa", "webgoat", "juice_shop"]
            if a in {r["app"] for r in R}] or sorted({r["app"] for r in R})
    print(f"  records: {len(R)} | classes: {classes} | apps: {apps}")

    # A1 records per class
    cc = Counter(r["cls"] for r in R)
    fig, ax = plt.subplots()
    xs = range(len(classes))
    ys = [cc[c] for c in classes]
    ax.bar(xs, ys, color=[CLASS_COLOR.get(c, GREY) for c in classes], width=0.6)
    bar_labels(ax, xs, ys)
    ax.set_xticks(list(xs)); ax.set_xticklabels(classes)
    ax.set_title("Attacks \u2014 records per class")
    ax.set_ylabel("records")
    savefig(fig, out, "A1_attacks_by_class.png")

    # A2 app x class grouped
    fig, ax = plt.subplots()
    w = 0.8 / max(len(classes), 1)
    for i, c in enumerate(classes):
        vals = [sum(1 for r in R if r["app"] == a and r["cls"] == c) for a in apps]
        ax.bar([j + i * w for j in range(len(apps))], vals, width=w,
               label=c, color=CLASS_COLOR.get(c, GREY))
    ax.set_xticks([j + (len(classes) - 1) * w / 2 for j in range(len(apps))])
    ax.set_xticklabels(apps)
    ax.set_title("Attacks \u2014 records per app \u00d7 class")
    ax.set_ylabel("records")
    ax.legend(frameon=False, ncol=len(classes), loc="upper center",
              bbox_to_anchor=(0.5, -0.10))
    savefig(fig, out, "A2_attacks_by_app_class.png")

    # A3 total vs unique
    total = Counter(); uniq = defaultdict(set)
    for r in R:
        total[r["cls"]] += 1
        uniq[r["cls"]].add(r["dedup"])
    fig, ax = plt.subplots()
    x = list(range(len(classes)))
    ax.bar([i - 0.21 for i in x], [total[c] for c in classes], width=0.42,
           label="total", color=GREY)
    ax.bar([i + 0.21 for i in x], [len(uniq[c]) for c in classes], width=0.42,
           label="unique", color=BLUE)
    ax.set_xticks(x); ax.set_xticklabels(classes)
    ax.set_title("Attacks \u2014 total vs unique (byte-identical dedup)")
    ax.set_ylabel("records")
    ax.legend(frameon=False)
    savefig(fig, out, "A3_attacks_dupes.png")

    # A4 status per class (stacked, calm)
    if any(r["status"] is not None for r in R):
        statuses = sorted({r["status"] for r in R if r["status"] is not None})
        st_color = {200: "#82B366", 302: "#D6A55C", 404: "#C08A8A"}
        fig, ax = plt.subplots()
        bottom = [0] * len(classes)
        for st in statuses:
            vals = [sum(1 for r in R if r["cls"] == c and r["status"] == st)
                    for c in classes]
            ax.bar(range(len(classes)), vals, bottom=bottom, width=0.6,
                   label=f"HTTP {st}", color=st_color.get(st, GREY))
            bottom = [b + v for b, v in zip(bottom, vals)]
        ax.set_xticks(range(len(classes))); ax.set_xticklabels(classes)
        ax.set_title("Attacks \u2014 response status per class")
        ax.set_ylabel("records")
        ax.legend(frameon=False, ncol=len(statuses))
        savefig(fig, out, "A4_attacks_status.png")

    # A5 payload length per class (box)
    data = [[r["plen"] for r in R if r["cls"] == c] or [0] for c in classes]
    fig, ax = plt.subplots()
    bp = ax.boxplot(data, showfliers=False, patch_artist=True)
    for patch, c in zip(bp["boxes"], classes):
        patch.set_facecolor(CLASS_COLOR.get(c, GREY)); patch.set_alpha(0.7)
    for med in bp["medians"]:
        med.set_color("#444444")
    ax.set_xticks(range(1, len(classes) + 1)); ax.set_xticklabels(classes)
    ax.set_title("Attacks \u2014 payload length per class")
    ax.set_ylabel("characters")
    savefig(fig, out, "A5_attacks_payload_len.png")

    # A6 per persona
    if any(r["persona"] for r in R):
        pc = Counter(r["persona"] for r in R if r["persona"])
        labels = [p for p, _ in pc.most_common()]
        fig, ax = plt.subplots(figsize=(12, 6.2))
        ax.bar(range(len(labels)), [pc[p] for p in labels], color=BLUE, width=0.6)
        ax.set_xticks(range(len(labels)))
        ax.set_xticklabels(labels, rotation=20, ha="right")
        ax.set_title("Attacks \u2014 records per persona")
        ax.set_ylabel("records")
        savefig(fig, out, "A6_attacks_by_persona.png")


def phase_full(recs, out):
    print("\n=== PHASE B: full dataset (after merge) ===")
    R = [norm(r) for r in recs]
    classes = order_classes({r["cls"] for r in R})
    print(f"  records: {len(R)} | classes: {classes}")

    def group(c):
        if c == "benign":
            return "benign"
        if c in HELDOUT:
            return "held-out\n(code_injection)"
        if c in KNOWN:
            return "known\n(train)"
        return "other"

    # B1 benign vs attack
    ba = Counter("benign" if r["cls"] == "benign" else "attack" for r in R)
    keys = [k for k in ["benign", "attack"] if k in ba]
    fig, ax = plt.subplots(figsize=(8, 6))
    ys = [ba[k] for k in keys]
    ax.bar(range(len(keys)), ys, width=0.5, color=[GREY, RED][:len(keys)])
    bar_labels(ax, range(len(keys)), ys)
    ax.set_xticks(range(len(keys))); ax.set_xticklabels(keys)
    ax.set_title("Full data \u2014 benign vs attack")
    ax.set_ylabel("records")
    savefig(fig, out, "B1_full_benign_vs_attack.png")

    # B2 records per class
    cc = Counter(r["cls"] for r in R)
    fig, ax = plt.subplots()
    ys = [cc[c] for c in classes]
    ax.bar(range(len(classes)), ys, width=0.6,
           color=[CLASS_COLOR.get(c, GREY) for c in classes])
    bar_labels(ax, range(len(classes)), ys)
    ax.set_xticks(range(len(classes))); ax.set_xticklabels(classes)
    ax.set_title("Full data \u2014 records per class")
    ax.set_ylabel("records")
    savefig(fig, out, "B2_full_by_class.png")

    # B3 per source (stacked benign/attack)
    apps = sorted({r["app"] for r in R})
    ben = [sum(1 for r in R if r["app"] == a and r["cls"] == "benign") for a in apps]
    att = [sum(1 for r in R if r["app"] == a and r["cls"] != "benign") for a in apps]
    fig, ax = plt.subplots(figsize=(12, 6.2))
    ax.bar(range(len(apps)), ben, width=0.62, label="benign", color=GREY)
    ax.bar(range(len(apps)), att, width=0.62, bottom=ben, label="attack", color=RED)
    ax.set_xticks(range(len(apps))); ax.set_xticklabels(apps, rotation=20, ha="right")
    ax.set_title("Full data \u2014 records per source")
    ax.set_ylabel("records")
    ax.legend(frameon=False)
    savefig(fig, out, "B3_full_by_source.png")

    # B4 open-set groups
    gc = Counter(group(r["cls"]) for r in R)
    order = ["known\n(train)", "held-out\n(code_injection)", "benign", "other"]
    order = [g for g in order if g in gc]
    fig, ax = plt.subplots(figsize=(9, 6))
    ys = [gc[g] for g in order]
    cols = {"known\n(train)": RED, "held-out\n(code_injection)": AMBER,
            "benign": GREY, "other": "#CCCCCC"}
    ax.bar(range(len(order)), ys, width=0.55, color=[cols[g] for g in order])
    bar_labels(ax, range(len(order)), ys)
    ax.set_xticks(range(len(order))); ax.set_xticklabels(order)
    ax.set_title("Full data \u2014 open-set split")
    ax.set_ylabel("records")
    savefig(fig, out, "B4_full_open_set_groups.png")

    # B5 payload length benign vs attack
    ben_len = [r["plen"] for r in R if r["cls"] == "benign"] or [0]
    att_len = [r["plen"] for r in R if r["cls"] != "benign"] or [0]
    fig, ax = plt.subplots(figsize=(8, 6))
    bp = ax.boxplot([ben_len, att_len], showfliers=False, patch_artist=True)
    for patch, col in zip(bp["boxes"], [GREY, RED]):
        patch.set_facecolor(col); patch.set_alpha(0.7)
    for med in bp["medians"]:
        med.set_color("#444444")
    ax.set_xticks([1, 2]); ax.set_xticklabels(["benign", "attack"])
    ax.set_title("Full data \u2014 payload length")
    ax.set_ylabel("characters")
    savefig(fig, out, "B5_full_payload_len.png")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--attacks")
    ap.add_argument("--merged")
    ap.add_argument("--out", default="reports/figures")
    args = ap.parse_args()
    if not args.attacks and not args.merged:
        print("pass --attacks and/or --merged"); sys.exit(1)
    if args.attacks:
        recs = load(args.attacks)
        if recs:
            phase_attacks(recs, os.path.join(args.out, "attacks"))
    if args.merged:
        recs = load(args.merged)
        if recs:
            phase_full(recs, os.path.join(args.out, "full"))
    print("\ndone.")


if __name__ == "__main__":
    main()
