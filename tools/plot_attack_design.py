"""
Attack DESIGN charts - reads the code (not collected data) so anyone can
understand the attack methodology at a glance. Available before collection.

Panels:
  1. Persona x axis matrix (the 6 attacker personas across all 6 axes)
  2. Payload bank sizes per attack class x goal family (+ polyglots)
  3. Endpoint coverage per attack class (known vs held-out)

Usage (from project root):
  python tools/plot_attack_design.py
  python tools/plot_attack_design.py --out data/merged/attack_design.png
"""
import argparse
import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src", "attacks"))

from attacker_personas import ATTACKER_PERSONAS          # noqa: E402
import attack_payloads as payloads                        # noqa: E402
from attack_scenarios import ENDPOINTS                     # noqa: E402

AXES = ["tooling", "evasion", "vector", "intensity", "rate", "goal"]
CLASSES = ["sqli", "xss", "path_traversal", "code_injection"]
HELDOUT = "code_injection"
FAMILIES = ["recon", "exploit", "exfiltration"]
FAM_COLORS = {"recon": "#60a5fa", "exploit": "#f59e0b", "exfiltration": "#ef4444"}


def _value_palette(personas):
    """Stable color per axis-value so the same value reads the same everywhere."""
    vals = []
    for p in personas.values():
        d = p.to_dict()
        for ax in AXES:
            if d[ax] not in vals:
                vals.append(d[ax])
    cmap = plt.get_cmap("tab20")
    return {v: cmap(i % 20) for i, v in enumerate(vals)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="data/merged/attack_design.png")
    args = ap.parse_args()

    personas = ATTACKER_PERSONAS
    pids = list(personas)
    palette = _value_palette(personas)

    fig = plt.figure(figsize=(16, 10))
    gs = fig.add_gridspec(2, 2, height_ratios=[1.15, 1], hspace=0.32, wspace=0.22)

    # ---- Panel 1: persona x axis matrix (colored table) ----
    ax1 = fig.add_subplot(gs[0, :])
    ax1.axis("off")
    cell_text, cell_colors = [], []
    for pid in pids:
        d = personas[pid].to_dict()
        cell_text.append([d[ax] for ax in AXES])
        cell_colors.append([palette[d[ax]] for ax in AXES])
    tbl = ax1.table(cellText=cell_text,
                    rowLabels=[personas[p].persona_name for p in pids],
                    colLabels=[a.upper() for a in AXES],
                    cellColours=cell_colors, cellLoc="center", loc="center")
    tbl.auto_set_font_size(False)
    tbl.set_fontsize(10)
    tbl.scale(1, 2.1)
    for (r, c), cell in tbl.get_celld().items():
        if r == 0 or c == -1:
            cell.set_text_props(fontweight="bold")
        cell.set_edgecolor("white")
    ax1.set_title("1. Attacker personas x 6 orthogonal axes  "
                  "(each persona differs on >=2 axes -> genuinely diverse)",
                  fontweight="bold", fontsize=12, pad=14)

    # ---- Panel 2: payload bank sizes ----
    ax2 = fig.add_subplot(gs[1, 0])
    x = np.arange(len(CLASSES))
    bottom = np.zeros(len(CLASSES))
    for fam in FAMILIES:
        vals = np.array([len(payloads.BANKS[c].get(fam, [])) for c in CLASSES])
        ax2.bar(x, vals, 0.6, bottom=bottom, label=fam, color=FAM_COLORS[fam])
        bottom += vals
    poly = np.array([len(payloads.POLYGLOTS[c]) for c in CLASSES])
    ax2.bar(x, poly, 0.6, bottom=bottom, label="polyglot", color="#6b7280")
    for xi, tot in zip(x, bottom + poly):
        ax2.text(xi, tot + 0.3, f"{int(tot)}", ha="center", va="bottom",
                 fontweight="bold", fontsize=9)
    ax2.set_xticks(x)
    ax2.set_xticklabels(CLASSES, rotation=15, ha="right")
    ax2.set_ylabel("# base payloads")
    ax2.set_title("2. Payload bank size per class x goal family", fontweight="bold")
    ax2.legend(fontsize=9)
    ax2.grid(axis="y", alpha=0.3)

    # ---- Panel 3: endpoint coverage per class ----
    ax3 = fig.add_subplot(gs[1, 1])
    cov = {c: sorted({a for (a, at) in ENDPOINTS if at == c}) for c in CLASSES}
    counts = [len(cov[c]) for c in CLASSES]
    colors = ["#dc2626" if c == HELDOUT else "#2563eb" for c in CLASSES]
    bars = ax3.bar(range(len(CLASSES)), counts, 0.6, color=colors)
    for i, c in enumerate(CLASSES):
        ax3.text(i, counts[i] + 0.03, "\n".join(cov[c]), ha="center", va="bottom",
                 fontsize=8, color="#374151")
    ax3.set_xticks(range(len(CLASSES)))
    ax3.set_xticklabels(CLASSES, rotation=15, ha="right")
    ax3.set_ylabel("# apps with endpoint")
    ax3.set_ylim(0, max(counts) + 1.2)
    ax3.set_title("3. Endpoint coverage  (blue=known/train, red=held-out)",
                  fontweight="bold")
    ax3.grid(axis="y", alpha=0.3)
    from matplotlib.patches import Patch
    ax3.legend(handles=[Patch(color="#2563eb", label="known (train)"),
                        Patch(color="#dc2626", label="held-out (open-set)")],
               fontsize=9, loc="upper right")

    fig.suptitle("WAF attack DESIGN - personas, payloads, scope (from code)",
                 fontsize=14, fontweight="bold")
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    fig.savefig(args.out, dpi=150, bbox_inches="tight")
    print("[saved]", args.out)
    print("personas:", len(pids),
          "| bank totals:", {c: sum(len(v) for v in payloads.BANKS[c].values())
                              for c in CLASSES})


if __name__ == "__main__":
    main()
