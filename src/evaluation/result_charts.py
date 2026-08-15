"""
Results charts.

WHEN TO RUN: AFTER model evaluation (Protocols 1-4) has written its metric
files. This script ONLY visualizes files you provide - it never invents
numbers, so it is safe to ship before any results exist.

EXPECTED INPUTS (your training/eval code must write these):
  reports/results/protocol1_predictions.csv   -> columns: true_class,pred_class
  reports/results/protocol2_cross_app_f1.csv   -> columns: held_out_app,macro_f1
  reports/results/protocol3_openset_scores.csv -> columns: true_is_known,msp_score   (true_is_known in {0,1})
  reports/results/protocol3_breakdown.csv      -> columns: outcome,count             (outcome in {unknown_flagged,misclassified_blocked,leaked_as_benign})
  reports/results/protocol4_obfuscation.csv    -> columns: variant_type,macro_f1
  reports/results/baseline_comparison.csv      -> columns: system,macro_f1

OUTPUT: reports/results/*.png (one chart per input that exists)

Run (from project root):
  python3 src/evaluation/result_charts.py --input reports/results --output reports/results
"""

import argparse
import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402


def _load(path: str):
    return pd.read_csv(path) if os.path.exists(path) else None


def chart_confusion_matrix(indir: str, outdir: str) -> bool:
    df = _load(os.path.join(indir, "protocol1_predictions.csv"))
    if df is None:
        return False
    labels = sorted(set(df["true_class"]) | set(df["pred_class"]))
    cm = pd.crosstab(df["true_class"], df["pred_class"]).reindex(index=labels, columns=labels, fill_value=0)
    fig, ax = plt.subplots(figsize=(6, 5))
    im = ax.imshow(cm.values, cmap="Blues")
    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(labels, rotation=45, ha="right")
    ax.set_yticks(range(len(labels)))
    ax.set_yticklabels(labels)
    ax.set_xlabel("Predicted")
    ax.set_ylabel("True")
    for i in range(len(labels)):
        for j in range(len(labels)):
            ax.text(j, i, str(cm.values[i, j]), ha="center", va="center", fontsize=8)
    fig.colorbar(im, fraction=0.046, pad=0.04)
    ax.set_title("Protocol 1 - in-distribution confusion matrix")
    plt.tight_layout()
    plt.savefig(os.path.join(outdir, "confusion_matrix_protocol1.png"), dpi=150)
    plt.close()
    return True


def chart_cross_app_f1(indir: str, outdir: str) -> bool:
    df = _load(os.path.join(indir, "protocol2_cross_app_f1.csv"))
    if df is None:
        return False
    ax = df.plot(kind="bar", x="held_out_app", y="macro_f1", legend=False, color="#55A868")
    ax.axhline(0.80, color="red", linestyle="--", label="target 0.80")
    ax.set_ylim(0, 1)
    ax.set_ylabel("macro-F1")
    ax.set_title("Protocol 2 - cross-app generalization (leave-one-app-out)")
    ax.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(outdir, "cross_app_f1.png"), dpi=150)
    plt.close()
    return True


def chart_openset_roc(indir: str, outdir: str) -> bool:
    df = _load(os.path.join(indir, "protocol3_openset_scores.csv"))
    if df is None:
        return False
    try:
        from sklearn.metrics import roc_curve, auc
    except ImportError:
        print("  [skip] openset ROC needs scikit-learn: pip install scikit-learn")
        return False
    # Known=1 is the positive class; MSP score should be higher for known.
    fpr, tpr, _ = roc_curve(df["true_is_known"], df["msp_score"])
    roc_auc = auc(fpr, tpr)
    plt.figure(figsize=(6, 5))
    plt.plot(fpr, tpr, label=f"MSP (AUROC={roc_auc:.3f})")
    plt.plot([0, 1], [0, 1], "k--", alpha=0.4)
    plt.xlabel("False positive rate")
    plt.ylabel("True positive rate")
    plt.title("Protocol 3 - open-set known-vs-unknown (MSP)")
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(outdir, "openset_roc.png"), dpi=150)
    plt.close()
    return True


def chart_openset_breakdown(indir: str, outdir: str) -> bool:
    df = _load(os.path.join(indir, "protocol3_breakdown.csv"))
    if df is None:
        return False
    order = ["unknown_flagged", "misclassified_blocked", "leaked_as_benign"]
    colors = {"unknown_flagged": "#55A868", "misclassified_blocked": "#DD8452", "leaked_as_benign": "#C44E52"}
    df = df.set_index("outcome").reindex(order).fillna(0)
    ax = df["count"].plot(kind="bar", color=[colors[o] for o in order])
    ax.set_title("Protocol 3 - unknown-attack outcome breakdown")
    ax.set_ylabel("count")
    ax.set_xticklabels(["Unknown (good)", "Misclassified but blocked (safe)", "Leaked as benign (failure)"], rotation=20, ha="right")
    plt.tight_layout()
    plt.savefig(os.path.join(outdir, "openset_breakdown.png"), dpi=150)
    plt.close()
    return True


def chart_obfuscation(indir: str, outdir: str) -> bool:
    df = _load(os.path.join(indir, "protocol4_obfuscation.csv"))
    if df is None:
        return False
    ax = df.plot(kind="bar", x="variant_type", y="macro_f1", legend=False, color="#8172B3")
    ax.set_ylim(0, 1)
    ax.set_ylabel("macro-F1")
    ax.set_title("Protocol 4 - robustness to obfuscation variants")
    plt.tight_layout()
    plt.savefig(os.path.join(outdir, "obfuscation_robustness.png"), dpi=150)
    plt.close()
    return True


def chart_baseline_comparison(indir: str, outdir: str) -> bool:
    df = _load(os.path.join(indir, "baseline_comparison.csv"))
    if df is None:
        return False
    ax = df.plot(kind="bar", x="system", y="macro_f1", legend=False, color="#4C72B0")
    ax.set_ylim(0, 1)
    ax.set_ylabel("macro-F1")
    ax.set_title("Baseline comparison")
    plt.tight_layout()
    plt.savefig(os.path.join(outdir, "baseline_comparison.png"), dpi=150)
    plt.close()
    return True


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default="reports/results")
    ap.add_argument("--output", default="reports/results")
    args = ap.parse_args()
    os.makedirs(args.output, exist_ok=True)

    charts = [
        chart_confusion_matrix,
        chart_cross_app_f1,
        chart_openset_roc,
        chart_openset_breakdown,
        chart_obfuscation,
        chart_baseline_comparison,
    ]
    made = 0
    for fn in charts:
        if fn(args.input, args.output):
            made += 1
    if made == 0:
        print("No result files found yet. Produce the CSVs listed in the module docstring, then re-run.")
    else:
        print(f"[done] {made} result chart(s) written to {args.output}/")


if __name__ == "__main__":
    main()
