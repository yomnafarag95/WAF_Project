"""
EDA / correlation charts.

WHEN TO RUN: right AFTER `extract_features.py --stage processed`, BEFORE
training any model. These charts describe the dataset so a reader who has
never seen the raw JSONL understands its shape, balance and structure.

INPUT : data/processed/*.jsonl  (schema_v2 records that include features_aux)
OUTPUT: reports/eda/*.png

Run (from project root):
  python3 src/analysis/eda_charts.py --input data/processed --output reports/eda

Uses only pandas + matplotlib (both preinstalled). No fabricated data - if
there are no processed records yet, it exits cleanly.
"""

import argparse
import glob
import json
import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402

NUMERIC_FEATURES = [
    "path_length",
    "query_param_count",
    "payload_length",
    "special_char_ratio",
    "encoded_char_ratio",
    "traversal_depth",
    "header_count",
    "inter_arrival_ms",
    "request_rate_window",
]


def load_records(input_dir: str) -> pd.DataFrame:
    rows = []
    for path in glob.glob(os.path.join(input_dir, "*.jsonl")):
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                feats = rec.get("features_aux") or {}
                if not feats:
                    continue
                rows.append({
                    "class": rec["label"]["class"],
                    "level1": rec["label"]["level1"],
                    "split_role": rec["label"]["split_role"],
                    "app": rec["metadata"]["app"],
                    **{k: feats.get(k) for k in NUMERIC_FEATURES},
                })
    return pd.DataFrame(rows)


def chart_class_balance(df: pd.DataFrame, outdir: str) -> None:
    counts = df["class"].value_counts()
    ax = counts.plot(kind="bar", color="#4C72B0")
    ax.set_title("Class balance (processed records)")
    ax.set_ylabel("count")
    for i, v in enumerate(counts.values):
        ax.text(i, v, str(v), ha="center", va="bottom", fontsize=8)
    plt.tight_layout()
    plt.savefig(os.path.join(outdir, "class_balance.png"), dpi=150)
    plt.close()


def chart_class_by_app(df: pd.DataFrame, outdir: str) -> None:
    """Source-leakage sanity check: each class should appear across apps."""
    pivot = df.pivot_table(index="app", columns="class", aggfunc="size", fill_value=0)
    pivot.plot(kind="bar", stacked=True)
    plt.title("Class distribution per app (source-leakage sanity check)")
    plt.ylabel("count")
    plt.tight_layout()
    plt.savefig(os.path.join(outdir, "class_by_app_stacked.png"), dpi=150)
    plt.close()


def chart_correlation_heatmap(df: pd.DataFrame, outdir: str) -> None:
    cols = [c for c in NUMERIC_FEATURES if c in df.columns and df[c].notna().any()]
    corr = df[cols].corr(numeric_only=True)
    fig, ax = plt.subplots(figsize=(8, 7))
    im = ax.imshow(corr, cmap="coolwarm", vmin=-1, vmax=1)
    ax.set_xticks(range(len(cols)))
    ax.set_xticklabels(cols, rotation=45, ha="right")
    ax.set_yticks(range(len(cols)))
    ax.set_yticklabels(cols)
    for i in range(len(cols)):
        for j in range(len(cols)):
            ax.text(j, i, f"{corr.iloc[i, j]:.2f}", ha="center", va="center", fontsize=7)
    fig.colorbar(im, fraction=0.046, pad=0.04)
    ax.set_title("Feature correlation (features_aux)")
    plt.tight_layout()
    plt.savefig(os.path.join(outdir, "feature_correlation_heatmap.png"), dpi=150)
    plt.close()


def chart_feature_distributions(df: pd.DataFrame, outdir: str) -> None:
    feats = [c for c in ["payload_length", "special_char_ratio", "encoded_char_ratio", "traversal_depth"] if c in df.columns]
    classes = sorted(df["class"].dropna().unique())
    fig, axes = plt.subplots(1, len(feats), figsize=(4 * len(feats), 4))
    if len(feats) == 1:
        axes = [axes]
    for ax, feat in zip(axes, feats):
        data = [df[df["class"] == c][feat].dropna().values for c in classes]
        ax.boxplot(data, tick_labels=classes)
        ax.set_title(feat)
        ax.tick_params(axis="x", rotation=45)
    plt.suptitle("Feature distributions by class")
    plt.tight_layout()
    plt.savefig(os.path.join(outdir, "feature_distributions_by_class.png"), dpi=150)
    plt.close()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default="data/processed")
    ap.add_argument("--output", default="reports/eda")
    args = ap.parse_args()

    os.makedirs(args.output, exist_ok=True)
    df = load_records(args.input)
    if df.empty:
        print("No processed records found. Run extract_features.py --stage processed first.")
        return

    chart_class_balance(df, args.output)
    chart_class_by_app(df, args.output)
    chart_correlation_heatmap(df, args.output)
    chart_feature_distributions(df, args.output)
    print(f"[done] EDA charts written to {args.output}/ ({len(df)} records)")


if __name__ == "__main__":
    main()
