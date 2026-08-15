"""
Compare REAL-site benign traffic vs LAB (scripted persona) benign traffic.

PURPOSE: after running both run_benign_generation.py/benign_driver.py (lab
apps, metadata.source_type="scripted") and real_sites_driver.py (real public
sites, metadata.source_type="real"), use this to sanity-check that both
look like plausible benign HTTP traffic and to document how they differ
before merging them (Phase 0 "Supplementary benign" in the methodology).

This does NOT decide pass/fail - real and lab traffic are expected to look
different (different apps, different content). It is a descriptive,
side-by-side comparison for you (and your reviewer) to read.

INPUT : data/raw/*.jsonl (schema_v2 RAW records)
OUTPUT: reports/eda/real_vs_scripted/*.png + a printed summary table

Run (from project root):
  python3 src/analysis/compare_real_vs_scripted.py --input data/raw --output reports/eda/real_vs_scripted
"""
import argparse
import glob
import json
import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402


def load_raw(input_dir: str) -> pd.DataFrame:
    rows = []
    for path in glob.glob(os.path.join(input_dir, "*.jsonl")):
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                meta = rec.get("metadata", {})
                content = rec.get("content", {})
                label = rec.get("label", {})
                if label.get("class") != "benign":
                    continue  # this comparison is benign-only by design
                raw_req = content.get("raw_request") or ""
                rows.append({
                    "app": meta.get("app"),
                    "source_type": meta.get("source_type") or "unknown",
                    "session_id": rec.get("session_id") or "(none)",
                    "status": meta.get("response_status_code"),
                    "method": content.get("http_method"),
                    "url_path": content.get("url_path"),
                    "raw_request_len": len(raw_req),
                })
    return pd.DataFrame(rows)


def make_charts(df: pd.DataFrame, outdir: str) -> None:
    groups = sorted(df["source_type"].unique())
    colors = {"scripted": "#4C72B0", "real": "#DD8452", "unknown": "#999999"}

    # 1. record counts per source_type (overall volume comparison)
    counts = df["source_type"].value_counts()
    ax = counts.plot(kind="bar", color=[colors.get(g, "#999999") for g in counts.index])
    ax.set_title("Benign records: lab (scripted) vs real sites")
    ax.set_ylabel("records")
    for i, v in enumerate(counts.values):
        ax.text(i, v, str(int(v)), ha="center", va="bottom", fontsize=9)
    plt.tight_layout()
    plt.savefig(os.path.join(outdir, "01_volume_by_source_type.png"), dpi=150)
    plt.close()

    # 2. status code health, side by side
    fig, axes = plt.subplots(1, len(groups), figsize=(5 * len(groups), 4), squeeze=False)
    for i, g in enumerate(groups):
        sub = df[df["source_type"] == g]
        status = sub["status"].fillna(-1).astype(int).astype(str).value_counts().sort_index()
        ax = axes[0][i]
        status.plot(kind="bar", ax=ax, color=colors.get(g, "#999999"))
        ax.set_title(f"{g}: status codes")
        ax.set_ylabel("count")
    plt.tight_layout()
    plt.savefig(os.path.join(outdir, "02_status_codes_side_by_side.png"), dpi=150)
    plt.close()

    # 3. request length distribution overlay (raw_request size in chars)
    ax = None
    for g in groups:
        sub = df[df["source_type"] == g]
        ax = sub["raw_request_len"].plot(
            kind="hist", bins=30, alpha=0.5, label=g, color=colors.get(g, "#999999"), ax=ax,
        )
    plt.title("Raw request length distribution (chars)")
    plt.xlabel("raw_request length")
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(outdir, "03_request_length_overlay.png"), dpi=150)
    plt.close()

    # 4. HTTP method mix, side by side
    fig, axes = plt.subplots(1, len(groups), figsize=(5 * len(groups), 4), squeeze=False)
    for i, g in enumerate(groups):
        sub = df[df["source_type"] == g]
        methods = sub["method"].value_counts()
        ax = axes[0][i]
        methods.plot(kind="bar", ax=ax, color=colors.get(g, "#999999"))
        ax.set_title(f"{g}: HTTP methods")
        ax.set_ylabel("count")
    plt.tight_layout()
    plt.savefig(os.path.join(outdir, "04_http_methods_side_by_side.png"), dpi=150)
    plt.close()

    # 5. app/site breakdown within each source_type
    apps = df.groupby(["source_type", "app"]).size().unstack(fill_value=0)
    ax = apps.T.plot(kind="bar", stacked=False, figsize=(8, 4))
    ax.set_title("Records per app/site, grouped by source_type")
    ax.set_ylabel("records")
    plt.tight_layout()
    plt.savefig(os.path.join(outdir, "05_apps_by_source_type.png"), dpi=150)
    plt.close()


def print_summary(df: pd.DataFrame) -> None:
    print("\n" + "=" * 60)
    print("REAL vs SCRIPTED BENIGN - SUMMARY")
    print("=" * 60)
    for g in sorted(df["source_type"].unique()):
        sub = df[df["source_type"] == g]
        per_session = sub.groupby("session_id").size()
        err = sub[sub["status"].fillna(0) >= 400]
        error_rate = (len(err) / len(sub)) if len(sub) else 0
        print(f"\n[{g}]")
        print(f"  records            : {len(sub)}")
        print(f"  apps/sites          : {sorted(sub['app'].dropna().unique())}")
        print(f"  unique url paths    : {sub['url_path'].nunique()}")
        print(f"  median req/session  : {per_session.median() if not per_session.empty else 0:.0f}")
        print(f"  error rate (>=400)  : {error_rate:.0%}")
        print(f"  avg raw_request len : {sub['raw_request_len'].mean():.0f} chars")
    print("\n" + "=" * 60)
    print("Read: real and lab traffic are EXPECTED to differ (different apps,")
    print("content, and structure). The goal is not to make them identical -")
    print("it is to confirm both are healthy, low-error, diverse benign traffic")
    print("before merging them as complementary benign sources (see methodology,")
    print("Phase 0: real sites = supplementary diversity, not the primary source).")
    print("=" * 60 + "\n")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default="data/raw")
    ap.add_argument("--output", default="reports/eda/real_vs_scripted")
    args = ap.parse_args()

    os.makedirs(args.output, exist_ok=True)
    df = load_raw(args.input)
    if df.empty:
        print("No benign records found in data/raw. Run the lab and/or real-site "
              "drivers first.")
        return 1
    if df["source_type"].nunique() < 2:
        print(f"Only one source_type present ({sorted(df['source_type'].unique())}). "
              "Run both run_benign_generation.py/benign_driver.py (scripted) AND "
              "real_sites_driver.py (real) before comparing.")
        return 1

    make_charts(df, args.output)
    print(f"[charts] {args.output}/ (5 charts, {len(df)} benign records)")
    print_summary(df)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
