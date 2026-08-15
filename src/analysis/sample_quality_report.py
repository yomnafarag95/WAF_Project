"""
BENIGN SAMPLE quality report + GO/NO-GO gate for starting attacks.

PURPOSE: after a SMALL benign run (e.g. --sessions-per-persona 2), look at
the raw capture immediately and decide whether the benign pipeline is
healthy enough to invest time in attack generation. It reads the RAW
records directly (data/raw/*.jsonl), so you do NOT need feature extraction
first - you get feedback in seconds, not after the whole pipeline.

It answers three questions:
  1. Is the data being captured at all, and in the right shape?
  2. Is it realistic/healthy (low error rate, diverse paths, all personas
     firing, login actually working)?
  3. Am I READY to start attacks? -> explicit GO / NO-GO verdict.

INPUT : data/raw/*.jsonl        (schema_v2 RAW records from capture_addon.py)
OUTPUT: reports/eda/sample/*.png + a printed checklist + a GO/NO-GO verdict

Run (from project root, after a small benign run):
  python3 src/analysis/sample_quality_report.py --input data/raw --output reports/eda/sample

Only pandas + matplotlib (preinstalled). Never invents data - if data/raw is
empty it tells you the capture produced nothing (a NO-GO in itself).
"""

import argparse
import glob
import json
import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402

# Expected personas (used for the coverage check).
EXPECTED_PERSONAS = 6

# Quality gate thresholds (tune for your own bar).
MIN_RECORDS = 40           # a 2-per-persona sample should clear this easily
MAX_ERROR_RATE = 0.20      # fraction of responses with status >= 400
MIN_UNIQUE_PATHS = 8       # url_path diversity
MIN_MEDIAN_PER_SESSION = 4 # sessions that die after 1 request are useless


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
                raw_req = (content.get("raw_request") or "").lower()
                rows.append({
                    "app": meta.get("app"),
                    "persona_id": meta.get("persona_id") or "(none)",
                    "session_id": rec.get("session_id") or "(none)",
                    "status": meta.get("response_status_code"),
                    "method": content.get("http_method"),
                    "url_path": content.get("url_path"),
                    "class": label.get("class"),
                    "is_authenticated": ("authorization: bearer" in raw_req),
                })
    return pd.DataFrame(rows)


def _bar(series, title, ylabel, outpath, color="#4C72B0", rotate=45):
    ax = series.plot(kind="bar", color=color)
    ax.set_title(title)
    ax.set_ylabel(ylabel)
    ax.tick_params(axis="x", rotation=rotate)
    for i, v in enumerate(series.values):
        ax.text(i, v, str(int(v)), ha="center", va="bottom", fontsize=8)
    plt.tight_layout()
    plt.savefig(outpath, dpi=150)
    plt.close()


def make_charts(df: pd.DataFrame, outdir: str) -> None:
    # 1. persona coverage - did every persona actually produce traffic?
    _bar(df["persona_id"].value_counts(), "Records per persona (coverage)",
         "records", os.path.join(outdir, "01_persona_coverage.png"))

    # 2. status codes - health. Lots of 4xx/5xx == broken selectors/flows.
    status = df["status"].fillna(-1).astype(int).astype(str).value_counts().sort_index()
    _bar(status, "HTTP status codes (health)", "count",
         os.path.join(outdir, "02_status_codes.png"), color="#55A868", rotate=0)

    # 3. method mix.
    _bar(df["method"].value_counts(), "HTTP method mix", "count",
         os.path.join(outdir, "03_http_methods.png"), color="#8172B3", rotate=0)

    # 4. top URL paths - diversity (a healthy benign sample hits many paths).
    top_paths = df["url_path"].value_counts().head(15)[::-1]
    ax = top_paths.plot(kind="barh", color="#C44E52")
    ax.set_title("Top 15 URL paths (diversity)")
    ax.set_xlabel("count")
    plt.tight_layout()
    plt.savefig(os.path.join(outdir, "04_top_url_paths.png"), dpi=150)
    plt.close()

    # 5. requests per session - are sessions long enough to be realistic?
    per_session = df.groupby("session_id").size()
    ax = per_session.plot(kind="hist", bins=15, color="#4C72B0", edgecolor="white")
    ax.set_title("Requests per session")
    ax.set_xlabel("requests")
    plt.tight_layout()
    plt.savefig(os.path.join(outdir, "05_requests_per_session.png"), dpi=150)
    plt.close()

    # 6. authenticated vs guest traffic - did login actually work?
    auth = df["is_authenticated"].map({True: "authenticated", False: "guest"}).value_counts()
    _bar(auth, "Authenticated vs guest requests", "count",
         os.path.join(outdir, "06_auth_vs_guest.png"), color="#DD8452", rotate=0)


def quality_gate(df: pd.DataFrame) -> bool:
    """Print a checklist and return True if it is a GO for attacks."""
    total = len(df)
    per_session = df.groupby("session_id").size()
    median_per_session = float(per_session.median()) if not per_session.empty else 0
    n_personas = df[df["persona_id"] != "(none)"]["persona_id"].nunique()
    unique_paths = df["url_path"].nunique()
    err = df[df["status"].fillna(0) >= 400]
    error_rate = (len(err) / total) if total else 1.0
    n_auth = int(df["is_authenticated"].sum())
    all_benign = set(df["class"].dropna().unique()) <= {"benign"}

    checks = [
        ("Records captured", total >= MIN_RECORDS, f"{total} (need >= {MIN_RECORDS})"),
        ("All personas fired", n_personas >= EXPECTED_PERSONAS, f"{n_personas}/{EXPECTED_PERSONAS}"),
        ("Error rate OK", error_rate <= MAX_ERROR_RATE, f"{error_rate:.0%} (max {MAX_ERROR_RATE:.0%})"),
        ("Path diversity", unique_paths >= MIN_UNIQUE_PATHS, f"{unique_paths} unique (need >= {MIN_UNIQUE_PATHS})"),
        ("Sessions long enough", median_per_session >= MIN_MEDIAN_PER_SESSION, f"median {median_per_session:.0f}/session"),
        ("Login worked (>=1 auth req)", n_auth >= 1, f"{n_auth} authenticated requests"),
        ("Sample is benign-only", all_benign, f"classes={sorted(df['class'].dropna().unique())}"),
    ]

    print("\n" + "=" * 60)
    print("BENIGN SAMPLE QUALITY GATE")
    print("=" * 60)
    hard_fail = False
    for name, ok, detail in checks:
        mark = "PASS" if ok else "FAIL"
        # login is a WARN, not a hard blocker (guests-only is a valid choice)
        if not ok and name.startswith("Login"):
            mark = "WARN"
        elif not ok:
            hard_fail = True
        print(f"  [{mark}] {name:28s} {detail}")

    verdict = not hard_fail
    print("-" * 60)
    if verdict:
        print("  VERDICT: GO - benign capture is healthy. Start attacks now.")
    else:
        print("  VERDICT: NO-GO - fix the FAIL items above BEFORE attacks.")
        print("           (attacks on a broken benign pipeline waste time)")
    print("=" * 60 + "\n")
    return verdict


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default="data/raw")
    ap.add_argument("--output", default="reports/eda/sample")
    args = ap.parse_args()

    os.makedirs(args.output, exist_ok=True)
    df = load_raw(args.input)
    if df.empty:
        print("NO-GO: data/raw has no records. The capture produced nothing - "
              "check that traffic went through the mitmproxy benign proxy (8888).")
        return 1

    make_charts(df, args.output)
    print(f"[charts] {args.output}/ (6 charts, {len(df)} records)")
    is_go = quality_gate(df)
    return 0 if is_go else 2


if __name__ == "__main__":
    raise SystemExit(main())
