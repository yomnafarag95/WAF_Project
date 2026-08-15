"""
Project progress checkpoint - "am I on track so far?"

PURPOSE: sample_quality_report.py already gives a GO/NO-GO gate, but it
lumps every app together into one set of charts/checks. This script instead
prints ONE row per expected source (the 3 lab apps + the 3 real sites), so
you can see exactly what has been captured, what is still missing, and
whether each source that DOES have data is actually healthy - without
needing to run feature extraction first.

Run any time, with however much (or little) data/raw currently has:
  python3 src/analysis/progress_report.py --input data/raw

Input : data/raw/*.jsonl (schema_v2 RAW records)
Output: a printed table only (no charts) - for charts, see:
  - src/analysis/sample_quality_report.py       (lab benign, combined)
  - src/analysis/compare_real_vs_scripted.py    (real vs lab, incl. the 3
    real sites broken out individually in 05_apps_by_source_type.png)
"""
import argparse
import glob
import json
import os

import pandas as pd

# name -> "lab" (persona-driven app) | "real" (real-site supplementary benign)
EXPECTED_SOURCES = {
    "juice_shop": "lab",
    "webgoat": "lab",
    "dvwa": "lab",
    "wikipedia": "real",
    "pokeapi": "real",
    "jsonplaceholder": "real",
}
EXPECTED_PERSONAS = 6
MIN_RECORDS_LAB = 40
MIN_RECORDS_REAL = 15
MAX_ERROR_RATE = 0.20


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
                rows.append({
                    "app": meta.get("app"),
                    "persona_id": meta.get("persona_id") or "(none)",
                    "session_id": rec.get("session_id") or "(none)",
                    "status": meta.get("response_status_code"),
                    "url_path": content.get("url_path"),
                    "class": label.get("class"),
                })
    return pd.DataFrame(rows)


def check_source(df: pd.DataFrame, name: str, kind: str):
    sub = df[df["app"] == name]
    if sub.empty:
        return None
    total = len(sub)
    err = sub[sub["status"].fillna(0) >= 400]
    error_rate = (len(err) / total) if total else 1.0
    unique_paths = sub["url_path"].nunique()
    per_session = sub.groupby("session_id").size()
    median_per_session = float(per_session.median()) if not per_session.empty else 0.0
    n_personas = sub[sub["persona_id"] != "(none)"]["persona_id"].nunique()
    not_benign = sorted(set(sub["class"].dropna().unique()) - {"benign"})

    min_records = MIN_RECORDS_LAB if kind == "lab" else MIN_RECORDS_REAL
    ok = total >= min_records and error_rate <= MAX_ERROR_RATE and not not_benign
    if kind == "lab":
        ok = ok and n_personas >= EXPECTED_PERSONAS

    return {
        "app": name, "kind": kind, "total": total, "error_rate": error_rate,
        "unique_paths": unique_paths, "median_per_session": median_per_session,
        "n_personas": n_personas, "not_benign": not_benign, "ok": ok,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default="data/raw")
    args = ap.parse_args()
    df = load_raw(args.input)

    print("\n" + "=" * 78)
    print("PROJECT PROGRESS CHECKPOINT - benign data collection so far")
    print("=" * 78)
    if df.empty:
        print("data/raw is empty - nothing captured yet. Run the collection scripts first.")
        return 1

    missing, results = [], []
    for name, kind in EXPECTED_SOURCES.items():
        r = check_source(df, name, kind)
        if r is None:
            missing.append(name)
            print(f"  [ - ]  {name:16s} not captured yet")
            continue
        results.append(r)
        mark = "PASS" if r["ok"] else "WARN"
        extra = f"personas={r['n_personas']}/{EXPECTED_PERSONAS}" if kind == "lab" else "real site"
        print(
            f"  [{mark}] {name:16s} records={r['total']:<5} "
            f"error_rate={r['error_rate']:.0%}  paths={r['unique_paths']:<4} "
            f"median/session={r['median_per_session']:.0f}  {extra}"
        )
        if r["not_benign"]:
            print(f"         note: non-benign classes present -> {r['not_benign']} "
                  "(expected once you start attack collection)")

    print("-" * 78)
    print(f"Sources captured: {len(results)}/{len(EXPECTED_SOURCES)}")
    if missing:
        print("Still missing    : " + ", ".join(missing))

    all_ok = all(r["ok"] for r in results)
    if missing:
        print("VERDICT: IN PROGRESS - keep collecting the missing sources above.")
        verdict_code = 1
    elif all_ok:
        print("VERDICT: GO - all 6 sources captured and healthy. "
              "Safe to run test_schema.py then merge_jsonl.py.")
        verdict_code = 0
    else:
        print("VERDICT: NO-GO on some sources - fix the WARN rows above before merging.")
        verdict_code = 2
    print("=" * 78 + "\n")
    return verdict_code


if __name__ == "__main__":
    raise SystemExit(main())
