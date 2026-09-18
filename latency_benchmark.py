"""
latency_benchmark.py - priority 2: does this run fast enough for a real WAF?

THREE measurements, not one:
  A. Worst-case: every request pays the full cascade cost (feature extract
     -> stage1 -> stage2 -> open-set ensemble), regardless of stage1's own
     decision. This is what the first version of this script measured -
     185ms/request, 5.4 req/s - and it's a real, useful CEILING number, but
     it does not reflect how a WAF would actually be deployed.
  B. Gated (realistic): stage1 runs on every request (it's cheap, ~1.2ms).
     Only requests stage1 flags malicious continue to stage2 + the open-set
     ensemble - benign-gated requests stop there, exactly like a real cascade
     classifier / any tiered IDS pipeline is designed to work. Measured using
     test.jsonl's ACTUAL benign/malicious mix (8.8% malicious), plus a
     sensitivity table across hypothetical malicious-traffic rates (1%-100%)
     since production traffic composition isn't necessarily like the curated
     test split.
  C. Batching: for the minority of requests that DO reach the expensive
     open-set stage, how much does scoring them in batches (vs. one at a
     time) help - the next lever if gating alone isn't enough throughput.

usage:
  python3 latency_benchmark.py
  python3 latency_benchmark.py --n 5000
"""
import argparse
import json
import os
import sys
import time

import joblib
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "src", "features"))
import train_baseline as tb  # noqa: E402
import extract_features as EF  # noqa: E402

SPLITS_DIR = tb.SPLITS_DIR
MODELS_DIR = tb.MODELS_DIR
OUT_DIR = "reports/latency"
SENSITIVITY_RATES = [0.01, 0.05, 0.10, 0.20, 0.30, 1.00]
BATCH_SIZES = [1, 10, 50, 100, 300]


def percentile(arr, p):
    return float(np.percentile(arr, p))


def summarize(times_ms, label):
    arr = np.array(times_ms)
    return {
        "label": label, "n": len(arr),
        "mean_ms": float(arr.mean()), "median_ms": percentile(arr, 50),
        "p95_ms": percentile(arr, 95), "p99_ms": percentile(arr, 99),
        "max_ms": float(arr.max()), "throughput_per_sec": float(1000.0 / arr.mean()),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=3000)
    args = ap.parse_args()

    print("[load] deployed models (stage1, stage2, open-set ensemble)...")
    stage1 = joblib.load(os.path.join(MODELS_DIR, "stage1_xgboost.joblib"))
    stage2 = joblib.load(os.path.join(MODELS_DIR, "stage2_xgboost.joblib"))
    forests = joblib.load(os.path.join(MODELS_DIR, "openset_isoforest.joblib"))
    with open(os.path.join(MODELS_DIR, "openset_ensemble_config.json"), encoding="utf-8") as f:
        calib = json.load(f)

    print(f"[load] {args.n} raw test records (full record, to time feature extraction too)...")
    records = []
    with open(os.path.join(SPLITS_DIR, "test.jsonl"), encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    records = records[:args.n]
    n_malicious_real = sum(1 for r in records if r["label"]["level1"] == "malicious")
    real_rate = n_malicious_real / len(records)
    print(f"[load] timing on {len(records)} requests, one at a time (single-threaded, CPU)  "
          f"(real malicious rate in this sample: {100*real_rate:.1f}%)")

    # ---- A: worst-case, every request pays full cost ----
    feat_times, stage1_times, stage2_times, iso_times, ensemble_times, total_times = [], [], [], [], [], []
    # ---- B: gated, per-request cost depends on stage1's OWN decision ----
    benign_path_times, malicious_path_times = [], []
    malicious_rows_for_batching = []

    for rec in records:
        t_start = time.perf_counter()

        t0 = time.perf_counter()
        feats = EF.compute_features(rec)
        feats["inter_arrival_ms"] = 0
        feats["request_rate_window"] = 1
        t1 = time.perf_counter()
        feat_ms = (t1 - t0) * 1000
        feat_times.append(feat_ms)

        X = tb.featurize([feats])

        t0 = time.perf_counter()
        bin_pred = stage1.predict(X)
        t1 = time.perf_counter()
        stage1_ms = (t1 - t0) * 1000
        stage1_times.append(stage1_ms)

        gated_so_far = feat_ms + stage1_ms

        t0 = time.perf_counter()
        proba = stage2.predict_proba(X)
        t1 = time.perf_counter()
        stage2_times.append((t1 - t0) * 1000)

        t0 = time.perf_counter()
        iso_raw = np.mean([-f.score_samples(X[:, tb.ISO_FEATURE_IDX]) for f in forests], axis=0)
        t1 = time.perf_counter()
        iso_times.append((t1 - t0) * 1000)

        t0 = time.perf_counter()
        zi = (iso_raw - calib["iso_mu"]) / calib["iso_sd"]
        zs = (1.0 - proba.max(axis=1) - calib["sm_mu"]) / calib["sm_sd"]
        _score = (zi + zs) / 2.0
        t1 = time.perf_counter()
        ensemble_times.append((t1 - t0) * 1000)

        t_end = time.perf_counter()
        total_times.append((t_end - t_start) * 1000)

        # gated cost: benign-flagged requests stop after stage1
        if bin_pred[0] == 0:
            benign_path_times.append(gated_so_far)
        else:
            malicious_path_times.append((t_end - t_start) * 1000)
            malicious_rows_for_batching.append(X[0])

    stages = [
        summarize(feat_times, "feature_extraction"),
        summarize(stage1_times, "stage1_predict"),
        summarize(stage2_times, "stage2_predict_proba"),
        summarize(iso_times, "isoforest_bag_score (5 forests)"),
        summarize(ensemble_times, "ensemble_combine"),
        summarize(total_times, "TOTAL_end_to_end (worst case - every request)"),
    ]

    print(f"\n[A] WORST CASE - every request pays full cascade cost")
    print(f"{'stage':40} {'mean(ms)':>10} {'p95(ms)':>9} {'req/sec':>10}")
    print("-" * 74)
    for s in stages:
        print(f"{s['label']:40} {s['mean_ms']:10.3f} {s['p95_ms']:9.3f} {s['throughput_per_sec']:10.1f}")

    # ---- B: gated, measured on the real test-split mix + sensitivity table ----
    mean_benign_path = float(np.mean(benign_path_times)) if benign_path_times else 0.0
    mean_malicious_path = float(np.mean(malicious_path_times)) if malicious_path_times else 0.0
    measured_gated_mean = (len(benign_path_times) * mean_benign_path +
                            len(malicious_path_times) * mean_malicious_path) / len(records)

    print(f"\n[B] GATED (realistic) - stage2/open-set only run when stage1 flags malicious")
    print(f"  benign-path cost (stage1 only):     {mean_benign_path:.3f} ms  (n={len(benign_path_times)})")
    print(f"  malicious-path cost (full cascade): {mean_malicious_path:.3f} ms  (n={len(malicious_path_times)})")
    print(f"  measured on this sample's real mix ({100*real_rate:.1f}% malicious): "
          f"{measured_gated_mean:.3f} ms/req  ({1000/measured_gated_mean:.1f} req/s)")

    sensitivity = []
    print(f"\n  sensitivity to malicious-traffic rate (hypothetical deployment scenarios):")
    print(f"  {'malicious rate':>16} {'avg latency (ms)':>18} {'throughput (req/s)':>20}")
    for rate in SENSITIVITY_RATES:
        blended = (1 - rate) * mean_benign_path + rate * mean_malicious_path
        sensitivity.append({"malicious_rate": rate, "avg_latency_ms": blended,
                             "throughput_per_sec": 1000.0 / blended})
        print(f"  {100*rate:>15.0f}% {blended:>18.3f} {1000/blended:>20.1f}")

    # ---- C: batching benefit for the malicious-flagged (expensive-path) subset ----
    print(f"\n[C] BATCHING - scoring the malicious-flagged subset in batches vs. one at a time")
    batch_results = []
    if len(malicious_rows_for_batching) >= max(BATCH_SIZES):
        X_mal = np.vstack(malicious_rows_for_batching)
        for bs in BATCH_SIZES:
            n_batches = len(X_mal) // bs
            t0 = time.perf_counter()
            for i in range(n_batches):
                chunk = X_mal[i * bs:(i + 1) * bs]
                _ = np.mean([-f.score_samples(chunk[:, tb.ISO_FEATURE_IDX]) for f in forests], axis=0)
            t1 = time.perf_counter()
            per_req_ms = (t1 - t0) * 1000 / (n_batches * bs)
            batch_results.append({"batch_size": bs, "ms_per_request": per_req_ms,
                                   "throughput_per_sec": 1000.0 / per_req_ms})
            print(f"  batch_size={bs:4d}  {per_req_ms:8.3f} ms/req  ({1000/per_req_ms:8.1f} req/s)")
    else:
        print(f"  not enough malicious-flagged rows in this sample ({len(malicious_rows_for_batching)}) "
              f"to test the largest batch size ({max(BATCH_SIZES)}) - skipped")

    os.makedirs(OUT_DIR, exist_ok=True)
    with open(os.path.join(OUT_DIR, "latency_benchmark.json"), "w", encoding="utf-8") as f:
        json.dump({
            "n_requests": len(records), "real_malicious_rate": real_rate,
            "worst_case_stages": stages,
            "gated": {
                "mean_benign_path_ms": mean_benign_path,
                "mean_malicious_path_ms": mean_malicious_path,
                "measured_on_real_mix_ms": measured_gated_mean,
                "measured_throughput_per_sec": 1000.0 / measured_gated_mean,
                "sensitivity": sensitivity,
            },
            "batching": batch_results,
        }, f, indent=2)

    fig, axes = plt.subplots(1, 3, figsize=(16, 4.6))
    stage_labels = [s["label"] for s in stages[:-1]]
    stage_means = [s["mean_ms"] for s in stages[:-1]]
    axes[0].bar(stage_labels, stage_means, color="#3454a5")
    axes[0].set_ylabel("mean latency (ms)")
    axes[0].set_title("Per-stage latency (worst case)")
    axes[0].tick_params(axis="x", rotation=30)
    for tick in axes[0].get_xticklabels():
        tick.set_ha("right")

    rates = [s["malicious_rate"] * 100 for s in sensitivity]
    tputs = [s["throughput_per_sec"] for s in sensitivity]
    axes[1].plot(rates, tputs, marker="o", color="#0f766e")
    axes[1].axvline(real_rate * 100, color="#b45309", linestyle="--", linewidth=1,
                     label=f"measured mix ({100*real_rate:.1f}%)")
    axes[1].set_xlabel("assumed malicious traffic rate (%)")
    axes[1].set_ylabel("throughput (req/sec)")
    axes[1].set_title("Gated throughput vs. traffic composition")
    axes[1].legend(fontsize=8)

    if batch_results:
        bsizes = [b["batch_size"] for b in batch_results]
        btputs = [b["throughput_per_sec"] for b in batch_results]
        axes[2].plot(bsizes, btputs, marker="o", color="#b91c1c")
        axes[2].set_xscale("log")
        axes[2].set_xlabel("batch size (malicious-flagged requests)")
        axes[2].set_ylabel("throughput (req/sec)")
        axes[2].set_title("Batching benefit on the expensive path")

    plt.tight_layout()
    plt.savefig(os.path.join(OUT_DIR, "latency_summary.png"), dpi=130)
    plt.close()

    print(f"\n[done] -> {OUT_DIR}/latency_benchmark.json, {OUT_DIR}/latency_summary.png")


if __name__ == "__main__":
    main()
