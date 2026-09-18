"""
tune_isoforest_latency.py - find a faster n_estimators setting that keeps
the stability win from the 5-forest bag fix (2026-09-10).

The bagged fix (5 forests x 200 trees x max_samples=full) solved the seed-
instability problem but costs ~185ms/request (5.4 req/sec) - not viable for
an inline WAF. A quick probe showed latency scales roughly with tree COUNT,
not max_samples, so this sweeps n_estimators (trees per forest) at a FIXED
max_samples=full (keeps the stability mechanism intact) and measures, for
each setting, across 5 seeds:
  - open-set recall / known-reject cost / cross_app accuracy (mean +/- std)
  - per-request scoring latency (ms)
so the tradeoff is visible in one place instead of guessed at.

usage:
  python3 tune_isoforest_latency.py
"""
import json
import os
import sys
import time

import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import xgboost as xgb
from sklearn.ensemble import IsolationForest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import train_baseline as tb  # noqa: E402

SPLITS_DIR = tb.SPLITS_DIR
OUT_DIR = "reports/latency"
SEEDS = [1, 2, 3, 42, 100]
N_ESTIMATORS_OPTIONS = [50, 100, 150, 200]
N_BAG = tb.N_BAG


def fit_ensemble(stage2, X_train_m, X_val_m, seed, n_estimators):
    forests = []
    for i in range(N_BAG):
        f = IsolationForest(n_estimators=n_estimators, max_samples=len(X_train_m),
                             contamination="auto", random_state=seed * 1000 + i, n_jobs=-1)
        f.fit(X_train_m[:, tb.ISO_FEATURE_IDX])
        forests.append(f)

    def iso_score(X):
        return np.mean([-f.score_samples(X[:, tb.ISO_FEATURE_IDX]) for f in forests], axis=0)

    def softmax_score(X):
        return 1.0 - stage2.predict_proba(X).max(axis=1)

    iso_val, sm_val = iso_score(X_val_m), softmax_score(X_val_m)
    iso_mu, iso_sd = float(iso_val.mean()), max(float(iso_val.std()), 1e-9)
    sm_mu, sm_sd = float(sm_val.mean()), max(float(sm_val.std()), 1e-9)

    def scorer(X):
        zi = (iso_score(X) - iso_mu) / iso_sd
        zs = (softmax_score(X) - sm_mu) / sm_sd
        return (zi + zs) / 2.0

    return forests, scorer


def cascade_acc(stage1, stage2, scorer, thr, X, cls_list):
    yb = stage1.predict(X)
    pi = stage2.predict_proba(X).argmax(axis=1)
    us = scorer(X)
    final = []
    for i in range(len(X)):
        if yb[i] == 0:
            final.append("benign")
        elif us[i] > thr:
            final.append("unknown")
        else:
            final.append(tb.CLASS_NAMES[pi[i]])

    def ok(p, t):
        return p == "unknown" if t == "code_injection" else p == t
    return sum(ok(f, t) for f, t in zip(final, cls_list)) / len(cls_list)


def measure_latency(forests, X_sample):
    t0 = time.perf_counter()
    for row in X_sample:
        X1 = row.reshape(1, -1)
        _ = np.mean([-f.score_samples(X1[:, tb.ISO_FEATURE_IDX]) for f in forests], axis=0)
    t1 = time.perf_counter()
    return (t1 - t0) / len(X_sample) * 1000


def main():
    print("[load] train (real+injected), val, test, cross_app_test, heldout_unknown...")
    tr_feats, tr_l1, tr_cls, _ = tb.load_split(os.path.join(SPLITS_DIR, "train.jsonl"))
    inj_feats, inj_l1, inj_cls, _ = tb.load_split(os.path.join(SPLITS_DIR, "injected_train.jsonl"))
    train_feats = tr_feats + inj_feats
    train_l1 = tr_l1 + inj_l1
    train_cls = tr_cls + inj_cls

    val_feats, _, val_cls, _ = tb.load_split(os.path.join(SPLITS_DIR, "val.jsonl"))
    test_feats, _, test_cls, _ = tb.load_split(os.path.join(SPLITS_DIR, "test.jsonl"))
    cross_feats, _, cross_cls, _ = tb.load_split(os.path.join(SPLITS_DIR, "cross_app_test.jsonl"))
    held_feats, _, held_cls, _ = tb.load_split(os.path.join(SPLITS_DIR, "heldout_unknown.jsonl"))

    X_train = tb.featurize(train_feats)
    y_train_bin = np.array([1 if l == "malicious" else 0 for l in train_l1])
    train_known = np.array([c in tb.CLASS_TO_IDX for c in train_cls])
    X_train_m = X_train[train_known]
    y_train_m = np.array([tb.CLASS_TO_IDX[c] for c in np.array(train_cls)[train_known]])

    X_val = tb.featurize(val_feats)
    val_known = np.array([c in tb.CLASS_TO_IDX for c in val_cls])
    X_val_m = X_val[val_known]

    X_test = tb.featurize(test_feats)
    X_cross = tb.featurize(cross_feats)
    X_held = tb.featurize(held_feats)
    X_latency_sample = X_test[:300]

    # stage1/stage2 don't depend on n_estimators - fit ONCE per seed, reuse across settings
    stage_cache = {}
    for seed in SEEDS:
        n_pos, n_neg = y_train_bin.sum(), len(y_train_bin) - y_train_bin.sum()
        stage1 = xgb.XGBClassifier(random_state=seed, eval_metric="logloss",
                                    scale_pos_weight=n_neg / max(n_pos, 1), n_jobs=-1)
        stage1.fit(X_train, y_train_bin)
        stage2 = xgb.XGBClassifier(random_state=seed, eval_metric="mlogloss",
                                    num_class=len(tb.CLASS_NAMES), objective="multi:softprob", n_jobs=-1)
        stage2.fit(X_train_m, y_train_m)
        stage_cache[seed] = (stage1, stage2)
        print(f"[prep] stage1+stage2 fitted for seed={seed}")

    results = {}
    for n_est in N_ESTIMATORS_OPTIONS:
        print(f"\n{'='*70}\nn_estimators={n_est}\n{'='*70}")
        recalls, costs, cross_accs, latencies = [], [], [], []
        for seed in SEEDS:
            stage1, stage2 = stage_cache[seed]
            forests, scorer = fit_ensemble(stage2, X_train_m, X_val_m, seed, n_est)
            known_score = scorer(X_val_m)
            unknown_score = scorer(X_held)
            thr, recall, cost = tb.sweep_threshold(known_score, unknown_score)
            cross_acc = cascade_acc(stage1, stage2, scorer, thr, X_cross, cross_cls)
            lat = measure_latency(forests, X_latency_sample)
            recalls.append(recall)
            costs.append(cost)
            cross_accs.append(cross_acc)
            latencies.append(lat)
            print(f"  seed={seed}  recall={recall*100:.1f}  cost={cost*100:.1f}  "
                  f"cross_app={cross_acc*100:.1f}  latency={lat:.1f}ms")
        results[n_est] = {
            "recall_mean": float(np.mean(recalls)), "recall_std": float(np.std(recalls)),
            "cost_mean": float(np.mean(costs)), "cost_std": float(np.std(costs)),
            "cross_app_mean": float(np.mean(cross_accs)), "cross_app_std": float(np.std(cross_accs)),
            "latency_ms_mean": float(np.mean(latencies)),
        }
        r = results[n_est]
        print(f"  -> recall={r['recall_mean']*100:.1f}±{r['recall_std']*100:.1f}  "
              f"cross_app={r['cross_app_mean']*100:.1f}±{r['cross_app_std']*100:.1f}  "
              f"latency={r['latency_ms_mean']:.1f}ms ({1000/r['latency_ms_mean']:.1f} req/s)")

    os.makedirs(OUT_DIR, exist_ok=True)
    with open(os.path.join(OUT_DIR, "isoforest_tuning.json"), "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    fig, axes = plt.subplots(1, 3, figsize=(15, 4.5))
    xs = N_ESTIMATORS_OPTIONS
    axes[0].errorbar(xs, [results[n]["recall_mean"] * 100 for n in xs],
                      yerr=[results[n]["recall_std"] * 100 for n in xs], marker="o", color="#0f766e")
    axes[0].set_title("Open-set recall vs. trees/forest")
    axes[0].set_xlabel("n_estimators")
    axes[0].set_ylabel("recall (%)")

    axes[1].errorbar(xs, [results[n]["cross_app_mean"] * 100 for n in xs],
                      yerr=[results[n]["cross_app_std"] * 100 for n in xs], marker="o", color="#3454a5")
    axes[1].set_title("Cross-app accuracy vs. trees/forest")
    axes[1].set_xlabel("n_estimators")
    axes[1].set_ylabel("accuracy (%)")

    axes[2].plot(xs, [results[n]["latency_ms_mean"] for n in xs], marker="o", color="#b45309")
    axes[2].set_title("Latency vs. trees/forest")
    axes[2].set_xlabel("n_estimators")
    axes[2].set_ylabel("ms/request")

    plt.tight_layout()
    plt.savefig(os.path.join(OUT_DIR, "isoforest_tuning.png"), dpi=130)
    plt.close()

    print(f"\n[done] -> {OUT_DIR}/isoforest_tuning.json, {OUT_DIR}/isoforest_tuning.png")


if __name__ == "__main__":
    main()
