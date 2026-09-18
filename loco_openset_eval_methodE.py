"""
loco_openset_eval_methodE.py - leave-one-class-out open-set evaluation for the
DEPLOYED method (method E: bagged isolation-forest + softmax ensemble).

WHY: loco_openset_eval.py already asked "is the open-set recall number a
structural property, or a fluke of code_injection specifically?" - but only
for method A (plain softmax). The deployed system uses method E, and every
method-E number reported so far (85.6% recall / 40.9%-51.4% known-reject)
rests on ONE held-out class (code_injection, from Juice Shop only, the
smallest and most syntactically alien payload bank in the project). This
script asks the same question for the model actually in production: rotate
the held-out role across the three real, well-populated known classes
(sqli/xss/command_injection), retraining stage2 (XGBoost) and the isolation
forest bag from scratch each time with that class fully removed, then
calibrate and measure method E exactly as train_baseline.py does.

If the LOCO mean lands far below the current 40.9%/51.4% reject rate, that
means code_injection's unusual syntax (SSTI {{...}}, #{...}) - not method E
itself - is the primary reason the open-set gate over-rejects, which reframes
the "problem" as a hard, honest test case rather than a general weakness.
If the LOCO mean is comparably high, method E is generally conservative
regardless of which class is unknown - a more general property worth stating
plainly.

usage:
  python3 loco_openset_eval_methodE.py
"""
import json
import os
import sys
import time

import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.metrics import f1_score
import xgboost as xgb

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import train_baseline as tb  # noqa: E402

SPLITS_DIR = tb.SPLITS_DIR
OUT_DIR = "reports/loco_openset_methodE"
SEED = tb.SEED
KNOWN_CLASSES = ["sqli", "xss", "command_injection"]
REFERENCE_CODE_INJECTION = {"recall": 0.8561484918793504, "known_reject_val": 0.4093816631130064}


def load_all(names):
    feats, classes, level1s = [], [], []
    for name in names:
        path = os.path.join(SPLITS_DIR, name)
        if not os.path.exists(path):
            continue
        f_, l1_, c_, _ = tb.load_split(path)
        feats += f_
        level1s += l1_
        classes += c_
    return feats, level1s, classes


def run_fold(held_class, all_feats, all_level1, all_classes,
             val_feats, val_level1, val_classes,
             test_feats, test_level1, test_classes,
             pool_feats, pool_classes):
    known_classes = sorted(c for c in KNOWN_CLASSES if c != held_class)
    idx_of = {c: i for i, c in enumerate(known_classes)}

    train_feats_f, train_bin_y = [], []
    train_mc_feats, train_mc_y = [], []
    for f, l1, c in zip(all_feats, all_level1, all_classes):
        if c == held_class:
            continue
        if l1 == "benign":
            train_feats_f.append(f)
            train_bin_y.append(0)
        elif c in known_classes:
            train_feats_f.append(f)
            train_bin_y.append(1)
            train_mc_feats.append(f)
            train_mc_y.append(idx_of[c])

    X_train_bin = tb.featurize(train_feats_f)
    y_train_bin = np.array(train_bin_y)
    X_train_mc = tb.featurize(train_mc_feats)
    y_train_mc = np.array(train_mc_y)

    n_pos, n_neg = y_train_bin.sum(), len(y_train_bin) - y_train_bin.sum()
    stage1 = xgb.XGBClassifier(random_state=SEED, eval_metric="logloss",
                                scale_pos_weight=n_neg / max(n_pos, 1), n_jobs=-1)
    stage1.fit(X_train_bin, y_train_bin)

    stage2 = xgb.XGBClassifier(random_state=SEED, eval_metric="mlogloss",
                                num_class=len(known_classes),
                                objective="multi:softprob", n_jobs=-1)
    stage2.fit(X_train_mc, y_train_mc)

    test_feats_f, test_y = [], []
    for f, l1, c in zip(test_feats, test_level1, test_classes):
        if l1 == "benign" or c in known_classes:
            test_feats_f.append(f)
            test_y.append(1 if l1 == "malicious" else 0)
    X_test = tb.featurize(test_feats_f)
    sanity_f1 = f1_score(test_y, stage1.predict(X_test), pos_label=1, zero_division=0)

    val_feats_f, val_y_mc = [], []
    for f, l1, c in zip(val_feats, val_level1, val_classes):
        if c in known_classes:
            val_feats_f.append(f)
            val_y_mc.append(idx_of[c])
    X_val_known = tb.featurize(val_feats_f)

    held_feats_f = [f for f, c in zip(pool_feats, pool_classes) if c == held_class]
    X_held = tb.featurize(held_feats_f)

    # method E: bagged isoforest + softmax ensemble, fit exactly as in
    # train_baseline.py's real calibration path.
    _, scorer, _ = tb.fit_open_set_ensemble(stage2, X_train_mc, X_val_known, seed=SEED)
    known_score = scorer(X_val_known)
    held_score = scorer(X_held)
    threshold, open_set_recall, known_reject = tb.sweep_threshold(known_score, held_score)

    return {
        "held_class": held_class,
        "known_classes": known_classes,
        "n_train_malicious": int((y_train_bin == 1).sum()),
        "n_val_known": len(X_val_known),
        "n_unknown_proxy": len(X_held),
        "sanity_stage1_f1_on_2_known_classes": float(sanity_f1),
        "threshold": threshold,
        "open_set_recall": open_set_recall,
        "known_reject_rate": known_reject,
    }


def main():
    t0 = time.time()
    print("[load] pooling features across all splits for LOCO folds (method E)...")
    all_feats, all_level1, all_classes = load_all(["train.jsonl", "injected_train.jsonl"])
    val_feats, val_level1, val_classes = load_all(["val.jsonl"])
    test_feats, test_level1, test_classes = load_all(["test.jsonl"])
    pool_feats, _, pool_classes = load_all(
        ["train.jsonl", "injected_train.jsonl", "val.jsonl", "test.jsonl", "cross_app_test.jsonl"])
    print(f"[load] train pool={len(all_feats)}  val={len(val_feats)}  test={len(test_feats)}  "
          f"full pool (unknown-proxy)={len(pool_feats)}")

    results = []
    for held_class in KNOWN_CLASSES:
        print(f"\n{'='*70}\nFOLD (method E): holding out '{held_class}'\n{'='*70}")
        r = run_fold(held_class, all_feats, all_level1, all_classes,
                     val_feats, val_level1, val_classes,
                     test_feats, test_level1, test_classes,
                     pool_feats, pool_classes)
        results.append(r)
        print(f"  trained on: {r['known_classes']} (malicious={r['n_train_malicious']})")
        print(f"  sanity stage1 F1 (2 known classes, test.jsonl): {r['sanity_stage1_f1_on_2_known_classes']:.4f}")
        print(f"  unknown-proxy pool size ({held_class} everywhere): {r['n_unknown_proxy']}")
        print(f"  threshold={r['threshold']:.4f}  open-set recall={r['open_set_recall']:.4f}  "
              f"known-reject={r['known_reject_rate']:.4f}")

    recalls = [r["open_set_recall"] for r in results]
    costs = [r["known_reject_rate"] for r in results]
    mean_recall, std_recall = float(np.mean(recalls)), float(np.std(recalls))
    mean_cost, std_cost = float(np.mean(costs)), float(np.std(costs))

    print(f"\n{'='*70}\nSUMMARY (method E)\n{'='*70}")
    print(f"{'held-out class':20} {'open-set recall':>17} {'known-reject':>13}")
    for r in results:
        print(f"{r['held_class']:20} {r['open_set_recall']:>17.4f} {r['known_reject_rate']:>13.4f}")
    print(f"{'MEAN (3 folds)':20} {mean_recall:>17.4f} {mean_cost:>13.4f}  "
          f"(std_recall={std_recall:.4f}, std_reject={std_cost:.4f})")
    print(f"{'code_injection (ref)':20} {REFERENCE_CODE_INJECTION['recall']:>17.4f} "
          f"{REFERENCE_CODE_INJECTION['known_reject_val']:>13.4f}  (from train_baseline.py, real pipeline)")

    os.makedirs(OUT_DIR, exist_ok=True)
    with open(os.path.join(OUT_DIR, "loco_methodE_results.json"), "w", encoding="utf-8") as f:
        json.dump({
            "folds": results,
            "mean_open_set_recall": mean_recall, "std_open_set_recall": std_recall,
            "mean_known_reject_rate": mean_cost, "std_known_reject_rate": std_cost,
            "reference_code_injection": REFERENCE_CODE_INJECTION,
        }, f, indent=2)

    fig, ax = plt.subplots(figsize=(8, 4.6))
    labels = [r["held_class"] for r in results] + ["code_injection\n(reference)"]
    recall_vals = recalls + [REFERENCE_CODE_INJECTION["recall"]]
    reject_vals = costs + [REFERENCE_CODE_INJECTION["known_reject_val"]]
    x = np.arange(len(labels)); w = 0.35
    ax.bar(x - w/2, [100*v for v in recall_vals], width=w, label="open-set recall", color="#7fb2e0")
    ax.bar(x + w/2, [100*v for v in reject_vals], width=w, label="known-reject rate", color="#e0a3b0")
    ax.set_xticks(x); ax.set_xticklabels(labels)
    ax.set_ylabel("%")
    ax.set_title("Method E: leave-one-class-out vs. the code_injection reference")
    ax.legend(fontsize=9)
    plt.tight_layout()
    plt.savefig(os.path.join(OUT_DIR, "loco_methodE_summary.png"), dpi=130)
    plt.close()

    print(f"\n[done] {time.time()-t0:.1f}s total. -> {OUT_DIR}/loco_methodE_results.json, "
          f"{OUT_DIR}/loco_methodE_summary.png")


if __name__ == "__main__":
    main()
