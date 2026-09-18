"""
multi_seed_eval.py - priority 1: is 67.5%/58.2% a reliable number, or luck?

Retrains stage1 + stage2 + the method-E open-set ensemble from scratch across
5 random seeds, on the SAME full dataset (no resampling - this isolates
algorithmic randomness: tree induction, IsolationForest bagging, from the
subsampling instability the learning curve already found). Evaluates each
run on the same fixed val/test/cross_app_test/heldout_unknown.

Reports mean +/- std instead of a single point estimate for: open-set
recall, known-reject cost, test cascade accuracy, cross_app_test cascade
accuracy. This is the number that should actually be cited, not the
single-seed 67.48%.

usage:
  python3 multi_seed_eval.py
"""
import json
import os
import sys

import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import xgboost as xgb

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import train_baseline as tb  # noqa: E402

SPLITS_DIR = tb.SPLITS_DIR
OUT_DIR = "reports/multi_seed"
SEEDS = [1, 2, 3, 42, 100]


def cascade_accuracy(stage1, stage2, scorer, threshold, X, cls_list):
    y_bin_pred = stage1.predict(X)
    proba_multi = stage2.predict_proba(X)
    pred_idx = proba_multi.argmax(axis=1)
    unknown_score = scorer(X)
    final = []
    for i in range(len(X)):
        if y_bin_pred[i] == 0:
            final.append("benign")
        elif unknown_score[i] > threshold:
            final.append("unknown")
        else:
            final.append(tb.CLASS_NAMES[pred_idx[i]])

    def _correct(pred, true):
        return pred == "unknown" if true == "code_injection" else pred == true

    correct = sum(_correct(f, t) for f, t in zip(final, cls_list))
    return correct / len(cls_list)


def run_seed(seed, X_train, y_train_bin, X_train_m, y_train_m,
             X_val_m, X_test, test_cls, X_cross, cross_cls, X_held, held_cls):
    n_pos, n_neg = y_train_bin.sum(), len(y_train_bin) - y_train_bin.sum()
    stage1 = xgb.XGBClassifier(random_state=seed, eval_metric="logloss",
                                scale_pos_weight=n_neg / max(n_pos, 1), n_jobs=-1)
    stage1.fit(X_train, y_train_bin)

    stage2 = xgb.XGBClassifier(random_state=seed, eval_metric="mlogloss",
                                num_class=len(tb.CLASS_NAMES), objective="multi:softprob", n_jobs=-1)
    stage2.fit(X_train_m, y_train_m)

    _, scorer, _ = tb.fit_open_set_ensemble(stage2, X_train_m, X_val_m, seed=seed)
    known_score = scorer(X_val_m)
    unknown_score = scorer(X_held)
    threshold, recall, cost = tb.sweep_threshold(known_score, unknown_score)

    test_acc = cascade_accuracy(stage1, stage2, scorer, threshold, X_test, test_cls)
    cross_acc = cascade_accuracy(stage1, stage2, scorer, threshold, X_cross, cross_cls)

    return {"seed": seed, "threshold": threshold, "open_set_recall": recall,
            "known_reject_cost": cost, "test_accuracy": test_acc, "cross_app_accuracy": cross_acc}


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

    results = []
    for seed in SEEDS:
        print(f"[seed={seed}] training stage1 + stage2 + method E ensemble from scratch...")
        r = run_seed(seed, X_train, y_train_bin, X_train_m, y_train_m,
                     X_val_m, X_test, test_cls, X_cross, cross_cls, X_held, held_cls)
        results.append(r)
        print(f"  threshold={r['threshold']:.4f}  open-set recall={r['open_set_recall']:.4f}  "
              f"known-reject={r['known_reject_cost']:.4f}  test_acc={r['test_accuracy']:.4f}  "
              f"cross_app_acc={r['cross_app_accuracy']:.4f}")

    metrics = ["open_set_recall", "known_reject_cost", "test_accuracy", "cross_app_accuracy"]
    summary = {}
    for m in metrics:
        vals = [r[m] for r in results]
        summary[m] = {"mean": float(np.mean(vals)), "std": float(np.std(vals)),
                       "min": float(np.min(vals)), "max": float(np.max(vals))}

    print(f"\n{'='*70}\nSUMMARY across {len(SEEDS)} seeds\n{'='*70}")
    for m in metrics:
        s = summary[m]
        print(f"{m:22} mean={s['mean']:.4f}  std={s['std']:.4f}  range=[{s['min']:.4f}, {s['max']:.4f}]")

    os.makedirs(OUT_DIR, exist_ok=True)
    with open(os.path.join(OUT_DIR, "multi_seed_results.json"), "w", encoding="utf-8") as f:
        json.dump({"seeds": SEEDS, "runs": results, "summary": summary}, f, indent=2)

    fig, ax = plt.subplots(figsize=(7.5, 4.8))
    labels = ["open-set\nrecall", "known-reject\ncost", "test\naccuracy", "cross_app\naccuracy"]
    means = [summary[m]["mean"] * 100 for m in metrics]
    stds = [summary[m]["std"] * 100 for m in metrics]
    colors = ["#0f766e", "#b45309", "#3454a5", "#3454a5"]
    bars = ax.bar(labels, means, yerr=stds, capsize=6, color=colors)
    for bar, mean, std in zip(bars, means, stds):
        ax.text(bar.get_x() + bar.get_width() / 2, mean + std + 1.5,
                 f"{mean:.1f}±{std:.1f}%", ha="center", fontsize=9)
    ax.set_ylabel("%")
    ax.set_title(f"Method E — mean ± std across {len(SEEDS)} seeds (same full dataset)")
    ax.set_ylim(0, 110)
    plt.tight_layout()
    plt.savefig(os.path.join(OUT_DIR, "multi_seed_summary.png"), dpi=130)
    plt.close()

    print(f"\n[done] -> {OUT_DIR}/multi_seed_results.json, {OUT_DIR}/multi_seed_summary.png")


if __name__ == "__main__":
    main()
