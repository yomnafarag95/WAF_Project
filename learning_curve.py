"""
learning_curve.py - "do we need more data?" diagnostic.

Trains stage1 (binary), stage2 (multiclass), AND method E's open-set
ensemble on increasing FRACTIONS of the combined train+injected pool
(stratified by class so the mix stays representative at every size),
evaluating each time on the SAME fixed val/heldout sets. Standard
interpretation:
  - if the validation-score curve has flattened well before 100% of the
    data, and the train/val gap is small, the model has converged - more
    ROWS of the same kind (same apps, same attack patterns) are unlikely to
    help further. The ceiling is model capacity / feature information, not
    data volume.
  - if the validation curve is still visibly rising at 100%, more data
    would plausibly help.

SCOPE NOTE (important, don't over-read this chart): this tests whether we
have enough ROWS. It does NOT test whether we have enough APP DIVERSITY,
which is the more relevant question for the cross_app_test / IsolationForest
generalization problem diagnosed earlier today (see reports/PROGRESS_LOG.md)
- that would need a curve over NUMBER OF DISTINCT APPS included in training,
not number of rows from the same 11 apps. This script does the classic
row-count version; an app-count version is a natural, separate follow-up.

usage:
  python3 learning_curve.py
"""
import json
import os
import random
import sys

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
OUT_DIR = "reports/learning_curve"
SEED = 42
FRACTIONS = [0.02, 0.05, 0.1, 0.2, 0.4, 0.6, 0.8, 1.0]


def stratified_subsample(l1, cls, frac, rng):
    idx_by_key = {}
    for i, (a, b) in enumerate(zip(l1, cls)):
        key = b if a == "malicious" else "benign"
        idx_by_key.setdefault(key, []).append(i)
    keep = []
    for key, idxs in idx_by_key.items():
        n = max(1, int(round(len(idxs) * frac)))
        keep += rng.sample(idxs, min(n, len(idxs)))
    rng.shuffle(keep)
    return keep


def main():
    rng = random.Random(SEED)
    print("[load] train (real+injected), val, heldout_unknown...")
    tr_feats, tr_l1, tr_cls, _ = tb.load_split(os.path.join(SPLITS_DIR, "train.jsonl"))
    inj_feats, inj_l1, inj_cls, _ = tb.load_split(os.path.join(SPLITS_DIR, "injected_train.jsonl"))
    train_feats = tr_feats + inj_feats
    train_l1 = tr_l1 + inj_l1
    train_cls = tr_cls + inj_cls
    print(f"[load] pool = {len(train_feats)} rows")

    val_feats, val_l1, val_cls, _ = tb.load_split(os.path.join(SPLITS_DIR, "val.jsonl"))
    held_feats, _, _, _ = tb.load_split(os.path.join(SPLITS_DIR, "heldout_unknown.jsonl"))

    X_val = tb.featurize(val_feats)
    y_val_bin = np.array([1 if l == "malicious" else 0 for l in val_l1])
    val_known_mask = np.array([c in tb.CLASS_TO_IDX for c in val_cls])
    X_val_m = X_val[val_known_mask]
    y_val_m = np.array([tb.CLASS_TO_IDX[c] for c in np.array(val_cls)[val_known_mask]])
    X_held = tb.featurize(held_feats)

    rows = []
    for frac in FRACTIONS:
        keep = stratified_subsample(train_l1, train_cls, frac, rng)
        sub_feats = [train_feats[i] for i in keep]
        sub_l1 = [train_l1[i] for i in keep]
        sub_cls = [train_cls[i] for i in keep]
        n = len(sub_feats)

        X_sub = tb.featurize(sub_feats)
        y_sub_bin = np.array([1 if l == "malicious" else 0 for l in sub_l1])
        n_pos, n_neg = y_sub_bin.sum(), len(y_sub_bin) - y_sub_bin.sum()
        stage1 = xgb.XGBClassifier(random_state=SEED, eval_metric="logloss",
                                    scale_pos_weight=n_neg / max(n_pos, 1), n_jobs=-1)
        stage1.fit(X_sub, y_sub_bin)
        train_f1_1 = f1_score(y_sub_bin, stage1.predict(X_sub), pos_label=1, zero_division=0)
        val_f1_1 = f1_score(y_val_bin, stage1.predict(X_val), pos_label=1, zero_division=0)

        sub_known = np.array([c in tb.CLASS_TO_IDX for c in sub_cls])
        X_sub_m = X_sub[sub_known]
        y_sub_m = np.array([tb.CLASS_TO_IDX[c] for c in np.array(sub_cls)[sub_known]])
        stage2 = xgb.XGBClassifier(random_state=SEED, eval_metric="mlogloss",
                                    num_class=len(tb.CLASS_NAMES), objective="multi:softprob", n_jobs=-1)
        stage2.fit(X_sub_m, y_sub_m)
        train_f1_2 = f1_score(y_sub_m, stage2.predict(X_sub_m),
                               labels=list(range(3)), average="macro", zero_division=0)
        val_f1_2 = f1_score(y_val_m, stage2.predict(X_val_m),
                             labels=list(range(3)), average="macro", zero_division=0)

        _, scorer, _ = tb.fit_open_set_ensemble(stage2, X_sub_m, X_val_m, seed=SEED)
        known_score = scorer(X_val_m)
        unknown_score = scorer(X_held)
        _, recall, cost = tb.sweep_threshold(known_score, unknown_score)

        rows.append({
            "frac": frac, "n_train_rows": n,
            "stage1_train_f1": float(train_f1_1), "stage1_val_f1": float(val_f1_1),
            "stage2_train_macrof1": float(train_f1_2), "stage2_val_macrof1": float(val_f1_2),
            "openset_recall": recall, "openset_known_reject": cost,
        })
        print(f"[frac={frac:.2f} n={n:6d}] stage1 val F1={val_f1_1:.4f}  "
              f"stage2 val macroF1={val_f1_2:.4f}  openset recall={recall:.4f} (cost={cost:.4f})")

    os.makedirs(OUT_DIR, exist_ok=True)
    with open(os.path.join(OUT_DIR, "learning_curve.json"), "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=2)

    ns = [r["n_train_rows"] for r in rows]
    fig, axes = plt.subplots(1, 3, figsize=(15.5, 4.5))
    axes[0].plot(ns, [r["stage1_train_f1"] for r in rows], "o-", label="train F1")
    axes[0].plot(ns, [r["stage1_val_f1"] for r in rows], "o-", label="val F1")
    axes[0].set_title("Stage 1 (binary) learning curve")
    axes[0].set_xlabel("training rows"); axes[0].set_ylabel("F1"); axes[0].legend(fontsize=8)

    axes[1].plot(ns, [r["stage2_train_macrof1"] for r in rows], "o-", label="train macroF1")
    axes[1].plot(ns, [r["stage2_val_macrof1"] for r in rows], "o-", label="val macroF1")
    axes[1].set_title("Stage 2 (multiclass) learning curve")
    axes[1].set_xlabel("training rows"); axes[1].set_ylabel("macro F1"); axes[1].legend(fontsize=8)

    axes[2].plot(ns, [r["openset_recall"] for r in rows], "o-", label="open-set recall")
    axes[2].plot(ns, [r["openset_known_reject"] for r in rows], "o-", label="known-reject cost")
    axes[2].set_title("Method E open-set learning curve")
    axes[2].set_xlabel("training rows"); axes[2].set_ylabel("rate"); axes[2].legend(fontsize=8)

    for ax in axes:
        ax.set_xscale("log")
    plt.tight_layout()
    plt.savefig(os.path.join(OUT_DIR, "learning_curve.png"), dpi=130)
    plt.close()
    print(f"\n[done] -> {OUT_DIR}/learning_curve.json, {OUT_DIR}/learning_curve.png")


if __name__ == "__main__":
    main()
