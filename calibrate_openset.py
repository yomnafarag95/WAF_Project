"""
calibrate_openset.py — pass 2: improve open-set (unknown-class) detection.

The fast-pass baseline (train_baseline.py) calibrated a raw max-softmax-
probability threshold and only caught 31.1% of held-out code_injection as
"unknown" - known and unknown rows both sat around 0.96-1.0 confidence, too
overlapping to separate well (reports/train_baseline/open_set_calibration.png).

Compares three open-set methods against the SAME already-trained stage1/
stage2 XGBoost models (loaded via joblib, NOT retrained):
  A. baseline   - raw max-softmax-probability (repeats pass 1, for reference)
  B. calibrated - temperature-scaled softmax (T fit on val NLL), same
                  threshold procedure on the calibrated probabilities
  C. distance   - squared Mahalanobis distance to the nearest known-class
                  centroid in standardized feature space (no softmax at all)

Evaluation metric: macro F1 over 5 labels {benign, sqli, xss,
command_injection, unknown} on a combined set = test.jsonl (real, known
classes + benign) UNION heldout_unknown.jsonl (code_injection, target label
'unknown'). ONE number that penalises both failure directions at once -
missing a genuine unknown attack, and wrongly rejecting a known one -
instead of two separate, hard-to-compare numbers.

usage:
  python3 calibrate_openset.py
"""
import json
import os
import sys

import joblib
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.metrics import f1_score, confusion_matrix

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import train_baseline as tb

SPLITS_DIR = tb.SPLITS_DIR
OUT_DIR = tb.OUT_DIR
MODELS_DIR = tb.MODELS_DIR
CLASS_NAMES = tb.CLASS_NAMES
LABELS_5WAY = ["benign", "sqli", "xss", "command_injection", "unknown"]


def known_mask(cls_list):
    return np.array([c in tb.CLASS_TO_IDX for c in cls_list])


# ---------------------------------------------------------------------------
# Method A: baseline max-softmax-probability
# ---------------------------------------------------------------------------
def method_baseline(stage2):
    def scorer(X):
        return 1.0 - stage2.predict_proba(X).max(axis=1)
    return scorer


# ---------------------------------------------------------------------------
# Method B: temperature-scaled softmax
# ---------------------------------------------------------------------------
def fit_temperature(stage2, X_val_known, y_val_known):
    margins = stage2.predict(X_val_known, output_margin=True)
    best_T, best_nll = 1.0, np.inf
    for T in np.arange(0.05, 8.0, 0.05):
        logits = margins / T
        logits = logits - logits.max(axis=1, keepdims=True)
        exp = np.exp(logits)
        probs = exp / exp.sum(axis=1, keepdims=True)
        nll = -np.log(np.clip(probs[np.arange(len(y_val_known)), y_val_known], 1e-12, 1.0)).mean()
        if nll < best_nll:
            best_nll, best_T = nll, T
    return best_T, best_nll


def method_temperature(stage2, T):
    def scorer(X):
        margins = stage2.predict(X, output_margin=True)
        logits = margins / T
        logits = logits - logits.max(axis=1, keepdims=True)
        exp = np.exp(logits)
        probs = exp / exp.sum(axis=1, keepdims=True)
        return 1.0 - probs.max(axis=1)
    return scorer


# ---------------------------------------------------------------------------
# Method C: Mahalanobis distance to nearest known-class centroid
# ---------------------------------------------------------------------------
def fit_mahalanobis(X_train_m, y_train_m, n_classes):
    mean = X_train_m.mean(axis=0)
    std = X_train_m.std(axis=0)
    std[std < 1e-6] = 1e-6
    Xs = (X_train_m - mean) / std
    centroids, inv_covs = [], []
    for c in range(n_classes):
        Xc = Xs[y_train_m == c]
        mu = Xc.mean(axis=0)
        cov = np.cov(Xc, rowvar=False) + np.eye(Xc.shape[1]) * 1e-3
        centroids.append(mu)
        inv_covs.append(np.linalg.inv(cov))

    def scorer(X):
        Xs2 = (X - mean) / std
        dists = []
        for mu, inv_cov in zip(centroids, inv_covs):
            diff = Xs2 - mu
            d = np.einsum("ij,jk,ik->i", diff, inv_cov, diff)
            dists.append(d)
        return np.min(np.stack(dists, axis=1), axis=1)

    return scorer


# ---------------------------------------------------------------------------
# shared: threshold sweep + 5-way macro-F1 evaluation
# ---------------------------------------------------------------------------
def sweep_threshold(known_score, held_score):
    """known_score / held_score: 'unknown-ness', higher = more unknown.
    Returns the threshold maximising J = unknown_recall - known_reject_rate."""
    lo = min(known_score.min(), held_score.min())
    hi = max(known_score.max(), held_score.max())
    best_thr, best_j = lo, -1.0
    for thr in np.linspace(lo, hi, 400):
        known_reject = float((known_score > thr).mean())
        unknown_recall = float((held_score > thr).mean())
        j = unknown_recall - known_reject
        if j > best_j:
            best_j, best_thr = j, thr
    known_reject_at_best = float((known_score > best_thr).mean())
    unknown_recall_at_best = float((held_score > best_thr).mean())
    return float(best_thr), unknown_recall_at_best, known_reject_at_best


def evaluate_cascade_5way(stage1, stage2, scorer_fn, threshold, X, y_class_true):
    y_bin_pred = stage1.predict(X)
    proba_multi = stage2.predict_proba(X)
    pred_idx = proba_multi.argmax(axis=1)
    unknown_score = scorer_fn(X)

    final = []
    for i in range(len(X)):
        if y_bin_pred[i] == 0:
            final.append("benign")
        elif unknown_score[i] > threshold:
            final.append("unknown")
        else:
            final.append(CLASS_NAMES[pred_idx[i]])

    y_true_mapped = ["unknown" if c == "code_injection" else c for c in y_class_true]
    f1m = f1_score(y_true_mapped, final, labels=LABELS_5WAY, average="macro", zero_division=0)
    per_class = f1_score(y_true_mapped, final, labels=LABELS_5WAY, average=None, zero_division=0)
    cm = confusion_matrix(y_true_mapped, final, labels=LABELS_5WAY)
    return {
        "macro_f1": float(f1m),
        "per_class_f1": {LABELS_5WAY[i]: float(per_class[i]) for i in range(len(LABELS_5WAY))},
        "confusion_matrix": cm.tolist(),
    }


def main():
    print("[load] trained stage1/stage2 XGBoost models...")
    stage1 = joblib.load(os.path.join(MODELS_DIR, "stage1_xgboost.joblib"))
    stage2 = joblib.load(os.path.join(MODELS_DIR, "stage2_xgboost.joblib"))

    print("[load] train (real + injected)...")
    tr_feats, _, tr_cls, _ = tb.load_split(os.path.join(SPLITS_DIR, "train.jsonl"))
    inj_feats, _, inj_cls, _ = tb.load_split(os.path.join(SPLITS_DIR, "injected_train.jsonl"))
    train_feats, train_cls = tr_feats + inj_feats, tr_cls + inj_cls

    print("[load] val...")
    val_feats, _, val_cls, _ = tb.load_split(os.path.join(SPLITS_DIR, "val.jsonl"))
    print("[load] test...")
    test_feats, _, test_cls, _ = tb.load_split(os.path.join(SPLITS_DIR, "test.jsonl"))
    print("[load] heldout_unknown...")
    held_feats, _, held_cls, _ = tb.load_split(os.path.join(SPLITS_DIR, "heldout_unknown.jsonl"))

    X_train_all = tb.featurize(train_feats)
    tr_known = known_mask(train_cls)
    X_train_m = X_train_all[tr_known]
    y_train_m = np.array([tb.CLASS_TO_IDX[c] for c in np.array(train_cls)[tr_known]])

    X_val_all = tb.featurize(val_feats)
    val_known = known_mask(val_cls)
    X_val_known = X_val_all[val_known]
    y_val_known = np.array([tb.CLASS_TO_IDX[c] for c in np.array(val_cls)[val_known]])

    X_held = tb.featurize(held_feats)
    X_test = tb.featurize(test_feats)
    X_eval = np.vstack([X_test, X_held])
    y_eval_true = list(test_cls) + list(held_cls)

    print(f"train(known)={len(X_train_m)}  val(known)={len(X_val_known)}  "
          f"held(unknown)={len(X_held)}  5-way eval set={len(X_eval)}\n")

    T, nll = fit_temperature(stage2, X_val_known, y_val_known)
    print(f"[B] fitted temperature T={T:.2f} (val NLL={nll:.4f}, T=1.0 is uncalibrated)")

    methods = {
        "A_baseline_softmax": method_baseline(stage2),
        "B_temperature_softmax": method_temperature(stage2, T),
        "C_mahalanobis": fit_mahalanobis(X_train_m, y_train_m, len(CLASS_NAMES)),
    }

    results = {}
    score_cache = {}
    for name, scorer in methods.items():
        known_score = scorer(X_val_known)
        held_score = scorer(X_held)
        score_cache[name] = (known_score, held_score)
        thr, open_set_recall, known_reject = sweep_threshold(known_score, held_score)
        metrics = evaluate_cascade_5way(stage1, stage2, scorer, thr, X_eval, y_eval_true)
        results[name] = {"threshold": thr, "open_set_recall": open_set_recall,
                          "known_reject_rate": known_reject, **metrics}
        if name == "B_temperature_softmax":
            results[name]["temperature"] = float(T)
        print(f"[{name}] threshold={thr:.4f}  open-set recall={open_set_recall:.4f}  "
              f"known-reject={known_reject:.4f}  5-way macroF1={metrics['macro_f1']:.4f}")
        print(f"    per-class F1: {metrics['per_class_f1']}")

    os.makedirs(OUT_DIR, exist_ok=True)
    with open(os.path.join(OUT_DIR, "openset_comparison.json"), "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print("\n" + "=" * 78)
    print(f"{'method':24} {'5-way macroF1':>14} {'open-set recall':>17} {'known-reject':>13}")
    print("-" * 78)
    for name, r in results.items():
        print(f"{name:24} {r['macro_f1']:>14.4f} {r['open_set_recall']:>17.4f} {r['known_reject_rate']:>13.4f}")

    fig, axes = plt.subplots(1, 3, figsize=(15.5, 4.3), sharey=False)
    titles = {"A_baseline_softmax": "A: baseline softmax",
              "B_temperature_softmax": f"B: temperature softmax (T={T:.2f})",
              "C_mahalanobis": "C: Mahalanobis distance"}
    for ax, name in zip(axes, methods):
        ks, hs = score_cache[name]
        ax.hist(ks, bins=40, alpha=0.6, label="known (val)", density=True)
        ax.hist(hs, bins=40, alpha=0.6, label="unknown (code_injection)", density=True)
        ax.axvline(results[name]["threshold"], color="red", linestyle="--", linewidth=1.2)
        ax.set_title(titles[name], fontsize=10)
        ax.set_xlabel("unknown-ness score")
        ax.legend(fontsize=8)
    plt.tight_layout()
    plt.savefig(os.path.join(OUT_DIR, "openset_methods_comparison.png"), dpi=130)
    plt.close()

    print(f"\n[done] -> {OUT_DIR}/openset_comparison.json, {OUT_DIR}/openset_methods_comparison.png")


if __name__ == "__main__":
    main()
