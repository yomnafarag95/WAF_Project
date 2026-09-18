"""
openmax_openset.py - OpenMax (Bendale & Boult, CVPR 2016) open-set scoring,
added as method D alongside the three already compared in calibrate_openset.py
(A: baseline softmax, B: temperature softmax, C: Mahalanobis). Reuses the
ALREADY-TRAINED stage1/stage2 XGBoost models (joblib, no retraining).

WHY: methods A-C all recalibrate or threshold the SAME raw signal (softmax
confidence, or a plain distance-to-centroid). loco_openset_eval.py confirmed
their ~52% recall ceiling is structural, not a code_injection quirk - so the
next real lever is a genuinely different, theoretically grounded open-set
method rather than another threshold trick on the same signal.

OPENMAX ALGORITHM (adapted from image classification to XGBoost logit space):
  1. Activation vector (AV) for a sample = stage2's raw per-class margins
     (xgb's `output_margin=True`, the pre-softmax logits) - the closest
     analog to the paper's penultimate-layer activations for a tree ensemble.
  2. Per class c: take the AVs of TRAINING points stage2 gets right (pred==
     true), compute the mean activation vector (MAV_c).
  3. Fit a Weibull distribution (extreme value theory) to the TAIL (largest
     `TAIL_SIZE`) of eucos-distances from those correct points to MAV_c - the
     tail models how far a genuinely-in-class point can plausibly stray from
     its class center.
  4. At inference: for each class, the Weibull CDF at the sample's distance
     to MAV_c gives w_score(c) - the probability this sample is an EXTREME
     outlier relative to class c. Revise the top-ranked class activations
     down by w_score, and redirect that "shaved off" mass into a new,
     explicit UNKNOWN logit. Softmax over [revised activations, unknown]
     gives an actual unknown-class probability instead of a raw confidence
     gap.
  5. unknown-ness score = that unknown-class probability. Same Youden's-J
     threshold sweep + 5-way macro-F1 evaluation as calibrate_openset.py, so
     method D is directly comparable to A/B/C in the same table.

usage:
  python3 openmax_openset.py
"""
import json
import os
import sys

import joblib
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import train_baseline as tb  # noqa: E402
import calibrate_openset as co  # noqa: E402

SPLITS_DIR = tb.SPLITS_DIR
OUT_DIR = tb.OUT_DIR
MODELS_DIR = tb.MODELS_DIR
CLASS_NAMES = tb.CLASS_NAMES
N_CLASSES = len(CLASS_NAMES)
LABELS_5WAY = co.LABELS_5WAY
TAIL_SIZE = 50
ALPHA = N_CLASSES  # revise all ranks - only 3 classes total


# ---------------------------------------------------------------------------
# fit: per-class mean activation vector + Weibull tail model
# ---------------------------------------------------------------------------
def eucos_distance(v, mu, cos_scale):
    eu = np.linalg.norm(v - mu)
    denom = (np.linalg.norm(v) * np.linalg.norm(mu)) + 1e-9
    cos = 1.0 - (np.dot(v, mu) / denom)
    return eu + cos * cos_scale


def fit_openmax(stage2, X_train_known, y_train_known, n_classes, tail_size=TAIL_SIZE):
    margins = stage2.predict(X_train_known, output_margin=True)
    pred = margins.argmax(axis=1)
    correct = pred == y_train_known

    mavs, weibulls, cos_scales = [], [], []
    for c in range(n_classes):
        pts = margins[correct & (y_train_known == c)]
        mu = pts.mean(axis=0)
        # rough eu/cos scale-matching: mean raw euclidean distance in this class
        raw_eu = np.linalg.norm(pts - mu, axis=1)
        cos_scale = float(raw_eu.mean()) if len(raw_eu) else 1.0
        dists = np.array([eucos_distance(p, mu, cos_scale) for p in pts])
        tail = np.sort(dists)[-min(tail_size, len(dists)):]
        # Weibull MLE on the tail (extreme-value fit), loc pinned at the
        # smallest tail distance so the fit models EXCESS beyond that point.
        from scipy.stats import weibull_min
        shape, loc, scale = weibull_min.fit(tail, floc=tail.min() * 0.99)
        mavs.append(mu)
        weibulls.append((shape, loc, scale))
        cos_scales.append(cos_scale)
    return mavs, weibulls, cos_scales


def openmax_unknown_proba(stage2, X, mavs, weibulls, cos_scales, n_classes, alpha=ALPHA):
    from scipy.stats import weibull_min
    margins = stage2.predict(X, output_margin=True)
    n = len(X)
    revised = margins.copy()
    unknown_logit = np.zeros(n)

    ranks = np.argsort(-margins, axis=1)  # descending, per row
    alpha_weights = [(alpha - i) / alpha for i in range(alpha)]

    for i in range(n):
        for rank_pos in range(min(alpha, n_classes)):
            c = ranks[i, rank_pos]
            shape, loc, scale = weibulls[c]
            d = eucos_distance(margins[i], mavs[c], cos_scales[c])
            w = float(weibull_min.cdf(d, shape, loc=loc, scale=scale))
            w = min(max(w, 0.0), 1.0)
            wt = alpha_weights[rank_pos] * w
            revised[i, c] = margins[i, c] * (1.0 - wt)
            unknown_logit[i] += margins[i, c] * wt

    full = np.concatenate([revised, unknown_logit.reshape(-1, 1)], axis=1)
    full = full - full.max(axis=1, keepdims=True)
    exp = np.exp(full)
    probs = exp / exp.sum(axis=1, keepdims=True)
    return probs[:, -1]  # unknown-class probability = unknown-ness score


def main():
    print("[load] trained stage1/stage2 XGBoost models...")
    stage1 = joblib.load(os.path.join(MODELS_DIR, "stage1_xgboost.joblib"))
    stage2 = joblib.load(os.path.join(MODELS_DIR, "stage2_xgboost.joblib"))

    print("[load] train (real + injected, known classes only)...")
    tr_feats, _, tr_cls, _ = tb.load_split(os.path.join(SPLITS_DIR, "train.jsonl"))
    inj_feats, _, inj_cls, _ = tb.load_split(os.path.join(SPLITS_DIR, "injected_train.jsonl"))
    train_feats, train_cls = tr_feats + inj_feats, tr_cls + inj_cls
    train_known = co.known_mask(train_cls)
    X_train_known = tb.featurize(train_feats)[train_known]
    y_train_known = np.array([tb.CLASS_TO_IDX[c] for c in np.array(train_cls)[train_known]])

    print("[load] val / test / heldout_unknown...")
    val_feats, _, val_cls, _ = tb.load_split(os.path.join(SPLITS_DIR, "val.jsonl"))
    test_feats, _, test_cls, _ = tb.load_split(os.path.join(SPLITS_DIR, "test.jsonl"))
    held_feats, _, held_cls, _ = tb.load_split(os.path.join(SPLITS_DIR, "heldout_unknown.jsonl"))

    val_known = co.known_mask(val_cls)
    X_val_known = tb.featurize(val_feats)[val_known]
    X_held = tb.featurize(held_feats)
    X_test = tb.featurize(test_feats)
    X_eval = np.vstack([X_test, X_held])
    y_eval_true = list(test_cls) + list(held_cls)

    print(f"[openmax] fitting MAV + Weibull tail (tail_size={TAIL_SIZE}) on "
          f"{len(X_train_known)} correctly-classified-eligible train points...")
    mavs, weibulls, cos_scales = fit_openmax(stage2, X_train_known, y_train_known, N_CLASSES)
    for c, (shape, loc, scale) in enumerate(weibulls):
        print(f"    class={CLASS_NAMES[c]:18s} weibull shape={shape:.3f} loc={loc:.3f} scale={scale:.3f}")

    def scorer(X):
        return openmax_unknown_proba(stage2, X, mavs, weibulls, cos_scales, N_CLASSES)

    known_score = scorer(X_val_known)
    held_score = scorer(X_held)
    threshold, open_set_recall, known_reject = co.sweep_threshold(known_score, held_score)
    metrics = co.evaluate_cascade_5way(stage1, stage2, scorer, threshold, X_eval, y_eval_true)

    result = {"threshold": threshold, "open_set_recall": open_set_recall,
              "known_reject_rate": known_reject, **metrics}
    print(f"\n[D_openmax] threshold={threshold:.4f}  open-set recall={open_set_recall:.4f}  "
          f"known-reject={known_reject:.4f}  5-way macroF1={metrics['macro_f1']:.4f}")
    print(f"    per-class F1: {metrics['per_class_f1']}")

    # --- merge into the existing A/B/C comparison file ---
    comp_path = os.path.join(OUT_DIR, "openset_comparison.json")
    with open(comp_path, encoding="utf-8") as f:
        all_results = json.load(f)
    all_results["D_openmax"] = result
    with open(comp_path, "w", encoding="utf-8") as f:
        json.dump(all_results, f, indent=2)

    print("\n" + "=" * 78)
    print(f"{'method':24} {'5-way macroF1':>14} {'open-set recall':>17} {'known-reject':>13}")
    print("-" * 78)
    for name, r in all_results.items():
        print(f"{name:24} {r['macro_f1']:>14.4f} {r['open_set_recall']:>17.4f} {r['known_reject_rate']:>13.4f}")

    fig, ax = plt.subplots(figsize=(6.5, 4.3))
    ax.hist(known_score, bins=40, alpha=0.6, label="known (val)", density=True)
    ax.hist(held_score, bins=40, alpha=0.6, label="unknown (code_injection)", density=True)
    ax.axvline(threshold, color="red", linestyle="--", linewidth=1.2)
    ax.set_title("D: OpenMax (EVT-calibrated) unknown-class probability")
    ax.set_xlabel("unknown-ness score (OpenMax unknown-class probability)")
    ax.legend(fontsize=8)
    plt.tight_layout()
    plt.savefig(os.path.join(OUT_DIR, "openmax_calibration.png"), dpi=130)
    plt.close()

    print(f"\n[done] -> {comp_path} (method D added), {OUT_DIR}/openmax_calibration.png")


if __name__ == "__main__":
    main()
