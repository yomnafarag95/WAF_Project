"""
isoforest_openset.py - method E: Isolation Forest anomaly score, ensembled
with method A's calibrated softmax score. Reuses the ALREADY-TRAINED stage1/
stage2 XGBoost models (joblib, no retraining) plus a newly fit IsolationForest
(unsupervised, trained once on known-malicious feature vectors - cheap).

WHY: methods A/B/C/D (calibrate_openset.py, openmax_openset.py) all derive
their unknown-ness score from stage2's OWN decision surface (softmax
confidence, distance-to-centroid in the same space, or EVT on stage2's
margins) - so they inherit whatever blind spot stage2 has. An Isolation
Forest fit directly on the malicious feature space is a genuinely
INDEPENDENT signal: it asks "does this point sit in a sparse, isolatable
region of the 26-feature space the known attack classes occupy?" without
ever looking at stage2's predictions. Ensembling an independent signal with
method A is the cheapest way to potentially catch cases A misses, without
committing to a whole new theoretical framework the way OpenMax did (and
which underperformed).

Two ensemble combiners are tried (both on z-scored, val-calibrated signals):
  mean - requires both signals to at least somewhat agree something is off
  max  - flags unknown if EITHER signal fires (logical-OR); more permissive

usage:
  python3 isoforest_openset.py
"""
import json
import os
import sys

import joblib
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.ensemble import IsolationForest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import train_baseline as tb  # noqa: E402
import calibrate_openset as co  # noqa: E402

SPLITS_DIR = tb.SPLITS_DIR
OUT_DIR = tb.OUT_DIR
MODELS_DIR = tb.MODELS_DIR
SEED = tb.SEED


def zscore_fit(x):
    mu, sd = float(np.mean(x)), float(np.std(x))
    sd = sd if sd > 1e-9 else 1e-9
    return mu, sd


def fit_isoforest(X_train_known, seed=SEED):
    """Bag of N_BAG forests, each seeing the FULL training set
    (max_samples=n) - a single default-config forest (max_samples='auto' =
    256 of 15,678 points, 1.6%) was found to be highly seed-unstable
    (multi_seed_eval.py, 2026-09-10: recall std +/-12.6%, cross_app accuracy
    std +/-20.8%). Delegates to train_baseline.fit_open_set_ensemble so this
    script can never drift out of sync with the actual deployed fit."""
    forests = []
    for i in range(tb.N_BAG):
        f = IsolationForest(n_estimators=tb.ISO_N_ESTIMATORS, max_samples=len(X_train_known),
                             contamination="auto", random_state=seed * 1000 + i, n_jobs=-1)
        f.fit(X_train_known[:, tb.ISO_FEATURE_IDX])
        forests.append(f)
    return forests


def build_mean_ensemble_scorer(stage2, forests, X_val_known, alpha=0.5):
    """Fit the val-calibrated z-scoring for method E and return a reusable
    scorer(X) -> unknown-ness score, importable by other scripts (e.g.
    fuzz_adversarial_methodE.py) without refitting anything.

    alpha = isoforest weight, (1-alpha) = softmax weight (default 0.5/0.5,
    the original mean combiner). Exposed 2026-09-12 after finding pure
    softmax (alpha=0) has better static known/unknown AUC (0.853 vs 0.797 at
    alpha=0.5) but that's NOT a safe change on its own - method E was chosen
    over plain softmax specifically for adversarial robustness (52.2%->39.1%
    recall collapse under mutation search, see PROGRESS_LOG 2026-09-09/10).
    Raising alpha (more isoforest, less softmax) is the candidate worth
    testing under the SAME adversarial fuzzer before trusting it - see
    fuzz_adversarial_methodE.py --alpha."""
    def iso_score(X):
        return np.mean([-f.score_samples(X[:, tb.ISO_FEATURE_IDX]) for f in forests], axis=0)

    def softmax_score(X):
        return 1.0 - stage2.predict_proba(X).max(axis=1)

    iso_mu, iso_sd = zscore_fit(iso_score(X_val_known))
    sm_mu, sm_sd = zscore_fit(softmax_score(X_val_known))

    def scorer(X):
        zi = (iso_score(X) - iso_mu) / iso_sd
        zs = (softmax_score(X) - sm_mu) / sm_sd
        return alpha * zi + (1 - alpha) * zs

    return scorer


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

    print(f"[isoforest] fitting {tb.N_BAG}-forest bag on {len(X_train_known)} known-malicious "
          f"training points (unsupervised, no class labels used, "
          f"restricted to {len(tb.ISO_FEATURE_IDX)} payload-content features, "
          f"max_samples=all)...")
    forests = fit_isoforest(X_train_known, seed=SEED)

    def iso_score(X):
        return np.mean([-f.score_samples(X[:, tb.ISO_FEATURE_IDX]) for f in forests], axis=0)  # higher = more anomalous

    def softmax_score(X):
        return 1.0 - stage2.predict_proba(X).max(axis=1)  # method A signal

    # --- calibrate z-scoring on val (known) so both signals share a scale ---
    iso_val, softmax_val = iso_score(X_val_known), softmax_score(X_val_known)
    iso_mu, iso_sd = zscore_fit(iso_val)
    sm_mu, sm_sd = zscore_fit(softmax_val)

    def z_iso(X):
        return (iso_score(X) - iso_mu) / iso_sd

    def z_softmax(X):
        return (softmax_score(X) - sm_mu) / sm_sd

    combiners = {
        "E_isoforest_mean": lambda X: (z_iso(X) + z_softmax(X)) / 2.0,
        "E_isoforest_max": lambda X: np.maximum(z_iso(X), z_softmax(X)),
    }

    comp_path = os.path.join(OUT_DIR, "openset_comparison.json")
    with open(comp_path, encoding="utf-8") as f:
        all_results = json.load(f)

    fig, axes = plt.subplots(1, 2, figsize=(11, 4.3))
    for ax, (name, scorer) in zip(axes, combiners.items()):
        known_score = scorer(X_val_known)
        held_score = scorer(X_held)
        threshold, open_set_recall, known_reject = co.sweep_threshold(known_score, held_score)
        metrics = co.evaluate_cascade_5way(stage1, stage2, scorer, threshold, X_eval, y_eval_true)
        result = {"threshold": threshold, "open_set_recall": open_set_recall,
                  "known_reject_rate": known_reject, **metrics}
        all_results[name] = result
        print(f"\n[{name}] threshold={threshold:.4f}  open-set recall={open_set_recall:.4f}  "
              f"known-reject={known_reject:.4f}  5-way macroF1={metrics['macro_f1']:.4f}")
        print(f"    per-class F1: {metrics['per_class_f1']}")

        ax.hist(known_score, bins=40, alpha=0.6, label="known (val)", density=True)
        ax.hist(held_score, bins=40, alpha=0.6, label="unknown (code_injection)", density=True)
        ax.axvline(threshold, color="red", linestyle="--", linewidth=1.2)
        ax.set_title(name)
        ax.set_xlabel("ensembled unknown-ness z-score")
        ax.legend(fontsize=8)

    with open(comp_path, "w", encoding="utf-8") as f:
        json.dump(all_results, f, indent=2)

    print("\n" + "=" * 78)
    print(f"{'method':24} {'5-way macroF1':>14} {'open-set recall':>17} {'known-reject':>13}")
    print("-" * 78)
    for name, r in all_results.items():
        print(f"{name:24} {r['macro_f1']:>14.4f} {r['open_set_recall']:>17.4f} {r['known_reject_rate']:>13.4f}")

    plt.tight_layout()
    plt.savefig(os.path.join(OUT_DIR, "isoforest_calibration.png"), dpi=130)
    plt.close()

    print(f"\n[done] -> {comp_path} (methods E added), {OUT_DIR}/isoforest_calibration.png")


if __name__ == "__main__":
    main()
