"""
train_baseline.py — Phase 5, pass 1: fast UNTUNED baseline comparison.

Trains Decision Tree, Random Forest, and XGBoost at two cascaded stages:
  Stage 1 (binary):      benign vs malicious
  Stage 2 (multiclass):  sqli / xss / command_injection (malicious rows only)
then calibrates the open-set "unknown attack" decision using val (known
classes) vs heldout_unknown (code_injection — never trained on, at any
stage).

OPEN-SET METHOD (method E, adopted 2026-09-10 after comparing 5 methods —
see reports/PROGRESS_LOG.md and reports/train_baseline/openset_comparison.json
for the full A-E comparison + adversarial-robustness validation): an
IsolationForest fit on the known-malicious feature space (independent of
stage2's own confidence) is ensembled with stage2's calibrated max-softmax
score (mean of both, z-scored on val) into a single unknown-ness score,
thresholded via a Youden's-J sweep. Chosen over plain softmax thresholding
(method A) because it holds up far better under adversarial mutation search
(98.3% vs 39.1% recall after compounding evasion attempts) — see
fuzz_adversarial_methodE.py. The known-attack "mislabeled as unknown" cost
this method accepts is judged cheap: stage1 already blocks that traffic
either way, so it's a labeling error, not a missed detection or a false
block of real users (per-app FPR stays a separate, untouched 0.0000 metric).

This is a DIAGNOSTIC pass: default hyperparameters, no Optuna, no SHAP, no
flat-vs-hierarchical ablation. Its job is to compare model families and
surface real per-class / per-app numbers before deciding where tuning effort
actually pays off — those come in pass 2.

Evaluation protocol:
  train = data/splits/train.jsonl (real) + data/splits/injected_train.jsonl
          (synthetic, train-only by construction)
  val   = data/splits/val.jsonl            - open-set calibration + model compare
  test  = data/splits/test.jsonl           - scored once per model, this pass
  cross_app_test = data/splits/cross_app_test.jsonl  - WebGoat generalisation
  heldout_unknown = data/splits/heldout_unknown.jsonl - code_injection, open-set

NOTE: test/cross_app_test/heldout_unknown are touched here as part of this
diagnostic pass. Once we move to Optuna tuning (pass 2), they should NOT be
re-checked repeatedly during that tuning — only once more, at the end, for
the final chosen configuration.

usage:
  python3 train_baseline.py
"""
import json
import os
import time
from collections import Counter, defaultdict

import joblib
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import f1_score, precision_score, recall_score, confusion_matrix
import xgboost as xgb

SPLITS_DIR = "data/splits"
OUT_DIR = "reports/train_baseline"
MODELS_DIR = "models"
SEED = 42

# surface_diversity_count and 8 hashed ngram3_density_* features were
# tried 2026-09-18 and dropped: despite 2 individual ngram buckets ranking
# well in isolation, the NET effect on the deployed pipeline was a
# regression (Amazon FPR 5->7 false positives, open-set known-reject cost
# 12.4%->16.8%, cascade accuracy down on test and cross-app) - see
# reports/PROGRESS_LOG.md, 2026-09-18 entry.
FEATURE_KEYS = [
    "path_length", "query_param_count", "payload_length", "url_payload_length",
    "body_payload_length", "cookie_payload_length", "header_payload_length",
    "header_count", "special_char_ratio", "digit_ratio", "uppercase_ratio",
    "entropy", "encoded_char_ratio", "double_encoding_count",
    "kw_sqli_count", "kw_xss_count", "kw_pathtrav_count", "kw_codeinj_count",
    "kw_cmdi_count", "kw_sqli_density", "kw_cmdi_density", "sql_comment_count",
    "angle_bracket_count", "quote_count", "quote_parity", "paren_count",
    "inter_arrival_ms", "request_rate_window",
]
CONTENT_TYPE_BUCKETS = ["none", "json", "form_urlencoded", "multipart", "text_plain", "other"]
FEATURE_NAMES = FEATURE_KEYS + [f"content_type={b}" for b in CONTENT_TYPE_BUCKETS]
CLASS_NAMES = ["sqli", "xss", "command_injection"]
CLASS_TO_IDX = {c: i for i, c in enumerate(CLASS_NAMES)}

# Content/payload-driven features only - excludes path_length, query_param_count,
# header_count, content_type, inter_arrival_ms, request_rate_window, which track
# an APP's own structural conventions more than the attack payload itself. The
# IsolationForest was found to key off exactly those excluded features on
# cross_app_test (WebGoat, an app never seen in training): it flagged the app
# as "unknown", not the attack. Restricting its input to payload-content
# signal is the fix - see reports/PROGRESS_LOG.md, 2026-09-10 entry.
ISO_FEATURE_KEYS = [
    "payload_length", "url_payload_length", "body_payload_length",
    "cookie_payload_length", "header_payload_length",
    "special_char_ratio", "digit_ratio", "uppercase_ratio", "entropy",
    "encoded_char_ratio", "double_encoding_count",
    "kw_sqli_count", "kw_xss_count", "kw_pathtrav_count", "kw_codeinj_count",
    "kw_cmdi_count", "kw_sqli_density", "kw_cmdi_density", "sql_comment_count",
    "angle_bracket_count", "quote_count", "quote_parity", "paren_count",
]
ISO_FEATURE_IDX = [FEATURE_NAMES.index(k) for k in ISO_FEATURE_KEYS]


# ---------------------------------------------------------------------------
# data loading — stream JSONL, keep only features_aux + label + app (small)
# ---------------------------------------------------------------------------
def load_split(path):
    feats, level1s, classes, apps = [], [], [], []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            feats.append(rec["features_aux"])
            lbl = rec["label"]
            level1s.append(lbl["level1"])
            classes.append(lbl["class"])
            apps.append((rec.get("metadata") or {}).get("app", "unknown"))
    return feats, level1s, classes, apps


def _content_type_bucket(ct):
    if not ct:
        return "none"
    ct = ct.lower()
    if "json" in ct:
        return "json"
    if "x-www-form-urlencoded" in ct:
        return "form_urlencoded"
    if "multipart" in ct:
        return "multipart"
    if "text/plain" in ct:
        return "text_plain"
    return "other"


def featurize(feats_list):
    n = len(feats_list)
    d = len(FEATURE_NAMES)
    X = np.zeros((n, d), dtype=np.float32)
    for i, fa in enumerate(feats_list):
        for j, k in enumerate(FEATURE_KEYS):
            v = fa.get(k)
            X[i, j] = 0.0 if v is None else float(v)
        bucket = _content_type_bucket(fa.get("content_type"))
        X[i, len(FEATURE_KEYS) + CONTENT_TYPE_BUCKETS.index(bucket)] = 1.0
    return X


# ---------------------------------------------------------------------------
# metrics helpers
# ---------------------------------------------------------------------------
def binary_metrics(y_true, y_pred):
    f1 = f1_score(y_true, y_pred, pos_label=1, zero_division=0)
    prec = precision_score(y_true, y_pred, pos_label=1, zero_division=0)
    rec = recall_score(y_true, y_pred, pos_label=1, zero_division=0)
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    acc = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) else 0.0
    return {"f1": f1, "precision": prec, "recall": rec, "fpr": fpr, "accuracy": acc,
            "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}


def fpr_at_recall(y_true, proba_pos, target_recall=0.95):
    """Threshold sweep: FPR when recall on the positive (malicious) class
    is pushed up to >= target_recall. This is the number that determines
    whether a WAF is operationally usable, not raw accuracy."""
    order = np.argsort(-proba_pos)
    y_sorted = np.asarray(y_true)[order]
    p_sorted = proba_pos[order]
    n_pos = y_sorted.sum()
    n_neg = len(y_sorted) - n_pos
    if n_pos == 0 or n_neg == 0:
        return None, None
    tp = np.cumsum(y_sorted)
    fp = np.cumsum(1 - y_sorted)
    recall = tp / n_pos
    fpr = fp / n_neg
    idx = np.searchsorted(recall, target_recall)
    if idx >= len(recall):
        return None, None
    return float(fpr[idx]), float(p_sorted[idx])


def macro_f1(y_true, y_pred, n_classes):
    return f1_score(y_true, y_pred, labels=list(range(n_classes)), average="macro", zero_division=0)


def per_app_fpr(y_true, y_pred, apps):
    """FPR restricted to true-benign rows, broken out by source app —
    the number that answers 'does this WAF false-positive more on some
    sites than others' instead of hiding it in an aggregate."""
    by_app = defaultdict(lambda: [0, 0])  # app -> [false_positives, total_benign]
    for yt, yp, app in zip(y_true, y_pred, apps):
        if yt == 0:  # true benign
            by_app[app][1] += 1
            if yp == 1:
                by_app[app][0] += 1
    out = {}
    for app, (fp, total) in by_app.items():
        out[app] = {"fpr": fp / total if total else 0.0, "n_benign": total, "fp": fp}
    return out


# ---------------------------------------------------------------------------
# stage 1: binary
# ---------------------------------------------------------------------------
def run_stage1(X_train, y_train, splits, out):
    print("\n" + "=" * 70)
    print("STAGE 1 — binary (benign vs malicious)")
    print("=" * 70)
    n_pos = y_train.sum()
    n_neg = len(y_train) - n_pos
    scale_pos_weight = n_neg / max(n_pos, 1)

    models = {
        "decision_tree": DecisionTreeClassifier(class_weight="balanced", random_state=SEED),
        "random_forest": RandomForestClassifier(n_estimators=200, class_weight="balanced",
                                                 random_state=SEED, n_jobs=-1),
        "xgboost": xgb.XGBClassifier(random_state=SEED, eval_metric="logloss",
                                      scale_pos_weight=scale_pos_weight, n_jobs=-1),
    }

    results = {}
    fitted = {}
    for name, clf in models.items():
        t0 = time.time()
        clf.fit(X_train, y_train)
        fit_s = time.time() - t0
        fitted[name] = clf
        os.makedirs(MODELS_DIR, exist_ok=True)
        joblib.dump(clf, os.path.join(MODELS_DIR, f"stage1_{name}.joblib"))

        row = {"fit_seconds": round(fit_s, 1)}
        for split_name, (X, y, apps) in splits.items():
            y_pred = clf.predict(X)
            m = binary_metrics(y, y_pred)
            if hasattr(clf, "predict_proba"):
                proba_pos = clf.predict_proba(X)[:, 1]
                fpr95, thr95 = fpr_at_recall(y, proba_pos, 0.95)
                m["fpr_at_95recall"] = fpr95
            row[split_name] = m
        results[name] = row

        print(f"\n[{name}]  fit={fit_s:.1f}s")
        for split_name in splits:
            m = row[split_name]
            extra = f"  FPR@95%recall={m.get('fpr_at_95recall')}" if "fpr_at_95recall" in m else ""
            print(f"  {split_name:16} Acc={m['accuracy']:.4f}  F1={m['f1']:.4f}  P={m['precision']:.4f}  "
                  f"R={m['recall']:.4f}  FPR={m['fpr']:.4f}{extra}")

    out["stage1"] = results
    return fitted


# ---------------------------------------------------------------------------
# stage 2: multiclass (malicious rows only)
# ---------------------------------------------------------------------------
def run_stage2(X_train, y_train, splits, out):
    print("\n" + "=" * 70)
    print("STAGE 2 — multiclass (sqli / xss / command_injection)")
    print("=" * 70)

    models = {
        "decision_tree": DecisionTreeClassifier(class_weight="balanced", random_state=SEED),
        "random_forest": RandomForestClassifier(n_estimators=200, class_weight="balanced",
                                                 random_state=SEED, n_jobs=-1),
        "xgboost": xgb.XGBClassifier(random_state=SEED, eval_metric="mlogloss",
                                      num_class=len(CLASS_NAMES),
                                      objective="multi:softprob", n_jobs=-1),
    }

    results = {}
    fitted = {}
    for name, clf in models.items():
        t0 = time.time()
        clf.fit(X_train, y_train)
        fit_s = time.time() - t0
        fitted[name] = clf
        joblib.dump(clf, os.path.join(MODELS_DIR, f"stage2_{name}.joblib"))

        row = {"fit_seconds": round(fit_s, 1)}
        for split_name, (X, y) in splits.items():
            y_pred = clf.predict(X)
            f1m = macro_f1(y, y_pred, len(CLASS_NAMES))
            acc = float((y_pred == y).mean())
            cm = confusion_matrix(y, y_pred, labels=list(range(len(CLASS_NAMES))))
            per_class = f1_score(y, y_pred, labels=list(range(len(CLASS_NAMES))),
                                  average=None, zero_division=0)
            row[split_name] = {
                "accuracy": acc,
                "macro_f1": f1m,
                "per_class_f1": {CLASS_NAMES[i]: float(per_class[i]) for i in range(len(CLASS_NAMES))},
                "confusion_matrix": cm.tolist(),
            }
        results[name] = row

        print(f"\n[{name}]  fit={fit_s:.1f}s")
        for split_name in splits:
            r = row[split_name]
            pc = " ".join(f"{k}={v:.3f}" for k, v in r["per_class_f1"].items())
            print(f"  {split_name:16} Acc={r['accuracy']:.4f}  macroF1={r['macro_f1']:.4f}  ({pc})")

    out["stage2"] = results
    return fitted


# ---------------------------------------------------------------------------
# open-set calibration — method E: IsolationForest + softmax, mean ensemble
# (see module docstring for why this replaced plain softmax thresholding)
# ---------------------------------------------------------------------------
N_BAG = 5  # number of IsolationForests averaged together (see docstring below)
ISO_N_ESTIMATORS = 150  # trees per forest - tuned 2026-09-10 (tune_isoforest_latency.py):
# latency scales ~linearly with tree count (200 trees = 100ms/req, 5.4 req/s -
# not production-viable); cross_app accuracy stability has a real cliff below
# 150 (std jumps from 5.1% at 150 to 14.5% at 100). 150 is the best available
# trade-off: ~77ms/req (13 req/s, a real but modest 23% latency win) while
# keeping cross_app std close to the 200-tree setting's 3.3%. Getting to
# genuinely production-scale throughput (1000s of req/s) would need a
# different approach, not just fewer trees - documented as unresolved.


def fit_open_set_ensemble(stage2_model, X_train_known, X_val_known, seed=SEED):
    """Fit the IsolationForest half of method E as a BAG of N_BAG forests
    (RESTRICTED to ISO_FEATURE_IDX - payload-content signal only), each with
    max_samples = the full training set, averaged together - then the
    val-calibrated z-scoring that combines the bagged score with stage2's
    softmax score. Returns (forests_list, scorer_fn, calibration_dict).
    scorer_fn(X) -> higher = more 'unknown-like'.

    WHY bagged, not a single forest (found 2026-09-10, multi_seed_eval.py):
    sklearn's IsolationForest default max_samples='auto' = min(256, n) - each
    of the 200 trees only ever saw 256 of our 15,678 training points (1.6%),
    so a single forest's boundary swung wildly with the random seed (recall
    std +/-12.6%, cross_app accuracy std +/-20.8% across 5 seeds - the
    reported "85.9%" cross_app number turned out to be an unstable, lucky
    single seed, not a reliable result). Giving every tree the FULL training
    set (max_samples=n) and averaging 5 independently-seeded forests cuts
    that down to +/-0.9% / +/-3.3% - confirmed stable, at a lower but HONEST
    cross_app accuracy (~53%, not ~86%). See reports/PROGRESS_LOG.md."""
    forests = []
    for i in range(N_BAG):
        f = IsolationForest(n_estimators=ISO_N_ESTIMATORS, max_samples=len(X_train_known),
                             contamination="auto", random_state=seed * 1000 + i, n_jobs=-1)
        f.fit(X_train_known[:, ISO_FEATURE_IDX])
        forests.append(f)

    def iso_score(X):
        return np.mean([-f.score_samples(X[:, ISO_FEATURE_IDX]) for f in forests], axis=0)

    def softmax_score(X):
        return 1.0 - stage2_model.predict_proba(X).max(axis=1)

    iso_val, sm_val = iso_score(X_val_known), softmax_score(X_val_known)
    iso_mu, iso_sd = float(iso_val.mean()), max(float(iso_val.std()), 1e-9)
    sm_mu, sm_sd = float(sm_val.mean()), max(float(sm_val.std()), 1e-9)

    def scorer(X):
        zi = (iso_score(X) - iso_mu) / iso_sd
        zs = (softmax_score(X) - sm_mu) / sm_sd
        return (zi + zs) / 2.0

    calib = {"iso_mu": iso_mu, "iso_sd": iso_sd, "sm_mu": sm_mu, "sm_sd": sm_sd}
    return forests, scorer, calib


def sweep_threshold(known_score, unknown_score):
    """Fine-grained Youden's-J sweep (400 points across the observed score
    range) — replaces the old coarse np.arange(0.30, 1.00, 0.01) grid, which
    was too coarse to find the good threshold (it lived past the grid's own
    upper bound). known/unknown_score: higher = more 'unknown-like'."""
    lo = min(known_score.min(), unknown_score.min())
    hi = max(known_score.max(), unknown_score.max())
    best_thr, best_j = lo, -1.0
    for thr in np.linspace(lo, hi, 400):
        known_reject = float((known_score > thr).mean())
        unknown_recall = float((unknown_score > thr).mean())
        j = unknown_recall - known_reject
        if j > best_j:
            best_j, best_thr = j, thr
    known_reject_at_best = float((known_score > best_thr).mean())
    unknown_recall_at_best = float((unknown_score > best_thr).mean())
    return float(best_thr), unknown_recall_at_best, known_reject_at_best


def calibrate_open_set(stage2_model, X_train_known, X_val_known, X_heldout, out):
    print("\n" + "=" * 70)
    print("OPEN-SET CALIBRATION — method E (IsolationForest + softmax, mean ensemble)")
    print("(known = val malicious rows, unknown = heldout code_injection)")
    print("=" * 70)

    forests, scorer, calib = fit_open_set_ensemble(stage2_model, X_train_known, X_val_known)
    known_score = scorer(X_val_known)
    unknown_score = scorer(X_heldout)
    best_thr, unknown_recall_at_best, known_reject_at_best = sweep_threshold(known_score, unknown_score)

    print(f"  chosen threshold: {best_thr:.4f}")
    print(f"  open-set recall (code_injection correctly flagged 'unknown'): {unknown_recall_at_best:.4f}")
    print(f"  cost: known-class val rows wrongly flagged 'unknown':          {known_reject_at_best:.4f}")
    print(f"  mean known unknown-ness score:   {known_score.mean():.4f}")
    print(f"  mean unknown unknown-ness score: {unknown_score.mean():.4f}")

    plt.figure(figsize=(7, 4.5))
    plt.hist(known_score, bins=40, alpha=0.6, label="known (val)", density=True)
    plt.hist(unknown_score, bins=40, alpha=0.6, label="unknown (code_injection)", density=True)
    plt.axvline(best_thr, color="red", linestyle="--", label=f"threshold={best_thr:.4f}")
    plt.xlabel("ensembled unknown-ness z-score (IsolationForest + softmax)")
    plt.ylabel("density")
    plt.title("Open-set separation: known vs unknown (method E)")
    plt.legend()
    plt.tight_layout()
    os.makedirs(OUT_DIR, exist_ok=True)
    plt.savefig(os.path.join(OUT_DIR, "open_set_calibration.png"), dpi=130)
    plt.close()

    os.makedirs(MODELS_DIR, exist_ok=True)
    joblib.dump(forests, os.path.join(MODELS_DIR, "openset_isoforest.joblib"))
    with open(os.path.join(MODELS_DIR, "openset_ensemble_config.json"), "w", encoding="utf-8") as f:
        json.dump({"method": "E_isoforest_bagged_softmax_mean", "threshold": best_thr,
                   "n_bag": N_BAG, "iso_feature_keys": ISO_FEATURE_KEYS, **calib}, f, indent=2)

    out["open_set"] = {
        "method": "E_isoforest_bagged_softmax_mean",
        "threshold": float(best_thr),
        "unknown_recall": unknown_recall_at_best,
        "known_reject_rate": known_reject_at_best,
        "mean_known_score": float(known_score.mean()),
        "mean_unknown_score": float(unknown_score.mean()),
        "calibration": calib,
    }
    return best_thr, scorer


# ---------------------------------------------------------------------------
# end-to-end cascade evaluation
# ---------------------------------------------------------------------------
def run_cascade(stage1_model, stage2_model, unknown_score_fn, threshold, X, y_level1, y_class_true, apps, split_name, out):
    """benign/malicious gate -> multiclass -> open-set threshold, scored
    against ground truth. y_class_true entries are class name strings
    ('benign','sqli','xss','command_injection','code_injection').
    unknown_score_fn(X) -> higher = more 'unknown-like' (method E ensemble)."""
    y_bin_pred = stage1_model.predict(X)
    final_labels = []
    proba_multi = stage2_model.predict_proba(X)
    pred_class_idx = proba_multi.argmax(axis=1)
    unknown_score = unknown_score_fn(X)

    for i in range(len(X)):
        if y_bin_pred[i] == 0:
            final_labels.append("benign")
        elif unknown_score[i] > threshold:
            final_labels.append("unknown")
        else:
            final_labels.append(CLASS_NAMES[pred_class_idx[i]])

    # code_injection is NEVER a valid model output by design (open-set) - a
    # code_injection row is "correct" iff it got flagged 'unknown', not iff
    # the model literally predicted the string 'code_injection'.
    def _is_correct(pred, true):
        return pred == "unknown" if true == "code_injection" else pred == true

    correct = sum(1 for f, t in zip(final_labels, y_class_true) if _is_correct(f, t))
    acc = correct / len(y_class_true) if y_class_true else 0.0

    labels_order = ["benign", "sqli", "xss", "command_injection", "code_injection", "unknown"]
    dist_true = Counter(y_class_true)
    dist_pred = Counter(final_labels)
    conf = defaultdict(Counter)
    for t, p in zip(y_class_true, final_labels):
        conf[t][p] += 1

    print(f"\n  [{split_name}] end-to-end accuracy: {acc:.4f}  (n={len(y_class_true)})")
    print(f"  true-label distribution: {dict(dist_true)}")
    print(f"  predicted distribution:  {dict(dist_pred)}")
    for t in labels_order:
        if t in conf:
            print(f"    true={t:18} -> {dict(conf[t])}")

    out.setdefault("cascade", {})[split_name] = {
        "accuracy": acc,
        "n": len(y_class_true),
        "true_dist": dict(dist_true),
        "pred_dist": dict(dist_pred),
        "confusion": {t: dict(c) for t, c in conf.items()},
    }
    return final_labels


def plot_confusion(y_true, y_pred, labels, title, path):
    cm = confusion_matrix(y_true, y_pred, labels=labels)
    fig, ax = plt.subplots(figsize=(6, 5))
    im = ax.imshow(cm, cmap="Blues")
    ax.set_xticks(range(len(labels))); ax.set_xticklabels(labels, rotation=45, ha="right")
    ax.set_yticks(range(len(labels))); ax.set_yticklabels(labels)
    ax.set_xlabel("predicted"); ax.set_ylabel("true"); ax.set_title(title)
    for i in range(len(labels)):
        for j in range(len(labels)):
            ax.text(j, i, cm[i, j], ha="center", va="center",
                     color="white" if cm[i, j] > cm.max() / 2 else "black", fontsize=9)
    fig.colorbar(im)
    plt.tight_layout()
    plt.savefig(path, dpi=130)
    plt.close()


# ---------------------------------------------------------------------------
def main():
    t_start = time.time()
    os.makedirs(OUT_DIR, exist_ok=True)
    os.makedirs(MODELS_DIR, exist_ok=True)
    out = {}

    print("[load] train (real)...")
    tr_feats, tr_l1, tr_cls, _ = load_split(os.path.join(SPLITS_DIR, "train.jsonl"))
    print("[load] train (injected, synthetic)...")
    inj_feats, inj_l1, inj_cls, _ = load_split(os.path.join(SPLITS_DIR, "injected_train.jsonl"))
    train_feats = tr_feats + inj_feats
    train_l1 = tr_l1 + inj_l1
    train_cls = tr_cls + inj_cls
    print(f"[load] train total: {len(train_feats)} ({len(tr_feats)} real + {len(inj_feats)} synthetic)")

    print("[load] val...")
    val_feats, val_l1, val_cls, val_apps = load_split(os.path.join(SPLITS_DIR, "val.jsonl"))
    print("[load] test...")
    test_feats, test_l1, test_cls, test_apps = load_split(os.path.join(SPLITS_DIR, "test.jsonl"))
    print("[load] cross_app_test...")
    cross_feats, cross_l1, cross_cls, cross_apps = load_split(os.path.join(SPLITS_DIR, "cross_app_test.jsonl"))
    print("[load] heldout_unknown...")
    held_feats, held_l1, held_cls, held_apps = load_split(os.path.join(SPLITS_DIR, "heldout_unknown.jsonl"))

    print("[featurize] building matrices...")
    X_train = featurize(train_feats)
    X_val = featurize(val_feats)
    X_test = featurize(test_feats)
    X_cross = featurize(cross_feats)
    X_held = featurize(held_feats)

    y_train_bin = np.array([1 if l == "malicious" else 0 for l in train_l1])
    y_val_bin = np.array([1 if l == "malicious" else 0 for l in val_l1])
    y_test_bin = np.array([1 if l == "malicious" else 0 for l in test_l1])
    y_cross_bin = np.array([1 if l == "malicious" else 0 for l in cross_l1])
    y_held_bin = np.array([1 if l == "malicious" else 0 for l in held_l1])  # should be all 1s

    print(f"[data] train malicious={y_train_bin.sum()} benign={len(y_train_bin) - y_train_bin.sum()} "
          f"({100 * y_train_bin.mean():.1f}% malicious)")

    stage1_splits = {
        "val": (X_val, y_val_bin, val_apps),
        "test": (X_test, y_test_bin, test_apps),
        "cross_app_test": (X_cross, y_cross_bin, cross_apps),
        "heldout_unknown": (X_held, y_held_bin, held_apps),
    }
    fitted1 = run_stage1(X_train, y_train_bin, stage1_splits, out)

    # per-app FPR on test, for the DEPLOYED stage-1 model. Switched from
    # xgboost to random_forest 2026-09-12: random_forest strictly beats
    # xgboost on cross-app recall (89.7% vs 80.5%), heldout_unknown recall
    # (80.6% vs 33.6%), AND adversarial-evasion robustness (10.0% vs 39.3%
    # worst-case full-bypass rate under 6-round mutation search) - see
    # PROGRESS_LOG.md. xgboost stays the stage-2 (multiclass) model, which
    # it wins outright on every split.
    rf1 = fitted1["random_forest"]
    test_pred_bin = rf1.predict(X_test)
    app_fpr = per_app_fpr(y_test_bin, test_pred_bin, test_apps)
    print("\n[per-app FPR, RandomForest (deployed stage-1), test split]")
    for app, m in sorted(app_fpr.items(), key=lambda kv: -kv[1]["n_benign"]):
        print(f"  {app:16} FPR={m['fpr']:.4f}  (n_benign={m['n_benign']}, fp={m['fp']})")
    out["stage1_per_app_fpr_test_random_forest"] = app_fpr

    # ---- stage 2: multiclass, malicious rows only ----
    def multi_subset(feats_idx_source, X, cls_list):
        idx = [i for i, c in enumerate(cls_list) if c in CLASS_TO_IDX]
        Xs = X[idx]
        ys = np.array([CLASS_TO_IDX[cls_list[i]] for i in idx])
        return Xs, ys

    X_train_m, y_train_m = multi_subset(None, X_train, train_cls)
    X_val_m, y_val_m = multi_subset(None, X_val, val_cls)
    X_test_m, y_test_m = multi_subset(None, X_test, test_cls)
    X_cross_m, y_cross_m = multi_subset(None, X_cross, cross_cls)

    stage2_splits = {"val": (X_val_m, y_val_m), "test": (X_test_m, y_test_m),
                      "cross_app_test": (X_cross_m, y_cross_m)}
    fitted2 = run_stage2(X_train_m, y_train_m, stage2_splits, out)

    # ---- open-set calibration on the xgboost stage-2 model (method E) ----
    xgb2 = fitted2["xgboost"]
    threshold, unknown_score_fn = calibrate_open_set(xgb2, X_train_m, X_val_m, X_held, out)

    # ---- end-to-end cascade (random_forest stage1 + xgboost stage2, method E) ----
    print("\n" + "=" * 70)
    print("END-TO-END CASCADE (RandomForest stage 1 + XGBoost stage 2 + method E open-set)")
    print("=" * 70)
    run_cascade(rf1, xgb2, unknown_score_fn, threshold, X_test, None, test_cls, test_apps, "test", out)
    run_cascade(rf1, xgb2, unknown_score_fn, threshold, X_cross, None, cross_cls, cross_apps, "cross_app_test", out)
    run_cascade(rf1, xgb2, unknown_score_fn, threshold, X_held, None, held_cls, held_apps, "heldout_unknown", out)

    # confusion matrix plots for the deployed (random_forest + xgboost) cascade on test
    all_true, all_pred = [], []
    y_bin_pred = rf1.predict(X_test)
    proba_multi = xgb2.predict_proba(X_test)
    pred_idx = proba_multi.argmax(axis=1)
    unknown_score_test = unknown_score_fn(X_test)
    for i in range(len(X_test)):
        all_true.append(test_cls[i])
        if y_bin_pred[i] == 0:
            all_pred.append("benign")
        elif unknown_score_test[i] > threshold:
            all_pred.append("unknown")
        else:
            all_pred.append(CLASS_NAMES[pred_idx[i]])
    plot_confusion(all_true, all_pred,
                    labels=["benign", "sqli", "xss", "command_injection", "unknown"],
                    title="End-to-end cascade — test split (RandomForest+XGBoost)",
                    path=os.path.join(OUT_DIR, "cascade_confusion_test.png"))

    with open(os.path.join(OUT_DIR, "metrics.json"), "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)

    elapsed = time.time() - t_start
    print(f"\n[done] {elapsed:.1f}s total. Models -> {MODELS_DIR}/  Metrics/plots -> {OUT_DIR}/")


if __name__ == "__main__":
    main()
