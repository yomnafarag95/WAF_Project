"""
eda_stage1_stage2.py - is F1=1.0000 genuine signal, or a too-easy/circular task?

Near-perfect scores are a red flag, not a trophy, until explained. This script
investigates WHY stage1/stage2 are so easy to classify, using val+test only
(never train, to avoid any argument about fitting artifacts):

  1. Class balance.
  2. Single-feature separability: for EVERY one of the 26 features alone,
     what's the best possible threshold-based F1 at separating benign vs
     malicious (stage1) and at separating each attack class from the rest
     (stage2)? If one feature alone gets close to the full model's F1, the
     task is easy by construction, not because the model learned something
     subtle - worth knowing explicitly, especially since several features
     (kw_sqli_count, kw_xss_count, kw_cmdi_count) are LITERALLENGTH counts of
     the same curated keyword banks used to GENERATE the synthetic attacks -
     a quasi-circular relationship between feature and label for that portion
     of the data.
  3. 2D PCA projection of the full feature space, colored by class - a direct
     visual check of separability.
  4. Feature correlation heatmap (quantifies the multicollinearity already
     discussed qualitatively).
  5. Real vs synthetic split: repeats the single-feature separability check
     on REAL-only malicious rows (DVWA/Juice Shop/WebGoat captures) to see
     whether the "too easy" result holds even without synthetic data's
     keyword-bank circularity.

usage:
  python3 eda_stage1_stage2.py
"""
import json
import os
import sys

import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.decomposition import PCA
from sklearn.metrics import f1_score, roc_auc_score

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import train_baseline as tb  # noqa: E402

SPLITS_DIR = tb.SPLITS_DIR
OUT_DIR = "reports/eda"


def load_raw(path):
    feats, l1, cls, apps, source = [], [], [], [], []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            feats.append(rec["features_aux"])
            feats[-1]["content_type"] = feats[-1].get("content_type")
            l1.append(rec["label"]["level1"])
            cls.append(rec["label"]["class"])
            apps.append((rec.get("metadata") or {}).get("app", "unknown"))
            source.append((rec.get("metadata") or {}).get("source_type", "unknown"))
    return feats, l1, cls, apps, source


def best_single_feature_f1(x, y):
    """Best threshold-based F1 for a single feature separating y==1 from y==0.
    Tries both directions (feature high => positive, and feature low => positive)."""
    x = np.nan_to_num(x.astype(float))
    if x.max() == x.min():
        return 0.0, 0.0
    thresholds = np.unique(np.percentile(x, np.linspace(0, 100, 60)))
    best_f1 = 0.0
    for t in thresholds:
        f1_hi = f1_score(y, (x > t).astype(int), zero_division=0)
        f1_lo = f1_score(y, (x <= t).astype(int), zero_division=0)
        best_f1 = max(best_f1, f1_hi, f1_lo)
    try:
        auc = roc_auc_score(y, x)
        auc = max(auc, 1 - auc)
    except ValueError:
        auc = 0.5
    return float(best_f1), float(auc)


def main():
    print("[load] val + test (never train, to avoid fitting-artifact arguments)...")
    v_feats, v_l1, v_cls, v_apps, v_src = load_raw(os.path.join(SPLITS_DIR, "val.jsonl"))
    t_feats, t_l1, t_cls, t_apps, t_src = load_raw(os.path.join(SPLITS_DIR, "test.jsonl"))
    feats = v_feats + t_feats
    l1 = v_l1 + t_l1
    cls = v_cls + t_cls
    apps = v_apps + t_apps
    src = v_src + t_src
    print(f"[load] {len(feats)} rows (val+test)")

    X = tb.featurize(feats)
    y_bin = np.array([1 if l == "malicious" else 0 for l in l1])

    print("\n[1] CLASS BALANCE")
    from collections import Counter
    print("  level1:", dict(Counter(l1)))
    print("  class:", dict(Counter(cls)))

    print("\n[2] SINGLE-FEATURE SEPARABILITY - stage 1 (benign vs malicious)")
    stage1_results = []
    for i, name in enumerate(tb.FEATURE_NAMES):
        f1, auc = best_single_feature_f1(X[:, i], y_bin)
        stage1_results.append({"feature": name, "best_f1": f1, "auc": auc})
    stage1_results.sort(key=lambda r: -r["best_f1"])
    print(f"  {'feature':28} {'best single-threshold F1':>26} {'AUC':>8}")
    for r in stage1_results[:8]:
        print(f"  {r['feature']:28} {r['best_f1']:26.4f} {r['auc']:8.4f}")

    print("\n[3] SINGLE-FEATURE SEPARABILITY - stage 2 (each class vs rest, malicious only)")
    known_mask = np.array([c in tb.CLASS_TO_IDX for c in cls])
    X_m = X[known_mask]
    cls_m = np.array(cls)[known_mask]
    stage2_results = {}
    for target in tb.CLASS_NAMES:
        y_c = (cls_m == target).astype(int)
        rows = []
        for i, name in enumerate(tb.FEATURE_NAMES):
            f1, auc = best_single_feature_f1(X_m[:, i], y_c)
            rows.append({"feature": name, "best_f1": f1, "auc": auc})
        rows.sort(key=lambda r: -r["best_f1"])
        stage2_results[target] = rows
        print(f"\n  target={target}")
        for r in rows[:4]:
            print(f"    {r['feature']:28} {r['best_f1']:26.4f} {r['auc']:8.4f}")

    print("\n[4] REAL-ONLY CHECK (DVWA/Juice Shop/WebGoat captures, excludes synthetic injection)")
    real_mask = np.array(src) == "real"
    print(f"  real-source rows in val+test: {int(real_mask.sum())} of {len(feats)}")
    if real_mask.sum() > 20:
        y_bin_real = y_bin[real_mask]
        X_real = X[real_mask]
        real_stage1 = []
        for i, name in enumerate(tb.FEATURE_NAMES):
            f1, auc = best_single_feature_f1(X_real[:, i], y_bin_real)
            real_stage1.append({"feature": name, "best_f1": f1, "auc": auc})
        real_stage1.sort(key=lambda r: -r["best_f1"])
        print(f"  best single feature (real-only, stage1): "
              f"{real_stage1[0]['feature']} F1={real_stage1[0]['best_f1']:.4f}")
    else:
        real_stage1 = []
        print("  too few real-source rows in val+test for a separate check "
              "(most real attack traffic lives in train.jsonl / cross_app_test.jsonl)")

    print("\n[5] PCA projection + correlation heatmap + feature distributions -> figures")
    os.makedirs(OUT_DIR, exist_ok=True)

    # PCA, stage1
    pca = PCA(n_components=2)
    X_2d = pca.fit_transform(X)
    fig, axes = plt.subplots(1, 2, figsize=(13, 5.5))
    colors_bin = ["#3454a5" if v == 0 else "#b91c1c" for v in y_bin]
    axes[0].scatter(X_2d[:, 0], X_2d[:, 1], c=colors_bin, s=4, alpha=0.35)
    axes[0].set_title(f"PCA (2D), colored by benign(blue)/malicious(red)\n"
                       f"explained variance: {pca.explained_variance_ratio_.sum()*100:.1f}%")
    axes[0].set_xlabel("PC1"); axes[0].set_ylabel("PC2")

    class_colors = {"benign": "#9aa3b2", "sqli": "#0f766e", "xss": "#b45309",
                     "command_injection": "#7c3aed", "code_injection": "#b91c1c"}
    colors_cls = [class_colors.get(c, "#000000") for c in cls]
    axes[1].scatter(X_2d[:, 0], X_2d[:, 1], c=colors_cls, s=4, alpha=0.35)
    axes[1].set_title("PCA (2D), colored by class")
    axes[1].set_xlabel("PC1"); axes[1].set_ylabel("PC2")
    handles = [plt.Line2D([0], [0], marker='o', color='w', markerfacecolor=v, label=k, markersize=7)
               for k, v in class_colors.items()]
    axes[1].legend(handles=handles, fontsize=8, loc="best")
    plt.tight_layout()
    plt.savefig(os.path.join(OUT_DIR, "pca_projection.png"), dpi=130)
    plt.close()

    # correlation heatmap
    corr = np.corrcoef(X[:, :len(tb.FEATURE_KEYS)], rowvar=False)
    fig, ax = plt.subplots(figsize=(9, 8))
    im = ax.imshow(corr, cmap="RdBu_r", vmin=-1, vmax=1)
    ax.set_xticks(range(len(tb.FEATURE_KEYS)))
    ax.set_xticklabels(tb.FEATURE_KEYS, rotation=90, fontsize=6.5)
    ax.set_yticks(range(len(tb.FEATURE_KEYS)))
    ax.set_yticklabels(tb.FEATURE_KEYS, fontsize=6.5)
    fig.colorbar(im, shrink=0.8)
    ax.set_title("Feature correlation matrix (26 numeric features)")
    plt.tight_layout()
    plt.savefig(os.path.join(OUT_DIR, "correlation_heatmap.png"), dpi=130)
    plt.close()

    # distributions of top-3 most-separating stage1 features
    top3 = [r["feature"] for r in stage1_results[:3]]
    fig, axes = plt.subplots(1, 3, figsize=(14, 4))
    for ax, feat_name in zip(axes, top3):
        idx = tb.FEATURE_NAMES.index(feat_name)
        vals_b = X[y_bin == 0, idx]
        vals_m = X[y_bin == 1, idx]
        lo, hi = np.percentile(X[:, idx], [1, 99])
        bins = np.linspace(lo, hi, 40)
        ax.hist(vals_b, bins=bins, alpha=0.6, label="benign", density=True, color="#3454a5")
        ax.hist(vals_m, bins=bins, alpha=0.6, label="malicious", density=True, color="#b91c1c")
        ax.set_title(feat_name, fontsize=10)
        ax.legend(fontsize=8)
    plt.tight_layout()
    plt.savefig(os.path.join(OUT_DIR, "top_feature_distributions.png"), dpi=130)
    plt.close()

    with open(os.path.join(OUT_DIR, "eda_results.json"), "w", encoding="utf-8") as f:
        json.dump({
            "n_rows": len(feats), "class_balance": dict(Counter(cls)),
            "stage1_single_feature": stage1_results,
            "stage2_single_feature": stage2_results,
            "real_only_stage1_top": real_stage1[:5] if real_stage1 else [],
            "real_only_n": int(real_mask.sum()),
            "pca_explained_variance": float(pca.explained_variance_ratio_.sum()),
        }, f, indent=2)

    print(f"\n[done] -> {OUT_DIR}/eda_results.json, pca_projection.png, "
          f"correlation_heatmap.png, top_feature_distributions.png")


if __name__ == "__main__":
    main()
