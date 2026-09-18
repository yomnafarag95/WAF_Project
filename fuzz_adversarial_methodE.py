"""
fuzz_adversarial_methodE.py - stress-test method E (IsolationForest + softmax
mean ensemble) under the SAME adversarial multi-round compounding-mutation
search used for method A in fuzz_adversarial.py.

WHY: method E was picked as the project's PRIMARY open-set method (100%
static recall on heldout_unknown, at a 43.8% known-attack mislabel cost the
team judged acceptable since stage1 still blocks that traffic regardless of
label). But method A's static 52.2% recall also looked solid before adaptive
search cut it to 39.1% (fuzz_adversarial.py). A 100% STATIC number deserves
the same scrutiny before being trusted - if it collapses under search the
way A's did, that changes the decision.

Reuses fuzz_adversarial.py's mutation machinery (apply_mutation, greedy
search, mutators) unchanged, and isoforest_openset.py's fitted ensemble
scorer (refit once here since the isoforest is not persisted to disk -
it's fast, ~1s).

usage:
  python3 fuzz_adversarial_methodE.py --rounds 6
"""
import argparse
import json
import os
import random
import sys
import time

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import train_baseline as tb  # noqa: E402
import calibrate_openset as co  # noqa: E402
import isoforest_openset as ISO  # noqa: E402
from fuzz_adversarial import greedy_search, malicious_proba, load_split  # noqa: E402

SPLITS_DIR = tb.SPLITS_DIR
MODELS_DIR = tb.MODELS_DIR
OUT_DIR = "reports/adversarial_fuzz_methodE"
SEED = 42


def run_experiment_b_methodE(stage1, scorer, threshold, rows, n_rounds, rng):
    print(f"\n[B-E] open-set-evasion search on {len(rows)} heldout code_injection rows "
          f"vs method E ({n_rounds} rounds, compounding mutations)...")
    print(f"[B-E] calibrated method-E threshold (ensembled z-score) = {threshold:.6f}")
    results = []
    static_missed = 0
    for rec in rows:
        f0 = rec["features_aux"]
        baseline_u = float(scorer(tb.featurize([f0]))[0])
        baseline_flagged_unknown = baseline_u > threshold
        if not baseline_flagged_unknown:
            static_missed += 1
        final_rec, trace, succeeded, round_won = greedy_search(
            rec, "code_injection",
            lambda f: float(scorer(tb.featurize([f]))[0]),
            n_rounds, lambda s: s <= threshold, rng)
        final_malicious = malicious_proba(stage1, final_rec["features_aux"])
        results.append({
            "record_id": rec["record_id"],
            "baseline_unknown_score": baseline_u,
            "baseline_flagged_unknown": baseline_flagged_unknown,
            "final_unknown_score": trace[-1],
            "adversarially_evaded_openset": succeeded,
            "round_of_evasion": round_won,
            "also_evaded_stage1_entirely": final_malicious < 0.5,
        })
    n = len(results)
    static_recall = 1 - static_missed / n
    adv_missed = sum(r["adversarially_evaded_openset"] or not r["baseline_flagged_unknown"] for r in results)
    adv_recall = 1 - adv_missed / n
    combined_fail = sum(r["also_evaded_stage1_entirely"] for r in results)
    print(f"[B-E] static open-set recall (no search):          {100*static_recall:.2f}%  "
          f"(reference: isoforest_openset.py's 100.00%)")
    print(f"[B-E] adversarial open-set recall (after search):   {100*adv_recall:.2f}%")
    print(f"[B-E] worst case - also evaded stage1 (-> 'benign'): {combined_fail}/{n} "
          f"({100*combined_fail/n:.2f}%)")
    return results, {
        "static_recall": static_recall, "adversarial_recall": adv_recall,
        "combined_stage1_evasion": combined_fail, "n": n,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, default=6)
    ap.add_argument("--sample", type=int, default=0)
    ap.add_argument("--seed", type=int, default=SEED)
    ap.add_argument("--alpha", type=float, default=0.5,
                     help="isoforest weight in the ensemble (1-alpha = softmax weight); "
                          "default 0.5 = original mean combiner")
    ap.add_argument("--stage1-model", default="xgboost",
                     help="which models/stage1_*.joblib to gate 'evaded stage1 entirely' with "
                          "(default xgboost matches the original script; random_forest is the "
                          "better-generalizing choice per PROGRESS_LOG 2026-09-12)")
    args = ap.parse_args()

    rng = random.Random(args.seed)
    t0 = time.time()

    print(f"[load] stage1={args.stage1_model}, stage2=xgboost...")
    stage1 = joblib.load(os.path.join(MODELS_DIR, f"stage1_{args.stage1_model}.joblib"))
    stage2 = joblib.load(os.path.join(MODELS_DIR, "stage2_xgboost.joblib"))

    print("[load] train (known classes only) + val, to refit method E's ensemble...")
    tr_feats, _, tr_cls, _ = tb.load_split(os.path.join(SPLITS_DIR, "train.jsonl"))
    inj_feats, _, inj_cls, _ = tb.load_split(os.path.join(SPLITS_DIR, "injected_train.jsonl"))
    train_feats, train_cls = tr_feats + inj_feats, tr_cls + inj_cls
    train_known = co.known_mask(train_cls)
    X_train_known = tb.featurize(train_feats)[train_known]

    val_feats, _, val_cls, _ = tb.load_split(os.path.join(SPLITS_DIR, "val.jsonl"))
    val_known = co.known_mask(val_cls)
    X_val_known = tb.featurize(val_feats)[val_known]

    iso = ISO.fit_isoforest(X_train_known, seed=SEED)
    scorer = ISO.build_mean_ensemble_scorer(stage2, iso, X_val_known, alpha=args.alpha)

    # threshold recomputed FRESH on the current dataset/alpha (not read from
    # the old openset_comparison.json, which is stale relative to the
    # current bwapp-holdout dataset and would give an invalid comparison).
    held_feats_all, _, held_cls_all, _ = tb.load_split(os.path.join(SPLITS_DIR, "heldout_unknown.jsonl"))
    X_heldout_all = tb.featurize(held_feats_all)
    known_score = scorer(X_val_known)
    unknown_score = scorer(X_heldout_all)
    threshold, static_recall_ref, known_reject_ref = tb.sweep_threshold(known_score, unknown_score)
    print(f"[calib] alpha={args.alpha}  threshold={threshold:.4f}  "
          f"static_recall={static_recall_ref:.4f}  known_reject={known_reject_ref:.4f}")

    held_rows = load_split(os.path.join(SPLITS_DIR, "heldout_unknown.jsonl"))
    if args.sample:
        rng.shuffle(held_rows)
        held_rows = held_rows[:args.sample]

    results_b, summary_b = run_experiment_b_methodE(stage1, scorer, threshold, held_rows, args.rounds, rng)

    os.makedirs(OUT_DIR, exist_ok=True)
    tag = f"_alpha{args.alpha:.2f}" if args.alpha != 0.5 else ""
    tag += f"_{args.stage1_model}" if args.stage1_model != "xgboost" else ""
    with open(os.path.join(OUT_DIR, f"fuzz_methodE_results{tag}.json"), "w", encoding="utf-8") as f:
        json.dump({
            "config": {"rounds": args.rounds, "seed": args.seed, "alpha": args.alpha,
                       "n_heldout_rows": len(held_rows), "threshold": threshold},
            "experiment_b_methodE": {"summary": summary_b, "rows": results_b},
        }, f, indent=2)

    before = [r["baseline_unknown_score"] for r in results_b]
    after = [r["final_unknown_score"] for r in results_b]
    fig, ax = plt.subplots(figsize=(6.5, 4.3))
    ax.hist(before, bins=40, alpha=0.6, label="before search", density=True)
    ax.hist(after, bins=40, alpha=0.6, label="after search", density=True)
    ax.axvline(threshold, color="red", linestyle="--", linewidth=1.2, label="threshold")
    ax.set_title(f"Method E (alpha={args.alpha}) under adversarial search\n"
                 f"(static {100*summary_b['static_recall']:.1f}% -> adversarial "
                 f"{100*summary_b['adversarial_recall']:.1f}% recall)")
    ax.set_xlabel("ensembled unknown-ness z-score")
    ax.legend(fontsize=8)
    plt.tight_layout()
    plt.savefig(os.path.join(OUT_DIR, f"fuzz_methodE_summary{tag}.png"), dpi=130)
    plt.close()

    print(f"\n[done] {time.time()-t0:.1f}s total. -> {OUT_DIR}/fuzz_methodE_results{tag}.json, "
          f"{OUT_DIR}/fuzz_methodE_summary{tag}.png")


if __name__ == "__main__":
    main()
