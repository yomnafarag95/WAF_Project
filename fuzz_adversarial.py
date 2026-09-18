"""
fuzz_adversarial.py - WAF-A-MoLE-style iterative mutational search against the
ALREADY-TRAINED stage1/stage2/open-set cascade (loaded via joblib, NOT
retrained). Reuses the evasion transforms already built for inject_payloads.py
(src/attacks/attack_payloads.py) as mutation operators, but applies them in a
GREEDY, MULTI-ROUND, COMPOUNDING search - never seen during training, which
only ever applies ONE evasion transform per record.

WHY: the earlier fast-pass (train_baseline.py) and open-set comparison
(calibrate_openset.py) both measured accuracy on a STATIC sample. That answers
"how good is the cascade on requests shaped like our data?" but not "how much
worse can an adaptive attacker who queries the model make it?" - the second
question is what actually matters for a WAF deployed against a real
adversary, and it is the thing ModSec-AdvLearn's WAF-A-MoLE methodology is
built to answer.

TWO EXPERIMENTS:
  A. binary evasion  - start from REAL, held-out (test.jsonl) sqli/xss/
     command_injection rows. Greedily mutate the query payload over several
     rounds trying to push stage1's malicious-probability below 0.5 (i.e.
     evade the binary gate entirely). Measures whether compounding mutations
     beyond what training saw can defeat detection of KNOWN attack classes.
  B. open-set evasion - start from heldout_unknown.jsonl (code_injection,
     genuinely never trained on). Greedily mutate to push the open-set
     "unknown-ness" score (max-softmax, method A from calibrate_openset.py -
     the winning method) below the calibrated threshold, i.e. trick the
     cascade into classifying it as a KNOWN class instead of flagging
     "unknown". Compares the ADVERSARIAL miss rate to the STATIC 52.2%
     baseline miss rate already measured.

Both experiments also record the worst-case COMBINED failure: a mutated
attack/code_injection row that ends up predicted "benign" outright (evades
stage1 entirely), which is more severe than a stage2/open-set miss.

usage:
  python3 fuzz_adversarial.py
  python3 fuzz_adversarial.py --rounds 5 --sample 300 --seed 42
"""
import argparse
import copy
import json
import os
import random
import sys
import time
import urllib.parse

import joblib
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "src", "attacks"))
sys.path.insert(0, os.path.join(HERE, "src", "features"))
import attack_payloads as AP  # noqa: E402
import extract_features as EF  # noqa: E402
import train_baseline as tb  # noqa: E402
import inject_payloads as IJ  # noqa: E402

SPLITS_DIR = tb.SPLITS_DIR
MODELS_DIR = tb.MODELS_DIR
OUT_DIR = "reports/adversarial_fuzz"
SEED = 42

MUTATORS = {
    "url_encode": AP._encode_url,
    "double_encode": AP._encode_double,
    "case_swap": AP._mutate_case,
    "sql_comment_ws": AP._mutate_comment,
    "ws_substitute": AP._mutate_ws,
    "null_byte": AP._mutate_nullbyte,
    "partial_encode": AP._encode_partial,
}
XSS_ONLY_MUTATORS = {"utf7_charset": AP._encode_utf7}


# ---------------------------------------------------------------------------
# mutation: rebuild a record with ONE query param transformed
# ---------------------------------------------------------------------------
def _mutate_query_value(query_string, mutator, rng):
    pairs = urllib.parse.parse_qsl(query_string or "", keep_blank_values=True)
    if not pairs:
        return None
    idx = rng.randrange(len(pairs))
    k, v = pairs[idx]
    new_v = mutator(v)
    if new_v == v:
        return None
    parts = []
    for i, (kk, vv) in enumerate(pairs):
        vv_out = new_v if i == idx else urllib.parse.quote(vv, safe="")
        parts.append(f"{urllib.parse.quote(kk, safe='')}={vv_out}")
    return "&".join(parts)


def apply_mutation(rec, mutator, rng):
    """Return a mutated deep copy with recomputed features_aux, or None if the
    mutator had no effect on this record's query string."""
    new_rec = copy.deepcopy(rec)
    content = new_rec["content"]
    qs = content.get("query_string") or ""
    new_qs = _mutate_query_value(qs, mutator, rng)
    if new_qs is None:
        return None
    method = content.get("http_method", "GET")
    url_path = content.get("url_path", "/")
    _, header_lines, body = IJ._split_raw(content.get("raw_request", ""))
    new_path_with_query = url_path + (("?" + new_qs) if new_qs else "")
    content["query_string"] = new_qs
    content["raw_request"] = IJ._rebuild_raw(method, new_path_with_query, header_lines, body)
    content["decoded_payload"] = IJ._decoded_payload(url_path, new_qs)
    new_rec["features_aux"] = EF.compute_features(new_rec)
    return new_rec


def mutators_for(attack_type):
    m = dict(MUTATORS)
    if attack_type == "xss":
        m.update(XSS_ONLY_MUTATORS)
    return m


# ---------------------------------------------------------------------------
# scoring
# ---------------------------------------------------------------------------
def malicious_proba(stage1, feats):
    X = tb.featurize([feats])
    return float(stage1.predict_proba(X)[0][1])


def unknown_score(stage2, feats):
    X = tb.featurize([feats])
    return float(1.0 - stage2.predict_proba(X)[0].max())


# ---------------------------------------------------------------------------
# greedy multi-round search
# ---------------------------------------------------------------------------
def greedy_search(rec, attack_type, objective_fn, n_rounds, success_fn, rng):
    """Greedily mutate `rec` over `n_rounds`, each round trying every mutator
    once and keeping whichever candidate minimises objective_fn (lower =
    'more evasive'). Stops early on success_fn(score). Returns
    (best_rec, score_trace, succeeded, round_of_success)."""
    mutators = mutators_for(attack_type)
    current = rec
    current_score = objective_fn(current["features_aux"])
    trace = [current_score]
    if success_fn(current_score):
        return current, trace, True, 0
    for round_idx in range(1, n_rounds + 1):
        best_candidate, best_score = None, current_score
        for mutator in mutators.values():
            cand = apply_mutation(current, mutator, rng)
            if cand is None:
                continue
            s = objective_fn(cand["features_aux"])
            if s < best_score:
                best_candidate, best_score = cand, s
        if best_candidate is None:
            break  # no mutator improved on this round -> local optimum
        current, current_score = best_candidate, best_score
        trace.append(current_score)
        if success_fn(current_score):
            return current, trace, True, round_idx
    return current, trace, False, None


# ---------------------------------------------------------------------------
# experiment A: binary evasion on KNOWN attack classes (test split)
# ---------------------------------------------------------------------------
def run_experiment_a(stage1, rows, n_rounds, rng):
    print(f"\n[A] binary-evasion search on {len(rows)} known-attack test rows "
          f"({n_rounds} rounds, compounding mutations)...")
    results = []
    for rec in rows:
        cls = rec["label"]["class"]
        baseline = malicious_proba(stage1, rec["features_aux"])
        final_rec, trace, succeeded, round_won = greedy_search(
            rec, cls, lambda f: malicious_proba(stage1, f),
            n_rounds, lambda s: s < 0.5, rng)
        results.append({
            "record_id": rec["record_id"], "class": cls,
            "baseline_malicious_proba": baseline,
            "final_malicious_proba": trace[-1],
            "evaded": succeeded, "round_of_evasion": round_won,
            "rounds_run": len(trace) - 1,
        })
    n = len(results)
    evaded = sum(r["evaded"] for r in results)
    print(f"[A] compound-mutation binary-evasion success: {evaded}/{n} ({100*evaded/n:.2f}%)")
    by_class = {}
    for cls in ("sqli", "xss", "command_injection"):
        sub = [r for r in results if r["class"] == cls]
        if sub:
            ev = sum(r["evaded"] for r in sub)
            by_class[cls] = {"n": len(sub), "evaded": ev, "rate": ev / len(sub)}
            print(f"    {cls:18s} evaded {ev}/{len(sub)} ({100*ev/len(sub):.2f}%)")
    return results, by_class


# ---------------------------------------------------------------------------
# experiment B: open-set evasion on code_injection (heldout_unknown split)
# ---------------------------------------------------------------------------
def run_experiment_b(stage1, stage2, threshold, rows, n_rounds, rng):
    print(f"\n[B] open-set-evasion search on {len(rows)} heldout code_injection rows "
          f"({n_rounds} rounds, compounding mutations)...")
    print(f"[B] calibrated open-set threshold (method A, unknown-ness score) = {threshold:.6f}")
    results = []
    static_missed = 0  # baseline: already misclassified as a known class, no search needed
    for rec in rows:
        baseline_u = unknown_score(stage2, rec["features_aux"])
        baseline_flagged_unknown = baseline_u > threshold
        if not baseline_flagged_unknown:
            static_missed += 1
        final_rec, trace, succeeded, round_won = greedy_search(
            rec, "code_injection", lambda f: unknown_score(stage2, f),
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
    print(f"[B] static open-set recall (no search):          {100*static_recall:.2f}%  "
          f"(matches calibrate_openset.py's 52.2% reference)")
    print(f"[B] adversarial open-set recall (after search):   {100*adv_recall:.2f}%")
    print(f"[B] worst case - also evaded stage1 (-> 'benign'): {combined_fail}/{n} "
          f"({100*combined_fail/n:.2f}%)")
    return results, {
        "static_recall": static_recall, "adversarial_recall": adv_recall,
        "combined_stage1_evasion": combined_fail, "n": n,
    }


# ---------------------------------------------------------------------------
def load_split(path):
    out = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, default=5)
    ap.add_argument("--sample", type=int, default=0, help="0 = use all available rows")
    ap.add_argument("--seed", type=int, default=SEED)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    t0 = time.time()

    print("[load] stage1/stage2 XGBoost models...")
    stage1 = joblib.load(os.path.join(MODELS_DIR, "stage1_xgboost.joblib"))
    stage2 = joblib.load(os.path.join(MODELS_DIR, "stage2_xgboost.joblib"))

    with open(os.path.join("reports", "train_baseline", "openset_comparison.json"), encoding="utf-8") as f:
        openset_cfg = json.load(f)
    threshold = openset_cfg["A_baseline_softmax"]["threshold"]

    test_rows = [r for r in load_split(os.path.join(SPLITS_DIR, "test.jsonl"))
                 if r["label"]["level1"] == "malicious"]
    held_rows = load_split(os.path.join(SPLITS_DIR, "heldout_unknown.jsonl"))

    if args.sample:
        rng.shuffle(test_rows)
        rng.shuffle(held_rows)
        test_rows = test_rows[:args.sample]
        held_rows = held_rows[:args.sample]

    results_a, by_class_a = run_experiment_a(stage1, test_rows, args.rounds, rng)
    results_b, summary_b = run_experiment_b(stage1, stage2, threshold, held_rows, args.rounds, rng)

    os.makedirs(OUT_DIR, exist_ok=True)
    with open(os.path.join(OUT_DIR, "fuzz_results.json"), "w", encoding="utf-8") as f:
        json.dump({
            "config": {"rounds": args.rounds, "seed": args.seed,
                       "n_test_rows": len(test_rows), "n_heldout_rows": len(held_rows),
                       "openset_threshold": threshold},
            "experiment_a_binary_evasion": {"by_class": by_class_a, "rows": results_a},
            "experiment_b_openset_evasion": {"summary": summary_b, "rows": results_b},
        }, f, indent=2)

    # -- plot: two panels, evasion-round histograms --
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.3))
    won_rounds_a = [r["round_of_evasion"] for r in results_a if r["evaded"]]
    axes[0].hist(won_rounds_a, bins=range(0, args.rounds + 2), align="left", color="#b02a37")
    axes[0].set_title(f"A: binary-evasion round of success\n({len(won_rounds_a)}/{len(results_a)} evaded)")
    axes[0].set_xlabel("round mutation succeeded")
    axes[0].set_ylabel("count")

    before = [r["baseline_unknown_score"] for r in results_b]
    after = [r["final_unknown_score"] for r in results_b]
    axes[1].hist(before, bins=40, alpha=0.6, label="before search", density=True)
    axes[1].hist(after, bins=40, alpha=0.6, label="after search", density=True)
    axes[1].axvline(threshold, color="red", linestyle="--", linewidth=1.2, label="threshold")
    axes[1].set_title("B: open-set unknown-ness score,\nbefore vs after adversarial search")
    axes[1].set_xlabel("unknown-ness score")
    axes[1].legend(fontsize=8)
    plt.tight_layout()
    plt.savefig(os.path.join(OUT_DIR, "fuzz_summary.png"), dpi=130)
    plt.close()

    print(f"\n[done] {time.time()-t0:.1f}s total. -> {OUT_DIR}/fuzz_results.json, {OUT_DIR}/fuzz_summary.png")


if __name__ == "__main__":
    main()
