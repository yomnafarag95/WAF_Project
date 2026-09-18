"""
make_splits.py — assign label.split_role to the REAL (captured) records.

Rules (LOCKED for this project):
  * code_injection            -> heldout_unknown   (open-set, never trained)
  * WebGoat known-attacks     -> cross_app_test     (generalisation test)
                                 (configurable / can be disabled)
  * everything else           -> train / val / test  (default 70/15/15)
        - STRATIFIED by class (benign counts as its own stratum)
        - GROUPED by session_id: a whole session lands in ONE split, so
          near-duplicate requests (13.6% dup rate) can never leak across
          train/val/test.

Injected/augmented payloads are NOT read here. They are generated AFTER this
step from benign_train.jsonl only, and are train-only by construction, so the
val/test/cross_app sets stay 100% real.

Outputs (under --out-dir, default data/splits/):
  dataset_split.jsonl          all records with label.split_role set
  train.jsonl val.jsonl test.jsonl heldout_unknown.jsonl cross_app_test.jsonl
  benign_train.jsonl           <- feed THIS to inject_payloads.py

usage:
  python3 make_splits.py data/processed/*_processed.jsonl \
          data/processed/benign_all_dedup_processed.jsonl
  # disable cross-app:  --cross-app-holdout none
"""
import argparse
import glob
import hashlib
import json
import os
import random
import sys
from collections import Counter, defaultdict

ATTACK_CLASSES = {"sqli", "xss", "command_injection", "code_injection"}


def load(paths):
    recs = []
    for pat in paths:
        for path in glob.glob(pat):
            with open(path, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    recs.append(json.loads(line))
    return recs


def session_key(rec):
    """Group by real session_id when present. Several real-site benign
    sources (pinterest/facebook/youtube/x/amazon) carry NO session_id at
    capture time, so records that hit the same endpoint TEMPLATE (same
    app + url_path) would otherwise each become their own singleton group
    and get scattered across train/val/test at random - since those
    templates repeat heavily (e.g. one Pinterest path alone is 3,408 of its
    18,349 records), that inflates apparent benign val/test accuracy without
    real generalisation. Fall back to (app, url_path) grouping instead, so a
    whole template lands in ONE split. Attack records are unaffected (they
    already carry real session_ids from the personas)."""
    sid = rec.get("session_id")
    if sid:
        return sid
    app = (rec.get("metadata", {}) or {}).get("app", "")
    url_path = (rec.get("content", {}) or {}).get("url_path", "")
    return f"__template__{app}:{url_path}"


def stratum(rec):
    cls = (rec.get("label", {}) or {}).get("class", "benign")
    return cls if cls in ATTACK_CLASSES else "benign"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("inputs", nargs="+", help="processed JSONL file(s)/globs")
    ap.add_argument("--out-dir", default="data/splits")
    ap.add_argument("--ratios", default="70,15,15", help="train,val,test")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--cross-app-holdout", default="webgoat",
                    help="app whose known-attacks become cross_app_test; 'none' to disable")
    args = ap.parse_args()

    tr, va, te = (float(x) for x in args.ratios.split(","))
    tot = tr + va + te
    tr, va, te = tr / tot, va / tot, te / tot
    random.seed(args.seed)
    hold_app = None if args.cross_app_holdout.lower() == "none" else args.cross_app_holdout.lower()

    recs = load(args.inputs)
    if not recs:
        print("[!] no records loaded.")
        return 1

    # ---- 1) group into sessions, decide each session's destination ----
    sessions = defaultdict(list)
    for r in recs:
        sessions[session_key(r)].append(r)

    forced = {}          # sid -> 'heldout_unknown' | 'cross_app_test'
    splitable = defaultdict(list)  # stratum -> [sid, ...]
    for sid, items in sessions.items():
        classes = {(_r.get("label", {}) or {}).get("class") for _r in items}
        apps = {(_r.get("metadata", {}) or {}).get("app", "").lower() for _r in items}
        levels = {(_r.get("label", {}) or {}).get("level1") for _r in items}
        if "code_injection" in classes:
            forced[sid] = "heldout_unknown"
        elif hold_app and hold_app in apps and "malicious" in levels:
            forced[sid] = "cross_app_test"
        else:
            # stratum = majority class of the session
            strat = Counter(stratum(_r) for _r in items).most_common(1)[0][0]
            splitable[strat].append(sid)

    # ---- 2) stratified + grouped split of the remaining sessions ----
    # Sessions/templates are sorted by a HASH of (seed, session_key) instead
    # of random.shuffle(). Found 2026-09-17: shuffle draws from one shared
    # global random stream across ALL strata, in dict-iteration order - any
    # unrelated change elsewhere (even removing 5 noise records from a
    # different app) shifts how many draws happen before this stratum's
    # shuffle, changing its resulting order and therefore which of its large
    # (app, url_path) template-groups (some are 5-10% of ALL benign data on
    # their own - see session_key()'s docstring) land in val vs train. That
    # swung val's benign share from 15% to 6.5% for a 5-record unrelated fix.
    # A per-session hash is a pure function of (seed, session_key) alone, so
    # one session's assignment never depends on what other sessions exist.
    assign = {}          # sid -> 'train' | 'val' | 'test'
    for strat, sids in splitable.items():
        sids = sorted(sids, key=lambda s: hashlib.md5(f"{args.seed}:{s}".encode()).hexdigest())
        n_records = sum(len(sessions[s]) for s in sids)
        want_train = tr * n_records
        want_val = va * n_records
        seen = 0
        for s in sids:
            if seen < want_train:
                assign[s] = "train"
            elif seen < want_train + want_val:
                assign[s] = "val"
            else:
                assign[s] = "test"
            seen += len(sessions[s])

    # ---- 3) write split_role back onto every record ----
    for sid, items in sessions.items():
        role = forced.get(sid) or assign.get(sid) or "train"
        for r in items:
            r.setdefault("label", {})["split_role"] = role

    # ---- 4) outputs ----
    os.makedirs(args.out_dir, exist_ok=True)
    buckets = defaultdict(list)
    for r in recs:
        buckets[r["label"]["split_role"]].append(r)

    def dump(name, rows):
        with open(os.path.join(args.out_dir, name), "w", encoding="utf-8") as fh:
            for r in rows:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")

    dump("dataset_split.jsonl", recs)
    for role in ("train", "val", "test", "heldout_unknown", "cross_app_test"):
        dump(f"{role}.jsonl", buckets.get(role, []))
    benign_train = [r for r in buckets.get("train", [])
                    if (r.get("label", {}) or {}).get("class") == "benign"]
    dump("benign_train.jsonl", benign_train)

    # ---- 5) report ----
    print(f"[splits] ratios train/val/test = {tr:.2f}/{va:.2f}/{te:.2f} "
          f"| cross_app_holdout = {hold_app or 'none'} | seed={args.seed}")
    print(f"[splits] total records = {len(recs)}\n")
    header = f"{'split':16} {'total':7} {'benign':7} {'sqli':6} {'xss':6} {'cmdi':6} {'codeinj':7}"
    print(header)
    order = ["train", "val", "test", "cross_app_test", "heldout_unknown"]
    for role in order:
        rows = buckets.get(role, [])
        c = Counter((r.get("label", {}) or {}).get("class") for r in rows)
        print(f"{role:16} {len(rows):<7} {c.get('benign',0):<7} {c.get('sqli',0):<6} "
              f"{c.get('xss',0):<6} {c.get('command_injection',0):<6} {c.get('code_injection',0):<7}")
    print(f"\n[splits] benign_train.jsonl = {len(benign_train)} records "
          f"(feed to inject_payloads.py so injected are train-only, zero leakage)")

    # ---- 6) leakage self-checks ----
    ok = True
    # (a) no session spans two splits
    for sid, items in sessions.items():
        if len({r["label"]["split_role"] for r in items}) != 1:
            print(f"[LEAK] session {sid} spans multiple splits"); ok = False
    # (b) code_injection only in heldout_unknown
    for r in recs:
        if (r.get("label", {}) or {}).get("class") == "code_injection" \
                and r["label"]["split_role"] != "heldout_unknown":
            print("[LEAK] code_injection outside heldout_unknown"); ok = False; break
    print("[splits] leakage self-check:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
