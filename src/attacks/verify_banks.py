#!/usr/bin/env python3
"""verify_banks.py - static integrity checker for attack_payloads base banks.

Drop this file into  src/attacks/  and run from the repo root:

    python src/attacks/verify_banks.py

Exit code 0 = all hard checks pass, 1 = at least one FAIL.
WARN lines are advisory (quality issues that won't corrupt labels).

It introspects the SAME contract attack_scenarios.py relies on:
    attack_payloads.base_payloads(attack_type, goal) -> list[(payload_id, raw_payload)]
so it works without you changing anything in attack_payloads.py.

ID SCHEME (matches your real code): base_payloads() emits ids shaped
    <class>-<family>-<suffix>       e.g.  sqli-exploit-bool_or_num
where <family> is recon|exploit|exfiltration and the SUB-TECHNIQUE is the
leading token of <suffix> (bool / err / time / union / html / cookie / ...).

What it enforces (maps 1:1 to the design rules):
  [C1] payload_id GLOBAL uniqueness + one id -> one payload (variant lineage safety)
  [C2] namespaced id scheme  <class>-<family>-<suffix>            (advisory)
  [C3] >= TARGET_MIN distinct base payloads per KNOWN class       (volume lever)
  [C4] cross-class disjointness (no raw payload in two classes)   (label integrity)
  [C5] canonical/clean base payloads (not already %-encoded)       (no double-transform)
  [C6] code_injection kept SMALL & held-out (open-set integrity)
  [C7] intra-class exact duplicates (wasted bank slots)           (advisory)
  [C8] technique spread per class (no single bucket dominates)    (advisory)
"""
import os
import re
import sys
import urllib.parse
from collections import defaultdict

# ---- config -----------------------------------------------------------------
CLASSES = ["sqli", "xss", "command_injection", "code_injection"]
GOALS_FALLBACK = ["exploit", "recon", "exfiltration"]
KNOWN = {"sqli", "xss", "command_injection"}
TARGET_MIN = 60          # distinct base payloads per KNOWN class
CI_MAX = 20              # code_injection must stay small (held-out novel type)
ID_RE = re.compile(
    r"^(sqli|xss|command_injection|code_injection)-(recon|exploit|exfiltration)-[a-z0-9_]+$"
)

# ---- import the module under test ------------------------------------------
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
try:
    import attack_payloads as P  # noqa: E402
except Exception as e:  # pragma: no cover
    print(f"[FATAL] could not import attack_payloads from {HERE}: {e}")
    sys.exit(2)


def discover_goals():
    """Prefer the real Goal enum values if attacker_personas exposes them."""
    try:
        import attacker_personas as ap  # noqa
        for name in dir(ap):
            obj = getattr(ap, name)
            members = getattr(obj, "__members__", None)
            if members and any(
                v in {m.value for m in members.values()}
                for v in ("exploit", "recon", "exfiltration")
            ):
                return [m.value for m in members.values()]
    except Exception:
        pass
    return GOALS_FALLBACK


def call_bank(cls, goal):
    """Call base_payloads defensively across signature variants."""
    for args in ((cls, goal), (cls,)):
        try:
            res = P.base_payloads(*args)
            if res:
                return list(res)
        except TypeError:
            continue
        except Exception:
            return []
    return []


def collect():
    goals = discover_goals()
    # cls -> id -> payload   (dedup id across goals)
    by_class = {c: {} for c in CLASSES}
    for cls in CLASSES:
        for goal in goals:
            for item in call_bank(cls, goal):
                try:
                    pid, raw = item[0], item[1]
                except Exception:
                    print(f"[FATAL] base_payloads({cls},{goal}) did not return "
                          f"(id, payload) tuples; got: {item!r}")
                    sys.exit(2)
                by_class[cls][str(pid)] = str(raw)
    return goals, by_class


def looks_encoded(s):
    # canonical base payloads should decode to themselves
    try:
        return urllib.parse.unquote(s) != s
    except Exception:
        return False


def technique_of(pid):
    # ids are <class>-<family>-<suffix>; sub-technique = leading token of suffix
    parts = pid.split("-")
    if len(parts) >= 3:
        suffix = "-".join(parts[2:])
        return suffix.split("_")[0]
    return "(unbucketed)"


def main():
    goals, by_class = collect()
    fails, warns = [], []

    # [C1] global id uniqueness + id->payload 1:1
    id_to_payloads = defaultdict(set)
    for cls in CLASSES:
        for pid, raw in by_class[cls].items():
            id_to_payloads[pid].add((cls, raw))
    dup_ids = {i: v for i, v in id_to_payloads.items() if len(v) > 1}
    if dup_ids:
        fails.append(f"[C1] {len(dup_ids)} payload_id(s) map to >1 payload/class: "
                     f"{list(dup_ids)[:5]}")
    else:
        print("[PASS] C1 payload_id uniqueness (one id -> one payload)")

    # [C2] id namespacing (advisory)
    bad_ids = [pid for cls in CLASSES for pid in by_class[cls] if not ID_RE.match(pid)]
    if bad_ids:
        warns.append(f"[C2] {len(bad_ids)} id(s) not <class>-<family>-<suffix>: "
                     f"{bad_ids[:5]}")
    else:
        print("[PASS] C2 id namespacing scheme")

    # [C3] per-class distinct base counts
    print("\n  class            distinct  techniques")
    print("  ---------------  --------  ----------")
    for cls in CLASSES:
        raws = set(by_class[cls].values())
        techs = {technique_of(p) for p in by_class[cls]}
        print(f"  {cls:<15}  {len(raws):>8}  {len(techs)}")
        if cls in KNOWN and len(raws) < TARGET_MIN:
            fails.append(f"[C3] {cls} has {len(raws)} distinct base payloads "
                         f"(< target {TARGET_MIN})")

    # [C4] cross-class disjointness
    raw_owner = defaultdict(set)
    for cls in CLASSES:
        for raw in set(by_class[cls].values()):
            raw_owner[raw].add(cls)
    ambiguous = {r: c for r, c in raw_owner.items() if len(c) > 1}
    if ambiguous:
        sample = list(ambiguous.items())[:3]
        fails.append(f"[C4] {len(ambiguous)} payload(s) appear in >1 class "
                     f"(label ambiguity): {sample}")
    else:
        print("\n[PASS] C4 cross-class disjointness")

    # [C5] canonical / not pre-encoded
    encoded = [(cls, pid) for cls in CLASSES for pid, raw in by_class[cls].items()
               if looks_encoded(raw)]
    if encoded:
        warns.append(f"[C5] {len(encoded)} base payload(s) look pre-encoded "
                     f"(let apply_evasion encode): {encoded[:5]}")
    else:
        print("[PASS] C5 base payloads are canonical (not pre-encoded)")

    # [C6] code_injection held-out size
    ci = len(set(by_class["code_injection"].values()))
    if ci > CI_MAX:
        fails.append(f"[C6] code_injection has {ci} distinct payloads (> {CI_MAX}); "
                     f"keep the open-set class small & novel")
    else:
        print(f"[PASS] C6 code_injection held-out small ({ci} <= {CI_MAX})")

    # [C7] intra-class exact duplicate raws (advisory)
    for cls in CLASSES:
        seen, dups = set(), 0
        for raw in by_class[cls].values():
            if raw in seen:
                dups += 1
            seen.add(raw)
        if dups:
            warns.append(f"[C7] {cls}: {dups} duplicate raw payload(s) under "
                         f"different ids (wasted slots)")

    # [C8] technique spread (advisory): no bucket > 40% of a KNOWN class
    for cls in KNOWN:
        counts = defaultdict(int)
        for pid in by_class[cls]:
            counts[technique_of(pid)] += 1
        tot = sum(counts.values()) or 1
        for tech, n in counts.items():
            if n / tot > 0.40:
                warns.append(f"[C8] {cls}: technique '{tech}' is {n}/{tot} "
                             f"({100*n/tot:.0f}%) of the class (>40%)")

    # ---- summary ------------------------------------------------------------
    print("\n" + "=" * 60)
    print(f"goals discovered: {goals}")
    for w in warns:
        print("WARN " + w)
    for f in fails:
        print("FAIL " + f)
    if fails:
        print(f"\nRESULT: {len(fails)} FAIL, {len(warns)} WARN")
        sys.exit(1)
    print(f"\nRESULT: all hard checks PASS, {len(warns)} WARN")
    sys.exit(0)


if __name__ == "__main__":
    main()
