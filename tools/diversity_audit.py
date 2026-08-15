"""
Diversity + grounding audit for the attacker personas / scenarios.
Runs as a data-scientist style verification, NOT assertions:
  A. Axis coverage        - every axis value actually used by >=1 persona
  B. Pairwise distinctness - Hamming distance over the 6-axis vectors
  C. Payload yield         - unique payloads/variants produced per persona over N sessions
  D. Variant realisation   - does evasion actually create non-original variants
  E. Vector realisation    - where payloads really land (query/body/header/cookie)
  F. Class balance         - known (sqli/xss/path_traversal) vs held-out (code_injection)
  G. Grounding             - endpoints & attack scope match config/sources.yaml
"""
import itertools, os, sys, random, collections

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "src", "attacks"))

import yaml
from attacker_personas import ATTACKER_PERSONAS
from attack_scenarios import ENDPOINTS, endpoint_for, build_attack_steps
import attack_payloads as payloads

AXES = ["tooling", "evasion", "vector", "intensity", "rate", "goal"]
line = lambda c="-": print(c * 74)

# ---------------------------------------------------------------- A. coverage
line("=")
print("A. AXIS COVERAGE  (every value must be exercised by >=1 persona)")
line()
vals = {ax: collections.Counter() for ax in AXES}
for p in ATTACKER_PERSONAS.values():
    d = p.to_dict()
    for ax in AXES:
        vals[ax][d[ax]] += 1
for ax in AXES:
    print(f"  {ax:10s}: " + ", ".join(f"{k}({n})" for k, n in vals[ax].items()))

# ------------------------------------------------------- B. pairwise distance
line("=")
print("B. PAIRWISE DISTINCTNESS  (Hamming over 6 axes; 0 = identical persona)")
line()
vecs = {pid: tuple(p.to_dict()[ax] for ax in AXES) for pid, p in ATTACKER_PERSONAS.items()}
min_d = 99
for a, b in itertools.combinations(vecs, 2):
    d = sum(x != y for x, y in zip(vecs[a], vecs[b]))
    min_d = min(min_d, d)
    flag = "  <-- NEAR DUP" if d <= 1 else ""
    print(f"  {a:26s} vs {b:26s} dist={d}/6{flag}")
print(f"\n  MIN pairwise distance = {min_d}/6  "
      f"({'OK - all clearly distinct' if min_d >= 2 else 'PROBLEM - near-duplicates'})")

# --------------------------------------------- C/D/E. real generation sweep
line("=")
print("C-E. GENERATION SWEEP  (seeded, all personas x all valid app/attack)")
line()
CFG = yaml.safe_load(open(os.path.join(ROOT, "config", "sources.yaml"), encoding="utf-8"))
SESSIONS = 5
rng = random.Random(2026)

per_persona_payloads = collections.defaultdict(set)
per_persona_variants = collections.defaultdict(collections.Counter)
per_persona_vectors = collections.defaultdict(collections.Counter)
per_persona_total = collections.defaultdict(int)
class_counter = collections.Counter()
split_counter = collections.Counter()

HELDOUT = "code_injection"
for app, acfg in CFG["apps"].items():
    attack_list = list(acfg.get("attacks", []))
    if acfg.get("code_injection"):
        attack_list.append(HELDOUT)
    for pid, persona in ATTACKER_PERSONAS.items():
        for attack in attack_list:
            if not endpoint_for(app, attack):
                continue
            for _ in range(SESSIONS):
                for st in build_attack_steps(persona, app, attack, rng):
                    per_persona_payloads[pid].add((attack, st.payload))
                    per_persona_variants[pid][st.variant_type] += 1
                    per_persona_vectors[pid][st.vector] += 1
                    per_persona_total[pid] += 1
                    class_counter[attack] += 1
                    split_counter["heldout_unknown" if attack == HELDOUT else "train"] += 1

print(f"  (sessions/persona/app-attack = {SESSIONS}, seed=2026)\n")
print(f"  {'persona':26s} {'sent':>6s} {'uniq':>6s} {'uniq%':>6s}  variants / vectors")
for pid in ATTACKER_PERSONAS:
    sent = per_persona_total[pid]
    uniq = len(per_persona_payloads[pid])
    pct = 100 * uniq / sent if sent else 0
    v = dict(per_persona_variants[pid]); vec = dict(per_persona_vectors[pid])
    print(f"  {pid:26s} {sent:6d} {uniq:6d} {pct:5.1f}%  {v} {vec}")

# ----------------------------------------------------- D. variant global mix
line("=")
print("D. VARIANT MIX PER EVASION AXIS  (evasion must yield matching variants)")
line()
for pid, persona in ATTACKER_PERSONAS.items():
    ev = persona.evasion.value
    mix = dict(per_persona_variants[pid])
    ok = (ev == "none" and set(mix) <= {"original"}) or (ev != "none" and ev in mix)
    print(f"  {pid:26s} evasion={ev:8s} -> {mix}   {'OK' if ok else 'MISMATCH'}")

# --------------------------------------------------------- F. class balance
line("=")
print("F. CLASS BALANCE  (known vs held-out)")
line()
tot = sum(class_counter.values())
for k, n in class_counter.most_common():
    role = "HELD-OUT (open-set)" if k == HELDOUT else "known/train"
    print(f"  {k:16s} {n:6d}  ({100*n/tot:4.1f}%)  {role}")
print(f"  split totals: {dict(split_counter)}")

# ------------------------------------------------------------- G. grounding
line("=")
print("G. GROUNDING vs config/sources.yaml  (scope + endpoints)")
line()
for app, acfg in CFG["apps"].items():
    cfg_known = set(acfg.get("attacks", []))
    ci = acfg.get("code_injection")
    have = {a for (ap2, a) in ENDPOINTS if ap2 == app}
    missing_ep = cfg_known - have
    print(f"  {app:11s} cfg_known={sorted(cfg_known)} "
          f"code_injection={ci!r}")
    print(f"              endpoints_defined={sorted(have)}  "
          f"{'OK' if not missing_ep else 'MISSING '+str(missing_ep)}")
    if ci and not endpoint_for(app, HELDOUT):
        print(f"              WARNING: {app} has code_injection in cfg but no endpoint")
print("\n  agreed scope: known = sqli, xss, path_traversal ; held-out = code_injection")
known_defined = {a for (_, a) in ENDPOINTS if a != HELDOUT}
print(f"  known attack types with endpoints: {sorted(known_defined)}")
print(f"  held-out endpoint present: {bool(endpoint_for('juice_shop', HELDOUT))}")
line("=")
print("AUDIT COMPLETE")
