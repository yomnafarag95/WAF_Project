# Attack collection - design, personas & run guide

This directory generates the **attack** half of the dataset. It mirrors the
benign pipeline so both land in the same schema_v2 records (the shared
`src/capture/capture_addon.py` does the capture on the wire).

## Files
| file | role (analogue in benign pipeline) |
|---|---|
| `attacker_personas.py` | attacker POLICY on explicit axes (~ `personas/configs.py`) |
| `attack_payloads.py` | payload banks per class/goal + evasion->variant transforms |
| `attack_scenarios.py` | (persona, app, attack) -> `AttackStep` list (~ `personas/scenarios.py`) |
| `attack_driver.py` | PRIMARY generator, sets all X-Capture-* headers (~ `benign_driver.py`) |
| `run_attacks.sh` | OPTIONAL real-tool layer (sqlmap / XSStrike / dotdotpwn) |

## Persona axis-matrix (dimensional basis)
Each axis changes something OBSERVABLE in the captured request or its features.

| Persona | Tooling | Evasion | Vector | Intensity | Rate | Goal |
|---|---|---|---|---|---|---|
| noisy_automated_scanner | automated | none | query | high | burst | exploit |
| evasive_encoder | automated | encoded | query | medium | throttled | exploit |
| manual_stealth | manual_replay | mutated | body | low | throttled | recon |
| polyglot_specialist | manual_replay | polyglot | header | medium | throttled | exploit |
| exfiltration_operator | automated | mutated | query | high | burst | exfiltration |
| script_kiddie_defaults | automated | none | cookie | low | burst | recon |

- **Persona** -> `X-Capture-Persona`  |  **Scenario** -> `X-Capture-Scenario`
  (`attack:goal:vector`)  |  **Variant** -> `X-Capture-Variant` + `X-Capture-Parent`.
- `split_role` is set automatically by the addon: `code_injection` ->
  `heldout_unknown`, everything else -> `train`.

## The notes this design bakes in
1. **Separate capture dir** - the attack proxy writes to `data/raw_attack`
   (not `data/raw`), so deleting/recollecting benign never wipes attacks and
   vice-versa.
2. **Label safety** - `attack_driver.py` sets `X-Capture-Label` per request, so
   it never depends on the proxy's `default_label=sqli`. Only the header-less
   tools (XSStrike/dotdotpwn) need a per-type proxy `default_label` (see
   `run_attacks.sh` FIX 2).
3. **Service names not localhost** - the proxy container resolves DNS on
   `lab_net`, so targets are `juice-shop:3000` / `dvwa:80` / `webgoat:8080`.
4. **DVWA auth** - the driver fetches the CSRF `user_token`, logs in as
   admin/password, and sets `security=low`.
5. **Addon reload** - after ANY change to `capture_addon.py` or a proxy
   `--set`, run `docker compose up -d --force-recreate mitmproxy-attack`.
6. **Dedup** - diversity comes from payload banks x evasion variants; byte
   duplicates still collapse harmlessly at merge time.
7. **Open-set validity** - `code_injection` (Juice Shop SSTI) is collected
   through the SAME personas/evasion as the known classes, and SQLi+XSS are
   ALSO collected from Juice Shop, so "unknown" is a novel ATTACK TYPE, not a
   novel source or style.

### Vector caveat (read this)
`capture_addon.py` derives `content.decoded_payload` from the URL (path+query)
ONLY. Body/header/cookie payloads live in `content.raw_request` but are NOT in
the URL-derived aux features. To featurise non-query vectors, extend
`extract_features.py` to fold `request_body` + injected headers into
`decoded_payload`.

## Run order
```bash
# 0) bring up the attack proxy (separate dir, force-recreate to load config)
docker compose up -d --force-recreate mitmproxy-attack

# 1) preview WITHOUT sending anything
python3 src/attacks/attack_driver.py --config config/sources.yaml --dry-run

# 2) collect all attacks (train sqli/xss/path_traversal + held-out code_injection)
python3 src/attacks/attack_driver.py --config config/sources.yaml --sessions-per-persona 3 --seed 42

# 3) (optional) add real-tool volume - see run_attacks.sh

# 4) merge BOTH dirs (benign + attack), then verify class balance
python3 src/dataset/merge_jsonl.py --raw data/raw data/raw_attack --out data/merged/dataset_v2.jsonl
python3 tests/test_schema.py --stage raw
```


---

## Diversity & grounding audit (tools/diversity_audit.py)

Run: `python3 tools/diversity_audit.py`. Reproducible, data-driven verification
that the personas are genuinely diverse and grounded in the project scope.

**Verified OK**
- **Axis coverage**: every value of all 6 axes is exercised by >=1 persona
  (tooling, evasion, vector, intensity, rate, goal).
- **Pairwise distinctness**: min Hamming distance between any two personas = 2/6
  (no near-duplicates; each persona differs on >=2 axes).
- **Evasion realisation**: each persona's evasion axis yields the matching
  variant type (none->original, encoded, mutated, polyglot).
- **Grounding**: endpoints and attack scope match config/sources.yaml exactly;
  known = {sqli, xss, path_traversal}, held-out = code_injection (juice_shop SSTI).
- **Class balance**: sqli 33% / xss 33% / path_traversal 22% / code_injection 11%
  (held-out). path_traversal is lower because Juice Shop has no PT endpoint; CI is
  intentionally small and held-out-only.

**Known, intentional limitations (documented, not bugs)**
- **Byte-duplication under high intensity + no evasion**: noisy_automated_scanner
  (~3% unique) and script_kiddie_defaults (~6% unique) repeat payloads because
  budget (22 / 4) exceeds the base-payload bank size. This is REALISTIC (a noisy
  scanner really does hammer the same payloads) and byte-identical repeats
  collapse in merge_jsonl.py dedup, so they do not distort labels. To raise unique
  yield, expand the base banks in attack_payloads.py or lower intensity.
- **polyglot_specialist**: originally collapsed to 4 unique payloads; fixed by
  turning POLYGLOTS into a per-class BANK (now ~19 unique). Still lower-volume by
  design (a specialist fires few, deliberate payloads).
- **body vector**: manual_stealth's body payloads fall back to query on GET-only
  endpoints; only juice_shop code_injection (POST /profile) carries a true body
  payload. Header/cookie vectors are always realised.
