# Progress log

## 2026-09-17 (cont.) — Full pre-finalization audit: 3 more real findings, 1 was severe

Requested: a concrete, systematic audit of the whole pipeline before treating
any result as final. Went beyond re-confirming known-good areas; found three
new, previously-undiscovered issues.

**1. New noise-path** (`/live_pipeline/events`, X's real-time pubsub telemetry,
sibling of the already-filtered `update_subscriptions`) - only 5 records
total, but 4 landed in the test split and were the ENTIRE explanation for
the "unexplained" x-app 5.6% Stage-1 FPR flagged earlier. Filtered and purged.
Confirmed fix: x's FPR is now exactly 0.0%.

**2. Payload double-encoding defect**: `apply_evasion()`'s "encoded" variant
was re-percent-encoding 5 command_injection payloads whose base form already
contains a literal `%0a`/`%0d` marker (`%0a id` -> `%250a id`), which a
single server-side URL-decode does not reverse back to a working separator -
and is also invisible to the `kw_cmdi_count` feature post-encoding. Affected
~206 already-captured records (~10% of command_injection) - not a labeling
or leakage defect (still genuine attack-intent captures, same tolerance the
project already extends to blind/recon attempts elsewhere), but fixed at the
source (skip percent-based re-encoding when the payload already contains
`%`) so it stops recurring.

**3. Split-instability bug (the serious one)**: `make_splits.py` sorted each
stratum's sessions via `random.shuffle()`, which draws from ONE shared
global random stream, consumed in dict-iteration order across ALL strata.
Some real-site benign apps have no `session_id`, so `session_key()` groups
them by `(app, url_path)` template instead - and several of those template
groups are individually 5-10% of ALL benign data. Removing the 5 noise
records above (finding #1) - unrelated to this app - shifted the shuffle
draw sequence enough that val's benign share swung from the intended 15% to
6.5% (val total 4630 -> 2539). Root-caused precisely (confirmed empirically:
the largest single template group is 2,412 records, 65% of the entire val
quota, by itself) and fixed by replacing the shared shuffle with a hash of
`(seed, session_key)` - a pure function of that session alone, so one
session's split assignment can never depend on what other sessions exist.
Re-verified: val is now within a few records of the exact 15% target
(3,684/24,563 benign = 15.00%) and stays that way regardless of unrelated
data changes going forward.

**Also verified clean** (checked the code directly, not assumed): no
response-derived feature leakage; cross-app holdout never leaks bWAPP into
train/val/test; synthetic-payload injection correctly excludes eval-set
signatures; feature-key alignment between extraction and training is exact;
`verify_banks.py` hard checks all pass; Pinterest's residual 0.2% FPR is
genuine model imprecision on complex real API traffic, not a data defect;
12-19% of val/test share an exact signature with train (finite payload bank
reusing "original" variants) but accuracy on the non-duplicate subset is
statistically indistinguishable from the reported number, and
`cross_app_test`/`heldout_unknown` have zero such overlap.

**Final numbers, full pipeline (dataset v8, all three fixes applied, stable
splits), RandomForest stage1 + XGBoost stage2:**

| | val | test | cross_app_test | heldout_unknown |
|---|---|---|---|---|
| Stage 1 accuracy | 99.59% | 99.91% | 97.67% | 91.55% |
| Stage 2 accuracy | 100% | 99.89% | 93.65% (macro-F1 0.922) | - |
| Cascade accuracy | - | 95.83% | 73.36% | 64.00% |
| Per-app FPR, worst case | - | 0.20% (pinterest) | - | - |

---

## 2026-09-17 — Found and fixed: header-realism patch was destroying header/cookie-vector attack payloads

`tests/test_attacks.py` (never run against bwapp data before) flagged 21
bwapp XSS rows with no detectable payload signature. Traced to
`patch_attack_headers.py`: two of the six attacker personas put their entire
payload in a header ("polyglot_specialist" -> User-Agent) or the Cookie
header ("script_kiddie_defaults" -> Cookie), and `attack_scenarios.py`'s
`force_vector` can push ANY persona into header-vector on some endpoints
(e.g. bwapp's `xss_user_agent.php`). The header-realism patch (needed to fix
the original source-shortcut bug) blindly replaced EVERY header with a
donor's, including the ones carrying the actual attack - silently turning
~1,758 records (1,343 header-vector + 415 cookie-vector, ~16% of all
malicious data) into rows labeled "attack" whose visible content was
indistinguishable from benign traffic.

Root cause of the detection gap: `metadata.persona_id` alone doesn't reflect
`force_vector` overrides. Fixed by keying off the last component of
`metadata.scenario_id` (the ACTUAL per-step vector) instead, and preserving
that one payload-carrying header line while still replacing every other
header with a donor value. Rebuilt the full pipeline (dataset v7).

**Effect - not a marginal fix:**

| | before (v6, bug present) | after (v7, fixed) |
|---|---|---|
| Stage 1 cross-app accuracy (RandomForest) | 89.69% | **97.79%** |
| Stage 1 heldout-unknown accuracy | 80.63% | **89.93%** |
| Stage 2 cross-app accuracy (XGBoost) | 85.60% | **95.00%** |
| Stage 2 cross-app macro-F1 | 0.849 | **0.939** |
| Open-set known-reject rate (val) | 40.9% | **16.8%** |
| Cascade cross-app accuracy | 45.3% | **76.3%** |

~16% of the malicious training data had been silently teaching the model
that "attack" looks like ordinary benign traffic - removing that noise
improved essentially every generalization metric at once. Per-app FPR on
`x` (5.6%, small 71-row sample) is unrelated to this fix (benign-side, not
malicious-side) and remains an open item.

---

## 2026-09-12 (cont.) — Production stage-1 model switched to RandomForest; open-set reweighting tested and rejected

Investigated whether the open-set "known-attack flagged unknown" rate
(40.9% val / 51.4% cross-app) could be improved for real. Tested 3
candidates: pure softmax (rejected - it's the exact config already known to
collapse 52%->39% recall under adversarial mutation search), a learned
logistic combination of isoforest+softmax (AUC 0.793, still worse than pure
softmax), and reweighting the ensemble toward the isoforest (alpha=0.9).

Alpha=0.9 looked promising in a first pass but that pass used the fuzzer's
hardcoded xgboost stage-1 model. Re-ran against random_forest stage-1 (the
model this project already knew generalizes better) and alpha=0.9 was
**strictly worse on every axis** (static recall 87.3%->74.7%, adversarial
recall 82.0%->64.7%, worst-case full-bypass 10.0%->12.0%). **Conclusion: do
not reweight the open-set ensemble** - the 40.9%/51.4% reject rate is a real,
deliberate cost of adversarial robustness, not a fixable miscalibration.

The one validated, cost-free win from this investigation: switching
production stage-1 from xgboost to random_forest, applied now in
`train_baseline.py` (`rf1` replaces `xgb1` in the cascade / per-app-FPR
sections; stage2 stays xgboost, which wins every stage-2 split outright).
Added `accuracy` to both stage1 (`binary_metrics`) and stage2 (`run_stage2`)
metrics output - previously only F1/precision/recall/FPR (stage1) and
macro-F1/per-class-F1 (stage2) were tracked.

**Final numbers (random_forest stage1 + xgboost stage2 + method E open-set,
dataset_v6, CMDI fix applied):**

| | val | test | cross_app_test | heldout_unknown |
|---|---|---|---|---|
| Stage 1 accuracy | 99.96% | 99.83% | 89.69% | 80.63% |
| Stage 2 accuracy | 94.78% | 94.31% | 85.60% | — |
| Cascade accuracy | — | 91.78% | 45.33% | 68.10% |

Cascade heldout_unknown accuracy jumped from 23.2% (xgboost stage1) to
**68.1%** purely from the stage1 swap - random_forest's much higher
code_injection recall (80.6% vs 33.6%) means far more of those rows now
correctly reach and get flagged "unknown" by the open-set gate instead of
being silently absorbed as "benign" before ever reaching it.

---

## 2026-09-12 — bWAPP replaces WebGoat as cross-app holdout; CMDI keyword-bank gap closed

Follow-up to the cross-app recall collapse below (26.5%/43.8%). Diagnosis:
real attack training data came from only 2 apps (DVWA, Juice Shop) — WebGoat's
real attacks were always held out for testing, and WebGoat has no
command_injection vulnerability at all, so command_injection cross-app
generalization was never even measurable. User noticed the WebGoat gap and
proposed swapping it for an app that actually has all three known classes.

**1. Added bWAPP as the new held-out cross-app test target** (replacing
WebGoat, which now feeds its real sqli/xss attacks into training instead).
`docker-compose.yml` service, `config/sources.yaml` entry, `login_bwapp()` in
`attack_driver.py`. Every endpoint (sqli ×6 variants, xss ×4, command_injection
×2) was ground-truth verified live via `curl` against the running container
(login flow, form field names, `portal.php` bug-ID → page redirects) — not
guessed from training-data memory.

**2. Refactored attack generation for real endpoint diversity**, per user
request after they noticed bWAPP's UI exposes many distinct vulnerable forms
per class. `ENDPOINTS` in `attack_scenarios.py` changed from one dict per
(app, attack_type) to a list of real variants; `build_attack_steps()` now
picks a variant at random per payload, so one capture run naturally spreads
across GET/POST/blind/header-vector forms instead of hammering one page.

**3. Capture run — two process mistakes, both caught, neither corrupted data:**
- Misreported "capture finished" to the user based on a **stale task-output
  file from an earlier 2-session smoke test**, not the actual 18-session
  production run, which was still executing in the background. Caught later
  by noticing the timestamps in the captured data didn't add up (traffic
  kept arriving well past the reported finish time).
- Restarted the capture proxy mid-run (to load a bugfix, see next item)
  without realizing the original run was still live, then launched a second
  supplemental run concurrently against the same container/session. Verified
  after the fact that this caused no corruption (3,480/3,480 unique
  `record_id`s in the final file, zero collisions) — but it was a process
  hygiene lapse, not a verified-safe-by-design choice.

**4. Found and fixed a real capture-pipeline bug**: the header-vector XSS
endpoint (`xss_user_agent.php`, payload lives only in the `User-Agent`
header) yielded 1 sample out of 536. Root cause: `is_duplicate()` in
`capture_safety.py` fingerprinted requests on `(method, path, body)` only —
this endpoint's method/path/body never varies (payload is header-only), so
every request after the first hashed identical to the first and was dropped
as an "exact duplicate" by the strict `MAX_DUPLICATES=1` filter. Fixed by
folding the `User-Agent` header into the dedup signature. Restarted the
proxy, re-ran a targeted backfill — final: 277/1,543 XSS samples on that
endpoint.

**5. Caught a near-miss before it reached the merged dataset**: bWAPP's
captured attack traffic still carried bare python-requests headers (the
exact shortcut fixed for DVWA/Juice Shop/WebGoat earlier — `capture_headers()`
only sets internal `X-Capture-*` control headers, not the visible
User-Agent/Accept stack). Since bWAPP is now the cross-app holdout, merging
it unpatched would have reintroduced the header-shortcut confound on the one
measurement the whole diversity fix exists to validate. Re-ran
`patch_attack_headers.py` (already covers any `*_raw.jsonl`, so bWAPP was
picked up automatically) before merging. **Any future app added (e.g.
Mutillidae II) needs this same patch step, or the bug returns.**

**Final bWAPP capture**: sqli=1,070 (6 endpoints, 162-192 each), xss=1,543
(4 endpoints, 277-445 each), command_injection=867 (2 endpoints, 420-447
each) — all above the ~800-900/class target.

**6. Rebuilt the full pipeline**: `dataset_v6.jsonl` (merge) → features →
`make_splits.py --cross-app-holdout bwapp` (**leakage self-check: PASS**) →
`inject_payloads.py --ratio 0.30` → `train_baseline.py`.

**7. Found and fixed the CMDI keyword-bank gap** (user had explicitly
requested this earlier and it had been deferred). Quantified: 57/165 (34.5%)
of the command_injection payload bank scored `kw_cmdi_count == 0` — the
feature was blind to a third of its own class. Root cause: the hand-written
keyword list paired `;`/`|`/`&&` with only 10 command names, while the
payload generator uses 18 commands and also emits `||`-separated and
`&`-separated variants never added to the list. Checked *why* single-`&` was
excluded before "fixing" it: verified 489/17,201 real benign records already
contain `&id=`/`&env=`/`&dir=`-style substrings from ordinary multi-param
query strings (vs. 0/17,201 containing literal `&&` or `||`) — adding
`&`+command as a keyword would have created hundreds of false positives.
Rewrote `CMDI_KEYWORDS` in `extract_features.py` as a generated product of
safe separators (`;`, `|`, `&&`, `||`) × the full 18-command list, keeping
single-`&` and literal-newline payloads deliberately excluded and documented.
Gap closed to 14.5% (24/165), all residual cases are the two documented
exclusions. Verified against all 17,201 benign train records: 1 new false
positive (0.006%, an HTML-entity-encoded `&amp;psc=1` Amazon tracking param
colliding with `;ps`) — negligible.

**Results, WebGoat-holdout baseline → bWAPP-holdout + CMDI fix (final):**

| metric | before | after |
|---|---|---|
| Stage-1 cross_app_test recall (best model) | 26.5% | 89.7% (random_forest) |
| Stage-1 heldout_unknown recall (best model) | 43.8% | 80.6% (random_forest) |
| Stage-2 cross_app_test macroF1 (xgboost) | n/a (no cmdi) | 0.849 |
| Stage-2 cross_app_test command_injection F1 (xgboost) | n/a | 0.720 → **0.820** after CMDI fix |

**Known open issue, not yet addressed**: the end-to-end cascade's
cross_app_test accuracy (≈42%) is held down by the open-set threshold
flagging a large fraction of genuinely-known bWAPP attacks as "unknown"
rather than misclassifying them — the current calibration (method E, tuned
on val-known vs. code_injection-unknown) conflates "novel attack class" with
"novel app distribution shift." Flagged for a future calibration pass.

**Also outstanding**: Mutillidae II (training-diversity source, not a
holdout) was discussed but never set up — no docker-compose service, no
`sources.yaml` entry, no capture run exists yet.

---

## 2026-09-11 (cont.) — Discovered: ~5,000 captured X records never merged

While building the header-donor pool for the Stage-1 shortcut fix, user
flagged that more X data had been placed in the project than the pipeline
is using (X currently sits at only 3,121 benign records / 45 in the raw
per-app file, the thinnest of the 11 apps). Investigated and found two
unmerged batches:

- `data/validated/x_yasmeen_2026-09-01.jsonl` — 1,908 records, already
  validated (QA report exists, 2026-09-03), but flags one issue: the path
  `/1.1/live_pipeline/update_subscriptions` is 34% of all traffic (a
  background polling/heartbeat endpoint) — needs noise-path filtering before
  merge, same class of issue already fixed once for a Pinterest path.
- `data/incoming_drive/2026-09-09/yomna/x_yomna_2026-09-09.jsonl` — 3,079
  records, captured but with **no QA report at all** — never even entered
  the validation step.

Neither is a quick fix: each needs the same validate → dedup → merge →
re-run-pipeline procedure already used for the Amazon and first X merges
earlier in this project (a preventive noise-path patch,
`patch_noise_path_x_timeline.py`, exists in the repo root but targets a
*different* endpoint - it does not fix Yasmeen's flagged noise path).

**Decision reversed same day: user asked to merge it before continuing.**
Executed the full validate → filter → merge → re-run-pipeline procedure:

1. QA check (`daily_qa_check.py`) on both unvalidated batches. Amazon
   (1,016 records) passed clean. Both X batches (Yasmeen's 1,908 and
   Yomna's 3,079) confirmed the same noise path
   (`/1.1/live_pipeline/update_subscriptions`, 34.0% and 35.6% of traffic
   respectively - a background polling endpoint).
2. Redaction spot-check on all 3 batches - `[REDACTED]` present and correct
   on every Cookie header found, 0 unredacted credentials.
3. Filtered the noise path out of both X batches (1,259 and 1,982 records
   kept respectively).
4. `merge_and_dedup.py` into `data/raw/{amazon,x}_raw.jsonl`: amazon
   1,194→2,210 (0 dupes - all new), x 45→2,027 unique (1,259 cross-batch
   duplicates removed - the two X captures overlapped substantially, which
   makes sense given both scraped the same live site's API-heavy traffic).
5. Rebuilt the full merged dataset: `src/dataset/merge_jsonl.py --raw
   data/raw data/raw_attack --out data/merged/dataset_v3.jsonl` (discovered
   attacks live in a separate `data/raw_attack/` dir - first attempt missed
   this and silently produced a benign-only merge, caught by checking the
   class distribution before proceeding rather than assuming the tool's
   output was correct). Result: 31,774 records (up from 28,778 in v2).
6. Re-ran `extract_features.py` -> `dataset_v3_processed.jsonl`, then
   `make_splits.py` -> new train/val/test/cross_app_test/heldout_unknown.
   **Leakage self-check: PASS.**
7. Re-ran `inject_payloads.py --ratio 0.30 --seed 42` for the new benign
   pool (17,850 shells, up from before) -> 4,709 synthetic attack rows.

**Result: X's benign volume in-splits goes from 45 (essentially unusable)
to 2,025** - no longer the thinnest app category. Amazon similarly grows.
All downstream numbers (stage1/2 accuracy, open-set recall, cross-app
generalization, latency) are now STALE relative to this new data and need
re-running before being cited again - noted as the next required step,
ahead of finishing the header-realism fix's step 2.

---

## 2026-09-11 — EDA reveals Stage 1's F1=1.0000 substantially relies on a source-artifact shortcut

User's instinct: "these numbers look like a bad indicator" (too-perfect F1) —
requested an EDA to investigate stage1/stage2 rather than keep reporting the
numbers at face value. Correct instinct.

New file: [`eda_stage1_stage2.py`](../eda_stage1_stage2.py). On val+test only
(never train, to rule out fitting-artifact arguments): single-feature
separability sweep across all 26 features, standardized 2D PCA, correlation
heatmap, feature distributions by class.

**Finding: `header_payload_length` alone achieves AUC = 1.0000** separating
benign from malicious. Root cause, confirmed directly: 100% of val/test's
malicious rows are `source_type=scripted` (attack_driver.py / inject_payloads.py
tooling, bare-minimum headers, mean header_payload_length ≈ 23 bytes) vs. real
Playwright-persona browsing traffic (mean ≈ 610-629 bytes, full realistic
header stack). Visually confirmed: malicious traffic spikes at
`header_count≈5-6`; benign spans 20-40 with almost no overlap.

**Quantified via ablation** (retrain stage1 XGBoost with all structural/
timing/content-type features removed — path_length, query_param_count,
header_payload_length, header_count, cookie_payload_length, inter_arrival_ms,
request_rate_window, content_type buckets — keeping only payload-content
features):

| configuration | F1 | false positives | false negatives |
|---|---|---|---|
| Full 26 features (as reported everywhere to date) | 1.0000 | 0 | 0 |
| Structural/source features removed | 0.3557 | 2,413 / 6,876 benign (35%) | 0 |

**Stage 2 checked identically and found clean** — macro F1 stays 1.0000 with
the same features removed; its performance is genuinely attributable to
attack-content signals (`sql_comment_count`, `angle_bracket_count`,
`kw_xss_count`, `kw_cmdi_count`), not the source artifact.

**Implications, not yet acted on:**
1. Every "Stage 1 F1=1.0000 / FPR=0.0000" claim already written into
   `reports/mvp_results_2026-09-10.html` and `reports/mvp_report_ieee_2026-09-10.html`
   overstates what's been demonstrated — real, but closer to "detects
   automated-tooling traffic" than "detects attack payloads."
2. **Genuine untested adversarial blind spot**: every adversarial search this
   session (`fuzz_adversarial.py`, `fuzz_adversarial_methodE.py`) mutated
   payload content only, never request structure/headers. An attacker adding
   realistic browser headers to existing tooling — no payload change needed —
   is untested and plausibly evades Stage 1 on this evidence.
3. Directly matches the "source shortcut" failure mode the user's own project
   proposal names in its related-work review (Martínez et al.) and claims to
   avoid by design ("a self-built paired dataset removes the source shortcut
   by construction, a property verified empirically rather than assumed") —
   this EDA is that verification, and it does not fully hold for Stage 1 as
   currently built.

**Fixed (2026-09-11, same day) via `patch_attack_headers.py`:** replaced the
bare python-requests header set on all 7,272 attack_driver-captured
malicious records (dvwa/juice_shop/webgoat) with a randomly-sampled real
browser header set from `build_header_donor_pool.py`'s rich-app pool
(pinterest/amazon/facebook/x/youtube - apps confirmed to have substantial,
diverse real headers; dvwa/juice_shop/webgoat's OWN benign headers were
checked and found too thin themselves, ~6-8, to serve as same-app donors).
Host header preserved to match each record's real target, only the header
block replaced, payload untouched. Full pipeline rebuilt on the patched data
(`dataset_v4.jsonl` -> re-extracted -> re-split, leakage check PASS ->
re-injected).

**Re-ran the exact same ablation. Result: substantial, not complete, fix:**

| configuration | F1 | false positives |
|---|---|---|
| Full 26 features | 0.9957 | 6 / 3,796 benign |
| Content-only, before header fix | 0.3557 | 2,413 / 6,876 (35%) |
| **Content-only, after header fix** | **0.6578** | **721 / 3,796 (19%)** |

**Single-feature separability re-checked: the shortcut is gone.** No feature
now approaches AUC=1.0 (max is `special_char_ratio` at 0.85, a genuine
content signal - attack payloads legitimately contain more special
characters). The remaining gap between 0.9957 and 0.6578 is now explained by
structural features (`query_param_count`, `path_length`) providing real but
secondary signal, not a single dominant artifact - a materially more
defensible situation than before, and now backed by evidence rather than
assumed.

**Not yet decided:** whether to adopt the content-only model as the
"official" reported Stage 1 (more conservative, defensible claim) or keep
the full 26-feature model (higher accuracy, weaker-but-real structural
reliance now well-characterized). Also still pending: re-running
`train_baseline.py` fully on this new data for updated official numbers
across the whole pipeline (open-set, cross-app, latency), extending
adversarial testing to headers, and updating both reports.

Outputs: [`reports/eda/eda_results.json`](eda/eda_results.json), [`reports/eda/pca_projection.png`](eda/pca_projection.png), [`reports/eda/correlation_heatmap.png`](eda/correlation_heatmap.png), [`reports/eda/top_feature_distributions.png`](eda/top_feature_distributions.png).

---


Running, append-only record of work done on this project by session, so it's
trackable from files instead of chat history. Newest entry at the top.

---

## 2026-09-10 — Leave-one-class-out open-set evaluation

Discussed project direction: agreed NOT to retreat from open-set detection
(it's the one thing none of the four reference papers attempt) and instead
invest in it properly. First step, agreed with the user: stop relying on a
single held-out class (`code_injection`) for the open-set number and check
whether ~52% recall is a structural ceiling or a `code_injection`-specific
quirk.

New file: [`loco_openset_eval.py`](../loco_openset_eval.py). Rotates the
"pretend-unknown" role across the three real, well-populated known classes
(`sqli`, `xss`, `command_injection`), retraining stage1+stage2 from scratch
each fold with that class fully excluded from all training material (mirrors
`code_injection`'s exclusion exactly), then scores the excluded class as the
open-set "unknown" proxy using the same method-A (max-softmax) + Youden's-J
threshold sweep as `calibrate_openset.py`.

**Result:**

| held-out class | open-set recall | known-reject |
|---|---|---|
| sqli | 41.68% | 1.77% |
| xss | 52.79% | 0.22% |
| command_injection | 61.88% | 0.19% |
| **mean (3 folds)** | **52.12%** (std 8.26%) | 0.73% |
| code_injection (reference, single-class) | 52.20% | 0.28% |

The 3-fold mean (52.12%) landed almost exactly on the single-class reference
(52.20%). **This is the key finding: the ~50% open-set recall ceiling is a
structural property of the softmax signal on this feature space and stage2
model — not an artifact of `code_injection` being the smallest/most
synthetic-looking bank.** That answers the open question from the adversarial
fuzzing entry below and justifies moving to a genuinely different open-set
method (OpenMax, EVT-calibrated) rather than further calibration tricks on
the same softmax signal.

Outputs: [`reports/loco_openset/loco_results.json`](loco_openset/loco_results.json), [`reports/loco_openset/loco_summary.png`](loco_openset/loco_summary.png).

### OpenMax (EVT-calibrated open-set method) — tried, and it lost

New file: [`openmax_openset.py`](../openmax_openset.py). Implemented OpenMax
(Bendale & Boult, CVPR 2016) adapted to XGBoost's margin/logit space in place
of a CNN's penultimate-layer activations: per-class mean activation vector
+ Weibull tail fit (EVT) on eucos-distance of correctly-classified training
points, then revise the top-ranked class activations down and redirect that
mass into an explicit "unknown" logit before softmax. Added as method D
alongside A/B/C in `reports/train_baseline/openset_comparison.json`.

**Result: it's the second-worst of the four methods tried.**

| method | 5-way macro F1 | open-set recall | known-reject |
|---|---|---|---|
| A: baseline softmax (fine threshold sweep) | **0.8167** | 52.20% | 2.11% |
| B: temperature-scaled softmax | 0.6186 | 10.76% | 0.00% |
| C: Mahalanobis distance | 0.7022 | 97.80% | 65.73% (too expensive) |
| D: OpenMax (EVT) | 0.6834 | 23.73% | 0.28% |

**Diagnosis, not just a number:** OpenMax is built on an assumption that
holds for CNN penultimate-layer embeddings — a genuinely novel input tends to
produce *uniformly lower-magnitude activations across all classes*, so it
lands far from every class's mean activation vector and the EVT tail catches
it. XGBoost's margin space doesn't have that property for this problem: the
Weibull fits (shape ≈1.3–1.8, scale <1, loc ≈6–8.4) show each known class is
tightly, confidently clustered in margin space — and `code_injection` points
get assigned a confident, high-magnitude margin for whichever known class
they superficially resemble (matches the original finding: mean unknown
max-softmax-proba is 0.96, barely below known's 0.9997). They just aren't far
from the wrong class's center in the way OpenMax's geometry assumes. This is
the same root problem as the softmax overconfidence issue in a new costume,
not a fix for it.

**Where this leaves things:** four substantively different open-set methods
tried (threshold sweep, temperature scaling, distance-to-centroid, EVT) and
plain calibrated softmax (method A, 52.2% recall / 0.82 macro F1) still wins.
That's itself a defensible, citable finding for the thesis — a real
comparison table with an honest negative result, not just "we picked the
first thing that worked." Framed as: for attack-detection on structured/
tabular features with a tree-ensemble backbone, don't assume open-set methods
built for deep image-embedding geometry transfer — measure them.

Outputs: [`reports/train_baseline/openset_comparison.json`](train_baseline/openset_comparison.json) (method D added), [`reports/train_baseline/openmax_calibration.png`](train_baseline/openmax_calibration.png).

### Isolation Forest ensemble (method E) — the interesting one

New file: [`isoforest_openset.py`](../isoforest_openset.py). Rather than another
score derived from stage2's own decision surface, fit an unsupervised
`IsolationForest` directly on the known-malicious feature space (no class
labels used) — a genuinely independent signal from softmax confidence. Two
ensembles tried, both z-scored against val before combining: mean (both
signals must agree) and max (either fires).

**Full 5-method table now:**

| method | 5-way macro F1 | open-set recall | known-reject |
|---|---|---|---|
| A: baseline softmax | 0.8167 | 52.20% | 2.11% |
| B: temperature softmax | 0.6186 | 10.76% | 0.00% |
| C: Mahalanobis | 0.7022 | 97.80% | 65.73% |
| D: OpenMax | 0.6834 | 23.73% | 0.28% |
| **E: IsolationForest + softmax (mean)** | **0.8109** | **100.00%** | 43.82% |
| E: IsolationForest + softmax (max) | 0.7983 | 82.18% | 34.69% |

E_isoforest_mean is the first method to genuinely separate on an independent
signal (its histogram shows real tail structure, unlike D's collapsed-at-zero
plot) and it's the only one besides A to land a macro F1 near 0.81-0.82 — but
it gets there by accepting a 43.8% known-reject rate, landing almost exactly
on method A's macro F1 by a completely different route (near-total recall,
high cost) rather than beating it outright.

**Open question raised for discussion, not yet resolved:** "known-reject" in
this metric means a genuinely KNOWN attack (real sqli/xss/cmdi) gets labeled
"unknown" instead of its correct class — but stage 1 still flagged it
malicious either way, so in a real deployment that traffic is still blocked/
logged as suspicious, just mislabeled. That's a much cheaper mistake than a
false positive against real benign traffic (measured separately at 0.0000
FPR across all 11 apps, untouched by any of this). If that reframing holds,
method E's 43.8% cost may be far less expensive operationally than the raw
number suggests, and E (not A) could be the better real deployment choice.
This needs a decision, not more code, before picking a "final" method.

Outputs: [`reports/train_baseline/openset_comparison.json`](train_baseline/openset_comparison.json) (methods E added), [`reports/train_baseline/isoforest_calibration.png`](train_baseline/isoforest_calibration.png).

### Decision: method E adopted as primary open-set method

User's call on the reframing above: mislabeling a known attack as "unknown"
is cheap (stage1 still blocks it either way), so recall against genuinely
novel attacks is what matters most. **Method E (IsolationForest + softmax,
mean ensemble) is now the project's primary open-set method.**

Before trusting that decision, ran the same adversarial-search stress test
against method E that was run against method A
(`fuzz_adversarial_methodE.py`, full 864 heldout `code_injection` rows,
6 compounding rounds — refactored `isoforest_openset.py` to expose
`fit_isoforest()` / `build_mean_ensemble_scorer()` so this script can reuse
the exact fitted ensemble instead of duplicating the fit logic):

| | static recall | adversarial recall | worst case (evades stage1 too) |
|---|---|---|---|
| A: baseline softmax | 52.20% | 39.12% (-13.1pt, -25% relative) | 0/864 |
| **E: IsolationForest ensemble** | **100.00%** | **98.26%** (-1.7pt, -1.7% relative) | 0/864 |

Method E's recall barely moves under adversarial search, while method A's
drops by a quarter. This is a second, independent piece of evidence (not
just the static number) that the IsolationForest signal is a materially
different and more robust kind of open-set defense — it isn't just winning
on a sample the way the earlier softmax-based methods' small differences
sometimes were.

**Current project state: method E is the adopted open-set method for the
cascade.** `train_baseline.py`'s `calibrate_open_set()` / `run_cascade()`
still hard-code the original coarse softmax threshold sweep and have NOT yet
been updated to use method E — that's the next piece of work if we want the
"official" end-to-end cascade numbers (and the pipeline status report) to
reflect this decision rather than living only in these standalone scripts.

Outputs: [`reports/adversarial_fuzz_methodE/fuzz_methodE_results.json`](adversarial_fuzz_methodE/fuzz_methodE_results.json), [`reports/adversarial_fuzz_methodE/fuzz_methodE_summary.png`](adversarial_fuzz_methodE/fuzz_methodE_summary.png).

### Method E wired into `train_baseline.py` — and a new, real problem surfaced

Replaced the old coarse softmax-threshold `calibrate_open_set()` with method
E (`fit_open_set_ensemble()`: IsolationForest fit on known-malicious training
features + stage2 softmax, mean-ensembled, fine Youden's-J threshold sweep).
`run_cascade()` now takes a generic `unknown_score_fn` instead of hard-coding
softmax. Artifacts persisted: `models/openset_isoforest.joblib`,
`models/openset_ensemble_config.json` (z-score calibration + threshold), so
the exact fitted ensemble is reproducible without recomputation.

Ran the full pipeline end to end. Two very different outcomes:

| split | old (method A) accuracy | new (method E) accuracy |
|---|---|---|
| test | 99.96% | 96.27% |
| **cross_app_test (WebGoat, unseen app)** | **99.54%** | **16.20%** |
| heldout_unknown (code_injection) | 31.13% | **100.00%** |

`heldout_unknown` is exactly the win we expected and validated in isolation.
**`cross_app_test` collapsing from 99.5% to 16.2% is a genuine new problem,
not a rounding difference.** Diagnosed, not just observed: stage2's raw
classification on `cross_app_test` is still near-perfect on its own
(sqli/xss F1 = 0.999-1.000, confirmed in the STAGE 2 printout) — the collapse
is 100% attributable to the open-set layer over-triggering "unknown" on that
split. Checked directly: mean z-score on `cross_app_test` is 0.856 for the
IsolationForest component vs. only 0.090 for the softmax component (both are
~0.000 on val, by calibration construction). **The IsolationForest isn't
detecting novel ATTACKS on `cross_app_test` — it's detecting that WebGoat is
an app it never saw during training, and flagging nearly everything from it
as "unknown" regardless of whether the traffic is a textbook sqli or
completely benign-shaped.**

This directly undercuts the "known-attack mislabeling is cheap" reasoning
the method-E decision was based on: that reasoning assumed the false-reject
cost falls roughly evenly on in-distribution traffic. It doesn't. It falls
almost entirely on requests from apps the isoforest never trained on — which
is precisely the cross-app-generalization scenario that matters most for a
WAF meant to be deployed on a new site. **Method E is not yet safe to treat
as the final answer; this needs a fix before it can be considered "solved."**
See the recommendation in the next chat turn for the proposed fix (feature
subsetting to make the isoforest attack-signal-driven rather than
app-identity-driven) and the decision on how to proceed.

### The fix: restrict the IsolationForest to payload-content features

Added `ISO_FEATURE_KEYS`/`ISO_FEATURE_IDX` to `train_baseline.py` — 21 of
the 26 features, excluding `path_length`, `query_param_count`,
`header_count`, `content_type`, `inter_arrival_ms`, `request_rate_window`
(app-structural, not payload-content). `fit_open_set_ensemble()` now fits
the IsolationForest on that subset only; stage2's softmax half is
unaffected. `isoforest_openset.py` updated to match (imports
`tb.ISO_FEATURE_IDX` so there's one source of truth, not two definitions
that could drift).

**Result — a real fix, but a real trade-off, not a free win:**

| split | method A (old) | method E, full features | method E, restricted features |
|---|---|---|---|
| test | 99.96% | 96.27% | 98.06% |
| cross_app_test (WebGoat) | 99.54% | **16.20%** | **85.88%** |
| heldout_unknown (open-set recall) | 52.20% | **100.00%** | **67.48%** |

Restricting the features fixed most of the cross-app collapse (16%→86%) —
confirms the diagnosis was right. But it cost real open-set recall
(100%→67.5%): some of the excluded features apparently *were* carrying
genuine novelty signal for `code_injection`, not just app-identity noise, so
this isn't a clean win, it's a different point on the same recall/
generalization trade-off curve. Still clearly the best balance found so far
— better than method A on open-set recall (67.5% vs 52.2%), and vastly
better than the full-feature method E on cross-app generalization. Refit and
confirmed consistent: `isoforest_openset.py`'s standalone comparison
reproduces the exact same threshold (0.2633) and recall (0.6748) as the
official `train_baseline.py` run.

Adversarial-robustness re-check (`fuzz_adversarial_methodE.py`, since the
feature restriction could plausibly have changed how easily the ensemble is
fooled) — completed:

| | static recall | adversarial recall (6 rounds) | worst case (evades stage1 too) |
|---|---|---|---|
| A: baseline softmax | 52.20% | 39.12% (-25.1% relative) | 0/864 |
| E, full features (superseded) | 100.00% | 98.26% (-1.7% relative) | 0/864 |
| **E, restricted features (current)** | **67.48%** | **58.22%** (-13.7% relative) | 0/864 |

Still comfortably beats method A on both the static and adversarial numbers,
and the worst-case full-evasion rate stays at 0/864 exactly like the other
two configurations. (Also fixed a cosmetic bug found while writing this up:
the plot title in `fuzz_adversarial_methodE.py` had a hard-coded "static
100%" left over from testing the full-feature version — corrected to read
the actual static-recall value from the results, and the saved plot was
regenerated from the existing results file rather than re-running the
7-minute search.)

**Where method E (restricted features) stands as the currently-deployed
open-set method:** open-set recall 67.5% static / 58.2% adversarial (vs.
method A's 52.2%/39.1%), cross_app_test 85.9% (vs. method A's 99.5%, still
the weaker side of this trade), zero full-evasion failures in every
configuration tested. This is now the "official" number in
`train_baseline.py`'s pipeline, not just a standalone-script result.

### Learning curve — "do we need more data?"

New file: [`learning_curve.py`](../learning_curve.py). Trains stage1,
stage2, and method E on stratified subsamples of the train+injected pool at
8 sizes from 1,046 to 52,261 rows, evaluating each time against the same
fixed val/heldout sets.

**Stage 1 (binary) and stage 2 (multiclass): fully converged, more rows will
not help.** Stage 2's validation macro-F1 is 1.0000 at every single size
tested, including the smallest (1,046 rows). Stage 1's validation F1 sits at
0.98-0.996 across the entire range with no trend. **These two stages hit
their ceiling almost immediately — the closed-set classification problem is
"too easy" for the current feature set, and more data of the same kind
(same apps, same attack patterns) is not the lever that will improve
anything here.**

**Method E's open-set recall: noisy, not a clean curve at all** — 94.9%,
96.6%, 62.7%, 88.8%, 57.3%, 97.7%, 53.4%, 63.2% across the 8 sizes, jumping
around with no visible upward trend as training size grows. **This is itself
an important, separate finding: the open-set signal isn't data-starved, it's
UNSTABLE** — small changes in which rows happen to be sampled swing the
IsolationForest's tail-boundary behavior substantially. More rows of the
same data are unlikely to fix this on their own; this points to a
methodological instability question (how the isolation-tree tail estimate
behaves on this feature space) rather than a data-volume question.

**Honest answer to "do we need more data": no, not more rows from the same
11 apps — both closed-set stages are already saturated and the open-set
instability doesn't trend with row count either.** The one form of "more
data" that could plausibly still help is more APP DIVERSITY (more distinct
sites, not more rows from the current ones) — this script doesn't test that
directly (would need a curve over number-of-distinct-apps, not number-of-
rows), and it's a different, still-open question from what was measured
here.

Outputs: [`reports/learning_curve/learning_curve.json`](learning_curve/learning_curve.json), [`reports/learning_curve/learning_curve.png`](learning_curve/learning_curve.png).

---

## 2026-09-10 (cont.) — Multi-seed robustness check: seed=42 was an outlier, not typical

Started the 3 agreed priorities (multi-seed robustness, latency benchmark,
app-diversity curve). The first one immediately surfaced something serious
enough to stop and report before continuing to the other two.

New file: [`multi_seed_eval.py`](../multi_seed_eval.py). Retrains stage1,
stage2, and method E's ensemble from scratch across 5 seeds (1, 2, 3, 42,
100) on the SAME full dataset (no resampling — isolates algorithmic
randomness from the subsampling instability the learning curve already
found), evaluated on the same fixed val/test/cross_app_test/heldout_unknown.

**Result — seed=42 (the one every number in this project and the MVP report
was built on) is not representative of typical behavior:**

| seed | open-set recall | known-reject cost | cross_app_test accuracy |
|---|---|---|---|
| 1 | 99.31% | 55.48% | 35.13% |
| 2 | 99.65% | 57.58% | 40.28% |
| 3 | 96.76% | 55.06% | 34.95% |
| **42 (reported)** | **67.48%** | **25.14%** | **85.88%** |
| 100 | 99.88% | 57.87% | 28.47% |
| **mean ± std (5 seeds)** | **92.6% ± 12.6%** | **50.2% ± 12.6%** | **44.9% ± 20.8%** |

Four of five seeds land close together (~97-99.9% recall, ~55-58% cost,
~28-40% cross_app accuracy) — and seed 42 is the outlier of the group, not
the center. The feature-restriction fix reduced the SEVERITY of the
cross-app collapse compared to the full-feature version (which hit 16.2% at
its worst), but **it did not fix the underlying instability** — it just
happened to land on a favorable seed when we tested it. The true typical
behavior of the deployed method is closer to ~45% cross_app accuracy with a
large spread (24.5%-65.7%, one std band), not the 85.9% reported in the MVP
report and PROGRESS_LOG entries above.

**This means the "final numbers" section of `reports/mvp_results_2026-09-10.html`
and the "method E, restricted features" row in earlier entries of this log
are not wrong, but they ARE unrepresentative — a single favorable seed, not
a reliable estimate.** The honest number to cite going forward is the
mean ± std across seeds, not the seed-42 point estimate. This needs to be
corrected in the MVP report before it's presented, and it changes the
priority ranking discussed with the user: the recall/generalization
trade-off (previously flagged as "blunt but real") is now understood to
be considerably less stable than believed, which raises the case for
trying a learned combiner (weighted, calibrated per-signal) rather than a
fixed mean, since a fixed 50/50 mean of two differently-scaled, differently-
behaved z-scores may simply be a fragile combination rule.

Outputs: [`reports/multi_seed/multi_seed_results.json`](multi_seed/multi_seed_results.json), [`reports/multi_seed/multi_seed_summary.png`](multi_seed/multi_seed_summary.png).

### Root cause found and fixed: IsolationForest's default `max_samples`

User's direction: fix the instability before touching latency or app-diversity.
Diagnosed the mechanism directly rather than guessing: sklearn's
`IsolationForest` default is `max_samples='auto'` = `min(256, n_samples)`.
With 15,678 known-malicious training points, that means every one of the 200
trees was built from a random **256-point sample — 1.6% of the data.**
Different seeds sample a different tiny slice, so different seeds built
meaningfully different forests. Confirmed with a controlled sweep
(`max_samples` = 256 / 2048 / 8192 / all, 5 seeds each): recall std dropped
from ±12.6% to ±4.8% just by raising `max_samples` to use the full dataset,
and a **bag of 5 independently-seeded forests (each with `max_samples` = all,
scores averaged)** brought it down further to **±0.9%** (cross_app accuracy
std: ±20.8% → ±3.3%).

**The honest part: the stabilized number is lower than what was reported.**
The "85.9%" cross_app accuracy in the MVP report was a statistical fluke —
seed 42 combined with the tiny-sample instability happened to land somewhere
favorable. The true, reproducible cross_app accuracy is **~52.7% ± 3.3%.**

Wired the fix into `train_baseline.py`: `fit_open_set_ensemble()` now bags
`N_BAG=5` forests, each with `max_samples=len(X_train_known)` (full data),
scores averaged before z-scoring/combining with softmax. Updated
`isoforest_openset.py` to match (`fit_isoforest()` now returns a list of 5
forests; delegates the same construction so it can't drift out of sync with
the deployed fit). `models/openset_isoforest.joblib` now stores a list of 5
forests instead of 1.

**Re-ran the full pipeline and the multi-seed check against the fix:**

| metric | before (single forest, max_samples=256) | after (5-forest bag, max_samples=all) |
|---|---|---|
| open-set recall | 92.6% ± 12.6% | **98.4% ± 0.9%** |
| known-reject cost | 50.2% ± 12.6% | **28.5% ± 1.2%** |
| test accuracy | 95.9% ± 1.1% | **97.7% ± 0.2%** |
| cross_app_test accuracy | 44.9% ± 20.8% | **52.7% ± 3.3%** |

**And re-ran the full A-E method comparison** (`isoforest_openset.py`) with
the fix — method E now has the BEST 5-way macro F1 of all five methods
compared, not just the best recall:

| method | 5-way macro F1 | open-set recall | known-reject |
|---|---|---|---|
| A: baseline softmax | 0.8167 | 52.20% | 2.11% |
| B: temperature softmax | 0.6186 | 10.76% | 0.00% |
| C: Mahalanobis | 0.7022 | 97.80% | 65.73% |
| D: OpenMax | 0.6834 | 23.73% | 0.28% |
| **E: IsolationForest bag + softmax (mean, deployed)** | **0.8840** | 99.65% | 29.92% |
| E: IsolationForest bag + softmax (max) | 0.8926 | 98.96% | 28.37% |

Note the "max" combiner scores marginally better than the deployed "mean"
combiner on this run — not switched yet (not re-validated for stability or
adversarial robustness), but worth a quick follow-up check.

Adversarial-robustness re-check against the fixed, bagged ensemble
(`fuzz_adversarial_methodE.py`) — completed (2049s, ~34 min; bagging 5
forests makes scoring ~5x slower than prior runs):

| | static recall | adversarial recall (6 rounds) | worst case (evades stage1 too) |
|---|---|---|---|
| A: baseline softmax | 52.20% | 39.12% (-25.1% relative) | 0/864 |
| E, single forest (superseded, unstable) | 67.48% | 58.22% (-13.7% relative) | 0/864 |
| **E, 5-forest bag (deployed, stable)** | **99.65%** | **96.88%** (-2.8% relative) | 0/864 |

The stabilized method isn't just more accurate (99.65% vs 67.48% static
recall) — it's also now MORE robust under adversarial pressure (a 2.8%
relative drop vs. the single-forest version's 13.7%). Fixing the instability
bug improved every dimension at once: accuracy, cross-app generalization,
and adversarial robustness. Worst-case full evasion stays at 0/864 across
every configuration ever tested.

**This closes out the open-set investigation for this MVP.** Final, fully
validated numbers for the deployed method: 98.4% ± 0.9% open-set recall
(mean across 5 training seeds), 96.9% recall under 6-round adversarial
search, 52.7% ± 3.3% cross_app_test accuracy, 0/864 full-evasion worst case,
best 5-way macro F1 (0.884) of every method compared.

### Priority 2 (latency) surfaced a THIRD real problem — and a partial fix

New file: [`latency_benchmark.py`](../latency_benchmark.py). Timed the full
deployed cascade (feature extraction -> stage1 -> stage2 -> open-set
ensemble) one request at a time (not batched — simulates real inline WAF
scoring), n=3000 from `test.jsonl`.

**Result: ~185ms/request, 5.4 req/sec single-threaded — not production-viable.**
97% of that time (180ms) is the 5-forest bagged IsolationForest scoring;
feature extraction + stage1 + stage2 combined are under 5ms. The stability
fix (bagging 5 forests, each seeing the full 15,678-point training set) that
fixed the accuracy/reliability problem earlier today directly caused this
new latency problem — every tree in every forest is far deeper and there are
5x as many forests to score per request as the original (broken) single-
forest version.

New file: [`tune_isoforest_latency.py`](../tune_isoforest_latency.py). Swept
`n_estimators` (trees per forest) at 50/100/150/200, keeping `max_samples`
= full data fixed (that's what fixes stability, not tree count), across the
same 5 seeds, measuring recall + cross_app accuracy + latency together:

| n_estimators | recall | cross_app accuracy | latency | throughput |
|---|---|---|---|---|
| 50 | 97.4% ± 1.2% | 53.2% ± **15.3%** | 25.7ms | 38.9 req/s |
| 100 | 97.4% ± 1.4% | 55.2% ± **14.5%** | 48.9ms | 20.5 req/s |
| **150 (adopted)** | 97.2% ± 3.1% | 52.3% ± **5.1%** | 76.6ms | 13.0 req/s |
| 200 (previous) | 98.4% ± 0.9% | 52.7% ± 3.3% | 100.1ms | 10.0 req/s |

Recall stays flat regardless of tree count, but cross_app stability has a
real cliff below 150 trees (std jumps from 5.1% to 14.5%) — cutting trees
much further silently reopens the instability bug just fixed. **150 is the
best available trade-off**: adopted as `ISO_N_ESTIMATORS` in
`train_baseline.py` (and mirrored in `isoforest_openset.py`), giving a real
but modest 23% latency improvement (100ms → 77ms, 10 → 13 req/s).

**Honest conclusion: this is an improvement, not a fix.** 13 req/sec
single-threaded is still far below what a production WAF needs (typically
thousands of req/sec). Getting there would require a genuinely different
approach — not a parameter tweak — such as replacing IsolationForest with a
faster anomaly-detection method, approximating/caching the score, or only
running the open-set check on a sampled fraction of traffic. **Documented as
a real, unresolved limitation**, not glossed over.

Outputs: [`reports/latency/latency_benchmark.json`](latency/latency_benchmark.json), [`reports/latency/latency_summary.png`](latency/latency_summary.png), [`reports/latency/isoforest_tuning.json`](latency/isoforest_tuning.json), [`reports/latency/isoforest_tuning.png`](latency/isoforest_tuning.png).

### Latency re-measured properly: the "5.4 req/sec" number was measuring the wrong thing

User's rational read of the latency problem: the benchmark scored EVERY
request through the full expensive cascade, which is not how any real
cascade classifier / tiered WAF is deployed — cheap checks should gate
expensive ones. Rebuilt `latency_benchmark.py` to measure three things
instead of one, on the full `test.jsonl` (7,542 requests):

**A. Worst case (every request pays full cost, as before):** 148.9ms/req,
6.7 req/sec. Kept as a documented ceiling, not the headline number.

**B. Gated (realistic): stage2 + the open-set ensemble only run on
requests stage1 already flagged malicious** — benign-flagged requests stop
after stage1 (2.8ms). Measured on the test split's own real mix (8.8%
malicious): **14.5ms/req, 68.8 req/sec — a ~10x improvement over the worst
case, for free** (no retraining, no accuracy change, pure deployment-
architecture correction). Sensitivity table across hypothetical malicious-
traffic rates (production traffic is rarely 8.8% malicious):

| malicious rate | avg latency | throughput |
|---|---|---|
| 1% | 4.1ms | 243.8 req/s |
| 5% | 9.4ms | 106.6 req/s |
| 10% | 16.0ms | 62.6 req/s |
| 20% | 29.2ms | 34.3 req/s |
| 30% | 42.4ms | 23.6 req/s |
| 100% (worst case) | 134.7ms | 7.4 req/s |

**C. Batching the malicious-flagged subset** (the next lever, tested not
just proposed): scoring the open-set ensemble in batches instead of one row
at a time, on the ~9% of traffic that actually reaches it:

| batch size | latency | throughput |
|---|---|---|
| 1 (current) | 73.4ms/req | 13.6 req/s |
| 10 | 6.5ms/req | 154.8 req/s |
| 50 | 1.4ms/req | 732.5 req/s |
| 100 | 0.7ms/req | 1421.8 req/s |
| 300 | 0.3ms/req | 3696.3 req/s |

**Combined conclusion: the latency problem is essentially solved, not just
mitigated, once gating and batching are both applied.** The earlier "not
production-viable" verdict was correct for the worst-case measurement, but
that measurement didn't reflect a realistic deployment. A WAF that gates
the expensive check behind stage1 and batches the malicious-flagged
minority even modestly (batch=50) reaches throughput in the hundreds of
req/sec — genuinely production-relevant, a complete reversal from the
"5.4 req/sec, not production-viable" conclusion reached before this fix.
This was a measurement-methodology problem, not a model problem.

**Where this leaves the "final numbers" claims made earlier today:** the
85.9% cross_app_test figure and the single-point 67.5%/58.2% open-set recall
figures in `reports/mvp_results_2026-09-10.html` are now KNOWN to be
unrepresentative and need correcting to the stabilized mean ± std values
above before that report is presented to anyone.

---

## 2026-09-09 — Fix known issues, then test the open-set gap under adversarial search

Three problems were tackled, in the order agreed on: clean up the two known
cosmetic/documentation issues first, then treat open-set recall as the real
unresolved problem, then build a tool (inspired by the ModSec-AdvLearn paper's
WAF-A-MoLE methodology) to measure that problem under active search rather
than just a static sample.

### 1. Cosmetic cleanup (done)

- [`src/attacks/attack_payloads.py`](../src/attacks/attack_payloads.py) — 3
  stale `path_traversal` mentions in comments/docstrings (lines 24, 289, 341)
  corrected to `command_injection`, which is what those code paths actually
  refer to (`path_traversal` was removed from the schema earlier in the
  project). No functional change — `verify_banks.py` still passes.
- [`schema/schema_v2.json`](../schema/schema_v2.json) — the `features_aux`
  sub-schema documented only 10 of the 27 properties `extract_features.py`
  actually emits. Rewrote it to list all 27 (the 26 `FEATURE_KEYS` numeric
  features + `content_type`), matching `train_baseline.py`'s `FEATURE_KEYS`
  exactly. Confirmed this schema file is documentation-only (nothing in the
  codebase loads it with `jsonschema` — `tests/test_schema.py` is a hand-written
  check that doesn't reference it), so this was a safe, zero-risk fix.

### 2. Open-set recall — confirmed as the one real open problem

Not "fixed" — this is a genuine, currently-unsolved weakness, not a bug.
Three open-set methods were already compared in a prior session
(`calibrate_openset.py`): raw softmax (52.2% recall, winner), temperature
scaling (10.8%, backfired), Mahalanobis distance (97.8% recall but 65.7%
false-reject cost — too expensive). The 52.2% number stood as the best
available, measured on a **static** held-out sample.

### 3. Built `fuzz_adversarial.py` — adversarial search against the live cascade

New file: [`fuzz_adversarial.py`](../fuzz_adversarial.py). Loads the already-trained
stage1/stage2 XGBoost models (no retraining) and runs a WAF-A-MoLE-style
greedy, multi-round, **compounding** mutation search — reusing the evasion
transforms already built in `attack_payloads.py` (URL-encode, double-encode,
case-swap, SQL-comment substitution, whitespace substitution, null-byte
splicing, partial encoding, UTF-7 for XSS) as mutation operators, but chaining
them across up to 6 rounds. Training data only ever applies ONE evasion
transform per record, so this tests generalization beyond what the model saw.

Two experiments, both run on the full frozen test/heldout splits (not a
sample):

**A — binary evasion (666 real, held-out sqli/xss/command_injection rows from
`test.jsonl`):** greedily mutate each row's query payload trying to push
stage1's malicious-probability below 0.5.
**Result: 0/666 evaded (0.00%), even after 6 compounding rounds.** Stage 1's
binary gate is robust to this class of adversarial search — a genuinely good,
now-measured (not assumed) result.

**B — open-set evasion (864 held-out `code_injection` rows,
`heldout_unknown.jsonl`):** greedily mutate trying to push the open-set
unknown-ness score below the calibrated threshold, i.e. trick the cascade
into labeling it a known attack class instead of flagging "unknown".
**Result: recall drops from the static 52.20% to 39.12% under active search**
— confirms the open-set signal is even weaker than the static number implied;
an adaptive attacker can find ~13 more points of evasion the static sample
didn't surface. **Worst case (evading stage 1 entirely, i.e. the request gets
through as "benign"): 0/864 (0.00%)** — every mutated `code_injection` row
was still caught by *something* (usually misclassified as a known attack
class rather than correctly flagged unknown), just mislabeled rather than
missed outright. That distinction matters operationally: the request still
gets blocked, it's just mis-attributed.

Outputs (regenerate with `python3 fuzz_adversarial.py --rounds 6`):
- [`reports/adversarial_fuzz/fuzz_results.json`](adversarial_fuzz/fuzz_results.json) — per-row results for both experiments
- [`reports/adversarial_fuzz/fuzz_summary.png`](adversarial_fuzz/fuzz_summary.png) — round-of-evasion histogram (A) + before/after unknown-ness score distributions (B)

### Honest takeaway

The open-set gap is real and, under adversarial search, slightly worse than
first measured (39.1% vs. 52.2%) — this is now the project's best-characterized
weakness, with both a static and an adaptive-attacker number to cite. The
binary gate (attack vs. benign) is comparatively strong evidence-wise: 0%
adversarial evasion across 666 rows. The next lever for the open-set number is
not more search (we now have that number) but a different detection signal or
architecture — that's still open and undecided.
