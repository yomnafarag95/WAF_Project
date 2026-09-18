# OSH-WAC — Open-Set Hierarchical Web Attack Classification

A machine-learning Web Application Firewall (WAF) that detects, classifies,
and — critically — **recognizes what it doesn't know**. Most published web-attack
classifiers report 99%+ accuracy on a benchmark and stop there. This project is
built to answer two harder questions instead: *does it generalize to an
application it never trained on*, and *does it survive an adversary who
deliberately disguises their payload*.

**Authors:** Yasmeen Algendy, Yomna Algendy, Alaa Zahra
**Student IDs:** 20596367, 20596368, 20596369
**Supervisor:** Dr. Mohammad Zulkernine
**Program:** M.S. in Computer Science

---

## How it works

A three-stage cascade over raw HTTP requests:

```
HTTP request
     │
     ▼
┌─────────────────────┐
│ Stage 1 — RandomForest │  benign vs. malicious (binary gate)
└─────────────────────┘
     │ malicious
     ▼
┌─────────────────────┐
│ Stage 2 — XGBoost       │  sqli / xss / command_injection (multiclass)
└─────────────────────┘
     │
     ▼
┌─────────────────────────────────────┐
│ Stage 3 — Isolation Forest + Softmax    │  "does this actually look like
│           (open-set ensemble)           │   training data, or should it
└─────────────────────────────────────┘   be flagged UNKNOWN instead?"
```

Every request is converted into a 34-dimensional feature vector (28 numeric
features — length/entropy/keyword-density/structural signals — plus 6
one-hot content-type flags) before it reaches any model. See
[`reports/OSH-WAC_Deep_Dive.pdf`](reports/OSH-WAC_Deep_Dive.pdf) for the full
feature-by-feature breakdown and the evidence behind every design choice.

## Why these specific choices

Every non-obvious decision in this pipeline was tested, not assumed:

- **RandomForest, not XGBoost, gates Stage 1** — XGBoost wins every
  in-distribution split, but RandomForest generalizes better to an
  unseen application and survives adversarial mutation better (4.7% vs.
  8.7% worst-case bypass rate).
- **An isolation-forest + softmax ensemble, not softmax alone, for the
  open-set layer** — softmax alone looks better on paper (higher AUC) but
  was shown to collapse under a 6-round adversarial mutation search.
- **26 candidate features were tested this project; only 3 survived
  evidence-based scrutiny** (`quote_parity`, `kw_sqli_density`,
  `kw_cmdi_density`). Six more "confident" candidates and nine "advanced"
  ones (hashed character n-grams, payload-surface diversity) were tried
  and dropped after real held-out data showed they hurt more than helped.

## Key results (current)

| Metric | Test (in-distribution) | Cross-app (bWAPP, never trained on) | Heldout-unknown (code_injection) |
|---|---|---|---|
| Stage 1 accuracy (RandomForest) | 99.80% | 98.36% | 90.97% |
| Stage 2 accuracy (XGBoost) | 99.89% | 99.17% | — |
| End-to-end cascade accuracy | 97.39% | 80.78% | 60.88% |

- **Open-set gate:** 69.3% of a genuinely novel attack class is correctly
  flagged "unknown"; the cost is a 12.4% false-"unknown" rate on known
  attacks from an unfamiliar application — a measured, deliberate
  trade-off, not an oversight (three attempts to lower it were tested and
  rejected because each one reopened an evasion hole).
- **Adversarial robustness:** under 6 rounds of compounding mutation
  search, the deployed model still catches 51.3% of a held-out attack
  class (down from 75.3% with no attacker effort), with a worst-case
  full-pipeline bypass rate of 4.7%.
- **8 real data-pipeline defects were found and fixed** during this
  project (a header-based shortcut, a cross-app generalization collapse,
  a blind command-injection feature, a privacy fix that was erasing 16% of
  attack payloads, a mislabeled telemetry endpoint, a payload
  double-encoding bug, and a data-splitting instability) — see
  [`reports/OSH-WAC_Deep_Dive.pdf`](reports/OSH-WAC_Deep_Dive.pdf), Findings
  Summary.

## The dataset

**35,315 real, captured HTTP requests** — no synthetic records counted in
this total:

| Source | Role |
|---|---|
| DVWA, Juice Shop, WebGoat (PHP / Node+Angular / Java) | Paired benign + attack traffic, trained on |
| bWAPP | Attacks only, held out **entirely** — the cross-app generalization test |
| Pinterest, Amazon, Facebook, X, YouTube, Wikipedia, PokeAPI, JSONPlaceholder | Real-world benign traffic diversity |
| code_injection (SSTI, all sources) | Held out **entirely** — the open-set "unknown" test |

**Class balance:** 69.6% benign, 11.7% xss, 10.4% sqli, 5.9% command_injection,
2.4% code_injection (held out). A fourth vulnerable app (Mutillidae II) is
being added as this README is written, specifically to strengthen
command_injection's real-data diversity — see `reports/PROGRESS_LOG.md` for
the live status.

## Repository structure

```
├─ config/sources.yaml       # single source of truth: apps, personas, attack matrix
├─ schema/schema_v2.json     # locked record schema (raw + processed + features_aux)
├─ docker-compose.yml        # lab environment: 4 vulnerable apps + 2 mitmproxy capture points
├─ methodology/              # methodology checklist (first-class deliverable, not just this README)
│
├─ src/
│  ├─ capture/               # capture_addon.py — mitmproxy traffic capture
│  ├─ collection/personas/    # benign browsing personas (Playwright-driven)
│  ├─ attacks/                # attacker personas, payload banks, evasion transforms, attack_driver.py
│  └─ features/extract_features.py   # the ONE feature-extraction code path
│
├─ make_splits.py             # stratified, session-grouped, leakage-safe 70/15/15 split
├─ inject_payloads.py         # train-only synthetic payload augmentation
├─ train_baseline.py          # trains Stage 1 + Stage 2 + calibrates the open-set gate
├─ fuzz_adversarial*.py       # adversarial mutation-search robustness testing
├─ latency_benchmark.py       # per-stage inference latency / throughput
│
├─ data/                      # (gitignored — regenerate via the scripts above)
├─ models/                    # (gitignored — regenerate via train_baseline.py)
├─ reports/                   # final deliverables + supporting evidence (see below)
└─ tests/                     # schema + attack-bank integrity guards
```

## Quick start

```bash
pip install -r requirements.txt && playwright install chromium

# bring up the lab (4 vulnerable apps + 2 mitmproxy capture points)
docker compose up -d

# capture benign + attack traffic (see RUN_GUIDE.md for the full walkthrough,
# per-app login/setup steps, and health checks)
python3 src/collection/benign_driver.py --config config/sources.yaml
python3 src/attacks/attack_driver.py --config config/sources.yaml

# build the dataset
python3 src/features/extract_features.py
python3 make_splits.py data/processed/*_processed.jsonl
python3 inject_payloads.py --ratio 0.30 --seed 42

# train + evaluate everything (Stage 1, Stage 2, open-set, cascade)
python3 train_baseline.py

# stress-test it
python3 fuzz_adversarial_methodE.py --rounds 6
```

For the detailed, step-by-step operational guide (per-app setup, health
checks, capture troubleshooting), see [`RUN_GUIDE.md`](RUN_GUIDE.md).

## Reports & deliverables

| Document | Contents |
|---|---|
| [`reports/OSH-WAC_Deep_Dive.pdf`](reports/OSH-WAC_Deep_Dive.pdf) | Full technical deep dive: every stage, every feature, every mutation, timing — from zero to hundred |
| [`reports/OSH-WAC_MVP_Report.pdf`](reports/OSH-WAC_MVP_Report.pdf) | IEEE-style MVP report: architecture, methodology, results, limitations |
| [`reports/OSH-WAC_Mentor_QA.pdf`](reports/OSH-WAC_Mentor_QA.pdf) | Anticipated mentor questions, answered with concrete numbers |
| [`reports/PROGRESS_LOG.md`](reports/PROGRESS_LOG.md) | Full chronological build log — every defect found, every fix, every measurement |

## Reproducibility

Every random process in this pipeline (data splitting, model training, the
adversarial mutation search) uses a fixed seed (42), and every number in the
reports above can be regenerated exactly by re-running the corresponding
script. No result in this project is a one-off that can't be checked.

## Status

Active development. Current focus: adding Mutillidae II as a second real
trainable source of command_injection data (DVWA has been the only one),
after a feature-space diagnostic (LDA + t-SNE, see the Deep Dive report)
showed it's the least-separated class in the whole dataset.
