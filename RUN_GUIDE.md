# WAF Attack Classifier - Run Guide

This guide covers: (1) the terminal commands to run everything, (2) how the
benign-traffic flow works, and (3) the charts to build, when, and where.

---

## 0. One-time setup (terminal)

```bash
# from the project root
cd waf-attack-classifier

# python env + deps
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt          # mitmproxy, playwright, pyyaml, xgboost, ...
playwright install chromium

# bring up the lab (3 apps + 2 mitmproxy capture points)
docker compose up -d
docker compose ps                          # all services healthy?

# health checks
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:3000   # Juice Shop
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8080/WebGoat
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8081    # DVWA

# DVWA: create/reset DB + set security = low (benign only)
#   open http://localhost:8081/setup.php -> Create / Reset Database
#   login admin/password -> Security -> Low

# Juice Shop: register the benign account used by logged-in personas
#   open http://localhost:3000 -> Account -> Login -> Not yet a customer?
#   email: benign_user@juice-sh.op   password: Benign123!
```

---

## 1. Generate BENIGN traffic (terminal)

All benign traffic goes through the **same mitmproxy capture proxy** and is
written by `src/capture/capture_addon.py` in the single locked **schema_v2**
format, regardless of which generator produced it.

```bash
# Juice Shop - rich persona-based generator (6 personas x jitter)
python3 -m src.collection.run_benign_generation \
    --config config/sources.yaml --sessions-per-persona 20 --seed 42

# WebGoat + DVWA - existing app-agnostic generator
python3 src/collection/benign_driver.py --config config/sources.yaml --only webgoat
python3 src/collection/benign_driver.py --config config/sources.yaml --only dvwa
```

### Benign traffic flow (what actually happens per session)

```
 run_benign_generation.py
        |
        v
 pick persona (goal, speed, device, auth, jitter)      # personas/configs.py
        |
        v
 build scenario for persona                            # personas/scenarios.py
   (login step prepended if logged_in) + goal journey
        |
        v
 launch Chromium via proxy=mitmproxy(8888)             # personas/juice_shop_actions.py
   set X-Capture-* headers on the context
   emulate device (iPhone 13 if mobile)
        |
        v
 SessionRunner walks the steps                          # personas/session_runner.py
   for each step:
     - sample human delay (normal dist + jitter)         # decision_engine.DelaySampler
     - decide skip / backtrack / revisit / abandon        # decision_engine.StepDecisionEngine
     - run the Playwright action (real click/fill/goto)
        |
        v
 every HTTP request crosses the proxy
   -> capture_addon.py strips X-Capture-* headers
   -> writes schema_v2 record to data/raw/juice_shop_raw.jsonl
        |
        v
 Playwright trace saved to data/traces/<session_id>.zip
```

Key point: personas only control **timing and behavior**. The dataset record
is built once, on the wire, so benign and attack traffic are structurally
identical (this is what prevents the model from learning a source shortcut).

---

## 2. Generate ATTACK traffic (terminal)

```bash
# routed through the attack mitmproxy (tool mode); code_injection is held out
bash src/attacks/run_attacks.sh
```

---

## 3. Merge + validate + features (terminal)

```bash
python3 src/dataset/merge_jsonl.py --in data/raw --out data/dataset_raw.jsonl
python3 tests/test_schema.py --stage raw                 # must pass, 0 bad
python3 src/features/extract_features.py \
    --in data/dataset_raw.jsonl --out data/processed/dataset.jsonl
python3 tests/test_schema.py --stage processed           # 0 bad
```

---

## 4. Charts

Two groups, two moments, two folders.

### 4a. EDA / correlation charts - run BEFORE modeling

```bash
python3 src/analysis/eda_charts.py --input data/processed --output reports/eda
```

| Chart | File (reports/eda/) | Why it matters |
|---|---|---|
| Class balance | `class_balance.png` | shows imbalance to fix before training |
| Class x app (stacked) | `class_by_app_stacked.png` | **source-leakage check**: a class must not live in only one app |
| Feature correlation heatmap | `feature_correlation_heatmap.png` | drop/merge redundant features_aux (high |r|) |
| Feature distributions by class | `feature_distributions_by_class.png` | shows which features actually separate classes (e.g. traversal_depth for path_traversal) |

### 4b. Results charts - run AFTER model evaluation (Protocols 1-4)

```bash
python3 src/evaluation/result_charts.py --input reports/results --output reports/results
```

This script only plots CSVs you produce from your eval code (it never invents
numbers). Produce these files first:

| Chart | Input CSV -> Output PNG | Reads |
|---|---|---|
| Confusion matrix (Protocol 1) | `protocol1_predictions.csv` -> `confusion_matrix_protocol1.png` | `true_class,pred_class` |
| Cross-app F1 (Protocol 2) | `protocol2_cross_app_f1.csv` -> `cross_app_f1.png` | `held_out_app,macro_f1` |
| Open-set ROC (Protocol 3) | `protocol3_openset_scores.csv` -> `openset_roc.png` | `true_is_known,msp_score` |
| Unknown-outcome breakdown (Protocol 3) | `protocol3_breakdown.csv` -> `openset_breakdown.png` | `outcome,count` |
| Obfuscation robustness (Protocol 4) | `protocol4_obfuscation.csv` -> `obfuscation_robustness.png` | `variant_type,macro_f1` |
| Baseline comparison | `baseline_comparison.csv` -> `baseline_comparison.png` | `system,macro_f1` |

SHAP summary (feature importance per class) can be produced by your training
code with the `shap` library and saved to `reports/results/shap_summary.png`.
