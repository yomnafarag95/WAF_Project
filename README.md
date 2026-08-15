# WAF Attack Classifier — Project Structure

مشروع تخرج: **open-set, hierarchical classification للـ web attacks من HTTP payloads**.
البنية دي مبنية على methodology v2 (benign+attack على نفس التطبيقات → لا source shortcut).

## 🗂️ Folder structure
```
waf-attack-classifier/
├─ README.md
├─ .gitignore                 # data/ و reports/ ماتترفعش على git
├─ requirements.txt
├─ docker-compose.yml         # 3 apps + mitmproxy (benign/attack)
│
├─ config/
│  └─ sources.yaml            # ⭐ source-of-truth: apps + personas params
│
├─ schema/
│  └─ schema_v2.json          # ⭐ الـ record schema (locked, machine-readable)
│
├─ methodology/
│  └─ ...checklist-v2.md      # الـ methodology كـ first-class artifact
│
├─ src/
│  ├─ capture/                # capture_addon.py (mitmproxy, schema v2)
│  ├─ collection/             # benign_driver.py + journeys.py (personas)
│  ├─ attacks/                # run_attacks.sh (sqlmap/XSStrike/DotDotPwn)
│  ├─ features/               # (لاحقًا) extract_features.py
│  ├─ dataset/                # merge_jsonl.py (dedup + merge)
│  └─ evaluation/             # (لاحقًا) fingerprint_test.py + splits.py
│
├─ tests/
│  └─ test_schema.py          # ⭐ schema guard + leakage guard
│
├─ data/                      # (gitignored)
│  ├─ raw/                    # traffic الخام (append-only, مايتعدلش)
│  ├─ processed/              # features / CSV النهائي
│  ├─ heldout/                # ⭐ CSIC 2010 / SR-BH 2020 (cross-app test — مايتدرّبش)
│  └─ traces/                 # Playwright traces / artifacts
│
└─ reports/                   # (gitignored)
   ├─ fingerprint/            # نتائج Phase 2
   ├─ splits/                 # نتائج Phase 4
   └─ shap/                   # Phase 5
```

## 🔑 الـ 5 تعديلات عن الـ structure القياسي (ليه؟)
1. **`data/heldout/` منفصل** — الـ datasets الخارجية (CSIC/SR-BH) ماتتدرّبش أبدًا؛ عزلها فيزيائيًا يمنع تسرّبها للتدريب.
2. **`schema/` machine-readable + guard في `tests/`** — كل الـ methodology معتمدة على الـ schema، فلازم يكون ملف رسمي + test يتأكد منه.
3. **`src/` مقسّم submodules** (capture/collection/attacks/features/dataset/evaluation) — الكود كتير، فملف واحد src مش كافي.
4. **`methodology/` مجلد مستقل** — الـ checklist جزء من الـ deliverables مش مجرد README.
5. **`config/` top-level** — `sources.yaml` مايتدفنش جوّا src.

## ▶️ Quick start
```bash
pip install -r requirements.txt && playwright install chromium
docker compose up -d juice-shop webgoat dvwa mitmproxy-benign
python3 src/collection/benign_driver.py --config config/sources.yaml
python3 src/dataset/merge_jsonl.py --raw data/raw --out data/processed/dataset_v2.jsonl
python3 tests/test_schema.py data/processed/dataset_v2.jsonl
```
