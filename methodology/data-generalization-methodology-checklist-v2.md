# Methodology Checklist v2 — منع Source/Identity Leakage وضمان الـ Generalization

> **نسخة v2** — أعيد بناؤها لإصلاح تناقض معماري أساسي في مصدر الـ benign، وإضافة payload content features، والـ open-set (Unknown class)، وخطوات dedup / variant-tracking.
> التغييرات الجوهرية عن v1 متوسّمة بـ **🔄 CHANGED** أو **➕ NEW**. الحاجات اللي اتساب زي ما هي متوسّمة **✅ KEPT**.

---

## 0. ملخص الفلسفة (اقرأيها الأول)

الموديل لازم يتعلم **سلوك/محتوى الهجوم** مش **بصمة المصدر أو التطبيق**. عشان كده:

1. **الـ benign والـ attack بيتولّدوا على نفس التطبيقات** (paired within app) — ده بيلغي الـ source shortcut من الجذر، مش بالـ test بس.
2. الـ **input الأساسي للموديل = raw/decoded payload text**، والأرقام الإحصائية auxiliary.
3. المواقع الحقيقية = مصدر benign **إضافي للتنويع**، مش المصدر الوحيد.
4. datasets عامة (CSIC 2010 / SR-BH 2020) = **held-out cross-app test** بره التدريب.
5. **class محجوز (Code Injection)** = **held-out Unknown** لتقييم الـ open-set rejection (ده الـ contribution الأساسي).

---

## Phase 0 — Schema & Infrastructure Consistency (أساس لازم يتعمل الأول)

- [ ] ✅ تثبيت الـ JSONL schema **قبل** أي جمع داتا جديدة — ممنوع تعديله بعد إضافة مصدر
- [ ] ✅ توثيق كل field: feature هيدخل الموديل، ولا metadata للـ audit؟
- [ ] ✅ توحيد أداة الـ capture (نفس الأداة، نفس الإصدار، نفس الإعدادات) لأي مصدر
- [ ] ✅ أي أداة مختلفة = تتسجّل رسميًا كـ "known limitation"
- [ ] ➕ **NEW:** توثيق أي feature بتتحسب من الـ raw payload (encoding-invariant قد إيه؟)

---

## Phase 0 — Answered decisions (مرجع موثق)

| الفئة | القرار |
|---|---|
| مستوى الالتقاط | HTTP request-level، كل request مربوط بـ `session_id` |
| Labeling | أوتوماتيك وقت الالتقاط من نفس السكريبت |
| **🔄 مصدر الـ benign** | **CHANGED:** الأساس = benign متولّد على **نفس تطبيقات اللاب** (Juice Shop + WebGoat + DVWA) عبر الـ personas. المواقع الحقيقية = تنويع إضافي. datasets عامة = held-out بس |
| **🔄 اقتران benign/attack** | **CHANGED:** كل تطبيق لاب لازم يطلّع **benign + attack** الاتنين (مش benign من مصدر وattack من تاني) |
| Feature vs Metadata | **Features:** raw_request, decoded_payload, + أرقام مشتقة. **Metadata:** source_id, app, account_id, session_id, capture_date, tool/persona, IP, **response_status_code** |
| **🔄 response_status_code** | **CHANGED:** اتنقل لـ **metadata** (كان feature) — لأنه بيسرّب الـ label (attack بيطلّع 500، benign 200) |
| حقول بريئة بتسرب | correlation/mutual-information check لكل feature مقابل `source_id` و `app` |
| الاتساق عبر المصادر | Minimum viable feature set؛ الناقص = `null` صريح + `field_available`، بدون imputation |
| Versioning | `schema_version` ثابت؛ JSONL قديم ما يتعدلش، أي تعديل = إضافة حقول بس |
| **➕ Open-set** | **NEW:** `code_injection` class محجوز كـ `heldout_unknown` — يتقاس عليه rejection، ما يتدرّبش |
| **➕ Variants** | **NEW:** كل obfuscation variant له `variant_type` + `parent_id`؛ variants نفس الأصل ما تتقسمش بين train/test |
| **➕ Dedup** | **NEW:** خطوة dedup إجبارية قبل أي split |

---

## Phase 0 — Confirmed Data Sources (v2)

### 🔄 CHANGED — Core benign + attack (نفس التطبيقات، مقترنين)

| Source ID | Tech stack | benign؟ | attack؟ | Status |
|---|---|---|---|---|
| `juice_shop` | Node.js / Angular | ✅ (17 personas) | ✅ | Active |
| `webgoat` | Java | ✅ (تمديد الـ personas) | ✅ | Required |
| `dvwa` | PHP | ✅ (تمديد الـ personas) | ✅ | Required |
| `bwapp` | PHP | ✅ | ✅ | Optional / cross-app enhancement |

> **النقطة الجوهرية:** كل تطبيق فيه الاتنين. عشان benign و attack بيشتركوا في نفس هوية التطبيق، الموديل **مايقدرش** يستغل الهوية كـ shortcut — مجبور يتعلم فرق المحتوى/السلوك.

### ✅ Supplementary benign (تنويع واقعية — مش المصدر الوحيد)

| Source ID | Type | Status |
|---|---|---|
| `wikipedia` | HTML content | policy allows read-only (≤5 req/sec) |
| `pokeapi` / `rickandmorty` / `openmeteo` | JSON API | open, no auth |
| `jsonplaceholder` | JSON API | smoke-test only |
| `saleor` (self-hosted) | e-commerce Python/GraphQL | zero ToS risk |

> دول benign **إضافي** للتنويع بس. **ممنوع** يبقوا المصدر الوحيد للـ benign (ده كان تناقض v1).

### ➕ NEW — Held-out cross-app test datasets (بره التدريب تمامًا)

| Dataset | استخدامه |
|---|---|
| `csic_2010` | held-out cross-app test (تطبيق e-commerce مختلف) |
| `srbh_2020` | held-out cross-app test (WordPress، multi-attack، CAPEC-labeled) |

⚠️ ✅ مفيش attack بيتنفذ على المواقع الحقيقية. الهجمات في اللاب المعزول بس.

---

## Phase 0 — Schema Reference v2 (locked)

```json
{
  "schema_version": "2.0",
  "record_id": "uuid",
  "session_id": "string",

  "metadata": {
    "source_id": "string",
    "app": "juice_shop | webgoat | dvwa | bwapp | <real_site> | csic_2010 | srbh_2020",
    "source_type": "real | scripted | public_dataset",
    "environment": "string",
    "capture_tool": "string",
    "capture_date": "iso8601",
    "account_id": "string | null",
    "tool_or_persona": "string | null",
    "response_status_code": "int | null"
  },

  "content": {
    "http_method": "string",
    "url_path": "string",
    "query_string": "string | null",
    "request_body": "string | null",
    "headers_subset": "object",
    "raw_request": "string  // PRIMARY model input",
    "decoded_payload": "string  // after canonicalization (crucial for path_traversal)"
  },

  "features_aux": {
    "path_length": "int",
    "query_param_count": "int",
    "payload_length": "int",
    "special_char_ratio": "float",
    "encoded_char_ratio": "float",
    "traversal_depth": "int",
    "header_count": "int",
    "content_type": "string",
    "time_since_last_request_ms": "int | null",
    "field_available": { "raw_request": "bool", "decoded_payload": "bool" }
  },

  "variant": {
    "variant_type": "none | url_encoding | double_encoding | case_mix | comment_insertion | ...",
    "parent_id": "uuid | null"
  },

  "label": {
    "class": "benign | sqli | xss | path_traversal | code_injection",
    "split_role": "train | val | test | heldout_unknown | cross_app_test",
    "label_source": "tool_confirmed | repo | manual"
  }
}
```

**Review notes (v2):**
- ➕ `content.raw_request` / `decoded_payload` = الـ input الأساسي (كان ناقص تمامًا في v1).
- ➕ `features_aux` = أرقام مساعدة بس (كانت اسمها features وكانت الوحيدة).
- 🔄 `response_status_code` اتنقل لـ metadata (leakage).
- ➕ `variant` block لتتبّع الـ obfuscation ومنع تسرّبها بين train/test.
- ➕ `label.class` زاد `code_injection` بس بيتحجز عبر `split_role = heldout_unknown`.
- ➕ `traversal_depth` / `encoded_char_ratio` features دلالية للـ path traversal.

---

## Phase 1 — Data Collection

- [ ] ✅ لكل sample سجّلي الـ metadata (منفصلة عن content/features)
- [ ] 🔄 **CHANGED:** ولّدي benign عبر الـ personas على **كل تطبيقات اللاب** (مش Juice Shop بس)
- [ ] ✅ jitter في التوقيت / ترتيب الـ navigation / طول الـ session
- [ ] ✅ raw JSONL منفصل عن processed CSV/Parquet
- [ ] ➕ **NEW:** خزّني الـ raw HTTP request كامل (مش الأرقام المشتقة بس) عشان تقدري تعيدي استخراج features بعدين بدون إعادة التقاط

---

## Phase 1B — Attack Data Collection & Diversification

⚠️ ✅ الهجمات في بيئات لاب معزولة ومصرّح بيها بس. ممنوع أي attack على المواقع الحقيقية.

- [ ] 🔄 **CHANGED:** نفّذي الهجمات على **نفس تطبيقات الـ benign** (كل app فيه الاتنين)
- [ ] ✅ 3 tech stacks متمايزة (Node / Java / PHP)
- [ ] ✅ خليط automated (sqlmap, XSStrike, DotDotPwn) + scripts يدوية
- [ ] ➕ **NEW:** لكل payload أساسي ولّدي **obfuscation variants** وسجّلي `variant_type` + `parent_id`
- [ ] ✅ jitter في توقيت الهجمات زي الـ benign
- [ ] ➕ **NEW:** طبّقي canonicalization/decoding وقت الالتقاط لملء `decoded_payload`
- [ ] ➕ **NEW:** جمّعي عينات **code_injection** بس علّميها `split_role = heldout_unknown` (للـ open-set، مش للتدريب)

---

## Phase 1C — ➕ NEW — Deduplication (قبل أي split)

- [ ] شيلي الـ exact duplicates (نفس الـ raw_request)
- [ ] شيلي الـ near-duplicates (مثلاً Jaccard/MinHash على tokens > عتبة)
- [ ] **variants نفس الـ `parent_id` تعتبر مجموعة واحدة** — كلها تروح نفس جهة الـ split (مايتقسموش train/test)
- [ ] وثّقي كام sample اتشال وليه

---

## Phase 2 — Source Fingerprint Test (v2 — أدق)

- [ ] ✅ درّبي موديل بسيط (Logistic Regression) يفرّق `source_type` / `app` بمعزل عن الـ label
- [ ] ✅ النتيجة المطلوبة: accuracy قريبة من العشوائية (~50–55%)
- [ ] ✅ لو فرّق بسهولة (85%+) → وقفي وارجعي لـ Phase 0/1
- [ ] ➕ **NEW — أهم إضافة:** شغّلي الاختبار على **benign-only** و **attack-only كل واحد لوحده** — عشان تكشفي leakage مشروط بالكلاس (هل الموديل يعرف التطبيق من benign بس؟ من attack بس؟)
- [ ] ✅ كرّريه كل ما ضفتي مصدر جديد

---

## Phase 3 — Mixing Strategy

- [ ] ✅ real benign = baseline، scripted = تغطية edge cases ناقصة
- [ ] ✅ وثّقي سبب كل edge case مغطى بـ scripted
- [ ] ✅ بعد الدمج، أعيدي الـ Fingerprint Test على الداتا الكاملة
- [ ] ➕ **NEW:** وثّقي **class distribution** (كام benign/sqli/xss/path_traversal) + استراتيجية الـ balancing، وتأكدي إن `heldout_unknown` فيه عينات كفاية للتقييم

---

## Phase 4 — Evaluation Splits (v2 — الأهم، تتخطط من الأول)

قسّمي نفس الداتا بأكتر من طريقة وقارني:

| Split | إزاي | إيه اللي بيثبته |
|---|---|---|
| **Random** (baseline) | 80/20 عشوائي | الأداء العام |
| **Cross-source** | تدريب على مصادر، اختبار على مصادر متشافتش | تعميم عبر المصادر |
| **Persona** | تدريب على 12–13 persona، اختبار على 4–5 متشافوش | تعلّم سلوك مش persona |
| **Scenario** | سحب flow كامل (login/checkout) للتست | مش معتمد على مسار |
| **🔄 Cross-app (attacks)** | تدريب على Juice Shop + WebGoat، اختبار على DVWA/bWAPP | كشف الهجوم مش معتمد على **تطبيق** |
| **➕ Open-set (Unknown class)** | تدريب على SQLi+XSS+PathTraversal، اختبار الـ **rejection** على `code_injection` المحجوز | الموديل يرفض هجوم **class** مشفوش قبل كده |

- [ ] ✅ نفّذي الـ splits دي قبل أي تدريب نهائي
- [ ] ✅ فرق كبير بين random و cross-source (98% مقابل 70%) = دليل leakage
- [ ] ➕ **NEW:** للـ open-set استخدمي metrics مخصصة (rejection rate, AUROC للـ known-vs-unknown, OSCR) مش accuracy بس
- [ ] ✅ وثّقي كل النتائج في جدول واحد

> **⚠️ تنسيق مهم — نوعين held-out مختلفين ومتكاملين:**
> - **Cross-app held-out** = تحجزي **تطبيق** (DVWA) → الكشف مش مربوط بتطبيق.
> - **Open-set held-out** = تحجزي **class** (Code Injection) → الموديل يرفض هجوم مشفوش.
> خليهم منفصلين واضحين، متدمجيهمش في مفهوم واحد.

---

## Phase 5 — Validation & Reporting

- [ ] ✅ SHAP على الموديل النهائي — أعلى features لازم تكون **محتوى/سلوك** (payload structure, traversal depth, tokens) مش مصدر (IP, headers خاصة بموقع)
- [ ] ➕ **NEW:** أكّدي إن `payload_length` / `special_char_ratio` **مش** من أعلى الـ features لوحدهم — لو طلعوا كده يبقى فيه شبهة tool-fingerprint، ورجّعي للـ content features
- [ ] ✅ finding رسمي: "الأداء ثابت عبر cross-source/persona/scenario/cross-app splits + open-set rejection ناجح، وSHAP بيأكد الاعتماد على المحتوى/السلوك"
- [ ] ✅ أي فرق أداء بين المصادر = يتوثّق كـ limitation مش يتخبّى
- [ ] ✅ اربطي بالـ adversarial robustness: موديل معتمد على المحتوى أصعب في الـ evasion

---

## Known Limitations (documented openly)

### 1. ✅ Time-of-day confound
- [ ] عشوائية وقت الجمع للـ benign والـ attack
- [ ] `time_since_last_request_ms` يفضل feature (rhythm مش وقت مطلق)
- [ ] `hour_of_day` / wall-clock **ما يدخلش features أبدًا** — metadata بس

### 2. ✅ Synthetic origin vs real destination
- destination حقيقي، origin مُحاكى (Playwright personas) — ممارسة قياسية في أبحاث WAF/IDS
- مصطلحات دقيقة: "real destination" ≠ "organic origin"
- mitigations: real Chromium fingerprint, jitter, per-persona UA, تنويع الـ navigation

### 3. ➕ NEW — Aggregate vs content features balance
- الأرقام الإحصائية بتساعد بس ممكن تبقى tool-fingerprints؛ الاعتماد الأساسي على الـ content features + الـ obfuscation variants بيخفّف ده

### 4. ✅ Optional limited human-validation subsample
- pilot صغير (5–10 sessions) كـ validation subsample مش primary source
- أكّدي مع الـ supervisor لو محتاج ethics review قبل أي جمع

---

## ملخص الفرق بين v1 و v2 (reference سريع)

| المحور | v1 | v2 |
|---|---|---|
| مصدر benign | مواقع حقيقية (منفصل عن attack) | **benign+attack على نفس الـ apps** + مواقع كتنويع |
| Model input | أرقام إحصائية بس | **raw/decoded payload** + أرقام auxiliary |
| decoded_payload | مش موجود | ➕ موجود (canonicalization) |
| response_status_code | feature | 🔄 metadata (leakage) |
| Open-set / Unknown | مش موجود | ➕ code_injection heldout + rejection metrics |
| Obfuscation variants | مذكور بدون tracking | ➕ variant_type + parent_id + grouping |
| Deduplication | مش موجود | ➕ Phase 1C |
| Fingerprint Test | overall بس | ➕ per-class (benign-only / attack-only) |
| Class balance | مش مذكور | ➕ موثّق |
