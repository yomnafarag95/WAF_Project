"""
Schema guard (two-tier) —  schema v2 (LOCKED)   leakage.
   .

:
  --stage raw        :   capture . features_aux    => .
  --stage processed  :  extract_features.py. features_aux  (default).

usage:
  python3 tests/test_schema.py                          # raw  data/raw + processed  data/processed
  python3 tests/test_schema.py --stage raw f.jsonl ...
  python3 tests/test_schema.py --stage processed f.jsonl ...
 exit code 1     ( CI / pre-commit).
"""
import glob
import json
import sys

ATTACK_CLASSES = {"sqli", "xss", "path_traversal", "code_injection"}
CLASSES = {"benign"} | ATTACK_CLASSES
LEVEL1 = {"benign", "malicious"}
SPLIT_ROLES = {"train", "val", "test", "heldout_unknown", "cross_app_test"}
SOURCE_TYPES = {"scripted", "real", "public_dataset"}
GEN_MODES = {"browser", "tool", "dataset"}
LABEL_SOURCES = {"tool_confirmed", "repo", "manual", "dataset"}

#  metadata    content/features_aux ( /)
FORBIDDEN_IN_FEATURES = {
    "response_status_code", "status_code", "content_length", "response_time_ms",
    "source_id", "app", "site_category", "persona_id", "scenario_id",
    "generation_mode", "tool_name", "domain_category",
}
TOP_REQUIRED_BASE = ["schema_version", "record_id", "session_id", "metadata", "content", "variant", "label"]


def check_record(rec, stage="processed"):
    errs = []
    if rec.get("schema_version") != "2.0":
        errs.append("schema_version != 2.0")
    required = list(TOP_REQUIRED_BASE)
    if stage == "processed":
        required.append("features_aux")
    for k in required:
        if k not in rec:
            errs.append(f"missing top-level '{k}'")

    md = rec.get("metadata", {})
    if md.get("source_type") not in SOURCE_TYPES:
        errs.append(f"bad metadata.source_type: {md.get('source_type')}")
    if md.get("generation_mode") is not None and md.get("generation_mode") not in GEN_MODES:
        errs.append(f"bad metadata.generation_mode: {md.get('generation_mode')}")
    for k in ("source_id", "app", "capture_tool"):
        if not md.get(k):
            errs.append(f"metadata.{k} missing")

    content = rec.get("content", {})
    for k in ("raw_request", "decoded_payload", "http_method", "url_path"):
        if not content.get(k):
            errs.append(f"content.{k} missing/empty (raw_request is PRIMARY input)")

    #   leakage:  metadata  content  features_aux
    feats = rec.get("features_aux", {})
    for bad in FORBIDDEN_IN_FEATURES:
        if bad in content or bad in feats:
            errs.append(f"LEAKAGE: '{bad}' must stay in metadata only")

    #    X-Capture headers   raw_request
    if "x-capture-" in (content.get("raw_request") or "").lower():
        errs.append("LEAKAGE: X-Capture-* header    raw_request")

    # features_aux     dict (  processed )
    if stage == "processed" and not isinstance(feats, dict):
        errs.append("features_aux must be an object")

    lbl = rec.get("label", {})
    cls = lbl.get("class")
    lvl1 = lbl.get("level1")
    if cls not in CLASSES:
        errs.append(f"bad label.class: {cls}")
    if lvl1 not in LEVEL1:
        errs.append(f"bad label.level1: {lvl1}")
    if lbl.get("split_role") not in SPLIT_ROLES:
        errs.append(f"bad label.split_role: {lbl.get('split_role')}")
    if lbl.get("label_source") not in LABEL_SOURCES:
        errs.append(f"bad label.label_source: {lbl.get('label_source')}")
    #  : benign<->benign , malicious<->
    if cls == "benign" and lvl1 != "benign":
        errs.append("hierarchy: class=benign requires level1=benign")
    if cls in ATTACK_CLASSES and lvl1 != "malicious":
        errs.append(f"hierarchy: class={cls} requires level1=malicious")
    #  open-set
    if cls == "code_injection" and lbl.get("split_role") != "heldout_unknown":
        errs.append("open-set: code_injection must have split_role=heldout_unknown")

    if "variant_type" not in rec.get("variant", {}):
        errs.append("variant.variant_type missing")
    return errs


def _run(targets):
    total, bad = 0, 0
    for path, stage in targets:
        with open(path, encoding="utf-8") as f:
            for i, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                total += 1
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError as e:
                    print(f"  [{path}:{i}] JSON error: {e}")
                    bad += 1
                    continue
                errs = check_record(rec, stage)
                if errs:
                    bad += 1
                    print(f"  [{path}:{i}] ({stage}) " + "; ".join(errs))
    print(f"\n[schema check] total={total} bad={bad}")
    return 1 if bad else 0


def main():
    args = sys.argv[1:]
    stage = "processed"
    files = []
    i = 0
    while i < len(args):
        if args[i] == "--stage":
            stage = args[i + 1]
            i += 2
        else:
            files.append(args[i])
            i += 1
    if files:
        targets = [(f, stage) for f in files]
    else:
        targets = [(p, "raw") for p in glob.glob("data/raw/*.jsonl")]
        targets += [(p, "processed") for p in glob.glob("data/processed/*.jsonl")]
    if not targets:
        print("[!]   jsonl .")
        return 0
    return _run(targets)


if __name__ == "__main__":
    sys.exit(main())
