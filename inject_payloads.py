"""
inject_payloads.py - synthesize TRAIN-ONLY attack records by splicing curated
attack payloads into real benign request shells.

WHY: sqli/xss/command_injection are under-represented relative to the 30%
attack-ratio target, and command_injection is currently DVWA-only (source
confound risk - the model could learn "DVWA's /vulnerabilities/exec/" instead
of "command injection"). Injecting attack payloads into REAL benign shells
drawn from ALL apps/sites (dvwa, juice_shop, webgoat, amazon, facebook, ...)
scales the attack classes AND breaks that confound, without discarding any of
the real benign traffic.

LEAKAGE POLICY (matches make_splits.py):
  - Input is data/splits/benign_train.jsonl ONLY (already train-only, real).
  - Output records ALWAYS get label.split_role = "train".
  - code_injection is NEVER injected (open-set/held-out class must stay
    genuinely unseen at train time).
  - Injected records are deduped by (method, url_path, body) signature
    against val/test/cross_app_test/heldout_unknown so a synthetic record can
    never coincide with a frozen eval record.
  - features_aux is computed by the SAME extract_features.compute_features()
    used for real data (single code path -> no train/synthetic feature skew).

MECHANISM: for each target record we
  1. pick a random real benign shell (method/path/query/body/headers),
  2. pick an attack class + goal (recon/exploit/exfiltration) + base payload
     from src/attacks/attack_payloads.py,
  3. optionally run it through apply_evasion() (encoded/mutated/polyglot),
  4. splice the resulting payload into ONE surface of the shell - query
     param, request body (JSON or form), a header, or the Cookie header -
     and rebuild content.raw_request / decoded_payload exactly the way
     capture_addon.py would have.

usage:
  python3 inject_payloads.py
  python3 inject_payloads.py --ratio 0.30 --seed 42
  python3 inject_payloads.py --counts sqli=3659,xss=3675,command_injection=4025
"""
import argparse
import copy
import hashlib
import json
import os
import random
import sys
import urllib.parse
import uuid
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "src", "attacks"))
sys.path.insert(0, os.path.join(HERE, "src", "features"))
import attack_payloads as AP  # noqa: E402
import extract_features as EF  # noqa: E402

SPLITS_DIR = os.path.join(HERE, "data", "splits")
INJECTABLE_CLASSES = ["sqli", "xss", "command_injection"]  # NEVER code_injection
GOAL_WEIGHTS = {"recon": 0.20, "exploit": 0.60, "exfiltration": 0.20}
EVASION_WEIGHTS = {"original": 0.40, "encoded": 0.20, "mutated": 0.20, "polyglot": 0.20}
VECTOR_WEIGHTS = {"query": 0.50, "body": 0.20, "header": 0.15, "cookie": 0.15}
CANDIDATE_HEADERS = ["referer", "x-forwarded-for", "user-agent", "accept-language", "x-requested-with"]


# ---------------------------------------------------------------------------
# raw_request parsing / rebuilding (mirrors capture_addon.py's construction)
# ---------------------------------------------------------------------------
def _split_raw(raw_request):
    head, _, body = (raw_request or "").partition("\r\n\r\n")
    lines = head.split("\r\n")
    return lines[0], lines[1:], body


def _parse_headers(header_lines):
    headers = []
    for line in header_lines:
        if ":" not in line:
            continue
        name, val = line.split(":", 1)
        headers.append([name, val.strip()])
    return headers


def _headers_to_lines(headers):
    return [f"{n}: {v}" for n, v in headers]


def _rebuild_raw(method, path_with_query, header_lines, body):
    request_line = f"{method} {path_with_query} HTTP/1.1"
    return "\r\n".join([request_line] + header_lines) + "\r\n\r\n" + (body or "")


def _decoded_payload(url_path, query_string):
    full_url = url_path + (("?" + query_string) if query_string else "")
    return urllib.parse.unquote(urllib.parse.unquote(full_url))


# ---------------------------------------------------------------------------
# injection surfaces
# ---------------------------------------------------------------------------
def _inject_query(query_string, payload, rng):
    pairs = urllib.parse.parse_qsl(query_string or "", keep_blank_values=True)
    if pairs:
        idx = rng.randrange(len(pairs))
        k, _ = pairs[idx]
        pairs[idx] = (k, payload)
    else:
        pairs = [(rng.choice(["q", "id", "search", "query", "name", "value"]), payload)]
    return urllib.parse.urlencode(pairs)


def _inject_json_field(data, payload, rng):
    """Mutate ONE string leaf of a JSON value in place; return True if applied."""
    setters = []

    def walk(obj):
        if isinstance(obj, dict):
            for k in list(obj.keys()):
                if isinstance(obj[k], str):
                    setters.append((lambda v, o=obj, kk=k: o.__setitem__(kk, v)))
                else:
                    walk(obj[k])
        elif isinstance(obj, list):
            for i in range(len(obj)):
                if isinstance(obj[i], str):
                    setters.append((lambda v, o=obj, ii=i: o.__setitem__(ii, v)))
                else:
                    walk(obj[i])

    walk(data)
    if setters:
        rng.choice(setters)(payload)
        return True
    if isinstance(data, dict):
        data["q"] = payload
        return True
    return False


def _try_inject_body(request_body, content_type, payload, rng):
    if not request_body:
        return None
    ct = (content_type or "").lower()
    try:
        if "application/json" in ct:
            data = json.loads(request_body)
            if not _inject_json_field(data, payload, rng):
                return None
            return json.dumps(data)
        if "x-www-form-urlencoded" in ct:
            pairs = urllib.parse.parse_qsl(request_body, keep_blank_values=True)
            if not pairs:
                return None
            idx = rng.randrange(len(pairs))
            k, _ = pairs[idx]
            pairs[idx] = (k, payload)
            return urllib.parse.urlencode(pairs)
    except Exception:
        return None
    return None  # opaque/binary body: not a safe injection surface


def _inject_header(header_lines, payload, rng):
    headers = _parse_headers(header_lines)
    present = {h[0].lower(): i for i, h in enumerate(headers)}
    candidates = [n for n in CANDIDATE_HEADERS if n in present]
    if candidates:
        name = rng.choice(candidates)
        headers[present[name]][1] = payload
    else:
        headers.append([rng.choice(CANDIDATE_HEADERS), payload])
    return _headers_to_lines(headers)


def _inject_cookie(header_lines, payload, rng):
    headers = _parse_headers(header_lines)
    for h in headers:
        if h[0].lower() == "cookie":
            parts = [p.strip() for p in h[1].split(";") if p.strip()]
            pairs = []
            for p in parts:
                if "=" in p:
                    k, v = p.split("=", 1)
                else:
                    k, v = p, ""
                pairs.append([k, v])
            if pairs:
                pairs[rng.randrange(len(pairs))][1] = payload
            else:
                pairs = [["injected", payload]]
            h[1] = "; ".join(f"{k}={v}" for k, v in pairs)
            return _headers_to_lines(headers)
    headers.append(["Cookie", f"injected={payload}"])
    return _headers_to_lines(headers)


# ---------------------------------------------------------------------------
# core: splice one payload into one shell
# ---------------------------------------------------------------------------
def _weighted_choice(weights, rng):
    keys, wts = zip(*weights.items())
    return rng.choices(keys, weights=wts, k=1)[0]


def synthesize(shell, attack_type, rng):
    """Return a new schema-v2 record, or None if this shell has no usable
    surface for the chosen vector (caller should retry with another shell)."""
    content = shell.get("content", {})
    method = content.get("http_method", "GET")
    url_path = content.get("url_path", "/")
    query_string = content.get("query_string") or ""
    request_body = content.get("request_body")
    raw_request = content.get("raw_request", "")
    content_type = None

    request_line, header_lines, body = _split_raw(raw_request)
    for hl in header_lines:
        if hl.lower().startswith("content-type:"):
            content_type = hl.split(":", 1)[1].strip()

    goal = _weighted_choice(GOAL_WEIGHTS, rng)
    base = AP.base_payloads(attack_type, goal)
    if not base:
        return None
    payload_id, raw_payload = base[rng.randrange(len(base))]
    evasion = _weighted_choice(EVASION_WEIGHTS, rng)
    variant_type, parent_id, payload = AP.apply_evasion(
        payload_id, raw_payload, evasion, attack_type, rng=rng)

    vector = _weighted_choice(VECTOR_WEIGHTS, rng)
    new_query_string, new_body, new_header_lines = query_string, request_body, header_lines

    if vector == "body":
        injected_body = _try_inject_body(request_body, content_type, payload, rng)
        if injected_body is None:
            vector = "query"  # no parseable body on this shell -> fall back
        else:
            new_body = injected_body
    if vector == "header":
        new_header_lines = _inject_header(header_lines, payload, rng)
    elif vector == "cookie":
        new_header_lines = _inject_cookie(header_lines, payload, rng)
    elif vector == "query":
        new_query_string = _inject_query(query_string, payload, rng)

    new_path_with_query = url_path + (("?" + new_query_string) if new_query_string else "")
    new_raw = _rebuild_raw(method, new_path_with_query, new_header_lines, new_body)
    decoded_payload = _decoded_payload(url_path, new_query_string)

    rec = {
        "schema_version": "2.0",
        "record_id": str(uuid.uuid4()),
        "session_id": "",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "metadata": {
            "source_id": shell.get("metadata", {}).get("source_id", "unknown"),
            "app": shell.get("metadata", {}).get("app", "unknown"),
            "source_type": "scripted",
            "tech_stack": shell.get("metadata", {}).get("tech_stack"),
            "environment": shell.get("metadata", {}).get("environment"),
            "generation_mode": "tool",
            "persona_id": None,
            "scenario_id": None,
            "tool_name": "inject_payloads",
            "capture_tool": "inject_payloads.py",
            "capture_date": datetime.now(timezone.utc).isoformat(),
            "site_category": None,
            "response_status_code": None,
        },
        "content": {
            "http_method": method,
            "url_path": url_path,
            "query_string": new_query_string or None,
            "request_body": new_body,
            "raw_request": new_raw,
            "decoded_payload": decoded_payload,
        },
        "variant": {"variant_type": variant_type, "parent_id": parent_id},
        "label": {
            "level1": "malicious",
            "class": attack_type,
            "split_role": "train",
            "label_source": "tool_confirmed",
        },
    }
    return rec


# ---------------------------------------------------------------------------
# dedup against frozen eval splits (zero leakage safety net)
# ---------------------------------------------------------------------------
def _sig(rec):
    c = rec.get("content", {})
    s = f"{c.get('http_method')}:{c.get('url_path')}:{c.get('query_string')}:{c.get('request_body')}"
    return hashlib.sha256(s.encode("utf-8", "ignore")).hexdigest()


def _load_eval_signatures():
    sigs = set()
    for name in ("val.jsonl", "test.jsonl", "cross_app_test.jsonl", "heldout_unknown.jsonl"):
        path = os.path.join(SPLITS_DIR, name)
        if not os.path.exists(path):
            continue
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                sigs.add(_sig(json.loads(line)))
    return sigs


# ---------------------------------------------------------------------------
# target counts
# ---------------------------------------------------------------------------
def _auto_targets(n_benign, train_path, ratio):
    real_counts = {c: 0 for c in INJECTABLE_CLASSES}
    if train_path and os.path.exists(train_path):
        with open(train_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                cls = json.loads(line).get("label", {}).get("class")
                if cls in real_counts:
                    real_counts[cls] += 1
    total_real_attack = sum(real_counts.values())
    total_attack_target = int(round(ratio / (1 - ratio) * n_benign))
    to_inject_total = max(0, total_attack_target - total_real_attack)
    per_class = to_inject_total // len(INJECTABLE_CLASSES)
    remainder = to_inject_total - per_class * len(INJECTABLE_CLASSES)
    targets = {}
    for i, cls in enumerate(INJECTABLE_CLASSES):
        targets[cls] = per_class + (1 if i < remainder else 0)
    return targets, real_counts, total_attack_target


def _parse_counts_arg(s):
    out = {}
    for part in s.split(","):
        part = part.strip()
        if not part:
            continue
        k, v = part.split("=")
        out[k.strip()] = int(v.strip())
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--benign", default=os.path.join(SPLITS_DIR, "benign_train.jsonl"))
    ap.add_argument("--train", default=os.path.join(SPLITS_DIR, "train.jsonl"),
                     help="used only to read CURRENT real attack counts for --ratio auto-targeting")
    ap.add_argument("--out", default=os.path.join(SPLITS_DIR, "injected_train.jsonl"))
    ap.add_argument("--ratio", type=float, default=0.30,
                     help="target attack/(attack+benign) ratio in the final train split")
    ap.add_argument("--counts", default=None,
                     help="explicit per-class counts, e.g. sqli=3659,xss=3675,command_injection=4025 "
                          "(overrides --ratio auto-targeting)")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    rng = random.Random(args.seed)

    if not os.path.exists(args.benign):
        print(f"[!] {args.benign} not found - run make_splits.py first.")
        return 1

    print(f"[inject] loading benign shells from {args.benign} ...")
    shells = []
    with open(args.benign, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                shells.append(json.loads(line))
    n_benign = len(shells)
    print(f"[inject] {n_benign} benign shells loaded")

    if args.counts:
        targets = _parse_counts_arg(args.counts)
        for cls in targets:
            if cls not in INJECTABLE_CLASSES:
                print(f"[!] unknown/forbidden class in --counts: {cls} (code_injection can never be injected)")
                return 1
        real_counts, total_attack_target = {}, None
    else:
        targets, real_counts, total_attack_target = _auto_targets(n_benign, args.train, args.ratio)
        print(f"[inject] real train attack counts: {real_counts} (total={sum(real_counts.values())})")
        print(f"[inject] target total train attack (ratio={args.ratio}): {total_attack_target}")

    print(f"[inject] targets to synthesize: {targets} (total={sum(targets.values())})")

    print("[inject] loading eval-split signatures for leakage dedup ...")
    eval_sigs = _load_eval_signatures()
    print(f"[inject] {len(eval_sigs)} eval signatures loaded")

    out_records = []
    seen_sigs = set()
    stats = {c: 0 for c in INJECTABLE_CLASSES}
    for cls, target in targets.items():
        attempts = 0
        max_attempts = target * 10 + 100
        while stats[cls] < target and attempts < max_attempts:
            attempts += 1
            shell = shells[rng.randrange(n_benign)]
            rec = synthesize(shell, cls, rng)
            if rec is None:
                continue
            sig = _sig(rec)
            if sig in eval_sigs or sig in seen_sigs:
                continue
            seen_sigs.add(sig)
            rec["features_aux"] = EF.compute_features(rec)
            out_records.append(rec)
            stats[cls] += 1
        if stats[cls] < target:
            print(f"[!] {cls}: only synthesized {stats[cls]}/{target} "
                  f"after {attempts} attempts (payload space exhausted?)")

    EF.add_timing(out_records)

    os.makedirs(SPLITS_DIR, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        for rec in out_records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    print(f"\n[inject] wrote {len(out_records)} records -> {args.out}")
    print(f"[inject] per-class: {stats}")
    print(f"[inject] all split_role == 'train': "
          f"{all(r['label']['split_role'] == 'train' for r in out_records)}")
    print(f"[inject] no code_injection present: "
          f"{all(r['label']['class'] != 'code_injection' for r in out_records)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
