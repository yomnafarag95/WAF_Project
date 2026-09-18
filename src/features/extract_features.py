"""
extract_features.py — Feature extraction (SINGLE code path for ALL raw records).

Input : data/raw*/*.jsonl  (raw record schema v2.0)
Adds  : rec["features_aux"] — deterministic features derived from `content`
        (+ per-session timing from `timestamp`).
        Payload features cover ALL injection vectors: URL query (via
        `decoded_payload`) PLUS request_body, Cookie values and injectable
        header values parsed out of `raw_request` (X-Capture-* excluded).
Output: data/processed/*_processed.jsonl (record schema v2, LOCKED).

LEAKAGE POLICY:
  Features are derived ONLY from the request (`content.*`) and request timing.
  NOTHING is read from `metadata.response_status_code` or any response field.

usage:
  python3 src/features/extract_features.py                       # all data/raw/*.jsonl
  python3 src/features/extract_features.py data/raw/juice_shop_raw.jsonl
  python3 src/features/extract_features.py data/dataset_raw.jsonl
"""
import glob
import json
import math
import os
import re
import sys
import urllib.parse
from collections import Counter
from datetime import datetime, timezone

RAW_DIR = "data/raw"
OUT_DIR = "data/processed"
RATE_WINDOW_MS = 10_000  # sliding window for request_rate_window
_AWARE_MIN = datetime.min.replace(tzinfo=timezone.utc)

# ---------------------------------------------------------------------------
# Attack-keyword banks (lowercase). Counted as occurrences, not just presence.
# These are request-derived tokens ONLY (never the label) -> not leakage.
# ---------------------------------------------------------------------------
SQLI_KEYWORDS = [
    "union", "select", "insert", "update", "delete", "drop", "or 1=1",
    "and 1=1", "or 1 =", "' or ", "\" or ", "' and ", "\" and ", "'='",
    "sleep(", "benchmark(", "waitfor",
    "information_schema", "load_file", "outfile", "concat(", "group_concat",
    "char(", "0x", "having", "group by", "order by", "cast(", "convert(",
    "@@version", "pg_sleep", "dbms_pipe",
]
XSS_KEYWORDS = [
    "<script", "</script", "onerror", "onload", "onmouseover", "onclick",
    "onfocus", "onstart", "javascript:", "alert(", "prompt(", "confirm(",
    "document.cookie", "document.location", "<img", "<svg", "<iframe",
    "<body", "<input", "<details", "fromcharcode", "expression(", "eval(",
    "onanimationstart", "srcdoc",
]
PATHTRAV_KEYWORDS = [
    "../", "..\\", "..%2f", "..%5c", "%2e%2e", "..;/", "/etc/passwd",
    "/etc/shadow", "/etc/hosts", "boot.ini", "win.ini", "/proc/self",
    "/windows/system32", "php://", "file://", "expect://", "zip://", "c:\\",
]
CODEINJ_KEYWORDS = [
    "{{", "}}", "${", "#{", "<%", "%>", "__import__", "os.system",
    "subprocess", "popen(", "exec(", "eval(", "commands.getoutput",
    "runtime.getruntime", "processbuilder", "system(", "passthru(",
    "shell_exec", "proc_open", "self.__class__", "__globals__", "freemarker",
]
# OS command injection. Designed to avoid benign false positives: NEVER match
# a BARE single '&' as a separator - it's the literal query-string param
# separator, so "& + command" (e.g. "&id", "&env", "&dir") collides with
# completely ordinary multi-param URLs (measured 2026-09-12: 489/17201 real
# benign train records already contain "&id"/"&env"/"&dir" as substrings from
# their own query strings). ';', '|', '&&', '||' never occur this way in
# benign traffic (0/17201 contain literal '&&' or '||') - safe to pair with a
# command word.
#
# GENERATED (not hand-enumerated) from separators x commands so this bank
# can't silently drift out of sync with attack_payloads.py's own
# COMMAND_INJECTION generator again: found 2026-09-12 that 57/165 (34.5%) of
# the actual command_injection payload bank scored kw_cmdi_count==0, because
# 8 of the generator's 15 commands (hostname/pwd/ps/netstat/ifconfig/env/dir/
# type) and the '||' separator were never added to the old hand-written list.
# Residual gap (intentionally NOT fixed): single-'&'-separator payloads
# ("& id", "& hostname", ...) and the one literal-newline payload
# ("\nid") stay invisible to this feature - closing those would reintroduce
# the false-positive risk above, or (for the newline case) require matching
# on a bare control character with no reliable command-word signal.
_CMDI_SAFE_SEPARATORS = ["; ", ";", "| ", "|", "&& ", "&&", "|| ", "||"]
_CMDI_COMMANDS = [
    "cat", "ls", "id", "whoami", "uname", "ping", "nc", "sleep", "wget", "curl",
    "hostname", "pwd", "ps", "netstat", "ifconfig", "env", "dir", "type",
]
CMDI_KEYWORDS = [
    f"{sep}{cmd}" for sep in _CMDI_SAFE_SEPARATORS for cmd in _CMDI_COMMANDS
] + [
    # command substitution / shell invocation (inherently suspicious alone,
    # no command-word pairing needed)
    "$(", "`", "/bin/sh", "/bin/bash", "bash -i", "sh -c",
    "cmd.exe", "powershell", "/c ",
    "nc -e", "netcat", "ping -c", "ping -n", "wget http", "curl http",
    # sensitive file reads (also caught by pathtrav; harmless overlap)
    "/etc/passwd", "/etc/shadow",
    # newline / CRLF command injection markers (present in RAW encoded form)
    "%0a", "%0d",
]
SQL_COMMENT_MARKERS = ["--", "#", "/*", "*/", ";--", "/**/"]


def _parse_ts(ts):
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None


def _ratio(count, total):
    if not total:
        return 0.0
    return round(count / total, 4)


def _special_char_ratio(s):
    if not s:
        return 0.0
    special = sum(1 for c in s if not c.isalnum())
    return round(special / len(s), 4)


def _digit_ratio(s):
    if not s:
        return 0.0
    return _ratio(sum(1 for c in s if c.isdigit()), len(s))


def _uppercase_ratio(s):
    if not s:
        return 0.0
    letters = [c for c in s if c.isalpha()]
    if not letters:
        return 0.0
    return _ratio(sum(1 for c in letters if c.isupper()), len(letters))


def _shannon_entropy(s):
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    ent = -sum((c / n) * math.log2(c / n) for c in counts.values())
    return round(ent, 4)


def _encoded_char_ratio(raw):
    """URL-encoding density. Computed on the RAW/still-encoded string so that
    %XX sequences are actually present (bugfix: previously ran on decoded)."""
    if not raw:
        return 0.0
    enc = len(re.findall(r"%[0-9a-fA-F]{2}", raw))
    return round(min(1.0, (enc * 3) / len(raw)), 4)


def _double_encoding_count(raw):
    """Count of double-encoded markers like %25XX (%25 == encoded '%')."""
    if not raw:
        return 0
    return len(re.findall(r"%25[0-9a-fA-F]{2}", raw, flags=re.IGNORECASE))


def _count_keywords(haystack, keywords):
    if not haystack:
        return 0
    return sum(haystack.count(k) for k in keywords)


def _density(count, length):
    """Keyword count normalized by payload length - 2 hits in a 15-char
    payload is a much stronger signal than 2 hits in a 500-char one, which
    kw_*_count alone can't distinguish. Found 2026-09-18: traversal_depth
    (../  counter) scores 0.0 on every single record in the entire 35,315
    -record dataset (no payload bank ever emits a literal ../ chain) -
    feature_importances_ confirms 0.00000 in both stage1 and stage2, so it
    was dropped and this was tried as a replacement. Kept for sqli/cmdi
    ONLY (kw_sqli_density rank 8/37, kw_cmdi_density rank 11/37 in stage1) -
    kw_xss_density and kw_codeinj_density were tried too but ranked 21-25/37
    (weak/no evidence) and were dropped again rather than kept "just in
    case" (see reports/PROGRESS_LOG.md, 2026-09-18 entry)."""
    return round(count / length, 4) if length else 0.0


# _ngram_bucket_densities (hashed character-trigram buckets) and
# _surface_diversity (how many of url/body/cookie/header carry content)
# were tried 2026-09-18 and DROPPED after real evidence, not assumption:
# surface_diversity_count scored 0.0 importance in stage2 and was weak in
# stage1; 6 of 8 hashed n-gram buckets were noise (rank 22-38/43) and,
# even though 2 buckets individually ranked well (7/43, 11/43 in stage1),
# the NET effect on the full pipeline was a regression - Amazon false
# positives rose 5->7, open-set known-reject cost rose 12.4%->16.8%, and
# cascade accuracy dropped on both test and cross-app. A feature that
# looks useful in isolation but makes the deployed system measurably
# worse is not kept "just in case" - see reports/PROGRESS_LOG.md,
# 2026-09-18 entry.


def _split_head(raw_request):
    return (raw_request or "").split("\r\n\r\n", 1)[0]


def _header_count(raw_request):
    head = _split_head(raw_request)
    if not head:
        return 0
    return max(0, len(head.split("\r\n")) - 1)  # minus the request line


def _content_type(raw_request):
    head = _split_head(raw_request)
    for line in head.split("\r\n")[1:]:
        if line.lower().startswith("content-type:"):
            return line.split(":", 1)[1].strip()
    return None


# ---------------------------------------------------------------------------
# Non-query payload surfaces (body / header / cookie).
# capture_addon.py derives `decoded_payload` from the URL (path+query) ONLY,
# so body/header/cookie payloads exist only inside `raw_request`. Here we fold
# them into the featurised payload so non-query vectors are not invisible.
# SAME single code path for benign AND attack records -> no leakage.
# ---------------------------------------------------------------------------
X_CAPTURE_PREFIX = "x-capture-"
# infrastructure headers whose values are never treated as a payload surface
NON_PAYLOAD_HEADERS = {
    "host", "connection", "accept", "accept-encoding", "content-length",
    "content-type", "cookie", "keep-alive", "transfer-encoding",
    "upgrade-insecure-requests", "cache-control", "pragma",
    "if-modified-since", "if-none-match", "te", "dnt",
}


def _decode_soft(s):
    """URL-decode twice (mirrors capture_addon's double-unquote), keep case."""
    if not s:
        return ""
    out = str(s)
    for _ in range(2):
        try:
            out = urllib.parse.unquote_plus(out)
        except Exception:
            break
    return out


def _parse_headers(raw_request):
    """(name_lower, value) pairs from the request head; X-Capture-* skipped."""
    head = _split_head(raw_request)
    headers = []
    for line in head.split("\r\n")[1:]:
        if ":" not in line:
            continue
        name, val = line.split(":", 1)
        name = name.strip().lower()
        if name.startswith(X_CAPTURE_PREFIX):
            continue
        headers.append((name, val.strip()))
    return headers


def _extra_payload_surfaces(content):
    """Decoded (body, cookie_values, injectable_header_values) strings."""
    body = _decode_soft(content.get("request_body") or "")
    cookie_vals, header_vals = [], []
    for name, val in _parse_headers(content.get("raw_request") or ""):
        if name == "cookie":
            for part in val.split(";"):
                part = part.strip()
                cookie_vals.append(
                    _decode_soft(part.split("=", 1)[1] if "=" in part else part))
        elif name not in NON_PAYLOAD_HEADERS:
            header_vals.append(_decode_soft(val))
    return body, " ".join(cookie_vals), " ".join(header_vals)


def compute_features(rec):
    content = rec.get("content", {})
    url_path = content.get("url_path") or ""
    query_string = content.get("query_string") or ""
    decoded = content.get("decoded_payload") or ""
    raw_request = content.get("raw_request") or ""

    # fold non-query surfaces (body / cookie / header) into the payload space
    body_dec, cookie_dec, header_dec = _extra_payload_surfaces(content)
    extra = " ".join(p for p in (body_dec, cookie_dec, header_dec) if p)
    payload = decoded + (" " + extra if extra else "")

    # normalized search spaces
    # fully decode for keyword hunting: stored decoded_payload may still carry
    # '+' for spaces (e.g. "AND+1=1"), which used to hide keywords like "and 1=1"
    dec_l = _decode_soft(payload).lower()
    # raw/encoded space: keep %XX visible for encoding + path-traversal markers
    raw_enc = " ".join([query_string, url_path, raw_request]).lower()
    # combined space for keyword hunting (decoded + raw so encoded markers count)
    combo = dec_l + " " + raw_enc

    plen = len(payload)
    kw_sqli = _count_keywords(combo, SQLI_KEYWORDS)
    kw_xss = _count_keywords(combo, XSS_KEYWORDS)
    kw_codeinj = _count_keywords(combo, CODEINJ_KEYWORDS)
    kw_cmdi = _count_keywords(combo, CMDI_KEYWORDS)
    quote_count = payload.count("'") + payload.count('"')

    return {
        # --- length / structure ---
        "path_length": len(url_path),
        "query_param_count": len(urllib.parse.parse_qsl(query_string)) if query_string else 0,
        "payload_length": plen,
        "url_payload_length": len(decoded),
        "body_payload_length": len(body_dec),
        "cookie_payload_length": len(cookie_dec),
        "header_payload_length": len(header_dec),
        "header_count": _header_count(raw_request),
        "content_type": _content_type(raw_request),
        # --- character statistics (over the FULL folded payload) ---
        "special_char_ratio": _special_char_ratio(payload),
        "digit_ratio": _digit_ratio(payload),
        "uppercase_ratio": _uppercase_ratio(payload),
        "entropy": _shannon_entropy(payload),
        # --- encoding / obfuscation (on RAW encoded form) ---
        "encoded_char_ratio": _encoded_char_ratio(raw_enc),
        "double_encoding_count": _double_encoding_count(raw_enc),
        # --- attack-class keyword signals (raw count + length-normalized density) ---
        "kw_sqli_count": kw_sqli,
        "kw_xss_count": kw_xss,
        "kw_pathtrav_count": _count_keywords(combo, PATHTRAV_KEYWORDS),
        "kw_codeinj_count": kw_codeinj,
        "kw_cmdi_count": kw_cmdi,
        "kw_sqli_density": _density(kw_sqli, plen),
        "kw_cmdi_density": _density(kw_cmdi, plen),
        "sql_comment_count": _count_keywords(dec_l, SQL_COMMENT_MARKERS),
        # --- token structure counts (over the FULL folded payload) ---
        "angle_bracket_count": payload.count("<") + payload.count(">"),
        "quote_count": quote_count,
        "quote_parity": quote_count % 2,
        "paren_count": payload.count("(") + payload.count(")"),
        # --- per-session timing (filled by add_timing) ---
        "inter_arrival_ms": None,
        "request_rate_window": None,
    }


def add_timing(records):
    """Fill inter_arrival_ms and request_rate_window per session from timestamps."""
    by_session = {}
    for idx, rec in enumerate(records):
        sid = rec.get("session_id") or "__nosession__"
        by_session.setdefault(sid, []).append(idx)
    for idxs in by_session.values():
        idxs.sort(key=lambda i: _parse_ts(records[i].get("timestamp")) or _AWARE_MIN)
        times = [_parse_ts(records[i].get("timestamp")) for i in idxs]
        for pos, i in enumerate(idxs):
            t = times[pos]
            if t is None:
                continue
            if pos == 0:
                records[i]["features_aux"]["inter_arrival_ms"] = 0
            elif times[pos - 1] is not None:
                records[i]["features_aux"]["inter_arrival_ms"] = int((t - times[pos - 1]).total_seconds() * 1000)
            cnt = sum(1 for tt in times[: pos + 1]
                      if tt is not None and (t - tt).total_seconds() * 1000 <= RATE_WINDOW_MS)
            records[i]["features_aux"]["request_rate_window"] = cnt


def process_file(path):
    records = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            rec["features_aux"] = compute_features(rec)
            records.append(rec)
    add_timing(records)
    os.makedirs(OUT_DIR, exist_ok=True)
    base = os.path.basename(path).replace("_raw.jsonl", "").replace(".jsonl", "")
    out_path = os.path.join(OUT_DIR, f"{base}_processed.jsonl")
    with open(out_path, "w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    return out_path, len(records)


def main():
    targets = sys.argv[1:] or glob.glob(os.path.join(RAW_DIR, "*.jsonl"))
    if not targets:
        print("[!] no input files under data/raw/")
        return 0
    for path in targets:
        out_path, n = process_file(path)
        print(f"[features] {path} -> {out_path} ({n} records)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
