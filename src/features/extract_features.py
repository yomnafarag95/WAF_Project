"""
extract_features.py — Feature extraction (SINGLE code path for ALL raw records).

Input : data/raw*/*.jsonl  (raw record schema v2.0)
Adds  : rec["features_aux"] — deterministic features derived from `content`
        (+ per-session timing from `timestamp`).
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
    "and 1=1", "or 1 =", "' or ", "\" or ", "sleep(", "benchmark(", "waitfor",
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


def _traversal_depth(decoded):
    if not decoded:
        return 0
    return decoded.replace("\\", "/").count("../")


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


def compute_features(rec):
    content = rec.get("content", {})
    url_path = content.get("url_path") or ""
    query_string = content.get("query_string") or ""
    decoded = content.get("decoded_payload") or ""
    raw_request = content.get("raw_request") or ""

    # normalized search spaces
    dec_l = decoded.lower()
    # raw/encoded space: keep %XX visible for encoding + path-traversal markers
    raw_enc = " ".join([query_string, url_path, raw_request]).lower()
    # combined space for keyword hunting (decoded + raw so encoded markers count)
    combo = dec_l + " " + raw_enc

    return {
        # --- length / structure ---
        "path_length": len(url_path),
        "query_param_count": len(urllib.parse.parse_qsl(query_string)) if query_string else 0,
        "payload_length": len(decoded),
        "header_count": _header_count(raw_request),
        "content_type": _content_type(raw_request),
        # --- character statistics ---
        "special_char_ratio": _special_char_ratio(decoded),
        "digit_ratio": _digit_ratio(decoded),
        "uppercase_ratio": _uppercase_ratio(decoded),
        "entropy": _shannon_entropy(decoded),
        # --- encoding / obfuscation (on RAW encoded form) ---
        "encoded_char_ratio": _encoded_char_ratio(raw_enc),
        "double_encoding_count": _double_encoding_count(raw_enc),
        # --- attack-class keyword signals ---
        "kw_sqli_count": _count_keywords(combo, SQLI_KEYWORDS),
        "kw_xss_count": _count_keywords(combo, XSS_KEYWORDS),
        "kw_pathtrav_count": _count_keywords(combo, PATHTRAV_KEYWORDS),
        "kw_codeinj_count": _count_keywords(combo, CODEINJ_KEYWORDS),
        "sql_comment_count": _count_keywords(dec_l, SQL_COMMENT_MARKERS),
        "traversal_depth": _traversal_depth(decoded),
        # --- token structure counts ---
        "angle_bracket_count": decoded.count("<") + decoded.count(">"),
        "quote_count": decoded.count("'") + decoded.count('"'),
        "paren_count": decoded.count("(") + decoded.count(")"),
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
