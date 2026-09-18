import re
import json
import hashlib
from collections import defaultdict
from urllib.parse import parse_qsl, urlencode

# ---------------------------------------------------------------------------
# 1) REDACTION
# ---------------------------------------------------------------------------

SENSITIVE_HEADER_NAMES = {
    "authorization", "cookie", "set-cookie", "x-csrftoken", "x-auth-token",
    "proxy-authorization", "x-session-token", "x-access-token",
}

SENSITIVE_BODY_FIELDS = {
    "password", "pass", "pwd", "email", "username", "login", "access_token",
    "refresh_token", "id_token", "session_key", "auth_token", "otp", "secret",
    "token",
}


def redact_headers(headers):
    """headers: dict-like of header name -> value (e.g. mitmproxy Headers). Returns a plain redacted dict."""
    redacted = {}
    for k, v in dict(headers).items():
        redacted[k] = "[REDACTED]" if k.lower() in SENSITIVE_HEADER_NAMES else v
    return redacted


def _redact_json(data):
    if isinstance(data, dict):
        return {
            k: ("[REDACTED]" if k.lower() in SENSITIVE_BODY_FIELDS else _redact_json(v))
            for k, v in data.items()
        }
    if isinstance(data, list):
        return [_redact_json(v) for v in data]
    return data


_FALLBACK_PATTERN = re.compile(
    r'(?i)("?(?:' + "|".join(SENSITIVE_BODY_FIELDS) + r')"?\s*[:=]\s*)("[^"]*"|[^&\s"]+)'
)


def redact_body(body_text, content_type=""):
    """body_text: decoded string body. Returns a redacted copy for JSON/form bodies."""
    if not body_text:
        return body_text
    ct = (content_type or "").lower()
    try:
        if "application/json" in ct:
            return json.dumps(_redact_json(json.loads(body_text)))
        if "x-www-form-urlencoded" in ct:
            pairs = parse_qsl(body_text, keep_blank_values=True)
            redacted_pairs = [
                (k, "[REDACTED]" if k.lower() in SENSITIVE_BODY_FIELDS else v)
                for k, v in pairs
            ]
            return urlencode(redacted_pairs)
    except Exception:
        pass
    # Fallback: regex-scrub common key=value / "key":"value" patterns for safety
    return _FALLBACK_PATTERN.sub(r"\1[REDACTED]", body_text)


def redact_query_string(query_string):
    """query_string: a 'k=v&k2=v2' string (no leading '?'), or None. Redacts sensitive params only,
    so attack payloads (XSS/SQLi/path traversal) in other params are preserved untouched."""
    if not query_string:
        return query_string
    pairs = parse_qsl(query_string, keep_blank_values=True)
    redacted_pairs = [
        (k, "[REDACTED]" if k.lower() in SENSITIVE_BODY_FIELDS else v)
        for k, v in pairs
    ]
    return urlencode(redacted_pairs)


# ---------------------------------------------------------------------------
# 2) DEDUPLICATION (for chatty endpoints like /api/graphql/)
# ---------------------------------------------------------------------------

_seen_counts = defaultdict(int)
MAX_DUPLICATES = 1  # strict: record the first occurrence only, drop exact repeats

_VOLATILE_FIELD_PATTERN = re.compile(
    r'"(timestamp|cursor|ts|_ts|request_id|client_mutation_id)"\s*:\s*"?[\w\-.]+"?'
)


def _normalize_body_for_dedup(body_text):
    if not body_text:
        return ""
    return _VOLATILE_FIELD_PATTERN.sub("", body_text)


def is_duplicate(method, path, body_text, user_agent=""):
    # user_agent is folded into the signature because header-vector attacks
    # (e.g. bwapp's xss_user_agent.php) carry their ENTIRE payload in the
    # User-Agent header with an otherwise constant method/path/empty-body -
    # without this, every such request after the first hashes identical and
    # gets dropped as a false "exact duplicate" (found 2026-09-12: 535/536
    # header-vector XSS captures were silently discarded this way).
    sig_source = f"{method}:{path}:{_normalize_body_for_dedup(body_text)}:{user_agent}"
    sig = hashlib.sha256(sig_source.encode("utf-8", "ignore")).hexdigest()
    _seen_counts[sig] += 1
    return _seen_counts[sig] > MAX_DUPLICATES


if __name__ == "__main__":
    h = redact_headers({"Cookie": "abc123", "User-Agent": "test", "Authorization": "Bearer xyz"})
    assert h["Cookie"] == "[REDACTED]" and h["Authorization"] == "[REDACTED]" and h["User-Agent"] == "test"

    b = redact_body('{"email": "a@b.com", "password": "hunter2", "note": "hi"}', "application/json")
    parsed = json.loads(b)
    assert parsed["email"] == "[REDACTED]" and parsed["password"] == "[REDACTED]" and parsed["note"] == "hi"

    b2 = redact_body("username=me&password=hunter2&q=hello", "application/x-www-form-urlencoded")
    assert "hunter2" not in b2 and "hello" in b2

    q = redact_query_string("email=a@b.com&search=%27%20OR%20%271%27=%271")
    assert "a@b.com" not in q and "OR" in q  # SQLi payload in another param must survive

    assert is_duplicate("POST", "/api/graphql/", '{"doc_id": "1"}') is False
    assert is_duplicate("POST", "/api/graphql/", '{"doc_id": "1"}') is False
    assert is_duplicate("POST", "/api/graphql/", '{"doc_id": "1"}') is False
    assert is_duplicate("POST", "/api/graphql/", '{"doc_id": "1"}') is True

    print("ALL SELF-TESTS PASSED")
