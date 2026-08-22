"""
mitmproxy addon â€” Unified capture layer (schema v2, RAW stage).

:   (benign + attack)     addon =   .
-  X-Capture-* headers     (  feature/leakage).
-  RAW record   schema v2 â€”   features_aux.
  ( features   src/features/extract_features.py    +  datasets .)
-  timestamp   extract_features.py   inter_arrival_ms.

Run:
  mitmdump -s capture_addon.py --set capture_dir=./data/raw --listen-port 8888
"""
import datetime
import json
import os
import urllib.parse
import uuid

from mitmproxy import ctx, http


# Static assets (css/js/images/fonts/source-maps) are byte-identical on every
# single page load and carry NO attack semantics - they are pure noise for an
# HTTP-request attack classifier, and (confirmed by a path-frequency audit of
# data/raw) they were a major source of exact-duplicate raw records. Skip them
# at capture time so they never enter data/raw at all.
# IMPORTANT: match ONLY on the URL path extension (the part before "?"), never
# the query string, so a genuinely dynamic endpoint such as
# /download.php?file=report.css (or a path-traversal payload) is still captured.
STATIC_ASSET_EXTS = (
    ".css", ".js", ".mjs", ".map",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
)


# Real dynamic sites captured via a real/organic browser session carry NO
# X-Capture-* headers (a real browser can't send custom headers), so we
# infer app/source_type from the request's own domain instead of relying
# on a client-sent header. This is only a FALLBACK: if X-Capture-App/-Type
# is explicitly present (e.g. from benign_driver.py or attack_driver.py),
# that explicit value always wins - this map never overrides it.
SITE_HOSTS = {
    "facebook": ["facebook.com", "www.facebook.com", "m.facebook.com", "web.facebook.com"],
    "amazon": ["amazon.com", "www.amazon.com"],
    "medium": ["medium.com", "www.medium.com"],
    "stackoverflow": ["stackoverflow.com", "www.stackoverflow.com"],
    "reddit": ["reddit.com", "www.reddit.com", "old.reddit.com", "m.reddit.com"],
    "youtube": ["youtube.com", "www.youtube.com", "m.youtube.com", "youtubei.googleapis.com"],
}

DOMAIN_APP_MAP = {host: app for app, hosts in SITE_HOSTS.items() for host in hosts    "x.com": "x",
    "www.x.com": "x",
    "mobile.x.com": "x",
    "twitter.com": "x",
    "www.twitter.com": "x",
    "mobile.twitter.com": "x",
    "api.x.com": "x",
    "api.twitter.com": "x",
}

NOISE_DOMAIN_SUFFIXES = (
    "doubleclick.net",
    "googlesyndication.com",
    "googletagmanager.com",
    "google-analytics.com",
    "googleadservices.com",
    "adtrafficquality.google",
    "gstatic.com",
    "googlevideo.com",
    "gvt2.com",
    "ytimg.com",
    "googleusercontent.com",
)


def _is_noise_host(host):
    host = (host or "").lower()
    return any(host == d or host.endswith("." + d) for d in NOISE_DOMAIN_SUFFIXES)


def _is_static_asset(path: str) -> bool:
    clean = path.split("?", 1)[0].lower()
    return clean.endswith(STATIC_ASSET_EXTS)


# Known background telemetry / analytics-beacon endpoints. These fire
# continuously regardless of what a user is actually doing (every scroll,
# hover, tab-switch, perf sample, recaptcha check, styling-config fetch, or
# cookie-consent ping), and each payload embeds a fresh UUID/timestamp so
# they never hash as exact duplicates - but they carry almost no
# request-shape diversity useful for an HTTP attack classifier. Drop them
# at capture time, same as static assets and third-party ad/tracking noise.
# Extend this list as new sites are added to the pilot.
NOISE_PATH_SUBSTRINGS = (
    "/svc/shreddit/events",
    "/svc/events/preload-head",
    "/svc/shreddit/perfMetrics",
    "/svc/shreddit/update-recaptcha",
    "/svc/shreddit/data-protection-consent",
    "/svc/shreddit/styling-overrides",
    "/api/stats/qoe",
    "/youtubei/v1/log_event",
)


def _is_noise_path(path: str) -> bool:
    clean = path.split("?", 1)[0]
    return any(noise in clean for noise in NOISE_PATH_SUBSTRINGS)



def load(loader):
    loader.add_option("capture_dir", str, "/out/raw", "Directory for raw JSONL output")
    loader.add_option("default_source", str, "unknown", "Fallback source_id")
    loader.add_option("default_app", str, "unknown", "Fallback app")
    loader.add_option("default_stack", str, "", "Fallback tech_stack")
    loader.add_option("default_label", str, "benign", "Fallback label class")
    loader.add_option("default_type", str, "scripted", "source_type: real|scripted|public_dataset")
    loader.add_option("default_mode", str, "browser", "generation_mode: browser|tool|dataset")
    loader.add_option("default_tool", str, "", "Fallback tool_name")


def configure(updated):
    os.makedirs(ctx.options.capture_dir, exist_ok=True)


def _pop(headers, name, default):
    """ header         default."""
    if name in headers:
        value = headers[name]
        del headers[name]
        return value
    return default


def _now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def request(flow: http.HTTPFlow):
    # Drop static assets before doing any work (see STATIC_ASSET_EXTS note).
    # No record is attached to flow.metadata, so response() will skip it too.
    if _is_static_asset(flow.request.path):
        return
    if _is_noise_path(flow.request.path):
        return

        if _is_noise_host(flow.request.host):
            return

    # skip login/bootstrap requests (carry X-Capture-Skip; never recorded)
    if "X-Capture-Skip" in flow.request.headers:
        del flow.request.headers["X-Capture-Skip"]
        return

    h = flow.request.headers
    o = ctx.options

    # --- X-Capture-* (control headers)     raw_request ---
    source_id = _pop(h, "X-Capture-Source", o.default_source)
    inferred_app = DOMAIN_APP_MAP.get(flow.request.host.lower(), o.default_app)
    app = _pop(h, "X-Capture-App", inferred_app)
    tech_stack = _pop(h, "X-Capture-Stack", o.default_stack) or None
    inferred_type = "real" if flow.request.host.lower() in DOMAIN_APP_MAP else o.default_type
    ctype = _pop(h, "X-Capture-Type", inferred_type)        # real|scripted|public_dataset
    mode = _pop(h, "X-Capture-Mode", o.default_mode)         # browser|tool|dataset
    label = _pop(h, "X-Capture-Label", o.default_label)      # benign|sqli|xss|path_traversal|code_injection
    session = _pop(h, "X-Capture-Session", "")
    persona_id = _pop(h, "X-Capture-Persona", "") or None
    scenario_id = _pop(h, "X-Capture-Scenario", "") or None
    tool = _pop(h, "X-Capture-Tool", o.default_tool) or None
    variant = _pop(h, "X-Capture-Variant", "original")
    parent = _pop(h, "X-Capture-Parent", "") or None

    req = flow.request
    query_string = urllib.parse.urlencode(list(req.query.items())) if req.query else None
    body = req.get_text(strict=False) or ""

    # raw_request      X-Capture-* (PRIMARY model input)
    raw_lines = [f"{req.method} {req.path} HTTP/1.1"]
    raw_lines += [f"{k}: {v}" for k, v in h.items()]
    raw_request = "\r\n".join(raw_lines) + "\r\n\r\n" + body

    # canonicalization:    (  path_traversal)
    full_url = req.path.split("?")[0] + (("?" + query_string) if query_string else "")
    decoded_payload = urllib.parse.unquote(urllib.parse.unquote(full_url))

    # : benign -> benign    -> malicious
    level1 = "benign" if label == "benign" else "malicious"
    split_role = "heldout_unknown" if label == "code_injection" else "train"
    # label_source     (  )
    if mode == "dataset":
        label_source = "dataset"
    elif mode == "tool":
        label_source = "tool_confirmed"
    else:
        label_source = "manual"

    record = {
        "schema_version": "2.0",
        "record_id": str(uuid.uuid4()),
        "session_id": session,
        "timestamp": _now_iso(),  # audit-only extract_features   inter_arrival_ms
        "metadata": {
            "source_id": source_id,
            "app": app,
            "source_type": ctype,
            "tech_stack": tech_stack,
            "environment": "docker_lab",
            "generation_mode": mode,
            "persona_id": persona_id,
            "scenario_id": scenario_id,
            "tool_name": tool,
            "capture_tool": "mitmproxy",
            "capture_date": _now_iso(),
            "site_category": None,
            "response_status_code": None,  #   response()
        },
        "content": {
            "http_method": req.method,
            "url_path": req.path.split("?")[0],
            "query_string": query_string,
            "request_body": body or None,
            "raw_request": raw_request,
            "decoded_payload": decoded_payload,
        },
        "variant": {"variant_type": variant, "parent_id": parent},
        "label": {
            "level1": level1,
            "class": label,
            "split_role": split_role,
            "label_source": label_source,
        },
    }
    flow.metadata["record"] = record


def response(flow: http.HTTPFlow):
    record = flow.metadata.get("record")
    if not record:
        return
    record["metadata"]["response_status_code"] = flow.response.status_code
    app = record["metadata"]["app"] or "unknown"
    out_path = os.path.join(ctx.options.capture_dir, f"{app}_raw.jsonl")
    with open(out_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

