"""
Real-site supplementary benign traffic (Phase 0 "Supplementary benign" tier).

Visits real, publicly accessible, low-risk, read-only endpoints through the
SAME mitmproxy capture proxy as the lab apps, so the resulting records use
the exact same schema_v2 format and can be directly compared/merged with
lab (scripted persona) benign traffic.

Sites (all read-only, public APIs, no auth, policy-compliant):
  - wikipedia        : Wikipedia REST API summaries (kept <= 4 req/sec,
                        under Wikipedia's 5 req/sec guidance)
  - pokeapi          : PokeAPI (open, no auth, no rate limit for small volume)
  - jsonplaceholder  : JSONPlaceholder fake REST API (smoke-test friendly)

These are NOT the primary benign source (that is the lab apps via
run_benign_generation.py / benign_driver.py, paired with attacks). They are
additional realistic diversity, tagged metadata.source_type="real" so they
can be told apart from metadata.source_type="scripted" lab traffic.

Usage (from project root):
  pip install requests pyyaml
  # start docker-compose (mitmproxy-benign must be up on 8888)
  python3 -m src.collection.real_sites_driver --config config/sources.yaml --requests-per-site 40
  python3 -m src.collection.real_sites_driver --config config/sources.yaml --only-site wikipedia
"""
import argparse
import random
import time
import uuid
import warnings

import requests
import urllib3
import yaml

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)

# NOTE on diversity: earlier versions used a fixed list of ~7-8 literal paths
# per site. capture_addon.py strips ALL X-Capture-* headers (including the
# per-session id) before building raw_request, so hitting the SAME literal
# path repeatedly produced a byte-IDENTICAL raw_request every time - real
# duplicates, not just similar-looking traffic. merge_jsonl.py dedups on a
# sha256 of raw_request, so most repeats of a fixed path were silently
# collapsed into one record at merge time. The "{placeholder}" entries below
# get a fresh random id substituted per request (see _pick_path()), and
# Wikipedia's own /page/random/summary endpoint returns a genuinely different
# article server-side each call - both give real, non-duplicate diversity.
# Large, diverse pools so repeated wikipedia calls produce genuinely
# DIFFERENT requests. The old version used ~8 literal paths (no
# placeholders), so every extra call re-hit the same URL and merge_jsonl.py
# collapsed them (413 raw -> 151 unique, 63% dup). {title}/{term} below are
# substituted per request from these pools (see _pick_path).
WIKI_TITLES = [
    "Cross-site_scripting", "SQL_injection", "Web_application_security",
    "Machine_learning", "Firewall_(computing)", "Cryptography",
    "Denial-of-service_attack", "Phishing", "Malware", "Computer_virus",
    "Encryption", "Public-key_cryptography", "Transport_Layer_Security",
    "HTTP_cookie", "Domain_Name_System", "IP_address", "Router_(computing)",
    "Operating_system", "Linux", "Python_(programming_language)",
    "JavaScript", "Database", "Relational_database", "Cloud_computing",
    "Artificial_intelligence", "Artificial_neural_network", "Deep_learning",
    "Data_science", "Statistics", "Algorithm", "Computer_network",
    "Internet", "World_Wide_Web", "HTML", "Cascading_Style_Sheets",
    "Docker_(software)", "Kubernetes", "Virtual_machine", "Penetration_test",
    "Vulnerability_(computing)", "Buffer_overflow", "Authentication",
    "Password", "Biometrics", "Blockchain", "Bitcoin", "Quantum_computing",
    "Physics", "Mathematics", "Biology", "Chemistry", "Astronomy",
    "History_of_the_Internet", "Alan_Turing", "Ada_Lovelace",
    "Computer_science", "Information_security", "Intrusion_detection_system",
    "Proxy_server", "Load_balancing_(computing)", "API",
    "Representational_state_transfer", "JSON", "XML", "Regular_expression",
    "Unicode", "Hash_function", "Digital_signature", "OWASP",
    "Secure_Shell", "Hypertext_Transfer_Protocol",
]
WIKI_SEARCH = [
    "security", "network", "encryption", "firewall", "python",
    "database", "cloud", "algorithm", "statistics", "malware",
    "phishing", "cryptography", "authentication", "protocol", "server",
    "javascript", "docker", "linux", "api", "vulnerability",
    "hashing", "neural", "science", "internet", "kernel",
]

REAL_SITES = {
    "wikipedia": {
        "base_url": "https://en.wikipedia.org",
        "tech_stack": "php_mediawiki",
        "paths": [
            "/api/rest_v1/page/summary/{title}",
            "/api/rest_v1/page/summary/{title}",
            "/api/rest_v1/page/summary/{title}",
            "/api/rest_v1/page/summary/{title}",
            "/w/api.php?action=query&list=search&srsearch={term}&format=json",
            "/w/api.php?action=query&list=search&srsearch={term}&format=json",
            "/api/rest_v1/page/random/summary",
        ],
        "min_delay_ms": 260,  # keep at/under 4 req/sec (policy allows <=5)
    },
    "pokeapi": {
        "base_url": "https://pokeapi.co",
        "tech_stack": "ruby_graphql",
        "paths": [
            "/api/v2/pokemon/{id}",
            "/api/v2/pokemon/{id}",
            "/api/v2/pokemon/{id}",
            "/api/v2/pokemon?limit=20&offset={offset}",
            "/api/v2/ability/{ability_id}",
            "/api/v2/move/{move_id}",
            "/api/v2/move/{move_id}",
            "/api/v2/item/{item_id}",
            "/api/v2/berry/{berry_id}",
            "/api/v2/pokemon-species/{id}",
            "/api/v2/location/{location_id}",
            "/api/v2/type/fire",
            "/api/v2/type/water",
            "/api/v2/type/grass",
        ],
        "min_delay_ms": 150,
    },
    "jsonplaceholder": {
        "base_url": "https://jsonplaceholder.typicode.com",
        "tech_stack": "node_express",
        "paths": [
            "/posts/{post_id}",
            "/posts",
            "/posts/{post_id}/comments",
            "/users/{user_id}",
            "/users/{user_id}/posts",
            "/users/{user_id}/todos",
            "/users/{user_id}/albums",
            "/comments?postId={post_id}",
            "/comments/{comment_id}",
            "/todos/{todo_id}",
            "/albums/{album_id}",
            "/albums/{album_id}/photos",
            "/photos/{photo_id}",
        ],
        "min_delay_ms": 120,
    },
}


def _pick_path(site_cfg: dict) -> str:
    """Pick a path template and substitute any {placeholder} with a fresh
    random, in-range id so repeated calls produce genuinely different
    (non-duplicate) requests instead of re-hitting the same literal URL."""
    template = random.choice(site_cfg["paths"])
    if "{" not in template:
        return template
    values = {
        "id": random.randint(1, 1010),           # pokemon id range
        "ability_id": random.randint(1, 300),
        "move_id": random.randint(1, 900),
        "item_id": random.randint(1, 1600),
        "berry_id": random.randint(1, 64),
        "location_id": random.randint(1, 800),
        "offset": random.choice([0, 20, 40, 60, 80, 100, 150, 200]),
        "post_id": random.randint(1, 100),        # jsonplaceholder has 100 posts
        "user_id": random.randint(1, 10),          # 10 users
        "todo_id": random.randint(1, 200),          # 200 todos
        "album_id": random.randint(1, 100),         # 100 albums
        "comment_id": random.randint(1, 500),        # 500 comments
        "photo_id": random.randint(1, 5000),         # 5000 photos
        "title": random.choice(WIKI_TITLES),
        "term": random.choice(WIKI_SEARCH),
    }
    return template.format(**values)


# Wikipedia (and some other public APIs) reject/rate-limit requests that use
# the default "python-requests/x.y" User-Agent - this is the most likely
# cause of a high error rate on real sites. Send a descriptive UA per WMF's
# User-Agent policy (https://meta.wikimedia.org/wiki/User-Agent_policy); it
# is harmless for pokeapi/jsonplaceholder too.
CONTACT_EMAIL = "yomnafarag95@gmail.com"

# Light-touch header diversity only (NOT a persona/scenario system - see
# discussion with the user: real sites are meant to stay organic/unscripted,
# a full persona system would blur the scripted-vs-real distinction the
# comparison tooling relies on). Each session picks ONE of these UAs and
# keeps it for all requests in that session, exactly like a real visitor
# would keep the same browser/device for one visit. All of them still
# identify the research contact per Wikipedia's User-Agent policy.
REAL_USER_AGENTS = [
    f"WAF-Attack-Classifier-Research/1.0 (desktop; thesis data collection; contact: {CONTACT_EMAIL})",
    f"WAF-Attack-Classifier-Research/1.0 (Macintosh; thesis data collection; contact: {CONTACT_EMAIL})",
    f"WAF-Attack-Classifier-Research/1.0 (Android 13; Mobile; thesis data collection; contact: {CONTACT_EMAIL})",
    f"WAF-Attack-Classifier-Research/1.0 (iPhone; CPU iPhone OS 17_0; thesis data collection; contact: {CONTACT_EMAIL})",
    f"WAF-Attack-Classifier-Research/1.0 (iPad; tablet; thesis data collection; contact: {CONTACT_EMAIL})",
]


def capture_headers(site_name: str, tech_stack: str, session_id: str, user_agent: str) -> dict:
    """X-Capture-* headers the mitmproxy addon reads then strips before the
    request reaches the real server, exactly like the lab-app drivers, PLUS
    a real User-Agent/Accept header that DOES reach the target site."""
    return {
        "X-Capture-Source": site_name,
        "X-Capture-App": site_name,
        "X-Capture-Stack": tech_stack,
        "X-Capture-Type": "real",
        "X-Capture-Mode": "tool",
        "X-Capture-Label": "benign",
        "X-Capture-Session": session_id,
        "X-Capture-Tool": "real_sites_driver",
        "User-Agent": user_agent,
        "Accept": "application/json",
    }


def _get_with_retry(url: str, headers: dict, proxies: dict, timeout: int, retries: int = 2):
    """jsonplaceholder in particular can be flaky/slow through a local proxy -
    retry transient timeouts/connection errors a couple of times with a short
    backoff before giving up on that request."""
    last_exc = None
    for attempt in range(retries + 1):
        try:
            return requests.get(url, headers=headers, proxies=proxies, verify=False, timeout=timeout)
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
            last_exc = e
            if attempt < retries:
                time.sleep(1.5 * (attempt + 1))
    raise last_exc


def run_site(site_name: str, site_cfg: dict, proxy_url: str, requests_per_site: int) -> int:
    proxies = {"http": proxy_url, "https": proxy_url}
    total = 0
    n_sessions = max(1, requests_per_site // 6)
    for _ in range(n_sessions):
        session_id = str(uuid.uuid4())
        user_agent = random.choice(REAL_USER_AGENTS)
        headers = capture_headers(site_name, site_cfg["tech_stack"], session_id, user_agent)
        n = random.randint(4, 8)
        for _ in range(n):
            path = _pick_path(site_cfg)
            url = site_cfg["base_url"] + path
            try:
                resp = _get_with_retry(url, headers, proxies, timeout=30)
                total += 1
                if resp.status_code >= 400:
                    print(f"    [warn] {resp.status_code} {url}")
            except Exception as e:
                print(f"    [skip] {url} -> {e}")
            time.sleep(site_cfg["min_delay_ms"] / 1000.0 + random.uniform(0, 0.3))
    return total


def main() -> None:
    ap = argparse.ArgumentParser(description="Real-site supplementary benign traffic")
    ap.add_argument("--config", required=True, help="path to config/sources.yaml")
    ap.add_argument("--requests-per-site", type=int, default=40)
    ap.add_argument("--only-site", default=None, choices=list(REAL_SITES.keys()))
    args = ap.parse_args()

    with open(args.config, encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    proxy_url = cfg["proxy_benign"]

    sites = {args.only_site: REAL_SITES[args.only_site]} if args.only_site else REAL_SITES
    grand_total = 0
    for site_name, site_cfg in sites.items():
        print(f"[+] {site_name} -> {site_cfg['base_url']}")
        n = run_site(site_name, site_cfg, proxy_url, args.requests_per_site)
        print(f"    {n} requests captured")
        grand_total += n

    print(f"[done] {grand_total} real-site requests -> data/raw/{{site}}_raw.jsonl")


if __name__ == "__main__":
    main()
