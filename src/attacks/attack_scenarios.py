"""Attack scenarios - maps (app, attack_type) to the concrete vulnerable endpoint
and turns an attacker persona into an ordered list of AttackStep objects.

This is the ATTACK analogue of src/collection/personas/scenarios.py:
  benign scenarios.py:  persona.goal          -> list[ScenarioStep]
  this module:          (persona, app, attack) -> list[AttackStep]

honouring the persona's evasion / vector / intensity / goal axes.

Endpoints mirror the vulnerable params already documented in
src/attacks/run_attacks.sh and config/sources.yaml, so benign and attack
traffic land on the SAME routes -> the classifier learns the PAYLOAD, not the
path.
"""
from dataclasses import dataclass, field

import attack_payloads as payloads

# (app, attack_type) -> endpoint spec.
# method/path/param describe the NATURAL injection point; the persona.vector
# axis may relocate the payload into body/header/cookie instead of `param`.
ENDPOINTS = {
    ("dvwa", "sqli"): {"method": "GET", "path": "/vulnerabilities/sqli/",
                       "param": "id", "extra": {"Submit": "Submit"}},
    ("dvwa", "xss"): {"method": "GET", "path": "/vulnerabilities/xss_r/", "param": "name"},
    ("dvwa", "command_injection"): {"method": "GET", "path": "/vulnerabilities/exec/",
                       "param": "ip", "extra": {"Submit": "Submit"}},

    # base_url already ends in /WebGoat -> paths here must be RELATIVE to it
    # (no leading /WebGoat), otherwise you get /WebGoat/WebGoat/... -> 404.
    ("webgoat", "sqli"): {"method": "POST", "path": "/SqlInjection/assignment5b",
                      "param": "userid", "extra": {"login_count": "1"}},
    ("webgoat", "xss"): {"method": "GET", "path": "/CrossSiteScripting/attack5a",
                     "param": "field1",
                     "extra": {"QTY1": "1", "QTY2": "1", "QTY3": "1", "QTY4": "1", "field2": "748474"}},

    ("juice_shop", "sqli"): {"method": "GET", "path": "/rest/products/search", "param": "q"},
    ("juice_shop", "xss"): {"method": "GET", "path": "/rest/products/search", "param": "q"},
    # HELD-OUT CWE-94: SSTI on the profile username field (Pug template).
    ("juice_shop", "code_injection"): {"method": "POST", "path": "/profile", "param": "username"},

    # bWAPP (2026-09-12): NEW held-out cross-app test target, replacing webgoat
    # in that role because it has real sqli + xss + command_injection - the
    # first cross-app source that can test all three known classes, not two.
    # MULTIPLE real endpoint variants per class (not one) - ground-truth
    # verified directly against the running container (login, form fields,
    # and the portal.php bug-select -> redirect mapping all confirmed live,
    # not guessed): covers GET/POST/select-tampering/blind-boolean/blind-time
    # for sqli, GET/POST/header-vector for xss. build_attack_steps() picks a
    # random variant PER PAYLOAD, so a single capture run naturally spreads
    # across real distinct injection contexts instead of hammering one page -
    # directly answers the "many forms of the same attack" diversity request.
    ("bwapp", "sqli"): [
        {"method": "GET", "path": "/sqli_1.php", "param": "title"},        # GET/Search
        {"method": "POST", "path": "/sqli_2.php", "param": "movie"},       # GET/Select UI, but POST-tamperable
        {"method": "POST", "path": "/sqli_6.php", "param": "title"},       # POST/Search
        {"method": "POST", "path": "/sqli_13.php", "param": "movie"},      # POST/Select
        {"method": "GET", "path": "/sqli_4.php", "param": "title"},        # Blind - Boolean-Based
        {"method": "GET", "path": "/sqli_15.php", "param": "title"},       # Blind - Time-Based
    ],
    ("bwapp", "xss"): [
        {"method": "GET", "path": "/xss_get.php", "param": "firstname",
         "extra": {"lastname": "test"}},                                   # Reflected GET
        {"method": "POST", "path": "/xss_post.php", "param": "firstname",
         "extra": {"lastname": "test"}},                                   # Reflected POST
        {"method": "GET", "path": "/xss_json.php", "param": "title"},      # Reflected JSON
        {"method": "GET", "path": "/xss_user_agent.php", "param": None,
         "force_vector": "header"},                                        # Reflected User-Agent - payload MUST go in the header, not a form field
    ],
    ("bwapp", "command_injection"): [
        {"method": "POST", "path": "/commandi.php", "param": "target"},
        {"method": "POST", "path": "/commandi_blind.php", "param": "target"},
    ],
    # Verified live 2026-09-18 against citizenstig/nowasp:latest, v2.6.62:
    # form method is POST (URL never changes on submit), field is
    # name="target_host" (page source even tags it
    # OSCommandInjectionPoint="1" - Mutillidae's own marker for this exact
    # injection point).
    #
    # value_prefix="127.0.0.1" - REQUIRED, found 2026-09-18 the hard way:
    # this page shells out to `nslookup $target_host` with NOTHING
    # prepended. Sending the raw payload alone (e.g. "| whoami") leaves
    # nslookup with ZERO arguments, and unlike ping (DVWA/bWAPP's command,
    # which just prints a usage error and exits), nslookup with no args
    # drops into an INTERACTIVE prompt and hangs forever waiting on stdin -
    # confirmed live (docker exec + ps aux caught two real stuck `nslookup`
    # processes, which then backed up Apache's whole worker pool and
    # timed out every subsequent request). Real attackers exploiting this
    # exact page always prepend a real-looking hostname first (confirmed
    # against a public walkthrough: "www.cnn.com;mkfifo ...") - this
    # prefix makes our traffic match that, and is the actual fix, not a
    # workaround.
    ("mutillidae", "command_injection"): [
        {"method": "POST", "path": "/index.php", "param": "target_host",
         "extra": {"page": "dns-lookup.php"}, "value_prefix": "127.0.0.1"},
    ],
}


@dataclass
class AttackStep:
    app: str
    attack_type: str
    method: str
    path: str
    param: str
    payload: str
    vector: str            # query|body|header|cookie
    variant_type: str      # original|encoded|mutated|polyglot
    parent_id: str
    payload_id: str
    extra_params: dict = field(default_factory=dict)
    value_prefix: str = ""


def endpoint_for(app: str, attack_type: str):
    """Returns a LIST of endpoint specs (normalizes the single-dict legacy
    entries used by dvwa/webgoat/juice_shop into a 1-element list, same shape
    as bwapp's multi-variant entries)."""
    spec = ENDPOINTS.get((app, attack_type))
    if spec is None:
        return []
    return spec if isinstance(spec, list) else [spec]


# Apps whose backend is confirmed Linux-only (checked live via `docker exec
# ps aux` - Apache/PHP on Linux, no cmd.exe/PowerShell). Windows-flavored
# command_injection payloads (payload_id prefix "win_") don't just "not
# work" against these - found live 2026-09-18 that they actively cause
# real hangs: e.g. `$(type C:\windows\win.ini)` evaluates to garbage text
# that becomes a SECOND positional argument to Mutillidae's `nslookup
# $target_host`, which nslookup then tries to contact as an alternate DNS
# SERVER, hanging/retrying for a long time. Excluding them per-app is both
# the safe fix and the more realistic one - a real attacker who's found a
# Linux target doesn't waste probes on Windows syntax either.
LINUX_ONLY_APPS = {"mutillidae"}


def build_attack_steps(persona, app: str, attack_type: str, rng) -> list:
    """Turn one attacker persona into a list of AttackStep for (app, attack_type).
    When multiple real endpoint variants exist for this (app, attack_type),
    a variant is chosen AT RANDOM PER PAYLOAD, so one capture run naturally
    spreads across distinct real injection contexts (GET/POST/select-
    tampering/blind/header) instead of repeating a single page."""
    specs = endpoint_for(app, attack_type)
    if not specs:
        return []

    bank = payloads.base_payloads(attack_type, persona.goal.value)
    if app in LINUX_ONLY_APPS:
        # Exclude by CONTENT, not just the "win_"-prefixed payload_ids -
        # the auto-generated gen_chain_N/gen_subshell_N entries also
        # contain "type C:\windows\win.ini" and "curl http://evil.example"
        # (found live 2026-09-18: both cause real hangs against
        # Mutillidae's nslookup-based endpoint, see LINUX_ONLY_APPS docstring
        # above), but their IDs don't start with "win_" so a prefix-only
        # filter would have missed 8 more of them.
        _risky = ("win.ini", "evil.example", "cmd.exe", "powershell")
        # ALSO exclude every $(...) / backtick command-substitution payload,
        # structurally, regardless of what's inside it - found live
        # 2026-09-18 (4th incident): `ps aux` substitutes its own
        # multi-word OUTPUT directly into the argument list, so
        # "nslookup 127.0.0.1`ps aux`" hands nslookup a dozen extra
        # positional arguments; nslookup treats the 2nd one as an
        # alternate DNS SERVER to query and hangs trying to reach it. This
        # happens for ANY successful substitution with whitespace in its
        # output (id/whoami/uname/ls/env/ps - nearly everything), not just
        # the two keyword-based cases above, so it needs a structural
        # exclusion, not another keyword.
        _subshell_markers = ("$" + "(", chr(96))  # chr(96) = backtick
        # REAL BUG found 2026-09-18 while testing: payload_id in the bank
        # is "{attack_type}-{goal}-{name}" (e.g.
        # "command_injection-exploit-win_ping_n"), which never STARTS WITH
        # "win_" - pid.startswith("win_") silently matched nothing, this
        # whole time, for every win_-prefixed entry that didn't ALSO
        # happen to trip the content/substitution checks below (win_ping_n,
        # win_semicolon_dir_c slipped through undetected). Check for
        # "-win_" as a substring instead - matches the real ID shape.
        # "%0a" as a literal separator (not a real decoded newline) is
        # ALSO structurally excluded: found live 2026-09-18 that
        # requests' own form-encoding re-encodes the "%" in our payload
        # text to "%25" on the wire, so PHP's single decode ALWAYS
        # produces literal "%0a" text, never a real newline - for every
        # app, not just Mutillidae. Harmless for DVWA/bWAPP (ping fails
        # cleanly on the resulting bad arg), but for Mutillidae the
        # literal space before the following command word creates the
        # same "2nd positional argument = DNS server" hang as everything
        # else above, regardless of which command follows.
        bank = [(pid, raw) for pid, raw in bank
                if "-win_" not in pid
                and "%0a" not in raw.lower()
                and not any(r in raw.lower() for r in _risky)
                and not any(m in raw for m in _subshell_markers)]
    if not bank:
        return []

    budget = persona.payload_budget()
    if len(bank) >= budget:
        chosen = rng.sample(bank, budget)
    else:
        chosen = [rng.choice(bank) for _ in range(budget)]

    steps = []
    for payload_id, raw_payload in chosen:
        spec = specs[rng.randrange(len(specs))]

        # A GET-only endpoint can't carry a body payload -> fall back to query.
        # An endpoint that forces a specific vector (e.g. xss_user_agent.php,
        # where the payload MUST be the User-Agent header, not a form field)
        # overrides whatever vector the persona would otherwise have chosen.
        vector = spec.get("force_vector") or persona.vector.value
        if vector == "body" and spec["method"] == "GET":
            vector = "query"

        variant_type, parent_id, transformed = payloads.apply_evasion(
            payload_id, raw_payload, persona.evasion.value, attack_type, rng
        )
        steps.append(AttackStep(
            app=app, attack_type=attack_type,
            method=spec["method"], path=spec["path"], param=spec["param"],
            payload=transformed, vector=vector,
            variant_type=variant_type, parent_id=parent_id, payload_id=payload_id,
            extra_params=dict(spec.get("extra", {})),
            value_prefix=spec.get("value_prefix", ""),
        ))
    return steps
