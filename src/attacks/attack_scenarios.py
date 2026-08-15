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
    ("dvwa", "path_traversal"): {"method": "GET", "path": "/vulnerabilities/fi/", "param": "page"},

    # base_url already ends in /WebGoat -> paths here must be RELATIVE to it
    # (no leading /WebGoat), otherwise you get /WebGoat/WebGoat/... -> 404.
    ("webgoat", "sqli"): {"method": "GET", "path": "/SqlInjection/attack", "param": "account"},
    ("webgoat", "xss"): {"method": "GET", "path": "/CrossSiteScripting/attack5a", "param": "field1"},
    ("webgoat", "path_traversal"): {"method": "GET", "path": "/PathTraversal", "param": "file"},

    ("juice_shop", "sqli"): {"method": "GET", "path": "/rest/products/search", "param": "q"},
    ("juice_shop", "xss"): {"method": "GET", "path": "/rest/products/search", "param": "q"},
    # HELD-OUT CWE-94: SSTI on the profile username field (Pug template).
    ("juice_shop", "code_injection"): {"method": "POST", "path": "/profile", "param": "username"},
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


def endpoint_for(app: str, attack_type: str):
    return ENDPOINTS.get((app, attack_type))


def build_attack_steps(persona, app: str, attack_type: str, rng) -> list:
    """Turn one attacker persona into a list of AttackStep for (app, attack_type)."""
    spec = endpoint_for(app, attack_type)
    if not spec:
        return []

    bank = payloads.base_payloads(attack_type, persona.goal.value)
    if not bank:
        return []

    budget = persona.payload_budget()
    if len(bank) >= budget:
        chosen = rng.sample(bank, budget)
    else:
        chosen = [rng.choice(bank) for _ in range(budget)]

    # A GET-only endpoint can't carry a body payload -> fall back to query.
    vector = persona.vector.value
    if vector == "body" and spec["method"] == "GET":
        vector = "query"

    steps = []
    for payload_id, raw_payload in chosen:
        variant_type, parent_id, transformed = payloads.apply_evasion(
            payload_id, raw_payload, persona.evasion.value, attack_type, rng
        )
        steps.append(AttackStep(
            app=app, attack_type=attack_type,
            method=spec["method"], path=spec["path"], param=spec["param"],
            payload=transformed, vector=vector,
            variant_type=variant_type, parent_id=parent_id, payload_id=payload_id,
            extra_params=dict(spec.get("extra", {})),
        ))
    return steps
