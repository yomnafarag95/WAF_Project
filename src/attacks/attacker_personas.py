"""
Attacker personas - attack-traffic generation (parallel to personas/configs.py).
=================================================================================
Built on the SAME philosophy as the 6 benign personas:
  - a small set of ORTHOGONAL axes, where each axis changes something
    OBSERVABLE in the captured raw HTTP request (or in the features that
    src/features/extract_features.py derives from it);
  - a handful of personas chosen as a SPREAD across that axis-space (NOT the
    full cartesian product), exactly like the benign personas cover the
    corners of speed x goal x device x auth.

GUIDING RULE (why these axes earn their place). An axis only counts if it
moves the captured request or a real feature:
    Evasion   -> payload bytes, encoded_char_ratio, special_char_ratio
    Vector    -> WHERE the payload sits (query/body/header/cookie) in raw_request
    Intensity -> number/complexity of requests per session
    Rate      -> inter_arrival_ms, request_rate_window (timing features)
    Goal      -> which payload FAMILY is used (recon/exploit/exfiltration)
    Tooling   -> automated fuzzing shape vs deliberate manual replay

SEPARATION OF CONCERNS (mirrors benign PersonaConfig / SessionRunner / Jitter):
    Persona  = attacker POLICY  -> emitted as X-Capture-Persona=<persona_id>
    Scenario = concrete execution for (attack_type, app, endpoint)
               -> attack_scenarios.py, emitted as X-Capture-Scenario
    Variant  = obfuscation transform applied to a base payload
               -> attack_payloads.py, emitted as X-Capture-Variant + -Parent
"""

from dataclasses import dataclass
from enum import Enum


class Tooling(str, Enum):
    AUTOMATED = "automated"          # tool-style: many payloads, fuzzing shape
    MANUAL_REPLAY = "manual_replay"  # few, hand-picked, deliberate payloads


class Evasion(str, Enum):
    NONE = "none"          # raw payloads, no obfuscation
    ENCODED = "encoded"    # URL / double-URL encoding
    MUTATED = "mutated"    # case-swap, inline comments, whitespace tricks
    POLYGLOT = "polyglot"  # context-breaking multi-context payloads


class Vector(str, Enum):
    QUERY = "query"    # payload in the URL query string  (GET ?p=...)
    BODY = "body"      # payload in the request body       (POST form/json)
    HEADER = "header"  # payload in a request header        (e.g. User-Agent)
    COOKIE = "cookie"  # payload in a cookie value


class Intensity(str, Enum):
    LOW = "low"        # few payloads per scenario
    MEDIUM = "medium"
    HIGH = "high"      # many payloads per scenario


class Rate(str, Enum):
    BURST = "burst"          # fast, no think-time (noisy scanner)
    THROTTLED = "throttled"  # slow, human-like delays (low & slow)


class Goal(str, Enum):
    RECON = "recon"                # light probing / detection payloads
    EXPLOIT = "exploit"            # weaponised payloads
    EXFILTRATION = "exfiltration"  # data-extraction payloads (UNION dumps, deep traversal)


@dataclass(frozen=True)
class RatePolicy:
    """Delay range between attack requests, in milliseconds."""
    min_delay_ms: int
    max_delay_ms: int


@dataclass(frozen=True)
class AttackerPersona:
    persona_id: str
    persona_name: str
    tooling: Tooling
    evasion: Evasion
    vector: Vector
    intensity: Intensity
    rate: Rate
    goal: Goal
    rate_policy: RatePolicy

    def payload_budget(self) -> int:
        """How many base payloads this persona fires per scenario."""
        return {Intensity.LOW: 4, Intensity.MEDIUM: 10, Intensity.HIGH: 22}[self.intensity]

    def to_dict(self) -> dict:
        """For X-Capture-Persona metadata / auditing."""
        return {
            "persona_id": self.persona_id,
            "persona_name": self.persona_name,
            "tooling": self.tooling.value,
            "evasion": self.evasion.value,
            "vector": self.vector.value,
            "intensity": self.intensity.value,
            "rate": self.rate.value,
            "goal": self.goal.value,
        }


# ---------------------------------------------------------------------------
# The 6 attacker personas - a deliberate SPREAD across the axis-space.
# Each one differs from the others on MULTIPLE axes (no near-duplicates).
# ---------------------------------------------------------------------------
ATTACKER_PERSONAS: dict[str, AttackerPersona] = {

    "noisy_automated_scanner": AttackerPersona(
        persona_id="noisy_automated_scanner",
        persona_name="Noisy Automated Scanner",
        tooling=Tooling.AUTOMATED, evasion=Evasion.NONE, vector=Vector.QUERY,
        intensity=Intensity.HIGH, rate=Rate.BURST, goal=Goal.EXPLOIT,
        rate_policy=RatePolicy(20, 120),
    ),

    "evasive_encoder": AttackerPersona(
        persona_id="evasive_encoder",
        persona_name="Evasive Encoder (WAF bypass)",
        tooling=Tooling.AUTOMATED, evasion=Evasion.ENCODED, vector=Vector.QUERY,
        intensity=Intensity.MEDIUM, rate=Rate.THROTTLED, goal=Goal.EXPLOIT,
        rate_policy=RatePolicy(600, 2200),
    ),

    "manual_stealth": AttackerPersona(
        persona_id="manual_stealth",
        persona_name="Manual Stealth (low & slow)",
        tooling=Tooling.MANUAL_REPLAY, evasion=Evasion.MUTATED, vector=Vector.BODY,
        intensity=Intensity.LOW, rate=Rate.THROTTLED, goal=Goal.RECON,
        rate_policy=RatePolicy(1500, 4000),
    ),

    "polyglot_specialist": AttackerPersona(
        persona_id="polyglot_specialist",
        persona_name="Polyglot Specialist (odd injection points)",
        tooling=Tooling.MANUAL_REPLAY, evasion=Evasion.POLYGLOT, vector=Vector.HEADER,
        intensity=Intensity.MEDIUM, rate=Rate.THROTTLED, goal=Goal.EXPLOIT,
        rate_policy=RatePolicy(800, 2500),
    ),

    "exfiltration_operator": AttackerPersona(
        persona_id="exfiltration_operator",
        persona_name="Exfiltration Operator",
        tooling=Tooling.AUTOMATED, evasion=Evasion.MUTATED, vector=Vector.QUERY,
        intensity=Intensity.HIGH, rate=Rate.BURST, goal=Goal.EXFILTRATION,
        rate_policy=RatePolicy(30, 150),
    ),

    "script_kiddie_defaults": AttackerPersona(
        persona_id="script_kiddie_defaults",
        persona_name="Script Kiddie (copy-paste defaults)",
        tooling=Tooling.AUTOMATED, evasion=Evasion.NONE, vector=Vector.COOKIE,
        intensity=Intensity.LOW, rate=Rate.BURST, goal=Goal.RECON,
        rate_policy=RatePolicy(50, 300),
    ),
}


def get_attacker_persona(persona_id: str) -> AttackerPersona:
    if persona_id not in ATTACKER_PERSONAS:
        raise KeyError(
            f"Attacker persona '{persona_id}' not found. "
            f"Available: {list(ATTACKER_PERSONAS)}"
        )
    return ATTACKER_PERSONAS[persona_id]


def list_attacker_personas() -> list:
    return list(ATTACKER_PERSONAS.keys())


if __name__ == "__main__":
    print(f"Attacker personas: {len(ATTACKER_PERSONAS)}\n")
    for pid, p in ATTACKER_PERSONAS.items():
        print(f"- {p.persona_name}")
        print(f"  tooling={p.tooling.value} evasion={p.evasion.value} "
              f"vector={p.vector.value} intensity={p.intensity.value} "
              f"rate={p.rate.value} goal={p.goal.value} "
              f"budget={p.payload_budget()} "
              f"delay={p.rate_policy.min_delay_ms}-{p.rate_policy.max_delay_ms}ms")
