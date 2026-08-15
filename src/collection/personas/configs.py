"""
Persona configurations - benign traffic generation (Juice Shop).
==================================================================
6 personas built on 4 core axes (Speed, Goal, Auth state, Device)
+ Depth/Patience as secondary axes.

Each persona = a baseline behavior policy.
Each jitter = execution-time randomness, kept separate from the policy itself.

FIX (vs. original persona_configs.py): no functional bug found here; only
moved into the `personas` package so imports are consistent with the rest
of the collection pipeline (see session_runner.py / juice_shop_actions.py).
"""

from dataclasses import dataclass
from enum import Enum


class Speed(str, Enum):
    FAST = "fast"
    MODERATE = "moderate"
    CAREFUL = "careful"


class Goal(str, Enum):
    BUY = "buy"
    COMPARE = "compare"
    BROWSE = "browse"
    SEARCH = "search"


class Device(str, Enum):
    DESKTOP = "desktop"
    MOBILE = "mobile"


class AuthState(str, Enum):
    GUEST = "guest"
    LOGGED_IN = "logged_in"


class Depth(str, Enum):
    SHALLOW = "shallow"
    DEEP = "deep"


class Patience(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True)
class SpeedProfile:
    """Delay range between requests, in milliseconds."""
    min_delay_ms: int
    max_delay_ms: int


@dataclass(frozen=True)
class JitterPolicy:
    """
    Human jitter - randomness inside the same persona so behavior does not
    look robotic even if the same persona runs across many sessions.
    """
    delay_variance_pct: float          # extra variance on top of speed_profile
    skip_optional_step_prob: float     # probability of skipping an optional step
    backtrack_prob: float              # probability of going back (browser back)
    revisit_page_prob: float           # probability of revisiting an already-seen page
    abandon_session_prob: float        # probability of abandoning the session early (tied to Patience)


@dataclass(frozen=True)
class PersonaConfig:
    persona_id: str
    persona_name: str
    goal: Goal
    speed: Speed
    speed_profile: SpeedProfile
    device: Device
    auth_state: AuthState
    depth: Depth
    patience: Patience
    jitter: JitterPolicy

    def to_dict(self) -> dict:
        """For direct use when writing X-Capture-Persona metadata."""
        return {
            "persona_id": self.persona_id,
            "persona_name": self.persona_name,
            "goal": self.goal.value,
            "speed": self.speed.value,
            "device": self.device.value,
            "auth_state": self.auth_state.value,
            "depth": self.depth.value,
            "patience": self.patience.value,
        }


# ---------------------------------------------------------------------------
# The 6 base personas
# ---------------------------------------------------------------------------

PERSONAS: dict[str, PersonaConfig] = {

    "fast_buyer_guest_desktop": PersonaConfig(
        persona_id="fast_buyer_guest_desktop",
        persona_name="Fast Buyer - Guest - Desktop",
        goal=Goal.BUY,
        speed=Speed.FAST,
        speed_profile=SpeedProfile(min_delay_ms=300, max_delay_ms=900),
        device=Device.DESKTOP,
        auth_state=AuthState.GUEST,
        depth=Depth.SHALLOW,
        patience=Patience.LOW,
        jitter=JitterPolicy(
            delay_variance_pct=20,
            skip_optional_step_prob=0.30,
            backtrack_prob=0.05,
            revisit_page_prob=0.05,
            abandon_session_prob=0.10,
        ),
    ),

    "careful_comparer_auth_desktop": PersonaConfig(
        persona_id="careful_comparer_auth_desktop",
        persona_name="Careful Comparer - Logged-in - Desktop",
        goal=Goal.COMPARE,
        speed=Speed.CAREFUL,
        speed_profile=SpeedProfile(min_delay_ms=1200, max_delay_ms=3500),
        device=Device.DESKTOP,
        auth_state=AuthState.LOGGED_IN,
        depth=Depth.DEEP,
        patience=Patience.HIGH,
        jitter=JitterPolicy(
            delay_variance_pct=35,
            skip_optional_step_prob=0.05,
            backtrack_prob=0.25,
            revisit_page_prob=0.30,
            abandon_session_prob=0.02,
        ),
    ),

    "moderate_browser_guest_mobile": PersonaConfig(
        persona_id="moderate_browser_guest_mobile",
        persona_name="Moderate Browser - Guest - Mobile",
        goal=Goal.BROWSE,
        speed=Speed.MODERATE,
        speed_profile=SpeedProfile(min_delay_ms=700, max_delay_ms=2000),
        device=Device.MOBILE,
        auth_state=AuthState.GUEST,
        depth=Depth.DEEP,
        patience=Patience.MEDIUM,
        jitter=JitterPolicy(
            delay_variance_pct=25,
            skip_optional_step_prob=0.15,
            backtrack_prob=0.15,
            revisit_page_prob=0.20,
            abandon_session_prob=0.15,
        ),
    ),

    "fast_searcher_auth_mobile": PersonaConfig(
        persona_id="fast_searcher_auth_mobile",
        persona_name="Fast Searcher - Logged-in - Mobile",
        goal=Goal.SEARCH,
        speed=Speed.FAST,
        speed_profile=SpeedProfile(min_delay_ms=250, max_delay_ms=800),
        device=Device.MOBILE,
        auth_state=AuthState.LOGGED_IN,
        depth=Depth.SHALLOW,
        patience=Patience.LOW,
        jitter=JitterPolicy(
            delay_variance_pct=20,
            skip_optional_step_prob=0.25,
            backtrack_prob=0.10,
            revisit_page_prob=0.05,
            abandon_session_prob=0.12,
        ),
    ),

    "careful_browser_guest_desktop": PersonaConfig(
        persona_id="careful_browser_guest_desktop",
        persona_name="Careful Browser - Guest - Desktop",
        goal=Goal.BROWSE,
        speed=Speed.CAREFUL,
        speed_profile=SpeedProfile(min_delay_ms=1500, max_delay_ms=4000),
        device=Device.DESKTOP,
        auth_state=AuthState.GUEST,
        depth=Depth.DEEP,
        patience=Patience.HIGH,
        jitter=JitterPolicy(
            delay_variance_pct=30,
            skip_optional_step_prob=0.10,
            backtrack_prob=0.20,
            revisit_page_prob=0.25,
            abandon_session_prob=0.03,
        ),
    ),

    "moderate_buyer_auth_mobile": PersonaConfig(
        persona_id="moderate_buyer_auth_mobile",
        persona_name="Moderate Buyer - Logged-in - Mobile",
        goal=Goal.BUY,
        speed=Speed.MODERATE,
        speed_profile=SpeedProfile(min_delay_ms=600, max_delay_ms=1800),
        device=Device.MOBILE,
        auth_state=AuthState.LOGGED_IN,
        depth=Depth.SHALLOW,
        patience=Patience.MEDIUM,
        jitter=JitterPolicy(
            delay_variance_pct=25,
            skip_optional_step_prob=0.15,
            backtrack_prob=0.10,
            revisit_page_prob=0.10,
            abandon_session_prob=0.08,
        ),
    ),
}


def get_persona(persona_id: str) -> PersonaConfig:
    """Look up a persona by id, with a clear error if it does not exist."""
    if persona_id not in PERSONAS:
        raise KeyError(
            f"Persona '{persona_id}' not found. "
            f"Available: {list(PERSONAS.keys())}"
        )
    return PERSONAS[persona_id]


def list_personas() -> list[str]:
    return list(PERSONAS.keys())


if __name__ == "__main__":
    print(f"Personas: {len(PERSONAS)}\n")
    for pid, config in PERSONAS.items():
        print(f"- {config.persona_name}")
        print(f"  goal={config.goal.value} speed={config.speed.value} "
              f"device={config.device.value} auth={config.auth_state.value} "
              f"depth={config.depth.value} patience={config.patience.value}")
        print(f"  delay range: {config.speed_profile.min_delay_ms}-"
              f"{config.speed_profile.max_delay_ms}ms | "
              f"jitter variance: {config.jitter.delay_variance_pct}%")
        print()
