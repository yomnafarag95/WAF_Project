"""
Delay sampling and step-decision engine for persona-driven benign sessions.

Extracted from the original persona_executor.py. Kept free of any HTTP or
schema concerns on purpose: this module only decides TIMING and BEHAVIOR
(skip, backtrack, revisit, abandon). Actual request capture happens on the
wire via the shared mitmproxy addon (src/capture/capture_addon.py), so the
same schema_v2 record shape is guaranteed for benign and attack traffic.
"""

import random
from dataclasses import dataclass
from typing import Optional

from .configs import PersonaConfig, JitterPolicy


class DelaySampler:
    """
    Converts speed_profile plus jitter.delay_variance_pct into an actual
    delay in milliseconds. Uses an approximate normal distribution instead
    of uniform, to mimic human behavior: most values cluster near the
    mean, with rare tails at the extremes.
    """

    def __init__(self, persona: PersonaConfig, seed: Optional[int] = None):
        self.persona = persona
        self._rng = random.Random(seed)

    def sample_delay_ms(self) -> int:
        profile = self.persona.speed_profile
        base_mean = (profile.min_delay_ms + profile.max_delay_ms) / 2
        base_std = (profile.max_delay_ms - profile.min_delay_ms) / 4

        variance_factor = 1 + (self.persona.jitter.delay_variance_pct / 100)
        std = base_std * variance_factor

        delay = self._rng.gauss(base_mean, std)
        delay = max(profile.min_delay_ms * 0.5, min(delay, profile.max_delay_ms * 2))
        return int(delay)


@dataclass
class StepDecision:
    skip: bool = False
    backtrack: bool = False
    revisit: bool = False
    abandon: bool = False


class StepDecisionEngine:
    """
    Decides, per scenario step, whether to skip, backtrack, revisit an
    earlier page, or abandon the session entirely. Each decision is an
    independent Bernoulli trial based on the probabilities in JitterPolicy.
    """

    def __init__(self, jitter: JitterPolicy, seed: Optional[int] = None):
        self.jitter = jitter
        self._rng = random.Random(seed)

    def decide(self) -> StepDecision:
        return StepDecision(
            skip=self._rng.random() < self.jitter.skip_optional_step_prob,
            backtrack=self._rng.random() < self.jitter.backtrack_prob,
            revisit=self._rng.random() < self.jitter.revisit_page_prob,
            abandon=self._rng.random() < self.jitter.abandon_session_prob,
        )
