"""
SessionRunner - drives one persona session through a scenario.

FIX (vs. original persona_executor.py): the original built its own
EventLogger and wrote a DIFFERENT record schema (schema_version 1.0.0,
fields like sample_id / label_level_1 / label_level_2) than the project's
locked schema_v2.json (schema_version 2.0: metadata / content /
features_aux / variant / label). That fork would produce two incompatible
raw formats for benign traffic and break extract_features.py and
test_schema.py, which only understand schema_v2.

The fix: SessionRunner no longer builds or writes any record. It only
decides WHEN actions happen (delay, skip, backtrack, revisit, abandon).
The actual HTTP capture is done once, on the wire, by the shared mitmproxy
addon (src/capture/capture_addon.py) - the same addon used by the existing
benign_driver.py (WebGoat/DVWA) and run_attacks.sh. One source of truth
for the raw schema.
"""

import random
from dataclasses import dataclass
from typing import Callable, Optional

from .configs import PersonaConfig
from .decision_engine import DelaySampler, StepDecisionEngine


@dataclass
class ScenarioStep:
    """One step in a scenario. optional=True means it can be skipped."""
    step_id: str
    action: Callable[["SessionRunner"], None]
    optional: bool = False


class SessionRunner:
    """
    Drives one full session for a persona:
    - walks the scenario steps in order
    - applies a delay before each step
    - applies StepDecisionEngine decisions (skip/backtrack/revisit/abandon)
    - never touches the network or the output schema (see module docstring)
    """

    def __init__(
        self,
        persona: PersonaConfig,
        session_id: str,
        run_id: str,
        seed: Optional[int] = None,
    ):
        self.persona = persona
        self.session_id = session_id
        self.run_id = run_id

        self.delay_sampler = DelaySampler(persona, seed=seed)
        self.decision_engine = StepDecisionEngine(persona.jitter, seed=seed)

        # Dedicated RNG for revisit/backtrack choices. Reuses the same seed
        # so a full session stays deterministic and reproducible if we ever
        # need to replay a specific scenario.
        self._rng = random.Random(seed)

        self._visited_steps: list = []

    def run_scenario(
        self,
        scenario_id: str,
        scenario_name: str,
        steps: list,
        sleep_fn: Callable[[float], None] = lambda ms: None,
    ) -> None:
        """
        sleep_fn: the actual sleep function (time.sleep or Playwright
        page.wait_for_timeout). Defaults to a no-op so this stays
        unit-testable without a real wait.
        """
        for step in steps:
            decision = self.decision_engine.decide()

            if decision.abandon:
                # Session closed abruptly - normal human behavior.
                break

            if step.optional and decision.skip:
                continue

            delay_ms = self.delay_sampler.sample_delay_ms()
            sleep_fn(delay_ms / 1000)

            step.action(self)
            self._visited_steps.append(step)

            if decision.revisit and self._visited_steps:
                revisit_target = self._rng.choice(self._visited_steps)
                sleep_fn(self.delay_sampler.sample_delay_ms() / 1000)
                revisit_target.action(self)

            if decision.backtrack and len(self._visited_steps) > 1:
                # Simulates the browser back button.
                sleep_fn(self.delay_sampler.sample_delay_ms() / 1000)
                self._visited_steps[-2].action(self)
