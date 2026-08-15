"""
Scenarios - benign traffic generation (Juice Shop).

Each scenario is a coherent journey aligned with a persona goal:
  buy     -> quick, direct purchase path
  compare -> view A, go back, view B, go back, view C (lots of back-nav)
  browse  -> deep, unhurried exploration
  search  -> targeted search then maybe open a result

DESIGN DECISIONS:
- `compare` and `browse` are now DISTINCT (they used to share one builder).
  compare = product-vs-product with browser-back between them; browse =
  wide catalog exploration. Distinct goals produce distinct URL + timing
  signatures, which is exactly the benign diversity the classifier needs.
- Login for logged-in personas is handled here, in one place, and degrades
  GRACEFULLY to a guest journey if no credentials are supplied (a missing
  password must never crash a whole generation run).

Imports resolve inside the `personas` package (relative), not the old
absolute `src.execution.*` paths.
"""

import logging

from .session_runner import ScenarioStep
from .configs import PersonaConfig, AuthState
from . import juice_shop_actions as actions

log = logging.getLogger(__name__)


def build_quick_buy_scenario(page) -> list:
    """goal=buy: short, direct - view a product, add to cart, view cart."""
    return [
        ScenarioStep("view_product", lambda r: actions.view_product_details(page), optional=False),
        ScenarioStep("add_to_cart", lambda r: actions.add_to_cart(page), optional=False),
        ScenarioStep("view_cart", lambda r: actions.view_cart(page), optional=True),
    ]


def build_compare_scenario(page) -> list:
    """goal=compare: A -> back -> B -> back -> C, then maybe add the winner.

    Heavy on browser-back navigation, which is the behavioral fingerprint of
    a shopper comparing options. The revisit/backtrack jitter in the persona
    adds even more of this on top.
    """
    return [
        ScenarioStep("browse_products", lambda r: actions.browse_products(page), optional=False),
        ScenarioStep("view_product_A", lambda r: actions.view_product_details(page), optional=False),
        ScenarioStep("back_to_catalog_1", lambda r: actions.go_back(page), optional=False),
        ScenarioStep("view_product_B", lambda r: actions.view_product_details(page), optional=False),
        ScenarioStep("back_to_catalog_2", lambda r: actions.go_back(page), optional=True),
        ScenarioStep("view_product_C", lambda r: actions.view_product_details(page), optional=True),
        ScenarioStep("add_winner_to_cart", lambda r: actions.add_to_cart(page), optional=True),
    ]


def build_browse_scenario(page) -> list:
    """goal=browse: wide, unhurried catalog exploration, no purchase intent."""
    return [
        ScenarioStep("browse_products_1", lambda r: actions.browse_products(page), optional=False),
        ScenarioStep("view_product_1", lambda r: actions.view_product_details(page), optional=False),
        ScenarioStep("browse_products_2", lambda r: actions.browse_products(page), optional=True),
        ScenarioStep("view_product_2", lambda r: actions.view_product_details(page), optional=True),
        ScenarioStep("view_product_3", lambda r: actions.view_product_details(page), optional=True),
    ]


def build_search_only_scenario(page, query: str = "juice") -> list:
    """goal=search: direct search for a specific product."""
    return [
        ScenarioStep("search_products", lambda r: actions.search_products(page, query=query), optional=False),
        ScenarioStep("view_search_result", lambda r: actions.view_product_details(page), optional=True),
    ]


# Map goal -> scenario builder. compare and browse are now distinct.
SCENARIO_BUILDERS = {
    "buy": build_quick_buy_scenario,
    "compare": build_compare_scenario,
    "browse": build_browse_scenario,
    "search": build_search_only_scenario,
}


def build_scenario_for_persona(
    persona: PersonaConfig,
    page,
    email: str = None,
    password: str = None,
) -> list:
    """
    Compose the full step list for a persona:
    - logged-in personas get a login step prepended IF credentials exist
    - if a logged-in persona has no credentials, we log a warning and fall
      back to a guest journey instead of crashing the run
    - then the goal-specific journey is appended
    """
    steps: list = []
    if persona.auth_state == AuthState.LOGGED_IN:
        if email and password:
            steps.append(
                ScenarioStep("login", lambda r: actions.login(page, email=email, password=password), optional=False)
            )
        else:
            log.warning(
                "Persona '%s' is logged_in but no credentials were provided; "
                "running it as a guest for this session.",
                persona.persona_id,
            )
    goal_builder = SCENARIO_BUILDERS[persona.goal.value]
    steps.extend(goal_builder(page))
    return steps
