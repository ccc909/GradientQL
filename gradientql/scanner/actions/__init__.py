"""The action registry."""

from __future__ import annotations

import logging
from typing import Any, Callable

from .context import ActionContext, Result

logger = logging.getLogger("gradientql.scanner")

Handler = Callable[[ActionContext, dict], Result]
ACTIONS: dict[str, Handler] = {}


def action(name: str) -> Callable[[Handler], Handler]:
    """Decorator registering a handler under `name` in the global ACTIONS table."""
    def _register(fn: Handler) -> Handler:
        ACTIONS[name] = fn
        return fn
    return _register


_ATTACK_TOGGLE = {
    "dos": "dos", "smuggle": "smuggle", "csrf": "csrf",
    "forge_jwt": "jwt", "batch_brute": "brute", "auth_test": "bola",
}
_SAFE_MODE_OFF = ("dos", "smuggle", "brute")
# Toggles default ON; dos defaults OFF (matches the shipped config: it can knock a target over).
_ATTACK_DEFAULT_OFF = ("dos",)


def _toggle_off(settings: dict[str, Any], toggle: str) -> bool:
    s = settings.get("scanner", {})
    attacks = s.get("attacks", {})
    default = toggle not in _ATTACK_DEFAULT_OFF
    return attacks.get(toggle, default) is False or (bool(s.get("safe_mode")) and toggle in _SAFE_MODE_OFF)


def disabled_actions(settings: dict[str, Any]) -> set[str]:
    """Action names turned off by scanner.attacks / safe_mode (e.g. {'dos', 'smuggle'})."""
    return {name for name, toggle in _ATTACK_TOGGLE.items() if _toggle_off(settings, toggle)}


def disabled_toggles(settings: dict[str, Any]) -> set[str]:
    """The disabled toggle keys themselves (e.g. {'dos', 'brute'}), for nudge filtering."""
    return {toggle for _, toggle in _ATTACK_TOGGLE.items() if _toggle_off(settings, toggle)}


def dispatch(name: str, ctx: ActionContext, args: dict[str, Any]) -> Result:
    """Run the registered handler for `name`, or a no-op Result if unknown or disabled."""
    fn = ACTIONS.get(name)
    if fn is None:
        ctx.log(f"[{ctx.step}] unknown action '{name}' ignored")
        return Result(observation=f"unknown action '{name}'")
    toggle = _ATTACK_TOGGLE.get(name)
    if toggle is not None and _toggle_off(ctx.settings, toggle):
        msg = f"{name} is disabled by config (scanner.attacks.{toggle} / safe_mode)."
        ctx.log(f"[{ctx.step}] {msg}")
        return Result(observation=msg, blocked=True, config_blocked=True)
    return fn(ctx, args or {})


from . import graphql as _graphql      # noqa: E402,F401
from . import recon as _recon          # noqa: E402,F401
from . import arsenal as _arsenal      # noqa: E402,F401
from . import fuzz as _fuzz            # noqa: E402,F401
from . import authmatrix as _authmatrix  # noqa: E402,F401

__all__ = ["ACTIONS", "action", "dispatch", "disabled_actions", "disabled_toggles",
           "ActionContext", "Result"]
