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


def dispatch(name: str, ctx: ActionContext, args: dict[str, Any]) -> Result:
    """Run the registered handler for `name`, or a no-op Result if unknown or disabled."""
    fn = ACTIONS.get(name)
    if fn is None:
        ctx.log(f"[{ctx.step}] unknown action '{name}' ignored")
        return Result(observation=f"unknown action '{name}'")
    toggle = _ATTACK_TOGGLE.get(name)
    if toggle is not None:
        s = ctx.settings.get("scanner", {})
        attacks = s.get("attacks", {})
        if attacks.get(toggle, True) is False or (s.get("safe_mode") and toggle in _SAFE_MODE_OFF):
            msg = f"{name} is disabled by config (scanner.attacks.{toggle} / safe_mode)."
            ctx.log(f"[{ctx.step}] {msg}")
            return Result(observation=msg, blocked=True)
    return fn(ctx, args or {})


from . import graphql as _graphql      # noqa: E402,F401
from . import recon as _recon          # noqa: E402,F401
from . import arsenal as _arsenal      # noqa: E402,F401
from . import fuzz as _fuzz            # noqa: E402,F401
from . import authmatrix as _authmatrix  # noqa: E402,F401

__all__ = ["ACTIONS", "action", "dispatch", "ActionContext", "Result"]
