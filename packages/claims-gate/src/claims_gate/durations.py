"""Range checks for the proxy's duration settings (seconds).

Every duration needs a finite *upper* bound, not only "finite": a huge finite
value (``1e300``, ``9e18``) behaves exactly like ``inf``. An introspection cache
entry then lives until token ``exp`` (revocation never applies at the proxy), a
JWKS is never refreshed, and an escalation approval or deny never expires.
The maxima themselves live next to the setting they bound.
"""

from __future__ import annotations

import math


def duration_error(what: str, value: float, *, maximum: float, allow_zero: bool = False) -> str | None:
    """``None`` if ``value`` is a finite number in ``[0, maximum]`` (or ``(0, maximum]``), else the error text."""
    low_ok = value >= 0 if allow_zero else value > 0
    if math.isfinite(value) and low_ok and value <= maximum:
        return None
    return f"{what} must be a finite number in {'[' if allow_zero else '('}0, {maximum}] seconds (got {value})"
