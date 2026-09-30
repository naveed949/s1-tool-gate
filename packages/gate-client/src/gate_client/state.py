"""Build the System-1 state: granted policy, tool, redacted args, short context."""

from __future__ import annotations

import math
import re
from collections.abc import Mapping
from typing import Any

# Match secret-like key segments. ``auth`` matches ``auth`` but not ``author``.
_SENSITIVE_KEY = re.compile(
    r"(^|[_-])(password|passwd|secret|token|api[_-]?key|authorization|authentication|"
    r"credential|cookie|session|private[_-]?key|access[_-]?key|bearer|auth)([_-]|$)",
    re.IGNORECASE,
)

MAX_CONTEXT_CHARS = 2000
_REDACTED = "[REDACTED]"


def is_sensitive_key(key: str) -> bool:
    return _SENSITIVE_KEY.search(key) is not None


def redact_args(value: Any) -> Any:
    """Return a copy of tool arguments with secret-like values removed."""
    return _redact(value)


def build_state(*, policy: str, tool_name: str, args: Mapping[str, Any], context: str) -> dict[str, Any]:
    """State object sent to ``TypeSafeClient.system_one``."""
    return {
        "granted_policy": policy,
        "tool_name": tool_name,
        "args": redact_args(args),
        "context": _short_context(context),
    }


def _short_context(context: str) -> str:
    if len(context) <= MAX_CONTEXT_CHARS:
        return context
    return context[: MAX_CONTEXT_CHARS - 1] + "…"


def _redact(value: Any) -> Any:
    if isinstance(value, Mapping):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            name = str(key)
            if is_sensitive_key(name):
                redacted[name] = _REDACTED
            else:
                redacted[name] = _redact(item)
        return redacted
    if isinstance(value, (list, tuple)):
        return [_redact(item) for item in value]
    return _json_safe(value)


def _json_safe(value: Any) -> Any:
    if value is None or isinstance(value, str | bool):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            return None
        return value
    return str(value)
