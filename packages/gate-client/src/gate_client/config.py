"""Local Ollama settings for the TypeSafe Python SDK.

The SDK's own default base URL is TypeSafe cloud (``https://api.typesafe.ai``).
This gate never leaves ``base_url`` unset on the client. Unset configuration
is wired to local Ollama. A base URL on a TypeSafe cloud host is refused
unless ``GATE_ALLOW_TYPESAFE_CLOUD`` is set.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import urlparse

from typesafe_sdk.constants import API_KEY_ENV, BASE_URL_ENV, DEFAULT_BASE_URL, DEFAULT_MODEL_ENV

from gate_client.decision import ReasonCode

# Required local SDK target. Ollama 0.35 or newer serves Nimble on this API.
LOCAL_BASE_URL = "http://localhost:11434"
LOCAL_API_KEY = "ollama"
LOCAL_MODEL = "nimble"
MIN_OLLAMA_VERSION = "0.35"

CLOUD_OPT_IN_ENV = "GATE_ALLOW_TYPESAFE_CLOUD"
CONFIDENCE_THRESHOLD_ENV = "GATE_CONFIDENCE_THRESHOLD"
TIMEOUT_ENV = "GATE_TIMEOUT_SECONDS"

DEFAULT_CONFIDENCE_THRESHOLD = 0.5
DEFAULT_TIMEOUT_SECONDS = 30.0

_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})


@dataclass(frozen=True, slots=True)
class SdkSettings:
    """Values passed explicitly into ``TypeSafeClient``."""

    base_url: str
    api_key: str
    model: str
    timeout_seconds: float
    confidence_threshold: float
    allow_typesafe_cloud: bool


@dataclass(frozen=True, slots=True)
class ConfigFailure:
    """Configuration that must deny before any SDK call."""

    reason_code: ReasonCode


def is_typesafe_cloud(base_url: str) -> bool:
    """True when ``base_url`` targets hosted TypeSafe rather than local Ollama."""
    parsed = urlparse(base_url.strip())
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        return False
    if host == "typesafe.ai" or host.endswith(".typesafe.ai"):
        return True
    default_host = (urlparse(DEFAULT_BASE_URL).hostname or "").lower()
    return bool(default_host) and host == default_host


def _nonblank(env: Mapping[str, str], name: str) -> str | None:
    raw = env.get(name)
    if raw is None:
        return None
    stripped = raw.strip()
    if not stripped:
        return None
    return stripped


def _truthy(value: str | None) -> bool:
    return value is not None and value.strip().lower() in _TRUE_VALUES


def _parse_float(raw: str) -> float | None:
    try:
        return float(raw)
    except ValueError:
        return None


def _http_base_url(base_url: str) -> str | None:
    stripped = base_url.strip()
    parsed = urlparse(stripped)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    return stripped.rstrip("/")


def resolve_settings(
    env: Mapping[str, str],
    *,
    base_url: str | None = None,
    api_key: str | None = None,
    model: str | None = None,
    timeout: float | None = None,
    confidence_threshold: float | None = None,
    allow_typesafe_cloud: bool | None = None,
) -> SdkSettings | ConfigFailure:
    """Resolve explicit SDK settings. Constructor arguments override the environment."""
    if allow_typesafe_cloud is None:
        allow_cloud = _truthy(_nonblank(env, CLOUD_OPT_IN_ENV))
    else:
        allow_cloud = allow_typesafe_cloud

    raw_base = base_url if base_url is not None else _nonblank(env, BASE_URL_ENV)
    if raw_base is None:
        raw_base = LOCAL_BASE_URL
    normalized_base = _http_base_url(raw_base)
    if normalized_base is None:
        return ConfigFailure(ReasonCode.FAIL_CLOSED_INVALID_CONFIG)
    if is_typesafe_cloud(normalized_base) and not allow_cloud:
        return ConfigFailure(ReasonCode.FAIL_CLOSED_CLOUD_MISCONFIGURED)

    raw_key = api_key if api_key is not None else _nonblank(env, API_KEY_ENV)
    resolved_key = LOCAL_API_KEY if raw_key is None else raw_key
    if not resolved_key.strip() or any(char.isspace() for char in resolved_key):
        return ConfigFailure(ReasonCode.FAIL_CLOSED_INVALID_CONFIG)

    raw_model = model if model is not None else _nonblank(env, DEFAULT_MODEL_ENV)
    resolved_model = LOCAL_MODEL if raw_model is None else raw_model.strip()
    if not resolved_model:
        return ConfigFailure(ReasonCode.FAIL_CLOSED_INVALID_CONFIG)

    if timeout is None:
        timeout_raw = _nonblank(env, TIMEOUT_ENV)
        resolved_timeout = DEFAULT_TIMEOUT_SECONDS if timeout_raw is None else _parse_float(timeout_raw)
    else:
        resolved_timeout = timeout
    if resolved_timeout is None or resolved_timeout <= 0:
        return ConfigFailure(ReasonCode.FAIL_CLOSED_INVALID_CONFIG)

    if confidence_threshold is None:
        threshold_raw = _nonblank(env, CONFIDENCE_THRESHOLD_ENV)
        resolved_threshold = (
            DEFAULT_CONFIDENCE_THRESHOLD if threshold_raw is None else _parse_float(threshold_raw)
        )
    else:
        resolved_threshold = confidence_threshold
    if (
        resolved_threshold is None
        or resolved_threshold < 0.0
        or resolved_threshold > 1.0
    ):
        return ConfigFailure(ReasonCode.FAIL_CLOSED_INVALID_CONFIG)

    return SdkSettings(
        base_url=normalized_base,
        api_key=resolved_key,
        model=resolved_model,
        timeout_seconds=resolved_timeout,
        confidence_threshold=resolved_threshold,
        allow_typesafe_cloud=allow_cloud,
    )
