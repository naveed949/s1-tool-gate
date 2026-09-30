"""System-1 gate client.

Decisions come from one TypeSafe SDK choice question against local Ollama
Nimble. This module does not execute tools or record side effects.
"""

from __future__ import annotations

import math
import os
from collections.abc import Mapping
from typing import Any

from typesafe_sdk import (
    Choice,
    RetryPolicy,
    TypeSafeAPIConnectionError,
    TypeSafeAPITimeoutError,
    TypeSafeClient,
    TypeSafeError,
    TypeSafeNotFoundError,
)

from gate_client.config import ConfigFailure, SdkSettings, resolve_settings
from gate_client.decision import CHOICES, GateDecision, ReasonCode, deny, reason_for_choice
from gate_client.state import build_state

AUTHORITY_QUESTION = "authority"

_INSTRUCTIONS = (
    "Decide this tool call against the granted policy. "
    "Use only the granted policy, tool name, redacted arguments, and short context. "
    "allow means the call is inside the granted policy. "
    "deny means the call is outside the granted policy. "
    "escalate means the call is a grey area that needs a higher-authority decision."
)

_CRITERIA = {
    "allow": "The tool call stays inside the granted policy.",
    "deny": "The tool call is outside the granted policy.",
    "escalate": "The call is ambiguous and needs a higher-authority decision.",
}


def authority_questions() -> dict[str, Choice]:
    """The single choice question this gate asks Nimble."""
    return {
        AUTHORITY_QUESTION: Choice(
            instructions=_INSTRUCTIONS,
            criteria=dict(_CRITERIA),
        )
    }


class GateClient:
    """Score one tool call as allow, deny, or escalate.

    Local Ollama is the default target. ``TypeSafeClient`` is always constructed
    with an explicit base URL, API key, and model. A TypeSafe cloud host without
    ``GATE_ALLOW_TYPESAFE_CLOUD`` denies before the SDK is constructed.

    Ollama 0.35 or newer is required for Nimble's ``/v1/systemone`` API. This
    client does not probe that version and does not invoke the tool.
    """

    def __init__(
        self,
        *,
        base_url: str | None = None,
        api_key: str | None = None,
        model: str | None = None,
        timeout: float | None = None,
        confidence_threshold: float | None = None,
        allow_typesafe_cloud: bool | None = None,
        env: Mapping[str, str] | None = None,
    ) -> None:
        source = os.environ if env is None else env
        resolved = resolve_settings(
            source,
            base_url=base_url,
            api_key=api_key,
            model=model,
            timeout=timeout,
            confidence_threshold=confidence_threshold,
            allow_typesafe_cloud=allow_typesafe_cloud,
        )
        self._settings: SdkSettings | None
        self._config_failure: ConfigFailure | None
        if isinstance(resolved, ConfigFailure):
            self._settings = None
            self._config_failure = resolved
        else:
            self._settings = resolved
            self._config_failure = None

    @property
    def settings(self) -> SdkSettings | None:
        """Resolved SDK settings, or ``None`` when configuration already fail-closes."""
        return self._settings

    def decide(
        self,
        *,
        policy: str,
        tool_name: str,
        args: Mapping[str, Any] | None = None,
        context: str = "",
    ) -> GateDecision:
        """Return a typed decision. Failures deny. This method does not run the tool."""
        if self._config_failure is not None or self._settings is None:
            reason = (
                self._config_failure.reason_code
                if self._config_failure is not None
                else ReasonCode.FAIL_CLOSED_INVALID_CONFIG
            )
            return deny(reason)

        if not isinstance(policy, str) or not isinstance(tool_name, str) or not isinstance(context, str):
            return deny(ReasonCode.FAIL_CLOSED_INVALID_CONFIG)
        if args is None:
            tool_args: Mapping[str, Any] = {}
        elif isinstance(args, Mapping):
            tool_args = args
        else:
            return deny(ReasonCode.FAIL_CLOSED_INVALID_CONFIG)

        state = build_state(policy=policy, tool_name=tool_name, args=tool_args, context=context)
        settings = self._settings
        try:
            with TypeSafeClient(
                api_key=settings.api_key,
                base_url=settings.base_url,
                model=settings.model,
                timeout=settings.timeout_seconds,
                retry=RetryPolicy(max_retries=0),
            ) as sdk:
                result = sdk.system_one(
                    state=state,
                    questions=authority_questions(),
                    model=settings.model,
                )
        except TypeSafeAPITimeoutError:
            return deny(ReasonCode.FAIL_CLOSED_TIMEOUT)
        except TypeSafeNotFoundError:
            return deny(ReasonCode.FAIL_CLOSED_DOWN)
        except TypeSafeAPIConnectionError:
            return deny(ReasonCode.FAIL_CLOSED_DOWN)
        except TimeoutError:
            return deny(ReasonCode.FAIL_CLOSED_TIMEOUT)
        except ConnectionError:
            return deny(ReasonCode.FAIL_CLOSED_DOWN)
        except TypeSafeError:
            return deny(ReasonCode.FAIL_CLOSED_SDK_ERROR)

        return _decision_from_response(result, settings.confidence_threshold)


def _decision_from_response(result: Any, confidence_threshold: float) -> GateDecision:
    choices = getattr(result, "choices", None)
    if not isinstance(choices, Mapping):
        return deny(ReasonCode.FAIL_CLOSED_INVALID_RESPONSE)
    answer = choices.get(AUTHORITY_QUESTION)
    if answer is None:
        return deny(ReasonCode.FAIL_CLOSED_INVALID_RESPONSE)

    probs = _coerce_probs(getattr(answer, "probabilities", None))
    if probs is None:
        return deny(ReasonCode.FAIL_CLOSED_INVALID_RESPONSE)

    label = getattr(answer, "choice", None)
    if label not in CHOICES:
        return deny(ReasonCode.FAIL_CLOSED_INVALID_RESPONSE, probs)

    confidence = getattr(answer, "confidence", None)
    if isinstance(confidence, bool) or not isinstance(confidence, int | float):
        return deny(ReasonCode.FAIL_CLOSED_INVALID_RESPONSE, probs)
    confidence_value = float(confidence)
    if not math.isfinite(confidence_value) or confidence_value < 0.0 or confidence_value > 1.0:
        return deny(ReasonCode.FAIL_CLOSED_INVALID_RESPONSE, probs)
    if confidence_value < confidence_threshold:
        return deny(ReasonCode.FAIL_CLOSED_LOW_CONFIDENCE, probs)

    choice: Any = label
    return GateDecision(
        choice=choice,
        probs=probs,
        reason_code=reason_for_choice(label).value,
    )


def _coerce_probs(raw: Any) -> dict[str, float] | None:
    if not isinstance(raw, Mapping) or not raw:
        return None
    probs: dict[str, float] = {}
    for key, value in raw.items():
        if isinstance(value, bool) or not isinstance(value, int | float):
            return None
        number = float(value)
        if not math.isfinite(number) or number < 0.0 or number > 1.0:
            return None
        probs[str(key)] = number
    return probs
