"""Unit tests for the gate client. The TypeSafe SDK is mocked; Ollama is not called."""

from __future__ import annotations

from unittest.mock import MagicMock

import httpx2
import pytest
from typesafe_sdk import (
    Choice,
    ChoiceAnswer,
    SystemOneResponse,
    TypeSafeAPIConnectionError,
    TypeSafeAPIError,
    TypeSafeAPITimeoutError,
    TypeSafeNotFoundError,
    Usage,
)
from typesafe_sdk.constants import DEFAULT_BASE_URL

from gate_client import (
    LOCAL_API_KEY,
    LOCAL_BASE_URL,
    LOCAL_MODEL,
    GateClient,
    ReasonCode,
)
from gate_client.client import AUTHORITY_QUESTION
from gate_client.config import is_typesafe_cloud

_PROBS = {"allow": 0.91, "deny": 0.05, "escalate": 0.04}


def _response(choice: str, confidence: float, probs: dict[str, float] | None = None) -> SystemOneResponse:
    return SystemOneResponse(
        model="nimble",
        usage=Usage(input_tokens=10, output_tokens=1),
        answers={
            AUTHORITY_QUESTION: ChoiceAnswer(
                choice=choice,
                confidence=confidence,
                probabilities=dict(probs or _PROBS),
            )
        },
    )


@pytest.fixture
def sdk(monkeypatch: pytest.MonkeyPatch) -> tuple[MagicMock, MagicMock]:
    client = MagicMock()
    client.__enter__.return_value = client
    client.__exit__.return_value = False
    constructor = MagicMock(return_value=client)
    monkeypatch.setattr("gate_client.client.TypeSafeClient", constructor)
    return constructor, client


def _decide(client: MagicMock, response: SystemOneResponse) -> GateClient:
    client.system_one.return_value = response
    return GateClient(env={})


def test_allow_uses_sdk_choice_and_probabilities(sdk: tuple[MagicMock, MagicMock]) -> None:
    constructor, client = sdk
    gate = _decide(client, _response("allow", 0.88))

    decision = gate.decide(
        policy="May read files under /tmp.",
        tool_name="read_file",
        args={"path": "/tmp/note.txt", "password": "hunter2"},
        context="User asked for the note.",
    )

    assert decision.choice == "allow"
    assert decision.probs == _PROBS
    assert decision.reason_code == ReasonCode.NIMBLE_ALLOW
    assert decision.reasonCode == "nimble_allow"
    assert decision.to_dict() == {
        "choice": "allow",
        "probs": _PROBS,
        "reasonCode": "nimble_allow",
    }
    constructor.assert_called_once()
    kwargs = constructor.call_args.kwargs
    assert kwargs["base_url"] == LOCAL_BASE_URL
    assert kwargs["api_key"] == LOCAL_API_KEY
    assert kwargs["model"] == LOCAL_MODEL
    assert kwargs["retry"].max_retries == 0
    assert kwargs["base_url"] != DEFAULT_BASE_URL

    call = client.system_one.call_args.kwargs
    assert call["model"] == LOCAL_MODEL
    assert set(call["questions"]) == {AUTHORITY_QUESTION}
    question = call["questions"][AUTHORITY_QUESTION]
    assert isinstance(question, Choice)
    assert set(question.criteria) == {"allow", "deny", "escalate"}
    assert call["state"]["granted_policy"] == "May read files under /tmp."
    assert call["state"]["tool_name"] == "read_file"
    assert call["state"]["args"]["path"] == "/tmp/note.txt"
    assert call["state"]["args"]["password"] == "[REDACTED]"
    assert "hunter2" not in str(call["state"])
    client.models.list.assert_not_called()


def test_deny_from_sdk(sdk: tuple[MagicMock, MagicMock]) -> None:
    _, client = sdk
    probs = {"allow": 0.02, "deny": 0.96, "escalate": 0.02}
    gate = _decide(client, _response("deny", 0.8, probs))

    decision = gate.decide(policy="read only", tool_name="delete_file", args={"path": "/tmp/x"})

    assert decision.to_dict() == {
        "choice": "deny",
        "probs": probs,
        "reasonCode": "nimble_deny",
    }


def test_escalate_only_when_nimble_chooses_grey(sdk: tuple[MagicMock, MagicMock]) -> None:
    _, client = sdk
    probs = {"allow": 0.2, "deny": 0.2, "escalate": 0.6}
    gate = _decide(client, _response("escalate", 0.62, probs))

    decision = gate.decide(policy="read only", tool_name="write_file", args={}, context="unclear")

    assert decision.choice == "escalate"
    assert decision.probs == probs
    assert decision.reason_code == ReasonCode.NIMBLE_ESCALATE


@pytest.mark.parametrize(
    "label",
    ["allow", "deny", "escalate"],
)
def test_low_confidence_fail_closes_to_deny(sdk: tuple[MagicMock, MagicMock], label: str) -> None:
    _, client = sdk
    gate = _decide(client, _response(label, 0.49))

    decision = gate.decide(policy="read only", tool_name="read_file", args={})

    assert decision.choice == "deny"
    assert decision.probs == _PROBS
    assert decision.reason_code == ReasonCode.FAIL_CLOSED_LOW_CONFIDENCE
    assert decision.to_dict()["reasonCode"] == "fail_closed_low_confidence"


def test_confidence_equal_to_threshold_keeps_sdk_choice(sdk: tuple[MagicMock, MagicMock]) -> None:
    _, client = sdk
    gate = GateClient(env={}, confidence_threshold=0.5)
    client.system_one.return_value = _response("allow", 0.5)

    decision = gate.decide(policy="read only", tool_name="read_file", args={})

    assert decision.choice == "allow"
    assert decision.reason_code == ReasonCode.NIMBLE_ALLOW


def test_timeout_fail_closes_to_deny(sdk: tuple[MagicMock, MagicMock]) -> None:
    _, client = sdk
    client.system_one.side_effect = TypeSafeAPITimeoutError(30.0)
    gate = GateClient(env={})

    decision = gate.decide(policy="read only", tool_name="read_file", args={"path": "/tmp/x"})

    assert decision.to_dict() == {
        "choice": "deny",
        "probs": {},
        "reasonCode": "fail_closed_timeout",
    }


def test_connection_error_fail_closes_to_deny(sdk: tuple[MagicMock, MagicMock]) -> None:
    _, client = sdk
    client.system_one.side_effect = TypeSafeAPIConnectionError("connection refused")
    gate = GateClient(env={})

    decision = gate.decide(policy="read only", tool_name="read_file", args={})

    assert decision.choice == "deny"
    assert decision.reason_code == ReasonCode.FAIL_CLOSED_DOWN


def test_model_not_found_fail_closes_to_deny(sdk: tuple[MagicMock, MagicMock]) -> None:
    _, client = sdk
    client.system_one.side_effect = TypeSafeNotFoundError(404, {"error": "model not found"}, httpx2.Headers())
    gate = GateClient(env={})

    decision = gate.decide(policy="read only", tool_name="read_file", args={})

    assert decision.reason_code == ReasonCode.FAIL_CLOSED_DOWN


def test_api_error_fail_closes_to_deny(sdk: tuple[MagicMock, MagicMock]) -> None:
    _, client = sdk
    client.system_one.side_effect = TypeSafeAPIError(500, {"error": "boom"}, httpx2.Headers())
    gate = GateClient(env={})

    decision = gate.decide(policy="read only", tool_name="read_file", args={})

    assert decision.choice == "deny"
    assert decision.reason_code == ReasonCode.FAIL_CLOSED_SDK_ERROR


def test_unrecognized_choice_fail_closes_and_keeps_probs(sdk: tuple[MagicMock, MagicMock]) -> None:
    _, client = sdk
    gate = _decide(client, _response("maybe", 0.99, {"maybe": 0.99, "allow": 0.01}))

    decision = gate.decide(policy="read only", tool_name="read_file", args={})

    assert decision.choice == "deny"
    assert decision.probs == {"maybe": 0.99, "allow": 0.01}
    assert decision.reason_code == ReasonCode.FAIL_CLOSED_INVALID_RESPONSE


def test_missing_choice_answer_fail_closes(sdk: tuple[MagicMock, MagicMock]) -> None:
    _, client = sdk
    client.system_one.return_value = SystemOneResponse(model="nimble", usage=Usage(), answers={})
    gate = GateClient(env={})

    decision = gate.decide(policy="read only", tool_name="read_file", args={})

    assert decision.reason_code == ReasonCode.FAIL_CLOSED_INVALID_RESPONSE
    assert decision.choice == "deny"


def test_cloud_base_url_without_opt_in_does_not_call_sdk(sdk: tuple[MagicMock, MagicMock]) -> None:
    constructor, client = sdk
    gate = GateClient(env={"TYPESAFE_BASE_URL": DEFAULT_BASE_URL, "TYPESAFE_API_KEY": "secret-key"})

    decision = gate.decide(policy="read only", tool_name="read_file", args={})

    assert decision.to_dict()["reasonCode"] == "fail_closed_cloud_misconfigured"
    assert decision.choice == "deny"
    constructor.assert_not_called()
    client.system_one.assert_not_called()
    assert gate.settings is None


def test_cloud_subdomain_without_opt_in_fail_closes(sdk: tuple[MagicMock, MagicMock]) -> None:
    constructor, _ = sdk
    gate = GateClient(env={"TYPESAFE_BASE_URL": "https://jev.typesafe.ai"})

    decision = gate.decide(policy="read only", tool_name="read_file", args={})

    assert decision.reason_code == ReasonCode.FAIL_CLOSED_CLOUD_MISCONFIGURED
    constructor.assert_not_called()


def test_cloud_opt_in_calls_sdk_with_explicit_cloud_url(sdk: tuple[MagicMock, MagicMock]) -> None:
    constructor, client = sdk
    client.system_one.return_value = _response("deny", 0.9)
    gate = GateClient(
        env={
            "TYPESAFE_BASE_URL": "https://api.typesafe.ai",
            "TYPESAFE_API_KEY": "ts_live_key",
            "TYPESAFE_DEFAULT_MODEL": "jev-latest",
            "GATE_ALLOW_TYPESAFE_CLOUD": "1",
        }
    )

    decision = gate.decide(policy="read only", tool_name="read_file", args={})

    assert decision.choice == "deny"
    assert decision.reason_code == ReasonCode.NIMBLE_DENY
    assert constructor.call_args.kwargs["base_url"] == "https://api.typesafe.ai"
    assert constructor.call_args.kwargs["api_key"] == "ts_live_key"
    assert constructor.call_args.kwargs["model"] == "jev-latest"


def test_env_local_triple_is_passed_explicitly(sdk: tuple[MagicMock, MagicMock]) -> None:
    constructor, client = sdk
    client.system_one.return_value = _response("allow", 0.7)
    gate = GateClient(
        env={
            "TYPESAFE_BASE_URL": "http://localhost:11434/",
            "TYPESAFE_API_KEY": "ollama",
            "TYPESAFE_DEFAULT_MODEL": "nimble",
        }
    )

    gate.decide(policy="read only", tool_name="read_file", args={})

    assert constructor.call_args.kwargs["base_url"] == "http://localhost:11434"
    assert constructor.call_args.kwargs["api_key"] == "ollama"
    assert constructor.call_args.kwargs["model"] == "nimble"


def test_constructor_does_not_construct_sdk(sdk: tuple[MagicMock, MagicMock]) -> None:
    constructor, _ = sdk
    GateClient(env={})
    constructor.assert_not_called()


def test_redaction_keeps_author_and_strips_nested_secrets() -> None:
    from gate_client.state import build_state

    original = {
        "author": "mira",
        "headers": {"Authorization": "Bearer secret", "Accept": "text/plain"},
        "refresh_token": "abc",
        "nested": [{"api_key": "k", "limit": 2}],
    }
    state = build_state(policy="p", tool_name="fetch", args=original, context="x" * 2005)

    assert original["headers"]["Authorization"] == "Bearer secret"
    assert state["args"]["author"] == "mira"
    assert state["args"]["headers"]["Authorization"] == "[REDACTED]"
    assert state["args"]["headers"]["Accept"] == "text/plain"
    assert state["args"]["refresh_token"] == "[REDACTED]"
    assert state["args"]["nested"][0]["api_key"] == "[REDACTED]"
    assert state["args"]["nested"][0]["limit"] == 2
    assert len(state["context"]) == 2000
    assert state["context"].endswith("…")


def test_invalid_threshold_fail_closes_without_sdk(sdk: tuple[MagicMock, MagicMock]) -> None:
    constructor, _ = sdk
    gate = GateClient(env={"GATE_CONFIDENCE_THRESHOLD": "2"})

    decision = gate.decide(policy="read only", tool_name="read_file", args={})

    assert decision.reason_code == ReasonCode.FAIL_CLOSED_INVALID_CONFIG
    constructor.assert_not_called()


def test_client_has_no_tool_execution_method() -> None:
    assert not hasattr(GateClient, "execute")
    assert not hasattr(GateClient, "run_tool")


@pytest.mark.parametrize(
    ("url", "cloud"),
    [
        ("http://localhost:11434", False),
        ("http://127.0.0.1:11434", False),
        ("https://api.typesafe.ai", True),
        ("https://API.TypeSafe.AI/v1", True),
        ("https://jev.typesafe.ai", True),
        ("https://openrouter.ai/api", False),
    ],
)
def test_cloud_host_detection(url: str, cloud: bool) -> None:
    assert is_typesafe_cloud(url) is cloud
