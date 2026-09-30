"""System-1 per-tool-call authority gate client.

Uses TypeSafe's official Python SDK against local Ollama Nimble. The client
returns a decision only. It does not execute tools.
"""

from gate_client.client import AUTHORITY_QUESTION, GateClient, authority_questions
from gate_client.config import (
    CLOUD_OPT_IN_ENV,
    LOCAL_API_KEY,
    LOCAL_BASE_URL,
    LOCAL_MODEL,
    MIN_OLLAMA_VERSION,
    is_typesafe_cloud,
)
from gate_client.decision import GateDecision, ReasonCode

__all__ = [
    "AUTHORITY_QUESTION",
    "CLOUD_OPT_IN_ENV",
    "GateClient",
    "GateDecision",
    "LOCAL_API_KEY",
    "LOCAL_BASE_URL",
    "LOCAL_MODEL",
    "MIN_OLLAMA_VERSION",
    "ReasonCode",
    "authority_questions",
    "is_typesafe_cloud",
]
