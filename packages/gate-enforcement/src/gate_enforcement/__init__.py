"""Enforcement seam and observation log for an injected System-1 decision.

The gate client chooses allow, deny, or escalate. This package enforces that
choice against a stub tool and records whether the stub ran. It does not call
Ollama and it does not treat a Nimble score as proof the gate held.
"""

from gate_enforcement.authority import GrantedAuthority
from gate_enforcement.escalate import EscalationChannel, EscalationNotice
from gate_enforcement.log import (
    OBSERVATION_LOG_FIELDS,
    OBSERVATION_SCHEMA_VERSION,
    ObservationLog,
    ObservationRecord,
)
from gate_enforcement.request import ToolRequest
from gate_enforcement.runner import StubToolRunner, ToolInvocation
from gate_enforcement.seam import EnforcementResult, EnforcementSeam

__all__ = [
    "OBSERVATION_LOG_FIELDS",
    "OBSERVATION_SCHEMA_VERSION",
    "EnforcementResult",
    "EnforcementSeam",
    "EscalationChannel",
    "EscalationNotice",
    "GrantedAuthority",
    "ObservationLog",
    "ObservationRecord",
    "StubToolRunner",
    "ToolInvocation",
    "ToolRequest",
]
