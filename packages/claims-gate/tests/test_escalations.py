"""Escalation queue: durable, file-backed, approve-once (claims_gate.escalations)."""

from __future__ import annotations

import json
import stat
from pathlib import Path
from typing import Any

import pytest
from claims_gate.__main__ import main
from claims_gate.escalations import EscalationError, EscalationStore, args_hash


class Clock:
    def __init__(self, t: float = 1_000_000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


def store(tmp_path: Path, clock: Clock, **kw: Any) -> EscalationStore:
    return EscalationStore(tmp_path / "esc", clock=clock, **kw)


H = args_hash({})


def test_args_hash_is_canonical_and_strict() -> None:
    assert args_hash({"a": 1, "b": [1, 2]}) == args_hash({"b": [1, 2], "a": 1})
    assert args_hash({"a": 1}) != args_hash({"a": 2})
    assert args_hash({}) != args_hash(None)  # absent arguments are not the same request as {}
    assert len(H) == 64


def test_escalate_records_pending_and_dedupes(tmp_path: Path) -> None:
    clock = Clock()
    s = store(tmp_path, clock)
    first = s.on_escalate("alice", "generate_wallet", H, "claims_wallet_escalate")
    assert first.action == "escalate"
    e = first.escalation
    assert (e.sub, e.tool, e.args_hash, e.status, e.created_at) == ("alice", "generate_wallet", H, "pending", clock.t)
    again = s.on_escalate("alice", "generate_wallet", H, "claims_wallet_escalate")
    assert again.action == "escalate" and again.escalation.id == e.id
    other = s.on_escalate("bob", "generate_wallet", H, "claims_wallet_escalate")
    assert other.escalation.id != e.id
    assert [x.id for x in s.list()] == [e.id, other.escalation.id]


def test_store_is_durable_and_private(tmp_path: Path) -> None:
    clock = Clock()
    e = store(tmp_path, clock).on_escalate("alice", "generate_wallet", H, "r").escalation
    reopened = store(tmp_path, clock)
    assert reopened.get(e.id) == e
    assert stat.S_IMODE((tmp_path / "esc").stat().st_mode) == 0o700
    assert stat.S_IMODE((tmp_path / "esc" / "escalations.sqlite3").stat().st_mode) == 0o600


def test_approve_lets_exactly_one_matching_retry_then_consumed(tmp_path: Path) -> None:
    clock = Clock()
    s = store(tmp_path, clock, approval_ttl=300)
    e = s.on_escalate("alice", "generate_wallet", H, "r").escalation
    approved = s.approve(e.id)
    assert approved.status == "approved" and approved.expires_at == clock.t + 300
    # non-matching retries do not consume it
    assert s.on_escalate("bob", "generate_wallet", H, "r").action == "escalate"
    assert s.on_escalate("alice", "generate_wallet", args_hash({"x": 1}), "r").action == "escalate"
    assert s.on_escalate("alice", "other_tool", H, "r").action == "escalate"
    assert s.get(e.id).status == "approved"
    clock.t += 10
    used = s.on_escalate("alice", "generate_wallet", H, "r")
    assert used.action == "allow" and used.escalation.id == e.id
    assert s.get(e.id).status == "consumed" and s.get(e.id).consumed_at == clock.t
    nxt = s.on_escalate("alice", "generate_wallet", H, "r")
    assert nxt.action == "escalate" and nxt.escalation.id != e.id and nxt.escalation.status == "pending"


def test_approval_expires_unused(tmp_path: Path) -> None:
    clock = Clock()
    s = store(tmp_path, clock, approval_ttl=60)
    e = s.on_escalate("alice", "generate_wallet", H, "r").escalation
    s.approve(e.id)
    clock.t += 60
    out = s.on_escalate("alice", "generate_wallet", H, "r")
    assert out.action == "escalate" and out.escalation.id != e.id
    assert s.get(e.id).status == "expired"


def test_pending_expires_and_cannot_be_approved(tmp_path: Path) -> None:
    clock = Clock()
    s = store(tmp_path, clock, pending_ttl=100)
    e = s.on_escalate("alice", "generate_wallet", H, "r").escalation
    assert e.expires_at == clock.t + 100
    clock.t += 100
    with pytest.raises(EscalationError, match="expired"):
        s.approve(e.id)
    assert s.get(e.id).status == "expired"
    assert [x.status for x in s.list()] == ["expired"]


def test_deny_sticks_for_the_same_request(tmp_path: Path) -> None:
    clock = Clock()
    s = store(tmp_path, clock, pending_ttl=100)
    e = s.on_escalate("alice", "generate_wallet", H, "r").escalation
    clock.t += 40
    denied = s.deny(e.id)
    assert denied.status == "denied" and denied.decided_at == clock.t and denied.expires_at == clock.t + 100
    out = s.on_escalate("alice", "generate_wallet", H, "r")
    assert out.action == "deny" and out.escalation.id == e.id
    assert s.on_escalate("alice", "generate_wallet", args_hash({"x": 1}), "r").action == "escalate"
    clock.t += 100  # denial window over: a retry opens a fresh request
    out = s.on_escalate("alice", "generate_wallet", H, "r")
    assert out.action == "escalate" and out.escalation.id != e.id


def test_deny_revokes_an_unused_approval(tmp_path: Path) -> None:
    clock = Clock()
    s = store(tmp_path, clock)
    e = s.on_escalate("alice", "generate_wallet", H, "r").escalation
    s.approve(e.id)
    s.deny(e.id)
    assert s.on_escalate("alice", "generate_wallet", H, "r").action == "deny"


def test_invalid_transitions_raise(tmp_path: Path) -> None:
    clock = Clock()
    s = store(tmp_path, clock)
    with pytest.raises(EscalationError, match="no escalation"):
        s.approve("nope")
    e = s.on_escalate("alice", "generate_wallet", H, "r").escalation
    s.approve(e.id)
    with pytest.raises(EscalationError, match="approved"):
        s.approve(e.id)
    s.on_escalate("alice", "generate_wallet", H, "r")  # consumes
    with pytest.raises(EscalationError, match="consumed"):
        s.deny(e.id)
    with pytest.raises(EscalationError, match="consumed"):
        s.approve(e.id)


def test_cli_list_approve_deny(tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> None:
    d = tmp_path / "esc"
    s = EscalationStore(d)
    a = s.on_escalate("alice", "generate_wallet", H, "claims_wallet_escalate").escalation
    b = s.on_escalate("bob", "generate_wallet", H, "claims_wallet_escalate").escalation
    assert main(["escalations", "list", "--dir", str(d)]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert [(r["id"], r["status"], r["sub"], r["argsHash"]) for r in rows] == [(a.id, "pending", "alice", H), (b.id, "pending", "bob", H)]
    assert main(["escalations", "approve", a.id, "--dir", str(d)]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "approved"
    monkeypatch.setenv("S1_ESCALATION_DIR", str(d))
    assert main(["escalations", "deny", b.id]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "denied"
    assert main(["escalations", "list", "--status", "denied"]) == 0
    assert [r["id"] for r in json.loads(capsys.readouterr().out)] == [b.id]
    assert main(["escalations", "approve", b.id]) == 1
    assert "denied" in capsys.readouterr().err
    monkeypatch.delenv("S1_ESCALATION_DIR")
    assert main(["escalations", "list"]) == 2
