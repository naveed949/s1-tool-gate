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


# ---- approve-once under concurrency ------------------------------------------

N_RETRIES = 12


def _race(store_dir: Path, barrier: Any, results: Any) -> None:
    """One retry: own store object (like a separate proxy process), released together."""
    s = EscalationStore(store_dir)
    barrier.wait(timeout=30)
    try:
        results.put(s.on_escalate("alice", "generate_wallet", H, "claims_wallet_escalate").action)
    except Exception as err:  # noqa: BLE001 - surfaced as a non-action result
        results.put(f"error:{type(err).__name__}:{err}")


@pytest.fixture
def widen_race(monkeypatch: pytest.MonkeyPatch) -> None:
    """Sleep between reading the approved row and updating it, so racing retries overlap.

    Without the sleep the transactions are too short to interleave reliably. What the
    two tests below then catch: dropping the transaction *and* the guarded consume
    together (no transaction at all, plus an unguarded UPDATE) lets more than one
    retry through. They do not prove ``BEGIN IMMEDIATE`` on its own is needed: with a
    deferred ``BEGIN`` (guarded or not) one retry is allowed and the others fail with
    ``database is locked``, which the proxy turns into a deny, never a second allow.
    Both claims are pinned by ``test_widen_race_mutations_behave_as_documented``; the
    status guard plus rowcount check is pinned separately by
    ``test_consume_requires_exactly_one_row_updated``.
    """
    import time as _time

    real = EscalationStore._match

    def slow_match(self: EscalationStore, db: Any, status: str, *a: Any) -> Any:
        row = real(self, db, status, *a)
        if status == "approved":
            _time.sleep(0.03)
        return row

    monkeypatch.setattr(EscalationStore, "_match", slow_match)


def _assert_one_allow(store_dir: Path, eid: str, actions: list[str]) -> None:
    assert sorted(actions) == ["allow"] + ["escalate"] * (N_RETRIES - 1), actions
    s = EscalationStore(store_dir)
    assert s.get(eid).status == "consumed"
    rows = s.list()
    # the losers share one fresh pending request; nothing else was approved or consumed
    assert sorted(r.status for r in rows) == ["consumed", "pending"], [(r.id, r.status) for r in rows]


def test_concurrent_identical_retries_threads_consume_one_approval(tmp_path: Path, widen_race: None) -> None:
    import queue
    import threading

    d = tmp_path / "esc"
    shared = EscalationStore(d)
    eid = shared.on_escalate("alice", "generate_wallet", H, "claims_wallet_escalate").escalation.id
    shared.approve(eid)
    barrier = threading.Barrier(N_RETRIES)
    results: queue.Queue[str] = queue.Queue()
    threads = [threading.Thread(target=_race, args=(d, barrier, results)) for _ in range(N_RETRIES)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    _assert_one_allow(d, eid, [results.get_nowait() for _ in range(N_RETRIES)])


def test_concurrent_identical_retries_processes_consume_one_approval(tmp_path: Path, widen_race: None) -> None:
    import multiprocessing

    ctx = multiprocessing.get_context("fork")
    d = tmp_path / "esc"
    s = EscalationStore(d)
    eid = s.on_escalate("alice", "generate_wallet", H, "claims_wallet_escalate").escalation.id
    s.approve(eid)
    barrier = ctx.Barrier(N_RETRIES)
    results = ctx.Queue()
    procs = [ctx.Process(target=_race, args=(d, barrier, results)) for _ in range(N_RETRIES)]
    for p in procs:
        p.start()
    actions = [results.get(timeout=60) for _ in range(N_RETRIES)]
    for p in procs:
        p.join(timeout=30)
        assert p.exitcode == 0
    _assert_one_allow(d, eid, actions)


class _MutatedDb:
    """sqlite connection whose SQL is rewritten: deferred or no transaction, unguarded consume."""

    def __init__(self, db: Any, mode: str) -> None:
        self._db, self._mode = db, mode

    def execute(self, sql: str, params: Any = ()) -> Any:
        stmt = sql.strip()
        if stmt.startswith("UPDATE escalations SET status = 'consumed'"):
            sql, params = "UPDATE escalations SET status = 'consumed', consumed_at = ? WHERE id = ?", params[:2]
        elif stmt in ("BEGIN IMMEDIATE", "COMMIT", "ROLLBACK") and self._mode == "no-transaction":
            sql, params = "SELECT 1", ()
        elif stmt == "BEGIN IMMEDIATE":
            sql = "BEGIN"
        return self._db.execute(sql, params)

    def close(self) -> None:
        self._db.close()


@pytest.mark.parametrize("mode", ["deferred-unguarded", "no-transaction"])
def test_widen_race_mutations_behave_as_documented(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, widen_race: None, mode: str) -> None:
    """What the widen_race docstring says about weaker variants, measured.

    deferred BEGIN + unguarded consume: one allow, the rest 'database is locked'
    (the proxy denies those), never two allows. No transaction + unguarded consume:
    more than one allow, which is what the concurrent-retry tests exist to catch.
    """
    import queue
    import sqlite3
    import threading

    d = tmp_path / "esc"
    s = EscalationStore(d)
    eid = s.on_escalate("alice", "generate_wallet", H, "claims_wallet_escalate").escalation.id
    s.approve(eid)
    real_connect = sqlite3.connect
    monkeypatch.setattr(sqlite3, "connect", lambda *a, **kw: _MutatedDb(real_connect(*a, **kw), mode))
    barrier = threading.Barrier(N_RETRIES)
    results: queue.Queue[str] = queue.Queue()
    threads = [threading.Thread(target=_race, args=(d, barrier, results)) for _ in range(N_RETRIES)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    actions = [results.get_nowait() for _ in range(N_RETRIES)]
    allows = actions.count("allow")
    if mode == "deferred-unguarded":
        assert allows == 1, actions
        others = [a for a in actions if a != "allow"]
        assert set(others) <= {"escalate", "error:OperationalError:database is locked"}, actions
        assert "error:OperationalError:database is locked" in others, actions
    else:
        assert allows > 1, actions


def test_consume_requires_exactly_one_row_updated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A stale 'approved' match (row already consumed) must not be allowed again."""
    import dataclasses

    clock = Clock()
    s = store(tmp_path, clock)
    e = s.on_escalate("alice", "generate_wallet", H, "r").escalation
    s.approve(e.id)
    assert s.on_escalate("alice", "generate_wallet", H, "r").action == "allow"
    real_match = s._match

    def stale_match(db: Any, status: str, *a: Any) -> Any:
        if status == "approved":  # pretend the read raced the other consumer
            return dataclasses.replace(s._get(db, e.id), status="approved")
        return real_match(db, status, *a)

    monkeypatch.setattr(s, "_match", stale_match)
    out = s.on_escalate("alice", "generate_wallet", H, "r")
    assert out.action == "escalate" and out.escalation.id != e.id
    monkeypatch.undo()
    assert s.get(e.id).status == "consumed"


@pytest.mark.parametrize("decision", ["approve", "deny"])
def test_decisions_guard_on_current_status(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, decision: str) -> None:
    """approve/deny UPDATEs carry a status guard: a stale read can never re-arm or rewrite a consumed row."""
    import dataclasses

    clock = Clock()
    s = store(tmp_path, clock)
    e = s.on_escalate("alice", "generate_wallet", H, "r").escalation
    s.approve(e.id)
    s.on_escalate("alice", "generate_wallet", H, "r")  # consumed
    real_get = s._get
    seen = {"n": 0}

    def stale_get(db: Any, escalation_id: str) -> Any:
        row = real_get(db, escalation_id)
        seen["n"] += 1
        if seen["n"] == 1:  # the pre-update state check sees a stale row
            return dataclasses.replace(row, status="pending")
        return row

    monkeypatch.setattr(s, "_get", stale_get)
    with pytest.raises(EscalationError, match="changed"):
        getattr(s, decision)(e.id)
    monkeypatch.undo()
    assert s.get(e.id).status == "consumed"
    assert s.on_escalate("alice", "generate_wallet", H, "r").action == "escalate"


def test_args_hash_is_over_exact_args_without_normalization() -> None:
    """Documented: no Unicode/number normalization; differently spelled args are different requests."""
    import unicodedata

    nfc, nfd = unicodedata.normalize("NFC", "caf\u00e9"), unicodedata.normalize("NFD", "caf\u00e9")
    assert nfc != nfd
    assert args_hash({"label": nfc}) != args_hash({"label": nfd})
    assert args_hash({"n": 1}) != args_hash({"n": 1.0})
    assert args_hash({"label": "A"}) != args_hash({"label": "a"})


@pytest.mark.parametrize("remove", ["file", "dir"])
def test_db_deleted_at_runtime_is_recreated_private(tmp_path: Path, remove: str) -> None:
    import os
    import shutil

    clock = Clock()
    s = store(tmp_path, clock)
    s.on_escalate("alice", "generate_wallet", H, "r")
    if remove == "file":
        s.path.unlink()
    else:
        shutil.rmtree(s.directory)
    old = os.umask(0o022)  # a permissive umask must not leak into the recreated db
    try:
        out = s.on_escalate("alice", "generate_wallet", H, "r")
    finally:
        os.umask(old)
    assert out.action == "escalate" and out.escalation.status == "pending"  # fresh queue: nothing approved survives
    assert stat.S_IMODE(s.path.stat().st_mode) == 0o600
    assert stat.S_IMODE(s.directory.stat().st_mode) == 0o700
    assert [e.id for e in s.list()] == [out.escalation.id]


# ---- db recreated at runtime: racing requests escalate, never error or allow ---


def test_schema_is_ensured_inside_every_transaction(tmp_path: Path) -> None:
    """Another request created the (empty) db file but has not made the table yet.

    This is the state a racing request sees right after a runtime deletion: the file
    exists, so the old code skipped the schema and failed with 'no such table'.
    """
    import os

    clock = Clock()
    s = store(tmp_path, clock)
    e = s.on_escalate("alice", "generate_wallet", H, "r").escalation
    s.approve(e.id)
    s.path.unlink()
    fd = os.open(s.path, os.O_CREAT | os.O_WRONLY, 0o600)  # what _create_private leaves behind
    os.close(fd)
    out = s.on_escalate("alice", "generate_wallet", H, "r")
    assert out.action == "escalate" and out.escalation.status == "pending"  # the old approval is gone
    assert [r.status for r in s.list()] == ["pending"]


def test_db_vanishing_before_connect_fails_closed_without_a_umask_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """sqlite must never create the db itself (it would use the umask): it errors, the proxy denies."""
    import sqlite3

    s = store(tmp_path, Clock())
    s.path.unlink()
    monkeypatch.setattr(s, "_create_private", lambda: False)  # file deleted after the existence check
    with pytest.raises(sqlite3.OperationalError):
        s.on_escalate("alice", "generate_wallet", H, "r")
    assert not s.path.exists()


DELETE_RACE_TRIALS = 20


def test_db_deleted_at_runtime_concurrent_retries_all_escalate(tmp_path: Path) -> None:
    """Repro of the round-2 finding: 12 racing retries right after the db is deleted.

    Every one must escalate (no 'no such table' -> claims_escalation_unavailable),
    they share exactly one fresh pending row, and the deleted approval never allows.
    """
    import threading

    outcomes: list[str] = []
    for trial in range(DELETE_RACE_TRIALS):
        s = EscalationStore(tmp_path / f"q{trial}")
        e = s.on_escalate("alice", "generate_wallet", H, "r").escalation
        s.approve(e.id)
        s.path.unlink()
        barrier = threading.Barrier(N_RETRIES)
        res: list[str] = []
        lock = threading.Lock()

        def one(s: EscalationStore = s, barrier: threading.Barrier = barrier, res: list[str] = res) -> None:
            barrier.wait(timeout=30)
            try:
                action = s.on_escalate("alice", "generate_wallet", H, "r").action
            except Exception as err:  # noqa: BLE001 - surfaced as a non-action result
                action = f"error:{type(err).__name__}:{err}"
            with lock:
                res.append(action)

        threads = [threading.Thread(target=one) for _ in range(N_RETRIES)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)
        outcomes += res
        assert [r.status for r in s.list()] == ["pending"], (trial, [(r.id, r.status) for r in s.list()])
        assert stat.S_IMODE(s.path.stat().st_mode) == 0o600
    assert outcomes == ["escalate"] * (DELETE_RACE_TRIALS * N_RETRIES), sorted(set(outcomes))


@pytest.mark.parametrize("ttl", [float("nan"), float("inf"), float("-inf"), 0.0, -1.0, 1e300, 9e18])
def test_escalation_ttls_must_be_finite_and_positive(tmp_path: Path, ttl: float) -> None:
    with pytest.raises(ValueError):
        EscalationStore(tmp_path / "a", pending_ttl=ttl)
    with pytest.raises(ValueError):
        EscalationStore(tmp_path / "b", approval_ttl=ttl)


def test_escalation_ttls_have_an_upper_bound(tmp_path: Path) -> None:
    """A huge finite TTL is a pending/deny/approval that never expires in practice."""
    with pytest.raises(ValueError, match=r"pending TTL must be a finite number in \(0, 86400"):
        EscalationStore(tmp_path / "a", pending_ttl=86400.001)
    with pytest.raises(ValueError, match=r"approval TTL must be a finite number in \(0, 3600"):
        EscalationStore(tmp_path / "b", approval_ttl=3600.001)
    s = EscalationStore(tmp_path / "c", pending_ttl=86400.0, approval_ttl=3600.0)
    assert (s.pending_ttl, s.approval_ttl) == (86400.0, 3600.0)
