"""Durable human-escalation queue for the live proxy (sqlite, stdlib only).

Data shape: one row per escalation request.

  id          16 hex chars, random
  sub         verified token subject that asked
  tool        MCP tool name
  args_hash   sha256 of the canonical JSON of ``params.arguments`` (see ``args_hash``)
  reason_code policy reason that escalated (``claims_wallet_escalate``)
  status      pending | approved | denied | expired | consumed
  created_at  unix seconds
  expires_at  unix seconds; meaning depends on status:
                pending  -> a human must decide before this, else ``expired``
                approved -> the one matching retry must arrive before this, else ``expired``
                denied   -> identical retries are denied until this (then a retry re-asks)
  decided_at  unix seconds of approve/deny, else NULL
  consumed_at unix seconds the approval was used, else NULL
  pending_ttl  seconds a request waits for a human, and how long a denial sticks
  approval_ttl seconds an approval stays usable
               (both TTLs are fixed by the proxy when it creates the row, so the CLI
               and the proxy always agree)

The proxy calls ``on_escalate`` whenever the claims policy says *escalate*:

  approved + same sub/tool/args_hash + unexpired -> ``allow`` and the row becomes ``consumed`` (once)
  denied   + same sub/tool/args_hash + unexpired -> ``deny``
  pending  + same sub/tool/args_hash             -> ``escalate`` with the existing id
  otherwise                                      -> ``escalate`` with a new pending row

Each call is one ``BEGIN IMMEDIATE`` transaction, so a single approval can never
be consumed twice, even across proxy threads or processes. Every state-changing
UPDATE is also guarded on the row's current status and must change exactly one
row, or the transition is refused (consume: not allowed; approve/deny: error).
Each transaction first ensures the schema (``CREATE TABLE IF NOT EXISTS``): a db
deleted at runtime is recreated empty and private (no approval survives), and
requests racing that recreation escalate normally instead of failing. Arguments are never
stored, only their hash. Approval can only turn an *escalate* into one allow;
it can never override a deny (the policy runs first).
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import secrets
import sqlite3
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

DB_FILENAME = "escalations.sqlite3"
DEFAULT_PENDING_TTL = 3600.0
DEFAULT_APPROVAL_TTL = 300.0
STATUSES = ("pending", "approved", "denied", "expired", "consumed")

Action = Literal["allow", "escalate", "deny"]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS escalations (
  id TEXT PRIMARY KEY,
  sub TEXT NOT NULL,
  tool TEXT NOT NULL,
  args_hash TEXT NOT NULL,
  reason_code TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending','approved','denied','expired','consumed')),
  created_at REAL NOT NULL,
  expires_at REAL NOT NULL,
  decided_at REAL,
  consumed_at REAL,
  pending_ttl REAL NOT NULL,
  approval_ttl REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS escalations_match ON escalations (sub, tool, args_hash, status);
"""

_COLUMNS = "id, sub, tool, args_hash, reason_code, status, created_at, expires_at, decided_at, consumed_at, pending_ttl, approval_ttl"


class EscalationError(Exception):
    """An approve/deny that is not allowed from the escalation's current state."""


def args_hash(arguments: Any) -> str:
    """sha256 of canonical JSON (sorted keys, no whitespace). ``{}`` and absent (``None``) differ."""
    canonical = json.dumps(arguments, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode()).hexdigest()


@dataclass(frozen=True)
class Escalation:
    id: str
    sub: str
    tool: str
    args_hash: str
    reason_code: str
    status: str
    created_at: float
    expires_at: float
    decided_at: float | None
    consumed_at: float | None
    pending_ttl: float
    approval_ttl: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "sub": self.sub,
            "tool": self.tool,
            "argsHash": self.args_hash,
            "reasonCode": self.reason_code,
            "status": self.status,
            "createdAt": self.created_at,
            "expiresAt": self.expires_at,
            "decidedAt": self.decided_at,
            "consumedAt": self.consumed_at,
            "pendingTtl": self.pending_ttl,
            "approvalTtl": self.approval_ttl,
        }


@dataclass(frozen=True)
class EscalationOutcome:
    action: Action
    escalation: Escalation


class EscalationStore:
    def __init__(
        self,
        directory: str | os.PathLike[str],
        *,
        pending_ttl: float = DEFAULT_PENDING_TTL,
        approval_ttl: float = DEFAULT_APPROVAL_TTL,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not all(math.isfinite(t) and t > 0 for t in (pending_ttl, approval_ttl)):
            raise ValueError(f"escalation TTLs must be finite and positive (got pending={pending_ttl}, approval={approval_ttl})")
        self.directory = Path(directory)
        self.path = self.directory / DB_FILENAME
        self.pending_ttl = float(pending_ttl)
        self.approval_ttl = float(approval_ttl)
        self._clock = clock
        self._create_private()
        os.chmod(self.directory, 0o700)
        os.chmod(self.path, 0o600)
        with self._tx():
            pass

    # ---- plumbing --------------------------------------------------------
    def _create_private(self) -> bool:
        """Create the dir (700) and db file (600) if missing, before sqlite can create them.

        sqlite would otherwise create a deleted db with the process umask (often 644).
        Returns True if the db file was missing.
        """
        if self.path.exists():
            return False
        if not self.directory.is_dir():
            self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            os.chmod(self.directory, 0o700)
        fd = os.open(self.path, os.O_CREAT | os.O_WRONLY, 0o600)
        try:
            os.fchmod(fd, 0o600)
        finally:
            os.close(fd)
        return True

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        # A db deleted at runtime is recreated private and empty (fail closed: no
        # approval survives; the next escalation is a fresh pending request).
        self._create_private()
        # mode=rw: sqlite never creates the file itself (it would use the process
        # umask). If the file vanishes between the line above and here, connect
        # fails and the caller denies (claims_escalation_unavailable).
        db = sqlite3.connect(f"{self.path.resolve().as_uri()}?mode=rw", uri=True, timeout=5.0, isolation_level=None)
        try:
            db.execute("BEGIN IMMEDIATE")
            try:
                # The schema is ensured inside every write transaction, not only by the
                # request that recreated the file: after a runtime deletion a racing
                # request can see the new empty file and take the write lock before
                # its creator, and must still find the table (IF NOT EXISTS: no-op).
                for stmt in _SCHEMA.split(";"):
                    if stmt.strip():
                        db.execute(stmt)
                yield db
            except BaseException:
                db.execute("ROLLBACK")
                raise
            db.execute("COMMIT")
        finally:
            db.close()

    @staticmethod
    def _row(row: tuple[Any, ...] | None) -> Escalation | None:
        return Escalation(*row) if row else None

    def _get(self, db: sqlite3.Connection, escalation_id: str) -> Escalation | None:
        return self._row(db.execute(f"SELECT {_COLUMNS} FROM escalations WHERE id = ?", (escalation_id,)).fetchone())

    @staticmethod
    def _expire(db: sqlite3.Connection, now: float) -> None:
        db.execute("UPDATE escalations SET status = 'expired' WHERE status IN ('pending','approved') AND expires_at <= ?", (now,))

    def _match(self, db: sqlite3.Connection, status: str, sub: str, tool: str, ahash: str, now: float) -> Escalation | None:
        return self._row(
            db.execute(
                f"SELECT {_COLUMNS} FROM escalations WHERE status = ? AND sub = ? AND tool = ? AND args_hash = ? "
                "AND expires_at > ? ORDER BY created_at, rowid LIMIT 1",
                (status, sub, tool, ahash, now),
            ).fetchone()
        )

    # ---- proxy side ------------------------------------------------------
    def on_escalate(self, sub: str, tool: str, ahash: str, reason_code: str) -> EscalationOutcome:
        now = self._clock()
        with self._tx() as db:
            self._expire(db, now)
            approved = self._match(db, "approved", sub, tool, ahash, now)
            if approved is not None:
                # Allow only if this transaction moved the row approved -> consumed.
                # (BEGIN IMMEDIATE already serializes writers; the status guard plus
                # rowcount check also make a stale read fail closed.)
                cur = db.execute(
                    "UPDATE escalations SET status = 'consumed', consumed_at = ? WHERE id = ? AND status = 'approved' AND expires_at > ?",
                    (now, approved.id, now),
                )
                if cur.rowcount == 1:
                    consumed = self._get(db, approved.id)
                    assert consumed is not None
                    return EscalationOutcome("allow", consumed)
            denied = self._match(db, "denied", sub, tool, ahash, now)
            if denied is not None:
                return EscalationOutcome("deny", denied)
            pending = self._match(db, "pending", sub, tool, ahash, now)
            if pending is not None:
                return EscalationOutcome("escalate", pending)
            new_id = secrets.token_hex(8)
            db.execute(
                f"INSERT INTO escalations ({_COLUMNS}) VALUES (?, ?, ?, ?, ?, 'pending', ?, ?, NULL, NULL, ?, ?)",
                (new_id, sub, tool, ahash, reason_code, now, now + self.pending_ttl, self.pending_ttl, self.approval_ttl),
            )
            created = self._get(db, new_id)
            assert created is not None
            return EscalationOutcome("escalate", created)

    # ---- human side ------------------------------------------------------
    def get(self, escalation_id: str) -> Escalation | None:
        with self._tx() as db:
            self._expire(db, self._clock())
            return self._get(db, escalation_id)

    def list(self, status: str | None = None) -> list[Escalation]:
        with self._tx() as db:
            self._expire(db, self._clock())
            if status is None:
                rows = db.execute(f"SELECT {_COLUMNS} FROM escalations ORDER BY created_at, rowid").fetchall()
            else:
                rows = db.execute(f"SELECT {_COLUMNS} FROM escalations WHERE status = ? ORDER BY created_at, rowid", (status,)).fetchall()
        return [Escalation(*r) for r in rows]

    def approve(self, escalation_id: str) -> Escalation:
        now = self._clock()
        with self._tx() as db:
            self._expire(db, now)
            cur = self._get(db, escalation_id)
            if cur is None:
                raise EscalationError(f"no escalation {escalation_id!r}")
            if cur.status != "pending":
                raise EscalationError(f"escalation {escalation_id} is {cur.status}; only pending can be approved")
            res = db.execute(
                "UPDATE escalations SET status = 'approved', decided_at = ?, expires_at = ? WHERE id = ? AND status = 'pending'",
                (now, now + cur.approval_ttl, escalation_id),
            )
            if res.rowcount != 1:
                raise EscalationError(f"escalation {escalation_id} changed before it could be approved; re-read it")
            out = self._get(db, escalation_id)
        assert out is not None
        return out

    def deny(self, escalation_id: str) -> Escalation:
        now = self._clock()
        with self._tx() as db:
            self._expire(db, now)
            cur = self._get(db, escalation_id)
            if cur is None:
                raise EscalationError(f"no escalation {escalation_id!r}")
            if cur.status not in ("pending", "approved"):
                raise EscalationError(f"escalation {escalation_id} is {cur.status}; only pending or approved can be denied")
            res = db.execute(
                "UPDATE escalations SET status = 'denied', decided_at = ?, expires_at = ? WHERE id = ? AND status IN ('pending','approved')",
                (now, now + cur.pending_ttl, escalation_id),
            )
            if res.rowcount != 1:
                raise EscalationError(f"escalation {escalation_id} changed before it could be denied; re-read it")
            out = self._get(db, escalation_id)
        assert out is not None
        return out
