"""Live claims-gate reverse proxy in front of an MCP Streamable HTTP server (kaia-mcp).

Every request on the MCP path must carry a bearer token that verifies against
the issuer's JWKS with the pinned issuer and audience (and, when configured,
is still active per RFC 7662 introspection). Token failures answer HTTP 401
with a JSON-RPC error and are never forwarded.

For JSON-RPC ``tools/call`` the claims policy decides:

- deny     -> JSON-RPC error ``-32050`` with ``data.reasonCode`` (``claims_*``); not forwarded
- escalate -> JSON-RPC error ``-32051`` with an escalation id; not forwarded.
              With an escalation queue (``claims_gate.escalations``) the request
              is recorded as pending; once a human approves it, exactly one
              retry with the same subject, tool, and arguments hash is
              forwarded. A human deny makes identical retries ``-32050``.
- allow    -> the original request is forwarded byte-for-byte, with its
              headers (including ``Authorization`` and ``Mcp-Session-Id``)

Other methods (``initialize``, ``tools/list``, notifications, responses, the
SSE ``GET`` and session ``DELETE``) are forwarded once the token is valid.
JSON-RPC batches and unparseable bodies are rejected (fail closed).

The proxy never logs or echoes a token. Logs and the audit file carry a
12-character sha256 fingerprint at most.

At startup the proxy compares its own kaia tool -> scope map with the one the
upstream publishes at ``/.well-known/kaia-mcp/tool-scopes`` and refuses to
start on any difference or if the map cannot be fetched (unless the drift
check is explicitly turned off). While running, ``DriftMonitor`` rechecks the
map every ``drift_interval`` seconds; on drift or a failed fetch every
``tools/call`` is denied (``claims_tool_scope_drift``) until the maps match
again. State transitions are logged and audited.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import logging
import sqlite3
import threading
import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlencode, urlsplit

import jwt

from claims_gate.escalations import args_hash
from claims_gate.policy import ToolPolicy
from claims_gate.reasons import ClaimsReason
from claims_gate.verify import (
    ClaimsFailure,
    VerifiedClaims,
    VerifierConfig,
    bearer_token,
    verify_access_token,
)

LOG = logging.getLogger("claims_gate.proxy")

DENY_CODE = -32050
ESCALATE_CODE = -32051
UPSTREAM_ERROR_CODE = -32052
INVALID_REQUEST_CODE = -32600

TOOL_SCOPES_PATH = "/.well-known/kaia-mcp/tool-scopes"
MAX_BODY_BYTES = 1_000_000

# RFC 7230 hop-by-hop headers plus ones the proxy recomputes.
_HOP_BY_HOP = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "trailers",
        "transfer-encoding",
        "upgrade",
        "host",
        "content-length",
    }
)

# Not copied from upstream responses; BaseHTTPRequestHandler writes its own.
_RESPONSE_SKIP = _HOP_BY_HOP | {"date", "server"}

JsonFetcher = Callable[..., Any]


class UpstreamError(Exception):
    """A metadata fetch (discovery, JWKS, introspection, tool map) failed."""


def fingerprint(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()[:12]


def http_json(
    url: str,
    *,
    method: str = "GET",
    form: Mapping[str, str] | None = None,
    basic_auth: tuple[str, str] | None = None,
    timeout: float = 5.0,
) -> tuple[int, Any]:
    """Minimal JSON-over-HTTP(S) client. Raises ``UpstreamError`` on transport or JSON errors."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise UpstreamError(f"unsupported url: {url!r}")
    conn_cls = http.client.HTTPSConnection if parts.scheme == "https" else http.client.HTTPConnection
    conn = conn_cls(parts.hostname, parts.port, timeout=timeout)
    path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    headers = {"Accept": "application/json"}
    body = None
    if form is not None:
        body = urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    if basic_auth is not None:
        raw = f"{basic_auth[0]}:{basic_auth[1]}".encode()
        headers["Authorization"] = "Basic " + base64.b64encode(raw).decode()
    try:
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        status = resp.status
    except (OSError, http.client.HTTPException) as err:
        raise UpstreamError(f"{method} {parts.netloc}{parts.path}: {type(err).__name__}") from err
    finally:
        conn.close()
    try:
        return status, json.loads(data) if data else None
    except ValueError as err:
        raise UpstreamError(f"{method} {parts.netloc}{parts.path}: non-JSON response") from err


def _origin(url: str) -> tuple[str, str, int | None]:
    p = urlsplit(url)
    return p.scheme, (p.hostname or "").lower(), p.port


def discover(issuer: str, *, fetch: JsonFetcher = http_json) -> dict[str, Any]:
    """Fetch OIDC discovery for ``issuer`` and require its ``issuer`` to match exactly."""
    status, doc = fetch(issuer.rstrip("/") + "/.well-known/openid-configuration")
    if status != 200 or not isinstance(doc, dict):
        raise UpstreamError(f"discovery returned HTTP {status}")
    if doc.get("issuer") != issuer:
        raise UpstreamError(f"discovery issuer {doc.get('issuer')!r} != pinned issuer {issuer!r}")
    return doc


class JwksCache:
    """JWKS with a TTL and a rate-limited refetch when a token names an unknown ``kid``.

    A stale cache is never served past its TTL: if the refetch fails, the
    caller gets ``UpstreamError`` and denies (``claims_jwks_unavailable``).
    """

    def __init__(
        self,
        jwks_uri: str,
        *,
        ttl_seconds: float = 300.0,
        min_refetch_seconds: float = 10.0,
        fetch: JsonFetcher = http_json,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.jwks_uri = jwks_uri
        self._ttl = ttl_seconds
        self._min_refetch = min_refetch_seconds
        self._fetch = fetch
        self._clock = clock
        self._lock = threading.Lock()
        self._jwks: dict[str, Any] | None = None
        self._fetched_at = float("-inf")
        self.fetch_count = 0

    def _refresh(self) -> None:
        self.fetch_count += 1
        status, doc = self._fetch(self.jwks_uri)
        if status != 200 or not isinstance(doc, dict) or not isinstance(doc.get("keys"), list):
            raise UpstreamError(f"jwks returned HTTP {status}")
        self._jwks = doc
        self._fetched_at = self._clock()

    def get(self, kid: str | None) -> dict[str, Any]:
        with self._lock:
            now = self._clock()
            stale = self._jwks is None or now - self._fetched_at >= self._ttl
            known = self._jwks is not None and (
                kid is None or any(k.get("kid") == kid for k in self._jwks["keys"] if isinstance(k, dict))
            )
            if stale or (not known and now - self._fetched_at >= self._min_refetch):
                try:
                    self._refresh()
                except UpstreamError:
                    if stale:
                        self._jwks = None
                        raise
            assert self._jwks is not None
            return self._jwks


@dataclass
class Introspector:
    """RFC 7662 client (``client_secret_basic``). Any failure is reported, never ignored."""

    url: str
    client_id: str
    client_secret: str = field(repr=False)
    timeout: float = 3.0
    fetch: JsonFetcher = http_json

    def check(self, token: str) -> ClaimsReason | None:
        try:
            status, doc = self.fetch(
                self.url,
                method="POST",
                form={"token": token, "token_type_hint": "access_token"},
                basic_auth=(self.client_id, self.client_secret),
                timeout=self.timeout,
            )
        except UpstreamError:
            return ClaimsReason.INTROSPECTION_UNAVAILABLE
        if status != 200 or not isinstance(doc, dict) or not isinstance(doc.get("active"), bool):
            return ClaimsReason.INTROSPECTION_UNAVAILABLE
        return None if doc["active"] else ClaimsReason.TOKEN_REVOKED


def check_tool_scope_drift(
    url: str, expected: Mapping[str, str], *, fetch: JsonFetcher = http_json
) -> dict[str, Any]:
    """Compare ``expected`` with the upstream's published map. Returns a report; ``ok`` False on any drift."""
    try:
        status, doc = fetch(url)
    except UpstreamError as err:
        return {"ok": False, "url": url, "error": str(err)}
    if status != 200 or not isinstance(doc, dict) or not isinstance(doc.get("tool_scopes"), dict):
        return {"ok": False, "url": url, "error": f"HTTP {status} or no tool_scopes"}
    upstream: dict[str, Any] = doc["tool_scopes"]
    missing = sorted(set(upstream) - set(expected))
    extra = sorted(set(expected) - set(upstream))
    changed = sorted(t for t in set(upstream) & set(expected) if upstream[t] != expected[t])
    return {
        "ok": not (missing or extra or changed),
        "url": url,
        "upstreamTools": len(upstream),
        "gateTools": len(expected),
        "missingFromGate": missing,
        "notUpstream": extra,
        "scopeChanged": {t: {"gate": expected[t], "upstream": upstream[t]} for t in changed},
    }


class DriftMonitor:
    """Periodic tool-scope drift recheck. Closed (``ok`` False) until a check passes, and on any failure."""

    def __init__(
        self,
        url: str,
        expected: Mapping[str, str],
        *,
        interval: float = 60.0,
        fetch: JsonFetcher = http_json,
        audit: Callable[[dict[str, Any]], None] | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if interval <= 0:
            raise ValueError("drift interval must be positive")
        self.url = url
        self.expected = dict(expected)
        self.interval = float(interval)
        self._fetch = fetch
        self._audit = audit
        self._clock = clock
        self._lock = threading.Lock()
        self._ok: bool | None = None  # None = never checked (treated as closed)
        self._report: dict[str, Any] = {"ok": False, "url": url, "error": "not checked yet"}
        self._checked_at: float | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def ok(self) -> bool:
        return self._ok is True

    @property
    def report(self) -> dict[str, Any]:
        with self._lock:
            return dict(self._report)

    def status(self) -> dict[str, Any]:
        with self._lock:
            return {"ok": self._ok is True, "checkedAt": self._checked_at, "intervalSeconds": self.interval, "url": self.url}

    def record(self, report: dict[str, Any]) -> dict[str, Any]:
        """Store a check result and log/audit a state transition."""
        ok = report.get("ok") is True
        with self._lock:
            prev = self._ok
            self._ok, self._report, self._checked_at = ok, dict(report), self._clock()
        if prev is not None and prev != ok:
            if ok:
                LOG.warning("tool-scope map drift -> ok: tools/call allowed again (%s)", self.url)
            else:
                summary = {k: report[k] for k in ("error", "missingFromGate", "notUpstream", "scopeChanged") if report.get(k)}
                LOG.warning("tool-scope map ok -> drift: denying every tools/call until the maps match (%s) %s", self.url, json.dumps(summary, sort_keys=True))
            if self._audit is not None:
                self._audit({"ts": time.time(), "event": "drift_recovered" if ok else "drift_failing", "stage": "drift", "drift": report})
        return report

    def check_once(self) -> dict[str, Any]:
        try:
            report = check_tool_scope_drift(self.url, self.expected, fetch=self._fetch)
        except Exception as err:  # noqa: BLE001 - any failure closes the gate
            report = {"ok": False, "url": self.url, "error": f"{type(err).__name__}"}
        return self.record(report)

    def _run(self) -> None:
        while not self._stop.wait(self.interval):
            self.check_once()

    def start(self) -> None:
        if self._thread is None:
            self._thread = threading.Thread(target=self._run, name="claims-gate-drift", daemon=True)
            self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)


@dataclass
class ProxyConfig:
    upstream: str
    issuer: str
    audience: str
    policy: ToolPolicy
    jwks: JwksCache
    introspector: Introspector | None = None
    mcp_path: str = "/"
    upstream_timeout: float = 120.0
    audit: Callable[[dict[str, Any]], None] | None = None
    algorithms: tuple[str, ...] = ("RS256", "ES256")
    escalations: Any = None  # claims_gate.escalations.EscalationStore, or None (escalations are terminal)
    drift: DriftMonitor | None = None  # None: startup check only (or drift check off)


@dataclass(frozen=True)
class TokenCheck:
    claims: VerifiedClaims | None
    reason: ClaimsReason | None
    fp: str | None


def check_token(config: ProxyConfig, authorization: str | None) -> TokenCheck:
    """JWT verification against the cached JWKS, then optional introspection."""
    token = bearer_token(authorization)
    if not token:
        return TokenCheck(None, ClaimsReason.UNAUTHENTICATED, None)
    fp = fingerprint(token)
    try:
        kid = jwt.get_unverified_header(token).get("kid")
    except jwt.PyJWTError:
        return TokenCheck(None, ClaimsReason.INVALID_TOKEN, fp)
    try:
        jwks = config.jwks.get(kid if isinstance(kid, str) else None)
    except UpstreamError:
        return TokenCheck(None, ClaimsReason.JWKS_UNAVAILABLE, fp)
    verified = verify_access_token(
        token,
        VerifierConfig(jwks=jwks, issuer=config.issuer, audience=config.audience, algorithms=config.algorithms),
    )
    if isinstance(verified, ClaimsFailure):
        return TokenCheck(None, verified.reason, fp)
    if config.introspector is not None:
        reason = config.introspector.check(token)
        if reason is not None:
            return TokenCheck(None, reason, fp)
    return TokenCheck(verified, None, fp)


def _jsonrpc_error(rpc_id: Any, code: int, message: str, data: Mapping[str, Any]) -> bytes:
    return json.dumps({"jsonrpc": "2.0", "id": rpc_id, "error": {"code": code, "message": message, "data": dict(data)}}).encode()


class _Handler(BaseHTTPRequestHandler):
    server_version = "s1-tool-gate-proxy"
    sys_version = ""
    config: ProxyConfig  # set by make_server

    # Close-delimited responses keep SSE pass-through simple.
    protocol_version = "HTTP/1.0"

    def log_message(self, format: str, *args: Any) -> None:
        # The default access log is off: request lines are harmless, but keep one structured line per request instead.
        return

    # ---- helpers -------------------------------------------------------
    def _record(self, **fields: Any) -> None:
        fields.setdefault("ts", time.time())
        fields.setdefault("httpMethod", self.command)
        LOG.info("proxy %s", json.dumps(fields, sort_keys=True))
        if self.config.audit is not None:
            self.config.audit(fields)

    def _send(self, status: int, body: bytes, headers: Mapping[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def _base_url(self) -> str:
        host = self.headers.get("Host") or f"{self.server.server_address[0]}:{self.server.server_address[1]}"
        return f"http://{host}"

    def _deny_token(self, check: TokenCheck, rpc_id: Any, rpc_method: str | None) -> None:
        assert check.reason is not None
        reason = check.reason.value
        www = (
            f'Bearer realm="s1-tool-gate", error="invalid_token", '
            f'resource_metadata="{self._base_url()}/.well-known/oauth-protected-resource"'
        )
        if check.reason is ClaimsReason.UNAUTHENTICATED:
            www = f'Bearer realm="s1-tool-gate", resource_metadata="{self._base_url()}/.well-known/oauth-protected-resource"'
        self._record(event="deny", stage="token", reasonCode=reason, rpcMethod=rpc_method, tokenFp=check.fp, forwarded=False)
        self._send(
            401,
            _jsonrpc_error(rpc_id, DENY_CODE, f"s1-tool-gate denied: {reason}", {"reasonCode": reason, "choice": "deny"}),
            {"WWW-Authenticate": www},
        )

    def _read_body(self) -> bytes | None:
        length = self.headers.get("Content-Length")
        if length is None:
            return b""
        try:
            n = int(length)
        except ValueError:
            return None
        if n < 0 or n > MAX_BODY_BYTES:
            return None
        return self.rfile.read(n)

    # ---- routing -------------------------------------------------------
    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path == "/health" and self.config.mcp_path != "/health":
            tool_scopes = self.config.drift.status() if self.config.drift is not None else {"periodic": False}
            self._send(200, json.dumps({"status": "ok", "server": "s1-tool-gate-proxy", "issuer": self.config.issuer, "audience": self.config.audience, "introspection": self.config.introspector is not None, "toolScopes": tool_scopes}).encode())
            return
        if path == "/.well-known/oauth-protected-resource":
            self._send(200, json.dumps({"resource": self._base_url() + self.config.mcp_path, "authorization_servers": [self.config.issuer], "bearer_methods_supported": ["header"], "resource_name": "kaia-mcp via s1-tool-gate"}).encode())
            return
        self._handle_mcp(body=None)

    def do_POST(self) -> None:
        body = self._read_body()
        if body is None:
            self._record(event="deny", stage="request", reasonCode=ClaimsReason.MALFORMED_REQUEST.value, forwarded=False)
            self._send(413, _jsonrpc_error(None, INVALID_REQUEST_CODE, "request body missing length or too large", {"reasonCode": ClaimsReason.MALFORMED_REQUEST.value}))
            return
        self._handle_mcp(body=body)

    def do_DELETE(self) -> None:
        self._handle_mcp(body=None)

    def _handle_mcp(self, body: bytes | None) -> None:
        if urlsplit(self.path).path != self.config.mcp_path:
            self._send(404, json.dumps({"error": "not_found"}).encode())
            return

        message: Any = None
        rpc_id: Any = None
        rpc_method: str | None = None
        if body:
            try:
                message = json.loads(body)
            except ValueError:
                message = None
            if isinstance(message, dict):
                rpc_id = message.get("id")
                rpc_method = message.get("method") if isinstance(message.get("method"), str) else None

        check = check_token(self.config, self.headers.get("Authorization"))
        if check.reason is not None:
            self._deny_token(check, rpc_id, rpc_method)
            return
        assert check.claims is not None

        if body is not None and self.command == "POST":
            if not isinstance(message, dict):
                reason = ClaimsReason.MALFORMED_REQUEST.value
                why = "JSON-RPC batches are not accepted" if isinstance(message, list) else "body is not a JSON-RPC object"
                self._record(event="deny", stage="request", reasonCode=reason, tokenFp=check.fp, forwarded=False, detail=why)
                self._send(400, _jsonrpc_error(None, INVALID_REQUEST_CODE, f"s1-tool-gate: {why}", {"reasonCode": reason, "choice": "deny"}))
                return
            if rpc_method == "tools/call":
                params = message.get("params")
                tool = params.get("name") if isinstance(params, dict) else None
                if not isinstance(tool, str) or not tool:
                    reason = ClaimsReason.MALFORMED_REQUEST.value
                    self._record(event="deny", stage="request", reasonCode=reason, rpcMethod=rpc_method, tokenFp=check.fp, forwarded=False)
                    self._send(200, _jsonrpc_error(rpc_id, INVALID_REQUEST_CODE, "s1-tool-gate: tools/call without params.name", {"reasonCode": reason, "choice": "deny"}))
                    return
                drift = self.config.drift
                if drift is not None and not drift.ok:
                    reason = ClaimsReason.TOOL_SCOPE_DRIFT.value
                    report = drift.report
                    self._record(event="deny", stage="drift", reasonCode=reason, choice="deny", rpcMethod=rpc_method, tool=tool, subject=check.claims.subject, tokenFp=check.fp, forwarded=False)
                    self._send(200, _jsonrpc_error(rpc_id, DENY_CODE, f"s1-tool-gate denied {tool}: {reason} (upstream tool-scope map differs or is unavailable; failing closed)", {"reasonCode": reason, "choice": "deny", "tool": tool, "drift": report}))
                    return
                decision = self.config.policy.decide(check.claims, tool)
                base = {
                    "rpcMethod": rpc_method,
                    "tool": tool,
                    "subject": check.claims.subject,
                    "tokenFp": check.fp,
                    "requiredScope": self.config.policy.required_scope(tool),
                    "reasonCode": decision.reason_code,
                    "choice": decision.choice,
                }
                if decision.choice == "deny":
                    self._record(event="deny", stage="policy", forwarded=False, **base)
                    self._send(200, _jsonrpc_error(rpc_id, DENY_CODE, f"s1-tool-gate denied {tool}: {decision.reason_code}", {"reasonCode": decision.reason_code, "choice": "deny", "tool": tool, "requiredScope": base["requiredScope"]}))
                    return
                if decision.choice == "escalate":
                    self._escalate(body, rpc_id, tool, params, check.claims.subject, decision.reason_code, base)
                    return
                self._forward(body, event_fields={"event": "allow", "stage": "policy", **base})
                return
        self._forward(body, event_fields={"event": "forward", "stage": "token", "rpcMethod": rpc_method, "tokenFp": check.fp, "subject": check.claims.subject})

    def _escalate(self, body: bytes, rpc_id: Any, tool: str, params: dict[str, Any], subject: str, reason_code: str, base: dict[str, Any]) -> None:
        """Escalate, or let one human-approved retry through. Any queue error fails closed."""
        store = self.config.escalations
        if store is None:
            escalation_id = str(uuid.uuid4())
            self._record(event="escalate", stage="policy", forwarded=False, escalationId=escalation_id, escalationStatus="not_queued", **base)
            self._send(200, _jsonrpc_error(rpc_id, ESCALATE_CODE, f"s1-tool-gate escalated {tool}: human review required; not executed", {"reasonCode": reason_code, "choice": "escalate", "tool": tool, "escalationId": escalation_id, "escalationStatus": "not_queued"}))
            return
        ahash = args_hash(params.get("arguments"))
        try:
            outcome = store.on_escalate(subject, tool, ahash, reason_code)
        except (sqlite3.Error, OSError) as err:
            reason = ClaimsReason.ESCALATION_UNAVAILABLE.value
            self._record(event="deny", stage="escalation", forwarded=False, queueError=type(err).__name__, **{**base, "reasonCode": reason, "choice": "deny"})
            self._send(200, _jsonrpc_error(rpc_id, DENY_CODE, f"s1-tool-gate denied {tool}: {reason}", {"reasonCode": reason, "choice": "deny", "tool": tool}))
            return
        esc = outcome.escalation
        fields = {"escalationId": esc.id, "escalationStatus": esc.status, "argsHash": ahash}
        if outcome.action == "allow":
            self._forward(body, event_fields={"event": "allow", "stage": "escalation", **base, "choice": "allow", **fields})
            return
        if outcome.action == "deny":
            reason = ClaimsReason.ESCALATION_DENIED.value
            self._record(event="deny", stage="escalation", forwarded=False, **{**base, "reasonCode": reason, "choice": "deny"}, **fields)
            self._send(200, _jsonrpc_error(rpc_id, DENY_CODE, f"s1-tool-gate denied {tool}: {reason}", {"reasonCode": reason, "choice": "deny", "tool": tool, "escalationId": esc.id}))
            return
        self._record(event="escalate", stage="policy", forwarded=False, **base, **fields)
        self._send(
            200,
            _jsonrpc_error(
                rpc_id,
                ESCALATE_CODE,
                f"s1-tool-gate escalated {tool}: human review required; not executed (escalation {esc.id})",
                {"reasonCode": reason_code, "choice": "escalate", "tool": tool, **fields, "expiresAt": esc.expires_at},
            ),
        )

    def _forward(self, body: bytes | None, *, event_fields: dict[str, Any]) -> None:
        up = urlsplit(self.config.upstream)
        conn_cls = http.client.HTTPSConnection if up.scheme == "https" else http.client.HTTPConnection
        conn = conn_cls(up.hostname, up.port, timeout=self.config.upstream_timeout)
        query = urlsplit(self.path).query
        target = (up.path.rstrip("/") + self.config.mcp_path) or "/"
        if query:
            target += "?" + query
        headers = {k: v for k, v in self.headers.items() if k.lower() not in _HOP_BY_HOP}
        try:
            conn.putrequest(self.command, target, skip_accept_encoding=True)
            for k, v in headers.items():
                conn.putheader(k, v)
            if body is not None and self.command == "POST":
                conn.putheader("Content-Length", str(len(body)))
            conn.endheaders(body if body else None)
            resp = conn.getresponse()
        except (OSError, http.client.HTTPException) as err:
            conn.close()
            self._record(forwarded=False, upstreamError=type(err).__name__, **{**event_fields, "event": "upstream_error"})
            self._send(502, _jsonrpc_error(None, UPSTREAM_ERROR_CODE, "s1-tool-gate: upstream unavailable", {"choice": event_fields.get("choice", "allow")}))
            return
        self._record(forwarded=True, upstreamStatus=resp.status, **event_fields)
        try:
            self.send_response(resp.status, resp.reason)
            for k, v in resp.getheaders():
                if k.lower() not in _RESPONSE_SKIP:
                    self.send_header(k, v)
            length = resp.getheader("Content-Length")
            if length is not None:
                self.send_header("Content-Length", length)
            self.send_header("Connection", "close")
            self.end_headers()
            while True:
                chunk = resp.read1(65536)
                if not chunk:
                    break
                self.wfile.write(chunk)
                self.wfile.flush()
        except (OSError, http.client.HTTPException):
            pass
        finally:
            conn.close()


def make_server(config: ProxyConfig, host: str = "127.0.0.1", port: int = 0) -> ThreadingHTTPServer:
    handler = type("ClaimsGateProxyHandler", (_Handler,), {"config": config})
    server = ThreadingHTTPServer((host, port), handler)
    server.daemon_threads = True
    return server


@dataclass
class StartupReport:
    issuer: str
    audience: str
    jwks_uri: str
    introspection_url: str | None
    drift: dict[str, Any] | None
    errors: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "issuer": self.issuer,
            "audience": self.audience,
            "jwksUri": self.jwks_uri,
            "introspectionUrl": self.introspection_url,
            "drift": self.drift,
            "errors": self.errors,
        }


def build_config(
    *,
    upstream: str,
    issuer: str,
    audience: str,
    policy: ToolPolicy,
    jwks_uri: str | None = None,
    introspection: str | None = None,
    introspection_client_id: str | None = None,
    introspection_client_secret: str | None = None,
    tool_scopes_url: str | None = None,
    drift_check: bool = True,
    drift_interval: float = 60.0,
    jwks_ttl_seconds: float = 300.0,
    mcp_path: str = "/",
    audit: Callable[[dict[str, Any]], None] | None = None,
    escalations: Any = None,
    fetch: JsonFetcher = http_json,
) -> tuple[ProxyConfig | None, StartupReport]:
    """Resolve discovery, JWKS, introspection, and the drift check. Fail closed: any error -> no config.

    ``introspection`` is ``None`` (off), ``"auto"`` (discovery's ``introspection_endpoint``),
    or an explicit URL. When introspection is on, missing credentials are an error.
    """
    errors: list[str] = []
    resolved_jwks = jwks_uri
    introspection_url: str | None = None
    try:
        doc = discover(issuer, fetch=fetch)
    except UpstreamError as err:
        doc = {}
        if jwks_uri is None or introspection == "auto":
            errors.append(f"discovery: {err}")
    if resolved_jwks is None:
        resolved_jwks = doc.get("jwks_uri") if isinstance(doc.get("jwks_uri"), str) else None
        if resolved_jwks is None and not errors:
            errors.append("discovery has no jwks_uri")
        elif resolved_jwks is not None and _origin(resolved_jwks) != _origin(issuer):
            errors.append(f"jwks_uri {resolved_jwks!r} is not on the issuer origin; pass --jwks-uri to trust it explicitly")
    if introspection == "auto":
        introspection_url = doc.get("introspection_endpoint") if isinstance(doc.get("introspection_endpoint"), str) else None
        if introspection_url is None and not errors:
            errors.append("introspection=auto but discovery has no introspection_endpoint")
        elif introspection_url is not None and _origin(introspection_url) != _origin(issuer):
            errors.append("introspection_endpoint is not on the issuer origin")
    elif introspection:
        introspection_url = introspection
    introspector = None
    if introspection_url:
        if not introspection_client_id or not introspection_client_secret:
            errors.append("introspection is configured but S1_INTROSPECTION_CLIENT_ID/SECRET are not set")
        else:
            introspector = Introspector(introspection_url, introspection_client_id, introspection_client_secret, fetch=fetch)

    drift = None
    monitor = None
    if drift_check:
        scopes_url = tool_scopes_url or upstream.rstrip("/") + TOOL_SCOPES_PATH
        drift = check_tool_scope_drift(scopes_url, policy.tool_scopes, fetch=fetch)
        if not drift["ok"]:
            errors.append("tool-scope drift check failed")
        elif drift_interval > 0:
            monitor = DriftMonitor(scopes_url, policy.tool_scopes, interval=drift_interval, fetch=fetch, audit=audit)
            monitor.record(drift)

    cache = JwksCache(resolved_jwks or "", ttl_seconds=jwks_ttl_seconds, fetch=fetch)
    if resolved_jwks and not errors:
        try:
            cache.get(None)
        except UpstreamError as err:
            errors.append(f"jwks: {err}")

    report = StartupReport(issuer, audience, resolved_jwks or "", introspection_url, drift, errors)
    if errors:
        return None, report
    return (
        ProxyConfig(
            upstream=upstream,
            issuer=issuer,
            audience=audience,
            policy=policy,
            jwks=cache,
            introspector=introspector,
            mcp_path=mcp_path,
            audit=audit,
            escalations=escalations,
            drift=monitor,
        ),
        report,
    )
