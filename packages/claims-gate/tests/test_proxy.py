"""Offline tests for claims_gate.proxy against an in-process fake kaia-mcp.

The fake serves discovery, JWKS, introspection, the tool-scope map, and an MCP
endpoint that records every request it receives. Keys are TEST-ONLY and made
at run time.
"""

from __future__ import annotations

import http.client
import json
import logging
import socket
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest
from claims_gate.escalations import EscalationStore, args_hash
from claims_gate.kaia import KAIA_TOOL_SCOPES, kaia_policy
from claims_gate.proxy import (
    DEFAULT_INTROSPECTION_CACHE_TTL,
    DENY_CODE,
    ESCALATE_CODE,
    DriftMonitor,
    Introspector,
    JwksCache,
    UpstreamError,
    build_config,
    check_tool_scope_drift,
    make_server,
)
from claims_gate.reasons import ClaimsReason
from claims_gate.testkit import TestSigner, build_claims, unsigned_token

GATEWAY = ("gw-client", "gw-test-secret")


@dataclass
class FakeKaia:
    signer: TestSigner
    issuer: str = ""
    revoked: set[str] = field(default_factory=set)
    introspection_status: int = 200
    tool_scopes_status: int = 200
    tool_scopes: dict[str, str] = field(default_factory=lambda: dict(KAIA_TOOL_SCOPES))
    mcp_requests: list[dict[str, Any]] = field(default_factory=list)
    jwks_fetches: int = 0
    introspection_calls: int = 0
    sse: bool = False
    legacy_session: bool = False  # answer with an Mcp-Session-Id like a pre-2026-07-28 server
    canned: tuple[int, list[tuple[str, str]], bytes] | None = None  # exact MCP response to send


def _fake_handler(state: FakeKaia) -> type[BaseHTTPRequestHandler]:
    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args: Any) -> None:
            return

        def _json(self, status: int, body: Any, headers: dict[str, str] | None = None) -> None:
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self) -> None:
            if self.path == "/.well-known/openid-configuration":
                self._json(200, {"issuer": state.issuer, "jwks_uri": state.issuer + "/oauth/jwks", "introspection_endpoint": state.issuer + "/oauth/introspect"})
            elif self.path == "/oauth/jwks":
                state.jwks_fetches += 1
                self._json(200, state.signer.jwks())
            elif self.path == "/.well-known/kaia-mcp/tool-scopes":
                self._json(state.tool_scopes_status, {"resource": "kaia-mcp", "tool_scopes": state.tool_scopes})
            else:
                self._mcp(b"")

        def do_DELETE(self) -> None:
            self._mcp(b"")

        def do_POST(self) -> None:
            body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            if self.path == "/oauth/introspect":
                import base64

                state.introspection_calls += 1

                expected = "Basic " + base64.b64encode(f"{GATEWAY[0]}:{GATEWAY[1]}".encode()).decode()
                if self.headers.get("Authorization") != expected:
                    self._json(401, {"error": "invalid_client"})
                    return
                if state.introspection_status != 200:
                    self._json(state.introspection_status, {"error": "server_error"})
                    return
                from urllib.parse import parse_qs

                token = parse_qs(body.decode())["token"][0]
                self._json(200, {"active": token not in state.revoked})
                return
            self._mcp(body)

        def _mcp(self, body: bytes) -> None:
            state.mcp_requests.append({"method": self.command, "path": self.path, "headers": dict(self.headers.items()), "body": body})
            if state.canned is not None:
                status, headers, data = state.canned
                self.send_response(status)
                for k, v in headers:
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return
            if state.sse:
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                if state.legacy_session:
                    self.send_header("Mcp-Session-Id", "sess-123")
                self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()
                for i in range(3):
                    chunk = f"event: message\ndata: {{\"n\":{i}}}\n\n".encode()
                    self.wfile.write(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
                    self.wfile.flush()
                self.wfile.write(b"0\r\n\r\n")
                return
            msg = json.loads(body) if body else {}
            self._json(200, {"jsonrpc": "2.0", "id": msg.get("id"), "result": {"echo": msg.get("method")}}, {"Mcp-Session-Id": "sess-123"} if state.legacy_session else None)

    return H


@dataclass
class Rig:
    fake: FakeKaia
    proxy_port: int
    audit: list[dict[str, Any]]
    now: float
    config: Any = None

    def token(self, scope: str = "kaia:read", *, signer: TestSigner | None = None, **kw: Any) -> str:
        claims = build_claims(now=self.now, iss=kw.pop("iss", self.fake.issuer), scope=scope, **kw)
        claims["jti"] = f"jti-{time.monotonic_ns()}"
        return (signer or self.fake.signer).mint(claims)

    def post(self, body: Any, token: str | None, headers: dict[str, str] | None = None) -> tuple[int, dict[str, str], bytes]:
        conn = http.client.HTTPConnection("127.0.0.1", self.proxy_port, timeout=10)
        h = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream", **(headers or {})}
        if token is not None:
            h["Authorization"] = f"Bearer {token}"
        conn.request("POST", "/", body=json.dumps(body) if not isinstance(body, bytes) else body, headers=h)
        r = conn.getresponse()
        data = r.read()
        conn.close()
        return r.status, {k.lower(): v for k, v in r.getheaders()}, data


class _FakeUpstreamServer(ThreadingHTTPServer):
    # Same backlog as the proxy, so a concurrency test measures the proxy, not this fake
    # (socketserver's default of 5 made the fake drop forwarded/introspection connections).
    request_queue_size = 128
    daemon_threads = True


def _serve(server: ThreadingHTTPServer) -> threading.Thread:
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return t


class RawTap:
    """TCP relay that records every byte the proxy sends upstream, one entry per connection."""

    def __init__(self) -> None:
        self._sock = socket.socket()
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(16)
        self.port: int = self._sock.getsockname()[1]
        self.connections: list[bytearray] = []
        self._lock = threading.Lock()
        self._target = 0

    def start(self, target_port: int) -> None:
        self._target = target_port
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self) -> None:
        while True:
            try:
                client, _ = self._sock.accept()
            except OSError:
                return
            seen = bytearray()
            with self._lock:
                self.connections.append(seen)
            upstream = socket.create_connection(("127.0.0.1", self._target))
            threading.Thread(target=self._pump, args=(client, upstream, seen), daemon=True).start()
            threading.Thread(target=self._pump, args=(upstream, client, None), daemon=True).start()

    @staticmethod
    def _pump(src: socket.socket, dst: socket.socket, record: bytearray | None) -> None:
        try:
            while data := src.recv(65536):
                if record is not None:
                    record.extend(data)
                dst.sendall(data)
        except OSError:
            pass
        finally:
            for s in (src, dst):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def raw(self) -> list[bytes]:
        with self._lock:
            return [bytes(c) for c in self.connections]

    def close(self) -> None:
        self._sock.close()


@pytest.fixture
def rig_factory() -> Iterator[Any]:
    servers: list[ThreadingHTTPServer] = []
    taps: list[RawTap] = []

    def make(*, introspection: bool = True, audience: str = "kaia-mcp", fake: FakeKaia | None = None, tap: RawTap | None = None, **config_kw: Any) -> Rig:
        fake = fake or FakeKaia(signer=TestSigner.generate(kid="kid-1"))
        upstream = _FakeUpstreamServer(("127.0.0.1", 0), _fake_handler(fake))
        servers.append(upstream)
        _serve(upstream)
        fake.issuer = f"http://127.0.0.1:{upstream.server_address[1]}"
        mcp_upstream = fake.issuer
        if tap is not None:
            # Only MCP traffic goes through the tap; metadata is fetched from the fake directly.
            tap.start(upstream.server_address[1])
            taps.append(tap)
            mcp_upstream = f"http://127.0.0.1:{tap.port}"
            config_kw.setdefault("tool_scopes_url", fake.issuer + "/.well-known/kaia-mcp/tool-scopes")
        audit: list[dict[str, Any]] = []
        config, report = build_config(
            upstream=mcp_upstream,
            issuer=fake.issuer,
            audience=audience,
            policy=kaia_policy(),
            introspection="auto" if introspection else None,
            introspection_client_id=GATEWAY[0],
            introspection_client_secret=GATEWAY[1],
            audit=audit.append,
            **config_kw,
        )
        assert config is not None, report.errors
        proxy = make_server(config)
        servers.append(proxy)
        _serve(proxy)
        return Rig(fake, proxy.server_address[1], audit, time.time(), config)

    yield make
    for s in servers:
        s.shutdown()
        s.server_close()
    for t in taps:
        t.close()


def _err(data: bytes) -> dict[str, Any]:
    return json.loads(data)["error"]


CALL = lambda tool, i=1, args=None: {"jsonrpc": "2.0", "id": i, "method": "tools/call", "params": {"name": tool, "arguments": args if args is not None else {}}}


def test_allow_forwards_body_and_auth_unchanged_without_a_session(rig_factory: Any) -> None:
    """kaia-mcp is stateless (MCP 2026-07-28): a client's stale Mcp-Session-Id is never forwarded."""
    fake = FakeKaia(signer=TestSigner.generate(kid="kid-1"), legacy_session=True)
    rig = rig_factory(fake=fake)
    tok = rig.token("kaia:read")
    body = json.dumps(CALL("get_block_number", 7)).encode()
    status, headers, data = rig.post(body, tok, {"Mcp-Session-Id": "stale-legacy-session", "Mcp-Method": "tools/call", "Mcp-Name": "get_block_number"})
    assert status == 200
    assert json.loads(data)["result"] == {"echo": "tools/call"}
    assert "mcp-session-id" not in headers  # nor is an upstream one handed back to the client
    [seen] = rig.fake.mcp_requests
    assert seen["body"] == body
    assert "mcp-session-id" not in {k.lower() for k in seen["headers"]}
    assert seen["headers"]["Authorization"] == f"Bearer {tok}"
    assert (seen["headers"]["Mcp-Method"], seen["headers"]["Mcp-Name"]) == ("tools/call", "get_block_number")
    assert rig.audit[-1]["event"] == "allow" and rig.audit[-1]["forwarded"] is True


def test_decision_uses_the_body_not_mcp_name_headers(rig_factory: Any) -> None:
    """Mcp-Method/Mcp-Name are forwarded as-is but never trusted: the gate decides on what kaia executes."""
    rig = rig_factory()
    status, _, data = rig.post(CALL("encode_function_data"), rig.token("kaia:read"), {"Mcp-Method": "tools/call", "Mcp-Name": "get_block_number"})
    err = _err(data)
    assert (status, err["code"], err["data"]["reasonCode"], err["data"]["tool"]) == (200, DENY_CODE, "claims_insufficient_scope", "encode_function_data")
    assert rig.fake.mcp_requests == []


# Captured live from kaia-mcp 00f3511 (a token without kaia:encode calling encode_function_data), port normalized;
# re-captured at 5794969 (MCP SDK v2): same status, headers, challenge and JSON body.
KAIA_403_WWW = (
    'Bearer realm="kaia-mcp", error="insufficient_scope", scope="kaia:encode", '
    'resource_metadata="http://127.0.0.1:3100/.well-known/oauth-protected-resource", '
    'error_description="insufficient_scope: encode_function_data requires kaia:encode"'
)
KAIA_403_BODY = json.dumps({"jsonrpc": "2.0", "id": 5, "error": {"code": -32042, "message": "insufficient_scope: encode_function_data requires kaia:encode", "data": {"error": "insufficient_scope"}}}).encode()


@pytest.mark.parametrize(
    ("method", "canned"),
    [
        ("POST", (403, [("Content-Type", "application/json"), ("Cache-Control", "no-store"), ("WWW-Authenticate", KAIA_403_WWW)], KAIA_403_BODY)),
        ("POST", (403, [("Content-Type", "application/json"), ("Cache-Control", "no-store")], b'{"jsonrpc":"2.0","error":{"code":-32000,"message":"Forbidden: Origin not allowed"}}')),
        ("GET", (405, [("Content-Type", "application/json"), ("Allow", "POST")], b'{"jsonrpc":"2.0","error":{"code":-32000,"message":"Method not allowed: the MCP endpoint accepts POST only"},"id":null}')),
        ("DELETE", (405, [("Content-Type", "application/json"), ("Allow", "POST")], b'{"jsonrpc":"2.0","error":{"code":-32000,"message":"Method not allowed: the MCP endpoint accepts POST only"},"id":null}')),
    ],
    ids=["403-insufficient-scope", "403-origin", "405-get", "405-delete"],
)
def test_upstream_errors_and_challenges_pass_through_unchanged(rig_factory: Any, method: str, canned: Any) -> None:
    """kaia's own 403 (insufficient_scope + WWW-Authenticate, Origin) and 405 reach the client as sent.

    The proxy only answers itself for its own decisions (401 token, -32050/-32051 policy);
    anything kaia says after a forward is relayed, status, challenge and body unchanged.
    """
    fake = FakeKaia(signer=TestSigner.generate(kid="kid-1"), canned=canned)
    rig = rig_factory(fake=fake)
    tok = rig.token("kaia:read kaia:encode")
    conn = http.client.HTTPConnection("127.0.0.1", rig.proxy_port, timeout=10)
    body = json.dumps(CALL("encode_function_data", 5, BALANCE_OF_LIKE)).encode() if method == "POST" else None
    conn.request(method, "/", body=body, headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json", "Accept": "application/json, text/event-stream", "Origin": "http://evil.example"})
    r = conn.getresponse()
    data = r.read()
    conn.close()
    status, headers = canned[0], dict(canned[1])
    assert r.status == status
    assert data == canned[2]
    for k, v in headers.items():
        assert r.getheader(k) == v, k
    [seen] = rig.fake.mcp_requests
    assert seen["method"] == method and seen["headers"]["Origin"] == "http://evil.example"  # Origin is kaia's to judge
    assert rig.audit[-1]["forwarded"] is True and rig.audit[-1]["upstreamStatus"] == status


BALANCE_OF_LIKE = {"functionName": "balanceOf", "args": ["0x1234567890123456789012345678901234567890"]}


def test_non_tool_methods_need_a_valid_token_then_forward(rig_factory: Any) -> None:
    rig = rig_factory()
    init = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
    status, headers, data = rig.post(init, None)
    assert status == 401
    assert "resource_metadata=" in headers["www-authenticate"]
    assert _err(data)["data"]["reasonCode"] == "claims_unauthenticated"
    assert rig.fake.mcp_requests == []
    for method in ("initialize", "tools/list", "notifications/initialized"):
        msg = {"jsonrpc": "2.0", "method": method} | ({"id": 2} if not method.startswith("notifications/") else {})
        assert rig.post(msg, rig.token("kaia:read"))[0] == 200
    assert [json.loads(r["body"])["method"] for r in rig.fake.mcp_requests] == ["initialize", "tools/list", "notifications/initialized"]


def test_scope_deny_is_jsonrpc_error_and_never_forwarded(rig_factory: Any) -> None:
    rig = rig_factory()
    status, _, data = rig.post(CALL("encode_function_data", 3), rig.token("kaia:read"))
    assert status == 200
    err = _err(data)
    assert err["code"] == DENY_CODE
    assert err["data"] == {"reasonCode": "claims_insufficient_scope", "choice": "deny", "tool": "encode_function_data", "requiredScope": "kaia:encode"}
    assert json.loads(data)["id"] == 3
    assert rig.fake.mcp_requests == []
    status, _, data = rig.post(CALL("not_a_kaia_tool"), rig.token("kaia:read"))
    assert _err(data)["data"]["reasonCode"] == "claims_unknown_tool"
    assert rig.fake.mcp_requests == []


def test_wallet_escalates_and_is_never_forwarded(rig_factory: Any) -> None:
    rig = rig_factory()
    status, _, data = rig.post(CALL("generate_wallet"), rig.token("kaia:read kaia:wallet"))
    assert status == 200
    err = _err(data)
    assert err["code"] == ESCALATE_CODE
    assert err["data"]["reasonCode"] == "claims_wallet_escalate"
    assert err["data"]["escalationId"]
    assert rig.fake.mcp_requests == []
    assert rig.audit[-1]["event"] == "escalate" and rig.audit[-1]["forwarded"] is False


@pytest.mark.parametrize(
    ("kind", "reason"),
    [
        ("forged", "claims_invalid_token"),
        ("alg-none", "claims_invalid_token"),
        ("expired", "claims_expired"),
        ("wrong-aud", "claims_audience_mismatch"),
        ("wrong-iss", "claims_issuer_mismatch"),
        ("garbage", "claims_invalid_token"),
    ],
)
def test_bad_tokens_are_401_and_not_forwarded(rig_factory: Any, kind: str, reason: str) -> None:
    rig = rig_factory()
    tok = {
        "forged": lambda: rig.token(signer=TestSigner.generate(kid="kid-1")),
        "alg-none": lambda: unsigned_token(build_claims(now=rig.now, iss=rig.fake.issuer, scope="kaia:read")),
        "expired": lambda: rig.token(exp_in=-5),
        "wrong-aud": lambda: rig.token(aud="other-api"),
        "wrong-iss": lambda: rig.token(iss="https://evil.test.invalid"),
        "garbage": lambda: "not.a.jwt",
    }[kind]()
    status, _, data = rig.post(CALL("get_block_number"), tok)
    assert status == 401
    assert _err(data)["code"] == DENY_CODE
    assert _err(data)["data"]["reasonCode"] == reason
    assert rig.fake.mcp_requests == []


def test_proxy_audience_pin_rejects_kaia_tokens(rig_factory: Any) -> None:
    rig = rig_factory(audience="other-api")
    status, _, data = rig.post(CALL("get_block_number"), rig.token("kaia:read"))
    assert (status, _err(data)["data"]["reasonCode"]) == (401, "claims_audience_mismatch")


def test_revoked_token_denied_via_introspection(rig_factory: Any) -> None:
    rig = rig_factory()  # default: introspection cache off -> revocation applies on the very next request
    tok = rig.token("kaia:read")
    assert rig.post(CALL("get_block_number"), tok)[0] == 200
    rig.fake.revoked.add(tok)
    status, _, data = rig.post(CALL("get_block_number"), tok)
    assert (status, _err(data)["data"]["reasonCode"]) == (401, "claims_token_revoked")
    assert len(rig.fake.mcp_requests) == 1


def test_introspection_cache_is_off_by_default_every_request_introspected(rig_factory: Any) -> None:
    assert DEFAULT_INTROSPECTION_CACHE_TTL == 0
    rig = rig_factory()
    assert rig.config.introspector is not None
    assert rig.config.introspector.cache_ttl == 0
    tok = rig.token("kaia:read")
    for i in range(3):
        assert rig.post(CALL("get_block_number", i + 1), tok)[0] == 200
    assert rig.fake.introspection_calls == 3


def test_introspection_failure_fails_closed(rig_factory: Any) -> None:
    rig = rig_factory()
    rig.fake.introspection_status = 503
    status, _, data = rig.post(CALL("get_block_number"), rig.token("kaia:read"))
    assert (status, _err(data)["data"]["reasonCode"]) == (401, "claims_introspection_unavailable")
    assert rig.fake.mcp_requests == []


def test_batches_and_garbage_bodies_are_rejected(rig_factory: Any) -> None:
    rig = rig_factory()
    tok = rig.token("kaia:read kaia:encode")
    status, _, data = rig.post([CALL("get_block_number"), CALL("encode_function_data")], tok)
    assert (status, _err(data)["data"]["reasonCode"]) == (400, "claims_malformed_request")
    status, _, data = rig.post(b"{not json", tok)
    assert status == 400
    status, _, data = rig.post({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {}}, tok)
    assert _err(data)["data"]["reasonCode"] == "claims_malformed_request"
    assert rig.fake.mcp_requests == []


def test_sse_response_streams_through(rig_factory: Any) -> None:
    fake = FakeKaia(signer=TestSigner.generate(kid="kid-1"), sse=True, legacy_session=True)
    rig = rig_factory(fake=fake)
    status, headers, data = rig.post(CALL("get_block_number"), rig.token("kaia:read"))
    assert status == 200
    assert headers["content-type"] == "text/event-stream"
    assert "mcp-session-id" not in headers
    assert data.count(b"event: message") == 3


def test_tokens_never_logged_or_audited(rig_factory: Any, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger="claims_gate.proxy")
    rig = rig_factory()
    toks = [rig.token("kaia:read"), rig.token("kaia:read", exp_in=-5), rig.token("kaia:read kaia:wallet")]
    rig.post(CALL("get_block_number"), toks[0])
    rig.post(CALL("get_block_number"), toks[1])
    rig.post(CALL("generate_wallet"), toks[2])
    blob = caplog.text + json.dumps(rig.audit)
    assert len(rig.audit) == 3
    for t in toks:
        assert t not in blob
        assert t.split(".")[2] not in blob


def test_jwks_cache_ttl_unknown_kid_refetch_and_fail_closed() -> None:
    signer_a, signer_b = TestSigner.generate(kid="a"), TestSigner.generate(kid="b")
    now = [0.0]
    served: list[Any] = [signer_a.jwks()]
    calls = {"n": 0}

    def fetch(url: str, **_: Any) -> tuple[int, Any]:
        calls["n"] += 1
        doc = served[0]
        if isinstance(doc, Exception):
            raise doc
        return 200, doc

    cache = JwksCache("http://idp/jwks", ttl_seconds=100, min_refetch_seconds=10, fetch=fetch, clock=lambda: now[0])
    assert cache.get("a")["keys"][0]["kid"] == "a"
    assert cache.get("a") and calls["n"] == 1  # cached
    served[0] = signer_b.jwks()
    now[0] = 5
    assert cache.get("b")["keys"][0]["kid"] == "a" and calls["n"] == 1  # rate-limited
    now[0] = 11
    assert cache.get("b")["keys"][0]["kid"] == "b" and calls["n"] == 2  # rotation picked up
    served[0] = UpstreamError("down")
    now[0] = 50
    assert cache.get("zzz")["keys"][0]["kid"] == "b"  # still fresh: keep serving, token will fail on kid
    now[0] = 200
    with pytest.raises(UpstreamError):
        cache.get("b")  # stale and refetch failed: fail closed


def test_drift_check_detects_any_difference() -> None:
    def serve(doc: Any) -> Any:
        return lambda url, **_: (200, doc)

    same = check_tool_scope_drift("u", KAIA_TOOL_SCOPES, fetch=serve({"tool_scopes": dict(KAIA_TOOL_SCOPES)}))
    assert same["ok"] is True
    changed = dict(KAIA_TOOL_SCOPES, encode_function_data="kaia:read", new_tool="kaia:read")
    del changed["get_block"]
    report = check_tool_scope_drift("u", KAIA_TOOL_SCOPES, fetch=serve({"tool_scopes": changed}))
    assert report["ok"] is False
    assert report["missingFromGate"] == ["new_tool"]
    assert report["notUpstream"] == ["get_block"]
    assert report["scopeChanged"] == {"encode_function_data": {"gate": "kaia:encode", "upstream": "kaia:read"}}

    def down(url: str, **_: Any) -> Any:
        raise UpstreamError("refused")

    assert check_tool_scope_drift("u", KAIA_TOOL_SCOPES, fetch=down)["ok"] is False


def test_build_config_fails_closed() -> None:
    signer = TestSigner.generate()
    issuer = "http://idp.test:1"
    good = {"issuer": issuer, "jwks_uri": issuer + "/jwks", "introspection_endpoint": issuer + "/introspect"}

    def fetcher(disc: dict[str, Any], scopes: dict[str, str] | None = None) -> Any:
        def fetch(url: str, **_: Any) -> tuple[int, Any]:
            if url.endswith("/openid-configuration"):
                return 200, disc
            if url.endswith("/tool-scopes"):
                return 200, {"tool_scopes": scopes if scopes is not None else dict(KAIA_TOOL_SCOPES)}
            return 200, signer.jwks()

        return fetch

    kw: dict[str, Any] = {"upstream": issuer, "issuer": issuer, "audience": "kaia-mcp", "policy": kaia_policy()}
    cfg, rep = build_config(**kw, fetch=fetcher(good))
    assert cfg is not None and rep.errors == []
    cfg, rep = build_config(**kw, fetch=fetcher(dict(good, issuer="http://other")))
    assert cfg is None and "pinned issuer" in rep.errors[0]
    cfg, rep = build_config(**kw, fetch=fetcher(dict(good, jwks_uri="http://evil.test/jwks")))
    assert cfg is None and "not on the issuer origin" in rep.errors[0]
    cfg, rep = build_config(**kw, introspection="auto", fetch=fetcher(good))
    assert cfg is None and "S1_INTROSPECTION_CLIENT_ID/SECRET" in rep.errors[0]
    cfg, rep = build_config(**kw, fetch=fetcher(good, {"get_block": "kaia:read"}))
    assert cfg is None and rep.errors == ["tool-scope drift check failed"]
    cfg, rep = build_config(**kw, drift_check=False, fetch=fetcher(good, {"get_block": "kaia:read"}))
    assert cfg is not None


# ---- escalation queue (approve once) ----------------------------------------


def test_wallet_escalation_is_queued_with_its_id(rig_factory: Any, tmp_path: Any) -> None:
    store = EscalationStore(tmp_path / "esc")
    rig = rig_factory(escalations=store)
    status, _, data = rig.post(CALL("generate_wallet", 5, {"label": "x"}), rig.token("kaia:wallet", sub="alice"))
    err = _err(data)
    assert (status, err["code"], err["data"]["reasonCode"]) == (200, ESCALATE_CODE, "claims_wallet_escalate")
    [rec] = store.list()
    assert err["data"]["escalationId"] == rec.id
    assert err["data"]["escalationStatus"] == "pending"
    assert (rec.sub, rec.tool, rec.args_hash, rec.status) == ("alice", "generate_wallet", args_hash({"label": "x"}), "pending")
    assert rig.fake.mcp_requests == []
    assert rig.audit[-1]["escalationId"] == rec.id


def test_approved_escalation_forwards_exactly_one_matching_retry(rig_factory: Any, tmp_path: Any) -> None:
    store = EscalationStore(tmp_path / "esc")
    rig = rig_factory(escalations=store)
    tok = rig.token("kaia:wallet", sub="alice")
    eid = _err(rig.post(CALL("generate_wallet"), tok)[2])["data"]["escalationId"]
    store.approve(eid)
    # different args or a different subject do not use the approval
    assert _err(rig.post(CALL("generate_wallet", 2, {"n": 1}), tok)[2])["code"] == ESCALATE_CODE
    assert _err(rig.post(CALL("generate_wallet", 3), rig.token("kaia:wallet", sub="mallory"))[2])["code"] == ESCALATE_CODE
    assert rig.fake.mcp_requests == []
    # the matching retry (fresh token, same subject) goes through once
    status, _, data = rig.post(CALL("generate_wallet", 4), rig.token("kaia:wallet", sub="alice"))
    assert status == 200 and json.loads(data)["result"] == {"echo": "tools/call"}
    assert len(rig.fake.mcp_requests) == 1
    assert rig.audit[-1]["event"] == "allow" and rig.audit[-1]["stage"] == "escalation" and rig.audit[-1]["escalationId"] == eid
    assert store.get(eid).status == "consumed"
    err = _err(rig.post(CALL("generate_wallet", 5), tok)[2])
    assert err["code"] == ESCALATE_CODE and err["data"]["escalationId"] != eid
    assert len(rig.fake.mcp_requests) == 1


def test_approval_is_spent_even_when_the_upstream_call_fails(rig_factory: Any, tmp_path: Any) -> None:
    """Pinned (fail closed): the approval is consumed before forwarding; a failed upstream call re-escalates."""
    import socket

    store = EscalationStore(tmp_path / "esc")
    rig = rig_factory(escalations=store)
    eid = _err(rig.post(CALL("generate_wallet"), rig.token("kaia:wallet", sub="alice"))[2])["data"]["escalationId"]
    store.approve(eid)
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        dead = f"http://127.0.0.1:{s.getsockname()[1]}"
    live_upstream, rig.config.upstream = rig.config.upstream, dead
    status, _, data = rig.post(CALL("generate_wallet", 2), rig.token("kaia:wallet", sub="alice"))
    assert status == 502 and json.loads(data)["error"]["data"]["choice"] == "allow"
    assert store.get(eid).status == "consumed"  # spent on the failed call
    assert rig.audit[-1]["event"] == "upstream_error" and rig.audit[-1]["stage"] == "escalation" and rig.audit[-1]["escalationId"] == eid
    rig.config.upstream = live_upstream  # upstream back: the same retry needs a new approval
    err = _err(rig.post(CALL("generate_wallet", 3), rig.token("kaia:wallet", sub="alice"))[2])
    assert err["code"] == ESCALATE_CODE and err["data"]["escalationId"] != eid and err["data"]["escalationStatus"] == "pending"
    assert rig.fake.mcp_requests == []


def test_approval_never_overrides_a_scope_deny(rig_factory: Any, tmp_path: Any) -> None:
    store = EscalationStore(tmp_path / "esc")
    rig = rig_factory(escalations=store)
    eid = _err(rig.post(CALL("generate_wallet"), rig.token("kaia:wallet", sub="alice"))[2])["data"]["escalationId"]
    store.approve(eid)
    err = _err(rig.post(CALL("generate_wallet"), rig.token("kaia:read", sub="alice"))[2])
    assert (err["code"], err["data"]["reasonCode"]) == (DENY_CODE, "claims_insufficient_scope")
    assert rig.fake.mcp_requests == [] and store.get(eid).status == "approved"


def test_denied_escalation_retry_is_denied(rig_factory: Any, tmp_path: Any) -> None:
    store = EscalationStore(tmp_path / "esc")
    rig = rig_factory(escalations=store)
    tok = rig.token("kaia:wallet", sub="alice")
    eid = _err(rig.post(CALL("generate_wallet"), tok)[2])["data"]["escalationId"]
    store.deny(eid)
    err = _err(rig.post(CALL("generate_wallet", 2), tok)[2])
    assert err["code"] == DENY_CODE
    assert err["data"]["reasonCode"] == "claims_escalation_denied" and err["data"]["escalationId"] == eid
    assert rig.fake.mcp_requests == []


def test_escalation_store_failure_fails_closed(rig_factory: Any) -> None:
    class Broken:
        def on_escalate(self, *a: Any, **k: Any) -> Any:
            import sqlite3

            raise sqlite3.OperationalError("disk I/O error")

    rig = rig_factory(escalations=Broken())
    err = _err(rig.post(CALL("generate_wallet"), rig.token("kaia:wallet"))[2])
    assert (err["code"], err["data"]["reasonCode"]) == (DENY_CODE, "claims_escalation_unavailable")
    assert rig.fake.mcp_requests == []


def test_escalation_without_a_queue_is_terminal(rig_factory: Any) -> None:
    rig = rig_factory()
    err = _err(rig.post(CALL("generate_wallet"), rig.token("kaia:wallet"))[2])
    assert err["code"] == ESCALATE_CODE and err["data"]["escalationStatus"] == "not_queued" and err["data"]["escalationId"]


# ---- periodic tool-scope drift recheck ---------------------------------------


def _health(rig: Rig) -> dict[str, Any]:
    conn = http.client.HTTPConnection("127.0.0.1", rig.proxy_port, timeout=10)
    conn.request("GET", "/health")
    data = json.loads(conn.getresponse().read())
    conn.close()
    return data


def test_drift_at_runtime_fails_closed_then_recovers(rig_factory: Any, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger="claims_gate.proxy")
    rig = rig_factory(drift_interval=3600)
    monitor = rig.config.drift
    assert isinstance(monitor, DriftMonitor) and monitor.ok
    tok = rig.token("kaia:read")
    assert rig.post(CALL("get_block_number"), tok)[0] == 200
    assert len(rig.fake.mcp_requests) == 1

    rig.fake.tool_scopes["get_block_number"] = "kaia:encode"
    assert monitor.check_once()["ok"] is False
    status, _, data = rig.post(CALL("get_block_number", 2), tok)
    err = _err(data)
    assert (status, err["code"], err["data"]["reasonCode"]) == (200, DENY_CODE, "claims_tool_scope_drift")
    assert err["data"]["drift"]["scopeChanged"] == {"get_block_number": {"gate": "kaia:read", "upstream": "kaia:encode"}}
    assert len(rig.fake.mcp_requests) == 1  # not forwarded
    assert rig.audit[-1]["event"] == "deny" and rig.audit[-1]["stage"] == "drift"
    assert _health(rig)["toolScopes"]["ok"] is False
    # other MCP traffic still needs only a valid token
    assert rig.post({"jsonrpc": "2.0", "id": 9, "method": "tools/list"}, tok)[0] == 200

    rig.fake.tool_scopes["get_block_number"] = "kaia:read"
    assert monitor.check_once()["ok"] is True
    assert rig.post(CALL("get_block_number", 3), tok)[0] == 200
    assert json.loads(rig.fake.mcp_requests[-1]["body"])["id"] == 3
    assert _health(rig)["toolScopes"]["ok"] is True
    transitions = [r.getMessage() for r in caplog.records if "tool-scope map" in r.getMessage()]
    assert len(transitions) == 2
    assert "ok -> drift" in transitions[0] and "drift -> ok" in transitions[1]
    assert [a["event"] for a in rig.audit if a["event"].startswith("drift_")] == ["drift_failing", "drift_recovered"]


def test_tool_scope_map_fetch_failure_fails_closed(rig_factory: Any) -> None:
    rig = rig_factory(drift_interval=3600)
    tok = rig.token("kaia:read")
    rig.fake.tool_scopes_status = 503
    report = rig.config.drift.check_once()
    assert report["ok"] is False and "503" in report["error"]
    err = _err(rig.post(CALL("get_block_number"), tok)[2])
    assert err["data"]["reasonCode"] == "claims_tool_scope_drift" and "503" in err["data"]["drift"]["error"]
    rig.config.drift.check_once()  # still failing: no second transition
    assert [a["event"] for a in rig.audit if a["event"].startswith("drift_")] == ["drift_failing"]
    rig.fake.tool_scopes_status = 200
    rig.config.drift.check_once()
    assert rig.post(CALL("get_block_number"), tok)[0] == 200
    assert len(rig.fake.mcp_requests) == 1


def test_drift_monitor_rechecks_on_its_interval() -> None:
    served = [dict(KAIA_TOOL_SCOPES)]
    calls = {"n": 0}

    def fetch(url: str, **_: Any) -> tuple[int, Any]:
        calls["n"] += 1
        return 200, {"tool_scopes": served[0]}

    monitor = DriftMonitor("u", KAIA_TOOL_SCOPES, interval=0.05, fetch=fetch)
    assert monitor.check_once()["ok"] and monitor.ok
    monitor.start()
    try:
        served[0] = {"get_block": "kaia:read"}
        deadline = time.time() + 5
        while monitor.ok and time.time() < deadline:
            time.sleep(0.02)
        assert monitor.ok is False
        served[0] = dict(KAIA_TOOL_SCOPES)
        deadline = time.time() + 5
        while not monitor.ok and time.time() < deadline:
            time.sleep(0.02)
        assert monitor.ok is True and calls["n"] >= 3
    finally:
        monitor.stop()
    n = calls["n"]
    time.sleep(0.2)
    assert calls["n"] == n  # stopped


def test_drift_monitor_starts_failed_closed_without_a_passing_check() -> None:
    monitor = DriftMonitor("u", KAIA_TOOL_SCOPES, interval=60, fetch=lambda url, **_: (200, {"tool_scopes": dict(KAIA_TOOL_SCOPES)}))
    assert monitor.ok is False  # no check yet: closed
    monitor.check_once()
    assert monitor.ok is True
    with pytest.raises(ValueError):
        DriftMonitor("u", KAIA_TOOL_SCOPES, interval=0)


def test_drift_monitor_first_periodic_check_runs_immediately_on_start() -> None:
    """No blind window: the periodic thread checks at t=0, not after a full interval."""
    calls = {"n": 0}

    def fetch(url: str, **_: Any) -> tuple[int, Any]:
        calls["n"] += 1
        return 200, {"tool_scopes": dict(KAIA_TOOL_SCOPES)}

    monitor = DriftMonitor("u", KAIA_TOOL_SCOPES, interval=3600, fetch=fetch)
    assert monitor.ok is False
    monitor.start()
    try:
        deadline = time.time() + 5
        while calls["n"] == 0 and time.time() < deadline:
            time.sleep(0.01)
        assert calls["n"] == 1 and monitor.ok is True
    finally:
        monitor.stop()


def test_build_config_rejects_negative_drift_interval() -> None:
    signer = TestSigner.generate()
    issuer = "http://idp.test:1"

    def fetch(url: str, **_: Any) -> tuple[int, Any]:
        if url.endswith("/openid-configuration"):
            return 200, {"issuer": issuer, "jwks_uri": issuer + "/jwks"}
        if url.endswith("/tool-scopes"):
            return 200, {"tool_scopes": dict(KAIA_TOOL_SCOPES)}
        return 200, signer.jwks()

    kw: dict[str, Any] = {"upstream": issuer, "issuer": issuer, "audience": "kaia-mcp", "policy": kaia_policy(), "fetch": fetch}
    cfg, rep = build_config(**kw, drift_interval=-1)
    assert cfg is None and any("drift interval" in e for e in rep.errors), rep.errors
    cfg, rep = build_config(**kw, drift_interval=0)
    assert cfg is not None and cfg.drift is None


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf"), -1.0, threading.TIMEOUT_MAX * 2])
def test_build_config_rejects_non_finite_or_out_of_range_drift_interval(bad: float) -> None:
    """nan/inf used to slip through (nan < 0 is False) and silently stop the periodic recheck."""
    signer = TestSigner.generate()
    issuer = "http://idp.test:1"

    def fetch(url: str, **_: Any) -> tuple[int, Any]:
        if url.endswith("/openid-configuration"):
            return 200, {"issuer": issuer, "jwks_uri": issuer + "/jwks"}
        if url.endswith("/tool-scopes"):
            return 200, {"tool_scopes": dict(KAIA_TOOL_SCOPES)}
        return 200, signer.jwks()

    kw: dict[str, Any] = {"upstream": issuer, "issuer": issuer, "audience": "kaia-mcp", "policy": kaia_policy(), "fetch": fetch}
    cfg, rep = build_config(**kw, drift_interval=bad)
    assert cfg is None and any("drift interval must be a finite number in [0, " in e for e in rep.errors), rep.errors
    cfg, rep = build_config(**kw, drift_interval=threading.TIMEOUT_MAX)
    assert cfg is not None and cfg.drift is not None and cfg.drift.interval == threading.TIMEOUT_MAX


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), 0.0, -1.0, threading.TIMEOUT_MAX * 2])
def test_drift_monitor_rejects_bad_intervals(bad: float) -> None:
    with pytest.raises(ValueError):
        DriftMonitor("http://x/tool-scopes", KAIA_TOOL_SCOPES, interval=bad, fetch=lambda url, **_: (200, {}))


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf"), 0.0, -1.0, 3600.001, 1e300, 9e18])
def test_build_config_rejects_bad_jwks_ttl(bad: float) -> None:
    signer = TestSigner.generate()
    issuer = "http://idp.test:1"

    def fetch(url: str, **_: Any) -> tuple[int, Any]:
        if url.endswith("/openid-configuration"):
            return 200, {"issuer": issuer, "jwks_uri": issuer + "/jwks"}
        if url.endswith("/tool-scopes"):
            return 200, {"tool_scopes": dict(KAIA_TOOL_SCOPES)}
        return 200, signer.jwks()

    cfg, rep = build_config(upstream=issuer, issuer=issuer, audience="kaia-mcp", policy=kaia_policy(), fetch=fetch, jwks_ttl_seconds=bad)
    assert cfg is None and [e for e in rep.errors if "jwks TTL" in e] == [f"jwks TTL must be a finite number in (0, 3600.0] seconds (got {bad})"], rep.errors
    with pytest.raises(ValueError):
        JwksCache("http://idp/jwks", ttl_seconds=bad)
    cfg, rep = build_config(upstream=issuer, issuer=issuer, audience="kaia-mcp", policy=kaia_policy(), fetch=fetch, jwks_ttl_seconds=3600.0)
    assert cfg is not None, rep.errors


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), -1.0, 300.001, 1e300, 9e18])
def test_build_config_reports_a_bad_introspection_cache_ttl_once(bad: float) -> None:
    """A huge TTL is inf in practice (cached until token exp: revocation never applies at the proxy)."""
    signer = TestSigner.generate()
    issuer = "http://idp.test:1"

    def fetch(url: str, **_: Any) -> tuple[int, Any]:
        if url.endswith("/openid-configuration"):
            return 200, {"issuer": issuer, "jwks_uri": issuer + "/jwks", "introspection_endpoint": issuer + "/introspect"}
        if url.endswith("/tool-scopes"):
            return 200, {"tool_scopes": dict(KAIA_TOOL_SCOPES)}
        return 200, signer.jwks()

    kw: dict[str, Any] = {"upstream": issuer, "issuer": issuer, "audience": "kaia-mcp", "policy": kaia_policy(), "fetch": fetch}
    for intro in (None, "auto"):
        cfg, rep = build_config(**kw, introspection=intro, introspection_client_id="c", introspection_client_secret="s", introspection_cache_ttl=bad)
        assert cfg is None
        assert [e for e in rep.errors if "introspection cache TTL" in e] == [f"introspection cache TTL must be a finite number in [0, 300.0] seconds (got {bad})"], rep.errors
    cfg, rep = build_config(**kw, introspection="auto", introspection_client_id="c", introspection_client_secret="s", introspection_cache_ttl=300.0)
    assert cfg is not None and cfg.introspector is not None and cfg.introspector.cache_ttl == 300.0, rep.errors


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), -1.0, 300.001, 1e300, 9e18])
def test_introspection_cache_ttl_must_be_finite(bad: float) -> None:
    """inf would cache an active answer until token exp: a revocation would never apply at the proxy."""
    with pytest.raises(ValueError):
        Introspector("http://idp/introspect", "c", "s", cache_ttl=bad)


def test_build_config_drift_interval_zero_means_startup_check_only(rig_factory: Any) -> None:
    rig = rig_factory(drift_interval=0)
    assert rig.config.drift is None


# ---- introspection TTL cache --------------------------------------------------


class _IntrospectionFake:
    def __init__(self) -> None:
        self.calls = 0
        self.answer: Any = (200, {"active": True})

    def __call__(self, url: str, **kw: Any) -> tuple[int, Any]:
        self.calls += 1
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer


def _introspector(ttl: float, now: list[float], fake: _IntrospectionFake, **kw: Any) -> Introspector:
    return Introspector("http://idp/introspect", "c", "s", fetch=fake, cache_ttl=ttl, clock=lambda: now[0], **kw)


def test_introspection_cache_hits_within_ttl_then_refetches() -> None:
    now, fake = [1000.0], _IntrospectionFake()
    intro = _introspector(10, now, fake)
    assert intro.check("tok-a", expires_at=2000) is None
    now[0] = 1009.9
    assert intro.check("tok-a", expires_at=2000) is None
    assert fake.calls == 1  # cached
    assert intro.check("tok-b", expires_at=2000) is None and fake.calls == 2  # per token
    now[0] = 1010.0
    assert intro.check("tok-a", expires_at=2000) is None and fake.calls == 3  # TTL over


def test_introspection_cache_revocation_latency_is_bounded_by_ttl() -> None:
    now, fake = [1000.0], _IntrospectionFake()
    intro = _introspector(5, now, fake)
    assert intro.check("tok", expires_at=2000) is None
    fake.answer = (200, {"active": False})  # revoked at the IdP
    now[0] = 1004.0
    assert intro.check("tok", expires_at=2000) is None  # documented tradeoff: still cached
    now[0] = 1005.0
    assert intro.check("tok", expires_at=2000) is ClaimsReason.TOKEN_REVOKED


def test_introspection_never_caches_inactive_or_errors() -> None:
    now, fake = [1000.0], _IntrospectionFake()
    intro = _introspector(30, now, fake)
    fake.answer = (200, {"active": False})
    assert [intro.check("tok", expires_at=2000) for _ in range(3)] == [ClaimsReason.TOKEN_REVOKED] * 3
    assert fake.calls == 3
    for answer in (UpstreamError("down"), (503, {"error": "x"}), (200, {"active": "yes"}), (200, None)):
        fake.answer = answer
        assert intro.check("tok", expires_at=2000) is ClaimsReason.INTROSPECTION_UNAVAILABLE
        assert intro.check("tok", expires_at=2000) is ClaimsReason.INTROSPECTION_UNAVAILABLE
    assert fake.calls == 3 + 8
    fake.answer = (200, {"active": True})
    assert intro.check("tok", expires_at=2000) is None and fake.calls == 12


def test_introspection_cache_is_bounded_by_token_exp() -> None:
    now, fake = [1000.0], _IntrospectionFake()
    intro = _introspector(30, now, fake)
    assert intro.check("tok", expires_at=1002) is None
    now[0] = 1001.9
    assert intro.check("tok", expires_at=1002) is None and fake.calls == 1
    now[0] = 1002.0
    assert intro.check("tok", expires_at=1002) is None and fake.calls == 2  # entry dropped at exp
    assert intro.check("tok2", expires_at=None) is None
    assert intro.check("tok2", expires_at=None) is None and fake.calls == 4  # no exp known: never cached


def test_introspector_default_never_caches() -> None:
    fake = _IntrospectionFake()
    intro = Introspector("http://idp/introspect", "c", "s", fetch=fake)
    assert intro.cache_ttl == 0
    assert [intro.check("tok", expires_at=time.time() + 600) for _ in range(3)] == [None] * 3
    assert fake.calls == 3 and intro._cache == {}
    fake.answer = (200, {"active": False})
    assert intro.check("tok", expires_at=time.time() + 600) is ClaimsReason.TOKEN_REVOKED


def test_introspection_cache_ttl_zero_disables_and_keys_are_hashes() -> None:
    now, fake = [1000.0], _IntrospectionFake()
    off = _introspector(0, now, fake)
    for _ in range(3):
        assert off.check("tok", expires_at=2000) is None
    assert fake.calls == 3
    on = _introspector(10, now, fake, max_entries=2)
    for t in ("secret-token-1", "secret-token-2", "secret-token-3"):
        on.check(t, expires_at=2000)
    assert len(on._cache) <= 2
    assert not any("secret-token" in k for k in on._cache)
    with pytest.raises(ValueError):
        _introspector(-1, now, fake)


def test_proxy_introspection_cache_end_to_end(rig_factory: Any) -> None:
    rig = rig_factory(introspection_cache_ttl=0.5)
    tok = rig.token("kaia:read")
    assert rig.post(CALL("get_block_number"), tok)[0] == 200
    rig.fake.revoked.add(tok)
    assert rig.post(CALL("get_block_number", 2), tok)[0] == 200  # within the cache TTL
    time.sleep(0.6)
    status, _, data = rig.post(CALL("get_block_number", 3), tok)
    assert (status, _err(data)["data"]["reasonCode"]) == (401, "claims_token_revoked")
    status, _, data = rig.post(CALL("get_block_number", 4), tok)
    assert (status, _err(data)["data"]["reasonCode"]) == (401, "claims_token_revoked")  # inactive not cached as allow


# ---- listen backlog ------------------------------------------------------------

BURST = 20


def test_proxy_listen_backlog_holds_a_20_connection_burst(rig_factory: Any) -> None:
    """All 20 connections are accepted by the kernel even while the accept loop is busy."""
    import socket

    rig = rig_factory()
    server = make_server(rig.config)  # listening, but not accepting yet
    port = server.server_address[1]
    socks: list[socket.socket] = []
    errors: list[str] = []
    thread: threading.Thread | None = None
    try:
        for _ in range(BURST):
            c = socket.socket()
            c.settimeout(0.5)
            try:
                c.connect(("127.0.0.1", port))
                c.sendall(b"GET /health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                socks.append(c)
            except OSError as err:
                errors.append(type(err).__name__)
                c.close()
        assert errors == [] and len(socks) == BURST, errors
        thread = _serve(server)
        for c in socks:
            c.settimeout(10)
            data = b""
            while chunk := c.recv(65536):
                data += chunk
            assert data.startswith((b"HTTP/1.0 200", b"HTTP/1.1 200")), data[:80]
    finally:
        for c in socks:
            c.close()
        if thread is not None:  # shutdown() blocks forever unless serve_forever is running
            server.shutdown()
            thread.join(timeout=5)
        server.server_close()


def test_proxy_serves_20_concurrent_requests_without_resets(rig_factory: Any) -> None:
    rig = rig_factory()
    tok = rig.token("kaia:read")
    barrier = threading.Barrier(BURST)
    results: list[Any] = []
    lock = threading.Lock()

    def one(i: int) -> None:
        barrier.wait(timeout=10)
        try:
            out: Any = rig.post(CALL("get_block_number", i), tok)[0]
        except OSError as err:  # ConnectionResetError, BrokenPipeError, timeouts
            out = type(err).__name__
        with lock:
            results.append(out)

    threads = [threading.Thread(target=one, args=(i,)) for i in range(BURST)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    assert results == [200] * BURST, results
    assert len(rig.fake.mcp_requests) == BURST


# ---- ambiguous (duplicated) auth-relevant headers ------------------------------


def _raw_post(port: int, headers: list[tuple[str, str]], body: bytes) -> tuple[int, dict[str, str], bytes]:
    """POST with exactly these header lines (duplicates kept), plus Content-Length unless given."""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.putrequest("POST", "/", skip_host=any(k.lower() == "host" for k, _ in headers), skip_accept_encoding=True)
    for k, v in headers:
        conn.putheader(k, v)
    if not any(k.lower() == "content-length" for k, _ in headers):
        conn.putheader("Content-Length", str(len(body)))
    conn.endheaders(body)
    r = conn.getresponse()
    data = r.read()
    conn.close()
    return r.status, {k.lower(): v for k, v in r.getheaders()}, data


def test_two_authorization_headers_are_refused_before_policy_and_never_forwarded(rig_factory: Any) -> None:
    """The gate used to verify the first Authorization and forward the last (token confusion)."""
    rig = rig_factory()
    encode_tok, read_tok = rig.token("kaia:read kaia:encode"), rig.token("kaia:read")
    body = json.dumps(CALL("encode_function_data", 5, BALANCE_OF_LIKE)).encode()
    base = [("Host", "127.0.0.1"), ("Content-Type", "application/json"), ("Accept", "application/json, text/event-stream")]
    for auths in ([encode_tok, read_tok], [read_tok, encode_tok], [encode_tok, encode_tok]):
        status, _, data = _raw_post(rig.proxy_port, [*base, *(("Authorization", f"Bearer {t}") for t in auths)], body)
        err = _err(data)
        assert (status, err["data"]["reasonCode"], err["data"]["choice"]) == (400, "claims_malformed_request", "deny"), data
        assert "Authorization" in err["message"]
    assert rig.fake.mcp_requests == []
    assert [a["event"] for a in rig.audit] == ["deny"] * 3
    assert all(a["stage"] == "request" and a["forwarded"] is False and a["header"] == "Authorization" for a in rig.audit)
    assert not any(encode_tok in json.dumps(a) or read_tok in json.dumps(a) for a in rig.audit)


@pytest.mark.parametrize(
    "value",
    ["Bearer {a}, Bearer {b}", "Bearer {a},Bearer {b}", "Bearer {a},", "Basic Zm9vOmJhcg==, Bearer {a}"],
)
def test_comma_joined_authorization_is_refused(rig_factory: Any, value: str) -> None:
    rig = rig_factory()
    a, b = rig.token("kaia:read kaia:encode"), rig.token("kaia:read")
    status, _, data = _raw_post(rig.proxy_port, [("Host", "127.0.0.1"), ("Content-Type", "application/json"), ("Authorization", value.format(a=a, b=b))], json.dumps(CALL("get_block_number")).encode())
    assert (status, _err(data)["data"]["reasonCode"]) == (400, "claims_malformed_request")
    assert rig.fake.mcp_requests == []
    assert rig.audit[-1]["event"] == "deny" and rig.audit[-1]["forwarded"] is False


@pytest.mark.parametrize(
    ("name", "values"),
    [
        ("Mcp-Method", ["tools/call", "tools/list"]),
        ("Mcp-Name", ["get_block_number", "generate_wallet"]),
        ("MCP-Protocol-Version", ["2025-06-18", "2026-07-28"]),
        ("Content-Type", ["application/json", "text/plain"]),
        ("Origin", ["http://127.0.0.1", "http://evil.example"]),
        ("Host", ["127.0.0.1", "evil.example"]),
        ("Content-Length", None),  # two equal lengths: still ambiguous framing
    ],
)
def test_duplicated_auth_relevant_headers_are_refused(rig_factory: Any, name: str, values: list[str] | None) -> None:
    rig = rig_factory()
    tok = rig.token("kaia:read")
    body = json.dumps(CALL("get_block_number")).encode()
    vals = values or [str(len(body)), str(len(body))]
    headers = [("Authorization", f"Bearer {tok}")]
    if name != "Host":
        headers.append(("Host", "127.0.0.1"))
    if name != "Content-Type":
        headers.append(("Content-Type", "application/json"))
    headers += [(name, v) for v in vals]
    status, _, data = _raw_post(rig.proxy_port, headers, body)
    err = _err(data)
    assert (status, err["data"]["reasonCode"]) == (400, "claims_malformed_request"), data
    assert name.lower() in err["message"].lower()
    assert rig.fake.mcp_requests == []
    assert rig.audit[-1]["event"] == "deny" and rig.audit[-1]["header"].lower() == name.lower()


def test_forwarded_authorization_is_exactly_the_authenticated_value(rig_factory: Any) -> None:
    """One header line in, the same value out (after the gate's own parsing), and only one."""
    rig = rig_factory()
    tok = rig.token("kaia:read")
    status, _, _ = _raw_post(rig.proxy_port, [("Host", "127.0.0.1"), ("Content-Type", "application/json"), ("Authorization", f"Bearer {tok}"), ("Accept", "application/json"), ("Accept", "text/event-stream")], json.dumps(CALL("get_block_number")).encode())
    assert status == 200
    [seen] = rig.fake.mcp_requests
    assert seen["headers"]["Authorization"] == f"Bearer {tok}"


def test_forwarded_headers_keep_each_line_and_one_authorization(rig_factory: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """Unrelated repeated headers are relayed line for line (not collapsed to the last one)."""
    targets: dict[int, tuple[int, str]] = {}
    sent: dict[int, list[tuple[str, str]]] = {}
    real_putrequest, real_putheader = http.client.HTTPConnection.putrequest, http.client.HTTPConnection.putheader

    def spy_putrequest(self: http.client.HTTPConnection, method: str, url: str, *a: Any, **kw: Any) -> None:
        targets[id(self)] = (self.port or 0, url)
        real_putrequest(self, method, url, *a, **kw)

    def spy_putheader(self: http.client.HTTPConnection, header: str, *values: Any) -> None:
        sent.setdefault(id(self), []).append((header, str(values[0]) if values else ""))
        real_putheader(self, header, *values)

    rig = rig_factory()
    tok = rig.token("kaia:read")
    monkeypatch.setattr(http.client.HTTPConnection, "putrequest", spy_putrequest)
    monkeypatch.setattr(http.client.HTTPConnection, "putheader", spy_putheader)
    status, _, _ = _raw_post(rig.proxy_port, [("Host", "127.0.0.1"), ("Content-Type", "application/json"), ("Authorization", f"Bearer {tok}"), ("Accept", "application/json"), ("Accept", "text/event-stream")], json.dumps(CALL("get_block_number")).encode())
    assert status == 200
    [upstream] = [sent[c] for c, (port, url) in targets.items() if port != rig.proxy_port and url == "/"]
    assert [v for k, v in upstream if k.lower() == "authorization"] == [f"Bearer {tok}"]
    assert [v for k, v in upstream if k.lower() == "accept"] == ["application/json", "text/event-stream"]


def _raw_request(port: int, method: str, headers: list[tuple[str, str]]) -> tuple[int, bytes]:
    """A body-less request with exactly these header lines (GET/DELETE)."""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.putrequest(method, "/", skip_host=any(k.lower() == "host" for k, _ in headers), skip_accept_encoding=True)
    for k, v in headers:
        conn.putheader(k, v)
    conn.endheaders()
    r = conn.getresponse()
    data = r.read()
    conn.close()
    return r.status, data


@pytest.mark.parametrize("method", ["GET", "DELETE"])
@pytest.mark.parametrize("name", ["Authorization", "Mcp-Method", "Origin"])
def test_duplicated_headers_are_refused_on_get_and_delete(rig_factory: Any, method: str, name: str) -> None:
    """The refusal runs first in do_GET/do_DELETE too, not only do_POST."""
    rig = rig_factory()
    a, b = rig.token("kaia:read kaia:encode"), rig.token("kaia:read")
    values = {"Authorization": [f"Bearer {a}", f"Bearer {b}"], "Mcp-Method": ["tools/call", "tools/list"], "Origin": ["http://127.0.0.1", "http://evil.example"]}[name]
    headers = [("Host", "127.0.0.1")] + ([("Authorization", f"Bearer {a}")] if name != "Authorization" else [])
    status, data = _raw_request(rig.proxy_port, method, headers + [(name, v) for v in values])
    err = _err(data)
    assert (status, err["code"], err["data"]["reasonCode"], err["data"]["header"]) == (400, -32600, "claims_malformed_request", name), data
    assert rig.fake.mcp_requests == []
    assert [(x["event"], x["stage"], x["forwarded"], x["httpMethod"]) for x in rig.audit] == [("deny", "request", False, method)]


# ---- raw header-block attacks (byte level) ------------------------------------


def _send_raw(port: int, raw: bytes) -> tuple[int, bytes]:
    """Write exactly ``raw`` to the proxy and parse the (close-delimited) response."""
    with socket.create_connection(("127.0.0.1", port), timeout=10) as s:
        s.sendall(raw)
        chunks = []
        while data := s.recv(65536):
            chunks.append(data)
    resp = b"".join(chunks)
    head, _, body = resp.partition(b"\r\n\r\n")
    return int(head.split(b" ", 2)[1]), body


def _raw_post_bytes(tok: str, lines: list[bytes], body: bytes, *, method: bytes = b"POST", auth: bool = True, length: bool = True) -> bytes:
    head = [method + b" / HTTP/1.1", b"Host: 127.0.0.1", b"Content-Type: application/json", b"Accept: application/json, text/event-stream"]
    if auth:
        head.append(b"Authorization: Bearer " + tok.encode())
    head += lines
    if length:
        head.append(b"Content-Length: " + str(len(body)).encode())
    return b"\r\n".join(head) + b"\r\n\r\n" + body


_BODY = json.dumps(CALL("get_block_number")).encode()

# (case id, extra header lines, whether the bearer line is added, whether Content-Length is added, refused header)
_REFUSED_RAW = [
    ("obs-fold-carrying-authorization", [b"X-Probe: a", b" Authorization: Bearer {read}"], True, True, "X-Probe"),
    ("obs-fold-carrying-session-id", [b"X-Probe: a", b"\tMcp-Session-Id: injected"], True, True, "X-Probe"),
    ("whitespace-only-continuation-after-authorization", [b" "], True, True, "Authorization"),
    ("fold-inside-authorization", None, False, True, "Authorization"),
    ("bearer-with-c0-control", [b"Authorization: Bearer \x1c{tok}"], False, True, "Authorization"),
    ("bearer-with-nul", [b"Authorization: Bearer {tok}\x00"], False, True, "Authorization"),
    ("bearer-with-del", [b"Authorization: Bearer {tok}\x7f"], False, True, "Authorization"),
    ("bearer-with-nbsp", [b"Authorization: Bearer \xa0{tok}"], False, True, "Authorization"),
    ("bearer-with-nel", [b"Authorization: Bearer {tok}\x85"], False, True, "Authorization"),
    ("control-in-other-header", [b"X-Trace: a\x01b"], True, True, "X-Trace"),
    ("mcp-name-with-control", [b"Mcp-Name: get_block_number\x1f"], True, True, "Mcp-Name"),
    ("whitespace-before-colon", [b"X-A : 1"], True, True, "header-block"),
    ("leading-whitespace-first-line", None, True, True, "header-block"),
    ("bare-cr-in-value", [b"X-A: a\rb"], True, True, "header-block"),
    ("bare-lf-obs-fold", [b"X-Probe: a\n Authorization: Bearer {read}"], True, True, "X-Probe"),
    ("non-token-header-name", [b"X(y): z"], True, True, "header-block"),
    ("non-token-header-name-slash", [b"X/y: z"], True, True, "header-block"),
    ("non-token-header-name-quote", [b'X"y: z'], True, True, "header-block"),
    ("non-token-header-name-braces", [b"{x}: z"], True, True, "header-block"),
    ("te-chunked-plus-content-length", [b"Transfer-Encoding: chunked"], True, True, "Transfer-Encoding"),
    ("te-gzip-chunked-plus-content-length", [b"Transfer-Encoding: gzip, chunked"], True, True, "Transfer-Encoding"),
    ("te-identity-plus-content-length", [b"Transfer-Encoding: identity"], True, True, "Transfer-Encoding"),
    ("te-gzip-plus-content-length", [b"Transfer-Encoding: gzip"], True, True, "Transfer-Encoding"),
    ("te-empty-plus-content-length", [b"Transfer-Encoding:"], True, True, "Transfer-Encoding"),
    ("content-length-empty", [b"Content-Length:"], True, False, "Content-Length"),
    ("content-length-plus-sign", [b"Content-Length: +{n}"], True, False, "Content-Length"),
    ("content-length-underscores", [b"Content-Length: {n_}"], True, False, "Content-Length"),
    ("content-length-trailing-space", [b"Content-Length: {n} "], True, False, "Content-Length"),
    ("content-length-trailing-tab", [b"Content-Length: {n}\t"], True, False, "Content-Length"),
    ("content-length-negative-zero", [b"Content-Length: -0"], True, False, "Content-Length"),
    ("content-length-hex", [b"Content-Length: 0x{nx}"], True, False, "Content-Length"),
    ("connection-lists-authorization", [b"Connection: keep-alive, Authorization"], True, True, "Connection"),
    ("connection-lists-mcp-method", [b"Connection: Mcp-Method", b"Mcp-Method: tools/call"], True, True, "Connection"),
]


def _refused_detail(case: str) -> str:
    """The message fragment each case must be refused with (which check fired, not just that one did)."""
    if case in ("bearer-with-nbsp", "bearer-with-nel"):
        return "non-ASCII byte"
    if case in ("whitespace-before-colon", "leading-whitespace-first-line"):
        return "malformed header line"
    if case == "bare-cr-in-value":
        return "bare CR in a header line"
    prefixes = {
        "obs-fold": "obs-fold or CR/LF",
        "bare-lf-obs-fold": "obs-fold or CR/LF",
        "non-token-header-name": "header name is not an RFC 9110 token",
        "whitespace-only": "obs-fold or CR/LF",
        "fold-": "obs-fold or CR/LF",
        "bearer-": "control character",
        "control-": "control character",
        "mcp-name-": "control character",
        "te-": "both Transfer-Encoding and Content-Length",
        "content-length-": "not plain ASCII digits",
        "connection-lists-": "Connection lists the",
    }
    return next(v for k, v in prefixes.items() if case.startswith(k))


def _build_raw(case: str, lines: list[bytes] | None, auth: bool, length: bool, tok: str, read: str) -> bytes:
    n = len(_BODY)
    fill = {b"{tok}": tok.encode(), b"{read}": read.encode(), b"{n}": str(n).encode(), b"{n_}": "_".join(str(n)).encode(), b"{nx}": f"{n:x}".encode()}

    def sub(line: bytes) -> bytes:
        for k, v in fill.items():
            line = line.replace(k, v)
        return line

    if case == "fold-inside-authorization":
        tok_b = tok.encode()
        lines = [b"Authorization: Bearer " + tok_b[:20], b" " + tok_b[20:]]
    if case == "leading-whitespace-first-line":
        head = b"POST / HTTP/1.1\r\n X-Lead: 1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nAuthorization: Bearer " + tok.encode() + b"\r\nContent-Length: " + str(n).encode() + b"\r\n\r\n"
        return head + _BODY
    return _raw_post_bytes(tok, [sub(x) for x in lines or []], _BODY, auth=auth, length=length)


@pytest.mark.parametrize(("case", "lines", "auth", "length", "header"), _REFUSED_RAW, ids=[c[0] for c in _REFUSED_RAW])
def test_hostile_header_blocks_are_refused_and_never_reach_upstream(rig_factory: Any, case: str, lines: list[bytes] | None, auth: bool, length: bool, header: str) -> None:
    """obs-fold (RFC 9112 5.2), control characters, malformed lines, TE+CL, non-digit
    Content-Length, and Connection naming an auth-relevant header: 400 before the token
    is checked, audited as a deny, and not one byte reaches the upstream (raw TCP tap)."""
    tap = RawTap()
    rig = rig_factory(tap=tap)
    tok, read = rig.token("kaia:read kaia:encode"), rig.token("kaia:read")
    status, data = _send_raw(rig.proxy_port, _build_raw(case, lines, auth, length, tok, read))
    err = _err(data)
    assert (status, err["code"], err["data"]["reasonCode"], err["data"]["choice"]) == (400, -32600, "claims_malformed_request", "deny"), data
    assert err["data"]["header"] == header, data
    assert _refused_detail(case) in err["message"], err["message"]
    assert rig.fake.mcp_requests == []
    assert tap.raw() == [], tap.raw()
    assert [(a["event"], a["stage"], a["forwarded"], a["header"]) for a in rig.audit] == [("deny", "request", False, header)]
    assert not any(t in json.dumps(rig.audit) or t.encode() in data for t in (tok, read))


def test_connection_listed_and_proxy_connection_headers_are_not_forwarded(rig_factory: Any) -> None:
    """RFC 9110 7.6.1: headers named in Connection are hop-by-hop, as is Proxy-Connection."""
    tap = RawTap()
    rig = rig_factory(tap=tap)
    tok = rig.token("kaia:read")
    lines = [b"Connection: keep-alive, X-Nominated", b"Connection: x-other", b"X-Nominated: hop-secret", b"X-Other: hop-2", b"Proxy-Connection: keep-alive", b"Keep-Alive: timeout=5", b"X-Kept: end-to-end", b"Mcp-Method: tools/call", b"Mcp-Name: get_block_number"]
    status, data = _send_raw(rig.proxy_port, _raw_post_bytes(tok, lines, _BODY))
    assert status == 200, data
    [seen] = rig.fake.mcp_requests
    names = {k.lower() for k in seen["headers"]}
    assert not names & {"x-nominated", "x-other", "proxy-connection", "keep-alive"}, names
    assert seen["headers"]["X-Kept"] == "end-to-end"
    [raw] = tap.raw()
    head = raw.split(b"\r\n\r\n", 1)[0].lower()
    for gone in (b"x-nominated", b"hop-secret", b"x-other", b"proxy-connection", b"keep-alive"):
        assert gone not in head, raw
    # Mcp-Method/Mcp-Name are relayed as sent (never trusted: the body decides).
    assert b"\r\nmcp-method: tools/call\r\n" in head and b"\r\nmcp-name: get_block_number\r\n" in head
    assert raw.count(b"Authorization: Bearer " + tok.encode() + b"\r\n") == 1 and head.count(b"\r\nauthorization:") == 1
    assert raw.endswith(b"\r\n\r\n" + _BODY)


def test_connection_listed_headers_are_dropped_from_upstream_responses(rig_factory: Any) -> None:
    fake = FakeKaia(signer=TestSigner.generate(kid="kid-1"))
    fake.canned = (200, [("Content-Type", "application/json"), ("Connection", "X-Hop"), ("X-Hop", "upstream-hop"), ("Proxy-Connection", "keep-alive"), ("X-End", "kept")], b'{"jsonrpc":"2.0","id":1,"result":{}}')
    rig = rig_factory(fake=fake)
    status, headers, _ = rig.post(CALL("get_block_number"), rig.token("kaia:read"))
    assert status == 200
    assert "x-hop" not in headers and "proxy-connection" not in headers and headers["x-end"] == "kept"


def test_valid_content_length_forms_are_accepted(rig_factory: Any) -> None:
    """Plain digits (leading zeros allowed by RFC 9110's 1*DIGIT; leading OWS is stripped by the parser)."""
    rig = rig_factory()
    tok = rig.token("kaia:read")
    for cl in (str(len(_BODY)).encode(), b"00" + str(len(_BODY)).encode()):
        status, data = _send_raw(rig.proxy_port, _raw_post_bytes(tok, [b"Content-Length:   " + cl], _BODY, length=False))
        assert status == 200, data
    assert [r["body"] for r in rig.fake.mcp_requests] == [_BODY, _BODY]


def test_htab_and_obs_text_in_other_headers_are_still_forwarded(rig_factory: Any) -> None:
    """Only control characters are refused everywhere; HTAB is legal, and obs-text is refused only in auth-relevant headers."""
    rig = rig_factory()
    tok = rig.token("kaia:read")
    status, data = _send_raw(rig.proxy_port, _raw_post_bytes(tok, [b"User-Agent: a\tb", b"X-Note: caf\xe9"], _BODY))
    assert status == 200, data
    [seen] = rig.fake.mcp_requests
    assert (seen["headers"]["User-Agent"], seen["headers"]["X-Note"]) == ("a\tb", "caf\xe9")


def test_transfer_encoding_alone_is_never_forwarded(rig_factory: Any) -> None:
    """TE without Content-Length: the proxy never decodes chunked, never forwards TE, and the
    empty body is not JSON-RPC, so the request ends in 400 after the token check."""
    tap = RawTap()
    rig = rig_factory(tap=tap)
    tok = rig.token("kaia:read")
    chunked = f"{len(_BODY):x}\r\n".encode() + _BODY + b"\r\n0\r\n\r\n"
    status, data = _send_raw(rig.proxy_port, _raw_post_bytes(tok, [b"Transfer-Encoding: chunked"], chunked, length=False))
    assert (status, _err(data)["data"]["reasonCode"]) == (400, "claims_malformed_request"), data
    assert tap.raw() == [] and rig.fake.mcp_requests == []


# ---- bare CR: the stdlib email parser splits a header line on a lone CR ---------
#
# "X: a\r\r\n" (or a line that is just "\r") makes the parser end the header block early with
# no defect: every later line lands in headers.get_payload(), unchecked and unforwarded.
# "X: a\rName: v" becomes two headers. An RFC 9112 2.2 parser (reject, or read the CR as SP)
# sees a different header set, so the gate refuses any raw header line with a CR left in it.


def _raw_head(lines: list[bytes], body: bytes, *, method: bytes = b"POST") -> bytes:
    return method + b" / HTTP/1.1\r\n" + b"\r\n".join(lines) + b"\r\n\r\n" + body


def _bare_cr_cases(tok: str, other: str) -> dict[str, list[bytes]]:
    """The review's 8 variants (S3 M1) plus edge forms. Content-Length comes first, so the
    unfixed proxy reads the whole body and the request is one kaia would execute."""
    auth, oth = b"Authorization: Bearer " + tok.encode(), b"Authorization: Bearer " + other.encode()
    pre = [b"Host: 127.0.0.1", b"Content-Type: application/json", b"Accept: application/json, text/event-stream", b"Content-Length: " + str(len(_BODY)).encode()]
    return {
        "crcrlf-hides-second-authorization": pre + [auth, b"X-Probe: a\r", oth],
        "crcrlf-hides-transfer-encoding": pre + [auth, b"X-Probe: a\r", b"Transfer-Encoding: chunked"],
        "crcrlf-hides-origin": pre + [auth, b"X-Probe: a\r", b"Origin: http://evil.example"],
        "crcrlf-hides-folded-auth": pre + [auth, b"X-Probe: a\r", b" " + oth],
        "lone-cr-line-hides-rest": pre + [auth, b"\r", oth, b"Connection: Authorization"],
        "auth-value-cr-then-crlf": pre + [auth + b"\r", oth],
        "bare-cr-mid-value-splits-header": pre + [auth, b"X-Probe: a\rX-Other: b"],
        "bare-cr-mid-value-supplies-auth": pre + [b"X-Probe: a\r" + auth],
        # edge forms
        "crcrlf-on-last-line": pre + [auth, b"X-Probe: a\r"],
        "lone-cr-line-last": pre + [auth, b"\r"],
        "lone-cr-line-first": [b"\r", *pre, auth],
        "cr-at-line-start": pre + [auth, b"\rX-Probe: a"],
        "cr-lf-only-line-endings-mixed": pre + [auth, b"X-Probe: a\r\n\r"],
    }


_BARE_CR_IDS = list(_bare_cr_cases("t", "o"))


@pytest.mark.parametrize("case", _BARE_CR_IDS)
def test_bare_cr_header_blocks_are_refused_and_never_reach_upstream(rig_factory: Any, case: str) -> None:
    tap = RawTap()
    rig = rig_factory(tap=tap)
    tok, other = rig.token("kaia:read kaia:encode"), rig.token("kaia:read")
    status, data = _send_raw(rig.proxy_port, _raw_head(_bare_cr_cases(tok, other)[case], _BODY))
    err = _err(data)
    assert (status, err["code"], err["data"]["reasonCode"], err["data"]["choice"], err["data"]["header"]) == (400, -32600, "claims_malformed_request", "deny", "header-block"), data
    assert "bare CR in a header line" in err["message"], err["message"]
    assert rig.fake.mcp_requests == []
    assert tap.raw() == [], tap.raw()
    assert [(a["event"], a["stage"], a["forwarded"], a["header"]) for a in rig.audit] == [("deny", "request", False, "header-block")]
    assert not any(t in json.dumps(rig.audit) or t.encode() in data for t in (tok, other))


@pytest.mark.parametrize("method", [b"GET", b"DELETE"])
def test_bare_cr_is_refused_on_get_and_delete(rig_factory: Any, method: bytes) -> None:
    tap = RawTap()
    rig = rig_factory(tap=tap)
    tok = rig.token("kaia:read")
    status, data = _send_raw(rig.proxy_port, _raw_head([b"Host: 127.0.0.1", b"Authorization: Bearer " + tok.encode(), b"X-Probe: a\r", b"Origin: http://evil.example"], b"", method=method))
    err = _err(data)
    assert (status, err["data"]["reasonCode"], err["data"]["header"]) == (400, "claims_malformed_request", "header-block"), data
    assert tap.raw() == [] and rig.fake.mcp_requests == []


def test_bare_cr_in_the_request_line_is_refused(rig_factory: Any) -> None:
    """The stdlib strips every trailing CR/LF from the request line; another parser may not."""
    tap = RawTap()
    rig = rig_factory(tap=tap)
    tok = rig.token("kaia:read")
    raw = _raw_post_bytes(tok, [], _BODY).replace(b" HTTP/1.1\r\n", b" HTTP/1.1\r\r\n", 1)
    status, data = _send_raw(rig.proxy_port, raw)
    err = _err(data)
    assert (status, err["data"]["reasonCode"], err["data"]["header"]) == (400, "claims_malformed_request", "request-line"), data
    assert "bare CR in the request line" in err["message"]
    assert tap.raw() == [] and rig.fake.mcp_requests == []


def test_bare_lf_line_endings_are_still_accepted(rig_factory: Any) -> None:
    """RFC 9112 2.2 lets a recipient accept a bare LF line terminator; only a CR left inside a line is refused."""
    rig = rig_factory()
    tok = rig.token("kaia:read")
    raw = _raw_post_bytes(tok, [b"X-Probe: a"], _BODY).replace(b"\r\n", b"\n")
    status, data = _send_raw(rig.proxy_port, raw)
    assert status == 200, data
    [seen] = rig.fake.mcp_requests
    assert seen["headers"]["X-Probe"] == "a" and seen["body"] == _BODY


def test_every_byte_glued_into_a_value_either_is_refused_or_stays_one_header(rig_factory: Any) -> None:
    """Sweep: "X-Probe: a<byte>X-Smuggled: v". Either 400 before forwarding, or forwarded with
    no X-Smuggled header (the parser did not split the line). LF is a line terminator (allowed)."""
    tap = RawTap()
    rig = rig_factory(tap=tap)
    tok = rig.token("kaia:read")
    refused, kept = [], []
    for b in range(256):
        if b == 0x0A:
            continue
        line = b"X-Probe: a" + bytes([b]) + b"X-Smuggled: v"
        status, data = _send_raw(rig.proxy_port, _raw_post_bytes(tok, [line], _BODY))
        (refused if status == 400 else kept).append(b)
        if status != 400:
            assert status == 200, (b, data)
    for raw in tap.raw():
        head = raw.split(b"\r\n\r\n", 1)[0].lower()
        assert b"\r\nx-smuggled:" not in head, raw
    assert 0x0D in refused and all(c in refused for c in range(0x20) if c not in (0x09, 0x0A)) and 0x7F in refused
    assert len(rig.fake.mcp_requests) == len(kept) == len(tap.raw())


# ---- L1 (S3 review): the checks run for every method and every auth-relevant header


_GET_DELETE_REFUSED = [
    ("obs-fold", [b"X-Probe: a", b" Authorization: Bearer {read}"], "X-Probe", "obs-fold or CR/LF"),
    ("control-char-in-bearer", None, "Authorization", "control character"),
    ("non-ascii-mcp-name", [b"Mcp-Name: get_block_number\xa0"], "Mcp-Name", "non-ASCII byte"),
    ("content-length-plus-sign", [b"Content-Length: +0"], "Content-Length", "not plain ASCII digits"),
    ("content-length-empty", [b"Content-Length:"], "Content-Length", "not plain ASCII digits"),
    ("te-plus-cl", [b"Transfer-Encoding: chunked", b"Content-Length: 0"], "Transfer-Encoding", "both Transfer-Encoding and Content-Length"),
]


@pytest.mark.parametrize("method", [b"GET", b"DELETE"])
@pytest.mark.parametrize(("case", "lines", "header", "detail"), _GET_DELETE_REFUSED, ids=[c[0] for c in _GET_DELETE_REFUSED])
def test_header_value_and_framing_checks_run_on_get_and_delete(rig_factory: Any, method: bytes, case: str, lines: list[bytes] | None, header: str, detail: str) -> None:
    tap = RawTap()
    rig = rig_factory(tap=tap)
    tok, read = rig.token("kaia:read"), rig.token("kaia:read")
    head = [b"Host: 127.0.0.1"]
    if lines is None:
        head.append(b"Authorization: Bearer \x1c" + tok.encode())
    else:
        head.append(b"Authorization: Bearer " + tok.encode())
        head += [ln.replace(b"{read}", read.encode()) for ln in lines]
    status, data = _send_raw(rig.proxy_port, _raw_head(head, b"", method=method))
    err = _err(data)
    assert (status, err["code"], err["data"]["reasonCode"], err["data"]["header"]) == (400, -32600, "claims_malformed_request", header), data
    assert detail in err["message"], err["message"]
    assert tap.raw() == [] and rig.fake.mcp_requests == []
    assert [(a["event"], a["stage"], a["forwarded"], a["httpMethod"]) for a in rig.audit] == [("deny", "request", False, method.decode())]


_NON_ASCII_VALUES = {
    "Authorization": b"Bearer {tok}\xe9",
    "Host": b"127.0.0.1\xe9",
    "Content-Length": b"\xd9\xa3",  # Arabic-Indic digit three, UTF-8
    "Content-Type": b"application/json; x=\xe9",
    "Origin": b"http://\xe9.example",
    "Mcp-Method": b"tools/call\xa0",
    "Mcp-Name": b"get_block_number\x85",
    "MCP-Protocol-Version": b"2026-07-28\xa0",
}


@pytest.mark.parametrize("name", list(_NON_ASCII_VALUES))
def test_non_ascii_is_refused_in_each_auth_relevant_header(rig_factory: Any, name: str) -> None:
    tap = RawTap()
    rig = rig_factory(tap=tap)
    tok = rig.token("kaia:read")
    base = {"Host": b"127.0.0.1", "Content-Type": b"application/json", "Authorization": b"Bearer " + tok.encode(), "Content-Length": str(len(_BODY)).encode()}
    base[name] = _NON_ASCII_VALUES[name].replace(b"{tok}", tok.encode())
    status, data = _send_raw(rig.proxy_port, _raw_head([k.encode() + b": " + v for k, v in base.items()], _BODY))
    err = _err(data)
    assert (status, err["data"]["reasonCode"], err["data"]["header"]) == (400, "claims_malformed_request", name), data
    assert f"non-ASCII byte in {name}" in err["message"], err["message"]
    assert tap.raw() == [] and rig.fake.mcp_requests == []


@pytest.mark.parametrize("position", ["first", "middle", "last"])
@pytest.mark.parametrize("named", ["Authorization", "mcp-name"])
def test_connection_naming_an_auth_header_is_refused_on_any_connection_line(rig_factory: Any, position: str, named: str) -> None:
    tap = RawTap()
    rig = rig_factory(tap=tap)
    tok = rig.token("kaia:read")
    conns = [b"Connection: keep-alive", b"Connection: X-Unrelated", b"Connection: X-Other"]
    conns[{"first": 0, "middle": 1, "last": 2}[position]] = b"Connection: X-A, " + named.encode()
    status, data = _send_raw(rig.proxy_port, _raw_post_bytes(tok, conns, _BODY))
    err = _err(data)
    assert (status, err["data"]["reasonCode"], err["data"]["header"]) == (400, "claims_malformed_request", "Connection"), data
    assert "Connection lists the" in err["message"]
    assert tap.raw() == [] and rig.fake.mcp_requests == []


def test_headers_named_on_any_upstream_connection_line_are_dropped_from_responses(rig_factory: Any) -> None:
    fake = FakeKaia(signer=TestSigner.generate(kid="kid-1"))
    fake.canned = (
        200,
        [("Content-Type", "application/json"), ("Connection", "X-Hop-A"), ("Connection", "keep-alive, X-Hop-B"), ("Connection", "x-hop-c"),
         ("X-Hop-A", "1"), ("X-Hop-B", "2"), ("X-Hop-C", "3"), ("X-End", "kept")],
        b'{"jsonrpc":"2.0","id":1,"result":{}}',
    )
    rig = rig_factory(fake=fake)
    status, headers, _ = rig.post(CALL("get_block_number"), rig.token("kaia:read"))
    assert status == 200
    assert not {"x-hop-a", "x-hop-b", "x-hop-c"} & set(headers), headers
    assert headers["x-end"] == "kept"


# ---- NIT: client forwarding headers stop at the gate ----------------------------


def test_client_forwarded_headers_are_not_forwarded(rig_factory: Any) -> None:
    """kaia-mcp trusts none of them, and the gate adds none: a client cannot plant them for a later hop."""
    tap = RawTap()
    rig = rig_factory(tap=tap)
    tok = rig.token("kaia:read")
    lines = [b"X-Forwarded-For: 10.0.0.1", b"x-forwarded-host: evil.example", b"X-Forwarded-Proto: https", b"X-Forwarded-Port: 443",
             b"Forwarded: for=10.0.0.1;host=evil.example", b"X-Forwardedness: kept", b"X-Kept: end-to-end"]
    status, data = _send_raw(rig.proxy_port, _raw_post_bytes(tok, lines, _BODY))
    assert status == 200, data
    [raw] = tap.raw()
    head = raw.split(b"\r\n\r\n", 1)[0].lower()
    for gone in (b"x-forwarded-for", b"x-forwarded-host", b"x-forwarded-proto", b"x-forwarded-port", b"\r\nforwarded:", b"evil.example", b"10.0.0.1"):
        assert gone not in head, raw
    assert b"\r\nx-forwardedness: kept" in head and b"\r\nx-kept: end-to-end" in head


def test_token_header_names_with_every_tchar_are_forwarded(rig_factory: Any) -> None:
    tap = RawTap()
    rig = rig_factory(tap=tap)
    tok = rig.token("kaia:read")
    name = b"X-a_b.c~!#$%&'*+^`|9"
    status, data = _send_raw(rig.proxy_port, _raw_post_bytes(tok, [name + b": v"], _BODY))
    assert status == 200, data
    [raw] = tap.raw()
    assert b"\r\n" + name + b": v\r\n" in raw
