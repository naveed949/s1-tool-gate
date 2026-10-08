"""Offline tests for claims_gate.proxy against an in-process fake kaia-mcp.

The fake serves discovery, JWKS, introspection, the tool-scope map, and an MCP
endpoint that records every request it receives. Keys are TEST-ONLY and made
at run time.
"""

from __future__ import annotations

import http.client
import json
import logging
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
            if state.sse:
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
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
            self._json(200, {"jsonrpc": "2.0", "id": msg.get("id"), "result": {"echo": msg.get("method")}}, {"Mcp-Session-Id": "sess-123"})

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


def _serve(server: ThreadingHTTPServer) -> threading.Thread:
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return t


@pytest.fixture
def rig_factory() -> Iterator[Any]:
    servers: list[ThreadingHTTPServer] = []

    def make(*, introspection: bool = True, audience: str = "kaia-mcp", fake: FakeKaia | None = None, **config_kw: Any) -> Rig:
        fake = fake or FakeKaia(signer=TestSigner.generate(kid="kid-1"))
        upstream = ThreadingHTTPServer(("127.0.0.1", 0), _fake_handler(fake))
        servers.append(upstream)
        _serve(upstream)
        fake.issuer = f"http://127.0.0.1:{upstream.server_address[1]}"
        audit: list[dict[str, Any]] = []
        config, report = build_config(
            upstream=fake.issuer,
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


def _err(data: bytes) -> dict[str, Any]:
    return json.loads(data)["error"]


CALL = lambda tool, i=1, args=None: {"jsonrpc": "2.0", "id": i, "method": "tools/call", "params": {"name": tool, "arguments": args if args is not None else {}}}


def test_allow_forwards_unchanged_with_session_and_auth(rig_factory: Any) -> None:
    rig = rig_factory()
    tok = rig.token("kaia:read")
    body = json.dumps(CALL("get_block_number", 7)).encode()
    status, headers, data = rig.post(body, tok, {"Mcp-Session-Id": "sess-123"})
    assert status == 200
    assert json.loads(data)["result"] == {"echo": "tools/call"}
    assert headers["mcp-session-id"] == "sess-123"
    [seen] = rig.fake.mcp_requests
    assert seen["body"] == body
    assert seen["headers"]["Mcp-Session-Id"] == "sess-123"
    assert seen["headers"]["Authorization"] == f"Bearer {tok}"
    assert rig.audit[-1]["event"] == "allow" and rig.audit[-1]["forwarded"] is True


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
    fake = FakeKaia(signer=TestSigner.generate(kid="kid-1"), sse=True)
    rig = rig_factory(fake=fake)
    status, headers, data = rig.post(CALL("get_block_number"), rig.token("kaia:read"))
    assert status == 200
    assert headers["content-type"] == "text/event-stream"
    assert headers["mcp-session-id"] == "sess-123"
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
