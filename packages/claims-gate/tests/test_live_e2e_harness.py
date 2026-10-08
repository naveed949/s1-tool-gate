"""Offline tests for the live e2e harness's check bookkeeping (e2e/live_kaia.py).

Only optional checks may SKIP; a SKIP never fails the run, and a skipped
required check counts as a failure.
"""

from __future__ import annotations

import importlib.util
import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

_SPEC = importlib.util.spec_from_file_location("live_kaia", Path(__file__).resolve().parents[1] / "e2e" / "live_kaia.py")
assert _SPEC and _SPEC.loader
live = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(live)


def test_allow_read_is_the_only_optional_check() -> None:
    assert live.OPTIONAL_CHECKS == frozenset({"allow-read"})


def test_skip_of_optional_check_does_not_fail_the_run(tmp_path: Path) -> None:
    r = live.Run(tmp_path)
    r.check("allow-encode", True)
    r.skip("allow-read", "Kaia RPC unreachable: https://public-en.node.kaia.io (URLError)")
    s = live.summarize(r.checks)
    assert s == {"passed": 1, "failed": 0, "skipped": 1, "total": 2, "ok": True}
    assert r.checks[1]["result"] == "SKIP" and r.checks[1]["ok"] is None and "unreachable" in r.checks[1]["skipReason"]


def test_skip_of_required_check_is_a_failure(tmp_path: Path) -> None:
    r = live.Run(tmp_path)
    r.skip("allow-encode", "whatever")
    assert r.checks[0]["result"] == "FAIL" and r.checks[0]["ok"] is False
    assert live.summarize(r.checks)["ok"] is False


def test_optional_check_that_ran_and_failed_fails(tmp_path: Path) -> None:
    r = live.Run(tmp_path)
    r.check("allow-read", False)
    assert live.summarize(r.checks) == {"passed": 0, "failed": 1, "skipped": 0, "total": 1, "ok": False}


def test_observed_fields_cannot_overwrite_the_result(tmp_path: Path) -> None:
    r = live.Run(tmp_path)
    r.check("revoked-denied", False, status=401, result="PASS", check="other")  # e.g. an HTTP status field
    assert (r.checks[0]["check"], r.checks[0]["result"], r.checks[0]["ok"], r.checks[0]["status"]) == ("revoked-denied", "FAIL", False, 401)
    assert live.summarize(r.checks)["ok"] is False


def _rpc_server(body: bytes) -> tuple[ThreadingHTTPServer, str]:
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a: Any) -> None:
            return

        def do_POST(self) -> None:
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


@pytest.mark.parametrize(("body", "reachable"), [(json.dumps({"jsonrpc": "2.0", "id": 1, "result": "0x10"}).encode(), True), (b"<html>blocked</html>", False), (json.dumps({"error": {"code": -32000}}).encode(), False)])
def test_rpc_probe(body: bytes, reachable: bool) -> None:
    srv, url = _rpc_server(body)
    try:
        ok, detail = live.rpc_reachable(url, timeout=3)
        assert ok is reachable, detail
    finally:
        srv.shutdown()
        srv.server_close()


def test_rpc_probe_dead_port() -> None:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    ok, detail = live.rpc_reachable(f"http://127.0.0.1:{port}", timeout=2)
    assert ok is False and detail
