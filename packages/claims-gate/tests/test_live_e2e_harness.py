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


def test_reused_evidence_dir_is_reset_to_this_run(tmp_path: Path) -> None:
    owned = ["audit-main.jsonl", "audit-drift-runtime.jsonl", "proxy-main.log", "kaia-mcp.log", "setup.log", "escalations-cli.log", "escalations.json", "summary.json"]
    for name in [*owned, "live-e2e.stdout", "notes.txt"]:
        (tmp_path / name).write_text("stale\n")
    live.reset_evidence(tmp_path)
    assert sorted(p.name for p in tmp_path.iterdir()) == ["live-e2e.stdout", "notes.txt"]


# ---- allow-read classification: only the pre-call probe may turn it into a SKIP ----


class _Probe:
    def __init__(self, *answers: tuple[bool, str]) -> None:
        self.answers = list(answers)
        self.calls = 0

    def __call__(self) -> tuple[bool, str]:
        self.calls += 1
        return self.answers.pop(0)


def test_allow_read_skips_only_when_the_pre_call_probe_fails(tmp_path: Path) -> None:
    r = live.Run(tmp_path)
    probe = _Probe((False, "http://127.0.0.1:9: URLError"))
    called: list[bool] = []
    live.run_allow_read(r, probe, lambda: called.append(True) or (True, {}))
    assert called == [] and probe.calls == 1
    assert r.checks[0]["result"] == "SKIP" and "before the call" in r.checks[0]["skipReason"]
    assert live.summarize(r.checks)["ok"] is False  # a lone SKIP is not a pass


def test_allow_read_failure_after_the_call_ran_is_fail_even_if_rpc_then_dies(tmp_path: Path) -> None:
    r = live.Run(tmp_path)
    # reachable before the call; a re-probe (if any) would say unreachable
    probe = _Probe((True, "eth_blockNumber=0x10"), (False, "went away"))
    live.run_allow_read(r, probe, lambda: (False, {"status": 200, "resultText": "gate bug"}))
    assert probe.calls == 1  # no re-probe after the call
    assert (r.checks[0]["check"], r.checks[0]["result"], r.checks[0]["ok"]) == ("allow-read", "FAIL", False)
    assert live.summarize(r.checks)["failed"] == 1


def test_allow_read_call_exception_is_fail(tmp_path: Path) -> None:
    r = live.Run(tmp_path)

    def boom() -> tuple[bool, dict[str, Any]]:
        raise ConnectionResetError("reset by proxy")

    live.run_allow_read(r, _Probe((True, "ok")), boom)
    assert r.checks[0]["result"] == "FAIL" and "ConnectionResetError" in r.checks[0]["error"]


def test_allow_read_pass(tmp_path: Path) -> None:
    r = live.Run(tmp_path)
    live.run_allow_read(r, _Probe((True, "eth_blockNumber=0x10")), lambda: (True, {"status": 200}))
    assert r.checks[0]["result"] == "PASS" and r.checks[0]["rpcProbe"] == "eth_blockNumber=0x10"
