#!/usr/bin/env python3
"""Live e2e: s1-tool-gate's claims proxy in front of a real, running kaia-mcp.

Starts kaia-mcp (pinned commit, or a local checkout), starts the proxy, logs in
with the device flow against kaia-mcp's demo IdP, and proves:

  initialize-through-proxy   MCP initialize through the proxy; Mcp-Session-Id passed through
  encode-denied              encode_function_data without kaia:encode denied at the proxy
                             (claims_insufficient_scope); kaia-mcp logs no Tool call for it
  wallet-escalated           generate_wallet escalated (-32051) with a queued escalationId, never forwarded
  escalation-approved-once   after `escalations approve <id>` exactly one identical retry reaches
                             kaia-mcp (which itself refuses: tool_disabled); the next retry is
                             escalated again with a new id
  escalation-denied          after `escalations deny <id>` the identical retry is -32050
                             claims_escalation_denied, never forwarded
  forged-denied              same claims + real kid, foreign key -> claims_invalid_token
  wrong-aud-denied           proxy pinned to audience other-api -> claims_audience_mismatch
  introspection-down         introspection configured but unreachable -> claims_introspection_unavailable
  allow-encode               REQUIRED allow path, offline: encode_function_data with kaia:encode
                             returns balanceOf calldata (0x70a08231...) from kaia-mcp
  revoked-denied             token revoked at kaia-mcp, still valid offline: the proxy forwards it only
                             while its introspection cache entry lives (3s; kaia-mcp itself then
                             refuses it), after that the proxy denies claims_token_revoked
  drift-refused-missing/changed  proxy refuses to start when the tool-scope map is missing or differs
  drift-runtime-fail-closed  proxy running with --drift-interval 1: the map changes -> tools/call
                             denied (claims_tool_scope_drift, not forwarded); map restored -> allowed
  allow-read                 OPTIONAL: get_block_number returns live mainnet data. Needs the public
                             Kaia RPC; reported as SKIP (not a failure) when the RPC is unreachable
  expired-denied             after the access-token TTL -> claims_expired
  audit-denies-never-forwarded   no deny/escalate audit line was forwarded
  no-token-in-logs           no token or secret appears in kaia, proxy, or audit logs

Usage (repo root, with claims-gate installed):

  python packages/claims-gate/e2e/live_kaia.py --evidence-dir DIR [--kaia-dir PATH | --kaia-ref SHA]

Needs git, node>=20, npm, and GitHub egress for the clone. The Kaia public RPC is
only needed for the optional allow-read check. Exit 0 iff no check FAILed
(SKIP is allowed only for optional checks). Nothing here is a real secret:
the introspection secret is random per run, and kaia-mcp's signing key lives only
in that process's memory.
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, ClassVar
from urllib.parse import urlencode

import jwt
from claims_gate.kaia import KAIA_TOOL_SCOPES
from claims_gate.verify import VerifiedClaims, VerifierConfig, verify_access_token
from cryptography.hazmat.primitives.asymmetric import rsa

# kaia-mcp commit that first ships JWT access tokens, JWKS, introspection, and the
# tool-scopes metadata (naveed949/kaia-mcp#3, squash-merge commit on main).
DEFAULT_KAIA_REF = "253d6c88c989019759449b5fbde44ae98ab49096"
DEFAULT_KAIA_REPO = "https://github.com/naveed949/kaia-mcp.git"
INTROSPECTION_CLIENT_ID = "s1-tool-gate"
DEFAULT_KAIA_RPC = "https://public-en.node.kaia.io"
# Checks allowed to SKIP (environment-dependent). Everything else must PASS.
OPTIONAL_CHECKS = frozenset({"allow-read"})
INTROSPECTION_CACHE_TTL = 3.0
BALANCE_OF_ABI = json.dumps([{"type": "function", "name": "balanceOf", "inputs": [{"name": "account", "type": "address"}], "outputs": [{"type": "uint256"}], "stateMutability": "view"}])
BALANCE_OF_ARGS = {"abi": BALANCE_OF_ABI, "functionName": "balanceOf", "args": ["0x1234567890123456789012345678901234567890"]}
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")


def log(msg: str) -> None:
    print(f"[live-e2e] {msg}", flush=True)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def run(cmd: list[str], cwd: Path, logfile: Path) -> None:
    with logfile.open("a") as fh:
        fh.write(f"$ {' '.join(cmd)}\n")
        fh.flush()
        subprocess.run(cmd, cwd=cwd, stdout=fh, stderr=subprocess.STDOUT, check=True)


def request(method: str, url: str, *, body: bytes | None = None, headers: dict[str, str] | None = None, timeout: float = 60) -> tuple[int, dict[str, str], bytes]:
    from urllib.parse import urlsplit

    u = urlsplit(url)
    conn = http.client.HTTPConnection(u.hostname, u.port, timeout=timeout)
    path = (u.path or "/") + (f"?{u.query}" if u.query else "")
    conn.request(method, path, body=body, headers=headers or {})
    r = conn.getresponse()
    data = r.read()
    conn.close()
    return r.status, {k.lower(): v for k, v in r.getheaders()}, data


def form(url: str, fields: dict[str, str]) -> tuple[int, Any]:
    status, _, data = request("POST", url, body=urlencode(fields).encode(), headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        return status, json.loads(data)
    except ValueError:
        return status, data.decode(errors="replace")


def wait_http(url: str, proc: subprocess.Popen[Any], what: str, timeout: float = 60) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"{what} exited with {proc.returncode} before becoming ready")
        try:
            if request("GET", url, timeout=2)[0] == 200:
                return
        except OSError:
            pass
        time.sleep(0.2)
    raise RuntimeError(f"{what} not ready at {url}")


def parse_rpc(headers: dict[str, str], data: bytes) -> Any:
    """JSON body, or the last JSON-RPC message of an SSE stream."""
    if headers.get("content-type", "").startswith("text/event-stream"):
        msgs = [json.loads(line[5:].strip()) for line in data.decode().splitlines() if line.startswith("data:") and line[5:].strip()]
        return msgs[-1] if msgs else None
    return json.loads(data) if data else None


class Mcp:
    """Minimal Streamable HTTP MCP client (through the proxy)."""

    INIT: ClassVar[dict[str, Any]] = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "s1-live-e2e", "version": "0"}}}

    def __init__(self, url: str, token: str) -> None:
        self.url, self.token, self.session = url, token, None
        self._id = 10

    def post(self, msg: Any) -> tuple[int, dict[str, str], Any]:
        h = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream", "Authorization": f"Bearer {self.token}"}
        if self.session:
            h["Mcp-Session-Id"] = self.session
        status, headers, data = request("POST", self.url, body=json.dumps(msg).encode(), headers=h)
        return status, headers, parse_rpc(headers, data) if status != 202 else None

    def initialize(self) -> tuple[int, Any]:
        status, headers, body = self.post(self.INIT)
        if status == 200:
            self.session = headers.get("mcp-session-id")
            self.post({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return status, body

    def call(self, tool: str, args: dict[str, Any] | None = None) -> tuple[int, Any]:
        self._id += 1
        status, _, body = self.post({"jsonrpc": "2.0", "id": self._id, "method": "tools/call", "params": {"name": tool, "arguments": args or {}}})
        return status, body


def rpc_reachable(url: str, timeout: float = 8.0) -> tuple[bool, str]:
    """POST eth_blockNumber to a JSON-RPC endpoint. (True, detail) only for a JSON-RPC ``result``."""
    import urllib.error
    import urllib.request

    req = urllib.request.Request(url, data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber", "params": []}).encode(), headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            doc = json.loads(resp.read())
    except (OSError, urllib.error.URLError, ValueError) as err:
        return False, f"{url}: {type(err).__name__}: {err}"[:300]
    if isinstance(doc, dict) and isinstance(doc.get("result"), str):
        return True, f"{url}: eth_blockNumber={doc['result']}"
    return False, f"{url}: no JSON-RPC result"


# Artifacts this harness writes into --evidence-dir. Several are appended to, so a
# reused dir is reset first or a previous run's lines would be counted again.
EVIDENCE_PATTERNS = ("audit-*.jsonl", "proxy-*.log", "kaia-mcp.log", "setup.log", "escalations-cli.log", "escalations.json", "summary.json")


def reset_evidence(evidence: Path) -> None:
    for pattern in EVIDENCE_PATTERNS:
        for stale in evidence.glob(pattern):
            stale.unlink()


def summarize(checks: list[dict[str, Any]]) -> dict[str, Any]:
    passed = sum(c["result"] == "PASS" for c in checks)
    failed = sum(c["result"] != "PASS" and c["result"] != "SKIP" for c in checks)
    skipped = sum(c["result"] == "SKIP" for c in checks)
    return {"passed": passed, "failed": failed, "skipped": skipped, "total": len(checks), "ok": failed == 0 and passed > 0}


class Run:
    def __init__(self, evidence: Path) -> None:
        self.evidence = evidence
        self.checks: list[dict[str, Any]] = []
        self.procs: list[subprocess.Popen[Any]] = []
        self.tokens: list[str] = []

    def check(self, name: str, ok: bool, **observed: Any) -> None:
        result = "PASS" if ok else "FAIL"
        # "check"/"result"/"ok" are written last so an observed field can never overwrite them.
        self.checks.append({**observed, "check": name, "result": result, "ok": bool(ok)})
        log(f"{result} {name} {json.dumps(observed, sort_keys=True)}")

    def skip(self, name: str, reason: str, **observed: Any) -> None:
        """SKIP an optional check. A required check cannot be skipped: it FAILs."""
        if name not in OPTIONAL_CHECKS:
            self.check(name, False, skipRefused=f"required check cannot SKIP: {reason}", **observed)
            return
        self.checks.append({**observed, "check": name, "result": "SKIP", "ok": None, "skipReason": reason})
        log(f"SKIP {name} (optional; not a failure): {reason}")

    def spawn(self, cmd: list[str], *, cwd: Path, env: dict[str, str], logfile: Path) -> subprocess.Popen[Any]:
        fh = logfile.open("w")
        p = subprocess.Popen(cmd, cwd=cwd, env=env, stdout=fh, stderr=subprocess.STDOUT)
        self.procs.append(p)
        return p

    def stop_all(self) -> None:
        for p in self.procs:
            if p.poll() is None:
                p.terminate()
                try:
                    p.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    p.kill()


def prepare_kaia(args: argparse.Namespace, work: Path, run_log: Path) -> tuple[Path, str]:
    if args.kaia_dir:
        kaia = Path(args.kaia_dir).resolve()
        log(f"kaia-mcp from local dir {kaia}")
    else:
        kaia = work / "kaia-mcp"
        kaia.mkdir(parents=True)
        log(f"kaia-mcp clone {args.kaia_repo}@{args.kaia_ref}")
        run(["git", "init", "-q"], kaia, run_log)
        run(["git", "remote", "add", "origin", args.kaia_repo], kaia, run_log)
        run(["git", "fetch", "-q", "--depth", "1", "origin", args.kaia_ref], kaia, run_log)
        run(["git", "checkout", "-q", "FETCH_HEAD"], kaia, run_log)
        run(["npm", "ci", "--no-audit", "--no-fund"], kaia, run_log)
    if not args.skip_build:
        run(["npm", "run", "build"], kaia, run_log)
    rev = subprocess.run(["git", "rev-parse", "HEAD"], cwd=kaia, capture_output=True, text=True, check=False).stdout.strip() or "unknown"
    dirty = subprocess.run(["git", "status", "--porcelain", "--untracked-files=no"], cwd=kaia, capture_output=True, text=True, check=False).stdout.strip()
    return kaia, rev + ("+dirty" if dirty else "")


def start_proxy(r: Run, name: str, kaia_url: str, *, audience: str = "kaia-mcp", extra: list[str] | None = None, env_extra: dict[str, str] | None = None, expect_ready: bool = True) -> tuple[str, subprocess.Popen[Any], Path]:
    port = free_port()
    logfile = r.evidence / f"proxy-{name}.log"
    cmd = [sys.executable, "-m", "claims_gate", "proxy", "--upstream", kaia_url, "--issuer", kaia_url, "--audience", audience, "--port", str(port), "--audit-log", str(r.evidence / f"audit-{name}.jsonl"), *(extra or [])]
    env = {**os.environ, **(env_extra or {})}
    p = r.spawn(cmd, cwd=Path.cwd(), env=env, logfile=logfile)
    url = f"http://127.0.0.1:{port}/"
    if expect_ready:
        wait_http(f"http://127.0.0.1:{port}/health", p, f"proxy {name}")
    return url, p, logfile


def device_login(kaia_url: str, scope: str) -> dict[str, Any]:
    status, start = form(kaia_url + "/oauth/device", {"client_id": "kaia-mcp-demo", "scope": scope})
    assert status == 200, start
    status, _ = form(kaia_url + "/oauth/device/verify", {"user_code": start["user_code"], "decision": "approve"})
    assert status == 200
    status, tok = form(kaia_url + "/oauth/token", {"grant_type": "urn:ietf:params:oauth:grant-type:device_code", "client_id": "kaia-mcp-demo", "device_code": start["device_code"]})
    assert status == 200 and tok.get("access_token"), {k: v for k, v in tok.items() if "token" not in k}
    return tok


def tool_calls(kaia_log: Path, tool: str) -> int:
    return len(re.findall(rf"msg=Tool call tool={re.escape(tool)} ", kaia_log.read_text()))


def result_text(body: Any) -> str:
    content = ((body or {}).get("result") or {}).get("content") or []
    return "".join(c.get("text", "") for c in content if isinstance(c, dict))


def wait_for(pred: Any, timeout: float) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if pred():
                return True
        except (OSError, ValueError, KeyError):
            pass
        time.sleep(0.2)
    return False


def reason(body: Any) -> str | None:
    try:
        return body["error"]["data"]["reasonCode"]
    except (TypeError, KeyError):
        return None


def serve_json(doc: Any) -> tuple[ThreadingHTTPServer, str]:
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a: Any) -> None:
            return

        def do_GET(self) -> None:
            data = json.dumps(doc).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/tool-scopes"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--evidence-dir", required=True)
    ap.add_argument("--kaia-dir", default=os.environ.get("KAIA_MCP_DIR"), help="local kaia-mcp checkout (default: clone --kaia-ref)")
    ap.add_argument("--kaia-ref", default=os.environ.get("KAIA_MCP_REF", DEFAULT_KAIA_REF))
    ap.add_argument("--kaia-repo", default=DEFAULT_KAIA_REPO)
    ap.add_argument("--skip-build", action="store_true", help="with --kaia-dir: use its existing dist/")
    ap.add_argument("--token-ttl", type=int, default=15)
    ap.add_argument("--keep-work", action="store_true")
    args = ap.parse_args()

    evidence = Path(args.evidence_dir).resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    reset_evidence(evidence)
    work = Path(tempfile.mkdtemp(prefix="s1-live-e2e-"))
    r = Run(evidence)
    started = time.time()
    meta: dict[str, Any] = {"startedAt": started}
    try:
        kaia_dir, kaia_rev = prepare_kaia(args, work, evidence / "setup.log")
        meta["kaia"] = {"rev": kaia_rev, "dir": str(kaia_dir) if args.kaia_dir else "clone", "ref": None if args.kaia_dir else args.kaia_ref}

        kport = free_port()
        kaia_url = f"http://127.0.0.1:{kport}"
        kaia_log = evidence / "kaia-mcp.log"
        introspection_secret = secrets.token_urlsafe(24)
        r.tokens.append(introspection_secret)  # scanned like a token: must never reach a log
        kaia_env = {
            **os.environ,
            "KAIA_AUTH_MODE": "required",
            "KAIA_ALLOW_UNSAFE_WALLET": "",
            "KAIA_ACCESS_TOKEN_TTL_SECONDS": str(args.token_ttl),
            "KAIA_OAUTH_SIGNING_KEY_FILE": "",
            "KAIA_INTROSPECTION_CLIENT_ID": INTROSPECTION_CLIENT_ID,
            "KAIA_INTROSPECTION_CLIENT_SECRET": introspection_secret,
            "LOG_LEVEL": "info",
        }
        kp = r.spawn(["node", "dist/bin/kaia-mcp.js", "--transport", "http", "--port", str(kport)], cwd=kaia_dir, env=kaia_env, logfile=kaia_log)
        wait_http(kaia_url + "/health", kp, "kaia-mcp")
        log(f"kaia-mcp {kaia_rev} up at {kaia_url}")

        gw_env = {"S1_INTROSPECTION_CLIENT_ID": INTROSPECTION_CLIENT_ID, "S1_INTROSPECTION_CLIENT_SECRET": introspection_secret}
        esc_dir = work / "escalations"
        proxy_url, _, _ = start_proxy(r, "main", kaia_url, extra=["--introspection", "auto", "--introspection-cache-ttl", str(INTROSPECTION_CACHE_TTL), "--escalation-dir", str(esc_dir)], env_extra=gw_env)
        log(f"proxy up at {proxy_url}")

        def escalations(*cli: str) -> tuple[int, Any]:
            out = subprocess.run([sys.executable, "-m", "claims_gate", "escalations", *cli, "--dir", str(esc_dir)], capture_output=True, text=True, check=False)
            with (evidence / "escalations-cli.log").open("a") as fh:
                fh.write(f"$ escalations {' '.join(cli)} -> exit {out.returncode}\n{out.stdout}{out.stderr}")
            try:
                return out.returncode, json.loads(out.stdout) if out.stdout.strip() else None
            except ValueError:
                return out.returncode, None

        # Device-flow login (kaia:read + kaia:wallet; deliberately no kaia:encode).
        t1 = device_login(kaia_url, "kaia:read kaia:wallet")
        r.tokens += [t1["access_token"], t1["refresh_token"]]
        access = t1["access_token"]
        claims = jwt.decode(access, options={"verify_signature": False})
        header = jwt.get_unverified_header(access)
        meta["token"] = {"alg": header.get("alg"), "kid": header.get("kid"), "aud": claims.get("aud"), "iss": claims.get("iss"), "scope": claims.get("scope"), "ttl": claims["exp"] - claims["iat"]}

        mcp = Mcp(proxy_url, access)
        st, body = mcp.initialize()
        r.check("initialize-through-proxy", st == 200 and bool(mcp.session), status=st, sessionIdForwarded=bool(mcp.session))

        st, body = mcp.call("encode_function_data", BALANCE_OF_ARGS)
        r.check("encode-denied", st == 200 and body["error"]["code"] == -32050 and reason(body) == "claims_insufficient_scope" and tool_calls(kaia_log, "encode_function_data") == 0, status=st, error=body.get("error"), kaiaToolCallLines=tool_calls(kaia_log, "encode_function_data"))

        st, body = mcp.call("generate_wallet")
        err = (body or {}).get("error") or {}
        id1 = (err.get("data") or {}).get("escalationId")
        _, queued = escalations("list")
        queued_row = next((e for e in queued or [] if e.get("id") == id1), None)
        r.check("wallet-escalated", st == 200 and err.get("code") == -32051 and reason(body) == "claims_wallet_escalate" and bool(id1) and queued_row is not None and queued_row["status"] == "pending" and queued_row["sub"] == claims["sub"] and tool_calls(kaia_log, "generate_wallet") == 0, status=st, error=err, queued=queued_row, kaiaToolCallLines=tool_calls(kaia_log, "generate_wallet"))

        rc_approve, approved = escalations("approve", str(id1))
        st_retry, retry = mcp.call("generate_wallet")
        lines_after_retry = tool_calls(kaia_log, "generate_wallet")
        st_again, again = mcp.call("generate_wallet")
        id2 = (((again or {}).get("error") or {}).get("data") or {}).get("escalationId")
        _, rows = escalations("list")
        by_id = {e["id"]: e for e in rows or []}
        retry_err = (retry or {}).get("error") or {}
        kaia_answered = retry_err.get("code") not in (-32050, -32051) and "tool_disabled" in json.dumps(retry)
        r.check(
            "escalation-approved-once",
            rc_approve == 0 and (approved or {}).get("status") == "approved" and st_retry == 200 and kaia_answered and lines_after_retry == 1
            and st_again == 200 and ((again or {}).get("error") or {}).get("code") == -32051 and bool(id2) and id2 != id1
            and tool_calls(kaia_log, "generate_wallet") == 1 and by_id.get(id1, {}).get("status") == "consumed" and by_id.get(id2, {}).get("status") == "pending",
            approveExit=rc_approve, retryStatus=st_retry, retryAnsweredByKaia=kaia_answered, retryBody=json.dumps(retry)[:300],
            kaiaToolCallLines=tool_calls(kaia_log, "generate_wallet"), nextEscalationId=id2, statuses={k: v["status"] for k, v in by_id.items()},
        )

        rc_deny, denied = escalations("deny", str(id2))
        st, body = mcp.call("generate_wallet")
        err = (body or {}).get("error") or {}
        r.check("escalation-denied", rc_deny == 0 and (denied or {}).get("status") == "denied" and st == 200 and err.get("code") == -32050 and reason(body) == "claims_escalation_denied" and (err.get("data") or {}).get("escalationId") == id2 and tool_calls(kaia_log, "generate_wallet") == 1, denyExit=rc_deny, status=st, error=err, kaiaToolCallLines=tool_calls(kaia_log, "generate_wallet"))
        _, final_rows = escalations("list")
        (evidence / "escalations.json").write_text(json.dumps(final_rows, indent=2) + "\n")

        foreign = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        forged = jwt.encode(claims, foreign, algorithm="RS256", headers={"kid": header["kid"], "typ": "at+jwt"})
        r.tokens.append(forged)
        st, body = Mcp(proxy_url, forged).initialize()
        r.check("forged-denied", st == 401 and reason(body) == "claims_invalid_token", status=st, reasonCode=reason(body))

        wrong_aud_url, _, _ = start_proxy(r, "wrong-aud", kaia_url, audience="other-api")
        st, body = Mcp(wrong_aud_url, access).initialize()
        r.check("wrong-aud-denied", st == 401 and reason(body) == "claims_audience_mismatch", status=st, reasonCode=reason(body), proxyAudience="other-api", tokenAud=claims.get("aud"))

        # Fresh kaia:encode token (independent of t1's short TTL).
        t3 = device_login(kaia_url, "kaia:encode")
        r.tokens += [t3["access_token"], t3["refresh_token"]]

        dead = f"http://127.0.0.1:{free_port()}/oauth/introspect"
        down_url, _, _ = start_proxy(r, "introspection-down", kaia_url, extra=["--introspection", dead], env_extra=gw_env)
        st, body = Mcp(down_url, t3["access_token"]).initialize()
        r.check("introspection-down", st == 401 and reason(body) == "claims_introspection_unavailable", status=st, reasonCode=reason(body))

        m3 = Mcp(proxy_url, t3["access_token"])
        st_init, _ = m3.initialize()
        before = tool_calls(kaia_log, "encode_function_data")
        st, body = m3.call("encode_function_data", BALANCE_OF_ARGS)
        text = result_text(body)
        r.check("allow-encode", st_init == 200 and st == 200 and "error" not in (body or {}) and re.fullmatch(r"0x70a08231[0-9a-fA-F]{64}", text.strip()) is not None and tool_calls(kaia_log, "encode_function_data") == before + 1, status=st, resultText=text[:200], kaiaToolCallLines=tool_calls(kaia_log, "encode_function_data"))

        t2 = device_login(kaia_url, "kaia:read")
        r.tokens += [t2["access_token"], t2["refresh_token"]]
        m2 = Mcp(proxy_url, t2["access_token"])
        st_before, _ = m2.initialize()
        cached_at = time.time()
        rv_status, _ = form(kaia_url + "/oauth/revoke", {"token": t2["access_token"]})
        _, _, jwks_raw = request("GET", kaia_url + "/oauth/jwks")
        offline = verify_access_token(t2["access_token"], VerifierConfig(jwks=json.loads(jwks_raw), issuer=kaia_url, audience="kaia-mcp"))
        # Within the cache TTL the proxy still lets the revoked token through (documented
        # revocation latency); kaia-mcp then refuses it itself (defense in depth).
        st_cached, b_cached = Mcp(proxy_url, t2["access_token"]).initialize()
        cached_window = time.time() - cached_at
        proxy_reason_cached = reason(b_cached)
        proxy_let_through = not (proxy_reason_cached or "").startswith("claims_")
        time.sleep(max(0.0, cached_at + INTROSPECTION_CACHE_TTL + 0.5 - time.time()))
        st, body = Mcp(proxy_url, t2["access_token"]).initialize()
        r.check(
            "revoked-denied",
            st_before == 200 and rv_status == 200 and isinstance(offline, VerifiedClaims) and cached_window < INTROSPECTION_CACHE_TTL and proxy_let_through and st == 401 and reason(body) == "claims_token_revoked",
            statusBeforeRevoke=st_before, revokeStatus=rv_status, stillValidOffline=isinstance(offline, VerifiedClaims),
            introspectionCacheTtl=INTROSPECTION_CACHE_TTL, withinCacheTtl={"proxyForwarded": proxy_let_through, "proxyReasonCode": proxy_reason_cached, "kaiaStatus": st_cached},
            status=st, reasonCode=reason(body),
        )

        for name, url_or_doc in (("drift-missing", kaia_url + "/.well-known/kaia-mcp/does-not-exist"), ("drift-changed", dict(KAIA_TOOL_SCOPES, encode_function_data="kaia:read"))):
            srv = None
            if isinstance(url_or_doc, dict):
                srv, url = serve_json({"tool_scopes": url_or_doc})
            else:
                url = url_or_doc
            _, p, plog = start_proxy(r, name, kaia_url, extra=["--tool-scopes-url", url], expect_ready=False)
            try:
                rc = p.wait(timeout=30)
            except subprocess.TimeoutExpired:
                rc = None
            if srv:
                srv.shutdown()
            out = plog.read_text()
            r.check(name.replace("drift-", "drift-refused-"), rc == 3 and "ready:" not in out and "refusing to start" in out, exitCode=rc)

        # Runtime drift: the proxy starts against a matching map that then changes under it.
        live_map = {"tool_scopes": dict(KAIA_TOOL_SCOPES)}
        srv, url = serve_json(live_map)
        try:
            rt_url, _, rt_log = start_proxy(r, "drift-runtime", kaia_url, extra=["--tool-scopes-url", url, "--drift-interval", "1"])
            health = rt_url.rstrip("/") + "/health"
            t4 = device_login(kaia_url, "kaia:encode")
            r.tokens += [t4["access_token"], t4["refresh_token"]]
            m4 = Mcp(rt_url, t4["access_token"])
            m4.initialize()
            n0 = tool_calls(kaia_log, "encode_function_data")
            st_ok, b_ok = m4.call("encode_function_data", BALANCE_OF_ARGS)
            live_map["tool_scopes"] = dict(KAIA_TOOL_SCOPES, encode_function_data="kaia:read")
            flipped = wait_for(lambda: not json.loads(request("GET", health)[2])["toolScopes"]["ok"], 10)
            st_drift, b_drift = m4.call("encode_function_data", BALANCE_OF_ARGS)
            n1 = tool_calls(kaia_log, "encode_function_data")
            live_map["tool_scopes"] = dict(KAIA_TOOL_SCOPES)
            recovered = wait_for(lambda: json.loads(request("GET", health)[2])["toolScopes"]["ok"], 10)
            st_back, b_back = m4.call("encode_function_data", BALANCE_OF_ARGS)
            n2 = tool_calls(kaia_log, "encode_function_data")
        finally:
            srv.shutdown()
        rt_text = rt_log.read_text()
        r.check(
            "drift-runtime-fail-closed",
            st_ok == 200 and "error" not in (b_ok or {}) and flipped and st_drift == 200 and reason(b_drift) == "claims_tool_scope_drift" and n1 == n0 + 1
            and recovered and st_back == 200 and "error" not in (b_back or {}) and n2 == n1 + 1 and "ok -> drift" in rt_text and "drift -> ok" in rt_text,
            beforeStatus=st_ok, flippedToClosed=flipped, duringDriftReason=reason(b_drift), recovered=recovered, afterStatus=st_back,
            kaiaToolCallLines=[n0, n1, n2], transitionsLogged=["ok -> drift" in rt_text, "drift -> ok" in rt_text],
        )

        # Optional live chain read: SKIP (not FAIL) when the public RPC is unreachable.
        rpc_url = os.environ.get("KAIA_RPC_URL") or DEFAULT_KAIA_RPC
        reachable, probe = rpc_reachable(rpc_url)
        if not reachable:
            r.skip("allow-read", f"Kaia RPC unreachable before the call: {probe}")
        else:
            t5 = device_login(kaia_url, "kaia:read")
            r.tokens += [t5["access_token"], t5["refresh_token"]]
            m5 = Mcp(proxy_url, t5["access_token"])
            m5.initialize()
            before_read = tool_calls(kaia_log, "get_block_number")
            st, body = m5.call("get_block_number", {"network": "mainnet"})
            text = result_text(body)
            block = re.search(r"\d{6,}", text)
            ok = st == 200 and "error" not in (body or {}) and block is not None and tool_calls(kaia_log, "get_block_number") == before_read + 1
            observed = {"status": st, "resultText": text[:200], "kaiaToolCallLines": tool_calls(kaia_log, "get_block_number"), "rpcProbe": probe}
            still, probe_after = (True, probe) if ok else rpc_reachable(rpc_url)
            if not ok and not still:
                r.skip("allow-read", f"Kaia RPC became unreachable during the call: {probe_after}", **observed)
            else:
                r.check("allow-read", ok, **observed)

        wait = claims["exp"] - time.time() + 1.5
        if wait > 0:
            log(f"waiting {wait:.1f}s for the first access token to expire")
            time.sleep(wait)
        before_exp = tool_calls(kaia_log, "get_block_number")
        st, body = mcp.call("get_block_number", {"network": "mainnet"})
        r.check("expired-denied", st == 401 and reason(body) == "claims_expired" and tool_calls(kaia_log, "get_block_number") == before_exp, status=st, reasonCode=reason(body))

        audit = [json.loads(line) for line in (evidence / "audit-main.jsonl").read_text().splitlines() if line.strip()]
        denied_forwarded = [a for a in audit if a.get("event") in ("deny", "escalate") and a.get("forwarded")]
        approved_forwarded = [a for a in audit if a.get("stage") == "escalation" and a.get("event") == "allow" and a.get("forwarded")]
        r.check("audit-denies-never-forwarded", len(audit) > 0 and not denied_forwarded and len(approved_forwarded) == 1, auditLines=len(audit), deniedButForwarded=len(denied_forwarded), approvedEscalationsForwarded=len(approved_forwarded))
    except Exception as err:  # noqa: BLE001 - report any harness failure as a failed check
        r.check("harness", False, error=f"{type(err).__name__}: {err}")
    finally:
        r.stop_all()
        time.sleep(0.2)
        blobs = {p.name: p.read_text(errors="replace") for p in evidence.glob("*.log")} | {p.name: p.read_text() for p in evidence.glob("*.jsonl")}
        leaks = sorted({name for name, text in blobs.items() for t in r.tokens if t and t in text} | {name for name, text in blobs.items() if JWT_RE.search(text)})
        r.check("no-token-in-logs", not leaks and len(r.tokens) > 1, filesScanned=sorted(blobs), secretsChecked=len(r.tokens), leakingFiles=leaks)
        if not args.keep_work:
            shutil.rmtree(work, ignore_errors=True)

    meta["elapsedSeconds"] = round(time.time() - started, 1)
    totals = summarize(r.checks)
    summary = {"summary": totals, "meta": meta, "checks": r.checks}
    (evidence / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    skipped = [c["check"] for c in r.checks if c["result"] == "SKIP"]
    log(f"{totals['passed']}/{totals['total']} checks passed, {totals['failed']} failed, {totals['skipped']} skipped{' (' + ', '.join(skipped) + ')' if skipped else ''}; evidence in {evidence}")
    return 0 if totals["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
