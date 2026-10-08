#!/usr/bin/env python3
"""Live e2e: s1-tool-gate's claims proxy in front of a real, running kaia-mcp.

Starts kaia-mcp (pinned commit, or a local checkout), starts the proxy, logs in
with the device flow against kaia-mcp's demo IdP, and proves:

  allow-read            get_block_number through the proxy returns live chain data
  encode-denied         encode_function_data denied at the proxy (claims_insufficient_scope),
                        and kaia-mcp's log has no Tool call line for it
  wallet-escalated      generate_wallet escalated (-32051), never forwarded
  forged-denied         same claims + real kid, foreign key -> claims_invalid_token
  wrong-aud-denied      proxy pinned to audience other-api -> claims_audience_mismatch
  revoked-denied        token revoked at kaia-mcp, still valid offline, denied via
                        introspection -> claims_token_revoked
  introspection-down    introspection configured but unreachable -> claims_introspection_unavailable
  expired-denied        after the access-token TTL -> claims_expired
  drift-refused         proxy refuses to start when the tool-scope map differs or is missing
  no-token-in-logs      no token appears in kaia, proxy, or audit logs

Usage (repo root, with claims-gate installed):

  python packages/claims-gate/e2e/live_kaia.py --evidence-dir DIR [--kaia-dir PATH | --kaia-ref SHA]

Needs git, node>=20, npm, and outbound HTTPS (GitHub for the clone, Kaia public RPC
for the read). Exit 0 only when every check passed. Nothing here is a real secret:
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


class Run:
    def __init__(self, evidence: Path) -> None:
        self.evidence = evidence
        self.checks: list[dict[str, Any]] = []
        self.procs: list[subprocess.Popen[Any]] = []
        self.tokens: list[str] = []

    def check(self, name: str, ok: bool, **observed: Any) -> None:
        self.checks.append({"check": name, "ok": bool(ok), **observed})
        log(f"{'PASS' if ok else 'FAIL'} {name} {json.dumps(observed, sort_keys=True)}")

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
        proxy_url, _, _ = start_proxy(r, "main", kaia_url, extra=["--introspection", "auto"], env_extra=gw_env)
        log(f"proxy up at {proxy_url}")

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

        before = tool_calls(kaia_log, "get_block_number")
        st, body = mcp.call("get_block_number", {"network": "mainnet"})
        text = "".join(c.get("text", "") for c in (body or {}).get("result", {}).get("content", []) if isinstance(c, dict))
        block = re.search(r"\d{6,}", text)
        r.check("allow-read", st == 200 and "error" not in (body or {}) and block is not None and tool_calls(kaia_log, "get_block_number") == before + 1, status=st, resultText=text[:200], kaiaToolCallLines=tool_calls(kaia_log, "get_block_number"))

        st, body = mcp.call("encode_function_data", {"abi": "[]", "functionName": "x", "args": []})
        r.check("encode-denied", st == 200 and body["error"]["code"] == -32050 and reason(body) == "claims_insufficient_scope" and tool_calls(kaia_log, "encode_function_data") == 0, status=st, error=body.get("error"), kaiaToolCallLines=tool_calls(kaia_log, "encode_function_data"))

        st, body = mcp.call("generate_wallet")
        r.check("wallet-escalated", st == 200 and body["error"]["code"] == -32051 and reason(body) == "claims_wallet_escalate" and bool(body["error"]["data"].get("escalationId")) and tool_calls(kaia_log, "generate_wallet") == 0, status=st, error=body.get("error"), kaiaToolCallLines=tool_calls(kaia_log, "generate_wallet"))

        foreign = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        forged = jwt.encode(claims, foreign, algorithm="RS256", headers={"kid": header["kid"], "typ": "at+jwt"})
        r.tokens.append(forged)
        st, body = Mcp(proxy_url, forged).initialize()
        r.check("forged-denied", st == 401 and reason(body) == "claims_invalid_token", status=st, reasonCode=reason(body))

        wrong_aud_url, _, _ = start_proxy(r, "wrong-aud", kaia_url, audience="other-api")
        st, body = Mcp(wrong_aud_url, access).initialize()
        r.check("wrong-aud-denied", st == 401 and reason(body) == "claims_audience_mismatch", status=st, reasonCode=reason(body), proxyAudience="other-api", tokenAud=claims.get("aud"))

        dead = f"http://127.0.0.1:{free_port()}/oauth/introspect"
        down_url, _, _ = start_proxy(r, "introspection-down", kaia_url, extra=["--introspection", dead], env_extra=gw_env)
        st, body = Mcp(down_url, access).initialize()
        r.check("introspection-down", st == 401 and reason(body) == "claims_introspection_unavailable", status=st, reasonCode=reason(body))

        t2 = device_login(kaia_url, "kaia:read")
        r.tokens += [t2["access_token"], t2["refresh_token"]]
        m2 = Mcp(proxy_url, t2["access_token"])
        st_before, _ = m2.initialize()
        rv_status, _ = form(kaia_url + "/oauth/revoke", {"token": t2["access_token"]})
        _, _, jwks_raw = request("GET", kaia_url + "/oauth/jwks")
        offline = verify_access_token(t2["access_token"], VerifierConfig(jwks=json.loads(jwks_raw), issuer=kaia_url, audience="kaia-mcp"))
        st, body = Mcp(proxy_url, t2["access_token"]).initialize()
        r.check("revoked-denied", st_before == 200 and rv_status == 200 and isinstance(offline, VerifiedClaims) and st == 401 and reason(body) == "claims_token_revoked", statusBeforeRevoke=st_before, revokeStatus=rv_status, stillValidOffline=isinstance(offline, VerifiedClaims), status=st, reasonCode=reason(body))

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

        wait = claims["exp"] - time.time() + 1.5
        if wait > 0:
            log(f"waiting {wait:.1f}s for the first access token to expire")
            time.sleep(wait)
        st, body = mcp.call("get_block_number", {"network": "mainnet"})
        r.check("expired-denied", st == 401 and reason(body) == "claims_expired" and tool_calls(kaia_log, "get_block_number") == before + 1, status=st, reasonCode=reason(body))

        audit = [json.loads(line) for line in (evidence / "audit-main.jsonl").read_text().splitlines() if line.strip()]
        denied_forwarded = [a for a in audit if a.get("event") in ("deny", "escalate") and a.get("forwarded")]
        r.check("audit-denies-never-forwarded", len(audit) > 0 and not denied_forwarded, auditLines=len(audit), deniedButForwarded=len(denied_forwarded))
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
    passed = sum(c["ok"] for c in r.checks)
    summary = {"summary": {"passed": passed, "total": len(r.checks), "ok": passed == len(r.checks)}, "meta": meta, "checks": r.checks}
    (evidence / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    log(f"{passed}/{len(r.checks)} checks passed; evidence in {evidence}")
    return 0 if passed == len(r.checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
