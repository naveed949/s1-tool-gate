"""CLI for the claims gate.

  python -m claims_gate tools
  python -m claims_gate demo [--wallet-default escalate|deny]
  python -m claims_gate testkit init --dir DIR
  python -m claims_gate testkit mint --dir DIR [--scope S] [--sub S] [--aud A] [--iss I]
                                     [--exp-in SECONDS] [--untrusted]
  S1_AUTHORIZATION="Bearer <jwt>" python -m claims_gate decide --jwks FILE --issuer ISS \
      --audience AUD --tool TOOL [--wallet-default escalate|deny]
  [S1_INTROSPECTION_CLIENT_ID=... S1_INTROSPECTION_CLIENT_SECRET=...] \
  python -m claims_gate proxy --upstream URL --issuer ISS --audience AUD [--port N]
      [--introspection auto|URL] [--jwks-uri URL] [--tool-scopes-url URL | --no-drift-check]
      [--audit-log FILE] [--wallet-default escalate|deny]
      [--escalation-dir DIR [--escalation-pending-ttl S] [--escalation-approval-ttl S]]
  python -m claims_gate escalations list [--status STATUS] [--dir DIR]
  python -m claims_gate escalations approve|deny ID [--dir DIR]

``decide`` reads the Authorization value from the ``S1_AUTHORIZATION`` env var
(or ``--authorization-file``) so tokens stay out of argv. It prints the
decision JSON and exits 0 for any decision; exit 2 is a usage/config error.
``demo`` exits 0 only when every golden case matched.
``proxy`` prints its startup report as JSON, then ``ready: ...``, and serves
until interrupted. It exits 3 without listening if discovery, the JWKS, the
introspection setup, or the tool-scope drift check fails (fail closed).
Introspection credentials come from the environment, never argv.
``escalations`` reads the queue in ``--dir`` (default ``$S1_ESCALATION_DIR``),
prints JSON, and exits 0; 1 if the approve/deny is not allowed from the
escalation's current state; 2 if no queue directory was given.
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
import time
from pathlib import Path

from claims_gate.kaia import KAIA_SOURCE, KAIA_TOOL_SCOPES, KAIA_WALLET_TOOLS


def _cmd_tools(_: argparse.Namespace) -> int:
    print(json.dumps({"source": KAIA_SOURCE, "toolScopes": KAIA_TOOL_SCOPES, "walletTools": sorted(KAIA_WALLET_TOOLS)}, indent=2))
    return 0


def _cmd_demo(args: argparse.Namespace) -> int:
    from claims_gate.demo import run_demo

    report = run_demo(wallet_default=args.wallet_default)
    print(json.dumps(report, indent=2))
    return 0 if report["summary"]["passed"] == report["summary"]["total"] else 1


def _cmd_testkit(args: argparse.Namespace) -> int:
    from claims_gate import testkit

    directory = Path(args.dir)
    if args.action == "init":
        signer = testkit.init_dir(directory)
        print(json.dumps({"dir": str(directory), "kid": signer.kid, "jwks": str(directory / "jwks.json"), "privateKey": str(directory / testkit.PRIVATE_KEY_FILENAME), "testOnly": True}))
        return 0
    signer = testkit.TestSigner.generate() if args.untrusted else testkit.load_dir(directory)
    now = time.time()
    claims = testkit.build_claims(
        now=now,
        sub=args.sub or None,
        iss=args.iss,
        aud=args.aud,
        exp_in=args.exp_in,
        scope=args.scope,
    )
    if args.sub == "":
        claims.pop("sub", None)
    print(signer.mint(claims))
    return 0


def _cmd_decide(args: argparse.Namespace) -> int:
    from claims_gate.gate import ClaimsGate
    from claims_gate.kaia import kaia_policy
    from claims_gate.verify import VerifierConfig

    if args.authorization_file:
        authorization = Path(args.authorization_file).read_text().strip() or None
    else:
        authorization = os.environ.get("S1_AUTHORIZATION") or None
    try:
        jwks = json.loads(Path(args.jwks).read_text())
        config = VerifierConfig(jwks=jwks, issuer=args.issuer, audience=args.audience)
    except (OSError, ValueError) as err:
        print(f"claims_gate decide: bad config: {err}", file=sys.stderr)
        return 2
    result = ClaimsGate(config, kaia_policy(args.wallet_default)).evaluate(authorization, args.tool)
    print(json.dumps(result.to_dict()))
    return 0


def _cmd_escalations(args: argparse.Namespace) -> int:
    from claims_gate.escalations import EscalationError, EscalationStore

    directory = args.dir or os.environ.get("S1_ESCALATION_DIR")
    if not directory:
        print("claims_gate escalations: pass --dir or set S1_ESCALATION_DIR", file=sys.stderr)
        return 2
    store = EscalationStore(directory)
    if args.action == "list":
        if args.id:
            print("claims_gate escalations list takes no id", file=sys.stderr)
            return 2
        print(json.dumps([e.to_dict() for e in store.list(args.status)], indent=2))
        return 0
    if not args.id:
        print(f"claims_gate escalations {args.action}: missing escalation id", file=sys.stderr)
        return 2
    try:
        rec = store.approve(args.id) if args.action == "approve" else store.deny(args.id)
    except EscalationError as err:
        print(f"claims_gate escalations {args.action}: {err}", file=sys.stderr)
        return 1
    print(json.dumps(rec.to_dict(), indent=2))
    return 0


def _cmd_proxy(args: argparse.Namespace) -> int:
    import logging
    import threading

    from claims_gate.kaia import kaia_policy
    from claims_gate.proxy import build_config, make_server

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    audit = None
    if args.audit_log:
        lock = threading.Lock()
        audit_path = Path(args.audit_log)

        def audit(record: dict[str, object]) -> None:
            with lock, audit_path.open("a") as fh:
                fh.write(json.dumps(record, sort_keys=True) + "\n")

    escalations = None
    if args.escalation_dir:
        from claims_gate.escalations import EscalationStore

        try:
            escalations = EscalationStore(args.escalation_dir, pending_ttl=args.escalation_pending_ttl, approval_ttl=args.escalation_approval_ttl)
        except (OSError, ValueError, sqlite3.Error) as err:
            print(f"claims_gate proxy: refusing to start (fail closed): escalation queue: {err}", file=sys.stderr, flush=True)
            return 3

    config, report = build_config(
        upstream=args.upstream,
        issuer=args.issuer,
        audience=args.audience,
        policy=kaia_policy(args.wallet_default),
        jwks_uri=args.jwks_uri,
        introspection=args.introspection,
        introspection_client_id=os.environ.get("S1_INTROSPECTION_CLIENT_ID") or None,
        introspection_client_secret=os.environ.get("S1_INTROSPECTION_CLIENT_SECRET") or None,
        tool_scopes_url=args.tool_scopes_url,
        drift_check=not args.no_drift_check,
        jwks_ttl_seconds=args.jwks_ttl,
        mcp_path=args.mcp_path,
        audit=audit,
        escalations=escalations,
    )
    print(json.dumps({"startup": report.to_dict()}), flush=True)
    if config is None:
        print("claims_gate proxy: refusing to start (fail closed): " + "; ".join(report.errors), file=sys.stderr, flush=True)
        return 3
    server = make_server(config, args.host, args.port)
    host, port = server.server_address[:2]
    print(f"ready: s1-tool-gate proxy on http://{host}:{port}{args.mcp_path} -> {args.upstream}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m claims_gate")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("tools", help="print the kaia-mcp tool -> scope fixture").set_defaults(func=_cmd_tools)

    p_demo = sub.add_parser("demo", help="run the golden kaia-mcp cases through gate + enforcement seam")
    p_demo.add_argument("--wallet-default", choices=["escalate", "deny"], default="escalate")
    p_demo.set_defaults(func=_cmd_demo)

    p_kit = sub.add_parser("testkit", help="TEST-ONLY keys and tokens")
    p_kit.add_argument("action", choices=["init", "mint"])
    p_kit.add_argument("--dir", required=True)
    p_kit.add_argument("--scope", default="kaia:read")
    p_kit.add_argument("--sub", default="partner-agent-1", help="empty string omits the claim")
    p_kit.add_argument("--aud", default="kaia-mcp")
    p_kit.add_argument("--iss", default="https://idp.test.invalid")
    p_kit.add_argument("--exp-in", type=float, default=600)
    p_kit.add_argument("--untrusted", action="store_true", help="sign with a fresh key not in the JWKS")
    p_kit.set_defaults(func=_cmd_testkit)

    p_dec = sub.add_parser("decide", help="decide one tool call from an Authorization header")
    p_dec.add_argument("--jwks", required=True)
    p_dec.add_argument("--issuer", required=True)
    p_dec.add_argument("--audience", required=True)
    p_dec.add_argument("--tool", required=True)
    p_dec.add_argument("--authorization-file")
    p_dec.add_argument("--wallet-default", choices=["escalate", "deny"], default="escalate")
    p_dec.set_defaults(func=_cmd_decide)

    p_proxy = sub.add_parser("proxy", help="live reverse proxy that gates an MCP Streamable HTTP server")
    p_proxy.add_argument("--upstream", required=True, help="MCP server origin, e.g. http://127.0.0.1:3100")
    p_proxy.add_argument("--issuer", required=True, help="pinned token issuer (exact match)")
    p_proxy.add_argument("--audience", required=True, help="pinned token audience")
    p_proxy.add_argument("--jwks-uri", help="override discovery's jwks_uri (also allows a different origin)")
    p_proxy.add_argument("--jwks-ttl", type=float, default=300.0)
    p_proxy.add_argument("--introspection", help="'auto' (discovery) or an RFC 7662 URL; credentials from S1_INTROSPECTION_CLIENT_ID/SECRET")
    p_proxy.add_argument("--tool-scopes-url", help="default: <upstream>/.well-known/kaia-mcp/tool-scopes")
    p_proxy.add_argument("--no-drift-check", action="store_true", help="skip the startup tool-scope drift check (not recommended)")
    p_proxy.add_argument("--host", default="127.0.0.1")
    p_proxy.add_argument("--port", type=int, default=0)
    p_proxy.add_argument("--mcp-path", default="/")
    p_proxy.add_argument("--audit-log", help="append one JSON line per decision (no tokens)")
    p_proxy.add_argument("--wallet-default", choices=["escalate", "deny"], default="escalate")
    p_proxy.add_argument("--escalation-dir", default=os.environ.get("S1_ESCALATION_DIR") or None, help="durable escalation queue (sqlite) so humans can approve one retry; default $S1_ESCALATION_DIR; unset = escalations are terminal")
    p_proxy.add_argument("--escalation-pending-ttl", type=float, default=3600.0, help="seconds a pending escalation waits for a human (also how long a deny sticks)")
    p_proxy.add_argument("--escalation-approval-ttl", type=float, default=300.0, help="seconds an approval stays usable for its one retry")
    p_proxy.set_defaults(func=_cmd_proxy)

    p_esc = sub.add_parser("escalations", help="list, approve, or deny queued escalations")
    p_esc.add_argument("action", choices=["list", "approve", "deny"])
    p_esc.add_argument("id", nargs="?")
    p_esc.add_argument("--dir", help="queue directory (default $S1_ESCALATION_DIR)")
    p_esc.add_argument("--status", choices=["pending", "approved", "denied", "expired", "consumed"])
    p_esc.set_defaults(func=_cmd_escalations)

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
