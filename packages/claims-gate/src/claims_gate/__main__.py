"""CLI for the claims gate.

  python -m claims_gate tools
  python -m claims_gate demo [--wallet-default escalate|deny]
  python -m claims_gate testkit init --dir DIR
  python -m claims_gate testkit mint --dir DIR [--scope S] [--sub S] [--aud A] [--iss I]
                                     [--exp-in SECONDS] [--untrusted]
  S1_AUTHORIZATION="Bearer <jwt>" python -m claims_gate decide --jwks FILE --issuer ISS \
      --audience AUD --tool TOOL [--wallet-default escalate|deny]

``decide`` reads the Authorization value from the ``S1_AUTHORIZATION`` env var
(or ``--authorization-file``) so tokens stay out of argv. It prints the
decision JSON and exits 0 for any decision; exit 2 is a usage/config error.
``demo`` exits 0 only when every golden case matched.
"""

from __future__ import annotations

import argparse
import json
import os
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

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
