"""Read cases from stdin and write the gate-path JSON to stdout.

Exit 0 means a JSON document was written, including ``status: unavailable``.
It does not mean Nimble scored the cases. Exit 1 means the input could not
be run and nothing was written to stdout.
"""

from __future__ import annotations

import json
import sys

from e2e_demo.path import parse_cases, run_gate_path


def main(stdin: str | None = None) -> int:
    raw = sys.stdin.read() if stdin is None else stdin
    try:
        cases = parse_cases(json.loads(raw))
        report = run_gate_path(cases)
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        message = exc.msg if isinstance(exc, json.JSONDecodeError) else str(exc)
        sys.stderr.write(f"{message}\n")
        return 1
    json.dump(report, sys.stdout)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
