"""Gate and observation half of the end-to-end demo.

This module calls ``gate_client`` and ``gate_enforcement``. It does not score
flip rate or ECE. Those metrics come from the authority-flip harness.
"""

from e2e_demo.path import GateCase, parse_cases, run_gate_path

__all__ = ["GateCase", "parse_cases", "run_gate_path"]
