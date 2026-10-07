from __future__ import annotations

import json
from pathlib import Path

import pytest

from claims_gate.__main__ import main
from claims_gate.demo import run_demo
from claims_gate.testkit import PRIVATE_KEY_FILENAME

PACKAGE_ROOT = Path(__file__).resolve().parents[1]


def test_demo_runs_through_enforcement_seam() -> None:
    report = run_demo()
    s = report["summary"]
    assert s["passed"] == s["total"] == 22
    assert (s["allow"], s["deny"], s["escalate"]) == (3, 18, 1)
    assert s["walletStubCalls"] == 0
    assert sorted(s["stubCalls"]) == ["encode_function_data", "get_chain_info", "get_kaia_balance"]
    for row in report["cases"]:
        assert row["sideEffect"] is (row["decision"]["choice"] == "allow")
        assert row["escalated"] is (row["decision"]["choice"] == "escalate")


def test_demo_wallet_default_deny() -> None:
    report = run_demo(wallet_default="deny")
    assert report["summary"]["passed"] == report["summary"]["total"]
    row = next(r for r in report["cases"] if r["id"] == "wallet-escalate")
    assert row["decision"]["reasonCode"] == "claims_wallet_denied"
    assert row["escalated"] is False


def _decide(capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, d: Path, token: str | None, tool: str) -> dict[str, object]:
    if token is None:
        monkeypatch.delenv("S1_AUTHORIZATION", raising=False)
    else:
        monkeypatch.setenv("S1_AUTHORIZATION", f"Bearer {token}")
    rc = main(["decide", "--jwks", str(d / "jwks.json"), "--issuer", "https://idp.test.invalid", "--audience", "kaia-mcp", "--tool", tool])
    assert rc == 0
    return json.loads(capsys.readouterr().out)


def _mint(capsys: pytest.CaptureFixture[str], d: Path, *extra: str) -> str:
    assert main(["testkit", "mint", "--dir", str(d), *extra]) == 0
    return capsys.readouterr().out.strip()


def test_cli_testkit_and_decide(tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> None:
    assert main(["testkit", "init", "--dir", str(tmp_path)]) == 0
    init = json.loads(capsys.readouterr().out)
    assert init["testOnly"] is True
    assert (tmp_path / PRIVATE_KEY_FILENAME).stat().st_mode & 0o077 == 0

    read = _mint(capsys, tmp_path, "--scope", "kaia:read")
    assert _decide(capsys, monkeypatch, tmp_path, read, "get_kaia_balance")["choice"] == "allow"
    assert _decide(capsys, monkeypatch, tmp_path, read, "encode_function_data")["reasonCode"] == "claims_insufficient_scope"
    expired = _mint(capsys, tmp_path, "--exp-in", "-5")
    assert _decide(capsys, monkeypatch, tmp_path, expired, "get_kaia_balance")["reasonCode"] == "claims_expired"
    wrong_aud = _mint(capsys, tmp_path, "--aud", "other-api")
    assert _decide(capsys, monkeypatch, tmp_path, wrong_aud, "get_kaia_balance")["reasonCode"] == "claims_audience_mismatch"
    forged = _mint(capsys, tmp_path, "--untrusted")
    assert _decide(capsys, monkeypatch, tmp_path, forged, "get_kaia_balance")["reasonCode"] == "claims_invalid_token"
    assert _decide(capsys, monkeypatch, tmp_path, None, "get_kaia_balance")["reasonCode"] == "claims_unauthenticated"
    wallet = _mint(capsys, tmp_path, "--scope", "kaia:read kaia:wallet")
    out = _decide(capsys, monkeypatch, tmp_path, wallet, "generate_wallet")
    assert (out["choice"], out["reasonCode"]) == ("escalate", "claims_wallet_escalate")
    assert wallet not in json.dumps(out)


def test_cli_decide_bad_config_exits_2(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["decide", "--jwks", str(tmp_path / "missing.json"), "--issuer", "i", "--audience", "a", "--tool", "get_kaia_balance"])
    assert rc == 2


def test_no_private_keys_committed_in_package() -> None:
    assert not list(PACKAGE_ROOT.rglob("*.pem"))
    marker = "BEGIN " + "PRIVATE KEY"  # split so this file does not match itself
    for path in PACKAGE_ROOT.rglob("*"):
        if path.is_file() and path.suffix in {".py", ".json", ".md", ".toml"}:
            assert marker not in path.read_text(), path
