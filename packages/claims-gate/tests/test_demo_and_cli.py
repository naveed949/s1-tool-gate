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


def test_proxy_cli_introspection_cache_defaults_off_and_is_opt_in() -> None:
    from claims_gate.__main__ import build_parser
    from claims_gate.proxy import DEFAULT_INTROSPECTION_CACHE_TTL

    base = ["proxy", "--upstream", "http://127.0.0.1:1", "--issuer", "http://127.0.0.1:1", "--audience", "kaia-mcp"]
    assert build_parser().parse_args(base).introspection_cache_ttl == 0 == DEFAULT_INTROSPECTION_CACHE_TTL
    assert build_parser().parse_args([*base, "--introspection-cache-ttl", "5"]).introspection_cache_ttl == 5.0


def test_proxy_cli_negative_drift_interval_refuses_to_start(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["proxy", "--upstream", "http://127.0.0.1:9", "--issuer", "http://127.0.0.1:9", "--audience", "kaia-mcp", "--drift-interval", "-1"])
    assert rc == 3
    assert "drift interval must be a finite number in [0, " in capsys.readouterr().err


@pytest.mark.parametrize("value", ["nan", "inf", "-inf", "1e300"])
def test_proxy_cli_non_finite_drift_interval_refuses_to_start(capsys: pytest.CaptureFixture[str], value: str) -> None:
    rc = main(["proxy", "--upstream", "http://127.0.0.1:9", "--issuer", "http://127.0.0.1:9", "--audience", "kaia-mcp", f"--drift-interval={value}"])
    assert rc == 3
    assert "drift interval must be a finite number in [0, " in capsys.readouterr().err


@pytest.mark.parametrize("flag", ["--introspection-cache-ttl", "--escalation-pending-ttl", "--escalation-approval-ttl", "--jwks-ttl"])
@pytest.mark.parametrize("value", ["nan", "inf"])
def test_proxy_cli_non_finite_durations_refuse_to_start(capsys: pytest.CaptureFixture[str], tmp_path: Any, flag: str, value: str) -> None:
    rc = main(["proxy", "--upstream", "http://127.0.0.1:9", "--issuer", "http://127.0.0.1:9", "--audience", "kaia-mcp", "--escalation-dir", str(tmp_path / "q"), f"{flag}={value}"])
    assert rc == 3
    assert "finite" in capsys.readouterr().err


# Upper bounds: a huge finite value (1e300, 9e18) behaves like inf (cache until token
# exp, keys never refreshed, approvals/denies that never expire), so each flag has a cap.
_CAPPED_FLAGS = {
    "--introspection-cache-ttl": "introspection cache TTL must be a finite number in [0, 300",
    "--jwks-ttl": "jwks TTL must be a finite number in (0, 3600",
    "--escalation-pending-ttl": "escalation pending TTL must be a finite number in (0, 86400",
    "--escalation-approval-ttl": "escalation approval TTL must be a finite number in (0, 3600",
}


@pytest.mark.parametrize("flag", sorted(_CAPPED_FLAGS))
@pytest.mark.parametrize("value", ["1e300", "9e18", "1.8e10", "1e309", "nan", "inf", "-1"])
def test_proxy_cli_out_of_range_durations_refuse_to_start(capsys: pytest.CaptureFixture[str], tmp_path: Any, flag: str, value: str) -> None:
    rc = main(["proxy", "--upstream", "http://127.0.0.1:9", "--issuer", "http://127.0.0.1:9", "--audience", "kaia-mcp", "--escalation-dir", str(tmp_path / "q"), f"{flag}={value}"])
    assert rc == 3
    err = capsys.readouterr().err
    assert _CAPPED_FLAGS[flag] in err, err
    assert err.count(_CAPPED_FLAGS[flag]) == 1, err  # reported once, not by every layer


@pytest.mark.parametrize("flag", ["--escalation-pending-ttl", "--escalation-approval-ttl"])
def test_proxy_cli_escalation_ttls_are_checked_even_without_a_queue(capsys: pytest.CaptureFixture[str], flag: str) -> None:
    rc = main(["proxy", "--upstream", "http://127.0.0.1:9", "--issuer", "http://127.0.0.1:9", "--audience", "kaia-mcp", f"{flag}=1e300"])
    assert rc == 3
    assert _CAPPED_FLAGS[flag] in capsys.readouterr().err


def test_duration_caps_are_inclusive_and_defaults_are_inside() -> None:
    from claims_gate.escalations import DEFAULT_APPROVAL_TTL, DEFAULT_PENDING_TTL, MAX_APPROVAL_TTL, MAX_PENDING_TTL
    from claims_gate.proxy import DEFAULT_INTROSPECTION_CACHE_TTL, DEFAULT_JWKS_TTL, MAX_INTROSPECTION_CACHE_TTL, MAX_JWKS_TTL

    assert (MAX_INTROSPECTION_CACHE_TTL, MAX_JWKS_TTL, MAX_PENDING_TTL, MAX_APPROVAL_TTL) == (300.0, 3600.0, 86400.0, 3600.0)
    assert 0 <= DEFAULT_INTROSPECTION_CACHE_TTL <= MAX_INTROSPECTION_CACHE_TTL
    assert 0 < DEFAULT_JWKS_TTL <= MAX_JWKS_TTL
    assert 0 < DEFAULT_PENDING_TTL <= MAX_PENDING_TTL and 0 < DEFAULT_APPROVAL_TTL <= MAX_APPROVAL_TTL
