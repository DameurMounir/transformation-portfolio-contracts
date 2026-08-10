from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from transformation_portfolio_contracts import cli

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "atlasbridge-end-to-end"
REQUIREMENTS = EXAMPLE / "01-requirements-assessment.v1.json"


def _json_output(capsys: pytest.CaptureFixture[str]) -> dict[str, Any]:
    captured = capsys.readouterr()
    assert captured.err == ""
    return json.loads(captured.out)


def test_validate_digest_catalog_and_lineage_commands(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert (
        cli.main(
            [
                "validate",
                "--artifact",
                str(REQUIREMENTS),
                "--root",
                str(ROOT),
                "--json",
            ]
        )
        == 0
    )
    assert _json_output(capsys)["documents"][0]["artifact_id"] == "RQA-ATLASBRIDGE-001"

    assert cli.main(["digest", str(REQUIREMENTS), "--verify", "--root", str(ROOT), "--json"]) == 0
    assert _json_output(capsys)["projection"] == "artifact"

    assert cli.main(["digest", str(REQUIREMENTS), "--payload", "--root", str(ROOT)]) == 0
    assert len(capsys.readouterr().out.strip()) == 64

    assert (
        cli.main(
            ["catalog", "--contract", "RequirementsAssessment.v1", "--root", str(ROOT), "--json"]
        )
        == 0
    )
    assert _json_output(capsys)["contract_count"] == 1

    assert cli.main(["verify-lineage", str(EXAMPLE), "--root", str(ROOT), "--json"]) == 0
    lineage = _json_output(capsys)
    assert lineage["artifact_count"] == 6
    assert lineage["valid"] is True


def test_conformance_and_example_commands(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["verify-conformance", "--root", str(ROOT), "--json"]) == 0
    conformance = _json_output(capsys)
    assert conformance["valid"] is True
    assert conformance["valid_fixture_count"] > 0
    assert conformance["invalid_fixture_count"] > 0

    assert cli.main(["verify-example", "--root", str(ROOT)]) == 0
    output = capsys.readouterr().out
    assert "VALID" in output
    assert "portfolio_chain_sha256=" in output


def test_document_digest_and_schema_only_authoring_path(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    document = tmp_path / "document.json"
    document.write_text('{"b":2,"a":1}', encoding="utf-8")
    assert cli.main(["digest", str(document), "--json"]) == 0
    assert _json_output(capsys)["projection"] == "document"

    artifact = json.loads(REQUIREMENTS.read_text(encoding="utf-8"))
    artifact["payload_sha256"] = "0" * 64
    artifact["artifact_sha256"] = "0" * 64
    authoring = tmp_path / "authoring.json"
    authoring.write_text(json.dumps(artifact), encoding="utf-8")
    assert (
        cli.main(
            [
                "validate",
                str(authoring),
                "--schema-only",
                "--root",
                str(ROOT),
            ]
        )
        == 0
    )
    assert "VALID" in capsys.readouterr().out


def test_expected_failures_return_stable_codes_and_machine_errors(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["validate", "--root", str(ROOT), "--json"]) == 3
    error = json.loads(capsys.readouterr().err)
    assert error["error"] == "RESOURCE_ERROR"

    assert cli.main(["catalog", "--contract", "Missing.v1", "--root", str(ROOT)]) == 3
    assert "ERROR [RESOURCE_ERROR]" in capsys.readouterr().err

    payloadless = tmp_path / "payloadless.json"
    payloadless.write_text("{}", encoding="utf-8")
    assert cli.main(["digest", str(payloadless), "--payload", "--json"]) == 3
    assert json.loads(capsys.readouterr().err)["error"] == "RESOURCE_ERROR"

    assert cli.main(["digest", str(payloadless), "--verify", "--json"]) == 3
    assert json.loads(capsys.readouterr().err)["error"] == "RESOURCE_ERROR"


def test_internal_boundary_is_fail_closed(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def explode(arguments: object) -> tuple[dict[str, Any], str | None]:
        raise RuntimeError("unexpected")

    monkeypatch.setattr(cli, "_dispatch", explode)
    assert cli.main(["catalog", "--root", str(ROOT), "--json"]) == 70
    assert json.loads(capsys.readouterr().err) == {
        "error": "INTERNAL_ERROR",
        "message": "unexpected",
    }


def test_version_and_usage_are_argparse_exit_two_or_zero(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as version:
        cli.main(["--version"])
    assert version.value.code == 0
    assert "portfolio-contracts 1.0.0" in capsys.readouterr().out

    with pytest.raises(SystemExit) as usage:
        cli.main([])
    assert usage.value.code == 2
