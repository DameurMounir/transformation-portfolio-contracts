from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import cast

import pytest

from transformation_portfolio_contracts import validation as validation_module
from transformation_portfolio_contracts.canonical import (
    JSONValue,
    artifact_digest,
    load_json,
    payload_digest,
)
from transformation_portfolio_contracts.errors import (
    ArtifactValidationError,
    ContractError,
    ResourceError,
    SchemaResolutionError,
)
from transformation_portfolio_contracts.validation import (
    ContractCatalog,
    discover_contract_root,
    validate_document,
    verify_artifact_integrity,
)

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples" / "atlasbridge-end-to-end"


def _stage_artifact(artifact_type: str) -> dict[str, JSONValue]:
    """Find an example by its stable contract identity, not its display filename."""

    for path in sorted(EXAMPLES.glob("*.json")):
        value = load_json(path)
        if isinstance(value, dict) and value.get("artifact_type") == artifact_type:
            return value
    raise AssertionError(f"missing AtlasBridge example for {artifact_type}")


def _redigest(artifact: dict[str, JSONValue]) -> None:
    artifact["payload_sha256"] = payload_digest(artifact)
    artifact["artifact_sha256"] = artifact_digest(artifact)


def _diagnostic_codes(error: ContractError) -> set[str]:
    return {diagnostic.code for diagnostic in error.diagnostics}


def _decision_pair(
    artifact: dict[str, JSONValue], decision_field: str
) -> tuple[dict[str, JSONValue], dict[str, JSONValue]]:
    authority = artifact.get("authority")
    payload = artifact.get("payload")
    assert isinstance(authority, dict)
    assert isinstance(payload, dict)
    embedded = payload.get(decision_field)
    assert isinstance(embedded, dict)
    return authority, embedded


def _copy_contract_resources(destination: Path) -> Path:
    destination.mkdir(parents=True)
    shutil.copytree(ROOT / "schemas", destination / "schemas")
    shutil.copytree(ROOT / "registry", destination / "registry")
    return destination


def test_installed_share_root_precedes_cwd_and_source_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prefix = tmp_path / "isolated-prefix"
    installed_root = _copy_contract_resources(
        prefix / "share" / "transformation-portfolio-contracts"
    )
    cwd_root = tmp_path / "cwd-shadow"
    (cwd_root / "schemas").mkdir(parents=True)
    (cwd_root / "registry").mkdir()

    monkeypatch.delenv("TPC_CONTRACT_ROOT", raising=False)
    monkeypatch.setattr(validation_module.sys, "prefix", str(prefix))
    monkeypatch.chdir(cwd_root)

    assert discover_contract_root() == installed_root


def test_stage_artifact_cannot_select_common_envelope_schema() -> None:
    artifact = _stage_artifact("RequirementsAssessment")
    artifact["$schema"] = "schemas/common/artifact-envelope.v1.schema.json"

    with pytest.raises(SchemaResolutionError) as raised:
        validate_document(artifact, root=ROOT)

    assert _diagnostic_codes(raised.value) == {"ARTIFACT_SCHEMA_MISMATCH"}


@pytest.mark.parametrize(
    ("producer_field", "mutated_value", "expected_code"),
    [
        ("repository", "ExampleOrg/requirements-quality-agent", "UNREGISTERED_PRODUCER"),
        ("release", "v9.9.9", "UNREGISTERED_PRODUCER_RELEASE"),
        ("tool_version", "9.9.9", "PRODUCER_TOOL_VERSION_MISMATCH"),
        (
            "source_uri",
            "https://github.com/ExampleOrg/requirements-quality-agent",
            "PRODUCER_SOURCE_URI_MISMATCH",
        ),
    ],
)
def test_producer_registration_mutations_have_stable_diagnostics(
    producer_field: str, mutated_value: str, expected_code: str
) -> None:
    artifact = _stage_artifact("RequirementsAssessment")
    producer = artifact.get("producer")
    assert isinstance(producer, dict)
    producer[producer_field] = mutated_value
    _redigest(artifact)

    with pytest.raises(ArtifactValidationError) as raised:
        verify_artifact_integrity(artifact, root=ROOT)

    assert expected_code in _diagnostic_codes(raised.value)


def test_consistent_but_unregistered_authority_scope_is_rejected() -> None:
    artifact = _stage_artifact("RequirementsAssessment")
    authority, embedded = _decision_pair(artifact, "human_review")
    authority["authority_scope"] = "ARBITRARY_REVIEW_SCOPE"
    embedded["authority_scope"] = "ARBITRARY_REVIEW_SCOPE"
    _redigest(artifact)

    with pytest.raises(ArtifactValidationError) as raised:
        verify_artifact_integrity(artifact, root=ROOT)

    assert "UNREGISTERED_AUTHORITY_SCOPE" in _diagnostic_codes(raised.value)


def test_envelope_authority_cannot_contradict_embedded_decision() -> None:
    artifact = _stage_artifact("RequirementsAssessment")
    authority, _ = _decision_pair(artifact, "human_review")
    authority["rationale"] = "Contradictory envelope-only rationale."
    _redigest(artifact)

    with pytest.raises(ArtifactValidationError) as raised:
        verify_artifact_integrity(artifact, root=ROOT)

    assert "AUTHORITY_DECISION_MISMATCH" in _diagnostic_codes(raised.value)


def test_zero_decision_subject_digest_is_rejected() -> None:
    artifact = _stage_artifact("RequirementsAssessment")
    authority, embedded = _decision_pair(artifact, "human_review")
    authority["artifact_digest"] = "0" * 64
    embedded["artifact_digest"] = "0" * 64
    _redigest(artifact)

    with pytest.raises(ArtifactValidationError) as raised:
        verify_artifact_integrity(artifact, root=ROOT)

    assert "DECISION_SUBJECT_DIGEST_MISMATCH" in _diagnostic_codes(raised.value)


def test_registry_reconciliation_rejects_unregistered_schema(tmp_path: Path) -> None:
    copied_root = _copy_contract_resources(tmp_path / "extra-schema")
    shutil.copy2(
        copied_root / "schemas" / "common" / "finding.v1.schema.json",
        copied_root / "schemas" / "common" / "unregistered-copy.v1.schema.json",
    )

    with pytest.raises(ResourceError, match="exactly one entry for every JSON schema"):
        ContractCatalog(copied_root).verify_registry_reconciliation()


def test_registry_reconciliation_rejects_map_matrix_edge_mismatch(tmp_path: Path) -> None:
    copied_root = _copy_contract_resources(tmp_path / "edge-mismatch")
    map_path = copied_root / "registry" / "producer-consumer-map.json"
    producer_map = json.loads(map_path.read_text(encoding="utf-8"))
    edges = cast(list[dict[str, object]], producer_map["edges"])
    edges[0]["relationship"] = "TEST_ONLY_RELATIONSHIP"
    map_path.write_text(json.dumps(producer_map, indent=2) + "\n", encoding="utf-8")

    with pytest.raises(ResourceError, match="compatibility rules must exactly equal"):
        ContractCatalog(copied_root).verify_registry_reconciliation()
