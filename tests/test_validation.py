from __future__ import annotations

import copy
import json
import shutil
import sys
from pathlib import Path
from typing import cast

import pytest

from transformation_portfolio_contracts.canonical import (
    JSONValue,
    artifact_digest,
    digest_json,
    load_json,
    payload_digest,
)
from transformation_portfolio_contracts.errors import (
    ArtifactValidationError,
    ResourceError,
    SchemaResolutionError,
    SchemaValidationError,
)
from transformation_portfolio_contracts.validation import (
    ContractCatalog,
    SchemaRecord,
    _gate_set_diagnostics,
    contract_major,
    decision_subject_projection,
    discover_contract_root,
    raw_file_sha256,
    validate_document,
    validate_file,
    verify_artifact_integrity,
)

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "atlasbridge-end-to-end"


def _artifact(name: str) -> dict[str, JSONValue]:
    value = load_json(EXAMPLE / name)
    assert isinstance(value, dict)
    return value


def _redigest(value: dict[str, JSONValue]) -> None:
    projection = decision_subject_projection(value)
    if projection is not None:
        subject_digest = digest_json(dict(projection))

        def bind(item: JSONValue) -> None:
            if isinstance(item, list):
                for nested in item:
                    bind(nested)
            elif isinstance(item, dict):
                if isinstance(item.get("authority_scope"), str):
                    item["artifact_digest"] = subject_digest
                for nested in item.values():
                    bind(nested)

        bind(value)
        payload = value.get("payload")
        if value.get("artifact_type") == "StakeholderAlignmentPacket" and isinstance(payload, dict):
            payload["decision_digest"] = digest_json(payload.get("decision"))
    value["payload_sha256"] = payload_digest(value)
    value["artifact_sha256"] = artifact_digest(value)


def _codes(error: ArtifactValidationError) -> set[str]:
    return {item.code for item in error.diagnostics}


def test_contract_root_and_catalog_are_complete(monkeypatch: pytest.MonkeyPatch) -> None:
    assert discover_contract_root(ROOT) == ROOT
    monkeypatch.setenv("TPC_CONTRACT_ROOT", str(ROOT))
    assert discover_contract_root() == ROOT

    catalog = ContractCatalog(ROOT)
    assert len(catalog.schemas) == 12
    assert len(catalog.catalog_entries()) == 12
    assert catalog.resolve_schema("RequirementsAssessment").relative_path.endswith(
        "requirements-assessment.v1.schema.json"
    )
    assert catalog.resolve_schema("HumanDecision.v1").relative_path.endswith(
        "human-decision.v1.schema.json"
    )

    monkeypatch.delenv("TPC_CONTRACT_ROOT", raising=False)
    monkeypatch.chdir(ROOT)
    installed_root = Path(sys.prefix) / "share" / "transformation-portfolio-contracts"
    expected_root = (
        installed_root.resolve()
        if (installed_root / "schemas").is_dir() and (installed_root / "registry").is_dir()
        else ROOT
    )
    assert discover_contract_root() == expected_root


def test_contract_root_and_schema_resolution_fail_closed(tmp_path: Path) -> None:
    with pytest.raises(ResourceError, match="schemas/ and registry"):
        discover_contract_root(tmp_path)
    with pytest.raises(SchemaResolutionError, match="no registered schema"):
        ContractCatalog(ROOT).resolve_schema("DoesNotExist.v1")

    catalog = ContractCatalog(ROOT)
    outside = tmp_path / "outside.schema.json"
    outside.write_text("{}", encoding="utf-8")
    with pytest.raises(SchemaResolutionError, match="within the immutable"):
        catalog.resolve_schema(outside.resolve())
    catalog._aliases["ambiguous"] = catalog.schemas[:2]
    with pytest.raises(SchemaResolutionError, match="ambiguous"):
        catalog.resolve_schema("ambiguous")


def test_valid_example_artifact_passes_schema_semantics_and_digests() -> None:
    path = EXAMPLE / "01-requirements-assessment.v1.json"
    result = validate_file(path, root=ROOT)
    document = _artifact(path.name)
    assert result.as_dict()["valid"] is True
    assert result.artifact_id == "RQA-ATLASBRIDGE-001"
    assert result.artifact_sha256 == document["artifact_sha256"]
    assert result.payload_sha256 == document["payload_sha256"]
    assert validate_document(document, root=ROOT).as_dict()["valid"] is True


def test_tampered_payload_reports_both_integrity_boundaries() -> None:
    document = _artifact("01-requirements-assessment.v1.json")
    payload = cast(dict[str, JSONValue], document["payload"])
    requirements = cast(list[JSONValue], payload["requirements"])
    first = cast(dict[str, JSONValue], requirements[0])
    first["statement"] = "tampered"

    with pytest.raises(ArtifactValidationError) as raised:
        verify_artifact_integrity(document)
    assert {"PAYLOAD_DIGEST_MISMATCH", "ARTIFACT_DIGEST_MISMATCH"} <= _codes(raised.value)


def test_evidence_quote_digest_and_location_order_are_computed_invariants() -> None:
    document = _artifact("01-requirements-assessment.v1.json")
    payload = cast(dict[str, JSONValue], document["payload"])
    requirements = cast(list[dict[str, JSONValue]], payload["requirements"])
    evidence = cast(list[dict[str, JSONValue]], requirements[0]["evidence_refs"])[0]
    evidence["exact_quote"] = "changed quote with a retained digest"
    evidence["location"] = {"start_line": 3, "end_line": 1}
    _redigest(document)

    with pytest.raises(ArtifactValidationError) as raised:
        verify_artifact_integrity(document)
    assert {"EVIDENCE_QUOTE_DIGEST_MISMATCH", "EVIDENCE_RANGE_INVERTED"} <= _codes(raised.value)

    with pytest.raises(ArtifactValidationError):
        validate_document(
            evidence,
            contract="EvidenceReference.v1",
            root=ROOT,
            verify_integrity=True,
        )


def test_unsupported_contract_major_is_rejected_even_with_fresh_digests() -> None:
    document = _artifact("01-requirements-assessment.v1.json")
    document["spec_version"] = "2.0.0"
    _redigest(document)
    with pytest.raises(ArtifactValidationError) as raised:
        verify_artifact_integrity(document)
    assert "UNSUPPORTED_CONTRACT_MAJOR" in _codes(raised.value)
    with pytest.raises(ArtifactValidationError):
        contract_major("garbage")


@pytest.mark.parametrize(
    ("produced_at", "code"),
    [
        (123, "INVALID_TIMESTAMP"),
        ("not-a-time", "INVALID_TIMESTAMP"),
        ("2026-08-08T12:00:00", "TIMEZONE_REQUIRED"),
    ],
)
def test_timestamp_and_digest_profile_failures_are_explicit(
    produced_at: JSONValue, code: str
) -> None:
    document = _artifact("01-requirements-assessment.v1.json")
    document["produced_at"] = produced_at
    document["digest_profile"] = "UNKNOWN-PROFILE"
    _redigest(document)
    with pytest.raises(ArtifactValidationError) as raised:
        verify_artifact_integrity(document)
    assert {code, "UNSUPPORTED_DIGEST_PROFILE"} <= _codes(raised.value)


def test_requirements_scorecard_and_critical_count_are_computed_invariants() -> None:
    document = _artifact("01-requirements-assessment.v1.json")
    payload = cast(dict[str, JSONValue], document["payload"])
    scorecard = cast(dict[str, JSONValue], payload["scorecard"])
    scorecard["confirmed"] = 1
    payload["critical_unresolved_count"] = 2
    _redigest(document)

    with pytest.raises(ArtifactValidationError) as raised:
        verify_artifact_integrity(document)
    assert {"SCORECARD_COUNT_MISMATCH", "CRITICAL_UNRESOLVED_COUNT_MISMATCH"} <= _codes(
        raised.value
    )


def test_go_live_gate_ids_names_partition_and_precedence_are_not_advisory() -> None:
    document = _artifact("06-go-live-decision-packet.v1.json")
    payload = cast(dict[str, JSONValue], document["payload"])
    gates = cast(list[JSONValue], payload["gate_results"])
    first = cast(dict[str, JSONValue], gates[0])
    first["gate_name"] = "BUSINESS_ACCEPTANCE"
    second = cast(dict[str, JSONValue], gates[1])
    second["gate_id"] = "G-01"
    payload["blocked_gates"] = []
    payload["final_decision"] = "PASS"
    document["status"] = "APPROVED"
    _redigest(document)

    with pytest.raises(ArtifactValidationError) as raised:
        verify_artifact_integrity(document)
    assert {
        "DUPLICATE_GATE_ID",
        "GATE_NAME_MISMATCH",
        "GATE_SET_MISMATCH",
        "GATE_PARTITION_MISMATCH",
        "FINAL_DECISION_PRECEDENCE_MISMATCH",
    } <= _codes(raised.value)


def test_pass_is_forbidden_while_carried_conditions_or_obligations_are_open() -> None:
    document = _artifact("06-go-live-decision-packet.v1.json")
    payload = cast(dict[str, JSONValue], document["payload"])
    gates = cast(list[dict[str, JSONValue]], payload["gate_results"])
    for gate in gates:
        gate["outcome"] = "PASS"
    payload["failed_gates"] = []
    payload["blocked_gates"] = []
    payload["passed_gates"] = [f"G-{index:02d}" for index in range(1, 15)]
    payload["final_decision"] = "PASS"
    decision = cast(dict[str, JSONValue], payload["decision"])
    decision["outcome"] = "APPROVED"
    decision["conditions"] = []
    document["authority"] = copy.deepcopy(decision)
    document["status"] = "APPROVED"
    _redigest(document)

    with pytest.raises(ArtifactValidationError) as raised:
        verify_artifact_integrity(document, root=ROOT)
    assert {
        "PASS_WITH_OPEN_UPSTREAM_CONDITION",
        "PASS_WITH_OPEN_UPSTREAM_OBLIGATION",
    } <= _codes(raised.value)


def test_selected_options_controls_and_decision_outcomes_are_computed_invariants() -> None:
    alignment = _artifact("02-stakeholder-alignment-packet.v1.json")
    alignment_payload = cast(dict[str, JSONValue], alignment["payload"])
    alignment_payload["selected_option_id"] = "OPTION-NOT-ASSESSED"
    _redigest(alignment)
    with pytest.raises(ArtifactValidationError) as alignment_error:
        verify_artifact_integrity(alignment, root=ROOT)
    assert "SELECTED_ALIGNMENT_OPTION_UNKNOWN" in _codes(alignment_error.value)

    process = _artifact("03-process-redesign-decision.v1.json")
    process_payload = cast(dict[str, JSONValue], process["payload"])
    process_payload["selected_option_id"] = "OPTION-NOT-ASSESSED"
    process_payload["controls_preserved"] = ["CTRL-UNRELATED"]
    _redigest(process)
    with pytest.raises(ArtifactValidationError) as process_error:
        verify_artifact_integrity(process, root=ROOT)
    assert "SELECTED_PROCESS_OPTION_UNKNOWN" in _codes(process_error.value)

    controls = _artifact("03-process-redesign-decision.v1.json")
    controls_payload = cast(dict[str, JSONValue], controls["payload"])
    controls_payload["controls_preserved"] = ["CTRL-UNRELATED"]
    _redigest(controls)
    with pytest.raises(ArtifactValidationError) as controls_error:
        verify_artifact_integrity(controls, root=ROOT)
    assert "PRESERVED_CONTROL_SET_MISMATCH" in _codes(controls_error.value)

    requirements = _artifact("01-requirements-assessment.v1.json")
    requirements_payload = cast(dict[str, JSONValue], requirements["payload"])
    review = cast(dict[str, JSONValue], requirements_payload["human_review"])
    review["outcome"] = "REJECTED"
    requirements["authority"] = copy.deepcopy(review)
    _redigest(requirements)
    with pytest.raises(ArtifactValidationError) as outcome_error:
        verify_artifact_integrity(requirements, root=ROOT)
    assert "DECISION_OUTCOME_STATUS_MISMATCH" in _codes(outcome_error.value)


def test_schema_format_and_raw_file_hash_failures(tmp_path: Path) -> None:
    document = _artifact("01-requirements-assessment.v1.json")
    document["produced_at"] = "2026-08-08 12:00:00"
    with pytest.raises(SchemaValidationError):
        validate_document(document, root=ROOT, verify_integrity=False)

    path = EXAMPLE / "01-requirements-assessment.v1.json"
    assert len(raw_file_sha256(path)) == 64
    with pytest.raises(ResourceError, match="cannot read"):
        raw_file_sha256(tmp_path / "missing")


def test_validate_file_rejects_non_object_json(tmp_path: Path) -> None:
    path = tmp_path / "array.json"
    path.write_text("[]", encoding="utf-8")
    with pytest.raises(SchemaValidationError, match="must be an object"):
        validate_file(path, root=ROOT)


def test_gate_helper_is_fail_closed_on_noncollections_and_partial_items() -> None:
    assert _gate_set_diagnostics(None, path="/gates") == ([], {})
    diagnostics, observed = _gate_set_diagnostics(
        ["not-an-object", {"gate_name": "UNKNOWN"}, {"gate_id": "G-99"}],
        path="/gates",
    )
    assert observed == {"G-99": ""}
    assert {item.code for item in diagnostics} == {"GATE_SET_MISMATCH"}


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


def test_catalog_registry_corruption_modes_are_distinguished(tmp_path: Path) -> None:
    source = json.loads((ROOT / "registry" / "contract-catalog.json").read_text())

    mutations: list[tuple[str, object, str]] = [
        ("missing-list", {}, "must contain contracts"),
        ("non-object", {"contracts": ["bad"]}, "not an object"),
        ("missing-identity", {"contracts": [{}]}, "lacks name/version/schema_path"),
    ]
    duplicate = copy.deepcopy(source)
    duplicate["contracts"].append(copy.deepcopy(duplicate["contracts"][0]))
    mutations.append(("duplicate", duplicate, "duplicate catalog identity"))
    bad_version = copy.deepcopy(source)
    bad_version["contracts"][0]["version"] = "v1"
    mutations.append(("version", bad_version, "not SemVer"))
    bad_digest = copy.deepcopy(source)
    bad_digest["contracts"][0]["schema_sha256"] = "BAD"
    mutations.append(("digest-shape", bad_digest, "digest is malformed"))
    wrong_digest = copy.deepcopy(source)
    wrong_digest["contracts"][0]["schema_sha256"] = "0" * 64
    mutations.append(("digest-value", wrong_digest, "digest mismatch"))
    wrong_major = copy.deepcopy(source)
    wrong_major["contracts"][0]["major_version"] = 2
    mutations.append(("major", wrong_major, "major_version mismatch"))

    catalog = ContractCatalog(ROOT)
    original_root = catalog.root
    for name, value, message in mutations:
        case_root = tmp_path / name
        (case_root / "registry").mkdir(parents=True)
        _write_json(case_root / "registry" / "contract-catalog.json", value)
        catalog.root = case_root
        with pytest.raises(ResourceError, match=message):
            catalog.catalog_entries()
    catalog.root = original_root
    assert len(catalog.catalog_entries(verify=False)) == 12


def test_compatibility_registry_corruption_modes_are_distinguished(tmp_path: Path) -> None:
    catalog = ContractCatalog(ROOT)
    registry = tmp_path / "registry"
    shutil.copytree(ROOT / "registry", registry)
    original = json.loads((registry / "compatibility-matrix.json").read_text())
    catalog.root = tmp_path

    mutations: list[tuple[object, str]] = [
        ({}, "must contain rules"),
        ({"rules": ["bad"]}, "not an object"),
        ({"rules": [{}]}, "lacks identity"),
    ]
    duplicate = copy.deepcopy(original)
    duplicate["rules"].append(copy.deepcopy(duplicate["rules"][0]))
    mutations.append((duplicate, "duplicate compatibility rule"))
    versions = copy.deepcopy(original)
    versions["rules"][0]["accepted_input_versions"] = []
    mutations.append((versions, "invalid versions"))
    statuses = copy.deepcopy(original)
    statuses["rules"][0]["accepted_statuses"] = []
    mutations.append((statuses, "invalid statuses"))
    unknown = copy.deepcopy(original)
    unknown["rules"][0]["producer_contract"] = "Unknown.v1"
    mutations.append((unknown, "unsupported or unknown"))

    path = registry / "compatibility-matrix.json"
    for value, message in mutations:
        _write_json(path, value)
        with pytest.raises(ResourceError, match=message):
            catalog.compatibility_rules()
    _write_json(path, unknown)
    assert catalog.compatibility_rules(verify=False)


def test_schema_loading_and_evaluation_resource_failures(tmp_path: Path) -> None:
    for name, schema_value, message in (
        ("empty", None, "no JSON schemas"),
        ("array", [], "schema is not a JSON object"),
        ("dialect", {"$schema": "draft-07"}, "does not declare"),
    ):
        root = tmp_path / name
        (root / "schemas").mkdir(parents=True)
        (root / "registry").mkdir()
        if schema_value is not None:
            _write_json(root / "schemas" / "bad.json", schema_value)
        with pytest.raises(ResourceError, match=message):
            ContractCatalog(root)

    catalog = ContractCatalog(ROOT)
    invalid_schema = SchemaRecord(
        path=tmp_path / "invalid.schema.json",
        relative_path="invalid.schema.json",
        document={"$schema": "https://json-schema.org/draft/2020-12/schema", "type": 7},
        schema_id=None,
        artifact_type=None,
    )
    with pytest.raises(ResourceError, match="itself invalid"):
        catalog.validate_schema_document({}, invalid_schema)

    unresolved = SchemaRecord(
        path=tmp_path / "unresolved.schema.json",
        relative_path="unresolved.schema.json",
        document={
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "https://example.invalid/unresolved.schema.json",
            "$ref": "missing.schema.json",
        },
        schema_id="https://example.invalid/unresolved.schema.json",
        artifact_type=None,
    )
    with pytest.raises(SchemaValidationError, match="failed closed"):
        catalog.validate_schema_document({}, unresolved)
