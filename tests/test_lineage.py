from __future__ import annotations

import copy
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
from transformation_portfolio_contracts.errors import LineageValidationError, ResourceError
from transformation_portfolio_contracts.lineage import (
    calculate_chain_sha256,
    chain_material,
    collect_artifact_files,
    verify_lineage,
    verify_lineage_files,
)
from transformation_portfolio_contracts.validation import decision_subject_projection

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "atlasbridge-end-to-end"


def _chain() -> list[dict[str, JSONValue]]:
    result: list[dict[str, JSONValue]] = []
    for path in sorted(EXAMPLE.glob("0*-*.v1.json")):
        value = load_json(path)
        assert isinstance(value, dict)
        result.append(value)
    assert len(result) == 6
    return result


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


def _codes(error: LineageValidationError) -> set[str]:
    return {item.code for item in error.diagnostics}


def test_atlasbridge_chain_is_complete_deterministic_and_order_independent() -> None:
    artifacts = _chain()
    forward = verify_lineage(artifacts, root=ROOT)
    reverse = verify_lineage(list(reversed(artifacts)), root=ROOT)

    assert forward.portfolio_chain_sha256 == reverse.portfolio_chain_sha256
    assert forward.transformation_id == "ATLASBRIDGE-ONBOARDING-TRANSFORMATION-001"
    assert len(forward.nodes) == 6
    assert forward.topological_order[0] == "RQA-ATLASBRIDGE-001"
    assert forward.terminal_artifact_ids == ("GLD-ATLASBRIDGE-001",)
    assert forward.as_dict()["valid"] is True


def test_lineage_files_expand_directories_and_preserve_sources(tmp_path: Path) -> None:
    result = verify_lineage_files([EXAMPLE], root=ROOT)
    assert all(node.source is not None for node in result.nodes)
    files = collect_artifact_files([EXAMPLE / "01-requirements-assessment.v1.json", EXAMPLE])
    assert len(files) >= 6
    with pytest.raises(ResourceError, match="does not exist"):
        collect_artifact_files([tmp_path / "missing"])


def test_changed_upstream_invalidates_descendant_reference() -> None:
    artifacts = _chain()
    root = artifacts[0]
    payload = cast(dict[str, JSONValue], root["payload"])
    payload["analysis_provenance"] = {
        **cast(dict[str, JSONValue], payload["analysis_provenance"]),
        "analysis_method": "changed after downstream creation",
    }
    _redigest(root)
    root["chain_sha256"] = calculate_chain_sha256(
        artifact_id=cast(str, root["artifact_id"]),
        artifact_sha256=cast(str, root["artifact_sha256"]),
    )

    with pytest.raises(LineageValidationError) as raised:
        verify_lineage(artifacts, root=ROOT)
    assert "STALE_UPSTREAM_DIGEST" in _codes(raised.value)


def test_reference_snapshot_status_time_and_version_are_verified() -> None:
    artifacts = _chain()
    alignment = artifacts[1]
    reference = cast(list[dict[str, JSONValue]], alignment["inputs"])[0]
    reference["status"] = "BLOCKED"
    reference["produced_at"] = "2026-08-08T11:59:59Z"
    reference["schema_version"] = "1.0.1"
    _redigest(alignment)

    with pytest.raises(LineageValidationError) as raised:
        verify_lineage(artifacts, root=ROOT)
    assert {
        "REFERENCE_STATUS_MISMATCH",
        "REFERENCE_TIME_MISMATCH",
        "UPSTREAM_VERSION_MISMATCH",
    } <= _codes(raised.value)


def test_alignment_partition_and_change_derivation_are_enforced() -> None:
    artifacts = _chain()
    alignment_payload = cast(dict[str, JSONValue], artifacts[1]["payload"])
    alignment_payload["agreed_requirement_ids"] = ["ATLASBRIDGE-REQ-IDENTITY-001"]
    _redigest(artifacts[1])

    impact_payload = cast(dict[str, JSONValue], artifacts[3]["payload"])
    impact_payload["selected_process_option_id"] = "OPT-UNSELECTED"
    _redigest(artifacts[3])

    with pytest.raises(LineageValidationError) as raised:
        verify_lineage(artifacts, root=ROOT)
    assert {
        "ALIGNMENT_REQUIREMENT_PARTITION_MISMATCH",
        "SELECTED_PROCESS_OPTION_MISMATCH",
    } <= _codes(raised.value)


def test_final_packet_cannot_drop_bundle_obligations_or_change_candidate() -> None:
    artifacts = _chain()
    final_payload = cast(dict[str, JSONValue], artifacts[-1]["payload"])
    final_payload["upstream_obligations"] = []
    candidate = cast(dict[str, JSONValue], final_payload["release_candidate"])
    candidate["version"] = "2.0.1"
    _redigest(artifacts[-1])

    with pytest.raises(LineageValidationError) as raised:
        verify_lineage(artifacts, root=ROOT)
    assert "BUNDLE_CONTENT_MISMATCH" in _codes(raised.value)


def test_duplicate_id_and_wrong_source_count_fail_closed() -> None:
    artifacts = _chain()
    with pytest.raises(LineageValidationError) as duplicate:
        verify_lineage([*artifacts, copy.deepcopy(artifacts[0])], root=ROOT)
    assert "DUPLICATE_ARTIFACT_ID" in _codes(duplicate.value)

    with pytest.raises(ValueError, match="one entry per artifact"):
        verify_lineage(artifacts, root=ROOT, sources=["only-one"])
    with pytest.raises(LineageValidationError, match="at least one"):
        verify_lineage([], root=ROOT)


def test_content_collision_missing_upstream_and_stale_chain_are_distinct() -> None:
    artifacts = _chain()
    collision = copy.deepcopy(artifacts[0])
    collision_payload = cast(dict[str, JSONValue], collision["payload"])
    collision_payload["analysis_provenance"] = {
        **cast(dict[str, JSONValue], collision_payload["analysis_provenance"]),
        "analysis_method": "different content under a reused id",
    }
    _redigest(collision)
    with pytest.raises(LineageValidationError) as collided:
        verify_lineage([artifacts[0], collision], root=ROOT)
    assert "ARTIFACT_ID_CONTENT_COLLISION" in _codes(collided.value)

    with pytest.raises(LineageValidationError) as missing:
        verify_lineage([artifacts[-1]], root=ROOT)
    assert "MISSING_UPSTREAM_ARTIFACT" in _codes(missing.value)

    artifacts[0]["chain_sha256"] = "f" * 64
    alignment_ref = cast(list[dict[str, JSONValue]], artifacts[1]["inputs"])[0]
    alignment_ref["chain_sha256"] = "f" * 64
    _redigest(artifacts[1])
    with pytest.raises(LineageValidationError) as stale:
        verify_lineage(artifacts, root=ROOT)
    assert {"STALE_CHAIN_DIGEST", "STALE_UPSTREAM_CHAIN_DIGEST"} <= _codes(stale.value)


def test_authority_chronology_and_transformation_mismatch_are_rejected() -> None:
    artifacts = _chain()
    authority = cast(dict[str, JSONValue], artifacts[0]["authority"])
    authority["recorded_at"] = "2026-08-08T12:01:00Z"
    requirements_payload = cast(dict[str, JSONValue], artifacts[0]["payload"])
    human_review = cast(dict[str, JSONValue], requirements_payload["human_review"])
    human_review["recorded_at"] = authority["recorded_at"]
    _redigest(artifacts[0])

    alignment_ref = cast(list[dict[str, JSONValue]], artifacts[1]["inputs"])[0]
    alignment_ref["transformation_id"] = "OTHER-TRANSFORMATION-001"
    _redigest(artifacts[1])

    with pytest.raises(LineageValidationError) as raised:
        verify_lineage(artifacts, root=ROOT)
    assert {
        "AUTHORITY_AFTER_PRODUCTION",
        "REFERENCE_TRANSFORMATION_MISMATCH",
    } <= _codes(raised.value)


def test_unknown_process_condition_and_gate_source_are_rejected() -> None:
    artifacts = _chain()
    redesign_payload = cast(dict[str, JSONValue], artifacts[2]["payload"])
    redesign_payload["constraining_condition_ids"] = ["CONDITION-DOES-NOT-EXIST"]
    _redigest(artifacts[2])

    bundle_payload = cast(dict[str, JSONValue], artifacts[4]["payload"])
    gates = cast(list[dict[str, JSONValue]], bundle_payload["gate_evidence"])
    gates[0]["source_artifact_ids"] = ["UNKNOWN-ARTIFACT-001"]
    _redigest(artifacts[4])

    with pytest.raises(LineageValidationError) as raised:
        verify_lineage(artifacts, root=ROOT)
    assert {
        "UNKNOWN_CONSTRAINING_CONDITION",
        "UNKNOWN_GATE_SOURCE_ARTIFACT",
    } <= _codes(raised.value)


def test_alignment_issue_and_process_selection_must_match_upstream_assessments() -> None:
    artifacts = _chain()[:3]
    alignment_payload = cast(dict[str, JSONValue], artifacts[1]["payload"])
    issues = cast(list[dict[str, JSONValue]], alignment_payload["alignment_issues"])
    requirement_ids = cast(list[JSONValue], issues[0]["requirement_ids"])
    requirement_ids.append("REQUIREMENT-NOT-ASSESSED")
    _redigest(artifacts[1])

    process_payload = cast(dict[str, JSONValue], artifacts[2]["payload"])
    process_payload["selected_option_id"] = "OPT-A"
    process_payload["controls_preserved"] = ["CTRL-IDENTITY", "CTRL-HUMAN-APPROVAL"]
    _redigest(artifacts[2])

    with pytest.raises(LineageValidationError) as raised:
        verify_lineage(artifacts, root=ROOT)
    assert {
        "UNKNOWN_ALIGNMENT_REQUIREMENT",
        "PROCESS_ALIGNMENT_SELECTION_MISMATCH",
    } <= _codes(raised.value)


def test_candidate_and_causal_time_inversions_are_rejected() -> None:
    artifacts = _chain()
    final_payload = cast(dict[str, JSONValue], artifacts[-1]["payload"])
    candidate = cast(dict[str, JSONValue], final_payload["release_candidate"])
    candidate["release_candidate_id"] = "ATLASBRIDGE-ONBOARDING-OTHER"
    artifacts[-1]["produced_at"] = "2026-08-08T12:30:00Z"
    _redigest(artifacts[-1])

    with pytest.raises(LineageValidationError) as raised:
        verify_lineage(artifacts, root=ROOT)
    assert {"RELEASE_CANDIDATE_MISMATCH", "CAUSAL_TIME_INVERSION"} <= _codes(raised.value)


def test_cycle_is_detected_even_when_other_relationship_claims_are_stale() -> None:
    first = copy.deepcopy(_chain()[2])
    second = copy.deepcopy(_chain()[2])
    for artifact, artifact_id, produced_at in (
        (first, "CYCLE-A", "2026-08-08T14:00:00Z"),
        (second, "CYCLE-B", "2026-08-08T15:00:00Z"),
    ):
        artifact["artifact_id"] = artifact_id
        artifact["produced_at"] = produced_at

    def supersession(replacement: dict[str, JSONValue], predecessor: dict[str, JSONValue]) -> None:
        authority = cast(dict[str, JSONValue], replacement["authority"])
        replacement["supersession"] = {
            "semantics": "IMMUTABLE_REPLACEMENT",
            "supersedes": {
                "artifact_type": predecessor["artifact_type"],
                "artifact_id": predecessor["artifact_id"],
                "transformation_id": predecessor["transformation_id"],
                "schema_version": predecessor["spec_version"],
                "sha256": "a" * 64,
                "chain_sha256": "b" * 64,
                "relationship": "SUPERSEDES",
                "status": predecessor["status"],
                "produced_at": predecessor["produced_at"],
            },
            "reason": "cycle detection test",
            "recorded_at": replacement["produced_at"],
            "authority_decision_id": authority["decision_id"],
        }

    supersession(first, second)
    supersession(second, first)
    _redigest(first)
    _redigest(second)

    with pytest.raises(LineageValidationError) as raised:
        verify_lineage([first, second], root=ROOT)
    assert "LINEAGE_CYCLE" in _codes(raised.value)


def test_chain_material_has_a_stable_domain_separated_projection() -> None:
    material = chain_material(
        artifact_id="A-001",
        artifact_sha256="a" * 64,
        upstream=[("B-001", "DERIVED_FROM", "b" * 64, "c" * 64)],
    )
    assert material["digest_profile"] == "TPC-JCS-SHA256-v1"
    assert (
        len(
            calculate_chain_sha256(
                artifact_id="A-001",
                artifact_sha256="a" * 64,
                upstream=[("B-001", "DERIVED_FROM", "b" * 64, "c" * 64)],
            )
        )
        == 64
    )
