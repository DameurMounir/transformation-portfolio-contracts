"""Deterministic, fail-closed verification of cross-stage artifact lineage."""

from __future__ import annotations

import hmac
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, cast

from .canonical import DIGEST_PROFILE, JSONValue, digest_json, load_json
from .errors import ContractError, Diagnostic, LineageValidationError, ResourceError
from .validation import ContractCatalog, contract_major, verify_artifact_integrity

INELIGIBLE_UPSTREAM_STATUSES = frozenset({"DRAFT", "REJECTED", "SUPERSEDED"})
AUTHORITY_REQUIRED_STATUSES = frozenset(
    {"HUMAN_CONFIRMED", "CONDITIONALLY_APPROVED", "APPROVED", "REJECTED", "SUPERSEDED"}
)
STAGE_ORDER = {
    "REQUIREMENTS_ASSESSMENT": 10,
    "REQUIREMENTS_QUALITY": 10,
    "STAKEHOLDER_ALIGNMENT": 20,
    "PROCESS_REDESIGN": 30,
    "CHANGE_IMPACT": 40,
    "BUSINESS_CHANGE_IMPACT": 40,
    "GO_LIVE_EVIDENCE": 50,
    "GO_LIVE_EVIDENCE_BUNDLE": 50,
    "GO_LIVE_DECISION": 60,
}


@dataclass(frozen=True, slots=True)
class ArtifactNode:
    """Verified artifact metadata used to calculate a lineage graph."""

    artifact_id: str
    artifact_type: str
    transformation_id: str
    stage: str
    produced_at: datetime
    artifact_sha256: str
    chain_sha256: str
    source: str | None = None

    def as_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "artifact_id": self.artifact_id,
            "artifact_sha256": self.artifact_sha256,
            "artifact_type": self.artifact_type,
            "chain_sha256": self.chain_sha256,
            "produced_at": self.produced_at.isoformat(),
            "stage": self.stage,
            "transformation_id": self.transformation_id,
        }
        if self.source is not None:
            result["source"] = self.source
        return result


@dataclass(frozen=True, slots=True)
class LineageResult:
    """Successful lineage result with deterministic order and portfolio digest."""

    transformation_id: str
    nodes: tuple[ArtifactNode, ...]
    topological_order: tuple[str, ...]
    terminal_artifact_ids: tuple[str, ...]
    portfolio_chain_sha256: str

    def as_dict(self) -> dict[str, Any]:
        by_id = {node.artifact_id: node for node in self.nodes}
        return {
            "artifact_count": len(self.nodes),
            "artifacts": [by_id[item].as_dict() for item in self.topological_order],
            "digest_profile": DIGEST_PROFILE,
            "portfolio_chain_sha256": self.portfolio_chain_sha256,
            "terminal_artifact_ids": list(self.terminal_artifact_ids),
            "topological_order": list(self.topological_order),
            "transformation_id": self.transformation_id,
            "valid": True,
        }


def _time(value: object) -> datetime:
    if not isinstance(value, str):
        raise ValueError("not a string")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    result = datetime.fromisoformat(normalized)
    if result.tzinfo is None or result.utcoffset() is None:
        raise ValueError("timezone offset is required")
    return result


def _candidate_id(artifact: Mapping[str, JSONValue]) -> str | None:
    direct = artifact.get("release_candidate_id")
    if isinstance(direct, str):
        return direct
    payload = artifact.get("payload")
    if isinstance(payload, dict):
        nested = payload.get("release_candidate_id")
        if isinstance(nested, str):
            return nested
        candidate = payload.get("candidate", payload.get("release_candidate"))
        if isinstance(candidate, dict):
            for key in ("release_candidate_id", "candidate_id"):
                value = candidate.get(key)
                if isinstance(value, str):
                    return value
    return None


def _references(artifact: Mapping[str, JSONValue]) -> tuple[Mapping[str, JSONValue], ...]:
    raw = artifact.get("inputs", [])
    if not isinstance(raw, list):
        return ()
    return tuple(item for item in raw if isinstance(item, dict))


def _supersession_reference(
    artifact: Mapping[str, JSONValue],
) -> Mapping[str, JSONValue] | None:
    supersession = artifact.get("supersession")
    if not isinstance(supersession, dict):
        return None
    reference = supersession.get("supersedes")
    return reference if isinstance(reference, dict) else None


def _snapshot_mismatch_fields(
    reference: Mapping[str, JSONValue], expected: Mapping[str, object]
) -> list[str]:
    """Compare authenticated snapshot fields, constant-time for SHA-256 values."""

    mismatched: list[str] = []
    for field, expected_value in expected.items():
        actual_value = reference.get(field)
        if field in {"sha256", "chain_sha256"}:
            if (
                not isinstance(actual_value, str)
                or not isinstance(expected_value, str)
                or not hmac.compare_digest(actual_value, expected_value)
            ):
                mismatched.append(field)
        elif actual_value != expected_value:
            mismatched.append(field)
    return mismatched


def _payload(artifact: Mapping[str, JSONValue]) -> Mapping[str, JSONValue]:
    value = artifact.get("payload")
    return value if isinstance(value, dict) else {}


def _upstream_of_type(
    artifact: Mapping[str, JSONValue],
    documents: Mapping[str, Mapping[str, JSONValue]],
    artifact_type: str,
) -> tuple[Mapping[str, JSONValue], Mapping[str, JSONValue]] | None:
    for reference in _references(artifact):
        upstream_id = reference.get("artifact_id")
        if (
            reference.get("artifact_type") == artifact_type
            and isinstance(upstream_id, str)
            and upstream_id in documents
        ):
            return reference, documents[upstream_id]
    return None


def _evidence_fingerprints(value: JSONValue) -> set[str]:
    """Collect canonical identities of nested portable EvidenceReference objects."""

    result: set[str] = set()

    def walk(item: JSONValue) -> None:
        if isinstance(item, list):
            for nested in item:
                walk(nested)
            return
        if not isinstance(item, dict):
            return
        if all(key in item for key in ("evidence_id", "source_sha256", "quote_sha256")):
            result.add(digest_json(item))
        for nested in item.values():
            walk(nested)

    walk(value)
    return result


def _stage_semantic_diagnostics(
    documents: Mapping[str, Mapping[str, JSONValue]],
    content_digests: Mapping[str, str],
    gate_source_policy: Mapping[str, tuple[str, ...]],
) -> tuple[Diagnostic, ...]:
    """Verify cross-stage claims that cannot be checked by one JSON Schema."""

    diagnostics: list[Diagnostic] = []
    for artifact_id in sorted(documents):
        artifact = documents[artifact_id]
        artifact_type = artifact.get("artifact_type")
        payload = _payload(artifact)

        if artifact_type == "StakeholderAlignmentPacket":
            resolved = _upstream_of_type(artifact, documents, "RequirementsAssessment")
            if resolved is not None:
                _, requirements = resolved
                requirements_payload = _payload(requirements)
                if payload.get("requirements_baseline_id") != requirements_payload.get(
                    "requirements_baseline_id"
                ):
                    diagnostics.append(
                        Diagnostic(
                            "REQUIREMENTS_BASELINE_MISMATCH",
                            "alignment requirements_baseline_id differs from its "
                            "upstream assessment",
                            f"/{artifact_id}/payload/requirements_baseline_id",
                        )
                    )
                requirements_items = requirements_payload.get("requirements")
                expected_ids = (
                    {
                        item["requirement_id"]
                        for item in requirements_items
                        if isinstance(item, dict) and isinstance(item.get("requirement_id"), str)
                    }
                    if isinstance(requirements_items, list)
                    else set()
                )
                groups = {
                    field: {
                        value
                        for value in cast(list[JSONValue], payload.get(field, []))
                        if isinstance(value, str)
                    }
                    for field in (
                        "agreed_requirement_ids",
                        "disputed_requirement_ids",
                        "undecided_requirement_ids",
                    )
                    if isinstance(payload.get(field, []), list)
                }
                all_values = [value for group in groups.values() for value in group]
                if len(all_values) != len(set(all_values)):
                    diagnostics.append(
                        Diagnostic(
                            "ALIGNMENT_REQUIREMENT_PARTITION_OVERLAP",
                            "agreed, disputed, and undecided requirement sets must be disjoint",
                            f"/{artifact_id}/payload",
                        )
                    )
                observed_ids = set(all_values)
                if observed_ids != expected_ids:
                    diagnostics.append(
                        Diagnostic(
                            "ALIGNMENT_REQUIREMENT_PARTITION_MISMATCH",
                            "alignment sets must partition every upstream requirement exactly once",
                            f"/{artifact_id}/payload",
                            {
                                "missing": sorted(expected_ids - observed_ids),
                                "extra": sorted(observed_ids - expected_ids),
                            },
                        )
                    )
                issues = payload.get("alignment_issues")
                unknown_issue_requirements: set[str] = set()
                if isinstance(issues, list):
                    for issue in issues:
                        requirement_ids = (
                            issue.get("requirement_ids") if isinstance(issue, dict) else None
                        )
                        if isinstance(requirement_ids, list):
                            unknown_issue_requirements.update(
                                value
                                for value in requirement_ids
                                if isinstance(value, str) and value not in expected_ids
                            )
                if unknown_issue_requirements:
                    diagnostics.append(
                        Diagnostic(
                            "UNKNOWN_ALIGNMENT_REQUIREMENT",
                            "alignment issue cites a requirement absent from its "
                            "upstream assessment",
                            f"/{artifact_id}/payload/alignment_issues",
                            {"unknown": sorted(unknown_issue_requirements)},
                        )
                    )

        if artifact_type == "ProcessRedesignDecision":
            resolved = _upstream_of_type(artifact, documents, "StakeholderAlignmentPacket")
            if resolved is not None:
                _, alignment = resolved
                alignment_payload = _payload(alignment)
                conditions_value = alignment_payload.get("open_conditions")
                condition_ids = (
                    {
                        item["condition_id"]
                        for item in conditions_value
                        if isinstance(item, dict) and isinstance(item.get("condition_id"), str)
                    }
                    if isinstance(conditions_value, list)
                    else set()
                )
                constraining = payload.get("constraining_condition_ids")
                constraining_ids = (
                    {item for item in constraining if isinstance(item, str)}
                    if isinstance(constraining, list)
                    else set()
                )
                missing = sorted(constraining_ids - condition_ids)
                if missing:
                    diagnostics.append(
                        Diagnostic(
                            "UNKNOWN_CONSTRAINING_CONDITION",
                            "process constraint does not exist in alignment open_conditions",
                            f"/{artifact_id}/payload/constraining_condition_ids",
                            {"unknown": missing},
                        )
                    )
                alignment_options = alignment_payload.get("options")
                alignment_option_ids = (
                    {
                        item["option_id"]
                        for item in alignment_options
                        if isinstance(item, dict) and isinstance(item.get("option_id"), str)
                    }
                    if isinstance(alignment_options, list)
                    else set()
                )
                selected_option = payload.get("selected_option_id")
                if selected_option not in alignment_option_ids:
                    diagnostics.append(
                        Diagnostic(
                            "PROCESS_OPTION_NOT_ALIGNED",
                            "selected process option was not assessed by stakeholder alignment",
                            f"/{artifact_id}/payload/selected_option_id",
                            {
                                "actual": selected_option,
                                "aligned_options": sorted(alignment_option_ids),
                            },
                        )
                    )
                if selected_option != alignment_payload.get("selected_option_id"):
                    diagnostics.append(
                        Diagnostic(
                            "PROCESS_ALIGNMENT_SELECTION_MISMATCH",
                            "process selection must preserve the stakeholder-aligned option",
                            f"/{artifact_id}/payload/selected_option_id",
                            {
                                "actual": selected_option,
                                "expected": alignment_payload.get("selected_option_id"),
                            },
                        )
                    )

        if artifact_type == "ChangeImpactPacket":
            resolved = _upstream_of_type(artifact, documents, "ProcessRedesignDecision")
            if resolved is not None:
                reference, redesign = resolved
                redesign_id = cast(str, redesign.get("artifact_id"))
                checks = (
                    (
                        "derived_from_artifact_id",
                        redesign_id,
                        "CHANGE_DERIVATION_ID_MISMATCH",
                    ),
                    (
                        "derived_from_artifact_sha256",
                        content_digests[redesign_id],
                        "CHANGE_DERIVATION_DIGEST_MISMATCH",
                    ),
                    (
                        "selected_process_option_id",
                        _payload(redesign).get("selected_option_id"),
                        "SELECTED_PROCESS_OPTION_MISMATCH",
                    ),
                    (
                        "portfolio_chain_sha256",
                        reference.get("chain_sha256"),
                        "PORTFOLIO_CHAIN_REFERENCE_MISMATCH",
                    ),
                )
                for field, expected, code in checks:
                    actual = payload.get(field)
                    matches = (
                        isinstance(actual, str)
                        and isinstance(expected, str)
                        and hmac.compare_digest(actual, expected)
                        if field in {"derived_from_artifact_sha256", "portfolio_chain_sha256"}
                        else actual == expected
                    )
                    if not matches:
                        diagnostics.append(
                            Diagnostic(
                                code,
                                f"{field} differs from the resolved process-redesign input",
                                f"/{artifact_id}/payload/{field}",
                                {"actual": actual, "expected": expected},
                            )
                        )

        if artifact_type == "GoLiveEvidenceBundle":
            declared_input_ids = {
                value
                for reference in _references(artifact)
                if isinstance((value := reference.get("artifact_id")), str)
            }
            gate_evidence = payload.get("gate_evidence")
            contract_to_artifact_id = {
                f"{documents[value].get('artifact_type')}.v1": value
                for reference in _references(artifact)
                if isinstance((value := reference.get("artifact_id")), str) and value in documents
            }
            operational_evidence = payload.get("operational_evidence")
            operational_fingerprints = _evidence_fingerprints(operational_evidence)
            if isinstance(gate_evidence, list):
                for index, gate in enumerate(gate_evidence):
                    if not isinstance(gate, dict):
                        continue
                    source_ids = gate.get("source_artifact_ids")
                    unknown = (
                        sorted(
                            item
                            for item in source_ids
                            if isinstance(item, str) and item not in declared_input_ids
                        )
                        if isinstance(source_ids, list)
                        else []
                    )
                    if unknown:
                        diagnostics.append(
                            Diagnostic(
                                "UNKNOWN_GATE_SOURCE_ARTIFACT",
                                "gate evidence cites an artifact outside the verified lineage",
                                f"/{artifact_id}/payload/gate_evidence/{index}/source_artifact_ids",
                                {"unknown": unknown},
                            )
                        )
                    gate_id = gate.get("gate_id")
                    expected_contracts = (
                        gate_source_policy.get(gate_id, ()) if isinstance(gate_id, str) else ()
                    )
                    expected_source_ids = {
                        contract_to_artifact_id[contract]
                        for contract in expected_contracts
                        if contract in contract_to_artifact_id
                    }
                    actual_source_ids = (
                        {value for value in source_ids if isinstance(value, str)}
                        if isinstance(source_ids, list)
                        else set()
                    )
                    if actual_source_ids != expected_source_ids:
                        diagnostics.append(
                            Diagnostic(
                                "GATE_SOURCE_SET_MISMATCH",
                                "gate source_artifact_ids must exactly match registered "
                                "stage sources",
                                f"/{artifact_id}/payload/gate_evidence/{index}/source_artifact_ids",
                                {
                                    "actual": sorted(actual_source_ids),
                                    "expected": sorted(expected_source_ids),
                                },
                            )
                        )
                    allowed_evidence = set(operational_fingerprints)
                    for source_id in actual_source_ids:
                        source = documents.get(source_id)
                        if source is not None:
                            allowed_evidence.update(
                                _evidence_fingerprints(cast(JSONValue, dict(source)))
                            )
                    evidence_refs = gate.get("evidence_refs")
                    if isinstance(evidence_refs, list):
                        invented = sorted(
                            cast(str, evidence.get("evidence_id"))
                            for evidence in evidence_refs
                            if isinstance(evidence, dict)
                            and digest_json(evidence) not in allowed_evidence
                        )
                        if invented:
                            diagnostics.append(
                                Diagnostic(
                                    "UNREGISTERED_GATE_EVIDENCE",
                                    "gate evidence must originate from operational or declared "
                                    "source evidence",
                                    f"/{artifact_id}/payload/gate_evidence/{index}/evidence_refs",
                                    {"evidence_ids": invented},
                                )
                            )

            expected_projections: dict[str, list[JSONValue]] = {
                "upstream_conditions": [],
                "upstream_obligations": [],
            }
            alignment_resolved = _upstream_of_type(
                artifact, documents, "StakeholderAlignmentPacket"
            )
            if alignment_resolved is not None:
                _, alignment = alignment_resolved
                alignment_id = cast(str, alignment.get("artifact_id"))
                conditions = _payload(alignment).get("open_conditions")
                if isinstance(conditions, list):
                    for condition in conditions:
                        if isinstance(condition, dict):
                            expected_projections["upstream_conditions"].append(
                                {
                                    "source_artifact_id": alignment_id,
                                    "condition_id": condition.get("condition_id"),
                                    "description": condition.get("description"),
                                    "status": condition.get("status"),
                                    "evidence_refs": condition.get("evidence_refs"),
                                }
                            )
            impact_resolved = _upstream_of_type(artifact, documents, "ChangeImpactPacket")
            if impact_resolved is not None:
                _, impact = impact_resolved
                impact_id = cast(str, impact.get("artifact_id"))
                obligations = _payload(impact).get("obligations")
                if isinstance(obligations, list):
                    for obligation in obligations:
                        if isinstance(obligation, dict):
                            expected_projections["upstream_obligations"].append(
                                {
                                    "source_artifact_id": impact_id,
                                    "obligation_id": obligation.get("obligation_id"),
                                    "description": obligation.get("description"),
                                    "status": obligation.get("status"),
                                    "evidence_refs": obligation.get("evidence_refs"),
                                }
                            )
            for field, expected_items in expected_projections.items():
                actual_items = payload.get(field)
                expected_fingerprints = sorted(digest_json(item) for item in expected_items)
                actual_fingerprints = (
                    sorted(digest_json(item) for item in actual_items if isinstance(item, dict))
                    if isinstance(actual_items, list)
                    else []
                )
                if actual_fingerprints != expected_fingerprints:
                    diagnostics.append(
                        Diagnostic(
                            "BUNDLE_UPSTREAM_PROJECTION_MISMATCH",
                            f"{field} must project every source record exactly once "
                            "without alteration",
                            f"/{artifact_id}/payload/{field}",
                            {
                                "actual_count": len(actual_fingerprints),
                                "expected_count": len(expected_fingerprints),
                            },
                        )
                    )

        if artifact_type == "GoLiveDecisionPacket":
            resolved = _upstream_of_type(artifact, documents, "GoLiveEvidenceBundle")
            if resolved is not None:
                _, bundle = resolved
                bundle_payload = _payload(bundle)
                for field in ("release_candidate", "upstream_conditions", "upstream_obligations"):
                    actual = payload.get(field)
                    expected = bundle_payload.get(field)
                    if digest_json(actual) != digest_json(expected):
                        diagnostics.append(
                            Diagnostic(
                                "BUNDLE_CONTENT_MISMATCH",
                                f"final packet must preserve bundle {field} without alteration",
                                f"/{artifact_id}/payload/{field}",
                            )
                        )
                bundle_gates_value = bundle_payload.get("gate_evidence")
                final_gates_value = payload.get("gate_results")
                bundle_gates = (
                    {
                        cast(str, gate["gate_id"]): gate
                        for gate in bundle_gates_value
                        if isinstance(gate, dict) and isinstance(gate.get("gate_id"), str)
                    }
                    if isinstance(bundle_gates_value, list)
                    else {}
                )
                final_gates = (
                    {
                        cast(str, gate["gate_id"]): gate
                        for gate in final_gates_value
                        if isinstance(gate, dict) and isinstance(gate.get("gate_id"), str)
                    }
                    if isinstance(final_gates_value, list)
                    else {}
                )
                for gate_id in sorted(set(bundle_gates) & set(final_gates)):
                    evidence_gate = bundle_gates[gate_id]
                    result_gate = final_gates[gate_id]
                    if result_gate.get("upstream_artifact_ids") != evidence_gate.get(
                        "source_artifact_ids"
                    ):
                        diagnostics.append(
                            Diagnostic(
                                "GATE_RESULT_SOURCE_MISMATCH",
                                "gate result must preserve bundle source artifact IDs",
                                f"/{artifact_id}/payload/gate_results/{gate_id}/upstream_artifact_ids",
                            )
                        )
                    if digest_json(result_gate.get("evidence_refs")) != digest_json(
                        evidence_gate.get("evidence_refs")
                    ):
                        diagnostics.append(
                            Diagnostic(
                                "GATE_RESULT_EVIDENCE_MISMATCH",
                                "gate result must preserve bundle evidence references",
                                f"/{artifact_id}/payload/gate_results/{gate_id}/evidence_refs",
                            )
                        )
                    availability = evidence_gate.get("availability")
                    outcome = result_gate.get("outcome")
                    if availability in {"MISSING", "INCOMPLETE"} and outcome != "BLOCKED":
                        diagnostics.append(
                            Diagnostic(
                                "GATE_EVIDENCE_UNAVAILABLE_FOR_PASS",
                                "missing or incomplete gate evidence requires a BLOCKED outcome",
                                f"/{artifact_id}/payload/gate_results/{gate_id}/outcome",
                                {"availability": availability, "outcome": outcome},
                            )
                        )
    return tuple(diagnostics)


def chain_material(
    *,
    artifact_id: str,
    artifact_sha256: str,
    upstream: Iterable[tuple[str, str, str, str]],
) -> dict[str, JSONValue]:
    """Return the normative per-artifact chain projection.

    Each upstream tuple is ``(artifact_id, relationship, artifact_sha256,
    chain_sha256)``.  Sorting makes command-line file order irrelevant.
    """

    ordered = sorted(upstream, key=lambda item: (item[0], item[1], item[2]))
    inputs: list[JSONValue] = [
        {
            "artifact_id": upstream_id,
            "artifact_sha256": upstream_sha,
            "chain_sha256": upstream_chain,
            "relationship": relationship,
        }
        for upstream_id, relationship, upstream_sha, upstream_chain in ordered
    ]
    return {
        "digest_profile": DIGEST_PROFILE,
        "artifact_id": artifact_id,
        "artifact_sha256": artifact_sha256,
        "inputs": inputs,
    }


def calculate_chain_sha256(
    *,
    artifact_id: str,
    artifact_sha256: str,
    upstream: Iterable[tuple[str, str, str, str]] = (),
) -> str:
    """Calculate one artifact's deterministic transitive chain digest."""

    return digest_json(
        chain_material(
            artifact_id=artifact_id,
            artifact_sha256=artifact_sha256,
            upstream=upstream,
        )
    )


def _topological_order(
    artifact_ids: Sequence[str], edges: Mapping[str, Sequence[str]]
) -> tuple[str, ...]:
    """Return stable upstream-first order or raise on a cycle."""

    state: dict[str, int] = {}
    result: list[str] = []
    stack: list[str] = []

    def visit(node: str) -> None:
        current = state.get(node, 0)
        if current == 2:
            return
        if current == 1:
            try:
                start = stack.index(node)
            except ValueError:
                start = 0
            cycle = [*stack[start:], node]
            raise LineageValidationError(
                "lineage contains a cycle",
                diagnostics=(
                    Diagnostic(
                        "LINEAGE_CYCLE",
                        " -> ".join(cycle),
                        context={"cycle": cycle},
                    ),
                ),
            )
        state[node] = 1
        stack.append(node)
        for upstream_id in sorted(edges.get(node, ())):
            visit(upstream_id)
        stack.pop()
        state[node] = 2
        result.append(node)

    for artifact_id in sorted(artifact_ids):
        visit(artifact_id)
    return tuple(result)


def verify_lineage(
    artifacts: Sequence[Mapping[str, JSONValue]],
    *,
    root: str | Path | None = None,
    sources: Sequence[str | None] | None = None,
) -> LineageResult:
    """Verify schemas, identities, causal edges, and every transitive digest."""

    if not artifacts:
        raise LineageValidationError("lineage requires at least one artifact")
    if sources is not None and len(sources) != len(artifacts):
        raise ValueError("sources must have exactly one entry per artifact")

    catalog = ContractCatalog(root)
    compatibility = {
        (
            cast(str, rule["producer_contract"]),
            cast(str, rule["consumer_contract"]),
            cast(str, rule["relationship"]),
        ): rule
        for rule in catalog.compatibility_rules(verify=True)
    }
    required_inputs = {
        cast(str, stage["produces"]): tuple(cast(list[str], stage.get("consumes", [])))
        for stage in catalog.stage_registrations(verify=True)
        if isinstance(stage.get("produces"), str) and isinstance(stage.get("consumes"), list)
    }
    gate_source_policy = catalog.gate_source_policy(verify=True)
    diagnostics: list[Diagnostic] = []
    documents: dict[str, Mapping[str, JSONValue]] = {}
    document_sources: dict[str, str | None] = {}
    content_digests: dict[str, str] = {}

    for index, artifact in enumerate(artifacts):
        artifact_id_value = artifact.get("artifact_id")
        if not isinstance(artifact_id_value, str):
            diagnostics.append(
                Diagnostic(
                    "MISSING_ARTIFACT_ID",
                    "artifact_id must be a string",
                    f"/{index}/artifact_id",
                )
            )
            continue
        artifact_id = artifact_id_value
        source = sources[index] if sources is not None else None
        try:
            schema = catalog.resolve_schema(document=artifact)
            catalog.validate_schema_document(artifact, schema)
            actual_digest, _ = verify_artifact_integrity(artifact, catalog=catalog)
        except ContractError as exc:
            if exc.diagnostics:
                diagnostics.extend(
                    Diagnostic(
                        item.code,
                        item.message,
                        f"/{artifact_id}{item.path}",
                        item.context,
                    )
                    for item in exc.diagnostics
                )
            else:
                diagnostics.append(Diagnostic("INVALID_ARTIFACT", exc.message, f"/{artifact_id}"))
            continue

        if artifact_id in documents:
            previous_digest = content_digests[artifact_id]
            code = (
                "DUPLICATE_ARTIFACT_ID"
                if previous_digest == actual_digest
                else "ARTIFACT_ID_CONTENT_COLLISION"
            )
            diagnostics.append(
                Diagnostic(
                    code,
                    "artifact_id occurs more than once"
                    if code == "DUPLICATE_ARTIFACT_ID"
                    else "the same artifact_id names different content",
                    f"/{artifact_id}",
                    {
                        "first_sha256": previous_digest,
                        "second_sha256": actual_digest,
                    },
                )
            )
            continue
        documents[artifact_id] = artifact
        document_sources[artifact_id] = source
        content_digests[artifact_id] = actual_digest

    if diagnostics:
        raise LineageValidationError(
            "one or more lineage artifacts are invalid", diagnostics=tuple(diagnostics)
        )

    transformations = {
        value
        for artifact in documents.values()
        if isinstance((value := artifact.get("transformation_id")), str)
    }
    if len(transformations) != 1 or len(documents) != len(artifacts):
        diagnostics.append(
            Diagnostic(
                "TRANSFORMATION_MISMATCH",
                "all artifacts must carry exactly one common transformation_id",
                context={"values": sorted(transformations)},
            )
        )
    cases = {
        value
        for artifact in documents.values()
        if isinstance((value := artifact.get("case_id")), str)
    }
    if len(cases) != 1:
        diagnostics.append(
            Diagnostic(
                "CASE_ID_MISMATCH",
                "all artifacts must carry exactly one common case_id",
                context={"values": sorted(cases)},
            )
        )

    edges: dict[str, list[str]] = {artifact_id: [] for artifact_id in documents}
    referenced: set[str] = set()
    superseded_by: dict[str, str] = {}
    for replacement_id in sorted(documents):
        replacement = documents[replacement_id]
        reference = _supersession_reference(replacement)
        if reference is None:
            continue
        predecessor_id = reference.get("artifact_id")
        reference_path = f"/{replacement_id}/supersession/supersedes"
        if not isinstance(predecessor_id, str) or predecessor_id not in documents:
            diagnostics.append(
                Diagnostic(
                    "MISSING_SUPERSEDED_ARTIFACT",
                    "the superseded predecessor artifact was not supplied",
                    reference_path + "/artifact_id",
                    {"artifact_id": predecessor_id},
                )
            )
            continue
        predecessor = documents[predecessor_id]
        previous_replacement = superseded_by.get(predecessor_id)
        if previous_replacement is not None and previous_replacement != replacement_id:
            diagnostics.append(
                Diagnostic(
                    "ARTIFACT_SUPERSESSION_FORK",
                    "one predecessor cannot have multiple replacement artifacts",
                    reference_path,
                    {
                        "predecessor_artifact_id": predecessor_id,
                        "replacement_artifact_ids": sorted({previous_replacement, replacement_id}),
                    },
                )
            )
        else:
            superseded_by[predecessor_id] = replacement_id
        edges[replacement_id].append(predecessor_id)
        referenced.add(predecessor_id)

        identity_fields = (
            "artifact_type",
            "transformation_id",
            "case_id",
            "stage",
        )
        mismatched_identity = [
            field for field in identity_fields if replacement.get(field) != predecessor.get(field)
        ]
        if mismatched_identity:
            diagnostics.append(
                Diagnostic(
                    "SUPERSESSION_IDENTITY_MISMATCH",
                    "replacement and predecessor must share type, stage, case, and transformation",
                    f"/{replacement_id}/supersession",
                    {"fields": mismatched_identity},
                )
            )

        expected_snapshot: dict[str, object] = {
            "artifact_type": predecessor.get("artifact_type"),
            "transformation_id": predecessor.get("transformation_id"),
            "schema_version": predecessor.get("spec_version", predecessor.get("schema_version")),
            "sha256": content_digests[predecessor_id],
            "chain_sha256": predecessor.get("chain_sha256"),
            "relationship": "SUPERSEDES",
            "status": predecessor.get("status"),
            "produced_at": predecessor.get("produced_at"),
        }
        mismatched_snapshot = _snapshot_mismatch_fields(reference, expected_snapshot)
        if mismatched_snapshot:
            diagnostics.append(
                Diagnostic(
                    "SUPERSESSION_REFERENCE_MISMATCH",
                    "supersession must authenticate the exact predecessor snapshot",
                    reference_path,
                    {"fields": mismatched_snapshot},
                )
            )

        supersession = cast(Mapping[str, JSONValue], replacement["supersession"])
        predecessor_time = _time(predecessor.get("produced_at"))
        replacement_time = _time(replacement.get("produced_at"))
        recorded_time = _time(supersession.get("recorded_at"))
        if recorded_time < predecessor_time or recorded_time > replacement_time:
            diagnostics.append(
                Diagnostic(
                    "SUPERSESSION_TIME_INVERSION",
                    "supersession recorded_at must fall between predecessor and replacement",
                    f"/{replacement_id}/supersession/recorded_at",
                )
            )
        authority = replacement.get("authority")
        authority_id = authority.get("decision_id") if isinstance(authority, dict) else None
        if supersession.get("authority_decision_id") != authority_id:
            diagnostics.append(
                Diagnostic(
                    "SUPERSESSION_AUTHORITY_MISMATCH",
                    "supersession authority_decision_id must identify replacement authority",
                    f"/{replacement_id}/supersession/authority_decision_id",
                    {"expected": authority_id},
                )
            )

    for downstream_id in sorted(documents):
        downstream = documents[downstream_id]
        downstream_stage = downstream.get("stage")
        downstream_time = _time(downstream.get("produced_at"))
        downstream_candidate = _candidate_id(downstream)

        downstream_type = downstream.get("artifact_type")
        downstream_version = downstream.get("spec_version", downstream.get("schema_version"))
        downstream_contract = (
            f"{downstream_type}.v{str(downstream_version).split('.', 1)[0]}"
            if isinstance(downstream_type, str)
            else ""
        )
        expected_input_contracts = set(required_inputs.get(downstream_contract, ()))
        actual_input_contracts = [
            f"{reference.get('artifact_type')}.v"
            f"{str(reference.get('schema_version', '')).split('.', 1)[0]}"
            for reference in _references(downstream)
            if isinstance(reference.get("artifact_type"), str)
            and isinstance(reference.get("schema_version"), str)
        ]
        if set(actual_input_contracts) != expected_input_contracts or len(
            actual_input_contracts
        ) != len(set(actual_input_contracts)):
            diagnostics.append(
                Diagnostic(
                    "REQUIRED_INPUT_SET_MISMATCH",
                    "artifact inputs must exactly equal registered required stage contracts",
                    f"/{downstream_id}/inputs",
                    {
                        "actual": sorted(actual_input_contracts),
                        "expected": sorted(expected_input_contracts),
                    },
                )
            )

        status = downstream.get("status")
        if status in AUTHORITY_REQUIRED_STATUSES and not isinstance(
            downstream.get("authority"), dict
        ):
            diagnostics.append(
                Diagnostic(
                    "HUMAN_AUTHORITY_REQUIRED",
                    f"status {status} requires a non-null authority record",
                    f"/{downstream_id}/authority",
                )
            )
        authority = downstream.get("authority")
        if isinstance(authority, dict) and "recorded_at" in authority:
            try:
                if _time(authority.get("recorded_at")) > downstream_time:
                    diagnostics.append(
                        Diagnostic(
                            "AUTHORITY_AFTER_PRODUCTION",
                            "authority.recorded_at is later than artifact produced_at",
                            f"/{downstream_id}/authority/recorded_at",
                        )
                    )
            except ValueError:
                # The schema/format checker already reports invalid timestamps.
                pass

        for reference_index, reference in enumerate(_references(downstream)):
            reference_path = f"/{downstream_id}/inputs/{reference_index}"
            upstream_id_value = reference.get("artifact_id")
            if not isinstance(upstream_id_value, str) or upstream_id_value not in documents:
                diagnostics.append(
                    Diagnostic(
                        "MISSING_UPSTREAM_ARTIFACT",
                        f"referenced artifact {upstream_id_value!r} was not supplied",
                        reference_path + "/artifact_id",
                    )
                )
                continue
            upstream_id = upstream_id_value
            upstream = documents[upstream_id]
            edges[downstream_id].append(upstream_id)
            referenced.add(upstream_id)
            if upstream_id in superseded_by:
                diagnostics.append(
                    Diagnostic(
                        "SUPERSEDED_UPSTREAM_ARTIFACT",
                        "downstream input uses an artifact with a supplied replacement",
                        reference_path + "/artifact_id",
                        {
                            "replacement_artifact_id": superseded_by[upstream_id],
                            "superseded_artifact_id": upstream_id,
                        },
                    )
                )

            declared_input_sha = reference.get("sha256")
            if not isinstance(declared_input_sha, str) or not hmac.compare_digest(
                declared_input_sha, content_digests[upstream_id]
            ):
                diagnostics.append(
                    Diagnostic(
                        "STALE_UPSTREAM_DIGEST",
                        "input sha256 no longer matches the resolved upstream artifact",
                        reference_path + "/sha256",
                        {
                            "computed": content_digests[upstream_id],
                            "declared": reference.get("sha256"),
                        },
                    )
                )
            if reference.get("artifact_type") != upstream.get("artifact_type"):
                diagnostics.append(
                    Diagnostic(
                        "UPSTREAM_TYPE_MISMATCH",
                        "input artifact_type differs from the resolved artifact",
                        reference_path + "/artifact_type",
                    )
                )
            if reference.get("transformation_id") != upstream.get("transformation_id"):
                diagnostics.append(
                    Diagnostic(
                        "REFERENCE_TRANSFORMATION_MISMATCH",
                        "input transformation_id differs from the resolved artifact",
                        reference_path + "/transformation_id",
                    )
                )
            if reference.get("status") != upstream.get("status"):
                diagnostics.append(
                    Diagnostic(
                        "REFERENCE_STATUS_MISMATCH",
                        "input status differs from the resolved artifact",
                        reference_path + "/status",
                    )
                )
            if reference.get("produced_at") != upstream.get("produced_at"):
                diagnostics.append(
                    Diagnostic(
                        "REFERENCE_TIME_MISMATCH",
                        "input produced_at differs from the resolved artifact",
                        reference_path + "/produced_at",
                    )
                )
            reference_version = reference.get("schema_version")
            upstream_version = upstream.get("spec_version", upstream.get("schema_version"))
            try:
                reference_major = contract_major(
                    reference_version, path=reference_path + "/schema_version"
                )
                upstream_major = contract_major(
                    upstream_version, path=f"/{upstream_id}/spec_version"
                )
                if reference_major != upstream_major:
                    diagnostics.append(
                        Diagnostic(
                            "UPSTREAM_VERSION_MISMATCH",
                            "input and resolved artifact contract majors differ",
                            reference_path + "/schema_version",
                        )
                    )
                elif reference_version != upstream_version:
                    diagnostics.append(
                        Diagnostic(
                            "UPSTREAM_VERSION_MISMATCH",
                            "input schema_version differs from the resolved artifact version",
                            reference_path + "/schema_version",
                            {"upstream": upstream_version, "reference": reference_version},
                        )
                    )
            except ContractError as exc:
                diagnostics.extend(exc.diagnostics)

            if upstream.get("transformation_id") != downstream.get("transformation_id"):
                diagnostics.append(
                    Diagnostic(
                        "TRANSFORMATION_MISMATCH",
                        "upstream and downstream transformation_id differ",
                        reference_path,
                    )
                )
            if upstream.get("case_id") != downstream.get("case_id"):
                diagnostics.append(
                    Diagnostic(
                        "CASE_ID_MISMATCH",
                        "upstream and downstream case_id differ",
                        reference_path,
                    )
                )
            upstream_status = upstream.get("status")
            if upstream_status in INELIGIBLE_UPSTREAM_STATUSES:
                diagnostics.append(
                    Diagnostic(
                        "INELIGIBLE_UPSTREAM_STATUS",
                        f"status {upstream_status} cannot be consumed",
                        f"/{upstream_id}/status",
                    )
                )
            upstream_type = upstream.get("artifact_type")
            relationship_value = reference.get("relationship")
            upstream_contract = (
                f"{upstream_type}.v{str(upstream_version).split('.', 1)[0]}"
                if isinstance(upstream_type, str)
                else ""
            )
            rule = compatibility.get(
                (
                    upstream_contract,
                    downstream_contract,
                    relationship_value if isinstance(relationship_value, str) else "",
                )
            )
            if rule is None:
                diagnostics.append(
                    Diagnostic(
                        "UNSUPPORTED_PRODUCER_CONSUMER",
                        "no supported compatibility rule authorizes this lineage edge",
                        reference_path,
                        {
                            "producer_contract": upstream_contract,
                            "consumer_contract": downstream_contract,
                            "relationship": relationship_value,
                        },
                    )
                )
            else:
                accepted_versions = rule.get("accepted_input_versions")
                if (
                    not isinstance(accepted_versions, list)
                    or upstream_version not in accepted_versions
                ):
                    diagnostics.append(
                        Diagnostic(
                            "INCOMPATIBLE_UPSTREAM_VERSION",
                            "upstream version is not accepted by the consumer contract",
                            reference_path + "/schema_version",
                            {"actual": upstream_version, "accepted": accepted_versions},
                        )
                    )
                accepted_statuses = rule.get("accepted_statuses")
                if (
                    not isinstance(accepted_statuses, list)
                    or upstream_status not in accepted_statuses
                ):
                    diagnostics.append(
                        Diagnostic(
                            "INCOMPATIBLE_UPSTREAM_STATUS",
                            "upstream status is not accepted by the consumer contract",
                            reference_path + "/status",
                            {"actual": upstream_status, "accepted": accepted_statuses},
                        )
                    )
            upstream_time = _time(upstream.get("produced_at"))
            if downstream_time < upstream_time:
                diagnostics.append(
                    Diagnostic(
                        "CAUSAL_TIME_INVERSION",
                        "downstream artifact was produced before its upstream input",
                        f"/{downstream_id}/produced_at",
                        {"upstream_artifact_id": upstream_id},
                    )
                )
            upstream_stage = upstream.get("stage")
            if (
                isinstance(downstream_stage, str)
                and isinstance(upstream_stage, str)
                and downstream_stage in STAGE_ORDER
                and upstream_stage in STAGE_ORDER
                and STAGE_ORDER[upstream_stage] >= STAGE_ORDER[downstream_stage]
            ):
                diagnostics.append(
                    Diagnostic(
                        "STAGE_ORDER_INVERSION",
                        "upstream stage must precede downstream stage",
                        reference_path,
                        {"upstream_stage": upstream_stage, "downstream_stage": downstream_stage},
                    )
                )
            upstream_candidate = _candidate_id(upstream)
            if (
                downstream_candidate is not None
                and upstream_candidate is not None
                and downstream_candidate != upstream_candidate
            ):
                diagnostics.append(
                    Diagnostic(
                        "RELEASE_CANDIDATE_MISMATCH",
                        "upstream and downstream release candidates differ",
                        reference_path,
                        {"upstream": upstream_candidate, "downstream": downstream_candidate},
                    )
                )

    for final_id, final in sorted(documents.items()):
        if final.get("artifact_type") != "GoLiveDecisionPacket":
            continue
        declared_value = _payload(final).get("superseded_artifacts")
        declared = declared_value if isinstance(declared_value, list) else []
        declared_by_id = {
            cast(str, item["artifact_id"]): item
            for item in declared
            if isinstance(item, dict) and isinstance(item.get("artifact_id"), str)
        }
        if len(declared_by_id) != len(declared) or set(declared_by_id) != set(superseded_by):
            diagnostics.append(
                Diagnostic(
                    "SUPERSEDED_ARTIFACT_SET_MISMATCH",
                    "final packet must list every effective superseded predecessor exactly once",
                    f"/{final_id}/payload/superseded_artifacts",
                    {
                        "actual": sorted(declared_by_id),
                        "expected": sorted(superseded_by),
                    },
                )
            )
        for predecessor_id in sorted(set(declared_by_id) & set(superseded_by)):
            predecessor = documents[predecessor_id]
            reference = declared_by_id[predecessor_id]
            expected = {
                "artifact_type": predecessor.get("artifact_type"),
                "transformation_id": predecessor.get("transformation_id"),
                "schema_version": predecessor.get(
                    "spec_version", predecessor.get("schema_version")
                ),
                "sha256": content_digests[predecessor_id],
                "chain_sha256": predecessor.get("chain_sha256"),
                "relationship": "SUPERSEDES",
                "status": predecessor.get("status"),
                "produced_at": predecessor.get("produced_at"),
            }
            mismatched = _snapshot_mismatch_fields(reference, expected)
            if mismatched:
                diagnostics.append(
                    Diagnostic(
                        "SUPERSEDED_ARTIFACT_REFERENCE_MISMATCH",
                        "final superseded_artifacts entry is not the exact predecessor snapshot",
                        f"/{final_id}/payload/superseded_artifacts/{predecessor_id}",
                        {"fields": mismatched},
                    )
                )

    diagnostics.extend(_stage_semantic_diagnostics(documents, content_digests, gate_source_policy))
    order: tuple[str, ...] | None = None
    try:
        order = _topological_order(tuple(documents), edges)
    except LineageValidationError as exc:
        diagnostics.extend(exc.diagnostics)
    if order is None:  # Defensive boundary if graph evaluation changes in the future.
        raise LineageValidationError(
            "lineage order could not be established", diagnostics=tuple(diagnostics)
        )
    computed_chains: dict[str, str] = {}
    nodes: list[ArtifactNode] = []
    for artifact_id in order:
        artifact = documents[artifact_id]
        upstream_material: list[tuple[str, str, str, str]] = []
        chain_references = list(_references(artifact))
        supersession_reference = _supersession_reference(artifact)
        if supersession_reference is not None:
            chain_references.append(supersession_reference)
        for reference in chain_references:
            upstream_id = cast(str, reference["artifact_id"])
            if upstream_id not in documents or upstream_id not in computed_chains:
                continue
            relationship_value = reference.get("relationship")
            relationship = relationship_value if isinstance(relationship_value, str) else ""
            upstream_material.append(
                (
                    upstream_id,
                    relationship,
                    content_digests[upstream_id],
                    computed_chains[upstream_id],
                )
            )
            declared_input_chain = reference.get("chain_sha256")
            if not isinstance(declared_input_chain, str) or not hmac.compare_digest(
                declared_input_chain, computed_chains[upstream_id]
            ):
                diagnostics.append(
                    Diagnostic(
                        "STALE_UPSTREAM_CHAIN_DIGEST",
                        "input chain_sha256 no longer matches resolved upstream lineage",
                        f"/{artifact_id}/inputs/{upstream_id}/chain_sha256",
                        {
                            "computed": computed_chains[upstream_id],
                            "declared": declared_input_chain,
                        },
                    )
                )
        computed_chain = calculate_chain_sha256(
            artifact_id=artifact_id,
            artifact_sha256=content_digests[artifact_id],
            upstream=upstream_material,
        )
        computed_chains[artifact_id] = computed_chain
        declared_chain = artifact.get("chain_sha256")
        if not isinstance(declared_chain, str) or not hmac.compare_digest(
            declared_chain, computed_chain
        ):
            diagnostics.append(
                Diagnostic(
                    "STALE_CHAIN_DIGEST",
                    "chain_sha256 does not match the resolved transitive lineage",
                    f"/{artifact_id}/chain_sha256",
                    {"computed": computed_chain, "declared": declared_chain},
                )
            )
        nodes.append(
            ArtifactNode(
                artifact_id=artifact_id,
                artifact_type=cast(str, artifact.get("artifact_type")),
                transformation_id=cast(str, artifact.get("transformation_id")),
                stage=cast(str, artifact.get("stage")),
                produced_at=_time(artifact.get("produced_at")),
                artifact_sha256=content_digests[artifact_id],
                chain_sha256=computed_chain,
                source=document_sources[artifact_id],
            )
        )
    if diagnostics:
        raise LineageValidationError(
            "one or more stored chain digests are stale", diagnostics=tuple(diagnostics)
        )

    terminals = tuple(sorted(set(documents) - referenced))
    portfolio_material: JSONValue = {
        "digest_profile": DIGEST_PROFILE,
        "artifacts": [
            {
                "artifact_id": node.artifact_id,
                "artifact_sha256": node.artifact_sha256,
                "chain_sha256": node.chain_sha256,
            }
            for node in sorted(nodes, key=lambda item: item.artifact_id)
        ],
    }
    return LineageResult(
        transformation_id=next(iter(transformations)),
        nodes=tuple(sorted(nodes, key=lambda item: item.artifact_id)),
        topological_order=order,
        terminal_artifact_ids=terminals,
        portfolio_chain_sha256=digest_json(portfolio_material),
    )


def collect_artifact_files(paths: Sequence[str | Path]) -> tuple[Path, ...]:
    """Expand explicit JSON files/directories in deterministic lexical order."""

    result: set[Path] = set()
    for raw_path in paths:
        path = Path(raw_path).expanduser().resolve()
        if path.is_dir():
            result.update(item for item in path.rglob("*.json") if item.is_file())
        elif path.is_file():
            result.add(path)
        else:
            raise ResourceError(f"lineage input does not exist: {path}")
    return tuple(sorted(result, key=lambda item: str(item)))


def verify_lineage_files(
    paths: Sequence[str | Path], *, root: str | Path | None = None
) -> LineageResult:
    """Load explicit artifact files and verify their complete lineage."""

    files = collect_artifact_files(paths)
    explicit_files = {
        Path(item).expanduser().resolve()
        for item in paths
        if Path(item).expanduser().resolve().is_file()
    }
    documents: list[Mapping[str, JSONValue]] = []
    sources: list[str] = []
    for path in files:
        raw = load_json(path)
        if not isinstance(raw, dict) or not isinstance(raw.get("artifact_id"), str):
            if path in explicit_files:
                raise LineageValidationError(f"lineage input is not an artifact: {path}")
            continue
        documents.append(cast(Mapping[str, JSONValue], raw))
        sources.append(str(path))
    if not documents:
        raise LineageValidationError("no artifacts were found in the lineage inputs")
    return verify_lineage(documents, root=root, sources=sources)
