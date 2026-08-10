"""Tamper-evident AgentEvent digest and append-only chain verification."""

from __future__ import annotations

import hmac
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, cast

from .canonical import JSONValue, digest_json, is_sha256
from .errors import Diagnostic, EventValidationError


@dataclass(frozen=True, slots=True)
class EventChainResult:
    """Deterministic metadata for one verified, linear AgentEvent chain."""

    transformation_id: str
    correlation_id: str
    event_ids: tuple[str, ...]
    root_event_id: str
    terminal_event_id: str
    terminal_event_digest: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "correlation_id": self.correlation_id,
            "event_count": len(self.event_ids),
            "event_ids": list(self.event_ids),
            "root_event_id": self.root_event_id,
            "terminal_event_digest": self.terminal_event_digest,
            "terminal_event_id": self.terminal_event_id,
            "transformation_id": self.transformation_id,
            "valid": True,
        }


def event_digest(event: Mapping[str, JSONValue]) -> str:
    """Digest the RFC 8785 projection that omits only ``event_digest``."""

    return digest_json({key: value for key, value in event.items() if key != "event_digest"})


def verify_event_digest(event: Mapping[str, JSONValue]) -> str:
    """Verify one already schema-validated AgentEvent's normative digest."""

    computed = event_digest(event)
    declared = event.get("event_digest")
    if not is_sha256(declared) or not hmac.compare_digest(cast(str, declared), computed):
        raise EventValidationError(
            "AgentEvent digest verification failed",
            diagnostics=(
                Diagnostic(
                    "EVENT_DIGEST_MISMATCH",
                    "event_digest must equal the JCS SHA-256 of the event without event_digest",
                    "/event_digest",
                    {"computed": computed, "declared": declared},
                ),
            ),
        )
    return computed


def verify_agent_event(event: Mapping[str, JSONValue], *, root: str | Path | None = None) -> str:
    """Schema-validate and authenticate one AgentEvent."""

    # Local import avoids coupling schema discovery into the digest primitive.
    from .validation import ContractCatalog

    catalog = ContractCatalog(root)
    catalog.verify_registry_reconciliation()
    schema = catalog.resolve_schema("AgentEvent.v1", document=event)
    catalog.validate_schema_document(event, schema)
    return verify_event_digest(event)


def _event_time(value: object) -> datetime:
    if not isinstance(value, str):
        raise ValueError("event time is not a string")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("event time has no UTC offset")
    return parsed


def verify_agent_event_chain(
    events: Sequence[Mapping[str, JSONValue]], *, root: str | Path | None = None
) -> EventChainResult:
    """Verify an ordered, single-root, fork-free AgentEvent sequence."""

    if not events:
        raise EventValidationError("AgentEvent chain requires at least one event")

    from .errors import ContractError
    from .validation import ContractCatalog

    catalog = ContractCatalog(root)
    catalog.verify_registry_reconciliation()
    diagnostics: list[Diagnostic] = []
    by_id: dict[str, Mapping[str, JSONValue]] = {}
    by_digest: dict[str, Mapping[str, JSONValue]] = {}
    supplied_ids: list[str] = []
    for index, event in enumerate(events):
        event_id = event.get("event_id")
        path = f"/{index}"
        if not isinstance(event_id, str):
            diagnostics.append(
                Diagnostic("MISSING_EVENT_ID", "event_id must be a string", path + "/event_id")
            )
            continue
        try:
            schema = catalog.resolve_schema("AgentEvent.v1", document=event)
            catalog.validate_schema_document(event, schema)
            digest = verify_event_digest(event)
        except ContractError as exc:
            diagnostics.extend(
                Diagnostic(item.code, item.message, path + item.path, item.context)
                for item in exc.diagnostics
            )
            if not exc.diagnostics:
                diagnostics.append(Diagnostic("INVALID_AGENT_EVENT", exc.message, path))
            continue
        supplied_ids.append(event_id)
        if event_id in by_id:
            diagnostics.append(
                Diagnostic(
                    "DUPLICATE_EVENT_ID",
                    "event_id occurs more than once",
                    path + "/event_id",
                    {"event_id": event_id},
                )
            )
            continue
        if digest in by_digest:
            diagnostics.append(
                Diagnostic(
                    "DUPLICATE_EVENT_DIGEST",
                    "different event identities share one event digest",
                    path + "/event_digest",
                    {"event_id": event_id},
                )
            )
            continue
        by_id[event_id] = event
        by_digest[digest] = event

    if diagnostics:
        raise EventValidationError("one or more AgentEvents are invalid", diagnostics=diagnostics)

    roots = sorted(
        cast(str, event["event_id"])
        for event in by_id.values()
        if event.get("previous_event_digest") is None
    )
    if len(roots) != 1:
        diagnostics.append(
            Diagnostic(
                "EVENT_ROOT_COUNT_MISMATCH",
                "an AgentEvent chain must contain exactly one root",
                context={"root_event_ids": roots},
            )
        )

    predecessor_by_id: dict[str, str] = {}
    children: dict[str, list[str]] = {event_id: [] for event_id in by_id}
    for event_id in sorted(by_id):
        event = by_id[event_id]
        previous_digest = event.get("previous_event_digest")
        if previous_digest is None:
            continue
        predecessor = by_digest.get(cast(str, previous_digest))
        if predecessor is None:
            diagnostics.append(
                Diagnostic(
                    "STALE_PREVIOUS_EVENT_DIGEST",
                    "previous_event_digest does not resolve within this event chain",
                    f"/{event_id}/previous_event_digest",
                    {"declared": previous_digest},
                )
            )
            continue
        predecessor_id = cast(str, predecessor["event_id"])
        predecessor_by_id[event_id] = predecessor_id
        children[predecessor_id].append(event_id)

    for predecessor_id, child_ids in sorted(children.items()):
        if len(child_ids) > 1:
            diagnostics.append(
                Diagnostic(
                    "EVENT_CHAIN_FORK",
                    "one event digest cannot have more than one successor",
                    f"/{predecessor_id}",
                    {"successor_event_ids": sorted(child_ids)},
                )
            )

    # Detect predecessor cycles independently of root and stale-link errors.
    for start in sorted(by_id):
        seen: list[str] = []
        current = start
        while current in predecessor_by_id:
            if current in seen:
                offset = seen.index(current)
                cycle = [*seen[offset:], current]
                diagnostics.append(
                    Diagnostic(
                        "EVENT_CHAIN_CYCLE",
                        "AgentEvent predecessor links contain a cycle",
                        context={"cycle": cycle},
                    )
                )
                break
            seen.append(current)
            current = predecessor_by_id[current]

    ordered_ids: list[str] = []
    if len(roots) == 1:
        current = roots[0]
        visited: set[str] = set()
        while current not in visited:
            visited.add(current)
            ordered_ids.append(current)
            successors = children.get(current, [])
            if len(successors) != 1:
                break
            current = successors[0]
        if len(visited) != len(by_id):
            diagnostics.append(
                Diagnostic(
                    "EVENT_CHAIN_DISCONNECTED",
                    "every event must be reachable from the single root",
                    context={"unreachable_event_ids": sorted(set(by_id) - visited)},
                )
            )

    transformations = {
        value
        for event in by_id.values()
        if isinstance((value := event.get("transformation_id")), str)
    }
    correlations = {
        value for event in by_id.values() if isinstance((value := event.get("correlation_id")), str)
    }
    if len(transformations) != 1:
        diagnostics.append(
            Diagnostic(
                "EVENT_TRANSFORMATION_MISMATCH",
                "all AgentEvents must share one transformation_id",
                context={"values": sorted(transformations)},
            )
        )
    if len(correlations) != 1:
        diagnostics.append(
            Diagnostic(
                "EVENT_CORRELATION_MISMATCH",
                "all AgentEvents must share one correlation_id",
                context={"values": sorted(correlations)},
            )
        )

    position = {event_id: index for index, event_id in enumerate(ordered_ids)}
    for event_id in ordered_ids:
        event = by_id[event_id]
        artifact_ref = event.get("artifact_ref")
        if isinstance(artifact_ref, dict) and artifact_ref.get("transformation_id") != event.get(
            "transformation_id"
        ):
            diagnostics.append(
                Diagnostic(
                    "EVENT_ARTIFACT_TRANSFORMATION_MISMATCH",
                    "artifact_ref transformation_id must equal the event transformation_id",
                    f"/{event_id}/artifact_ref/transformation_id",
                )
            )
        prior_event_id = predecessor_by_id.get(event_id)
        if prior_event_id is not None and _event_time(event.get("occurred_at")) < _event_time(
            by_id[prior_event_id].get("occurred_at")
        ):
            diagnostics.append(
                Diagnostic(
                    "EVENT_TIME_INVERSION",
                    "an event cannot occur before its predecessor",
                    f"/{event_id}/occurred_at",
                    {"predecessor_event_id": prior_event_id},
                )
            )
        causation_id = event.get("causation_id")
        if causation_id is not None and (
            not isinstance(causation_id, str)
            or causation_id not in position
            or position[causation_id] >= position[event_id]
        ):
            diagnostics.append(
                Diagnostic(
                    "CAUSATION_EVENT_MISMATCH",
                    "causation_id must identify an earlier event in the same chain",
                    f"/{event_id}/causation_id",
                    {"causation_id": causation_id},
                )
            )

    if ordered_ids and supplied_ids != ordered_ids:
        diagnostics.append(
            Diagnostic(
                "EVENT_SEQUENCE_ORDER_MISMATCH",
                "events must be supplied in root-to-terminal chain order",
                context={"actual": supplied_ids, "expected": ordered_ids},
            )
        )
    if diagnostics:
        raise EventValidationError("AgentEvent chain verification failed", diagnostics=diagnostics)

    root_id = ordered_ids[0]
    terminal_id = ordered_ids[-1]
    terminal_digest = cast(str, by_id[terminal_id]["event_digest"])
    return EventChainResult(
        transformation_id=next(iter(transformations)),
        correlation_id=next(iter(correlations)),
        event_ids=tuple(ordered_ids),
        root_event_id=root_id,
        terminal_event_id=terminal_id,
        terminal_event_digest=terminal_digest,
    )
