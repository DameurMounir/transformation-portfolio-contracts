from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from transformation_portfolio_contracts import cli
from transformation_portfolio_contracts.canonical import JSONValue
from transformation_portfolio_contracts.errors import EventValidationError
from transformation_portfolio_contracts.events import (
    event_digest,
    verify_agent_event,
    verify_agent_event_chain,
)
from transformation_portfolio_contracts.validation import validate_document

ROOT = Path(__file__).resolve().parents[1]


def _root_event() -> dict[str, JSONValue]:
    event: dict[str, JSONValue] = {
        "event_id": "EVENT-ROOT-001",
        "transformation_id": "TRANSFORMATION-EVENT-001",
        "correlation_id": "CORRELATION-EVENT-001",
        "causation_id": None,
        "stage": "PORTFOLIO",
        "event_type": "TRANSFORMATION_STARTED",
        "actor_type": "SYSTEM",
        "actor_id": "portfolio-orchestrator",
        "artifact_ref": None,
        "occurred_at": "2026-08-10T10:00:00Z",
        "previous_event_digest": None,
        "event_digest": "0" * 64,
    }
    event["event_digest"] = event_digest(event)
    return event


def _terminal_event(root_event: dict[str, JSONValue]) -> dict[str, JSONValue]:
    event: dict[str, JSONValue] = {
        "event_id": "EVENT-TERMINAL-001",
        "transformation_id": root_event["transformation_id"],
        "correlation_id": root_event["correlation_id"],
        "causation_id": root_event["event_id"],
        "stage": "PORTFOLIO",
        "event_type": "TRANSFORMATION_COMPLETED",
        "actor_type": "SYSTEM",
        "actor_id": "portfolio-orchestrator",
        "artifact_ref": None,
        "occurred_at": "2026-08-10T10:01:00Z",
        "previous_event_digest": root_event["event_digest"],
        "event_digest": "0" * 64,
    }
    event["event_digest"] = event_digest(event)
    return event


def _codes(error: EventValidationError) -> set[str]:
    return {item.code for item in error.diagnostics}


def test_single_event_and_ordered_chain_are_authenticated() -> None:
    root_event = _root_event()
    terminal = _terminal_event(root_event)

    assert verify_agent_event(root_event, root=ROOT) == root_event["event_digest"]
    assert validate_document(root_event, contract="AgentEvent.v1", root=ROOT).schema_path.endswith(
        "agent-event.v1.schema.json"
    )
    result = verify_agent_event_chain([root_event, terminal], root=ROOT)
    assert result.event_ids == ("EVENT-ROOT-001", "EVENT-TERMINAL-001")
    assert result.terminal_event_digest == terminal["event_digest"]


def test_event_tamper_and_stale_previous_link_are_distinct() -> None:
    root_event = _root_event()
    tampered = copy.deepcopy(root_event)
    tampered["actor_id"] = "attacker"
    with pytest.raises(EventValidationError) as changed:
        verify_agent_event(tampered, root=ROOT)
    assert _codes(changed.value) == {"EVENT_DIGEST_MISMATCH"}

    terminal = _terminal_event(root_event)
    terminal["previous_event_digest"] = "f" * 64
    terminal["event_digest"] = event_digest(terminal)
    with pytest.raises(EventValidationError) as stale:
        verify_agent_event_chain([root_event, terminal], root=ROOT)
    assert "STALE_PREVIOUS_EVENT_DIGEST" in _codes(stale.value)


def test_event_fork_order_causation_and_chronology_fail_closed() -> None:
    root_event = _root_event()
    first = _terminal_event(root_event)
    second = copy.deepcopy(first)
    second["event_id"] = "EVENT-TERMINAL-002"
    second["event_digest"] = event_digest(second)
    with pytest.raises(EventValidationError) as forked:
        verify_agent_event_chain([root_event, first, second], root=ROOT)
    assert "EVENT_CHAIN_FORK" in _codes(forked.value)

    with pytest.raises(EventValidationError) as reordered:
        verify_agent_event_chain([first, root_event], root=ROOT)
    assert "EVENT_SEQUENCE_ORDER_MISMATCH" in _codes(reordered.value)

    first["causation_id"] = "EVENT-UNKNOWN-001"
    first["occurred_at"] = "2026-08-10T09:59:00Z"
    first["event_digest"] = event_digest(first)
    with pytest.raises(EventValidationError) as invalid_links:
        verify_agent_event_chain([root_event, first], root=ROOT)
    assert {"CAUSATION_EVENT_MISMATCH", "EVENT_TIME_INVERSION"} <= _codes(invalid_links.value)


def test_event_root_identity_and_artifact_correlation_are_fail_closed() -> None:
    first_root = _root_event()
    second_root = copy.deepcopy(first_root)
    second_root["event_id"] = "EVENT-ROOT-002"
    second_root["transformation_id"] = "TRANSFORMATION-EVENT-002"
    second_root["correlation_id"] = "CORRELATION-EVENT-002"
    second_root["event_digest"] = event_digest(second_root)
    with pytest.raises(EventValidationError) as roots:
        verify_agent_event_chain([first_root, second_root], root=ROOT)
    assert {
        "EVENT_ROOT_COUNT_MISMATCH",
        "EVENT_TRANSFORMATION_MISMATCH",
        "EVENT_CORRELATION_MISMATCH",
    } <= _codes(roots.value)

    produced = _terminal_event(first_root)
    produced["event_type"] = "ARTIFACT_PRODUCED"
    produced["stage"] = "REQUIREMENTS_QUALITY"
    produced["artifact_ref"] = {
        "artifact_type": "RequirementsAssessment",
        "artifact_id": "RQA-EVENT-001",
        "transformation_id": "TRANSFORMATION-OTHER-001",
        "schema_version": "1.0.0",
        "sha256": "a" * 64,
        "chain_sha256": "b" * 64,
        "relationship": "DERIVED_FROM",
        "status": "HUMAN_CONFIRMED",
        "produced_at": "2026-08-10T10:00:30Z",
    }
    produced["event_digest"] = event_digest(produced)
    with pytest.raises(EventValidationError) as mismatched:
        verify_agent_event_chain([first_root, produced], root=ROOT)
    assert "EVENT_ARTIFACT_TRANSFORMATION_MISMATCH" in _codes(mismatched.value)


def test_event_chain_rejects_empty_and_duplicate_identity() -> None:
    with pytest.raises(EventValidationError, match="at least one"):
        verify_agent_event_chain([], root=ROOT)

    root_event = _root_event()
    with pytest.raises(EventValidationError) as duplicate:
        verify_agent_event_chain([root_event, copy.deepcopy(root_event)], root=ROOT)
    assert "DUPLICATE_EVENT_ID" in _codes(duplicate.value)


def test_verify_events_cli_accepts_scenario_document(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root_event = _root_event()
    path = tmp_path / "events.json"
    path.write_text(
        json.dumps({"case_id": "EVENT-CASE-001", "events": [root_event]}),
        encoding="utf-8",
    )
    assert cli.main(["verify-events", str(path), "--root", str(ROOT), "--json"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["root_event_id"] == "EVENT-ROOT-001"
    assert output["valid"] is True


def test_verify_events_cli_handles_direct_directory_and_malformed_inputs(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    direct = tmp_path / "event.json"
    direct.write_text(json.dumps(_root_event()), encoding="utf-8")
    assert cli.main(["verify-events", str(direct), "--root", str(ROOT), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["event_count"] == 1

    collection = tmp_path / "collection"
    collection.mkdir()
    (collection / "event.json").write_text(json.dumps(_root_event()), encoding="utf-8")
    (collection / "ancillary.json").write_text("{}", encoding="utf-8")
    assert cli.main(["verify-events", str(collection), "--root", str(ROOT), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["valid"] is True

    malformed = tmp_path / "malformed.json"
    malformed.write_text('{"events":[]}', encoding="utf-8")
    assert cli.main(["verify-events", str(malformed), "--root", str(ROOT), "--json"]) == 3
    assert json.loads(capsys.readouterr().err)["error"] == "RESOURCE_ERROR"

    unrelated = tmp_path / "unrelated.json"
    unrelated.write_text("{}", encoding="utf-8")
    assert cli.main(["verify-events", str(unrelated), "--root", str(ROOT), "--json"]) == 3
    assert json.loads(capsys.readouterr().err)["error"] == "RESOURCE_ERROR"
