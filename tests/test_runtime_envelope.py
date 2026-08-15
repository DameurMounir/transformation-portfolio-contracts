from __future__ import annotations

import copy
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest

from transformation_portfolio_contracts.canonical import JSONValue, load_json
from transformation_portfolio_contracts.errors import (
    ResourceError,
    RuntimeEnvelopeValidationError,
)
from transformation_portfolio_contracts.runtime_envelope import (
    ActorReference,
    CorrelationReference,
    RuntimeEnvelopeModel,
    hmac_signature_value,
    runtime_envelope_digest,
    runtime_envelope_projection,
    sign_runtime_envelope,
    validate_runtime_envelope_schema,
    verify_runtime_envelope,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures" / "runtime-envelope" / "v1.1"
KEY = bytes(range(1, 33))
NOW = datetime(2026, 8, 15, 12, 15, tzinfo=UTC)


def _load(relative: str) -> dict[str, JSONValue]:
    value = load_json(FIXTURES / relative)
    assert isinstance(value, dict)
    return value


def _resolver(key_id: str) -> bytes | None:
    return KEY if key_id == "KEY-TEST-RUNTIME-001" else None


def _codes(error: RuntimeEnvelopeValidationError) -> set[str]:
    return {item.code for item in error.diagnostics}


def test_valid_fixture_passes_schema_model_digests_expiry_and_signature() -> None:
    envelope = _load("valid/minimal.json")

    result = verify_runtime_envelope(envelope, key_resolver=_resolver, now=NOW, root=ROOT)

    assert result.envelope_id == "RUNTIME-ENVELOPE-ATLASBRIDGE-001"
    assert result.envelope_digest == (
        "5bb4e813b762b63b59593f35cd7c33372dde8d80e9eeefebd7b060dd355fbb2b"
    )
    assert result.as_dict()["valid"] is True


def test_reference_model_is_strict_and_forbids_extra_members() -> None:
    envelope = _load("valid/minimal.json")
    envelope["unexpected"] = True

    with pytest.raises(RuntimeEnvelopeValidationError) as raised:
        verify_runtime_envelope(envelope, key_resolver=_resolver, now=NOW, root=ROOT)

    assert "SCHEMA_ADDITIONALPROPERTIES" in _codes(raised.value)


def test_signing_is_non_mutating_and_deterministic() -> None:
    signed = _load("valid/minimal.json")
    unsigned = runtime_envelope_projection(signed)
    original = copy.deepcopy(unsigned)

    first = sign_runtime_envelope(
        unsigned,
        key_id="KEY-TEST-RUNTIME-001",
        key=KEY,
        signed_at=datetime(2026, 8, 15, 12, 0, 5, tzinfo=UTC),
        root=ROOT,
    )
    second = sign_runtime_envelope(
        unsigned,
        key_id="KEY-TEST-RUNTIME-001",
        key=KEY,
        signed_at=datetime(2026, 8, 15, 12, 0, 5, tzinfo=UTC),
        root=ROOT,
    )

    assert unsigned == original
    assert first == second == signed


def test_projection_excludes_only_signature() -> None:
    envelope = _load("valid/minimal.json")
    projection = runtime_envelope_projection(envelope)

    assert "signature" not in projection
    assert set(projection) == set(envelope) - {"signature"}
    assert (
        runtime_envelope_digest(envelope)
        == cast(dict[str, str], envelope["signature"])["signed_digest"]
    )


@pytest.mark.parametrize(
    ("fixture", "expected_code", "evaluated_at"),
    [
        ("invalid/tampered-payload.json", "PAYLOAD_DIGEST_MISMATCH", NOW),
        ("invalid/wrong-signature.json", "SIGNATURE_MISMATCH", NOW),
        ("invalid/unsupported-version.json", "SCHEMA_CONST", NOW),
        ("invalid/zero-traceparent.json", "REFERENCE_MODEL_INVALID", NOW),
        (
            "invalid/expired.json",
            "ENVELOPE_EXPIRED",
            datetime(2026, 8, 15, 12, 45, tzinfo=UTC),
        ),
    ],
)
def test_invalid_fixtures_fail_closed(
    fixture: str, expected_code: str, evaluated_at: datetime
) -> None:
    with pytest.raises(RuntimeEnvelopeValidationError) as raised:
        verify_runtime_envelope(_load(fixture), key_resolver=_resolver, now=evaluated_at, root=ROOT)

    assert expected_code in _codes(raised.value)


def test_unknown_key_fails_closed() -> None:
    with pytest.raises(RuntimeEnvelopeValidationError) as raised:
        verify_runtime_envelope(
            _load("valid/minimal.json"), key_resolver=lambda _key_id: None, now=NOW, root=ROOT
        )

    assert _codes(raised.value) == {"SIGNING_KEY_UNAVAILABLE"}


def test_key_resolver_exception_is_masked_and_fails_closed() -> None:
    def broken_resolver(_key_id: str) -> bytes | None:
        raise RuntimeError("provider detail must not escape")

    with pytest.raises(RuntimeEnvelopeValidationError) as raised:
        verify_runtime_envelope(
            _load("valid/minimal.json"), key_resolver=broken_resolver, now=NOW, root=ROOT
        )

    assert _codes(raised.value) == {"SIGNING_KEY_UNAVAILABLE"}
    assert "provider detail" not in str(raised.value)


def test_not_yet_valid_is_distinct_from_expired() -> None:
    with pytest.raises(RuntimeEnvelopeValidationError) as raised:
        verify_runtime_envelope(
            _load("valid/minimal.json"),
            key_resolver=_resolver,
            now=datetime(2026, 8, 15, 11, 59, tzinfo=UTC),
            root=ROOT,
        )

    assert _codes(raised.value) == {"ENVELOPE_NOT_YET_VALID"}


def test_naive_evaluation_time_is_rejected() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        verify_runtime_envelope(
            _load("valid/minimal.json"),
            key_resolver=_resolver,
            now=datetime(2026, 8, 15, 12, 15),
            root=ROOT,
        )


def test_reference_hmac_rejects_short_keys_and_bad_digests() -> None:
    with pytest.raises(ValueError, match="at least 32 bytes"):
        hmac_signature_value(b"short", "0" * 64)
    with pytest.raises(ValueError, match="lowercase hexadecimal"):
        hmac_signature_value(KEY, "not-a-digest")
    with pytest.raises(ValueError, match="SHA-256"):
        hmac_signature_value(KEY, "00")


def test_traceparent_reference_model_rejects_forbidden_version() -> None:
    with pytest.raises(ValueError, match="version ff"):
        CorrelationReference(
            correlation_id="CORRELATION-001",
            traceparent="ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
        )


def test_schema_fixture_and_python_model_remain_aligned() -> None:
    envelope = _load("valid/minimal.json")
    validate_runtime_envelope_schema(envelope, root=ROOT)
    model = RuntimeEnvelopeModel.model_validate(envelope)

    assert model.spec_version == "1.1.0"
    assert model.signature.profile == "TPC-HMAC-SHA256-v1"


def test_golden_vectors_match_fixture() -> None:
    envelope = _load("valid/minimal.json")
    vectors = json.loads((FIXTURES / "golden-vectors.json").read_text(encoding="utf-8"))
    by_name = {item["name"]: item["sha256"] for item in vectors["vectors"]}
    signature = cast(dict[str, str], envelope["signature"])

    assert by_name == {
        "policy_context": envelope["policy_context_digest"],
        "payload": envelope["payload_digest"],
        "envelope_projection": runtime_envelope_digest(envelope),
        "hmac_signature": signature["value"],
    }


def test_actor_reference_requires_exact_agent_binding() -> None:
    with pytest.raises(ValueError, match="required for AGENT"):
        ActorReference(
            actor_id="AGENT-001",
            actor_type="AGENT",
            accountable_principal_id="PRINCIPAL-001",
        )
    with pytest.raises(ValueError, match="allowed only for AGENT"):
        ActorReference(
            actor_id="SERVICE-001",
            actor_type="SERVICE",
            accountable_principal_id="PRINCIPAL-001",
            agent_id="AGENT-001",
        )


def test_traceparent_reference_model_rejects_zero_parent_id() -> None:
    with pytest.raises(ValueError, match="parent-id"):
        CorrelationReference(
            correlation_id="CORRELATION-001",
            traceparent="00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
        )


def test_temporal_reference_model_rejects_invalid_order_and_non_utc() -> None:
    envelope = _load("valid/minimal.json")
    envelope["expires_at"] = envelope["issued_at"]
    with pytest.raises(ValueError, match="expires_at"):
        RuntimeEnvelopeModel.model_validate(envelope)

    envelope = _load("valid/minimal.json")
    envelope["issued_at"] = datetime(2026, 8, 15, 12, 0)
    with pytest.raises(ValueError, match="timezone-aware"):
        RuntimeEnvelopeModel.model_validate(envelope)

    envelope = _load("valid/minimal.json")
    signature = cast(dict[str, JSONValue], envelope["signature"])
    signature["signed_at"] = "2026-08-15T14:00:00+01:00"
    with pytest.raises(ValueError, match="must be UTC"):
        RuntimeEnvelopeModel.model_validate(envelope)


def test_signature_timestamp_must_fall_within_validity_window() -> None:
    envelope = _load("valid/minimal.json")
    signature = cast(dict[str, JSONValue], envelope["signature"])
    signature["signed_at"] = "2026-08-15T13:30:00Z"
    with pytest.raises(ValueError, match="validity window"):
        RuntimeEnvelopeModel.model_validate(envelope)


def test_schema_resource_failures_are_explicit(tmp_path: Path) -> None:
    (tmp_path / "schemas").mkdir()
    (tmp_path / "registry").mkdir()
    with pytest.raises(ResourceError, match="schema is unavailable"):
        validate_runtime_envelope_schema(_load("valid/minimal.json"), root=tmp_path)

    schema_dir = tmp_path / "schemas" / "envelope"
    schema_dir.mkdir()
    schema_path = schema_dir / "v1.1.json"
    schema_path.write_text("[]\n", encoding="utf-8")
    with pytest.raises(ResourceError, match="must be a JSON object"):
        validate_runtime_envelope_schema(_load("valid/minimal.json"), root=tmp_path)

    schema_path.write_text('{"$schema":"https://json-schema.org/draft/2020-12/schema","type":7}\n')
    with pytest.raises(ResourceError, match="schema is invalid"):
        validate_runtime_envelope_schema(_load("valid/minimal.json"), root=tmp_path)


def test_signing_requires_payload_and_policy_context() -> None:
    unsigned = runtime_envelope_projection(_load("valid/minimal.json"))
    unsigned.pop("payload")
    with pytest.raises(RuntimeEnvelopeValidationError) as raised:
        sign_runtime_envelope(
            unsigned,
            key_id="KEY-TEST-RUNTIME-001",
            key=KEY,
            signed_at=datetime(2026, 8, 15, 12, 0, 5, tzinfo=UTC),
            root=ROOT,
        )
    assert _codes(raised.value) == {"PAYLOAD_REQUIRED"}

    unsigned = runtime_envelope_projection(_load("valid/minimal.json"))
    unsigned.pop("policy_context")
    with pytest.raises(RuntimeEnvelopeValidationError) as raised:
        sign_runtime_envelope(
            unsigned,
            key_id="KEY-TEST-RUNTIME-001",
            key=KEY,
            signed_at=datetime(2026, 8, 15, 12, 0, 5, tzinfo=UTC),
            root=ROOT,
        )
    assert _codes(raised.value) == {"POLICY_CONTEXT_REQUIRED"}


def test_signing_rejects_naive_timestamp() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        sign_runtime_envelope(
            runtime_envelope_projection(_load("valid/minimal.json")),
            key_id="KEY-TEST-RUNTIME-001",
            key=KEY,
            signed_at=datetime(2026, 8, 15, 12, 0, 5),
            root=ROOT,
        )


def test_signing_wraps_reference_model_failure() -> None:
    unsigned = runtime_envelope_projection(_load("valid/minimal.json"))
    correlation = cast(dict[str, JSONValue], unsigned["correlation"])
    correlation["traceparent"] = "00-00000000000000000000000000000000-00f067aa0ba902b7-01"
    with pytest.raises(RuntimeEnvelopeValidationError) as raised:
        sign_runtime_envelope(
            unsigned,
            key_id="KEY-TEST-RUNTIME-001",
            key=KEY,
            signed_at=datetime(2026, 8, 15, 12, 0, 5, tzinfo=UTC),
            root=ROOT,
        )
    assert _codes(raised.value) == {"REFERENCE_MODEL_INVALID"}


def test_policy_and_complete_projection_tampering_are_distinct() -> None:
    envelope = _load("valid/minimal.json")
    policy = cast(dict[str, JSONValue], envelope["policy_context"])
    policy["effect_class"] = "IRREVERSIBLE"
    with pytest.raises(RuntimeEnvelopeValidationError) as raised:
        verify_runtime_envelope(envelope, key_resolver=_resolver, now=NOW, root=ROOT)
    assert _codes(raised.value) == {"POLICY_CONTEXT_DIGEST_MISMATCH"}

    envelope = _load("valid/minimal.json")
    envelope["idempotency_key"] = "IDEMPOTENCY-ATLASBRIDGE-002"
    with pytest.raises(RuntimeEnvelopeValidationError) as raised:
        verify_runtime_envelope(envelope, key_resolver=_resolver, now=NOW, root=ROOT)
    assert _codes(raised.value) == {"SIGNED_DIGEST_MISMATCH"}
