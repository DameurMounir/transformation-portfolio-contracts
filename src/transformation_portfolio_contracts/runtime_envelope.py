"""Typed runtime-envelope models, digest binding, and reference HMAC verification.

The public contract is ``RuntimeEnvelope.v1.1``. JSON Schema remains normative;
the Pydantic models are strict reference models for Python consumers. The
reference signature profile signs a domain-separated SHA-256 digest of the
RFC 8785 projection that excludes only the top-level ``signature`` member.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, Self, cast

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from .canonical import JSONValue, digest_json, load_json
from .errors import Diagnostic, ResourceError, RuntimeEnvelopeValidationError
from .validation import discover_contract_root

RUNTIME_ENVELOPE_SCHEMA_PATH = "schemas/envelope/v1.1.json"
RUNTIME_ENVELOPE_SCHEMA_ID = (
    "https://raw.githubusercontent.com/DameurMounir/"
    "transformation-agent-contracts/v1.1.0/schemas/envelope/v1.1.json"
)
RUNTIME_ENVELOPE_SPEC_VERSION = "1.1.0"
RUNTIME_ENVELOPE_DIGEST_PROFILE = "TPC-JCS-SHA256-v1"
RUNTIME_ENVELOPE_SIGNATURE_PROFILE = "TPC-HMAC-SHA256-v1"
RUNTIME_ENVELOPE_SIGNATURE_ALGORITHM = "HMAC-SHA256"
_SIGNATURE_DOMAIN = b"TPC-RUNTIME-ENVELOPE-HMAC-SHA256-v1\x00"
_ZERO_TRACE_ID = "0" * 32
_ZERO_PARENT_ID = "0" * 16

KeyResolver = Callable[[str], bytes | None]


class _ReferenceModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)


class ActorReference(_ReferenceModel):
    actor_id: str
    actor_type: Literal["HUMAN", "SERVICE", "AGENT"]
    accountable_principal_id: str
    agent_id: str | None = None

    @model_validator(mode="after")
    def require_exact_agent_binding(self) -> Self:
        if self.actor_type == "AGENT" and self.agent_id is None:
            raise ValueError("agent_id is required for AGENT actors")
        if self.actor_type != "AGENT" and self.agent_id is not None:
            raise ValueError("agent_id is allowed only for AGENT actors")
        return self


class TenantReference(_ReferenceModel):
    tenant_id: str
    workspace_id: str
    environment: Literal["DEVELOPMENT", "TEST", "STAGING", "PRODUCTION"]


class CorrelationReference(_ReferenceModel):
    correlation_id: str
    causation_id: str | None = None
    traceparent: str = Field(pattern=r"^[0-9a-f]{2}-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$")

    @model_validator(mode="after")
    def reject_invalid_trace_identifiers(self) -> Self:
        version, trace_id, parent_id, _flags = self.traceparent.split("-")
        if version == "ff":
            raise ValueError("traceparent version ff is forbidden")
        if trace_id == _ZERO_TRACE_ID:
            raise ValueError("traceparent trace-id must not be all zeros")
        if parent_id == _ZERO_PARENT_ID:
            raise ValueError("traceparent parent-id must not be all zeros")
        return self


class ArtifactReference(_ReferenceModel):
    artifact_id: str
    schema_uri: str
    digest: str
    relationship: Literal["INPUT", "OUTPUT", "SUPERSEDES", "EVIDENCES"]


class EvidenceReference(_ReferenceModel):
    evidence_id: str
    kind: str
    digest: str
    uri: str | None = None


class SignatureMetadata(_ReferenceModel):
    profile: Literal["TPC-HMAC-SHA256-v1"]
    algorithm: Literal["HMAC-SHA256"]
    key_id: str
    signed_digest: str
    value: str
    signed_at: datetime


class RuntimeEnvelopeModel(_ReferenceModel):
    contract_schema: Literal[
        "https://raw.githubusercontent.com/DameurMounir/"
        "transformation-agent-contracts/v1.1.0/schemas/envelope/v1.1.json"
    ] = Field(alias="$schema")
    spec_version: Literal["1.1.0"]
    digest_profile: Literal["TPC-JCS-SHA256-v1"]
    envelope_id: str
    actor: ActorReference
    tenant: TenantReference
    correlation: CorrelationReference
    schema_uri: str
    artifact_references: tuple[ArtifactReference, ...]
    evidence_references: tuple[EvidenceReference, ...]
    policy_context: dict[str, Any]
    policy_context_digest: str
    payload: dict[str, Any]
    payload_digest: str
    issued_at: datetime
    expires_at: datetime
    idempotency_key: str
    signature: SignatureMetadata

    @model_validator(mode="after")
    def require_temporal_order(self) -> Self:
        for label, value in (
            ("issued_at", self.issued_at),
            ("expires_at", self.expires_at),
            ("signature.signed_at", self.signature.signed_at),
        ):
            if value.tzinfo is None or value.utcoffset() is None:
                raise ValueError(f"{label} must be timezone-aware")
            if value.utcoffset() != timezone.utc.utcoffset(value):
                raise ValueError(f"{label} must be UTC")
        if self.expires_at <= self.issued_at:
            raise ValueError("expires_at must be after issued_at")
        if not self.issued_at <= self.signature.signed_at <= self.expires_at:
            raise ValueError("signature.signed_at must fall within the envelope validity window")
        return self


@dataclass(frozen=True, slots=True)
class RuntimeEnvelopeResult:
    envelope_id: str
    envelope_digest: str
    payload_digest: str
    policy_context_digest: str
    key_id: str
    expires_at: str

    def as_dict(self) -> dict[str, str | bool]:
        return {
            "envelope_id": self.envelope_id,
            "envelope_digest": self.envelope_digest,
            "payload_digest": self.payload_digest,
            "policy_context_digest": self.policy_context_digest,
            "key_id": self.key_id,
            "expires_at": self.expires_at,
            "valid": True,
        }


def _error(
    code: str,
    message: str,
    path: str = "",
    *,
    context: Mapping[str, Any] | None = None,
) -> RuntimeEnvelopeValidationError:
    return RuntimeEnvelopeValidationError(
        message,
        diagnostics=(Diagnostic(code, message, path, context or {}),),
    )


def _format_utc(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")
    normalized = value.astimezone(timezone.utc).isoformat(timespec="seconds")
    return normalized.replace("+00:00", "Z")


def _schema_path(root: str | Path | None) -> Path:
    contract_root = discover_contract_root(root)
    path = contract_root / RUNTIME_ENVELOPE_SCHEMA_PATH
    if not path.is_file():
        raise ResourceError(f"runtime envelope schema is unavailable: {path}")
    return path


def validate_runtime_envelope_schema(
    envelope: Mapping[str, JSONValue],
    *,
    root: str | Path | None = None,
) -> None:
    """Validate the normative Draft 2020-12 schema without network access."""

    try:
        from jsonschema import Draft202012Validator, FormatChecker  # type: ignore[import-untyped]
        from jsonschema.exceptions import SchemaError  # type: ignore[import-untyped]
    except ImportError as exc:  # pragma: no cover - dependency installation error.
        raise ResourceError("jsonschema runtime dependency is missing") from exc

    raw_schema = load_json(_schema_path(root))
    if not isinstance(raw_schema, dict):
        raise ResourceError("runtime envelope schema must be a JSON object")
    try:
        Draft202012Validator.check_schema(raw_schema)
        validator = Draft202012Validator(raw_schema, format_checker=FormatChecker())
        errors = sorted(
            validator.iter_errors(dict(envelope)),
            key=lambda item: (tuple(str(part) for part in item.absolute_path), item.message),
        )
    except SchemaError as exc:
        raise ResourceError("runtime envelope schema is invalid") from exc
    if errors:
        diagnostics = tuple(
            Diagnostic(
                "SCHEMA_" + str(error.validator or "ERROR").upper(),
                error.message,
                "" if not error.absolute_path else "/" + "/".join(
                    str(part).replace("~", "~0").replace("/", "~1")
                    for part in error.absolute_path
                ),
            )
            for error in errors
        )
        raise RuntimeEnvelopeValidationError(
            "runtime envelope violates its normative schema", diagnostics=diagnostics
        )


def runtime_envelope_projection(
    envelope: Mapping[str, JSONValue],
) -> dict[str, JSONValue]:
    """Return the exact signing projection, excluding only ``signature``."""

    return {key: value for key, value in envelope.items() if key != "signature"}


def runtime_envelope_digest(envelope: Mapping[str, JSONValue]) -> str:
    """Return the RFC 8785/SHA-256 digest of the signing projection."""

    return digest_json(runtime_envelope_projection(envelope))


def hmac_signature_value(key: bytes, signed_digest: str) -> str:
    """Return the reference profile's domain-separated HMAC value."""

    if len(key) < 32:
        raise ValueError("reference HMAC keys must contain at least 32 bytes")
    try:
        digest_bytes = bytes.fromhex(signed_digest)
    except ValueError as exc:
        raise ValueError("signed_digest must be lowercase hexadecimal") from exc
    if len(digest_bytes) != hashlib.sha256().digest_size:
        raise ValueError("signed_digest must be a SHA-256 digest")
    return hmac.new(key, _SIGNATURE_DOMAIN + digest_bytes, hashlib.sha256).hexdigest()


def sign_runtime_envelope(
    envelope: Mapping[str, JSONValue],
    *,
    key_id: str,
    key: bytes,
    signed_at: datetime,
    root: str | Path | None = None,
) -> dict[str, JSONValue]:
    """Create a signed copy without mutating caller-owned input."""

    result = cast(dict[str, JSONValue], copy.deepcopy(dict(envelope)))
    result.pop("signature", None)
    payload = result.get("payload")
    policy_context = result.get("policy_context")
    if not isinstance(payload, dict):
        raise _error("PAYLOAD_REQUIRED", "payload must be a JSON object", "/payload")
    if not isinstance(policy_context, dict):
        raise _error(
            "POLICY_CONTEXT_REQUIRED",
            "policy_context must be a JSON object",
            "/policy_context",
        )
    result["payload_digest"] = digest_json(cast(JSONValue, payload))
    result["policy_context_digest"] = digest_json(cast(JSONValue, policy_context))
    signed_digest = runtime_envelope_digest(result)
    result["signature"] = {
        "profile": RUNTIME_ENVELOPE_SIGNATURE_PROFILE,
        "algorithm": RUNTIME_ENVELOPE_SIGNATURE_ALGORITHM,
        "key_id": key_id,
        "signed_digest": signed_digest,
        "value": hmac_signature_value(key, signed_digest),
        "signed_at": _format_utc(signed_at),
    }
    validate_runtime_envelope_schema(result, root=root)
    try:
        RuntimeEnvelopeModel.model_validate(result)
    except ValidationError as exc:
        raise _error(
            "REFERENCE_MODEL_INVALID",
            "runtime envelope failed the Python reference model",
            context={"errors": exc.error_count()},
        ) from exc
    return result


def verify_runtime_envelope(
    envelope: Mapping[str, JSONValue],
    *,
    key_resolver: KeyResolver,
    now: datetime | None = None,
    root: str | Path | None = None,
) -> RuntimeEnvelopeResult:
    """Verify schema, reference model, digests, expiry, key resolution, and HMAC."""

    validate_runtime_envelope_schema(envelope, root=root)
    try:
        model = RuntimeEnvelopeModel.model_validate(dict(envelope))
    except ValidationError as exc:
        raise _error(
            "REFERENCE_MODEL_INVALID",
            "runtime envelope failed the Python reference model",
            context={"errors": exc.error_count()},
        ) from exc

    payload_actual = digest_json(cast(JSONValue, model.payload))
    if not hmac.compare_digest(model.payload_digest, payload_actual):
        raise _error(
            "PAYLOAD_DIGEST_MISMATCH",
            "payload_digest does not match payload",
            "/payload_digest",
        )
    policy_actual = digest_json(cast(JSONValue, model.policy_context))
    if not hmac.compare_digest(model.policy_context_digest, policy_actual):
        raise _error(
            "POLICY_CONTEXT_DIGEST_MISMATCH",
            "policy_context_digest does not match policy_context",
            "/policy_context_digest",
        )

    envelope_actual = runtime_envelope_digest(envelope)
    if not hmac.compare_digest(model.signature.signed_digest, envelope_actual):
        raise _error(
            "SIGNED_DIGEST_MISMATCH",
            "signature.signed_digest does not match the envelope projection",
            "/signature/signed_digest",
        )

    evaluated_at = now or datetime.now(timezone.utc)
    if evaluated_at.tzinfo is None or evaluated_at.utcoffset() is None:
        raise ValueError("now must be timezone-aware")
    evaluated_at = evaluated_at.astimezone(timezone.utc)
    if evaluated_at < model.issued_at:
        raise _error("ENVELOPE_NOT_YET_VALID", "envelope has not reached issued_at", "/issued_at")
    if evaluated_at > model.expires_at:
        raise _error("ENVELOPE_EXPIRED", "envelope has passed expires_at", "/expires_at")

    try:
        key = key_resolver(model.signature.key_id)
    except Exception as exc:
        raise _error(
            "SIGNING_KEY_UNAVAILABLE",
            "signing key resolution failed closed",
            "/signature/key_id",
        ) from exc
    if key is None:
        raise _error(
            "SIGNING_KEY_UNAVAILABLE",
            "no verification key is registered for signature.key_id",
            "/signature/key_id",
        )
    expected_signature = hmac_signature_value(key, model.signature.signed_digest)
    if not hmac.compare_digest(model.signature.value, expected_signature):
        raise _error(
            "SIGNATURE_MISMATCH",
            "signature value is not valid for the registered key",
            "/signature/value",
        )

    return RuntimeEnvelopeResult(
        envelope_id=model.envelope_id,
        envelope_digest=envelope_actual,
        payload_digest=payload_actual,
        policy_context_digest=policy_actual,
        key_id=model.signature.key_id,
        expires_at=_format_utc(model.expires_at),
    )
