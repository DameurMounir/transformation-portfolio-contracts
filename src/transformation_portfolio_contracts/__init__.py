"""Governed interoperability contracts for the transformation portfolio."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

from .canonical import (
    DIGEST_PROFILE,
    artifact_digest,
    canonicalize,
    digest_json,
    payload_digest,
)
from .events import (
    EventChainResult,
    event_digest,
    verify_agent_event,
    verify_agent_event_chain,
)
from .lineage import LineageResult, calculate_chain_sha256, verify_lineage
from .runtime_envelope import (
    ActorReference,
    ArtifactReference,
    CorrelationReference,
    EvidenceReference,
    RuntimeEnvelopeModel,
    RuntimeEnvelopeResult,
    SignatureMetadata,
    TenantReference,
    hmac_signature_value,
    runtime_envelope_digest,
    runtime_envelope_projection,
    sign_runtime_envelope,
    validate_runtime_envelope_schema,
    verify_runtime_envelope,
)
from .validation import (
    ValidationResult,
    decision_subject_digest,
    decision_subject_projection,
    validate_document,
    verify_artifact_integrity,
)

try:
    __version__ = version("transformation-portfolio-contracts")
except PackageNotFoundError:  # Source checkout before editable installation.
    __version__ = "1.0.0"

__all__ = [
    "DIGEST_PROFILE",
    "ActorReference",
    "ArtifactReference",
    "CorrelationReference",
    "EventChainResult",
    "EvidenceReference",
    "LineageResult",
    "RuntimeEnvelopeModel",
    "RuntimeEnvelopeResult",
    "SignatureMetadata",
    "TenantReference",
    "ValidationResult",
    "__version__",
    "artifact_digest",
    "calculate_chain_sha256",
    "canonicalize",
    "decision_subject_digest",
    "decision_subject_projection",
    "digest_json",
    "event_digest",
    "hmac_signature_value",
    "payload_digest",
    "runtime_envelope_digest",
    "runtime_envelope_projection",
    "sign_runtime_envelope",
    "validate_document",
    "validate_runtime_envelope_schema",
    "verify_agent_event",
    "verify_agent_event_chain",
    "verify_artifact_integrity",
    "verify_lineage",
    "verify_runtime_envelope",
]
