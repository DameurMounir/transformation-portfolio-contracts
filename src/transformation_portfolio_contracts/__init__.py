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
    "EventChainResult",
    "LineageResult",
    "ValidationResult",
    "__version__",
    "artifact_digest",
    "calculate_chain_sha256",
    "canonicalize",
    "decision_subject_digest",
    "decision_subject_projection",
    "digest_json",
    "event_digest",
    "payload_digest",
    "validate_document",
    "verify_agent_event",
    "verify_agent_event_chain",
    "verify_artifact_integrity",
    "verify_lineage",
]
