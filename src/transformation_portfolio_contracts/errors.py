"""Typed, machine-readable failures raised by the contract implementation."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class Diagnostic:
    """One deterministic validation diagnostic.

    ``path`` uses JSON Pointer syntax.  Context values are intended for machine
    consumers and must therefore be JSON-serialisable.
    """

    code: str
    message: str
    path: str = ""
    context: Mapping[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "code": self.code,
            "message": self.message,
            "path": self.path,
        }
        if self.context:
            result["context"] = dict(sorted(self.context.items()))
        return result


class ContractError(Exception):
    """Base class for an expected, fail-closed contract error."""

    error_code = "CONTRACT_ERROR"
    exit_code = 4

    def __init__(
        self,
        message: str,
        *,
        diagnostics: Sequence[Diagnostic] = (),
    ) -> None:
        super().__init__(message)
        self.message = message
        self.diagnostics = tuple(diagnostics)

    def as_dict(self) -> dict[str, Any]:
        return {
            "error": self.error_code,
            "message": self.message,
            "diagnostics": [item.as_dict() for item in self.diagnostics],
        }


class ResourceError(ContractError):
    """A required file or installed resource could not be resolved."""

    error_code = "RESOURCE_ERROR"
    exit_code = 3


class JSONInputError(ContractError):
    """Input is not strict JSON or is not readable."""

    error_code = "JSON_INPUT_ERROR"
    exit_code = 3


class CanonicalizationError(ContractError):
    """A value cannot be represented by the portfolio JCS profile."""

    error_code = "CANONICALIZATION_ERROR"
    exit_code = 4


class SchemaResolutionError(ContractError):
    """No unique contract schema could be resolved."""

    error_code = "SCHEMA_RESOLUTION_ERROR"
    exit_code = 4


class SchemaValidationError(ContractError):
    """A JSON document does not conform to its Draft 2020-12 schema."""

    error_code = "SCHEMA_VALIDATION_ERROR"
    exit_code = 4


class ArtifactValidationError(ContractError):
    """An artifact is schema-valid but fails a semantic integrity rule."""

    error_code = "ARTIFACT_VALIDATION_ERROR"
    exit_code = 4


class RuntimeEnvelopeValidationError(ContractError):
    """A runtime envelope fails schema, digest, time, key, or signature verification."""

    error_code = "RUNTIME_ENVELOPE_VALIDATION_ERROR"
    exit_code = 4


class LineageValidationError(ContractError):
    """A set of artifacts does not form a trustworthy lineage graph."""

    error_code = "LINEAGE_VALIDATION_ERROR"
    exit_code = 5


class EventValidationError(ContractError):
    """An audit event or append-only event chain is not trustworthy."""

    error_code = "EVENT_VALIDATION_ERROR"
    exit_code = 5


class ConformanceError(ContractError):
    """A conformance suite or worked example did not meet expectations."""

    error_code = "CONFORMANCE_ERROR"
    exit_code = 6
