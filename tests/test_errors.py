from __future__ import annotations

from transformation_portfolio_contracts.errors import (
    ArtifactValidationError,
    CanonicalizationError,
    ConformanceError,
    ContractError,
    Diagnostic,
    JSONInputError,
    LineageValidationError,
    ResourceError,
    SchemaResolutionError,
    SchemaValidationError,
)


def test_diagnostic_serialization_is_stable() -> None:
    diagnostic = Diagnostic(
        code="WRONG_TRANSFORMATION",
        message="transformation differs",
        path="/inputs/0/transformation_id",
        context={"observed": "B", "expected": "A"},
    )
    assert diagnostic.as_dict() == {
        "code": "WRONG_TRANSFORMATION",
        "message": "transformation differs",
        "path": "/inputs/0/transformation_id",
        "context": {"expected": "A", "observed": "B"},
    }
    assert Diagnostic(code="X", message="x").as_dict() == {
        "code": "X",
        "message": "x",
        "path": "",
    }


def test_error_types_have_frozen_machine_contracts() -> None:
    cases = [
        (ContractError, "CONTRACT_ERROR", 4),
        (ResourceError, "RESOURCE_ERROR", 3),
        (JSONInputError, "JSON_INPUT_ERROR", 3),
        (CanonicalizationError, "CANONICALIZATION_ERROR", 4),
        (SchemaResolutionError, "SCHEMA_RESOLUTION_ERROR", 4),
        (SchemaValidationError, "SCHEMA_VALIDATION_ERROR", 4),
        (ArtifactValidationError, "ARTIFACT_VALIDATION_ERROR", 4),
        (LineageValidationError, "LINEAGE_VALIDATION_ERROR", 5),
        (ConformanceError, "CONFORMANCE_ERROR", 6),
    ]
    diagnostic = Diagnostic(code="DETAIL", message="detail")
    for error_type, error_code, exit_code in cases:
        error = error_type("stopped", diagnostics=[diagnostic])
        assert str(error) == "stopped"
        assert error.error_code == error_code
        assert error.exit_code == exit_code
        assert error.as_dict() == {
            "error": error_code,
            "message": "stopped",
            "diagnostics": [{"code": "DETAIL", "message": "detail", "path": ""}],
        }
