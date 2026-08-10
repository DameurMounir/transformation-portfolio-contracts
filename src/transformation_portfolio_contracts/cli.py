"""Provider-neutral ``portfolio-contracts`` command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping, Sequence
from enum import IntEnum
from pathlib import Path
from typing import Any, cast

from . import __version__
from .canonical import JSONValue, artifact_digest, digest_json, load_json, payload_digest
from .errors import ConformanceError, ContractError, Diagnostic, ResourceError
from .events import EventChainResult, verify_agent_event_chain
from .lineage import LineageResult, collect_artifact_files, verify_lineage, verify_lineage_files
from .validation import (
    ContractCatalog,
    ValidationResult,
    discover_contract_root,
    validate_document,
    validate_file,
)


class ExitCode(IntEnum):
    """Stable process exit codes for automation consumers."""

    SUCCESS = 0
    USAGE = 2
    INPUT_OR_RESOURCE = 3
    VALIDATION = 4
    LINEAGE = 5
    CONFORMANCE = 6
    INTERNAL = 70


def _add_common_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--root",
        type=Path,
        help="contract resource root (otherwise auto-detected or TPC_CONTRACT_ROOT)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="emit deterministic machine-readable JSON",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="portfolio-contracts",
        description="Validate transformation portfolio artifacts and immutable lineage.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    validate = commands.add_parser("validate", help="validate schema and artifact digests")
    validate.add_argument("paths", nargs="*", type=Path, metavar="PATH")
    validate.add_argument(
        "--artifact",
        action="append",
        nargs="+",
        type=Path,
        default=[],
        metavar="PATH",
        help="artifact path; repeat the option or provide multiple values",
    )
    validate.add_argument(
        "--contract",
        help="catalog name, artifact type, schema ID, or root-relative schema path",
    )
    validate.add_argument(
        "--schema-only",
        action="store_true",
        help="skip digest verification (intended only for schema authoring)",
    )
    _add_common_options(validate)

    digest = commands.add_parser("digest", help="calculate a JCS SHA-256 digest")
    digest.add_argument("path", type=Path, metavar="PATH")
    digest.add_argument("--payload", action="store_true", help="digest only the payload")
    digest.add_argument(
        "--verify",
        action="store_true",
        help="verify stored artifact and payload digests before printing",
    )
    _add_common_options(digest)

    lineage = commands.add_parser("verify-lineage", help="verify a complete artifact graph")
    lineage.add_argument("paths", nargs="+", type=Path, metavar="PATH")
    _add_common_options(lineage)

    events = commands.add_parser("verify-events", help="verify an ordered AgentEvent chain")
    events.add_argument("paths", nargs="+", type=Path, metavar="PATH")
    _add_common_options(events)

    catalog = commands.add_parser("catalog", help="verify and display the contract catalog")
    catalog.add_argument("--contract", help="filter by name or artifact_type")
    _add_common_options(catalog)

    conformance = commands.add_parser(
        "verify-conformance", help="execute valid and invalid conformance fixtures"
    )
    conformance.add_argument(
        "--path",
        type=Path,
        help="suite directory (defaults to <root>/conformance)",
    )
    _add_common_options(conformance)

    example = commands.add_parser(
        "verify-example", help="verify the complete AtlasBridge worked example"
    )
    example.add_argument("paths", nargs="*", type=Path, metavar="PATH")
    _add_common_options(example)
    return parser


def _print_json(value: Any, *, stream: Any = None) -> None:
    print(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True),
        file=stream if stream is not None else sys.stdout,
    )


def _validation_paths(arguments: argparse.Namespace) -> tuple[Path, ...]:
    option_paths = [path for group in arguments.artifact for path in group]
    paths = tuple(arguments.paths) + tuple(option_paths)
    if not paths:
        raise ResourceError("validate requires PATH or --artifact PATH")
    return paths


def _run_validate(arguments: argparse.Namespace) -> dict[str, Any]:
    paths = _validation_paths(arguments)
    results: list[dict[str, Any]] = []
    for path in paths:
        result: ValidationResult = validate_file(
            path,
            contract=arguments.contract,
            root=arguments.root,
            verify_integrity=not arguments.schema_only,
        )
        item = result.as_dict()
        item["path"] = str(path)
        results.append(item)
    return {"count": len(results), "documents": results, "valid": True}


def _run_digest(arguments: argparse.Namespace) -> tuple[dict[str, Any], str]:
    raw = load_json(arguments.path)
    if arguments.verify:
        if not isinstance(raw, dict) or not isinstance(raw.get("artifact_id"), str):
            raise ResourceError("--verify requires an artifact object")
        # Schema and all semantic digest checks are intentionally included.
        validate_file(arguments.path, root=arguments.root, verify_integrity=True)
    if arguments.payload:
        if not isinstance(raw, dict) or "payload" not in raw:
            raise ResourceError("--payload requires an object containing payload")
        result = payload_digest(cast(Mapping[str, JSONValue], raw))
        projection = "payload"
    elif isinstance(raw, dict) and isinstance(raw.get("artifact_id"), str):
        result = artifact_digest(cast(Mapping[str, JSONValue], raw))
        projection = "artifact"
    else:
        result = digest_json(raw)
        projection = "document"
    return (
        {
            "path": str(arguments.path),
            "profile": "TPC-JCS-SHA256-v1",
            "projection": projection,
            "sha256": result,
            "verified": bool(arguments.verify),
        },
        result,
    )


def _run_lineage(arguments: argparse.Namespace) -> dict[str, Any]:
    result: LineageResult = verify_lineage_files(arguments.paths, root=arguments.root)
    return result.as_dict()


def _run_events(arguments: argparse.Namespace) -> dict[str, Any]:
    files = collect_artifact_files(arguments.paths)
    events: list[Mapping[str, JSONValue]] = []
    for path in files:
        raw = load_json(path)
        embedded: object = raw.get("events") if isinstance(raw, dict) else raw
        if isinstance(embedded, list):
            if not embedded or not all(isinstance(item, dict) for item in embedded):
                raise ResourceError(f"AgentEvent scenario must contain event objects: {path}")
            events.extend(cast(list[Mapping[str, JSONValue]], embedded))
        elif isinstance(raw, dict) and isinstance(raw.get("event_id"), str):
            events.append(cast(Mapping[str, JSONValue], raw))
        elif path in {Path(item).expanduser().resolve() for item in arguments.paths}:
            raise ResourceError(f"verify-events input is not an AgentEvent: {path}")
    result: EventChainResult = verify_agent_event_chain(events, root=arguments.root)
    return result.as_dict()


def _run_catalog(arguments: argparse.Namespace) -> dict[str, Any]:
    catalog = ContractCatalog(arguments.root)
    # Check every schema, not just one reached by a fixture.
    try:
        from jsonschema import Draft202012Validator  # type: ignore[import-untyped]
        from jsonschema.exceptions import SchemaError  # type: ignore[import-untyped]
    except ImportError as exc:  # pragma: no cover - installation error.
        raise ResourceError("jsonschema runtime dependency is missing") from exc
    for record in catalog.schemas:
        try:
            Draft202012Validator.check_schema(dict(record.document))
        except SchemaError as exc:
            raise ResourceError(f"invalid registered schema: {record.relative_path}") from exc

    registry_counts = catalog.verify_registry_reconciliation()
    entries = list(catalog.catalog_entries(verify=True))
    if arguments.contract:
        entries = [
            entry
            for entry in entries
            if arguments.contract in {entry.get("name"), entry.get("artifact_type")}
        ]
        if not entries:
            raise ResourceError(f"contract is not in the catalog: {arguments.contract}")
    return {
        "contract_count": len(entries),
        "contracts": entries,
        **registry_counts,
        "root": str(catalog.root),
        "schema_count": len(catalog.schemas),
        "valid": True,
    }


def _load_conformance_manifest(
    expected_root: Path,
    valid_files: Sequence[Path],
    invalid_files: Sequence[Path],
) -> dict[str, tuple[str, ...]]:
    """Load the single authoritative, exact fixture-verdict manifest."""

    manifests = tuple(sorted(expected_root.rglob("*.json"))) if expected_root.is_dir() else ()
    if len(manifests) != 1:
        raise ConformanceError(
            "conformance expected-results must contain exactly one JSON manifest"
        )
    raw = load_json(manifests[0])
    if not isinstance(raw, dict):
        raise ConformanceError("conformance expected-results manifest must be an object")
    valid_entries = raw.get("valid_fixtures")
    invalid_entries = raw.get("cases")
    if not isinstance(valid_entries, list) or not isinstance(invalid_entries, list):
        raise ConformanceError("expected-results requires valid_fixtures[] and cases[] partitions")

    actual_valid = [path.name for path in valid_files]
    actual_invalid = [path.name for path in invalid_files]
    if len(actual_valid) != len(set(actual_valid)) or len(actual_invalid) != len(
        set(actual_invalid)
    ):
        raise ConformanceError("conformance fixture basenames must be unique per partition")
    if set(actual_valid) & set(actual_invalid):
        raise ConformanceError("valid and invalid fixtures must not share a basename")

    declared_valid: list[str] = []
    for index, item in enumerate(valid_entries):
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("fixture"), str)
            or item.get("expected") != "VALID"
        ):
            raise ConformanceError(f"invalid valid_fixtures manifest entry at index {index}")
        declared_valid.append(Path(cast(str, item["fixture"])).name)

    expected_codes: dict[str, tuple[str, ...]] = {}
    declared_invalid: list[str] = []
    for index, item in enumerate(invalid_entries):
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("fixture"), str)
            or item.get("expected") != "INVALID"
        ):
            raise ConformanceError(f"invalid cases manifest entry at index {index}")
        fixture = Path(cast(str, item["fixture"])).name
        raw_codes = item.get("expected_error")
        codes: tuple[str, ...]
        if isinstance(raw_codes, str) and raw_codes:
            codes = (raw_codes,)
        elif (
            isinstance(raw_codes, list)
            and raw_codes
            and all(isinstance(code, str) and code for code in raw_codes)
        ):
            codes = tuple(sorted(set(cast(list[str], raw_codes))))
        else:
            raise ConformanceError(
                f"invalid fixture {fixture} must declare nonempty expected_error code(s)"
            )
        declared_invalid.append(fixture)
        if fixture in expected_codes:
            raise ConformanceError(f"duplicate invalid manifest verdict for {fixture}")
        expected_codes[fixture] = codes

    if len(declared_valid) != len(set(declared_valid)):
        raise ConformanceError("duplicate valid fixture manifest verdict")
    if set(declared_valid) & set(declared_invalid):
        raise ConformanceError("a fixture cannot have both VALID and INVALID verdicts")
    if set(declared_valid) != set(actual_valid) or set(declared_invalid) != set(actual_invalid):
        raise ConformanceError(
            "manifest fixture partitions must exactly equal files on disk",
            diagnostics=(
                Diagnostic(
                    "CONFORMANCE_MANIFEST_PARTITION_MISMATCH",
                    "missing or orphan fixture verdict",
                    context={
                        "invalid_missing": sorted(set(actual_invalid) - set(declared_invalid)),
                        "invalid_orphan": sorted(set(declared_invalid) - set(actual_invalid)),
                        "valid_missing": sorted(set(actual_valid) - set(declared_valid)),
                        "valid_orphan": sorted(set(declared_valid) - set(actual_valid)),
                    },
                ),
            ),
        )
    return expected_codes


def _validate_fixture(path: Path, root: Path) -> None:
    raw = load_json(path)
    event_values = raw.get("events") if isinstance(raw, dict) else None
    if isinstance(event_values, list):
        if not event_values or not all(isinstance(item, dict) for item in event_values):
            raise ConformanceError(
                f"embedded conformance case must contain AgentEvent objects: {path}"
            )
        verify_agent_event_chain(cast(list[Mapping[str, JSONValue]], event_values), root=root)
        return
    embedded: object = raw.get("artifacts") if isinstance(raw, dict) else raw
    if isinstance(embedded, list):
        if not embedded or not all(isinstance(item, dict) for item in embedded):
            raise ConformanceError(
                f"embedded conformance case must contain artifact objects: {path}"
            )
        artifacts = [cast(Mapping[str, JSONValue], item) for item in embedded]
        for artifact in artifacts:
            validate_document(artifact, root=root, verify_integrity=True)
        verify_lineage(artifacts, root=root, sources=[str(path)] * len(artifacts))
        return
    validate_file(path, root=root, verify_integrity=True)


def _fixture_error(path: Path, root: Path) -> ContractError | None:
    try:
        _validate_fixture(path, root)
        raw = load_json(path)
        if isinstance(raw, dict) and isinstance(raw.get("artifact_id"), str):
            verify_lineage([cast(Mapping[str, JSONValue], raw)], root=root, sources=[str(path)])
    except ContractError as exc:
        return exc
    return None


def _run_conformance(arguments: argparse.Namespace) -> dict[str, Any]:
    root = discover_contract_root(arguments.root)
    suite = arguments.path.resolve() if arguments.path else root / "conformance"
    valid_root = suite / "valid"
    invalid_root = suite / "invalid"
    if not valid_root.is_dir() or not invalid_root.is_dir():
        raise ConformanceError(f"suite must contain valid/ and invalid/: {suite}")
    valid_files = tuple(sorted(valid_root.rglob("*.json")))
    invalid_files = tuple(sorted(invalid_root.rglob("*.json")))
    if not valid_files or not invalid_files:
        raise ConformanceError("conformance suite requires both valid and invalid fixtures")

    expected_codes = _load_conformance_manifest(
        suite / "expected-results", valid_files, invalid_files
    )
    failures: list[Diagnostic] = []
    results: list[dict[str, Any]] = []
    for path in valid_files:
        try:
            _validate_fixture(path, root)
        except ContractError as exc:
            failures.append(Diagnostic("VALID_FIXTURE_REJECTED", exc.message, str(path)))
            results.append({"actual": "INVALID", "expected": "VALID", "path": str(path)})
        else:
            results.append({"actual": "VALID", "expected": "VALID", "path": str(path)})

    for path in invalid_files:
        error = _fixture_error(path, root)
        if error is None:
            failures.append(
                Diagnostic("INVALID_FIXTURE_ACCEPTED", "invalid fixture passed", str(path))
            )
            results.append({"actual": "VALID", "expected": "INVALID", "path": str(path)})
            continue
        actual_codes = {error.error_code, *(item.code for item in error.diagnostics)}
        expected = expected_codes[path.name]
        missing_codes = sorted(set(expected) - actual_codes)
        if missing_codes:
            failures.append(
                Diagnostic(
                    "EXPECTED_ERROR_MISMATCH",
                    f"expected {list(expected)}, observed {sorted(actual_codes)}",
                    str(path),
                    {"missing_expected_codes": missing_codes},
                )
            )
        results.append(
            {
                "actual": "INVALID",
                "error_codes": sorted(actual_codes),
                "expected": "INVALID",
                "path": str(path),
            }
        )
    if failures:
        raise ConformanceError("conformance suite failed", diagnostics=tuple(failures))
    return {
        "invalid_fixture_count": len(invalid_files),
        "results": results,
        "suite": str(suite),
        "valid": True,
        "valid_fixture_count": len(valid_files),
    }


def _run_example(arguments: argparse.Namespace) -> dict[str, Any]:
    root = discover_contract_root(arguments.root)
    requested = tuple(arguments.paths) or (root / "examples" / "atlasbridge-end-to-end",)
    files = collect_artifact_files(requested)
    artifacts: list[Mapping[str, JSONValue]] = []
    sources: list[str] = []
    for path in files:
        raw = load_json(path)
        if isinstance(raw, dict) and isinstance(raw.get("artifact_id"), str):
            artifacts.append(cast(Mapping[str, JSONValue], raw))
            sources.append(str(path))
        elif isinstance(raw, dict) and isinstance(raw.get("$schema"), str):
            # Validate contract-addressed ancillary documents, while identity
            # maps and manifests without a contract remain informational.
            validate_file(path, root=root, verify_integrity=False)
    expected_types = {
        "RequirementsAssessment",
        "StakeholderAlignmentPacket",
        "ProcessRedesignDecision",
        "ChangeImpactPacket",
        "GoLiveEvidenceBundle",
        "GoLiveDecisionPacket",
    }
    actual_types = {
        cast(str, artifact.get("artifact_type"))
        for artifact in artifacts
        if isinstance(artifact.get("artifact_type"), str)
    }
    if actual_types != expected_types or len(artifacts) != 6:
        raise ConformanceError(
            "worked example must contain exactly one artifact of every portfolio type",
            diagnostics=(
                Diagnostic(
                    "INCOMPLETE_EXAMPLE",
                    "missing, duplicate, or unexpected stage artifact",
                    context={
                        "actual": sorted(actual_types),
                        "expected": sorted(expected_types),
                        "artifact_count": len(artifacts),
                    },
                ),
            ),
        )
    result = verify_lineage(artifacts, root=root, sources=sources)
    response = result.as_dict()
    response["example_paths"] = [str(path) for path in requested]
    return response


def _dispatch(arguments: argparse.Namespace) -> tuple[dict[str, Any], str | None]:
    if arguments.command == "validate":
        return _run_validate(arguments), None
    if arguments.command == "digest":
        return _run_digest(arguments)
    if arguments.command == "verify-lineage":
        return _run_lineage(arguments), None
    if arguments.command == "verify-events":
        return _run_events(arguments), None
    if arguments.command == "catalog":
        return _run_catalog(arguments), None
    if arguments.command == "verify-conformance":
        return _run_conformance(arguments), None
    if arguments.command == "verify-example":
        return _run_example(arguments), None
    raise AssertionError(f"unhandled command: {arguments.command}")


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return a stable process exit code."""

    parser = build_parser()
    arguments = parser.parse_args(argv)
    try:
        result, plain = _dispatch(arguments)
    except ContractError as exc:
        if getattr(arguments, "json_output", False):
            _print_json(exc.as_dict(), stream=sys.stderr)
        else:
            print(f"ERROR [{exc.error_code}]: {exc.message}", file=sys.stderr)
            for diagnostic in exc.diagnostics:
                location = f" at {diagnostic.path}" if diagnostic.path else ""
                print(
                    f"  - {diagnostic.code}{location}: {diagnostic.message}",
                    file=sys.stderr,
                )
        return exc.exit_code
    except Exception as exc:  # Last-resort fail-closed boundary for console use.
        payload = {"error": "INTERNAL_ERROR", "message": str(exc)}
        if getattr(arguments, "json_output", False):
            _print_json(payload, stream=sys.stderr)
        else:
            print(f"ERROR [INTERNAL_ERROR]: {exc}", file=sys.stderr)
        return int(ExitCode.INTERNAL)

    if getattr(arguments, "json_output", False):
        _print_json(result)
    elif plain is not None:
        print(plain)
    else:
        print("VALID")
        if "portfolio_chain_sha256" in result:
            print(f"portfolio_chain_sha256={result['portfolio_chain_sha256']}")
        elif "contract_count" in result:
            print(f"contracts={result['contract_count']} schemas={result['schema_count']}")
        elif "valid_fixture_count" in result:
            print(
                f"valid={result['valid_fixture_count']} invalid={result['invalid_fixture_count']}"
            )
        elif "count" in result:
            print(f"documents={result['count']}")
    return int(ExitCode.SUCCESS)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
