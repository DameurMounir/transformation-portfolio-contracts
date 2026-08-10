"""Draft 2020-12 schema resolution and fail-closed artifact validation."""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import sys
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, cast
from urllib.parse import unquote, urlparse

from .canonical import (
    DIGEST_PROFILE,
    JSONValue,
    artifact_digest,
    digest_json,
    is_sha256,
    load_json,
    payload_digest,
    sha256_bytes,
)
from .errors import (
    ArtifactValidationError,
    Diagnostic,
    EventValidationError,
    ResourceError,
    SchemaResolutionError,
    SchemaValidationError,
)

DRAFT_2020_12 = "https://json-schema.org/draft/2020-12/schema"
_SEMVER = re.compile(
    r"^(?P<major>0|[1-9][0-9]*)\.(?P<minor>0|[1-9][0-9]*)\.(?P<patch>0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
_REPOSITORY = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$")
_STAGE_ID = re.compile(r"^[A-Z][A-Z0-9_]{2,127}$")
SUPPORTED_CONTRACT_MAJORS = frozenset({1})
GATE_NAMES = {
    "G-01": "RELEASE_IDENTITY_AND_SCOPE",
    "G-02": "BUSINESS_ACCEPTANCE",
    "G-03": "FUNCTIONAL_ACCEPTANCE",
    "G-04": "SECURITY_VERIFICATION",
    "G-05": "PRIVACY_AND_DATA_PROTECTION",
    "G-06": "DATA_MIGRATION",
    "G-07": "PERFORMANCE_AND_CAPACITY",
    "G-08": "RELIABILITY_AND_RECOVERY",
    "G-09": "OBSERVABILITY_AND_INCIDENT_RESPONSE",
    "G-10": "SUPPORT_READINESS",
    "G-11": "TRAINING_AND_COMMUNICATIONS",
    "G-12": "ROLLBACK_AND_ROLLFORWARD",
    "G-13": "EXTERNAL_DEPENDENCIES",
    "G-14": "RELEASE_AUTHORITY_AND_WINDOW",
}


def _same_digest(left: object, right: object) -> bool:
    return (
        is_sha256(left)
        and is_sha256(right)
        and hmac.compare_digest(cast(str, left), cast(str, right))
    )


@dataclass(frozen=True, slots=True)
class SchemaRecord:
    """A parsed schema and its stable local and public identities."""

    path: Path
    relative_path: str
    document: Mapping[str, JSONValue]
    schema_id: str | None
    artifact_type: str | None

    @property
    def canonical_sha256(self) -> str:
        return digest_json(dict(self.document))


@dataclass(frozen=True, slots=True)
class ValidationResult:
    """Successful validation metadata suitable for CLI JSON output."""

    schema_path: str
    artifact_id: str | None
    artifact_sha256: str | None
    payload_sha256: str | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "artifact_sha256": self.artifact_sha256,
            "payload_sha256": self.payload_sha256,
            "schema_path": self.schema_path,
            "valid": True,
        }


def _has_contract_resources(candidate: Path) -> bool:
    return (candidate / "schemas").is_dir() and (candidate / "registry").is_dir()


def discover_contract_root(root: str | Path | None = None) -> Path:
    """Resolve root resources in a checkout, wheel, or explicit installation.

    Resolution is deterministic and never downloads a schema.  ``--root`` (or
    ``TPC_CONTRACT_ROOT``) is therefore the provider-neutral escape hatch for
    non-standard package managers.
    """

    if root is not None:
        explicit = Path(root).expanduser().resolve()
        if not _has_contract_resources(explicit):
            raise ResourceError(f"contract root must contain schemas/ and registry/: {explicit}")
        return explicit

    environment = os.environ.get("TPC_CONTRACT_ROOT")
    if environment:
        return discover_contract_root(environment)

    # The active interpreter's installed resources have precedence over source
    # trees.  In particular, never consult ``base_prefix``: doing so could mix
    # schemas from a different installation into a virtual environment.
    candidates: list[Path] = [
        Path(sys.prefix) / "share" / "transformation-portfolio-contracts",
        Path(__file__).resolve().parent / "resources",
    ]
    module_path = Path(__file__).resolve().parent
    candidates.extend(
        ancestor
        for ancestor in module_path.parents
        if (ancestor / "src" / "transformation_portfolio_contracts").resolve() == module_path
    )

    seen: set[Path] = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        if _has_contract_resources(candidate):
            return candidate
    raise ResourceError("cannot locate contract resources; pass --root or set TPC_CONTRACT_ROOT")


def _artifact_type_from_schema(schema: Mapping[str, JSONValue]) -> str | None:
    """Find a unique artifact_type const, including one nested below allOf."""

    found: set[str] = set()

    def walk(value: JSONValue) -> None:
        if isinstance(value, dict):
            properties = value.get("properties")
            if isinstance(properties, dict):
                artifact_property = properties.get("artifact_type")
                if isinstance(artifact_property, dict):
                    constant = artifact_property.get("const")
                    if isinstance(constant, str):
                        found.add(constant)
            for nested in value.values():
                walk(nested)
        elif isinstance(value, list):
            for nested in value:
                walk(nested)

    walk(cast(JSONValue, dict(schema)))
    return next(iter(found)) if len(found) == 1 else None


def _pointer(parts: Iterable[object]) -> str:
    encoded = [str(part).replace("~", "~0").replace("/", "~1") for part in parts]
    return "" if not encoded else "/" + "/".join(encoded)


def _parse_timestamp(value: object, *, path: str) -> datetime:
    if not isinstance(value, str):
        raise ArtifactValidationError(
            "artifact timestamp is not a string",
            diagnostics=(Diagnostic("INVALID_TIMESTAMP", "expected RFC 3339 string", path),),
        )
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ArtifactValidationError(
            "artifact timestamp is invalid",
            diagnostics=(Diagnostic("INVALID_TIMESTAMP", "expected RFC 3339 date-time", path),),
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ArtifactValidationError(
            "artifact timestamp has no UTC offset",
            diagnostics=(
                Diagnostic("TIMEZONE_REQUIRED", "RFC 3339 timestamp must include an offset", path),
            ),
        )
    return parsed


def contract_major(value: object, *, path: str = "/spec_version") -> int:
    """Parse a SemVer contract version and reject unsupported major versions."""

    if not isinstance(value, str) or (match := _SEMVER.fullmatch(value)) is None:
        raise ArtifactValidationError(
            "contract version is not valid SemVer",
            diagnostics=(Diagnostic("INVALID_CONTRACT_VERSION", "expected SemVer", path),),
        )
    major = int(match.group("major"))
    if major not in SUPPORTED_CONTRACT_MAJORS:
        raise ArtifactValidationError(
            f"unsupported contract major version {major}",
            diagnostics=(
                Diagnostic(
                    "UNSUPPORTED_CONTRACT_MAJOR",
                    f"supported major versions: {sorted(SUPPORTED_CONTRACT_MAJORS)}",
                    path,
                    {"actual": major},
                ),
            ),
        )
    return major


class ContractCatalog:
    """Local, network-independent schema and registry resolver."""

    def __init__(self, root: str | Path | None = None) -> None:
        self.root = discover_contract_root(root)
        self._records = self._load_schemas()
        self._aliases = self._build_aliases(self._records)
        self._add_catalog_aliases()

    @property
    def schemas(self) -> tuple[SchemaRecord, ...]:
        return self._records

    def _load_schemas(self) -> tuple[SchemaRecord, ...]:
        records: list[SchemaRecord] = []
        paths = sorted((self.root / "schemas").rglob("*.json"))
        if not paths:
            raise ResourceError(f"no JSON schemas found under {self.root / 'schemas'}")
        for path in paths:
            raw = load_json(path)
            if not isinstance(raw, dict):
                raise ResourceError(f"schema is not a JSON object: {path}")
            dialect = raw.get("$schema")
            if dialect not in {DRAFT_2020_12, DRAFT_2020_12 + "#"}:
                raise ResourceError(f"schema does not declare JSON Schema Draft 2020-12: {path}")
            relative = path.relative_to(self.root).as_posix()
            schema_id_value = raw.get("$id")
            schema_id = schema_id_value if isinstance(schema_id_value, str) else None
            records.append(
                SchemaRecord(
                    path=path,
                    relative_path=relative,
                    document=cast(Mapping[str, JSONValue], raw),
                    schema_id=schema_id,
                    artifact_type=_artifact_type_from_schema(raw),
                )
            )
        return tuple(records)

    @staticmethod
    def _build_aliases(
        records: Sequence[SchemaRecord],
    ) -> dict[str, tuple[SchemaRecord, ...]]:
        aliases: dict[str, list[SchemaRecord]] = {}
        for record in records:
            values: set[str] = {
                record.relative_path,
                record.path.name,
                record.path.stem,
            }
            if record.schema_id:
                values.add(record.schema_id)
                parsed = urlparse(record.schema_id)
                if parsed.path:
                    values.add(Path(unquote(parsed.path)).name)
            if record.artifact_type:
                values.add(record.artifact_type)
                values.add(record.artifact_type.lower())
            title = record.document.get("title")
            if isinstance(title, str):
                values.add(title)
            for value in values:
                aliases.setdefault(value, []).append(record)
        return {
            key: tuple(sorted(value, key=lambda item: item.relative_path))
            for key, value in aliases.items()
        }

    def _add_catalog_aliases(self) -> None:
        """Add registry contract names without trusting them for validation."""

        path = self.root / "registry" / "contract-catalog.json"
        if not path.is_file():
            return
        raw = load_json(path)
        contracts = raw.get("contracts") if isinstance(raw, dict) else None
        if not isinstance(contracts, list):
            return
        by_path = {record.relative_path: record for record in self._records}
        mutable = {key: list(value) for key, value in self._aliases.items()}
        for item in contracts:
            if not isinstance(item, dict):
                continue
            schema_path = item.get("schema_path")
            name = item.get("name")
            version = item.get("version")
            if not isinstance(schema_path, str) or not isinstance(name, str):
                continue
            record = by_path.get(schema_path)
            if record is None:
                continue
            for alias in (name, f"{name}@{version}" if isinstance(version, str) else None):
                if alias is not None and record not in mutable.setdefault(alias, []):
                    mutable[alias].append(record)
        self._aliases = {
            key: tuple(sorted(value, key=lambda item: item.relative_path))
            for key, value in mutable.items()
        }

    def resolve_schema(
        self,
        contract: str | Path | None = None,
        *,
        document: Mapping[str, JSONValue] | None = None,
    ) -> SchemaRecord:
        """Resolve an explicit contract or infer one uniquely from a document."""

        candidates: list[str] = []
        if contract is not None:
            candidate_path = Path(contract)
            if candidate_path.is_absolute() and candidate_path.is_file():
                try:
                    relative = candidate_path.resolve().relative_to(self.root).as_posix()
                except ValueError as exc:
                    raise SchemaResolutionError(
                        f"schema must be within the immutable contract root: {candidate_path}"
                    ) from exc
                candidates.append(relative)
            else:
                root_relative = self.root / candidate_path
                if root_relative.is_file():
                    candidates.append(candidate_path.as_posix())
                candidates.append(str(contract))
        elif document is not None:
            declared = document.get("$schema")
            if isinstance(declared, str) and not declared.startswith(
                "https://json-schema.org/draft/"
            ):
                candidates.append(declared)
            else:
                artifact_type = document.get("artifact_type")
                if isinstance(artifact_type, str):
                    candidates.extend((artifact_type, artifact_type.lower()))

        resolved: dict[str, SchemaRecord] = {}
        for candidate in candidates:
            for record in self._aliases.get(candidate, ()):
                resolved[record.relative_path] = record
        if len(resolved) == 1:
            selected = next(iter(resolved.values()))
            artifact_type = document.get("artifact_type") if document is not None else None
            if isinstance(artifact_type, str):
                expected = tuple(
                    record for record in self._records if record.artifact_type == artifact_type
                )
                if len(expected) == 1 and selected.relative_path != expected[0].relative_path:
                    raise SchemaResolutionError(
                        "artifact_type must use its registered stage schema",
                        diagnostics=(
                            Diagnostic(
                                "ARTIFACT_SCHEMA_MISMATCH",
                                "declared schema does not match the registered stage contract",
                                "/$schema",
                                {
                                    "actual": selected.relative_path,
                                    "expected": expected[0].relative_path,
                                },
                            ),
                        ),
                    )
            return selected
        if not resolved:
            subject = str(contract) if contract is not None else "document metadata"
            raise SchemaResolutionError(f"no registered schema matches {subject!r}")
        paths = sorted(resolved)
        raise SchemaResolutionError(
            f"schema reference is ambiguous: {paths}",
            diagnostics=(
                Diagnostic(
                    "AMBIGUOUS_SCHEMA",
                    "use a catalog-relative schema path",
                    context={"matches": paths},
                ),
            ),
        )

    def _registry(self) -> Any:
        try:
            from referencing import Registry, Resource
            from referencing.jsonschema import DRAFT202012
        except ImportError as exc:  # pragma: no cover - dependency installation error.
            raise ResourceError("jsonschema/referencing runtime dependency is missing") from exc

        registry = Registry()
        for record in self._records:
            resource = Resource.from_contents(
                dict(record.document), default_specification=DRAFT202012
            )
            uris = {record.path.resolve().as_uri()}
            if record.schema_id:
                uris.add(record.schema_id)
            for uri in sorted(uris):
                registry = registry.with_resource(uri, resource)
        return registry

    def validate_schema_document(
        self,
        document: Mapping[str, JSONValue],
        schema: SchemaRecord,
    ) -> None:
        """Validate with Draft 2020-12 and full format checks."""

        try:
            from jsonschema import (  # type: ignore[import-untyped]
                Draft202012Validator,
                FormatChecker,
            )
            from jsonschema.exceptions import SchemaError  # type: ignore[import-untyped]
        except ImportError as exc:  # pragma: no cover - dependency installation error.
            raise ResourceError("jsonschema runtime dependency is missing") from exc

        try:
            Draft202012Validator.check_schema(dict(schema.document))
            validator = Draft202012Validator(
                dict(schema.document),
                registry=self._registry(),
                format_checker=FormatChecker(),
            )
            errors = sorted(
                validator.iter_errors(dict(document)),
                key=lambda error: (
                    tuple(str(part) for part in error.absolute_path),
                    error.validator or "",
                    error.message,
                ),
            )
        except SchemaError as exc:
            raise ResourceError(
                f"registered schema is itself invalid: {schema.relative_path}"
            ) from exc
        except Exception as exc:
            # Unresolvable references are a hard validation failure, never a
            # reason to accept a document with partial checking.
            raise SchemaValidationError(
                f"schema evaluation failed closed for {schema.relative_path}: {exc}"
            ) from exc

        if errors:
            diagnostics = tuple(
                Diagnostic(
                    code="SCHEMA_" + str(error.validator or "ERROR").upper(),
                    message=error.message,
                    path=_pointer(error.absolute_path),
                    context={"schema_path": _pointer(error.absolute_schema_path)},
                )
                for error in errors
            )
            raise SchemaValidationError(
                f"document violates {schema.relative_path}", diagnostics=diagnostics
            )

    def catalog_entries(self, *, verify: bool = True) -> tuple[Mapping[str, Any], ...]:
        """Return catalog entries after structural and digest verification."""

        catalog_path = self.root / "registry" / "contract-catalog.json"
        raw = load_json(catalog_path)
        contracts_value = raw.get("contracts") if isinstance(raw, dict) else None
        if not isinstance(raw, dict) or not isinstance(contracts_value, list):
            raise ResourceError("registry/contract-catalog.json must contain contracts[]")

        entries: list[Mapping[str, Any]] = []
        identities: set[tuple[str, str]] = set()
        catalog_paths: set[str] = set()
        catalog_schema_ids: set[str] = set()
        for index, item in enumerate(contracts_value):
            if not isinstance(item, dict):
                raise ResourceError(f"catalog contract at index {index} is not an object")
            name = item.get("name")
            version = item.get("version")
            schema_path = item.get("schema_path")
            if not all(isinstance(value, str) for value in (name, version, schema_path)):
                raise ResourceError(
                    f"catalog contract at index {index} lacks name/version/schema_path"
                )
            identity = (cast(str, name), cast(str, version))
            if identity in identities:
                raise ResourceError(f"duplicate catalog identity {identity}")
            identities.add(identity)
            if cast(str, schema_path) in catalog_paths:
                raise ResourceError(f"duplicate catalog schema_path: {schema_path}")
            catalog_paths.add(cast(str, schema_path))
            if _SEMVER.fullmatch(cast(str, version)) is None:
                raise ResourceError(f"catalog version is not SemVer: {identity}")
            record = self.resolve_schema(cast(str, schema_path))
            if verify:
                if item.get("schema_id") != record.schema_id:
                    raise ResourceError(f"catalog schema_id mismatch for {identity}")
                if record.schema_id is None:
                    raise ResourceError(f"catalog schema has no $id: {identity}")
                if record.schema_id in catalog_schema_ids:
                    raise ResourceError(f"duplicate schema $id: {record.schema_id}")
                catalog_schema_ids.add(record.schema_id)
                declared_sha = item.get("schema_sha256")
                if not is_sha256(declared_sha):
                    raise ResourceError(f"catalog schema digest is malformed: {identity}")
                if not hmac.compare_digest(cast(str, declared_sha), record.canonical_sha256):
                    raise ResourceError(
                        f"catalog schema digest mismatch for {identity}: "
                        f"expected {declared_sha}, computed {record.canonical_sha256}"
                    )
                declared_major = item.get("major_version")
                actual_major = int(cast(str, version).split(".", 1)[0])
                if declared_major != actual_major:
                    raise ResourceError(f"catalog major_version mismatch for {identity}")
            entries.append(cast(Mapping[str, Any], item))
        if verify:
            actual_paths = {record.relative_path for record in self._records}
            if catalog_paths != actual_paths:
                raise ResourceError(
                    "catalog must contain exactly one entry for every JSON schema; "
                    f"missing={sorted(actual_paths - catalog_paths)}, "
                    f"orphan={sorted(catalog_paths - actual_paths)}"
                )
        return tuple(entries)

    def compatibility_rules(self, *, verify: bool = True) -> tuple[Mapping[str, Any], ...]:
        """Load and fail-closed verify producer/consumer compatibility rules."""

        path = self.root / "registry" / "compatibility-matrix.json"
        raw = load_json(path)
        rules_value = raw.get("rules") if isinstance(raw, dict) else None
        if not isinstance(rules_value, list):
            raise ResourceError("registry/compatibility-matrix.json must contain rules[]")
        catalog_entries = self.catalog_entries(verify=verify)
        catalog_by_name = {
            cast(str, entry["name"]): entry
            for entry in catalog_entries
            if isinstance(entry.get("name"), str)
        }
        known_contracts = set(catalog_by_name)
        stage_by_contract = (
            {cast(str, item["produces"]): item for item in self.stage_registrations(verify=verify)}
            if verify
            else {}
        )
        identities: set[tuple[str, str, str]] = set()
        rules: list[Mapping[str, Any]] = []
        for index, item in enumerate(rules_value):
            if not isinstance(item, dict):
                raise ResourceError(f"compatibility rule at index {index} is not an object")
            producer = item.get("producer_contract")
            consumer = item.get("consumer_contract")
            relationship = item.get("relationship")
            versions = item.get("accepted_input_versions")
            statuses = item.get("accepted_statuses")
            if not all(isinstance(value, str) for value in (producer, consumer, relationship)):
                raise ResourceError(f"compatibility rule at index {index} lacks identity")
            identity = (cast(str, producer), cast(str, consumer), cast(str, relationship))
            if identity in identities:
                raise ResourceError(f"duplicate compatibility rule {identity}")
            identities.add(identity)
            if (
                not isinstance(versions, list)
                or not versions
                or not all(
                    isinstance(value, str) and _SEMVER.fullmatch(value) for value in versions
                )
            ):
                raise ResourceError(f"compatibility rule has invalid versions: {identity}")
            if (
                not isinstance(statuses, list)
                or not statuses
                or not all(isinstance(value, str) for value in statuses)
            ):
                raise ResourceError(f"compatibility rule has invalid statuses: {identity}")
            if verify and (
                producer not in known_contracts
                or consumer not in known_contracts
                or item.get("compatibility") != "SUPPORTED"
            ):
                raise ResourceError(f"unsupported or unknown compatibility rule: {identity}")
            if verify:
                producer_entry = catalog_by_name[cast(str, producer)]
                consumer_entry = catalog_by_name[cast(str, consumer)]
                if item.get("producer_version") != producer_entry.get("version") or item.get(
                    "consumer_version"
                ) != consumer_entry.get("version"):
                    raise ResourceError(f"compatibility contract version mismatch: {identity}")
                if versions != [producer_entry.get("version")]:
                    raise ResourceError(
                        "accepted input versions must equal the producer catalog "
                        f"version: {identity}"
                    )
                producer_stage = stage_by_contract.get(cast(str, producer))
                consumer_stage = stage_by_contract.get(cast(str, consumer))
                if (
                    producer_stage is None
                    or consumer_stage is None
                    or item.get("producer_release") != producer_stage.get("release")
                    or item.get("consumer_release") != consumer_stage.get("release")
                ):
                    raise ResourceError(f"compatibility producer release mismatch: {identity}")
            rules.append(cast(Mapping[str, Any], item))
        return tuple(rules)

    def stage_registrations(self, *, verify: bool = True) -> tuple[Mapping[str, Any], ...]:
        """Return the exact producer, release, and authority registration per stage."""

        path = self.root / "registry" / "producer-consumer-map.json"
        raw = load_json(path)
        if not isinstance(raw, dict):
            raise ResourceError("registry/producer-consumer-map.json must be an object")
        stages_value = raw.get("stages")
        if not isinstance(stages_value, list):
            raise ResourceError("registry/producer-consumer-map.json must contain stages[]")
        if (
            not isinstance(raw.get("registry_version"), str)
            or _SEMVER.fullmatch(cast(str, raw.get("registry_version"))) is None
        ):
            raise ResourceError("producer-consumer map registry_version must be SemVer")
        try:
            _parse_timestamp(raw.get("generated_at"), path="/generated_at")
        except ArtifactValidationError as exc:
            raise ResourceError("producer-consumer map generated_at must be RFC 3339") from exc
        catalog_by_name = {
            cast(str, item["name"]): item
            for item in self.catalog_entries(verify=verify)
            if isinstance(item.get("name"), str)
        }
        stages: list[Mapping[str, Any]] = []
        identities: set[tuple[str, str]] = set()
        orders: set[int] = set()
        for index, item in enumerate(stages_value):
            if not isinstance(item, dict):
                raise ResourceError(f"stage registration at index {index} is not an object")
            stage = item.get("stage")
            repository = item.get("repository")
            release = item.get("release")
            produces = item.get("produces")
            order = item.get("order")
            authority_scope = item.get("authority_scope")
            execution_scope = item.get("execution_authority_scope")
            if not all(
                isinstance(value, str) for value in (stage, repository, release, produces)
            ) or not isinstance(order, int):
                raise ResourceError(f"stage registration at index {index} lacks identity")
            if (
                _STAGE_ID.fullmatch(cast(str, stage)) is None
                or _REPOSITORY.fullmatch(cast(str, repository)) is None
            ):
                raise ResourceError(f"stage registration identity is not normalized: {stage}")
            if authority_scope is not None and not isinstance(authority_scope, str):
                raise ResourceError(f"stage registration has invalid authority scope: {stage}")
            if execution_scope is not None and not isinstance(execution_scope, str):
                raise ResourceError(f"stage registration has invalid execution scope: {stage}")
            if (
                not cast(str, release).startswith("v")
                or _SEMVER.fullmatch(cast(str, release)[1:]) is None
            ):
                raise ResourceError(f"stage registration has invalid release: {stage}")
            identity = (cast(str, stage), cast(str, produces))
            if identity in identities or order in orders:
                raise ResourceError(f"duplicate stage registration: {identity}")
            identities.add(identity)
            orders.add(order)
            catalog_entry = catalog_by_name.get(cast(str, produces))
            producers = catalog_entry.get("producer_repositories") if catalog_entry else None
            if verify and (
                catalog_entry is None
                or not isinstance(producers, list)
                or repository not in producers
            ):
                raise ResourceError(f"stage producer is not authorized by catalog: {identity}")
            stages.append(cast(Mapping[str, Any], item))
        if orders != set(range(1, len(stages) + 1)):
            raise ResourceError("stage orders must be exactly the contiguous range 1..N")
        return tuple(sorted(stages, key=lambda item: cast(int, item["order"])))

    def gate_source_policy(self, *, verify: bool = True) -> Mapping[str, tuple[str, ...]]:
        """Return exact stage-contract sources required for every go-live gate."""

        path = self.root / "registry" / "producer-consumer-map.json"
        raw = load_json(path)
        policy_value = raw.get("gate_source_policy") if isinstance(raw, dict) else None
        if not isinstance(policy_value, dict):
            raise ResourceError(
                "registry/producer-consumer-map.json must contain gate_source_policy"
            )
        known_stage_contracts = {
            cast(str, item["produces"]) for item in self.stage_registrations(verify=verify)
        }
        if set(policy_value) != set(GATE_NAMES):
            raise ResourceError("gate source policy must define G-01 through G-14 exactly")
        result: dict[str, tuple[str, ...]] = {}
        for gate_id in sorted(GATE_NAMES):
            sources = policy_value.get(gate_id)
            if (
                not isinstance(sources, list)
                or not sources
                or not all(isinstance(value, str) for value in sources)
                or len(sources) != len(set(cast(list[str], sources)))
            ):
                raise ResourceError(f"gate source policy is malformed for {gate_id}")
            if verify and not set(cast(list[str], sources)) <= known_stage_contracts:
                raise ResourceError(f"gate source policy references unknown contract for {gate_id}")
            result[gate_id] = tuple(cast(list[str], sources))
        return result

    def verify_registry_reconciliation(self) -> Mapping[str, int]:
        """Fail closed unless catalog, producer map, and compatibility matrix agree.

        The three registries describe the same stage graph from different
        viewpoints.  Treating any one as advisory would allow producer or
        compatibility authorization to be widened by editing only one file.
        """

        catalog_entries = self.catalog_entries(verify=True)
        stage_entries = self.stage_registrations(verify=True)
        rules = self.compatibility_rules(verify=True)

        map_raw = load_json(self.root / "registry" / "producer-consumer-map.json")
        matrix_raw = load_json(self.root / "registry" / "compatibility-matrix.json")
        catalog_raw = load_json(self.root / "registry" / "contract-catalog.json")
        if not all(isinstance(value, dict) for value in (map_raw, matrix_raw, catalog_raw)):
            raise ResourceError("all registries must be JSON objects")
        map_document = cast(dict[str, JSONValue], map_raw)
        matrix_document = cast(dict[str, JSONValue], matrix_raw)
        catalog_document = cast(dict[str, JSONValue], catalog_raw)
        registry_versions = {
            value.get("registry_version")
            for value in (map_document, matrix_document, catalog_document)
        }
        if len(registry_versions) != 1 or not all(
            isinstance(value, str) and _SEMVER.fullmatch(value) for value in registry_versions
        ):
            raise ResourceError("all registries must declare the same SemVer registry_version")
        registry_version = next(iter(registry_versions))
        if matrix_document.get("contracts_release") != f"v{registry_version}":
            raise ResourceError("compatibility contracts_release must match registry_version")
        try:
            _parse_timestamp(map_document.get("generated_at"), path="/generated_at")
            _parse_timestamp(matrix_document.get("generated_at"), path="/generated_at")
            _parse_timestamp(catalog_document.get("published_at"), path="/published_at")
        except ArtifactValidationError as exc:
            raise ResourceError("registry publication timestamps must be RFC 3339") from exc
        if catalog_document.get("json_schema_dialect") != DRAFT_2020_12:
            raise ResourceError("catalog json_schema_dialect must be Draft 2020-12")
        if catalog_document.get("digest_profile") != DIGEST_PROFILE:
            raise ResourceError("catalog digest_profile is unsupported")

        stage_catalog = {
            cast(str, item["name"]): item
            for item in catalog_entries
            if item.get("contract_kind") == "STAGE" and isinstance(item.get("name"), str)
        }
        stage_by_contract = {
            cast(str, item["produces"]): item
            for item in stage_entries
            if isinstance(item.get("produces"), str)
        }
        if set(stage_catalog) != set(stage_by_contract):
            raise ResourceError("producer map stages must exactly cover stage catalog contracts")

        edges_value = map_document.get("edges")
        if not isinstance(edges_value, list):
            raise ResourceError("registry/producer-consumer-map.json must contain edges[]")
        edge_identities: set[tuple[str, str, str]] = set()
        incoming: dict[str, set[str]] = {name: set() for name in stage_by_contract}
        outgoing_repositories: dict[str, set[str]] = {name: set() for name in stage_by_contract}
        for index, edge in enumerate(edges_value):
            if not isinstance(edge, dict):
                raise ResourceError(f"producer map edge at index {index} is not an object")
            producer = edge.get("from")
            consumer = edge.get("to")
            relationship = edge.get("relationship")
            if (
                not all(isinstance(value, str) for value in (producer, consumer, relationship))
                or edge.get("required") is not True
                or producer not in stage_by_contract
                or consumer not in stage_by_contract
            ):
                raise ResourceError(f"producer map edge at index {index} is malformed")
            identity = (cast(str, producer), cast(str, consumer), cast(str, relationship))
            if identity in edge_identities:
                raise ResourceError(f"duplicate producer map edge: {identity}")
            edge_identities.add(identity)
            incoming[cast(str, consumer)].add(cast(str, producer))
            consumer_repository = stage_by_contract[cast(str, consumer)].get("repository")
            if isinstance(consumer_repository, str):
                outgoing_repositories[cast(str, producer)].add(consumer_repository)

        for contract, stage in sorted(stage_by_contract.items()):
            consumes = stage.get("consumes")
            if (
                not isinstance(consumes, list)
                or not all(isinstance(value, str) for value in consumes)
                or len(consumes) != len(set(cast(list[str], consumes)))
                or set(cast(list[str], consumes)) != incoming[contract]
            ):
                raise ResourceError(
                    f"stage consumes[] does not equal incoming producer-map edges: {contract}"
                )
            catalog_entry = stage_catalog[contract]
            producer_repositories = catalog_entry.get("producer_repositories")
            consumer_repositories = catalog_entry.get("consumer_repositories")
            expected_producer = {stage.get("repository")}
            if (
                not isinstance(producer_repositories, list)
                or len(producer_repositories) != len(set(cast(list[str], producer_repositories)))
                or set(cast(list[str], producer_repositories)) != expected_producer
            ):
                raise ResourceError(f"catalog producer repositories disagree for {contract}")
            if (
                not isinstance(consumer_repositories, list)
                or len(consumer_repositories) != len(set(cast(list[str], consumer_repositories)))
                or set(cast(list[str], consumer_repositories)) != outgoing_repositories[contract]
            ):
                raise ResourceError(f"catalog consumer repositories disagree for {contract}")

        rule_identities = {
            (
                cast(str, rule["producer_contract"]),
                cast(str, rule["consumer_contract"]),
                cast(str, rule["relationship"]),
            )
            for rule in rules
        }
        if rule_identities != edge_identities:
            raise ResourceError(
                "compatibility rules must exactly equal producer-consumer map edges; "
                f"missing={sorted(edge_identities - rule_identities)}, "
                f"orphan={sorted(rule_identities - edge_identities)}"
            )

        self.gate_source_policy(verify=True)
        return {
            "catalog_contract_count": len(catalog_entries),
            "compatibility_rule_count": len(rules),
            "producer_consumer_edge_count": len(edge_identities),
            "stage_count": len(stage_entries),
        }

    def artifact_registration_diagnostics(
        self, artifact: Mapping[str, JSONValue]
    ) -> tuple[Diagnostic, ...]:
        """Authenticate producer provenance and every scoped human authority record."""

        diagnostics: list[Diagnostic] = []
        stage = artifact.get("stage")
        artifact_type = artifact.get("artifact_type")
        registrations = {item.get("stage"): item for item in self.stage_registrations(verify=True)}
        registration = registrations.get(stage)
        if registration is None:
            return (
                Diagnostic(
                    "UNREGISTERED_STAGE_CONTRACT",
                    "artifact stage has no producer registration",
                    "/stage",
                    {"stage": stage},
                ),
            )
        expected_contract = registration.get("produces")
        actual_contract = (
            f"{artifact_type}.v{str(artifact.get('spec_version', '')).split('.', 1)[0]}"
            if isinstance(artifact_type, str)
            else None
        )
        if actual_contract != expected_contract:
            diagnostics.append(
                Diagnostic(
                    "UNREGISTERED_STAGE_CONTRACT",
                    "artifact type/version does not match the stage registration",
                    "/artifact_type",
                    {"actual": actual_contract, "expected": expected_contract},
                )
            )

        producer = artifact.get("producer")
        if not isinstance(producer, dict):
            diagnostics.append(
                Diagnostic(
                    "UNREGISTERED_PRODUCER",
                    "artifact must identify the registered stage producer",
                    "/producer",
                )
            )
        else:
            expected_repository = registration.get("repository")
            expected_release = registration.get("release")
            if producer.get("repository") != expected_repository:
                diagnostics.append(
                    Diagnostic(
                        "UNREGISTERED_PRODUCER",
                        "producer repository is not registered for this stage",
                        "/producer/repository",
                        {"actual": producer.get("repository"), "expected": expected_repository},
                    )
                )
            if producer.get("release") != expected_release:
                diagnostics.append(
                    Diagnostic(
                        "UNREGISTERED_PRODUCER_RELEASE",
                        "producer release is not registered for this stage",
                        "/producer/release",
                        {"actual": producer.get("release"), "expected": expected_release},
                    )
                )
            expected_tool_version = (
                expected_release[1:]
                if isinstance(expected_release, str) and expected_release.startswith("v")
                else None
            )
            if producer.get("tool_version") != expected_tool_version:
                diagnostics.append(
                    Diagnostic(
                        "PRODUCER_TOOL_VERSION_MISMATCH",
                        "tool_version must equal the registered release without leading v",
                        "/producer/tool_version",
                        {
                            "actual": producer.get("tool_version"),
                            "expected": expected_tool_version,
                        },
                    )
                )
            source_uri = producer.get("source_uri")
            expected_source_uri = (
                f"https://github.com/{expected_repository}"
                if isinstance(expected_repository, str)
                else None
            )
            if source_uri is not None and source_uri != expected_source_uri:
                diagnostics.append(
                    Diagnostic(
                        "PRODUCER_SOURCE_URI_MISMATCH",
                        "producer source_uri contradicts the registered repository",
                        "/producer/source_uri",
                        {"actual": source_uri, "expected": expected_source_uri},
                    )
                )

        authority_scope = registration.get("authority_scope")
        execution_scope = registration.get("execution_authority_scope")

        def walk(value: JSONValue, path: str) -> None:
            if isinstance(value, list):
                for index, item in enumerate(value):
                    walk(item, f"{path}/{index}")
                return
            if not isinstance(value, dict):
                return
            observed = value.get("authority_scope")
            if isinstance(observed, str):
                expected_scope = (
                    execution_scope
                    if path.startswith("/payload/execution_authority")
                    else authority_scope
                )
                if observed != expected_scope:
                    diagnostics.append(
                        Diagnostic(
                            "UNREGISTERED_AUTHORITY_SCOPE",
                            "human authority scope is not registered for this stage",
                            f"{path}/authority_scope",
                            {"actual": observed, "expected": expected_scope},
                        )
                    )
            for key, nested in value.items():
                encoded = key.replace("~", "~0").replace("/", "~1")
                walk(nested, f"{path}/{encoded}")

        walk(cast(JSONValue, dict(artifact)), "")
        return tuple(diagnostics)


def verify_artifact_integrity(
    artifact: Mapping[str, JSONValue],
    *,
    catalog: ContractCatalog | None = None,
    root: str | Path | None = None,
) -> tuple[str, str]:
    """Verify profile, payload digest, artifact digest, version, and time."""

    diagnostics: list[Diagnostic] = []
    active_catalog = catalog if catalog is not None else ContractCatalog(root)
    active_catalog.verify_registry_reconciliation()
    diagnostics.extend(active_catalog.artifact_registration_diagnostics(artifact))
    if artifact.get("digest_profile") != DIGEST_PROFILE:
        diagnostics.append(
            Diagnostic(
                "UNSUPPORTED_DIGEST_PROFILE",
                f"expected {DIGEST_PROFILE!r}",
                "/digest_profile",
            )
        )

    version_key = "spec_version" if "spec_version" in artifact else "schema_version"
    try:
        contract_major(artifact.get(version_key), path=f"/{version_key}")
    except ArtifactValidationError as exc:
        diagnostics.extend(exc.diagnostics)

    if "produced_at" in artifact:
        try:
            _parse_timestamp(artifact.get("produced_at"), path="/produced_at")
        except ArtifactValidationError as exc:
            diagnostics.extend(exc.diagnostics)

    payload_actual = payload_digest(artifact)
    payload_declared = artifact.get("payload_sha256")
    if not is_sha256(payload_declared) or not hmac.compare_digest(
        cast(str, payload_declared), payload_actual
    ):
        diagnostics.append(
            Diagnostic(
                "PAYLOAD_DIGEST_MISMATCH",
                "payload_sha256 does not match the JCS payload digest",
                "/payload_sha256",
                {"computed": payload_actual, "declared": payload_declared},
            )
        )

    artifact_actual = artifact_digest(artifact)
    artifact_declared = artifact.get("artifact_sha256")
    if not is_sha256(artifact_declared) or not hmac.compare_digest(
        cast(str, artifact_declared), artifact_actual
    ):
        diagnostics.append(
            Diagnostic(
                "ARTIFACT_DIGEST_MISMATCH",
                "artifact_sha256 does not match the digest-profile projection",
                "/artifact_sha256",
                {"computed": artifact_actual, "declared": artifact_declared},
            )
        )

    diagnostics.extend(_domain_semantic_diagnostics(artifact))
    if diagnostics:
        raise ArtifactValidationError(
            "artifact integrity verification failed",
            diagnostics=tuple(diagnostics),
        )
    return artifact_actual, payload_actual


def _gate_set_diagnostics(
    values: object, *, path: str, outcome_key: str | None = None
) -> tuple[list[Diagnostic], dict[str, str]]:
    diagnostics: list[Diagnostic] = []
    observed: dict[str, str] = {}
    if not isinstance(values, list):
        return diagnostics, observed  # Schema validation reports the shape first.
    for index, item in enumerate(values):
        if not isinstance(item, dict):
            continue
        gate_id = item.get("gate_id")
        gate_name = item.get("gate_name")
        if not isinstance(gate_id, str):
            continue
        if gate_id in observed:
            diagnostics.append(
                Diagnostic(
                    "DUPLICATE_GATE_ID",
                    f"gate {gate_id} appears more than once",
                    f"{path}/{index}/gate_id",
                )
            )
        observed[gate_id] = (
            cast(str, item.get(outcome_key))
            if outcome_key is not None and isinstance(item.get(outcome_key), str)
            else ""
        )
        expected_name = GATE_NAMES.get(gate_id)
        if expected_name is not None and gate_name != expected_name:
            diagnostics.append(
                Diagnostic(
                    "GATE_NAME_MISMATCH",
                    f"{gate_id} must be named {expected_name}",
                    f"{path}/{index}/gate_name",
                    {"actual": gate_name, "expected": expected_name},
                )
            )
    missing = sorted(set(GATE_NAMES) - set(observed))
    extra = sorted(set(observed) - set(GATE_NAMES))
    if missing or extra or len(values) != len(GATE_NAMES):
        diagnostics.append(
            Diagnostic(
                "GATE_SET_MISMATCH",
                "gate collection must contain G-01 through G-14 exactly once",
                path,
                {"missing": missing, "extra": extra},
            )
        )
    return diagnostics, observed


_MAIN_DECISION_FIELDS = {
    "RequirementsAssessment": "human_review",
    "StakeholderAlignmentPacket": "decision",
    "ProcessRedesignDecision": "selection",
    "GoLiveDecisionPacket": "decision",
}


def decision_subject_projection(
    artifact: Mapping[str, JSONValue],
) -> Mapping[str, JSONValue] | None:
    """Return the non-circular governed payload projection for HumanDecision."""

    artifact_type = artifact.get("artifact_type")
    decision_field = _MAIN_DECISION_FIELDS.get(cast(str, artifact_type))
    payload = artifact.get("payload")
    if decision_field is None or not isinstance(payload, dict):
        return None
    projection = {
        key: value
        for key, value in payload.items()
        if key not in {decision_field, "decision_digest"}
    }

    def strip_digests(value: JSONValue) -> JSONValue:
        if isinstance(value, list):
            return [strip_digests(item) for item in value]
        if isinstance(value, dict):
            return {
                key: strip_digests(nested)
                for key, nested in value.items()
                if key != "artifact_digest"
            }
        return value

    return cast(Mapping[str, JSONValue], strip_digests(cast(JSONValue, projection)))


def decision_subject_digest(artifact: Mapping[str, JSONValue]) -> str | None:
    """Return the JCS SHA-256 for a governed stage's decision subject."""

    projection = decision_subject_projection(artifact)
    return digest_json(dict(projection)) if projection is not None else None


def _decision_binding_diagnostics(
    artifact: Mapping[str, JSONValue],
) -> tuple[Diagnostic, ...]:
    artifact_type = artifact.get("artifact_type")
    decision_field = _MAIN_DECISION_FIELDS.get(cast(str, artifact_type))
    payload = artifact.get("payload")
    if decision_field is None or not isinstance(payload, dict):
        return ()
    embedded = payload.get(decision_field)
    envelope = artifact.get("authority")
    projection = decision_subject_projection(artifact)
    if not isinstance(embedded, dict) or projection is None:
        return ()  # Stage schema reports the missing/invalid decision shape.

    diagnostics: list[Diagnostic] = []
    if not isinstance(envelope, dict) or not hmac.compare_digest(
        digest_json(envelope), digest_json(embedded)
    ):
        diagnostics.append(
            Diagnostic(
                "AUTHORITY_DECISION_MISMATCH",
                "envelope authority must exactly equal the embedded stage decision",
                "/authority",
            )
        )
    expected_outcome_by_status = {
        "HUMAN_CONFIRMED": "APPROVED",
        "CONDITIONALLY_APPROVED": "CONDITIONAL",
        "APPROVED": "APPROVED",
        "BLOCKED": "CONDITIONAL",
        "REJECTED": "REJECTED",
        "SUPERSEDED": "SUPERSEDED",
    }
    expected_outcome = expected_outcome_by_status.get(cast(str, artifact.get("status")))
    if expected_outcome is not None and embedded.get("outcome") != expected_outcome:
        diagnostics.append(
            Diagnostic(
                "DECISION_OUTCOME_STATUS_MISMATCH",
                "embedded HumanDecision outcome must correspond to artifact lifecycle status",
                f"/payload/{decision_field}/outcome",
                {"actual": embedded.get("outcome"), "expected": expected_outcome},
            )
        )
    subject_digest = decision_subject_digest(artifact)
    if subject_digest is None:  # Kept explicit as a fail-closed typing boundary.
        return (
            Diagnostic(
                "DECISION_SUBJECT_UNRESOLVABLE",
                "governed decision subject projection could not be constructed",
                "/payload",
            ),
        )

    def walk(value: JSONValue, path: str) -> None:
        if isinstance(value, list):
            for index, item in enumerate(value):
                walk(item, f"{path}/{index}")
            return
        if not isinstance(value, dict):
            return
        if isinstance(value.get("authority_scope"), str):
            declared = value.get("artifact_digest")
            if not isinstance(declared, str) or not hmac.compare_digest(declared, subject_digest):
                diagnostics.append(
                    Diagnostic(
                        "DECISION_SUBJECT_DIGEST_MISMATCH",
                        "HumanDecision artifact_digest must bind the governed payload projection",
                        f"{path}/artifact_digest",
                        {"actual": declared, "expected": subject_digest},
                    )
                )
        for key, nested in value.items():
            encoded = key.replace("~", "~0").replace("/", "~1")
            walk(nested, f"{path}/{encoded}")

    walk(cast(JSONValue, dict(artifact)), "")
    if artifact_type == "StakeholderAlignmentPacket":
        actual_decision_digest = payload.get("decision_digest")
        expected_decision_digest = digest_json(embedded)
        if not isinstance(actual_decision_digest, str) or not hmac.compare_digest(
            actual_decision_digest, expected_decision_digest
        ):
            diagnostics.append(
                Diagnostic(
                    "ALIGNMENT_DECISION_DIGEST_MISMATCH",
                    "decision_digest must be the JCS digest of payload.decision",
                    "/payload/decision_digest",
                    {
                        "actual": actual_decision_digest,
                        "expected": expected_decision_digest,
                    },
                )
            )
    return tuple(diagnostics)


def _domain_semantic_diagnostics(
    artifact: Mapping[str, JSONValue],
) -> tuple[Diagnostic, ...]:
    """Check business invariants that JSON Schema cannot express safely."""

    diagnostics = list(_evidence_semantic_diagnostics(artifact))
    diagnostics.extend(_decision_binding_diagnostics(artifact))
    artifact_type = artifact.get("artifact_type")
    payload = artifact.get("payload")
    if not isinstance(payload, dict):
        return tuple(diagnostics)

    if artifact_type == "RequirementsAssessment":
        requirements = payload.get("requirements")
        scorecard = payload.get("scorecard")
        findings = payload.get("findings")
        if isinstance(requirements, list) and isinstance(scorecard, dict):
            counts = {"CONFIRMED": 0, "NEEDS_CLARIFICATION": 0, "REJECTED": 0}
            for requirement in requirements:
                if isinstance(requirement, dict) and requirement.get("status") in counts:
                    counts[cast(str, requirement["status"])] += 1
            expected_counts = {
                "total_requirements": len(requirements),
                "confirmed": counts["CONFIRMED"],
                "unresolved": counts["NEEDS_CLARIFICATION"],
                "rejected": counts["REJECTED"],
            }
            for key, value in expected_counts.items():
                if scorecard.get(key) != value:
                    diagnostics.append(
                        Diagnostic(
                            "SCORECARD_COUNT_MISMATCH",
                            f"scorecard.{key} must equal the requirements count",
                            f"/payload/scorecard/{key}",
                            {"actual": scorecard.get(key), "expected": value},
                        )
                    )
        if isinstance(findings, list):
            critical = sum(
                1
                for finding in findings
                if isinstance(finding, dict)
                and finding.get("severity") == "CRITICAL"
                and finding.get("status") in {"OPEN", "ACKNOWLEDGED"}
            )
            if payload.get("critical_unresolved_count") != critical:
                diagnostics.append(
                    Diagnostic(
                        "CRITICAL_UNRESOLVED_COUNT_MISMATCH",
                        "critical_unresolved_count does not match unresolved CRITICAL findings",
                        "/payload/critical_unresolved_count",
                        {"actual": payload.get("critical_unresolved_count"), "expected": critical},
                    )
                )

    if artifact_type == "StakeholderAlignmentPacket":
        options = payload.get("options")
        option_ids = (
            {
                item["option_id"]
                for item in options
                if isinstance(item, dict) and isinstance(item.get("option_id"), str)
            }
            if isinstance(options, list)
            else set()
        )
        selected = payload.get("selected_option_id")
        if selected is not None and selected not in option_ids:
            diagnostics.append(
                Diagnostic(
                    "SELECTED_ALIGNMENT_OPTION_UNKNOWN",
                    "selected_option_id must identify an assessed alignment option",
                    "/payload/selected_option_id",
                    {"actual": selected, "known": sorted(option_ids)},
                )
            )

    if artifact_type == "ProcessRedesignDecision":
        options = payload.get("options_assessed")
        by_id = (
            {
                item["option_id"]: item
                for item in options
                if isinstance(item, dict) and isinstance(item.get("option_id"), str)
            }
            if isinstance(options, list)
            else {}
        )
        selected = payload.get("selected_option_id")
        selected_option = by_id.get(selected) if isinstance(selected, str) else None
        if selected_option is None:
            diagnostics.append(
                Diagnostic(
                    "SELECTED_PROCESS_OPTION_UNKNOWN",
                    "selected_option_id must identify an assessed process option",
                    "/payload/selected_option_id",
                    {"actual": selected, "known": sorted(by_id)},
                )
            )
        else:
            expected_controls = selected_option.get("control_ids")
            actual_controls = payload.get("controls_preserved")
            expected_set = (
                {item for item in expected_controls if isinstance(item, str)}
                if isinstance(expected_controls, list)
                else set()
            )
            actual_set = (
                {item for item in actual_controls if isinstance(item, str)}
                if isinstance(actual_controls, list)
                else set()
            )
            if actual_set != expected_set:
                diagnostics.append(
                    Diagnostic(
                        "PRESERVED_CONTROL_SET_MISMATCH",
                        "controls_preserved must exactly match the selected option controls",
                        "/payload/controls_preserved",
                        {
                            "missing": sorted(expected_set - actual_set),
                            "extra": sorted(actual_set - expected_set),
                        },
                    )
                )

    if artifact_type == "GoLiveEvidenceBundle":
        gate_diagnostics, _ = _gate_set_diagnostics(
            payload.get("gate_evidence"), path="/payload/gate_evidence"
        )
        diagnostics.extend(gate_diagnostics)

    if artifact_type == "GoLiveDecisionPacket":
        gate_diagnostics, outcomes = _gate_set_diagnostics(
            payload.get("gate_results"),
            path="/payload/gate_results",
            outcome_key="outcome",
        )
        diagnostics.extend(gate_diagnostics)
        expected_gates_by_outcome: dict[str, list[str]] = {
            "failed_gates": sorted(gate for gate, outcome in outcomes.items() if outcome == "FAIL"),
            "blocked_gates": sorted(
                gate for gate, outcome in outcomes.items() if outcome == "BLOCKED"
            ),
            "passed_gates": sorted(gate for gate, outcome in outcomes.items() if outcome == "PASS"),
        }
        for field, expected_gate_ids in expected_gates_by_outcome.items():
            actual_value = payload.get(field)
            actual_gate_ids = (
                sorted(item for item in actual_value if isinstance(item, str))
                if isinstance(actual_value, list)
                else []
            )
            if actual_gate_ids != expected_gate_ids:
                diagnostics.append(
                    Diagnostic(
                        "GATE_PARTITION_MISMATCH",
                        f"{field} does not correspond exactly to gate_results outcomes",
                        f"/payload/{field}",
                        {"actual": actual_gate_ids, "expected": expected_gate_ids},
                    )
                )
        expected_decision = (
            "FAIL"
            if expected_gates_by_outcome["failed_gates"]
            else "BLOCKED"
            if expected_gates_by_outcome["blocked_gates"]
            else "PASS"
        )
        actual_decision = payload.get("final_decision")
        if actual_decision == "PASS" and (
            set(outcomes) != set(GATE_NAMES)
            or any(outcome != "PASS" for outcome in outcomes.values())
        ):
            diagnostics.append(
                Diagnostic(
                    "PASS_REQUIRES_ALL_GATES_PASS",
                    "PASS requires every one of the fourteen gate outcomes to be PASS",
                    "/payload/final_decision",
                )
            )
        if actual_decision != expected_decision:
            diagnostics.append(
                Diagnostic(
                    "FINAL_DECISION_PRECEDENCE_MISMATCH",
                    "final_decision must follow FAIL > BLOCKED > PASS gate precedence",
                    "/payload/final_decision",
                    {"actual": actual_decision, "expected": expected_decision},
                )
            )
        if expected_decision == "PASS":
            expected_status = "APPROVED"
        elif expected_decision == "BLOCKED":
            expected_status = "BLOCKED"
        else:
            expected_status = "REJECTED"
        if artifact.get("status") != expected_status:
            diagnostics.append(
                Diagnostic(
                    "DECISION_STATUS_MISMATCH",
                    "envelope status does not correspond to final_decision",
                    "/status",
                    {"actual": artifact.get("status"), "expected": expected_status},
                )
            )

        if actual_decision == "PASS":
            conditions = payload.get("upstream_conditions")
            open_condition_ids = (
                sorted(
                    cast(str, item.get("condition_id"))
                    for item in conditions
                    if isinstance(item, dict)
                    and item.get("status") == "OPEN"
                    and isinstance(item.get("condition_id"), str)
                )
                if isinstance(conditions, list)
                else []
            )
            if open_condition_ids:
                diagnostics.append(
                    Diagnostic(
                        "PASS_WITH_OPEN_UPSTREAM_CONDITION",
                        "PASS is forbidden while a carried upstream condition remains OPEN",
                        "/payload/upstream_conditions",
                        {"blocking_condition_ids": open_condition_ids},
                    )
                )
            obligations = payload.get("upstream_obligations")
            open_obligation_ids = (
                sorted(
                    cast(str, item.get("obligation_id"))
                    for item in obligations
                    if isinstance(item, dict)
                    and item.get("status") in {"OPEN", "IN_PROGRESS"}
                    and isinstance(item.get("obligation_id"), str)
                )
                if isinstance(obligations, list)
                else []
            )
            if open_obligation_ids:
                diagnostics.append(
                    Diagnostic(
                        "PASS_WITH_OPEN_UPSTREAM_OBLIGATION",
                        "PASS is forbidden while a carried upstream obligation remains open",
                        "/payload/upstream_obligations",
                        {"blocking_obligation_ids": open_obligation_ids},
                    )
                )

        gate_results = payload.get("gate_results")
        union_by_id: dict[str, JSONValue] = {}
        collisions: set[str] = set()
        if isinstance(gate_results, list):
            for gate in gate_results:
                if not isinstance(gate, dict):
                    continue
                actions = gate.get("required_actions")
                if not isinstance(actions, list):
                    continue
                for action in actions:
                    if not isinstance(action, dict) or not isinstance(action.get("action_id"), str):
                        continue
                    action_id = cast(str, action["action_id"])
                    if action_id in union_by_id and digest_json(
                        union_by_id[action_id]
                    ) != digest_json(action):
                        collisions.add(action_id)
                    union_by_id[action_id] = action
        if collisions:
            diagnostics.append(
                Diagnostic(
                    "REQUIRED_ACTION_ID_COLLISION",
                    "the same required action ID has different gate content",
                    "/payload/gate_results",
                    {"action_ids": sorted(collisions)},
                )
            )
        top_actions = payload.get("required_actions")
        actual_by_id = (
            {
                cast(str, action["action_id"]): action
                for action in top_actions
                if isinstance(action, dict) and isinstance(action.get("action_id"), str)
            }
            if isinstance(top_actions, list)
            else {}
        )
        expected_fingerprints = sorted(digest_json(item) for item in union_by_id.values())
        actual_fingerprints = sorted(digest_json(item) for item in actual_by_id.values())
        if expected_fingerprints != actual_fingerprints or (
            isinstance(top_actions, list) and len(actual_by_id) != len(top_actions)
        ):
            diagnostics.append(
                Diagnostic(
                    "REQUIRED_ACTION_UNION_MISMATCH",
                    "top-level required_actions must equal the union of gate required_actions",
                    "/payload/required_actions",
                )
            )
        inputs = artifact.get("inputs")
        if isinstance(inputs, list) and len(inputs) == 1 and isinstance(inputs[0], dict):
            reference = inputs[0]
            if not _same_digest(payload.get("evidence_bundle_sha256"), reference.get("sha256")):
                diagnostics.append(
                    Diagnostic(
                        "EVIDENCE_BUNDLE_DIGEST_MISMATCH",
                        "evidence_bundle_sha256 must equal the sole input sha256",
                        "/payload/evidence_bundle_sha256",
                    )
                )
            if not _same_digest(
                payload.get("portfolio_chain_sha256"), reference.get("chain_sha256")
            ):
                diagnostics.append(
                    Diagnostic(
                        "PORTFOLIO_CHAIN_REFERENCE_MISMATCH",
                        "portfolio_chain_sha256 must equal the sole input chain_sha256",
                        "/payload/portfolio_chain_sha256",
                    )
                )

    return tuple(diagnostics)


def _evidence_semantic_diagnostics(document: Mapping[str, JSONValue]) -> tuple[Diagnostic, ...]:
    """Verify every nested EvidenceReference quote digest and ordered range."""

    diagnostics: list[Diagnostic] = []

    def walk(value: JSONValue, path: str) -> None:
        if isinstance(value, list):
            for index, item in enumerate(value):
                walk(item, f"{path}/{index}")
            return
        if not isinstance(value, dict):
            return

        quote = value.get("exact_quote")
        declared_quote_digest = value.get("quote_sha256")
        if isinstance(quote, str) and isinstance(declared_quote_digest, str):
            computed_quote_digest = sha256_bytes(quote.encode("utf-8"))
            if not hmac.compare_digest(declared_quote_digest, computed_quote_digest):
                diagnostics.append(
                    Diagnostic(
                        "EVIDENCE_QUOTE_DIGEST_MISMATCH",
                        "quote_sha256 must equal SHA-256 of the exact UTF-8 quote",
                        f"{path}/quote_sha256",
                        {
                            "computed": computed_quote_digest,
                            "declared": declared_quote_digest,
                        },
                    )
                )

        location = value.get("location")
        if isinstance(location, dict):
            for start_key, end_key in (
                ("start_line", "end_line"),
                ("start_character", "end_character"),
            ):
                start = location.get(start_key)
                end = location.get(end_key)
                if isinstance(start, int) and isinstance(end, int) and end < start:
                    diagnostics.append(
                        Diagnostic(
                            "EVIDENCE_RANGE_INVERTED",
                            f"{end_key} cannot precede {start_key}",
                            f"{path}/location/{end_key}",
                            {"end": end, "start": start},
                        )
                    )

        for key, nested in value.items():
            encoded_key = key.replace("~", "~0").replace("/", "~1")
            walk(nested, f"{path}/{encoded_key}")

    walk(cast(JSONValue, dict(document)), "")
    return tuple(diagnostics)


def validate_document(
    document: Mapping[str, JSONValue],
    *,
    contract: str | Path | None = None,
    root: str | Path | None = None,
    verify_integrity: bool = True,
) -> ValidationResult:
    """Validate one document and, for artifacts, recompute required digests."""

    catalog = ContractCatalog(root)
    catalog.verify_registry_reconciliation()
    schema = catalog.resolve_schema(contract, document=document)
    catalog.validate_schema_document(document, schema)

    artifact_sha: str | None = None
    payload_sha: str | None = None
    artifact_id = document.get("artifact_id")
    if verify_integrity and isinstance(artifact_id, str):
        artifact_sha, payload_sha = verify_artifact_integrity(document, catalog=catalog)
    elif verify_integrity:
        diagnostics = list(_evidence_semantic_diagnostics(document))
        if schema.relative_path.endswith("agent-event.v1.schema.json"):
            from .events import verify_event_digest

            try:
                verify_event_digest(document)
            except EventValidationError as exc:
                diagnostics.extend(exc.diagnostics)
        if diagnostics:
            raise ArtifactValidationError(
                "portable evidence semantic verification failed",
                diagnostics=tuple(diagnostics),
            )
    return ValidationResult(
        schema_path=schema.relative_path,
        artifact_id=artifact_id if isinstance(artifact_id, str) else None,
        artifact_sha256=artifact_sha,
        payload_sha256=payload_sha,
    )


def validate_file(
    path: str | Path,
    *,
    contract: str | Path | None = None,
    root: str | Path | None = None,
    verify_integrity: bool = True,
) -> ValidationResult:
    """Strictly load and validate one file."""

    raw = load_json(path)
    if not isinstance(raw, dict):
        raise SchemaValidationError(f"contract document must be an object: {path}")
    return validate_document(
        cast(Mapping[str, JSONValue], raw),
        contract=contract,
        root=root,
        verify_integrity=verify_integrity,
    )


def raw_file_sha256(path: str | Path) -> str:
    """Return a file-byte SHA-256 for provenance tooling (not artifact identity)."""

    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except OSError as exc:
        raise ResourceError(f"cannot read file for SHA-256: {path}") from exc
