"""Strict JSON loading, RFC 8785 canonicalisation, and digest profiles.

The public digest profile is ``TPC-JCS-SHA256-v1``.  An artifact digest is the
SHA-256 of its RFC 8785 (JCS) representation after removing *only* the
top-level ``artifact_sha256`` and ``chain_sha256`` members.  In particular,
``payload_sha256`` and all upstream-reference digests remain in the signed
projection.  Removing members recursively would erase lineage and is never
performed.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import math
import re
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any, TypeAlias, cast

from .errors import CanonicalizationError, JSONInputError

try:  # The declared runtime dependency provides complete ECMAScript numbers.
    rfc8785: Any = importlib.import_module("rfc8785")
except ImportError:  # pragma: no cover - exercised only in minimal bootstraps.
    rfc8785 = None


JSONScalar: TypeAlias = bool | int | float | str | None
JSONValue: TypeAlias = JSONScalar | list["JSONValue"] | dict[str, "JSONValue"]

DIGEST_PROFILE = "TPC-JCS-SHA256-v1"
SELF_REFERENTIAL_DIGEST_FIELDS = frozenset({"artifact_sha256", "chain_sha256"})
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_MAX_EXACT_INTEGER = 9_007_199_254_740_991


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number {value!r} is forbidden")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate object member {key!r} is forbidden")
        result[key] = value
    return result


def loads_json(data: str | bytes, *, source: str = "<memory>") -> JSONValue:
    """Load strict JSON, rejecting duplicate members and non-finite numbers."""

    try:
        value = json.loads(
            data,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise JSONInputError(f"invalid strict JSON in {source}: {exc}") from exc
    return cast(JSONValue, value)


def load_json(path: str | Path) -> JSONValue:
    """Read a UTF-8 strict JSON document from ``path``."""

    resolved = Path(path)
    try:
        raw = resolved.read_bytes()
    except OSError as exc:
        raise JSONInputError(f"cannot read JSON input {resolved}: {exc}") from exc
    # JSON exchanged by this specification is UTF-8 and must not depend on a
    # platform locale.  utf-8-sig accepts a transport BOM without preserving it.
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise JSONInputError(f"JSON input is not UTF-8: {resolved}") from exc
    return loads_json(text, source=str(resolved))


def _validate_unicode(value: str) -> None:
    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise CanonicalizationError("JCS forbids unpaired Unicode surrogate code points")


def _fallback_jcs(value: JSONValue) -> str:
    """Bounded JCS fallback for integer-only bootstrap documents.

    The project depends on :mod:`rfc8785` for complete ECMAScript number
    serialisation.  This fallback deliberately rejects floats rather than
    silently emitting a representation that might not be RFC 8785 compliant.
    """

    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        _validate_unicode(value)
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, int):
        if abs(value) > _MAX_EXACT_INTEGER:
            raise CanonicalizationError(
                "integer is outside the RFC 8785/I-JSON exact range; install rfc8785"
            )
        return str(value)
    if isinstance(value, float):
        if not math.isfinite(value):
            raise CanonicalizationError("JCS forbids NaN and infinite numbers")
        raise CanonicalizationError("floating-point JCS requires the declared rfc8785 dependency")
    if isinstance(value, list):
        return "[" + ",".join(_fallback_jcs(item) for item in value) + "]"
    if isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                raise CanonicalizationError("JSON object members must have string names")
            _validate_unicode(key)
        # UTF-16 code-unit order is required by RFC 8785.  Encoding as
        # UTF-16BE provides precisely that order for Unicode scalar values.
        keys = sorted(value, key=lambda item: item.encode("utf-16-be"))
        return (
            "{"
            + ",".join(f"{_fallback_jcs(key)}:{_fallback_jcs(value[key])}" for key in keys)
            + "}"
        )
    raise CanonicalizationError(f"value of type {type(value).__name__} is not JSON")


def canonicalize(value: JSONValue) -> bytes:
    """Return the RFC 8785 canonical byte representation of ``value``."""

    if rfc8785 is None:
        return _fallback_jcs(value).encode("utf-8")
    try:
        result = rfc8785.dumps(value)
    except Exception as exc:  # rfc8785 exposes several input-specific errors.
        raise CanonicalizationError(f"value is outside the RFC 8785 domain: {exc}") from exc
    return result if isinstance(result, bytes) else str(result).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    """Return a lowercase, unprefixed SHA-256 hexadecimal digest."""

    return hashlib.sha256(data).hexdigest()


def digest_json(value: JSONValue) -> str:
    """Return the RFC 8785/JCS SHA-256 digest of any JSON value."""

    return sha256_bytes(canonicalize(value))


def artifact_projection(
    artifact: Mapping[str, JSONValue],
    *,
    excluded_fields: Iterable[str] = SELF_REFERENTIAL_DIGEST_FIELDS,
) -> dict[str, JSONValue]:
    """Build the non-mutating top-level projection used by the digest profile."""

    excluded = frozenset(excluded_fields)
    return {key: value for key, value in artifact.items() if key not in excluded}


def artifact_digest(artifact: Mapping[str, JSONValue]) -> str:
    """Compute an artifact digest under :data:`DIGEST_PROFILE`."""

    return digest_json(artifact_projection(artifact))


def payload_digest(artifact_or_payload: Mapping[str, JSONValue] | JSONValue) -> str:
    """Compute a payload digest from an artifact or a raw JSON payload."""

    if isinstance(artifact_or_payload, Mapping) and "payload" in artifact_or_payload:
        value = artifact_or_payload["payload"]
    else:
        value = cast(JSONValue, artifact_or_payload)
    return digest_json(value)


def is_sha256(value: object) -> bool:
    """Return whether ``value`` is a lowercase, unprefixed SHA-256 digest."""

    return isinstance(value, str) and SHA256_PATTERN.fullmatch(value) is not None
