from __future__ import annotations

import json
from pathlib import Path

import pytest

import transformation_portfolio_contracts.canonical as canonical_module
from transformation_portfolio_contracts.canonical import (
    DIGEST_PROFILE,
    artifact_digest,
    artifact_projection,
    canonicalize,
    digest_json,
    is_sha256,
    load_json,
    loads_json,
    payload_digest,
    sha256_bytes,
)
from transformation_portfolio_contracts.errors import CanonicalizationError, JSONInputError


def test_digest_profile_is_frozen() -> None:
    assert DIGEST_PROFILE == "TPC-JCS-SHA256-v1"


def test_canonicalization_is_order_independent_and_utf8() -> None:
    left = {"z": 1, "a": "é", "nested": {"b": True, "a": None}}
    right = {"nested": {"a": None, "b": True}, "a": "é", "z": 1}

    assert canonicalize(left) == canonicalize(right)
    assert canonicalize(left).decode("utf-8") == '{"a":"é","nested":{"a":null,"b":true},"z":1}'
    assert digest_json(left) == digest_json(right)


def test_strict_loader_rejects_duplicate_members_and_nonfinite_numbers() -> None:
    with pytest.raises(JSONInputError, match="duplicate object member"):
        loads_json('{"same": 1, "same": 2}')
    with pytest.raises(JSONInputError, match="non-finite"):
        loads_json('{"value": NaN}')
    with pytest.raises(JSONInputError, match="invalid strict JSON"):
        loads_json("{")


def test_strict_loader_reports_invalid_utf8_and_missing_files(tmp_path: Path) -> None:
    invalid = tmp_path / "invalid.json"
    invalid.write_bytes(b"\xff")
    with pytest.raises(JSONInputError, match="not UTF-8"):
        load_json(invalid)
    with pytest.raises(JSONInputError, match="cannot read"):
        load_json(tmp_path / "missing.json")


def test_strict_loader_accepts_utf8_bom(tmp_path: Path) -> None:
    document = tmp_path / "bom.json"
    document.write_bytes(b"\xef\xbb\xbf" + json.dumps({"ok": True}).encode())
    assert load_json(document) == {"ok": True}


def test_artifact_projection_excludes_only_top_level_self_digests() -> None:
    artifact = {
        "artifact_sha256": "a" * 64,
        "chain_sha256": "b" * 64,
        "payload_sha256": "c" * 64,
        "payload": {"artifact_sha256": "preserved"},
    }

    assert artifact_projection(artifact) == {
        "payload_sha256": "c" * 64,
        "payload": {"artifact_sha256": "preserved"},
    }
    assert artifact_digest(artifact) == digest_json(artifact_projection(artifact))
    assert artifact_projection(artifact, excluded_fields=["payload_sha256"]) == {
        "artifact_sha256": "a" * 64,
        "chain_sha256": "b" * 64,
        "payload": {"artifact_sha256": "preserved"},
    }


def test_payload_digest_accepts_artifact_or_payload() -> None:
    payload = {"value": [1, 2, 3]}
    assert payload_digest({"payload": payload}) == payload_digest(payload)
    assert payload_digest([1, 2]) == digest_json([1, 2])


def test_sha256_helpers_are_lowercase_and_strict() -> None:
    digest = sha256_bytes(b"portfolio")
    assert digest == "0e6a8e0b849ed9b064c5a25e1ee5592f427e3eb9d250e42069ce46147d00e8d4"
    assert is_sha256(digest)
    assert not is_sha256(digest.upper())
    assert not is_sha256("0" * 63)
    assert not is_sha256(123)


def test_canonicalization_rejects_non_json_values_and_surrogates() -> None:
    with pytest.raises(CanonicalizationError):
        canonicalize({"bad": {1, 2}})  # type: ignore[dict-item]
    with pytest.raises(CanonicalizationError):
        canonicalize({"bad": "\ud800"})


def test_bounded_fallback_canonicalizer_covers_the_complete_bootstrap_domain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(canonical_module, "rfc8785", None)
    value = {
        "z": [None, True, False, 7, "é"],
        "😀": {"a": 1},
    }
    assert canonicalize(value).decode("utf-8") == '{"z":[null,true,false,7,"é"],"😀":{"a":1}}'

    with pytest.raises(CanonicalizationError, match="exact range"):
        canonicalize(9_007_199_254_740_992)
    with pytest.raises(CanonicalizationError, match="floating-point"):
        canonicalize(1.5)
    with pytest.raises(CanonicalizationError, match="NaN and infinite"):
        canonicalize(float("inf"))
    with pytest.raises(CanonicalizationError, match="string names"):
        canonicalize({1: "bad"})  # type: ignore[dict-item]
    with pytest.raises(CanonicalizationError, match="surrogate"):
        canonicalize({"\ud800": "bad"})
    with pytest.raises(CanonicalizationError, match="not JSON"):
        canonicalize({1, 2})  # type: ignore[arg-type]


def test_declared_canonicalizer_errors_and_string_results_are_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class StringCanonicalizer:
        @staticmethod
        def dumps(value: object) -> str:
            return "canonical"

    monkeypatch.setattr(canonical_module, "rfc8785", StringCanonicalizer())
    assert canonicalize({"a": 1}) == b"canonical"

    class BrokenCanonicalizer:
        @staticmethod
        def dumps(value: object) -> bytes:
            raise ValueError("outside domain")

    monkeypatch.setattr(canonical_module, "rfc8785", BrokenCanonicalizer())
    with pytest.raises(CanonicalizationError, match="outside the RFC 8785 domain"):
        canonicalize({"a": 1})
