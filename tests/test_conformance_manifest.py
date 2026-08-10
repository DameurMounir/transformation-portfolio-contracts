from __future__ import annotations

import json
from pathlib import Path

import pytest

from transformation_portfolio_contracts.cli import _load_conformance_manifest
from transformation_portfolio_contracts.errors import ConformanceError


def _write_manifest(tmp_path: Path, value: object) -> Path:
    expected = tmp_path / "expected-results"
    expected.mkdir(parents=True, exist_ok=True)
    (expected / "manifest.json").write_text(json.dumps(value), encoding="utf-8")
    return expected


def test_manifest_accepts_exact_partitions_and_multiple_required_codes(tmp_path: Path) -> None:
    expected = _write_manifest(
        tmp_path,
        {
            "valid_fixtures": [{"fixture": "valid.json", "expected": "VALID"}],
            "cases": [
                {
                    "fixture": "invalid.json",
                    "expected": "INVALID",
                    "expected_error": ["CODE-B", "CODE-A", "CODE-A"],
                }
            ],
        },
    )
    result = _load_conformance_manifest(
        expected, [tmp_path / "valid.json"], [tmp_path / "invalid.json"]
    )
    assert result == {"invalid.json": ("CODE-A", "CODE-B")}


@pytest.mark.parametrize(
    ("manifest", "message"),
    [
        ([], "must be an object"),
        ({}, "requires valid_fixtures"),
        (
            {
                "valid_fixtures": [{"fixture": "valid.json", "expected": "INVALID"}],
                "cases": [],
            },
            "invalid valid_fixtures",
        ),
        (
            {
                "valid_fixtures": [],
                "cases": [{"fixture": "invalid.json", "expected": "VALID"}],
            },
            "invalid cases",
        ),
        (
            {
                "valid_fixtures": [],
                "cases": [{"fixture": "invalid.json", "expected": "INVALID"}],
            },
            "must declare nonempty expected_error",
        ),
    ],
)
def test_manifest_rejects_malformed_verdicts(
    tmp_path: Path, manifest: object, message: str
) -> None:
    expected = _write_manifest(tmp_path, manifest)
    with pytest.raises(ConformanceError, match=message):
        _load_conformance_manifest(expected, [tmp_path / "valid.json"], [tmp_path / "invalid.json"])


def test_manifest_rejects_missing_multiple_and_duplicate_verdicts(tmp_path: Path) -> None:
    with pytest.raises(ConformanceError, match="exactly one"):
        _load_conformance_manifest(
            tmp_path / "missing", [tmp_path / "valid.json"], [tmp_path / "invalid.json"]
        )

    expected = _write_manifest(
        tmp_path,
        {
            "valid_fixtures": [],
            "cases": [
                {
                    "fixture": "invalid.json",
                    "expected": "INVALID",
                    "expected_error": "CODE-A",
                },
                {
                    "fixture": "invalid.json",
                    "expected": "INVALID",
                    "expected_error": "CODE-B",
                },
            ],
        },
    )
    with pytest.raises(ConformanceError, match="duplicate invalid"):
        _load_conformance_manifest(expected, [], [tmp_path / "invalid.json"])

    (expected / "second.json").write_text("{}", encoding="utf-8")
    with pytest.raises(ConformanceError, match="exactly one"):
        _load_conformance_manifest(expected, [], [tmp_path / "invalid.json"])


def test_manifest_rejects_duplicate_crossed_and_orphan_partitions(tmp_path: Path) -> None:
    duplicate_valid = _write_manifest(
        tmp_path,
        {
            "valid_fixtures": [
                {"fixture": "valid.json", "expected": "VALID"},
                {"fixture": "valid.json", "expected": "VALID"},
            ],
            "cases": [],
        },
    )
    with pytest.raises(ConformanceError, match="duplicate valid"):
        _load_conformance_manifest(duplicate_valid, [tmp_path / "valid.json"], [])

    crossed_root = tmp_path / "crossed"
    crossed = _write_manifest(
        crossed_root,
        {
            "valid_fixtures": [{"fixture": "same.json", "expected": "VALID"}],
            "cases": [
                {
                    "fixture": "same.json",
                    "expected": "INVALID",
                    "expected_error": "CODE-A",
                }
            ],
        },
    )
    with pytest.raises(ConformanceError, match="both VALID and INVALID"):
        _load_conformance_manifest(crossed, [tmp_path / "valid.json"], [tmp_path / "invalid.json"])

    orphan_root = tmp_path / "orphan"
    orphan = _write_manifest(
        orphan_root,
        {
            "valid_fixtures": [{"fixture": "orphan.json", "expected": "VALID"}],
            "cases": [],
        },
    )
    with pytest.raises(ConformanceError) as partition:
        _load_conformance_manifest(orphan, [tmp_path / "valid.json"], [])
    assert {item.code for item in partition.value.diagnostics} == {
        "CONFORMANCE_MANIFEST_PARTITION_MISMATCH"
    }


def test_manifest_rejects_ambiguous_actual_basenames(tmp_path: Path) -> None:
    expected = _write_manifest(
        tmp_path,
        {"valid_fixtures": [], "cases": []},
    )
    with pytest.raises(ConformanceError, match="unique per partition"):
        _load_conformance_manifest(
            expected,
            [tmp_path / "one" / "same.json", tmp_path / "two" / "same.json"],
            [],
        )
    with pytest.raises(ConformanceError, match="must not share"):
        _load_conformance_manifest(expected, [tmp_path / "same.json"], [tmp_path / "same.json"])
