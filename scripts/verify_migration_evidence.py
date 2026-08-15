"""Verify the committed G0 identity evidence without external network access."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "docs" / "migration" / "identity-manifest.json"
SHA1 = re.compile(r"[0-9a-f]{40}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
MARKDOWN_LINK = re.compile(r"(?<!!)\[[^]]+\]\(([^)]+)\)")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def git(*args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(ROOT), *args], text=True, stderr=subprocess.STDOUT
    ).strip()


def verify_relative_markdown_links() -> None:
    excluded = {".git", ".venv", "build", "dist"}
    for document in ROOT.rglob("*.md"):
        if any(part in excluded for part in document.parts):
            continue
        text = document.read_text(encoding="utf-8")
        for match in MARKDOWN_LINK.finditer(text):
            target = match.group(1).strip().split(maxsplit=1)[0].strip("<>")
            if target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            relative = unquote(target.split("#", maxsplit=1)[0])
            if relative:
                require(
                    (document.parent / relative).exists(),
                    f"broken relative link in {document.relative_to(ROOT)}: {target}",
                )


def main() -> None:
    raw = MANIFEST.read_bytes()
    data = json.loads(raw)
    require(data["schema_version"] == "1.0", "unsupported manifest schema")

    source = data["source"]
    for field in ("commit", "tree"):
        require(SHA1.fullmatch(source[field]) is not None, f"invalid source {field}")
    require(
        git("rev-parse", f"{source['commit']}^{{tree}}") == source["tree"],
        "source commit/tree mismatch",
    )
    require(source["commit_signature"]["status"] == "VERIFIED", "commit is not verified")

    release = data["release_v1_0_0"]
    require(git("rev-parse", "v1.0.0^{tag}") == release["tag_object"], "tag object mismatch")
    require(
        git("rev-parse", "v1.0.0^{commit}") == release["tag_commit"],
        "release commit mismatch",
    )
    require(git("rev-parse", "v1.0.0^{tree}") == release["tag_tree"], "release tree mismatch")
    for name, digest in release["assets"].items():
        require(SHA256.fullmatch(digest) is not None, f"invalid {name} digest")

    backup = data["backup"]
    require(SHA256.fullmatch(backup["sha256"]) is not None, "invalid backup digest")
    require(backup["complete_history"] is True, "backup is not complete")
    require(backup["restore_rehearsal"] == "PASS", "backup restore did not pass")

    inventory = data["reference_inventory"]
    repositories = inventory["repositories_scanned"]
    require(len(repositories) == 7, "expected seven repository snapshots")
    require(
        sum(item["hosted_action_reference_files"] for item in repositories) == 0,
        "hosted Action dependency found",
    )
    require(len(inventory["direct_consumer_references"]) == 1, "consumer inventory mismatch")
    consumer = inventory["direct_consumer_references"][0]
    require(len(consumer["paths"]) == 10, "consumer path inventory mismatch")

    decision = data["decision"]
    require(decision["feasibility_verdict"] == "PASS", "feasibility is not PASS")
    require(decision["execution_verdict"] == "BLOCKED", "rename must remain BLOCKED")
    require(data["target"]["execution_status"] == "BLOCKED", "target mutation is not blocked")
    verify_relative_markdown_links()

    print(f"G0_IDENTITY_MANIFEST=PASS sha256={hashlib.sha256(raw).hexdigest()}")


if __name__ == "__main__":
    main()
