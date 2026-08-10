#!/usr/bin/env bash
# Build, verify, and optionally publish transformation-portfolio-contracts v1.0.0.
#
# Exactly one source must be supplied:
#   SOURCE_DIR=/absolute/existing/repository
# or
#   SOURCE_TARBALL=/absolute/source.tar.gz
#   SOURCE_TARBALL_SHA256=<lowercase sha256>
#
# Verification is the default and has no Git/GitHub publication effect:
#   SOURCE_DIR=/absolute/transformation-portfolio-contracts \
#     bash build_and_publish_transformation_portfolio_contracts_v1.0.0.sh
#
# Publication additionally requires:
#   PUBLISH=1
#   EXPECTED_REMOTE_MAIN=EMPTY|<exact 40-character commit SHA>
#   CREATE_REMOTE=0|1  # 1 is required only when the GitHub repository does not exist
#
# A successful publication ends in SOURCE_TAG_PUBLISHED_RELEASE_PENDING. GitHub Actions must still
# build, attest, and publish the release assets; this transaction does not claim those later gates.
#
# The transaction never deletes or replaces a source/target directory, rewrites history, force
# pushes, rebases, or resets. Every missing or conflicting prerequisite stops execution.

set -Eeuo pipefail
IFS=$'\n\t'
umask 027

readonly PROJECT_NAME="transformation-portfolio-contracts"
readonly PACKAGE_NAME="transformation_portfolio_contracts"
readonly EXPECTED_VERSION="1.0.0"
readonly EXPECTED_TAG="v${EXPECTED_VERSION}"
readonly EXPECTED_REPOSITORY="DameurMounir/transformation-portfolio-contracts"
readonly EXPECTED_SETUPTOOLS_SPEC="setuptools>=83,<84"
readonly EXPECTED_HTTPS_REMOTE="https://github.com/DameurMounir/transformation-portfolio-contracts.git"
readonly EXPECTED_SSH_REMOTE="git@github.com:DameurMounir/transformation-portfolio-contracts.git"
readonly DEFAULT_TARGET_DIR="/home/dameurmounir/development/tech/ai-engineering/labs/sherizon-labs/transformation-portfolio-contracts"
readonly DEFAULT_EVIDENCE_ROOT="/home/dameurmounir/development/artifacts/transformation-portfolio-contracts/v1.0.0"

PUBLISH="${PUBLISH:-0}"
CREATE_REMOTE="${CREATE_REMOTE:-0}"
EXPECTED_REMOTE_MAIN="${EXPECTED_REMOTE_MAIN:-}"
SOURCE_DIR="${SOURCE_DIR:-}"
SOURCE_TARBALL="${SOURCE_TARBALL:-}"
SOURCE_TARBALL_SHA256="${SOURCE_TARBALL_SHA256:-}"
TARGET_DIR="${TARGET_DIR:-$DEFAULT_TARGET_DIR}"
EVIDENCE_ROOT="${EVIDENCE_ROOT:-$DEFAULT_EVIDENCE_ROOT}"
PYTHON_BIN="${PYTHON_BIN:-python3}"
GIT_COMMIT_MESSAGE="${GIT_COMMIT_MESSAGE:-feat: publish transformation portfolio contracts v1.0.0}"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
EVIDENCE_DIR="${EVIDENCE_ROOT%/}/${RUN_ID}"
STATE_FILE="${EVIDENCE_DIR}/transaction-state.txt"
LOG_FILE="${EVIDENCE_DIR}/transaction.log"
CURRENT_PHASE="INITIALIZATION"

die() {
  local message="$1"
  printf 'ERROR: %s\n' "$message" >&2
  if [[ -d "$EVIDENCE_DIR" ]]; then
    printf 'FAILED phase=%s message=%s\n' "$CURRENT_PHASE" "$message" >"$STATE_FILE"
  fi
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command is unavailable: $1"
}

on_error() {
  local exit_code="$1"
  local line_number="$2"
  trap - ERR
  printf 'FAILED phase=%s line=%s exit=%s\n' \
    "$CURRENT_PHASE" "$line_number" "$exit_code" >"$STATE_FILE"
  printf 'Transaction failed closed in phase %s at line %s (exit %s).\n' \
    "$CURRENT_PHASE" "$line_number" "$exit_code" >&2
  exit "$exit_code"
}

run_gate() {
  local gate_name="$1"
  shift
  local gate_log="${EVIDENCE_DIR}/${gate_name}.log"
  local exit_code

  printf '\n>>> GATE %s\n' "$gate_name"
  set +e
  "$@" 2>&1 | tee "$gate_log"
  exit_code="${PIPESTATUS[0]}"
  set -e
  if [[ "$exit_code" -ne 0 ]]; then
    printf 'Gate %s failed with exit %s.\n' "$gate_name" "$exit_code" >&2
    return "$exit_code"
  fi
  printf '<<< PASS %s\n' "$gate_name"
}

canonical_path() {
  realpath -m -- "$1"
}

validate_boolean() {
  local name="$1"
  local value="$2"
  [[ "$value" == "0" || "$value" == "1" ]] || die "$name must be exactly 0 or 1"
}

validate_remote_url() {
  local remote_url="$1"
  [[ "$remote_url" == "$EXPECTED_HTTPS_REMOTE" || "$remote_url" == "$EXPECTED_SSH_REMOTE" ]] || \
    die "origin does not resolve to the exact authorized GitHub repository: $remote_url"
}

validate_target_path() {
  local canonical_target
  canonical_target="$(canonical_path "$TARGET_DIR")"
  [[ "$canonical_target" != "/" ]] || die "TARGET_DIR cannot be the filesystem root"
  [[ "${canonical_target##*/}" == "$PROJECT_NAME" ]] || \
    die "TARGET_DIR basename must be exactly $PROJECT_NAME"
  TARGET_DIR="$canonical_target"
}

extract_verified_tarball() {
  local archive_path="$1"
  local destination_path="$2"

  "$PYTHON_BIN" - "$archive_path" "$destination_path" <<'PY'
from __future__ import annotations

import shutil
import stat
import sys
import tarfile
from pathlib import Path, PurePosixPath

archive = Path(sys.argv[1]).resolve(strict=True)
destination = Path(sys.argv[2]).resolve(strict=False)
if destination.exists():
    raise SystemExit(f"target already exists; preservation rule blocks extraction: {destination}")

with tarfile.open(archive, mode="r:*") as source:
    members = source.getmembers()
    if not members:
        raise SystemExit("source tarball is empty")
    if len(members) > 20_000:
        raise SystemExit("source tarball exceeds the 20,000-member safety limit")
    if sum(member.size for member in members if member.isreg()) > 268_435_456:
        raise SystemExit("source tarball exceeds the 256 MiB uncompressed safety limit")

    parsed: list[tuple[tarfile.TarInfo, PurePosixPath]] = []
    first_parts: set[str] = set()
    has_nested_member = False
    for member in members:
        path = PurePosixPath(member.name)
        if not member.name or path.is_absolute() or ".." in path.parts:
            raise SystemExit(f"unsafe archive path: {member.name!r}")
        if not path.parts or ".git" in path.parts:
            raise SystemExit(f"forbidden archive member: {member.name!r}")
        if not (member.isdir() or member.isreg()):
            raise SystemExit(f"links, devices, and special files are forbidden: {member.name!r}")
        first_parts.add(path.parts[0])
        has_nested_member = has_nested_member or len(path.parts) > 1
        parsed.append((member, path))

    strip_one = len(first_parts) == 1 and has_nested_member
    relative_names: set[tuple[str, ...]] = set()
    for member, source_path in parsed:
        relative_parts = source_path.parts[1:] if strip_one else source_path.parts
        if not relative_parts:
            continue
        if relative_parts in relative_names:
            raise SystemExit(f"duplicate archive target: {member.name!r}")
        relative_names.add(relative_parts)

    destination.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    destination.mkdir(mode=0o750, exist_ok=False)
    destination_root = destination.resolve(strict=True)

    for member, source_path in parsed:
        relative_parts = source_path.parts[1:] if strip_one else source_path.parts
        if not relative_parts:
            continue
        target = destination.joinpath(*relative_parts)
        resolved_parent = target.parent.resolve(strict=False)
        if destination_root != resolved_parent and destination_root not in resolved_parent.parents:
            raise SystemExit(f"archive member escapes target: {member.name!r}")
        if member.isdir():
            target.mkdir(mode=0o750, parents=True, exist_ok=True)
            continue
        target.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
        file_object = source.extractfile(member)
        if file_object is None:
            raise SystemExit(f"unable to read archive member: {member.name!r}")
        with file_object, target.open("xb") as output:
            shutil.copyfileobj(file_object, output)
        executable = bool(member.mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
        target.chmod(0o750 if executable else 0o640)
PY
}

verify_project_metadata() {
  "$PYTHON_BIN" - \
    "$WORK_DIR/pyproject.toml" "$EXPECTED_VERSION" "$PROJECT_NAME" \
    "$EXPECTED_SETUPTOOLS_SPEC" <<'PY'
from __future__ import annotations

import sys
import tomllib
from pathlib import Path

pyproject = Path(sys.argv[1])
expected_version = sys.argv[2]
expected_name = sys.argv[3]
expected_setuptools = sys.argv[4]
with pyproject.open("rb") as stream:
    document = tomllib.load(stream)
project = document["project"]
if project.get("name") != expected_name:
    raise SystemExit(f"unexpected project name: {project.get('name')!r}")
if project.get("version") != expected_version:
    raise SystemExit(f"unexpected project version: {project.get('version')!r}")
requires_python = project.get("requires-python", "")
if requires_python != ">=3.11,<3.14":
    raise SystemExit(f"unexpected Python support declaration: {requires_python!r}")
build_requirements = document.get("build-system", {}).get("requires", [])
if expected_setuptools not in build_requirements:
    raise SystemExit(
        f"build system must require the audited range {expected_setuptools!r}: "
        f"{build_requirements!r}"
    )
PY
}

verify_github_metadata() {
  local metadata_file="$1"
  local require_main="${2:-0}"
  "$PYTHON_BIN" - "$metadata_file" "$EXPECTED_REPOSITORY" "$require_main" <<'PY'
from __future__ import annotations

import json
import sys
from pathlib import Path

metadata = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
expected = sys.argv[2]
require_main = sys.argv[3] == "1"
if metadata.get("nameWithOwner") != expected:
    raise SystemExit(f"wrong repository identity: {metadata.get('nameWithOwner')!r}")
if metadata.get("visibility") != "PUBLIC":
    raise SystemExit(f"repository must be PUBLIC, got {metadata.get('visibility')!r}")
if metadata.get("isArchived") is not False:
    raise SystemExit("repository is archived")
default_branch = metadata.get("defaultBranchRef")
if default_branch is not None and (
    not isinstance(default_branch, dict) or default_branch.get("name") != "main"
):
    raise SystemExit(f"repository default branch must be main: {default_branch!r}")
if require_main and default_branch is None:
    raise SystemExit(f"repository has no verified main default branch: {default_branch!r}")
PY
}

verify_installed_catalog_root() {
  local catalog_json="$1"
  local expected_root="$2"

  "$PYTHON_BIN" - "$catalog_json" "$expected_root" <<'PY'
from __future__ import annotations

import json
import sys
from pathlib import Path

catalog_path = Path(sys.argv[1])
expected = Path(sys.argv[2]).resolve(strict=True)
document = json.loads(catalog_path.read_text(encoding="utf-8"))
actual_value = document.get("root")
if not isinstance(actual_value, str):
    raise SystemExit("installed-wheel catalog JSON has no string root")
actual = Path(actual_value).resolve(strict=True)
if actual != expected:
    raise SystemExit(f"installed-wheel catalog resolved the wrong resource root: {actual} != {expected}")
PY
}

write_source_inventory() {
  local output_path="$1"
  (
    cd "$WORK_DIR"
    find . -type f \
      -not -path './.git' \
      -not -path './.git/*' \
      -not -path './build/*' \
      -not -path './dist/*' \
      -not -path '*.egg-info/*' \
      -not -path './.venv/*' \
      -not -path './.venv-*/*' \
      -not -path './venv/*' \
      -not -path './.tox/*' \
      -not -path './.nox/*' \
      -not -path '*/__pycache__/*' \
      -not -path './.pytest_cache/*' \
      -not -path './.mypy_cache/*' \
      -not -path './.ruff_cache/*' \
      -not -path './.pip-audit-cache/*' \
      -not -name '.coverage' \
      -not -name 'coverage.xml' \
      -not -name '*.pyc' \
      -print0 | sort -z | xargs -0 sha256sum
  ) >"$output_path"
}

verify_git_scope() {
  "$PYTHON_BIN" - "$WORK_DIR" <<'PY'
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

root = Path(sys.argv[1])
allowed_files = {
    ".editorconfig",
    ".gitignore",
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "LICENSE",
    "MANIFEST.in",
    "Makefile",
    "README.md",
    "SECURITY.md",
    "build_and_publish_transformation_portfolio_contracts_v1.0.0.sh",
    "pyproject.toml",
    "setup.py",
}
allowed_directories = {
    ".github",
    "conformance",
    "docs",
    "examples",
    "registry",
    "schemas",
    "src",
    "tests",
}

def is_allowed(path_text: str) -> bool:
    path = Path(path_text)
    if path.name in {"", ".", ".."} or ".." in path.parts:
        return False
    return path_text in allowed_files or path.parts[0] in allowed_directories


tracked = subprocess.run(
    ["git", "ls-files", "--stage", "-z"],
    cwd=root,
    check=True,
    stdout=subprocess.PIPE,
)
for raw_entry in tracked.stdout.split(b"\0"):
    if not raw_entry:
        continue
    metadata, separator, raw_path = raw_entry.partition(b"\t")
    if not separator:
        raise SystemExit("cannot parse staged Git inventory")
    mode = metadata.split(b" ", 1)[0]
    path_text = raw_path.decode("utf-8", errors="strict")
    if mode in {b"120000", b"160000"}:
        raise SystemExit(f"symlink or submodule is outside this transaction: {path_text!r}")
    if not is_allowed(path_text):
        raise SystemExit(f"tracked path outside sealed project scope: {path_text!r}")

result = subprocess.run(
    ["git", "status", "--porcelain=v1", "-z", "--untracked-files=all"],
    cwd=root,
    check=True,
    stdout=subprocess.PIPE,
)
for raw_entry in result.stdout.split(b"\0"):
    if not raw_entry:
        continue
    entry = raw_entry.decode("utf-8", errors="strict")
    status = entry[:2]
    path_text = entry[3:]
    if "D" in status or "R" in status or "C" in status:
        raise SystemExit(f"deletion/rename/copy is outside this transaction: {entry!r}")
    if not is_allowed(path_text):
        raise SystemExit(f"path outside sealed project scope: {path_text!r}")
PY
}

remote_ref_sha() {
  local ref_name="$1"
  git ls-remote origin "$ref_name" | awk 'NR == 1 {print $1}'
}

remote_tag_commit() {
  local tag_name="$1"
  local peeled direct
  peeled="$(remote_ref_sha "refs/tags/${tag_name}^{}")"
  if [[ -n "$peeled" ]]; then
    printf '%s\n' "$peeled"
    return 0
  fi
  direct="$(remote_ref_sha "refs/tags/${tag_name}")"
  printf '%s\n' "$direct"
}

remote_tag_is_annotated() {
  [[ -n "$(remote_ref_sha "refs/tags/${1}^{}")" ]]
}

validate_boolean "PUBLISH" "$PUBLISH"
validate_boolean "CREATE_REMOTE" "$CREATE_REMOTE"
require_command realpath
require_command sha256sum
require_command tee
require_command "$PYTHON_BIN"
validate_target_path

if [[ -n "$SOURCE_DIR" && -n "$SOURCE_TARBALL" ]]; then
  die "provide SOURCE_DIR or SOURCE_TARBALL, not both"
fi
if [[ -z "$SOURCE_DIR" && -z "$SOURCE_TARBALL" ]]; then
  die "one of SOURCE_DIR or SOURCE_TARBALL is required"
fi

EVIDENCE_ROOT="$(canonical_path "$EVIDENCE_ROOT")"
EVIDENCE_DIR="${EVIDENCE_ROOT%/}/${RUN_ID}"
STATE_FILE="${EVIDENCE_DIR}/transaction-state.txt"
LOG_FILE="${EVIDENCE_DIR}/transaction.log"
mkdir -p -- "$EVIDENCE_DIR"
exec > >(tee -a "$LOG_FILE") 2>&1
trap 'on_error "$?" "$LINENO"' ERR
printf 'STARTED run_id=%s utc=%s\n' "$RUN_ID" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >"$STATE_FILE"

CURRENT_PHASE="SOURCE_ACQUISITION"
if [[ -n "$SOURCE_DIR" ]]; then
  SOURCE_DIR="$(canonical_path "$SOURCE_DIR")"
  [[ -d "$SOURCE_DIR" ]] || die "SOURCE_DIR is not a directory: $SOURCE_DIR"
  [[ "${SOURCE_DIR##*/}" == "$PROJECT_NAME" ]] || \
    die "SOURCE_DIR basename must be exactly $PROJECT_NAME"
  if [[ "$TARGET_DIR" != "$DEFAULT_TARGET_DIR" && "$(canonical_path "$TARGET_DIR")" != "$SOURCE_DIR" ]]; then
    die "when SOURCE_DIR is used, TARGET_DIR must be unset or identify the same directory"
  fi
  WORK_DIR="$SOURCE_DIR"
  SOURCE_MODE="REPOSITORY_DIRECTORY"
else
  require_command "$PYTHON_BIN"
  SOURCE_TARBALL="$(canonical_path "$SOURCE_TARBALL")"
  [[ -f "$SOURCE_TARBALL" ]] || die "SOURCE_TARBALL is not a regular file"
  [[ "$SOURCE_TARBALL_SHA256" =~ ^[0-9a-f]{64}$ ]] || \
    die "SOURCE_TARBALL_SHA256 must be a lowercase 64-character SHA-256"
  ACTUAL_TARBALL_SHA256="$(sha256sum -- "$SOURCE_TARBALL" | awk '{print $1}')"
  [[ "$ACTUAL_TARBALL_SHA256" == "$SOURCE_TARBALL_SHA256" ]] || \
    die "source tarball digest mismatch"
  [[ ! -e "$TARGET_DIR" ]] || \
    die "TARGET_DIR already exists; preservation rule forbids overwrite or merge"
  extract_verified_tarball "$SOURCE_TARBALL" "$TARGET_DIR"
  WORK_DIR="$TARGET_DIR"
  SOURCE_MODE="VERIFIED_TARBALL"
  printf '%s  %s\n' "$ACTUAL_TARBALL_SHA256" "$SOURCE_TARBALL" \
    >"${EVIDENCE_DIR}/source-tarball.sha256"
fi

WORK_DIR="$(canonical_path "$WORK_DIR")"
case "${EVIDENCE_DIR}/" in
  "${WORK_DIR}/"*) die "EVIDENCE_ROOT must be outside the source repository" ;;
esac

printf 'run_id=%s\nsource_mode=%s\nwork_dir=%s\nevidence_dir=%s\npublish=%s\ncreate_remote=%s\nexpected_repository=%s\nexpected_version=%s\n' \
  "$RUN_ID" "$SOURCE_MODE" "$WORK_DIR" "$EVIDENCE_DIR" "$PUBLISH" "$CREATE_REMOTE" \
  "$EXPECTED_REPOSITORY" "$EXPECTED_VERSION" >"${EVIDENCE_DIR}/transaction-inputs.txt"

CURRENT_PHASE="SOURCE_PREFLIGHT"
for required_path in \
  pyproject.toml setup.py README.md LICENSE SECURITY.md CONTRIBUTING.md CHANGELOG.md \
  schemas registry conformance examples src tests docs .github/workflows; do
  [[ -e "$WORK_DIR/$required_path" ]] || die "required project path is missing: $required_path"
done
[[ -z "$(find "$WORK_DIR" -path "$WORK_DIR/.git" -prune -o -type l -print -quit)" ]] || \
  die "symbolic links are forbidden in source"
[[ ! -e "$WORK_DIR/.gitmodules" ]] || die "Git submodules are outside this transaction"

"$PYTHON_BIN" - <<'PY'
import sys

if not ((3, 11) <= sys.version_info[:2] <= (3, 13)):
    raise SystemExit(f"Python 3.11-3.13 required, got {sys.version.split()[0]}")
PY
verify_project_metadata
"$PYTHON_BIN" --version | tee "${EVIDENCE_DIR}/python-version.txt"

CURRENT_PHASE="SOURCE_BASELINE"
write_source_inventory "${EVIDENCE_DIR}/source-files-baseline.sha256"

CURRENT_PHASE="ISOLATED_ENVIRONMENT"
BUILD_VENV="${EVIDENCE_DIR}/build-venv"
SMOKE_VENV="${EVIDENCE_DIR}/smoke-venv"
"$PYTHON_BIN" -m venv "$BUILD_VENV"
export PIP_DISABLE_PIP_VERSION_CHECK=1
export PYTHONHASHSEED=0
export SOURCE_DATE_EPOCH=315532800
run_gate pip-bootstrap "$BUILD_VENV/bin/python" -m pip install 'pip>=26.1.2,<27'
run_gate build-tool-bootstrap "$BUILD_VENV/bin/python" -m pip install \
  "$EXPECTED_SETUPTOOLS_SPEC" 'wheel>=0.45,<1'
run_gate install "$BUILD_VENV/bin/python" -m pip install "$WORK_DIR[dev]"
"$BUILD_VENV/bin/python" -m pip freeze --all >"${EVIDENCE_DIR}/python-packages.txt"

CURRENT_PHASE="QUALITY_GATES"
pushd "$WORK_DIR" >/dev/null
run_gate ruff-lint "$BUILD_VENV/bin/python" -m ruff check .
run_gate ruff-format "$BUILD_VENV/bin/python" -m ruff format --check .
run_gate mypy "$BUILD_VENV/bin/python" -m mypy src
run_gate pytest "$BUILD_VENV/bin/python" -m pytest
run_gate conformance "$BUILD_VENV/bin/python" -m "$PACKAGE_NAME.cli" verify-conformance --json
run_gate atlasbridge-example "$BUILD_VENV/bin/python" -m "$PACKAGE_NAME.cli" verify-example --json
run_gate bandit "$BUILD_VENV/bin/python" -m bandit -q -r src setup.py
run_gate dependency-audit "$BUILD_VENV/bin/python" -m pip_audit \
  --local --skip-editable --cache-dir "${EVIDENCE_DIR}/pip-audit-cache"
popd >/dev/null

CURRENT_PHASE="REPRODUCIBLE_BUILD"
DIST_A="${EVIDENCE_DIR}/dist-a"
DIST_B="${EVIDENCE_DIR}/dist-b"
mkdir -- "$DIST_A" "$DIST_B"
run_gate build-a "$BUILD_VENV/bin/python" -m build --outdir "$DIST_A" "$WORK_DIR"
run_gate build-b "$BUILD_VENV/bin/python" -m build --outdir "$DIST_B" "$WORK_DIR"
[[ "$(find "$DIST_A" -maxdepth 1 -type f | wc -l)" -eq 2 ]] || \
  die "build must produce exactly one wheel and one source archive"
(cd "$DIST_A" && sha256sum * | sort -k2) >"${EVIDENCE_DIR}/dist-a.sha256"
(cd "$DIST_B" && sha256sum * | sort -k2) >"${EVIDENCE_DIR}/dist-b.sha256"
run_gate deterministic-build diff -u \
  "${EVIDENCE_DIR}/dist-a.sha256" "${EVIDENCE_DIR}/dist-b.sha256"
run_gate package-metadata "$BUILD_VENV/bin/python" -m twine check "$DIST_A"/*

CURRENT_PHASE="INSTALLED_WHEEL_SMOKE"
mapfile -t WHEELS < <(find "$DIST_A" -maxdepth 1 -type f -name '*.whl' -print)
[[ "${#WHEELS[@]}" -eq 1 ]] || die "exactly one wheel is required for smoke testing"
"$PYTHON_BIN" -m venv "$SMOKE_VENV"
run_gate wheel-pip-bootstrap "$SMOKE_VENV/bin/python" -m pip install 'pip>=26.1.2,<27'
run_gate wheel-install "$SMOKE_VENV/bin/python" -m pip install "${WHEELS[0]}"
SMOKE_CWD="${EVIDENCE_DIR}/wheel-smoke-cwd"
mkdir -- "$SMOKE_CWD"
(
  unset TPC_CONTRACT_ROOT
  cd "$SMOKE_CWD"
  run_gate wheel-help "$SMOKE_VENV/bin/portfolio-contracts" --help
  run_gate wheel-events-help "$SMOKE_VENV/bin/portfolio-contracts" verify-events --help
  run_gate wheel-catalog "$SMOKE_VENV/bin/portfolio-contracts" catalog --json
)
verify_installed_catalog_root \
  "${EVIDENCE_DIR}/wheel-catalog.log" \
  "${SMOKE_VENV}/share/transformation-portfolio-contracts"
(
  unset TPC_CONTRACT_ROOT
  cd "$SMOKE_CWD"
  run_gate wheel-conformance "$SMOKE_VENV/bin/portfolio-contracts" verify-conformance --json
  run_gate wheel-example "$SMOKE_VENV/bin/portfolio-contracts" verify-example --json
)

CURRENT_PHASE="POST_GATE_SOURCE_INTEGRITY"
[[ -z "$(find "$WORK_DIR" -path "$WORK_DIR/.git" -prune -o -type l -print -quit)" ]] || \
  die "symbolic links appeared during verification gates"
write_source_inventory "${EVIDENCE_DIR}/source-files-post-gates.sha256"
run_gate source-unchanged-after-gates diff -u \
  "${EVIDENCE_DIR}/source-files-baseline.sha256" \
  "${EVIDENCE_DIR}/source-files-post-gates.sha256"

if [[ "$PUBLISH" == "0" ]]; then
  CURRENT_PHASE="VERIFIED_NOT_PUBLISHED"
  printf 'VERIFIED_NOT_PUBLISHED run_id=%s utc=%s evidence=%s\n' \
    "$RUN_ID" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$EVIDENCE_DIR" >"$STATE_FILE"
  printf '\nVerification passed. Publication was not requested.\nEvidence: %s\n' "$EVIDENCE_DIR"
  exit 0
fi

CURRENT_PHASE="LOCAL_PUBLICATION_PREFLIGHT"
require_command git
require_command gh
[[ "$EXPECTED_REMOTE_MAIN" == "EMPTY" || "$EXPECTED_REMOTE_MAIN" =~ ^[0-9a-f]{40}$ ]] || \
  die "PUBLISH=1 requires EXPECTED_REMOTE_MAIN=EMPTY or one exact lowercase commit SHA"

pushd "$WORK_DIR" >/dev/null
if ! git rev-parse --git-dir >/dev/null 2>&1; then
  git init --initial-branch=main
fi
[[ "$(git rev-parse --show-toplevel)" == "$WORK_DIR" ]] || \
  die "WORK_DIR is not the exact Git repository root"
[[ "$(git rev-parse --is-shallow-repository)" == "false" ]] || \
  die "publication from a shallow repository is forbidden"

if git rev-parse --verify HEAD >/dev/null 2>&1; then
  [[ "$(git branch --show-current)" == "main" ]] || \
    die "publication requires the checked-out main branch"
else
  [[ "$(git symbolic-ref --short HEAD)" == "main" ]] || \
    die "new repository must use main as its initial branch"
fi

[[ -n "$(git config user.name || true)" ]] || die "Git user.name is required"
[[ -n "$(git config user.email || true)" ]] || die "Git user.email is required"

git add -- \
  .editorconfig .github .gitignore CHANGELOG.md CONTRIBUTING.md LICENSE MANIFEST.in Makefile \
  README.md SECURITY.md build_and_publish_transformation_portfolio_contracts_v1.0.0.sh \
  conformance docs examples pyproject.toml setup.py registry schemas src tests
verify_git_scope
git diff --quiet || die "unstaged tracked changes remain after sealed staging"
[[ -z "$(git ls-files --others --exclude-standard)" ]] || \
  die "untracked source files remain after sealed staging"
[[ -z "$(git diff --cached --diff-filter=D --name-only)" ]] || \
  die "deletions are forbidden in this transaction"

STAGED_CHANGES=0
if ! git diff --cached --quiet; then
  STAGED_CHANGES=1
fi

LOCAL_HEAD_BEFORE=""
if git rev-parse --verify HEAD >/dev/null 2>&1; then
  LOCAL_HEAD_BEFORE="$(git rev-parse HEAD)"
elif [[ "$STAGED_CHANGES" == "0" ]]; then
  die "nothing is staged and no existing commit exists"
fi

if git rev-parse --verify "refs/tags/$EXPECTED_TAG" >/dev/null 2>&1 && \
  [[ "$STAGED_CHANGES" == "1" ]]; then
  die "existing local release tag forbids creating a different publish commit"
fi

CURRENT_PHASE="REMOTE_READ_ONLY_PREFLIGHT"
gh auth status --hostname github.com >"${EVIDENCE_DIR}/github-auth-status.txt" 2>&1 || \
  die "GitHub CLI authentication is unavailable"

GITHUB_METADATA="${EVIDENCE_DIR}/github-repository.json"
REPOSITORY_EXISTS=0
if gh repo view "$EXPECTED_REPOSITORY" \
  --json nameWithOwner,visibility,isArchived,defaultBranchRef >"$GITHUB_METADATA" \
  2>"${EVIDENCE_DIR}/github-repository-view.stderr"; then
  REPOSITORY_EXISTS=1
  verify_github_metadata "$GITHUB_METADATA"
else
  [[ "$CREATE_REMOTE" == "1" ]] || \
    die "GitHub repository is absent or unreadable; explicit CREATE_REMOTE=1 is required"
  [[ "$EXPECTED_REMOTE_MAIN" == "EMPTY" ]] || \
    die "new repository creation requires EXPECTED_REMOTE_MAIN=EMPTY"
fi

if git remote get-url origin >/dev/null 2>&1; then
  mapfile -t ORIGIN_FETCH_URLS < <(git remote get-url --all origin)
  mapfile -t ORIGIN_PUSH_URLS < <(git remote get-url --push --all origin)
  [[ "${#ORIGIN_FETCH_URLS[@]}" -eq 1 && "${#ORIGIN_PUSH_URLS[@]}" -eq 1 ]] || \
    die "origin must have exactly one fetch URL and one push URL"
  validate_remote_url "${ORIGIN_FETCH_URLS[0]}"
  validate_remote_url "${ORIGIN_PUSH_URLS[0]}"
else
  git remote add origin "$EXPECTED_HTTPS_REMOTE"
fi

REMOTE_MAIN_BEFORE=""
REMOTE_TAG_BEFORE=""
if [[ "$REPOSITORY_EXISTS" == "1" ]]; then
  REMOTE_MAIN_BEFORE="$(remote_ref_sha refs/heads/main)"
  REMOTE_TAG_BEFORE="$(remote_tag_commit "$EXPECTED_TAG")"

  if [[ "$EXPECTED_REMOTE_MAIN" == "EMPTY" ]]; then
    if [[ -n "$REMOTE_MAIN_BEFORE" && \
      ! ( "$STAGED_CHANGES" == "0" && "$REMOTE_MAIN_BEFORE" == "$LOCAL_HEAD_BEFORE" ) ]]; then
      die "remote main is non-empty but EMPTY was authorized"
    fi
  elif [[ "$REMOTE_MAIN_BEFORE" != "$EXPECTED_REMOTE_MAIN" ]]; then
    if [[ "$STAGED_CHANGES" == "0" && "$REMOTE_MAIN_BEFORE" == "$LOCAL_HEAD_BEFORE" ]]; then
      printf 'Idempotence: authorized base has already advanced to local HEAD.\n'
    else
      die "remote main does not equal EXPECTED_REMOTE_MAIN"
    fi
  fi

  if [[ "$STAGED_CHANGES" == "1" && -n "$REMOTE_MAIN_BEFORE" && \
    "$LOCAL_HEAD_BEFORE" != "$REMOTE_MAIN_BEFORE" ]]; then
    die "local HEAD does not equal the exact authorized remote base"
  fi
  if [[ "$STAGED_CHANGES" == "1" && -n "$REMOTE_TAG_BEFORE" ]]; then
    die "existing immutable remote tag forbids creating a different publish commit"
  fi
  if [[ -n "$REMOTE_TAG_BEFORE" ]] && ! remote_tag_is_annotated "$EXPECTED_TAG"; then
    die "existing remote release tag is not annotated"
  fi
  if [[ "$STAGED_CHANGES" == "0" && -n "$REMOTE_MAIN_BEFORE" && \
    "$REMOTE_MAIN_BEFORE" != "$LOCAL_HEAD_BEFORE" ]]; then
    LOCAL_PARENT="$(git rev-parse "${LOCAL_HEAD_BEFORE}^" 2>/dev/null || true)"
    [[ "$LOCAL_PARENT" == "$REMOTE_MAIN_BEFORE" ]] || \
      die "existing local publish commit is not the direct child of remote main"
  fi
fi

CURRENT_PHASE="PRECOMMIT_SOURCE_INTEGRITY"
[[ -z "$(find "$WORK_DIR" -path "$WORK_DIR/.git" -prune -o -type l -print -quit)" ]] || \
  die "symbolic links appeared after source preflight"
write_source_inventory "${EVIDENCE_DIR}/source-files-precommit.sha256"
run_gate source-unchanged-before-commit diff -u \
  "${EVIDENCE_DIR}/source-files-baseline.sha256" \
  "${EVIDENCE_DIR}/source-files-precommit.sha256"
verify_git_scope
git diff --quiet || die "source changed after sealed staging"
[[ -z "$(git ls-files --others --exclude-standard)" ]] || \
  die "untracked source files appeared after sealed staging"

CURRENT_PHASE="LOCAL_COMMIT_AND_TAG"
if [[ "$STAGED_CHANGES" == "0" ]]; then
  printf 'Idempotence: source tree is already committed.\n'
else
  git commit -m "$GIT_COMMIT_MESSAGE"
fi

PUBLISH_COMMIT="$(git rev-parse HEAD)"
PUBLISH_TREE="$(git rev-parse 'HEAD^{tree}')"

if git rev-parse --verify "refs/tags/$EXPECTED_TAG" >/dev/null 2>&1; then
  [[ "$(git cat-file -t "refs/tags/$EXPECTED_TAG")" == "tag" ]] || \
    die "existing local release tag is not annotated"
  [[ "$(git rev-list -n 1 "$EXPECTED_TAG")" == "$PUBLISH_COMMIT" ]] || \
    die "existing local tag points to a different commit"
  printf 'Idempotence: local tag already points to publish commit.\n'
else
  git tag -a "$EXPECTED_TAG" -m "Transformation Portfolio Contracts $EXPECTED_TAG"
fi

if [[ -n "$REMOTE_TAG_BEFORE" && "$REMOTE_TAG_BEFORE" != "$PUBLISH_COMMIT" ]]; then
  die "existing remote tag points to a different commit"
fi

if [[ "$REPOSITORY_EXISTS" == "0" ]]; then
  CURRENT_PHASE="EXPLICIT_REMOTE_CREATION"
  gh repo create "$EXPECTED_REPOSITORY" \
    --public \
    --description "Governed interoperability contracts for the transformation decision portfolio"
  gh repo view "$EXPECTED_REPOSITORY" \
    --json nameWithOwner,visibility,isArchived,defaultBranchRef >"$GITHUB_METADATA"
  verify_github_metadata "$GITHUB_METADATA"
  REMOTE_MAIN_BEFORE="$(remote_ref_sha refs/heads/main)"
  REMOTE_TAG_BEFORE="$(remote_tag_commit "$EXPECTED_TAG")"
  [[ -z "$REMOTE_MAIN_BEFORE" && -z "$REMOTE_TAG_BEFORE" ]] || \
    die "newly created repository unexpectedly contains Git refs"
fi

MAIN_PUSH_NEEDED=0
TAG_PUSH_NEEDED=0
if [[ "$REMOTE_MAIN_BEFORE" != "$PUBLISH_COMMIT" ]]; then
  MAIN_PUSH_NEEDED=1
fi
if [[ "$REMOTE_TAG_BEFORE" != "$PUBLISH_COMMIT" ]]; then
  TAG_PUSH_NEEDED=1
fi

CURRENT_PHASE="ATOMIC_OR_IDEMPOTENT_PUSH"
if [[ "$MAIN_PUSH_NEEDED" == "1" && "$TAG_PUSH_NEEDED" == "1" ]]; then
  git push --atomic origin HEAD:refs/heads/main "refs/tags/$EXPECTED_TAG"
elif [[ "$MAIN_PUSH_NEEDED" == "1" ]]; then
  [[ "$REMOTE_TAG_BEFORE" == "$PUBLISH_COMMIT" ]] || \
    die "single main push requires the exact remote tag to be verified first"
  git push origin HEAD:refs/heads/main
elif [[ "$TAG_PUSH_NEEDED" == "1" ]]; then
  [[ "$REMOTE_MAIN_BEFORE" == "$PUBLISH_COMMIT" ]] || \
    die "single tag push requires the exact remote main ref to be verified first"
  git push origin "refs/tags/$EXPECTED_TAG"
else
  printf 'Idempotence: remote main and tag publication are already complete.\n'
fi

REMOTE_MAIN_AFTER="$(remote_ref_sha refs/heads/main)"
REMOTE_TAG_AFTER="$(remote_tag_commit "$EXPECTED_TAG")"
[[ "$REMOTE_MAIN_AFTER" == "$PUBLISH_COMMIT" ]] || die "post-push main verification failed"
[[ "$REMOTE_TAG_AFTER" == "$PUBLISH_COMMIT" ]] || die "post-push tag verification failed"
remote_tag_is_annotated "$EXPECTED_TAG" || die "post-push remote tag is not annotated"

GITHUB_METADATA_AFTER="${EVIDENCE_DIR}/github-repository-after.json"
gh repo view "$EXPECTED_REPOSITORY" \
  --json nameWithOwner,visibility,isArchived,defaultBranchRef >"$GITHUB_METADATA_AFTER"
verify_github_metadata "$GITHUB_METADATA_AFTER" 1

git status --short --branch >"${EVIDENCE_DIR}/git-status-final.txt"
git show --no-patch --format=fuller HEAD >"${EVIDENCE_DIR}/git-commit.txt"
git ls-tree -r --full-tree HEAD >"${EVIDENCE_DIR}/git-tree.txt"
printf 'commit=%s\ntree=%s\ntag=%s\nremote_main=%s\nremote_tag=%s\n' \
  "$PUBLISH_COMMIT" "$PUBLISH_TREE" "$EXPECTED_TAG" "$REMOTE_MAIN_AFTER" "$REMOTE_TAG_AFTER" \
  >"${EVIDENCE_DIR}/publication-result.txt"
printf 'release_status=NOT_VERIFIED_PENDING_GITHUB_ACTIONS\n' \
  >>"${EVIDENCE_DIR}/publication-result.txt"
popd >/dev/null

CURRENT_PHASE="SOURCE_TAG_PUBLISHED_RELEASE_PENDING"
printf 'SOURCE_TAG_PUBLISHED_RELEASE_PENDING run_id=%s utc=%s commit=%s tree=%s tag=%s evidence=%s\n' \
  "$RUN_ID" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$PUBLISH_COMMIT" "$PUBLISH_TREE" \
  "$EXPECTED_TAG" "$EVIDENCE_DIR" >"$STATE_FILE"
printf '\nSource and tag publication passed; the GitHub release workflow, assets, checksums, and attestation remain unverified and pending.\nCommit: %s\nTree: %s\nTag: %s\nEvidence: %s\n' \
  "$PUBLISH_COMMIT" "$PUBLISH_TREE" "$EXPECTED_TAG" "$EVIDENCE_DIR"
