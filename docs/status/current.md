# Current status

**Status date:** 2026-08-15  
**Release baseline:** v1.0.0  
**G0 feasibility:** PASS  
**G0 publication:** BLOCKED

The released contract implementation remains unchanged. The active migration branch records exact
repository authority, immutable release evidence, a complete-history backup, restore proof, and a
cross-repository reference inventory before any identity setting can change.

## Verified

- Source `main` commit and tree.
- Valid GitHub signature on the captured `main` merge commit.
- Immutable v1.0.0 release and three asset digests.
- Complete-history bundle checksum and restore rehearsal.
- Target-name availability at the capture time.
- Zero hosted Action consumers across seven exact snapshots.
- One direct consumer with ten affected files.
- Local G0 identity verification, relative-link scanning, Ruff, formatting, strict mypy, 79 tests,
  90.12% branch coverage, conformance, Bandit, and dependency audit.

## Blocked or missing

- Remote migration branch and draft pull request are not published from this workspace.
- Current branch protection could not be read through the connected integration.
- The proposed repository rename is not authorized in G0.
- Consumer references have not been updated.
- The annotated v1.0.0 tag is unsigned.

See the [identity manifest](../migration/identity-manifest.md) for the exact authority tuple,
decision, preconditions, and rollback, and the
[G0 verification record](../verification/g0-identity-evidence.md) for the local gate results.
