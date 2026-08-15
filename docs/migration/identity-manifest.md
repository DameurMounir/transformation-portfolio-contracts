# Repository identity migration manifest

**Capture:** 2026-08-15T10:16:19+01:00  
**Scope:** G0 evidence only  
**Feasibility verdict:** PASS  
**Rename execution:** BLOCKED

This manifest decides whether the existing shared-contracts repository can later adopt the
professional identity `transformation-agent-contracts`. It does not authorize or perform a
repository rename, release rewrite, archive, deployment, credential change, or consumer update.
The machine-readable authority record is
[`identity-manifest.json`](identity-manifest.json).

## Exact authority

| Item | Evidence |
| --- | --- |
| Source default ref | `refs/heads/main` |
| Source commit | `4fb6af9344ba1b903fdda96891a18eb708ab82ea` |
| Source tree | `e44be69ff1cd60fe9bb6f45a1b915db3fa7b6e27` |
| Commit verification | GitHub reports a valid signature, verified 2026-08-14T12:15:21Z |
| Proposed repository name | `transformation-agent-contracts` |
| Collision check | Available at capture time; GitHub lookup returned HTTP 404 |
| GitHub Pages | Not configured; Pages lookup returned HTTP 404 and no Pages source reference was found |
| Current branch protection | Not verified in this capture; the connected integration returned HTTP 403 |

The branch-protection result is not inferred from earlier observations. It must be read again with
administrator authority immediately before any later setting change.

## Immutable release authority

| Item | Evidence |
| --- | --- |
| Release | v1.0.0, immutable GitHub release `370636962` |
| Annotated tag object | `75ab3f4c6ad171b7c2e6f3ad33512c774a44a126` |
| Release commit | `7362a85f381842d5178fc8b12bad48759fd46ec9` |
| Release tree | `194c5907711559ffeedc4fb11f104e92cabe132d` |
| Wheel SHA-256 | `b4ccab6f65443bc29dcc065ddd6c74e2952ba7e8d1ab2c518433eec1c29853a9` |
| Source archive SHA-256 | `e05ef917c227310106ed1d8a55584dacdf6c85f436a5130fa66d5d4c031a3255` |
| SHA256SUMS SHA-256 | `47cd90b5a526737df86046fde2a1ca4f7cd05d6c95733a4219ec15477f2981a9` |
| Tag signature | UNSIGNED; this remains a recorded residual risk |

Published v1.0.0 package names, asset filenames, schema IDs, digests, tag objects, and release
contents are compatibility identifiers. A later repository rename must not rewrite them.

## Dependency and hosted Action inventory

Seven repository snapshots were searched at exact commits and trees. The complete counts are in
[`reference-inventory.csv`](reference-inventory.csv).

- Hosted GitHub Action references to the current source path: **0**.
- Direct consumer repositories: **1**.
- Direct reference files in `requirements-quality-agent`: **10** at commit
  `f08fa2fd08817e60a09bc6a4275a3584674e8580`.
- Internal source files containing compatibility paths or distribution names: **56**, with **166**
  occurrences at the captured source tree.
- GitHub Pages or `github.io` references: **0**.

The consumer is pinned to the immutable v1.0.0 wheel and its SHA-256. Its dependency URL, lock,
adapter provenance, verification scripts, tests, README, and changelog require a separate reviewed
update. No consumer change belongs in this branch.

## Backup and restore proof

| Item | Evidence |
| --- | --- |
| Bundle | `source-contracts-all.bundle` |
| Size | 175,255 bytes |
| SHA-256 | `63b90e98f049931a7681fc1a06d892e800ed9718bae5757667b7d408dee3a0f0` |
| Complete history | PASS, seven refs recorded |
| Restore rehearsal | PASS |
| Restored main commit/tree | `4fb6af9…` / `e44be69…` |
| Restored v1.0.0 object/commit/tree | `75ab3f4…` / `7362a85…` / `194c590…` |

The bundle is evidence stored outside the repository; only its digest and verification record are
committed. Immediately before a later rename, create and restore-test a new bundle if `main` has
advanced.

## Decision and controlled sequence

The evidence supports **rename in place** because the target is available, Git history and the
immutable release can remain on one repository, and no hosted Action is bound to the old path.
Execution remains BLOCKED until all of these steps are authorized and verified:

1. Merge this branch through protected review and independently verify its evidence.
2. Re-read source `main`, the target collision result, current protection, workflows, security
   settings, release assets, and backup hash.
3. Prepare the consumer update and rollback without merging it.
4. Obtain separate authorization for the repository-setting mutation.
5. Rename once; do not recreate, archive, or delete the source.
6. Verify Git and web redirects, v1.0.0 release downloads, raw schema URLs, both workflows, required
   checks, security reporting, and administrator access.
7. Merge the consumer reference update only after those checks pass.
8. Preserve old v1.0.0 compatibility identifiers permanently; introduce any future naming alias as
   a versioned, backward-compatible contract change.

If any post-change check fails, stop releases and consumer merges. Rename back only while the former
name is still available, or recover exact refs from the verified bundle under separate recovery
authorization.
