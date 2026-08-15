# Current status

**Status date:** 2026-08-15  
**Release baseline:** v1.0.0  
**G0 feasibility:** PASS  
**G0 remote publication and protected merge:** PASS  
**Active roadmap branch:** `feat/02-runtime-envelope-v1-1`

G0 identity evidence was published, reviewed through exact-head CI, and merged normally. The
GitHub-verified merge commit is `3e220c36abc13efe7339f238a4210e9522aa40f0` with tree
`e72938a749f08468760aa1acf0a9b8af934899ab`. The released v1.0.0 contract bytes, package name,
schema identifiers, release tag, and assets remain unchanged.

The active branch now implements the candidate `RuntimeEnvelope.v1.1` contract required before the
governed runtime can add restart-safe PostgreSQL checkpoints. This is development evidence, not a
stable release or consumer-adoption claim.

## Verified

- G0 source authority, target-name availability, hosted-Action inventory, and direct-reference
  inventory.
- Complete-history backup checksum and restore rehearsal.
- Published identity branch and GitHub-verified normal merge.
- Immutable v1.0.0 release compatibility surface.
- Runtime repository foundation branch published, exact-head Python 3.12/3.13 CI green, and merged
  normally in `DameurMounir/governed-agent-runtime`.
- `feat/02-runtime-envelope-v1-1` created from the verified post-G0 `main`.

## Active branch gates

Before branch 02 can merge, it must prove the new schema, Pydantic models, canonical digest vectors,
tamper handling, temporal validity, key-resolution failures, HMAC verification, backward
compatibility, package resources, Python 3.11/3.12/3.13 tests, security checks, deterministic builds,
and exact-head GitHub CI.

## Still separate or incomplete

- No repository rename has been performed; the direct consumer-reference migration remains a
  separate controlled transaction.
- Current branch-protection settings remain to be independently reconciled with the committed
  manifest.
- `RuntimeEnvelope.v1.1` is not yet released, signed, or adopted by a production consumer.
- The annotated v1.0.0 tag remains an immutable historical compatibility identifier.
- No database, runtime deployment, model call, tool execution, credential, or signing-key service is
  created by this contracts branch.

See the [identity manifest](../migration/identity-manifest.md), the
[G0 verification record](../verification/g0-identity-evidence.md), and the
[runtime envelope status](runtime-envelope-v1.1.md).
