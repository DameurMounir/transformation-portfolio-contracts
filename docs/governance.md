# Contract governance

## Governing principles

The contract family is governed by six invariants:

1. Published schemas and release tags are immutable.
2. Consumers fail closed on uncertainty or incompatibility.
3. Human authority stays scoped, explicit, and externally granted.
4. Artifacts are content-addressed and upstream records are never rewritten downstream.
5. Stage repositories remain independently owned and released.
6. Compatibility claims require executable conformance evidence.

## Sources of truth

The following precedence applies inside one released version:

1. JSON Schemas define normative document structure and local constraints.
2. The contract catalog and compatibility matrix define registered identity and supported
   producer-consumer relationships.
3. Conformance expected results define executable acceptance and rejection behavior.
4. The digest profile defines canonical bytes and digest computation.
5. Other documentation explains intent and adoption.

If these sources conflict, a consumer must stop. It must not choose the least restrictive
interpretation. The conflict is a release defect requiring correction in a new version.

## Ownership roles

| Role | Accountability |
| --- | --- |
| Contract maintainer | Catalog integrity, release composition, version decision |
| Contract reviewer | Independent schema, security, and compatibility review |
| Stage producer owner | Correct mapping, provenance, evidence, and authority record |
| Stage consumer owner | Pinned dependency, fail-closed validation, policy interpretation |
| Business decision owner | Decision outcome within an externally granted authority scope |
| Release authority | Final authorization outside the analytical and contract tools |

One person may hold multiple roles in a small project, but the evidence must still distinguish the
actions. An automated agent cannot silently substitute for a human decision owner.

## Versioning policy

The repository and contract family follow Semantic Versioning.

| Change | Version treatment | Example |
| --- | --- | --- |
| Documentation or validation correction that does not alter accepted documents | Patch | Better diagnostic text |
| Backward-compatible optional field or new independent contract | Minor | Optional provenance extension |
| New required field, changed meaning, removed value, or different digest projection | Major | `ArtifactEnvelope.v2` |

Every schema has a versioned `$id` and contract name. A published `$id` is never reassigned to new
bytes. A consumer advertises supported major versions through the compatibility registry and must
reject an unsupported major even if generic schema validation happens to succeed.

Adding an optional field can still change an artifact digest when a producer uses it. That is an
expected content change, not a reason to weaken digest verification.

## Lifecycle and supersession

Lifecycle status is stage-specific but portable enough for safe consumption. Required upstream
artifacts in `DRAFT`, `REJECTED`, or `SUPERSEDED` state are not consumable. A new artifact may
supersede an older one by explicit reference; it does not mutate or erase the earlier artifact.

Consumers must detect a stale chain created from a superseded artifact and require deliberate
reassembly. They must not automatically substitute the newest artifact because doing so would
invalidate the downstream decision context.

## Decision authority

A `HumanDecision.v1` record is evidence of a decision assertion bound to an artifact digest. It must
not be interpreted beyond its `authority_scope`, action, outcome, conditions, or expiry. A decision
for process-option selection cannot authorize risk acceptance or production release.

The raw one-use challenge or nonce used by a stage may remain local after consumption. The durable
decision record and its digest cross the boundary.

## Change proposal requirements

Every normative proposal must include:

- problem statement and affected contract IDs;
- change classification and compatibility analysis;
- producer and consumer migration impact;
- positive, boundary, and negative fixtures;
- expected conformance results;
- deterministic digest evidence;
- security, privacy, and human-authority analysis;
- rollback or coexistence plan;
- catalog, matrix, map, documentation, and changelog updates.

No exception may remove a mandatory integrity or authority check. Organization-specific extensions
use namespaced optional structures and cannot redefine a normative field.

## Release gates

A release is eligible only when all of the following are true:

- repository scope and version are exact;
- schemas are Draft 2020-12 and all registered `$id` values are unique;
- catalog, compatibility matrix, and producer-consumer map agree;
- valid fixtures pass and invalid fixtures fail for the expected reason;
- the AtlasBridge chain validates with a deterministic final digest;
- formatting, lint, strict typing, tests, and coverage pass on Python 3.11-3.13;
- source and dependency security checks pass;
- the isolated build backend resolves within the audited `setuptools>=83,<84` range;
- wheel and source distribution build and metadata checks pass;
- the tag version equals `pyproject.toml` and the tag commit belongs to protected `main`;
- release artifacts have SHA-256 checksums and build provenance;
- no existing release asset, tag, or published contract is overwritten.

Release automation stops on any missing evidence. A partial release is reconciled by verifying exact
existing state and completing only the missing forward action; it is never repaired with force push,
history rewrite, or artifact replacement.

The VPS transaction deliberately stops at `SOURCE_TAG_PUBLISHED_RELEASE_PENDING`. That state proves
only the exact source commit and tag refs. It does not prove branch protection, workflow completion,
release assets, checksums, or provenance; those controls require separate GitHub-side evidence before
the release is eligible for governed use.

## Consumer obligations

A governed consumer must:

- pin the contracts release tag and commit SHA;
- verify release checksum and provenance where available;
- parse JSON without accepting duplicate object keys or non-finite numbers;
- validate contract, format, digest, identity, lifecycle, chronology, and lineage;
- resolve exact upstream files by ID and digest, not filename alone;
- retain original upstream artifacts and validation evidence;
- keep organizational authorization and data controls outside this public package;
- treat validator success as conformance, not business approval.

## Deprecation and support

The latest patch release of a supported major receives security and correctness fixes. Deprecation
must be recorded in the catalog and changelog with a replacement and migration period. Removal or
semantic replacement requires a new major version.

The v1.0 release establishes the first supported major. Earlier stage-local v0.1.0 artifacts remain
historical records but are not implicitly v1-conformant; explicit adapters and identity maps are
required.

## Incident handling

Suspected vulnerabilities follow [../SECURITY.md](../SECURITY.md). A contract-integrity incident
freezes new release claims, preserves evidence, identifies affected tags and downstream chains, and
publishes a new corrected version. Existing assets and tags are not silently replaced.
