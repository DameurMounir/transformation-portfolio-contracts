# Adoption guide

## Adoption outcome

Adoption is complete when a stage can export or consume its portable v1 artifact without manual
copying, validates every upstream reference fail closed, remains independently runnable, and passes
the central conformance fixtures against a pinned contracts release.

Do not rewrite a stage's v0.1.0 release. Add the adapter in a new interoperability branch and release
the stage as v0.2.0 after conformance.

## 1. Pin the contract release

A governed build pins both tag and commit SHA. Do not consume `main`.

```bash
git clone --branch v1.0.0 --depth 1 \
  https://github.com/DameurMounir/transformation-portfolio-contracts.git vendor/contracts
git -C vendor/contracts rev-parse HEAD
python -m pip install ./vendor/contracts
portfolio-contracts catalog --json
```

Record the resolved commit in the stage repository's compatibility manifest. Verify release
`SHA256SUMS` and GitHub provenance when consuming a packaged release.

## 2. Add an adapter boundary

The adapter may import its own stage's public model and the contracts package. It must not import
another stage's private package. Keep these responsibilities separate:

| Adapter action | Rule |
| --- | --- |
| Import | Read an immutable file, validate it, then map allowed values into local input models |
| Export | Map a completed local record into one stage payload and common envelope |
| Authority | Copy the durable scoped decision record; never infer or widen authority |
| Digests | Use `TPC-JCS-SHA256-v1`; never maintain a stage-specific hash convention |
| Storage | Write a new artifact; never modify the upstream file |
| Failure | Stop on every schema, compatibility, identity, status, digest, or lineage error |

The local engine remains usable without the adapter. Integrated mode adds immutable inputs and
portable outputs; it does not replace the stage's reasoning.

## 3. Map canonical identity

Use one `transformation_id` across all five stages. Preserve old local IDs through an explicit
`portfolio/atlasbridge-id-map.json`, for example:

```json
{
  "canonical_id": "ATLASBRIDGE-CHANGE-001",
  "local_id": "ATLASBRIDGE-ONBOARDING-IMPACT-001",
  "relationship": "SAME_SYNTHETIC_TRANSFORMATION"
}
```

Do not rename or rewrite historical artifacts. An adapter rejects a canonical/local conflict.

## 4. Produce a valid artifact

The producer should:

1. complete its local analysis and required human review;
2. map stable IDs, evidence references, open findings, conditions, risks, and limitations;
3. identify the exact producer repository, release, commit, tree, and tool version;
4. add exact immutable input references and allowed relationships;
5. compute payload, artifact, and chain digests under `TPC-JCS-SHA256-v1`;
6. validate the artifact against the pinned schema and complete lineage set;
7. write it once to the run workspace and retain the validation result.

Example validation:

```bash
portfolio-contracts validate \
  --contract ProcessRedesignDecision.v1 \
  --artifact artifacts/03-process-redesign-decision.v1.json \
  --json
portfolio-contracts digest artifacts/03-process-redesign-decision.v1.json --verify --json
```

## 5. Consume fail closed

Validate before local mapping. For a set of upstream files:

```bash
portfolio-contracts verify-lineage \
  artifacts/01-requirements-assessment.v1.json \
  artifacts/02-stakeholder-alignment-packet.v1.json \
  artifacts/03-process-redesign-decision.v1.json \
  --json
```

Validate AgentEvents individually when received, then verify the complete ordered audit chain:

```bash
portfolio-contracts validate --contract AgentEvent.v1 --artifact audit/event-001.json --json
portfolio-contracts verify-events audit/ordered-events.scenario.json --json
```

The event digest removes only its own top-level `event_digest` before JCS SHA-256. Consumers must
retain `previous_event_digest`, supply events root-to-terminal, and reject a missing predecessor,
duplicate ID or digest, fork, cycle, disconnected event, identity mismatch, time inversion, or
causation that does not identify an earlier event.

The CLI exit contract is stable for automation:

| Exit | Meaning | Consumer action |
| --- | --- | --- |
| `0` | Requested verification passed | Continue to stage-specific checks |
| `2` | Invalid CLI use | Correct invocation; do not consume |
| `3` | Missing/unreadable input or resources | Restore exact input; do not consume |
| `4` | Schema or contract failure | Reject artifact |
| `5` | Lineage or AgentEvent identity, digest, chronology, ordering, or graph failure | Reject chain |
| `6` | Conformance/example suite failure | Block build or release |
| `70` | Internal or dependency failure | Stop; investigate without bypass |

Never use shell constructs that discard these exit codes in a governed workflow.

## 6. Stage-specific minimums

### Requirements quality

- Export `RequirementsAssessment.v1` with stable requirement IDs.
- Preserve confirmed and unresolved findings, questions, approved revisions, source-pack digest,
  human review, provenance, and limitations.
- Add `portfolio-export --run-id ... --output ...` without changing the existing local artifact.

### Stakeholder alignment

- Import and verify the requirements assessment.
- Preserve the exact upstream reference, agreed/disputed/undecided IDs, scoped approvals, open
  conditions, sponsor outcome, and decision digest.
- Reject alignment issues that cite an unavailable requirement.

### Process redesign

- Import both requirements and alignment packets.
- Export the selected option, TO-BE model, preserved controls, assumptions, targets, estimates,
  comparison digest, stakeholder constraints, and human selection.
- Bind the selection to exact upstream digests.

### Business change impact

- Import the confirmed process-redesign decision.
- State the selected option, upstream artifact ID and digest, impacts, unaffected scope, collisions,
  obligations, evidence gaps, risks, and chain digest.
- Reject impact claims derived from a different option or transformation.

### Go-live decision

- Assemble `GoLiveEvidenceBundle.v1` from all four upstream packets and operational evidence.
- Verify every upstream condition and change obligation is represented at the appropriate gate.
- Export gate results, required actions, residual risks, final `PASS`, `BLOCKED`, or `FAIL`, and the
  final portfolio chain digest.
- Keep actual release authorization outside the tool.

## 7. Add CI conformance

Every stage repository should add:

- **producer conformance** for the artifact it exports;
- **consumer conformance** for every artifact it imports;
- **lineage conformance** for stale, tampered, wrong-identity, and cyclic inputs.

Pin stage releases in central integration tests. Required scenarios include the complete happy path,
an upstream condition that blocks go-live, an explicit security or rollback failure, tampering,
wrong transformation and candidate identity, unsupported major version, rejected or superseded
decisions, a missing obligation, a stale bundle, and deterministic final lineage.

Run the local contract suites with:

```bash
portfolio-contracts verify-conformance --json
portfolio-contracts verify-example --json
```

## 8. Release and operate

Publish each adapted stage as v0.2.0 only after its independent tests and contract conformance pass.
A portfolio runner may then invoke the five pinned public CLIs, transfer immutable files, verify
lineage, and render a manifest or dashboard. It must not duplicate business reasoning.

Preserve for every run:

- pinned contract and stage release/commit identities;
- the six stage artifacts and their SHA-256 values;
- conformance and lineage results;
- producer manifests and build provenance;
- authority records and limitations;
- the final portfolio manifest and event chain.

## Upgrade rule

Before adopting a newer compatible v1 release, run the complete local and central conformance suites
with both the old and new validator. A changed acceptance result requires investigation and explicit
adoption; it must not be silently promoted. A v2 contract requires an explicit adapter and migration
decision.
