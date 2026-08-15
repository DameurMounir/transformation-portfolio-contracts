# Runtime Envelope v1.1

**Status:** implementation candidate on `feat/02-runtime-envelope-v1-1`  
**Normative schema:** `schemas/envelope/v1.1.json`  
**Stable release:** not yet published; `v1.0.0` remains the current immutable release

`RuntimeEnvelope.v1.1` is the framework-neutral authority and correlation wrapper for governed
runtime messages. It binds an accountable actor, tenant/workspace scope, trace context, payload
schema, policy context, evidence and artifact references, validity window, idempotency key, payload
digest, policy-context digest, and signature metadata into one canonical document.

It does **not** authorize work by itself. A consumer must still evaluate the referenced authority,
policy, approval, capability, and evidence contracts. A valid envelope proves structural and
cryptographic integrity under the configured key; it does not prove that the underlying business
claims are true.

## Normative fields

| Field | Purpose |
| --- | --- |
| `$schema` | Exact `RuntimeEnvelope.v1.1` schema identity. |
| `spec_version` | Contract version, fixed to `1.1.0`. |
| `digest_profile` | RFC 8785 canonicalization plus SHA-256 profile. |
| `envelope_id` | Stable identifier for this immutable envelope. |
| `actor` | Runtime actor and accountable-principal binding. |
| `tenant` | Tenant, workspace, and environment scope. |
| `correlation` | Correlation, causation, and W3C `traceparent` continuity. |
| `schema_uri` | Contract URI of the enclosed payload. |
| `artifact_references` | Content-addressed business artifacts used or produced. |
| `evidence_references` | Content-addressed evidence required by policy. |
| `policy_context` | Bounded, provider-neutral policy inputs. |
| `policy_context_digest` | SHA-256 of the canonical policy context. |
| `payload` | Bounded JSON object carried to the runtime consumer. |
| `payload_digest` | SHA-256 of the canonical payload. |
| `issued_at` / `expires_at` | Exact UTC validity window. |
| `idempotency_key` | Stable replay/deduplication identity. |
| `signature` | Signature profile, algorithm, key identity, signed digest, value, and UTC time. |

Unknown fields are rejected. IDs, arrays, object sizes, timestamps, URIs, digests, and trace context
are bounded by the schema. `AGENT` actors must carry `agent_id`; human and service actors must not.

## Digest and signature construction

The public digest profile is `TPC-JCS-SHA256-v1`.

1. Canonicalize `payload` with RFC 8785 and calculate `payload_digest`.
2. Canonicalize `policy_context` and calculate `policy_context_digest`.
3. Create the signing projection by excluding only the top-level `signature` member.
4. Canonicalize the projection and calculate its SHA-256 digest.
5. Record that value as `signature.signed_digest`.
6. For the reference profile `TPC-HMAC-SHA256-v1`, calculate HMAC-SHA-256 over:

   ```text
   UTF8("TPC-RUNTIME-ENVELOPE-HMAC-SHA256-v1\\0") || HEX_DECODE(signed_digest)
   ```

7. Record the lowercase hexadecimal HMAC as `signature.value`.

Any payload, policy, identity, scope, reference, timestamp, idempotency, or correlation mutation
changes the signed digest and invalidates the signature.

The HMAC profile is a deterministic reference profile for bounded service-to-service trust. Key
material is injected through a resolver, never serialized into an envelope, fixture, log, error, or
telemetry record. Later asymmetric profiles must use a new versioned profile and remain backward
compatible with this schema family.

## Verification order

Consumers fail closed in this order:

1. validate Draft 2020-12 structure and formats without network schema resolution;
2. validate the Python reference model and actor/trace/temporal invariants;
3. recompute payload and policy-context digests;
4. recompute the complete signing-projection digest;
5. enforce `issued_at`, `expires_at`, and `signature.signed_at` ordering;
6. resolve the exact `signature.key_id` through injected trust configuration;
7. compare the HMAC in constant time;
8. only then evaluate domain authority and execute a runtime transition.

Missing keys, resolver errors, malformed trace IDs, unsupported versions, stale or future validity
windows, digest mismatches, and signature mismatches are terminal validation failures.

## Python reference API

```python
from datetime import datetime, timezone

from transformation_portfolio_contracts.runtime_envelope import (
    sign_runtime_envelope,
    verify_runtime_envelope,
)

key = key_provider.resolve("KEY-RUNTIME-001")
signed = sign_runtime_envelope(
    unsigned_envelope,
    key_id="KEY-RUNTIME-001",
    key=key,
    signed_at=datetime.now(timezone.utc),
    root=contract_root,
)

result = verify_runtime_envelope(
    signed,
    key_resolver=key_provider.resolve,
    now=datetime.now(timezone.utc),
    root=contract_root,
)
```

Callers own key storage, rotation, revocation, authorization decisions, and clock policy. The
reference implementation never creates durable keys or treats a valid HMAC as business approval.

## Compatibility and migration

- Existing v1.0.0 artifact, event, evidence, human-decision, and risk schemas remain immutable.
- Runtime envelope v1.1 adds a new common contract; it does not rewrite any released v1 schema.
- Consumers must reject unsupported major versions and must not silently remove unknown signed
  fields before verification.
- A later v1.1.0 release will publish this schema, fixtures, digest manifest, and migration guide.
- Until that release, the contract is a candidate and consumers must pin the exact commit used for
  integration testing.

## Fixtures and test vectors

`fixtures/runtime-envelope/v1.1/` contains:

- a fully signed valid envelope;
- payload-tamper, signature-tamper, expired, unsupported-version, and invalid-trace fixtures;
- deterministic payload, policy, envelope-projection, and HMAC vectors;
- expected fail-closed diagnostic codes.

The fixture key is explicitly public test material and has no operational authority.

## Explicit limitations

This branch does not provide an identity registry, production key-management service, asymmetric
PKI, remote protocol transport, authorization policy engine, database, workflow state, model call,
tool execution, deployment, or production-readiness claim. Those remain separate governed
components and roadmap branches.
