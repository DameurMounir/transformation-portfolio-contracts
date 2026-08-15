# Runtime envelope v1.1 status

**Branch:** `feat/02-runtime-envelope-v1-1`  
**State:** implementation candidate  
**Stable package/release:** `v1.0.0` remains authoritative  
**Consumer adoption:** not claimed

## Implemented in this branch

- strict Draft 2020-12 `RuntimeEnvelope.v1.1` schema;
- actor/accountable-principal, tenant/workspace, correlation/causation/trace, payload-schema,
  artifact/evidence-reference, policy, digest, expiry, idempotency, and signature fields;
- Pydantic reference models with forbidden extra fields and semantic invariants;
- RFC 8785/SHA-256 payload, policy-context, and signing-projection digests;
- domain-separated HMAC-SHA-256 reference signing and constant-time verification;
- injected key resolution with fail-closed missing/error behavior;
- deterministic valid, tamper, expiry, unsupported-version, and trace fixtures;
- canonical digest and signature golden vectors;
- schema, model, tamper, temporal, resolver, and signature tests;
- packaging, catalog, README, changelog, and contract documentation updates.

## Required evidence before merge

- Ruff lint and format on the exact head;
- strict mypy on the exact head;
- all existing and new tests on Python 3.11, 3.12, and 3.13;
- branch coverage at or above the repository threshold;
- existing v1.0 conformance and AtlasBridge example unchanged;
- Bandit and dependency audit;
- deterministic wheel and source archive build;
- installed-wheel discovery of the new schema and fixtures;
- exact-head GitHub CI success.

## Explicit non-claims

No runtime service has adopted this envelope. No repository has been renamed by this branch. No
production signing key, approval authority, database, model, A2A/MCP transport, tool execution, or
deployment is created. A schema-valid and signature-valid envelope still requires a separate
business-authority decision.
