# Changelog

All notable changes are recorded here. This project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Contracts

- Add the candidate `RuntimeEnvelope.v1.1` Draft 2020-12 schema with bounded actor,
  accountable-principal, tenant/workspace, correlation/causation/trace, payload-schema,
  artifact/evidence-reference, policy-context, digest, expiry, idempotency, and signature fields.
- Add strict Pydantic reference models, RFC 8785/SHA-256 digest binding, a domain-separated
  HMAC-SHA-256 reference profile, injected key resolution, and fail-closed verification.
- Add deterministic valid, tamper, expiry, unsupported-version, invalid-trace, digest, and signature
  fixtures with golden vectors and expected diagnostics.
- Package the runtime-envelope schema and fixtures while preserving every released v1.0.0 contract.

### Governance

- Add the G0 repository identity manifest, target-name collision evidence, dependency and hosted
  Action inventory, complete-history backup checksum, and restore-rehearsal record.
- Record the proposed `transformation-agent-contracts` identity without changing repository
  settings or immutable v1.0.0 compatibility identifiers.

## [1.0.0] - 2026-08-10

### Added

- Draft 2020-12 contracts for the common envelope, five shared primitives, and six stage
  artifacts.
- Versioned contract catalog, compatibility matrix, and producer-consumer registry.
- Positive and negative conformance fixtures plus the AtlasBridge end-to-end example.
- RFC 8785 canonicalization, SHA-256 digest verification, fail-closed validation, and
  lineage-cycle detection.
- A provider-neutral `portfolio-contracts` CLI.
- Governance, adoption, architecture, and digest-profile documentation.
- Python 3.11-3.13 CI, deterministic package checks, release checksums, and build provenance.
- A non-vulnerable setuptools 83.x build boundary and defense-in-depth source-distribution path
  validation for `PYSEC-2026-3447`.
- A fail-closed VPS transaction with pre-gate and pre-commit source inventories, installed-wheel
  resource isolation, atomic source/tag publication, and an explicit release-pending terminal state.

[Unreleased]: https://github.com/DameurMounir/transformation-portfolio-contracts/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/DameurMounir/transformation-portfolio-contracts/releases/tag/v1.0.0
