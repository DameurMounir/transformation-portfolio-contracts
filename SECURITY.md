# Security policy

## Supported versions

| Version | Security support |
| --- | --- |
| 1.0.x | Supported |
| Earlier or unreleased snapshots | Not supported |

Only immutable release tags are suitable for a governed portfolio run. A floating branch is
development material, not a certified dependency.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use the repository's **Security** tab
to submit a private vulnerability report through GitHub Security Advisories:

<https://github.com/DameurMounir/transformation-portfolio-contracts/security/advisories/new>

Include the affected release, contract or command, a minimal reproduction, the expected security
property, observed behavior, and impact. Do not include production secrets, personal data, or
third-party confidential evidence.

The maintainer will acknowledge a complete report as soon as practical, investigate it without
weakening validation, and coordinate remediation and disclosure. No response-time guarantee is
made by this public, independently maintained project.

## Security boundary

This repository validates portable artifacts; it does not grant business authority, execute a
release, sign artifacts, retrieve confidential evidence, or replace source-system access controls.
Consumers must independently verify release provenance and preserve their own authorization gates.

Validation is fail-closed for malformed schemas, unsupported major versions, digest mismatches,
identity conflicts, invalid lifecycle states, missing required human decisions, stale references,
and lineage cycles. A successful schema check is necessary but not sufficient evidence for a
business decision.

## Release integrity

Official releases publish source and wheel distributions, `SHA256SUMS`, and GitHub build provenance.
Verify the release tag, checksum, and attestation before use. Report any discrepancy privately.

Build isolation is constrained to `setuptools>=83,<84`. Earlier versions, including 81.0.0 and
82.0.1, are prohibited by the release gates because
[PYSEC-2026-3447](https://github.com/pypa/advisory-database/blob/main/vulns/setuptools/PYSEC-2026-3447.yaml)
allows a Unicode-normalization collision to bypass `MANIFEST.in` exclusions during source archive
creation. The custom reproducible-sdist hook also rejects non-NFC paths, normalization collisions,
links, and special files before archiving.
