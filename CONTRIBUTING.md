# Contributing

Contributions are welcome when they preserve independent repositories, immutable artifact transfer,
explicit human authority, deterministic digests, and fail-closed consumption.

## Development setup

Python 3.11, 3.12, and 3.13 are supported.

```bash
python3 -m venv .venv
. .venv/bin/activate
make install-dev
make check
```

`make check` is the local equivalent of the core CI gates. It runs formatting and lint checks,
strict static typing, tests with coverage, contract conformance, security checks, and package
validation.

## Change rules

1. Create a focused branch and keep unrelated files out of the change.
2. Add or update conformance fixtures for every normative contract change.
3. Preserve a valid example for each supported contract and a negative fixture for each rejection
   rule.
4. Do not rewrite a published contract in place. Add a compatible minor contract or a new major
   version under a new identifier.
5. Do not fetch a producer's floating `main` branch from validation code or tests.
6. Do not add provider-specific identity, storage, transport, or workflow requirements to the
   normative schemas.
7. Do not make a digest comparison optional or silently coerce malformed values.
8. Do not allow a schema or validator to infer business approval.

## Contract change checklist

- Describe producer and consumer impact.
- Classify the change as patch, backward-compatible minor, or breaking major.
- Update `registry/contract-catalog.json` and `registry/compatibility-matrix.json`.
- Update the producer-consumer map if the data flow changes.
- Add valid, invalid, and expected-result fixtures.
- Confirm deterministic canonical bytes and digests.
- Confirm wrong identity, unsupported version, altered digest, stale reference, and lineage-cycle
  cases still fail closed.
- Update the relevant documentation and changelog.

## Pull requests

A pull request should state the contract IDs changed, compatibility classification, affected
producers and consumers, test evidence, and rollback approach. Review approval and green CI are
required before a normal protected merge. Squashing or rebasing published contract history is not
part of this repository's release process.

## License

By contributing, you agree that your contribution is licensed under Apache License 2.0.
