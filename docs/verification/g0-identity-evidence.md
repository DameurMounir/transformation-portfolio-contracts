# G0 identity evidence

## Result

| Control | Result | Evidence |
| --- | --- | --- |
| Source commit/tree authority | PASS | `4fb6af9344ba1b903fdda96891a18eb708ab82ea` / `e44be69ff1cd60fe9bb6f45a1b915db3fa7b6e27` |
| Target-name collision check | PASS | Target lookup returned HTTP 404 at capture time |
| Hosted Action dependency scan | PASS | Zero matches across seven exact repository snapshots |
| Direct consumer inventory | PASS | One consumer, ten exact files, commit/tree recorded |
| Complete-history backup | PASS | SHA-256 `63b90e98f049931a7681fc1a06d892e800ed9718bae5757667b7d408dee3a0f0` |
| Restore rehearsal | PASS | Main and v1.0.0 object/commit/tree reproduced exactly |
| Identity verifier and relative links | PASS | Offline manifest verifier and Markdown link scan |
| Schema/runtime behavior | PASS, UNCHANGED | 79 tests, 90.12% branch coverage, 5 valid and 23 invalid conformance fixtures |
| Quality and security | PASS | Ruff, formatting, strict mypy for seven source files, Bandit, and dependency audit |
| Current branch protection read | BLOCKED | Connected integration returned HTTP 403 |
| Remote branch and draft PR | BLOCKED | Not published in this local evidence capture |
| Repository rename | BLOCKED | Outside G0; requires separate explicit authorization |

## Evidence boundary

This record proves that an identity transition is feasible under the stated controls. It does not
prove that the branch is on GitHub, that required checks passed remotely, that protection is active,
or that a rename occurred. Those claims require their own GitHub URLs and exact post-mutation refs.

The dependency audit reported no known third-party vulnerability and skipped only the editable
first-party distribution.
