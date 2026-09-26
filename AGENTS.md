# AFTERLOCK Engineering Contract

## Mission
Determine whether modeled residual attacker access survives a proposed
containment sequence. Never equate removal of an acquisition permission
with removal of capabilities acquired earlier.

## Read before editing
Read the architecture (`docs/architecture/system.md`), supported semantics
(`docs/semantics/supported.md`), relevant ADRs (`docs/adr/`), current status
(`docs/engineering/status.md`), and the code and tests for the affected subsystem.
If a file does not exist, say so; do not pretend it was read.

## Architecture
The domain model and engine (`packages/afterlock/{model,semantics,engine,results,planner}.py`)
are pure libraries. They must not import HTTP frameworks, database sessions,
Kubernetes clients, or frontend code. External adapters (`evidence.py`, `cli.py`,
`services/api`) validate and normalize inputs.
The reference checker (`packages/afterlock_reference`) must not import `afterlock`
or reuse production transition/search logic. `tests/security` enforces both rules.

## Incremental changes
State the intended behavior and affected interfaces before editing.
Add characterization tests when existing behavior lacks coverage.
Change one concern at a time. Avoid unrelated rewrites.
Preserve public interfaces (schemas `afterlock.analysis-input/1`, `afterlock.result/1`,
`afterlock.replay/1`, `afterlock.plan/1`) unless an explicit migration is approved.

## Semantic rules
Separate observed facts, inferred possibilities, and assumptions.
Separate credential possession, authentication, authorization, and knowledge.
Respect object UIDs and declared time semantics.
Unknown, stale, unsupported, and incomplete are first-class states.
Never convert missing evidence or a search cap into containment.
A new semantic rule needs: specification in `docs/semantics/supported.md`, a positive
case, a negative control, a reference-checker implementation, and a conformance plan.

## Testing
Run relevant unit, property, differential, integration, and security tests
(`./scripts/verify`). Run lint and type checks for changed languages.
Record exact commands and environment in `docs/engineering/verification.md`.
Skipped, blocked, and not-run checks are not passes.
Do not weaken assertions to make a failing implementation pass.
Do not regenerate `datasets/fixtures/expected.json` from engine output.

## Lab safety
Only the isolated lab supervisor (`labs/supervisor/lab.py`) may mutate lab resources.
Never target arbitrary clusters, public services, or user credentials.
Never mount the Docker socket into the product.
Never persist tokens or Secret bodies.
Do not run privileged jobs for untrusted contributions.

## Dependencies
Use lockfiles and pinned release inputs.
Justify every new runtime dependency in the change summary.
The core packages have zero runtime dependencies; keep it that way.
Do not download and execute unverified scripts.

## Documentation
Update contracts, semantic coverage, limitations, and examples with behavior.
Performance and security claims require reproducible evidence.

## Completion
Report changed files, behavior, tests, security implications, migrations,
remaining risks, and the next task. Update `docs/engineering/status.md`.
Do not call the system production-ready because CI is green.
