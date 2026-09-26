# Contributing

Thank you for helping make false containment claims harder to produce.

1. Read [AGENTS.md](AGENTS.md). It is the engineering contract for humans and agents alike.
2. Keep pull requests small, and focus each one on a single concern.
3. Run `./scripts/verify` and list the exact commands in the PR template.

## Semantic rule contributions

A change to what the engine considers possible must include:

- the rule, added to `docs/semantics/supported.md`, with its exclusions;
- a positive case and a negative control in `datasets/generators/build_semantic_cases.py`,
  with expected outcomes written in `datasets/fixtures/expected.json` **before**
  implementation;
- an independent implementation in `packages/afterlock_reference`;
- a conformance plan (a lab step in `labs/supervisor/lab.py`) or an explicit statement
  that the rule is unverified.

## Scenario contributions

Scenarios must use synthetic data, isolated targets, deterministic setup,
independently recorded outcomes, and teardown.

## Licensing

Contributions are accepted under Apache-2.0. Do not copy code whose license is
incompatible with Apache-2.0.
