# ADR 0002: No AI component in containment decisions

- Status: accepted
- Date: 2026-09-25

## Decision
No LLM or learned model participates in the MVP or V1. Conclusions come from explicit
rules, bounded search, and checkable witnesses. Explanations are generated
deterministically from provenance.

## Consequences
Results are reproducible (`result_digest` is stable across runs) and can be challenged
step by step.
