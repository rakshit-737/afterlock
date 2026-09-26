# ADR 0003: Reference checker shares no semantic or search code

- Status: accepted
- Date: 2026-09-25

## Decision
`afterlock_reference` re-implements the semantics from the written specification.
It uses a different state encoding and explicit BFS, and it does not import `afterlock`.
Only the naming conventions for model-created objects are shared, because witness replay
needs them.

## Consequences
The duplicated logic costs maintenance. In exchange, it has already caught one engine
witness bug and one checker bug. See docs/architecture/reference-checker.md.
