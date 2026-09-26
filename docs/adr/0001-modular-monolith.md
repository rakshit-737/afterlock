# ADR 0001: Modular monolith with pure domain packages

- Status: accepted
- Date: 2026-09-25

## Context
The hard part is semantic correctness, not scale. Microservices would add failure
modes without adding verification value.

## Decision
One Python distribution. The domain modules (model, semantics, engine, results, planner)
are pure and have no runtime dependencies. Adapters (evidence, CLI, API) sit around them.
Trust-sensitive processes (the lab supervisor, and a future collector) stay separate. No
graph database, broker, or cache.

## Consequences
The engine runs directly on a replay directory without services. PostgreSQL arrives with
the worker, as an adapter.

## Evidence that would reverse this decision
Measured ingestion or analysis load that a single process cannot meet.
