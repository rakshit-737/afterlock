# ADR 0004: Per-interval monotone fixpoint with one live model workload per service account

- Status: accepted
- Date: 2026-09-25

## Context
The attacker does not pause between defender steps. Enumerating interleavings explicitly
is exponential.

## Decision
Supported attacker transitions only add capability. Between defender steps, the engine
therefore computes the fixpoint, which equals the join over interleavings. To keep
workload creation finite, it keeps at most one live *model-created* workload per
(namespace, service account, kind). This is sound because:
1. defender actions cannot address model-created UIDs (they are reserved prefixes);
2. selector-based deletions treat all such workloads alike;
3. observed attacker workloads never count toward the limit.

An earlier draft kept one live workload of *any* origin. That was unsound: an attacker
could create a second Pod before the binding was removed, and it would survive deletion
of the first. This was found during design review, before implementation.

## Consequences
The planner needs selector-based defender actions (`delete_pods_except`) to remove
workloads the defender never observed. This matches real incident response.

## Evidence that would reverse this decision
Any differential disagreement with the reference checker at
`max_live_attacker_workloads_per_sa >= 2`, or a new defender action that can distinguish
model-created workloads.
