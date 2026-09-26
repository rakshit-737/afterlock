# AFTERLOCK

**A permission was revoked. Prove the access is gone.**

AFTERLOCK is an open-source, evidence-backed **containment verifier** for Kubernetes
workload identities. It models permissions, previously acquired credentials,
attacker-controlled workloads, and credential lifecycles. From that model it
determines whether a proposed remediation removes attacker access, or only blocks
the way that access was first acquired.

!!! warning "Maturity: research-grade, version 0.1.0. Not production-ready."
    From the [final audit](engineering/final-audit.md#6-verdict): *AFTERLOCK 0.1.0 is a
    research-grade containment verifier with one live-validated scenario family. It is not
    production-ready. It is also not a general Kubernetes security tool.*

    Live validation covers one Kubernetes version (v1.31.4) on one idle single-node kind
    cluster; other rules remain model-level. See the [final audit](engineering/final-audit.md)
    and the [current status](engineering/status.md).

## Quick start (replay mode: Python 3.11 only, no cluster, no Docker)

```bash
git clone https://github.com/rakshit-737/afterlock afterlock && cd afterlock
./scripts/bootstrap                       # creates .venv, installs afterlock (core has zero runtime deps)
. .venv/bin/activate
python scripts/doctor --profile replay

afterlock replay import datasets/replay/residual-token
afterlock analyze --case residual-token
afterlock explain --latest
afterlock verify --latest                 # independent reference checker
afterlock plan --case residual-token      # constrained containment search
```

`make demo` runs the same sequence. `./scripts/verify` runs lint, strict typing, all
tests, and the replay-reproducibility check. The full walkthrough is in the
[repository README](https://github.com/rakshit-737/afterlock#readme).

## Where to go next

- [Architecture](architecture/system.md) and [supported semantics](semantics/supported.md)
- [CLI reference](cli/cli.md) and the [live lab tutorial](tutorials/live-lab.md)
- [Verification record](engineering/verification.md) and [research claims](research/claims.md)
- [Threat model](threat_model/threat-model.md) and [security policy](security/policy.md)
