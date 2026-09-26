# Live lab: semantic spike

**Status: written, not yet executed.** Until a receipt exists, every result says
`validation: not_executed` and the profile says `unverified`.

## Requirements

- A **disposable** Linux host with a Docker daemon, `kind`, and `kubectl`. Never use a host
  that holds real cluster credentials.
- About 4 CPU and 8 GB RAM for the spike.
- `python scripts/doctor --profile live-lab` must report `available`.

## Run

```bash
scripts/lab create     # kind cluster "afterlock-lab"; records the lab identity in labs/.state/lab.json
scripts/lab spike      # real API outcomes vs model predictions -> labs/receipts/spike-*.json
scripts/lab destroy    # deletes only the recorded cluster
```

Or run the `live-lab` workflow (manual dispatch) on a disposable GitHub-hosted runner.

## What the spike checks

| Step | Model prediction |
|---|---|
| CI token creates a Pod as `release-reader` | allowed |
| That Pod's token reads `release-credential` | allowed |
| After deleting `ci-pod-creator`, CI creation is denied | denied (time until effective is recorded) |
| The stolen token still reads the Secret | **allowed: residual access** |
| After the Pod is fully deleted, the stolen token is rejected | 401 (time recorded) |
| With the CEL admission policy, CI cannot select `release-reader` | denied |

Any disagreement is recorded as `lab_contradicted`. It must be investigated, and the model
must be revised before the profile can be marked verified.

## Safety

The supervisor refuses to act unless the context, local API endpoint, CA digest,
namespace UID, and lab instance label all match the record. Tokens exist only in process
memory, and response bodies are never read. The fake Secret value is random and never stored.
