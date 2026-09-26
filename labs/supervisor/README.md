# Lab supervisor

`lab.py` is the only component allowed to mutate lab resources. It:

- creates the kind cluster `afterlock-lab` and records its identity (context, API endpoint,
  CA certificate digest, `demo` namespace UID, random lab instance id) in `labs/.state/lab.json`;
- refuses every later command unless the live cluster matches that record;
- performs only fixed, allowlisted actions against the `demo` namespace (no shell strings,
  no arbitrary manifests, no target URLs);
- holds service-account tokens only in process memory, sends them only to the recorded API
  endpoint, and never writes them to disk or logs;
- writes receipts (HTTP status codes, timings, model predictions) to `labs/receipts/`.

Commands: `create`, `spike`, `destroy`, `status`. See docs/tutorials/live-lab.md.
