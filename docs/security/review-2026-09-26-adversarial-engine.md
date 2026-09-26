# Adversarial review, phase 9: engine, evidence, CLI, reference checker, collector, lab supervisor (2026-09-26)

Scope: engine soundness (`packages/afterlock/{model,semantics,engine,results,planner}.py`), evidence
ingestion (`evidence.py`), CLI (`cli.py`), reference-checker independence
(`packages/afterlock_reference`), the Go collector (`services/collector`), and the lab supervisor
(`labs/supervisor`). API, web, containers and CI are out of scope; another review covers them.
This review follows the pattern-based starter in `review-2026-09-26.md`.

Method: every suspected issue got a failing test first and then a minimal fix. Issues that could
not be demonstrated are listed as **unconfirmed**. False containment (the engine reports
`contained_within_scope` or `satisfied_within_scope` while the semantics leave access) is ranked
highest. Line numbers refer to the tree after the fixes.

## Soundness search

`tests/differential/adversarial_generators.py` widens the existing generator. It adds:

- 2 namespaces and several Pods per service account;
- controllers with 0 to 2 Pods;
- ClusterRoleBindings, and RoleBindings that reference ClusterRoles;
- `Group` subjects (`system:authenticated`, `system:serviceaccounts`, `system:serviceaccounts:<ns>`),
  `User` subjects, subjects in other namespaces, and bindings to missing roles;
- `resourceNames` on exec, and a `list secrets` rule;
- Pods with several token audiences, stale SA UIDs, and credentials bound to Pods of other SAs;
- expiry at `T0`, `T0+1`, `TTL-1`, `TTL`, and `TTL+1`, with waits of 1, 89, 90 and TTL seconds;
- rotation windows equal to the waits (S-SEC-5), and two services sourcing one Secret;
- creator-specific admission, and unsupported admission in the other namespace.

Before the fixes, 200 generated cases, plus a longer background run (see "Commands"), turned up no
engine-vs-reference disagreement. Reference exploration was complete for 379 of 400 view runs.
Each confirmed soundness bug below was found by reading the code and building a targeted input. In
every one, the engine and the reference either agreed on the wrong answer or were never generated
into disagreement. Differential agreement alone would not have exposed them.

## Findings

| # | Severity | Location | Finding | Reproduction | Fix | Status |
|---|---|---|---|---|---|---|
| A-1 | **High** (false containment) | `packages/afterlock/model.py:410` (`_not_reserved`), callers in `parse_inventory` / `parse_analysis_input` | An inventory Pod whose UID equals a model UID (e.g. `model-pod:n:admin:i0`) made `_create_workloads` skip modelling the attacker's Pod creation (`if uid in env.pods: continue`). The engine reported `contained_within_scope`; the reference and S-WL-1 reach the Secret. The canonicalization argument in `system.md` assumes that no observed object can carry a reserved UID, but nothing enforced it. | `tests/differential/test_adversarial_engine.py::test_inventory_objects_cannot_use_reserved_model_uids` | The model rejects reserved prefixes on inventory Pod and controller UIDs, and in `controls_pod` / `controls_controller` / `historical_pod` facts. | Fixed |
| A-2 | **High** (false containment, engine **and** reference) | `packages/afterlock/semantics.py:238`, `packages/afterlock_reference/__init__.py` (`_reconcile`) | S-WL-2 replacement Pods are named `<controller>-p<k>`. If a different Pod already had that UID, the engine overwrote it in `env.pods`, and the reference held two tuples for one UID. The attacker's control of an admin Pod vanished, and **both** implementations reported containment. | `test_controller_replacement_does_not_overwrite_an_existing_pod` | Both implementations take the next `k` whose UID is free. `supported.md` S-WL-2 is updated. | Fixed |
| A-3 | **High** (false containment, engine **and** reference) | `semantics.py:88` (`SECRET_READ_VERBS`), `engine.py:305`, reference `_can_read` | Only `get` on Secrets gave knowledge. Kubernetes returns Secret data for `list` and `watch`, so a credential holding only `list secrets` (a common grant) was reported contained. Neither implementation modelled it, and the semantics were silent, which the engine's own rule forbids ("never silently treated as allow or deny"). | `test_list_or_watch_on_secrets_reads_them[list,watch]`; negative control `test_list_with_resource_names_reads_only_named_secrets` | S-SEC-1 now covers get, list and watch. `resourceNames` match the Secret name, because list/watch accept a `metadata.name` field selector. Implemented independently in both checkers. No lab receipt yet (planned). | Fixed (model-level; conformance planned) |
| E-1 | **High** (false containment from evidence) | `packages/afterlock/evidence.py:433` | Attribution was seeded only by `pods`/`pods/exec` creations. Requests from Pods of an attacker-created **Deployment** were not attributed, so an observed Secret read was dropped. In `controller-replacement` the projected input had no `knows_secret`. Once the reader's access was revoked, a copied credential that the audit log shows was read would be reported contained. | `tests/security/test_adversarial_evidence.py::test_reads_by_a_pod_of_an_attacker_created_controller_are_attributed` | Pods in the inventory whose `controller_uid` is an attacker-created controller join the attribution fixpoint. Residual: controller Pods that were already deleted cannot be linked (see U-3). | Fixed (partial) |
| E-4 | Medium | `evidence.py:518` | An attacker's successful `list`/`watch` of Secrets was not projected as knowledge (companion to A-3). | `test_attacker_list_of_secrets_is_observed_knowledge` | Knowledge of every inventory Secret in scope (namespace, and name if present), at its inventory version, noted as assumed. | Fixed |
| E-2 | Medium (credential persistence) | `evidence.py:163` (`_scan_document`), called from `ReplayBundle.load` | `inventory.json` and `case.json` are copied verbatim into the stored analysis input (`cases/<id>/input.json`, exports, API cases), but only events were scanned. A JWT in a Pod annotation or an objective description reached disk. | `test_credentials_in_inventory_are_rejected`, `test_credentials_in_case_are_rejected` | Both files get the forbidden-key and credential-value checks. Any hit is `invalid_input`. | Fixed |
| E-3 | Medium (redaction bypass) | `evidence.py:59-98`; `services/collector/internal/redact/redact.go` | Credential patterns only matched plain text. Base64- or percent-encoded JWTs and base64 PEM headers passed. `collector.gap` reasons are persisted into `coverage_gaps`. Credential-named keys such as `accessToken`, `id_token`, `clientSecret`, `apiKey` and `private_key` were not forbidden. | `test_encoded_credentials_in_persisted_fields_are_rejected`, `test_forbidden_key_variants_are_rejected`; Go `TestEncodedCredentialsAreSensitive` | Added patterns for base64 JWTs (`ZXlK…`) and base64 `-----BEGIN` (`LS0tLS1CRUdJTi`), and matching on the percent-decoded value. The Go side decodes leniently, so one malformed escape cannot turn decoding off. Keys are normalized and suffix-matched in both Python and Go. | Fixed |
| E-5 | Medium (DoS / crash) | `evidence.py:102` (`parse_time`), `_events`, `_json` | `observed_at: "0001-01-01T00:00:00+01:00"` raised an uncaught `OverflowError`, and an event line nested about 20,000 deep raised `RecursionError`. Either way, one record crashed the whole projection instead of becoming a rejected record and coverage gap. | `test_out_of_range_timestamp_is_a_rejected_record_not_a_crash`, `test_deeply_nested_event_is_a_rejected_record_not_a_crash`, `test_parse_time_overflow_is_bundle_error` | Both exceptions are caught and reported as `BundleError` or a rejected record. | Fixed |
| E-6 | Low (soundness edge) | `evidence.py:486` | `credential_expires_at` with a fractional second was truncated, so the token was treated as expired up to 1 s early. A wait landing on the truncated second would claim containment. | `test_fractional_credential_expiry_is_rounded_up` | Expiry rounds up. Other timestamps floor. | Fixed |
| E-7 | Low | `evidence.py:84-98` (`_loads`) | Duplicate JSON keys were resolved last-wins, while other parsers pick first-wins. An event could carry `"outcome":{"http_status":403}` followed by `"outcome":{…200}`. | `test_duplicate_json_keys_in_an_event_are_rejected` | Duplicate keys are rejected: the event becomes a rejected record, and a manifest, inventory or case with duplicates is `invalid_input`. | Fixed |
| G-1 | **Medium** (silent evidence loss) | `services/collector/internal/audit/audit.go:160-168` | Deduplication keyed on `auditID` alone. kube-apiserver accepts a client-supplied `Audit-ID` header, so an attacker who reuses an earlier request's ID has its own request dropped as a "duplicate", counted but with **no gap**. Credential-like IDs also all redact to `[redacted]`, so they collide too. | Go `TestReusedAuditIDWithDifferentContentIsKept` | The key is `auditID` plus a SHA-256 of the envelope content. Byte-identical redeliveries still deduplicate (fixture counters unchanged); a reused ID with different content is kept. | Fixed |
| L-1 | Low (executor-boundary defense in depth) | `labs/supervisor/lab.py:160` (`is_local_endpoint`) | `startswith("https://127.0.0.1:")` accepted `https://127.0.0.1:6443@remote.example` (host `remote.example`) and `https://127.0.0.1:6443.example.com`. The CA-digest and namespace-UID pins still apply, but the "local endpoint only" guard was bypassable, and `create` recorded whatever endpoint it found. | `tests/unit/test_lab_identity.py` | The URL is parsed, and exactly `https://127.0.0.1:<port>` with no userinfo or path is required. `create` refuses to record a non-local endpoint. | Fixed |

## Open (confirmed, not fixed here)

| # | Severity | Location | Finding |
|---|---|---|---|
| O-1 | Low | `evidence.py:486` | One event with a malformed `credential_expires_at` raises `BundleError`, which makes the whole bundle `invalid_input` instead of rejecting that record. The failure is explicit, not unsound. |
| O-2 | Low | `cli.py` (`cmd_plan`, `cmd_verify`, `cmd_analyze --remediation`) | `ModelError` and invalid JSON surface as tracebacks, not `invalid_input`. `_store_result` builds a path from `inp.case_id` without `CASE_ID` validation. It is reachable only through a locally tampered `input.json`, because import validates the ID. |
| O-3 | Low | `afterlock_reference` (`_attacker_steps`) | The reference counts its own workloads by the `ref-pod:` / `ref-deploy:` prefix. An inventory Pod with such a UID reduces the reference attacker. This shows up as a disagreement (engine reaches more), never as false containment, because the engine is not affected. |

## Unconfirmed / design questions

| # | Topic | Note |
|---|---|---|
| U-1 | Possible-history phase and expiry | Both implementations evaluate the history phase at `analysis_time`. A seeded credential that expired before analysis time was usable earlier, and the conservative view may miss Secret knowledge it could have produced then. The written semantics ("the assumed unchanged environment") do not settle whether this counts. Both checkers agree, so no test can demonstrate a violation of the current text. This needs a semantic decision. |
| U-2 | Profile trust | `parse_analysis_input` accepts any `profile` (ID, audiences, TTL) in direct input. The evidence path loads the packaged profile, but direct API or CLI input could shorten the TTL. Worth checking in the API review. |
| U-3 | Attribution through deleted controller Pods | After E-1, requests from an attacker Deployment's Pod that is no longer in the inventory still cannot be attributed. The request carries no controller UID. This could become a coverage gap: "request from an unknown Pod UID". |
| U-4 | Split or custom-encoded tokens | A token split across fields, or encoded other ways (hex, double encoding), is not detectable by pattern matching. Only allowlisted metadata fields are persisted, which limits exposure. |
| U-5 | Collector HTTP server | `ReadHeaderTimeout` and `ReadTimeout` are set; `WriteTimeout` and `IdleTimeout` are not. No resource exhaustion was demonstrated (body 8 MiB via `MaxBytesReader`, token compare constant-time on SHA-256). |
| U-6 | Non-DNS names | Names are not validated as DNS-1123. A `:` in an SA name makes its username unparsable, which is conservative (`unsupported`). A lookalike Unicode name only refers to a different, nonexistent object. No unsound case was found. |

## Checked, no issue found

- **Reference independence.** `tests/security` enforces that the reference imports nothing from `afterlock`, and the fixes kept the implementations separate.
- **Token expiry boundaries.** Strict `<` holds in both checkers, and waits landing exactly on expiry are contained (`test_expiry_on_the_interval_boundary_is_expired`).
- **S-SEC-5 windows.** Rotation windows equal to the wait length agree (generator).
- **Canonicalization with ClusterRoleBindings and Group subjects.** No disagreement, including controller cascades.
- **Planner.** It accepts a plan only on a full re-analysis. It reports `incomplete_search` rather than "no plan".
- **Bundle loading.** It rejects symlinks and path escapes. The file set is fixed, and the manifest must list exactly the three files.
- **Collector memory.** Spool state is bounded by `MaxRecords`/`MaxBytes`, audit lines by 4 MiB, and webhook batches by 8 MiB.
- **Collector `resourceVersion`.** It is used only for watch resume, as an opaque value, with gaps on expiry and relist.
- **Lab supervisor.** It uses argv lists only. Tokens stay in memory, or in a 0600 temporary kubeconfig for the collector that is removed on close. stderr is scrubbed. The kubeconfig CA is pinned.

## Commands and results (Windows 11, Python 3.14, go1.24.13 with GOTOOLCHAIN=local, gcc from msys64)

| Command | Result |
|---|---|
| `python -m ruff check packages services tests datasets benchmarks labs` | pass |
| `python -m mypy` | pass (15 files) |
| `AFTERLOCK_DIFFERENTIAL_EXAMPLES=40 python -m pytest -q tests/unit tests/security tests/differential tests/property` | 278 passed, 1 failed: `test_evidence.py::test_symlinked_file_rejected` fails with `OSError [WinError 1314]` because this host cannot create symlinks. This is a pre-existing environment failure, unrelated to these changes. The run was before A-3/E-4; see the final run below. |
| `go vet ./...` (services/collector) | pass |
| `go test -race ./...` (services/collector) | pass (CGO with gcc available, so `-race` ran) |
| Adversarial hunt script (200 examples, `live=1`, `max_states=20000`) | 0 disagreements, 0 invalid witnesses |
| Same, after all fixes (300 examples, `live=2`) | 0 disagreements (538 complete / 62 incomplete view runs) |
| Final: `python -m pytest -q tests/unit tests/security tests/differential tests/property` (default 150 examples) | 283 passed, 1 failed (the same pre-existing Windows symlink-privilege failure) |

Replay determinism (`datasets/generators/build_semantic_cases.py`) regenerates identical content.
On this Windows checkout the only diff is CRLF line endings (starter finding 11).
