# Final audit (design phase 12 / prompt 20)

Date: 2026-09-26. Audited tree: `b574b8f` (`origin/main`) plus the doc corrections listed in
section 3. Auditor: independent pass. I checked each claim against files, tests, receipts and CI
logs. I did not trust summaries in other docs.

Rule used throughout: **if there is no evidence, the item is not met.** A skipped, blocked or
unexecuted check is not a pass. "Model-level" means the engine and the independent reference
checker agree, but no real cluster confirmed the result.

Primary evidence:

| Evidence | What it shows |
|---|---|
| CI run [36244804735](https://github.com/rakshit-737/afterlock/actions/runs/36244804735) (head `78ac404`) | 6/6 jobs green. portable: ruff, `mypy` (15 files), pytest **359 passed, 20 skipped** (the skips are PostgreSQL/live-lab BLOCKED; each is run in its own job), 300 Hypothesis examples per differential test. postgres: **41 passed**, where any skip fails the job. web: 46 vitest, **6 Playwright** incl. axe. collector, containers (compose smoke), sbom |
| live-lab run [36244828581](https://github.com/rakshit-737/afterlock/actions/runs/36244828581) (head `78ac404`) | spike 3 runs: `1 passed`. collector: `1 passed`. Receipts `labs/receipts/spike-summary-20260926T132141Z.json` (3 x 17 steps, `all_runs_agree: true`, `missing_steps: {}`) and `collect-20260926T132806Z.json` (`lab_confirmed`, 28/28 checks, both windows) |
| Commits after `78ac404` | Only receipts and regenerated labels (`e648715..b574b8f`). No CI run covers them. `tests/unit/test_lab_receipts.py` / `test_committed_lab_labels_match_receipts` passed in the local reproduction (section 5) |

---

## 1. Acceptance matrix

Status key: **met** · **partial** · **not met** · **n/a**.

### 1a. Development phases (design doc, "Development Phases")

| Phase | Acceptance criterion | Status | Evidence / gap |
|---|---|---|---|
| 0 Research + architecture | Every research claim has a proposed falsification test; no unsupported novelty claim | met | `docs/research/claims.md` (C1–C8 each have a falsification test), `docs/research/prior-art.md`, README "Prior art" disclaims novelty of components |
| 0 | Machine-readable scenario contract | met | `schemas`/`afterlock.analysis-input/1`, `datasets/fixtures/expected.json`, `docs/research/scenarios.md` |
| 1 Core engine | Unit and property tests pass | met | CI 36244804735 portable; `tests/unit/test_model_and_semantics.py`, `tests/property/test_rotation_propagation.py` |
| 1 | Reference agreement on small cases | met | `tests/differential/test_engine_vs_reference.py::test_semantic_cases_agree`, `::test_generated_cases_agree` (300 examples in CI), `test_adversarial_engine.py::test_adversarial_generated_cases_agree` |
| 1 | One early live semantic check | met | `labs/receipts/spike-20260926T054738Z.json` (run 36221758899) |
| 1 | CLI-computable residual-access witness | met | `afterlock explain` output in README; `test_flagship_witness_explains_residual_credential` |
| 2 Data/telemetry | Duplicate, reordered, late, malformed, missing-event tests pass | met | `test_duplicates_are_harmless_and_counted`, `test_delivery_order_does_not_change_input`, `test_conflicting_duplicate_becomes_gap`, `test_malformed_and_sensitive_records_rejected_and_gap_recorded`, `test_stale_collector_is_a_gap` |
| 2 | Deterministic replay bundle | met | CI portable "replay determinism" step; `test_determinism`; `test_manifest_is_content_addressed` |
| 2 | Live metadata feed | partial | Collector ran live, 2 windows `lab_confirmed` (`collect-20260926T132806Z.json`). Not a continuous feed: the lab runs it batch-style. Watch-expiry (410) fault and kube-apiserver's own webhook backend are not exercised live. No evidence/cursor tables in PostgreSQL |
| 3 Security intelligence | Known unsafe fixes fail | met | `residual-token`, `defender-race`, `copied-downstream` cases (`benchmarks/reports/semantic-corpus.md`); lab `residual-token-still-reads-secret` 200 x3 |
| 3 | Valid small plans match exhaustive search | met | `tests/unit/test_planner_and_baselines.py::test_plan_matches_exhaustive_optimum_on_small_candidate_set` (optimum over a small candidate set only) |
| 4 Backend | API contract, worker recovery, migration and authorization tests pass | met | `tests/integration/test_api*.py`, `test_storage_contract.py` (`test_worker_death_lease_expiry_rerun_and_duplicate_completion`, `test_interrupted_publication_leaves_no_partial_result`), `test_migrate.py::test_schema_upgrade_from_0001_preserves_data_and_immutability`, `test_cross_cluster_access_is_indistinguishable_from_missing`; postgres job 41 passed |
| 4 | Exports | partial | `afterlock export` (CLI) and `scripts/export_replay`. There is **no replay export from the DB/API** (status.md) |
| 5 Frontend | Playwright tests pass | met | CI web job: 6 Playwright tests (`services/web/e2e/*.spec.ts`) |
| 5 | Accessibility checks pass | met (scope-limited) | axe zero serious/critical in light and dark (CI web job). No manual screen-reader audit |
| 5 | Stale/unknown-state tests pass | partial | Unknown states: `ResultView.test.tsx` and fixtures. No test targets **stale-result mixing** by name. Prompt 12 also requires "generated API contract", which is not met (types are hand-written in `services/web/src/api/types.ts`) |
| 6 Demo lab | Repeated create/run/reset cycles pass | met | 4 repeated summaries (`spike-summary-*`), each 3 runs with `reset`, all `lab_confirmed` |
| 6 | Old access survives the naive fix and fails after validated containment | met (one version) | `residual-token-still-reads-secret` 200; `bound-token-rejected-after-pod-deletion` 401; `copied-credential-rejected-after-rotation` 401 (3/3 in latest summary) |
| 6 | Exported replay | met | Collector bundle uploaded as artifact `collected-bundle` (run 36244828581) after the leak scan |
| 7 Detection/evaluation | Predictions compared against independently recorded outcomes; disagreements visible | partial | Lab-derived labels (`benchmarks/labels/lab-derived.json`, 14 receipts) cover only 6 objectives in 4 cases from one scenario. Held-out labels are reference-derived, not outcome-derived. Held-out templates have **not** been executed in the lab |
| 8 Advanced | Each feature has conformance tests and ablation value | partial | S-SEC-5 is lab-confirmed (`s-sec-5-*` steps 3/3), but `d` is measured in the same run (consistency, not prediction). No robust-plans-under-uncertainty work, and no richer controller behaviour |
| 9 Hardening | No unresolved critical boundary failure | met (as far as reviewed) | Three reviews (`docs/security/review-*.md`): every High finding fixed with a regression test. Open items are Low/Medium (section 4) |
| 9 | Canary secrets absent from all exported surfaces | partial | Bundles, receipts and API: `test_canaries_never_reach_outputs`, `test_golden_bundle_carries_no_credential_material`, lab leak scan, e2e "token never reaches web storage, cookies, the URL, or the DOM". DB exports do not exist, and logs are not scanned systematically |
| 10 Benchmarks | Raw results, manifests, scripts, confidence treatment published; claims match measurements | partial | `benchmarks/run.py` regenerates `benchmarks/reports/*` (the report was stale; regenerated here, see section 3). There is **no confidence-interval treatment**, no scaling sweep, and no performance numbers (timings deliberately uncommitted). `docs/research/results.md` named in the design does not exist |
| 11 Documentation | A fresh environment follows the docs without hidden steps | partial | Portable checks reproduced from a fresh clone on Windows (section 5). This was not done by a third party. `./scripts/bootstrap` / `make demo` and the live lab were not run from docs by someone new. Cold-start vs warm demo duration is not recorded |
| 12 Final audit | All required checks pass on documented environments; blocked checks remain blockers | partial | CI and live-lab green (above). Blockers that remain: section 6. **No release tag exists** (`git tag` empty), and none should be created until the section 6 blockers are addressed or accepted |

### 1b. MVP table

| Deliverable | Status | Evidence |
|---|---|---|
| Typed temporal state model separating permissions, possession, validity, information | met | `packages/afterlock/model.py`; `test_knowledge_is_monotone_usability_is_not`, `test_credential_usability_reasons` |
| Reference explorer finds residual access, rejects negative controls | met | `packages/afterlock_reference`; `test_semantic_cases_agree` incl. `admission-denied`, `same-name-recreation` |
| Replay runs without Kubernetes/proprietary services | met | Section 5 (no cluster, no Docker used) |
| Minimal live lab: binding removal leaves delegated access usable | met | `residual-token-still-reads-secret` 200 (every spike receipt) |
| Model witness includes evidence, assumptions, rule ids, bounds | met | `results.py`; `test_contained_result_states_scope`, `test_witnesses_replay_in_reference_checker` |
| CLI imports, analyzes, explains, exports | met | `packages/afterlock/cli.py`; CI `make demo`-equivalent steps |
| Basic API without duplicating reasoning | met | `services/api`; `test_domain_packages_do_not_import_adapters`; API calls the engine |
| Explicit unknown state | met | `test_search_limit_never_establishes_containment`, `test_unknown_names_the_missing_evidence`, mutation `test_mutant_is_killed_*` |

### 1c. Implementation prompts 01–20

| # | Acceptance (abridged) | Status | Evidence / gap |
|---|---|---|---|
| 01 | New session finds architecture, profiles, next task from repo files | met | `AGENTS.md`, `CLAUDE.md`, `docs/engineering/status.md` ("Next safe task"), `scripts/doctor --profile`, `afterlock version` / `capabilities` |
| 02 | Round-trip, deterministic serialization, validation, property tests; model free of API/DB imports | met | `test_digest_is_key_order_independent`, `test_rejects_malformed_input`, `test_invalid_inputs`, `test_domain_packages_do_not_import_adapters` |
| 03 | Permission removal keeps possession; knowledge persists; incomplete exploration never unconditional containment | met | `test_acquisition_survives_source_permission_removal`, `test_knowledge_is_monotone_usability_is_not`, `test_incomplete_search_is_labelled`, `test_search_limit_never_establishes_containment`; independence `test_reference_checker_is_independent_of_engine` |
| 04 | Cases agree; witnesses replay; conclusions include assumptions, profile, bounds, unsupported | met | Differential suite; `test_generated_witnesses_are_valid`; `test_mutant_is_killed_by_reference_checker` |
| 05 | Real receipts, pinned version, actual timings, admission negative control | met | `spike-20260926T054738Z.json` onward; v1.31.4; `negative-control-admission-denies` 422; timings in summaries |
| 06 | Replay produces identical canonical inputs on repeats; missing evidence never negative fact | met | `test_determinism`, `test_delivery_order_does_not_change_input`, `test_stale_collector_is_a_gap`, `test_wrong_cluster_events_rejected` |
| 07 | Watch gaps visible; duplicates harmless; no sensitive payloads; restart resumes or records uncertainty | partial | Restart gaps and leak scan are lab-confirmed (`collector-restart-recorded-as-gap`, `collected-bundle-has-no-credential-material`). Go fake-client tests cover duplicates. **Watch expiry not forced live.** RBAC minimality ("each permission necessary") is argued in `docs/collector/README.md`, not tested |
| 08 | Crash recovery cannot publish on partial input; replay export preserves dependencies | partial | `test_interrupted_publication_leaves_no_partial_result`, `test_stale_lease_*` (A-2 fixed). **Retention not implemented; no DB replay export; evidence/cursor tables absent** |
| 09 | Uncertainty affects conclusion explicitly; no invented probability; explanation names missing evidence | met | `test_unknown_names_the_missing_evidence`, `test_possible_state_residual_is_labelled_as_such`, `test_evidence_view_never_worse_than_possible_view`. Gap: "analysis versioning when late evidence changes a conclusion" exists only as immutable manifests + `manifest_version` in SSE; no supersession test |
| 10 | Small plans match oracle; incomplete search labelled; no unjustified "optimal" | met | `test_plan_matches_exhaustive_optimum_on_small_candidate_set`, `test_incomplete_search_is_labelled`, `test_planner_offers_propagation_wait`; `defender-race` case |
| 11 | Backend protects every sensitive op independently of frontend | met (for listed endpoints) | `test_full_flow_and_role_separation`, `test_cross_cluster_access_is_indistinguishable_from_missing`, `/v1/lab/*` always 403 (`test_api_never_mutates_clusters`). Gaps: OpenAPI-generated **frontend types not done**; OIDC only against local keys / fake JWKS; limits per process |
| 12 | Investigator can explain naive failure from visible evidence and see every assumption | partial | Playwright `upload residual-token bundle, analyze: residual path with provenance, evidence and credential lifecycle`, `targeted containment remediation is contained within scope`. No usability study; no SSE consumption; types hand-written |
| 13 | Repeated runs reproduce naive-fix failure, targeted containment, rotation, preserved legitimate op, no external targets | met (one version) | Latest summary 3 x 17 steps incl. isolation steps (`isolation-*`, status 0 = no answer), `legitimate-workload-uses-rotated-credential` 200; collector second window `collected-conclusion-matches-targeted-containment` |
| 14 | Every case has reviewable label source; corpus shows failures of history-free, lifecycle-free, ordering-free analyses | met (labels circular for 16 cases) | `benchmarks/reports/semantic-corpus.md`: snapshot 5 false containments, final-state 1, lifecycle-free over-reports; label sources separated (hand-authored / lab-derived / reference-derived held-out) |
| 15 | Tests catch removed lifecycle checks and wrong safe defaults; blocked live tests visible | met | `tests/differential/test_mutation.py` (4/4); BLOCKED skips shown with `-rs` and fail the postgres job. Fault campaign partial: interrupted-rotation and clock-ambiguity faults not injected |
| 16 | Benchmark regenerates tables from raw artifacts; headline claims trace to metrics | partial | Regeneration works (`python benchmarks/run.py --repeat 3`, section 3). Missing: resource cost, uncertainty intervals, hardware record in committed report (deliberate), scaling |
| 17 | Observability; measured optimization with before/after artifacts | **not met** | No metrics endpoint or instrumentation for ingestion lag, queue depth, states explored, etc.; no profiling artifacts |
| 18 | No unresolved critical trust-boundary defect; dependency exceptions documented with expiry; release workflows not triggerable by untrusted code | partial | No open Critical/High. CI uses `pull_request` only, `permissions: contents: read`, live-lab is `workflow_dispatch`. Open: API image not built from `uv.lock` (review finding 9, no expiry date); no release provenance/signing; no release workflow exists |
| 19 | New user runs replay mode without hidden services; lab host reproduces live results without undocumented steps | partial | Replay mode: reproduced here (section 5). Live: reproduced only by the project's own workflow; no third-party host. No annotated demo script with cold/warm timings |
| 20 | Audit, fix, rerun matrix, release-readiness report, tag only when checks pass | partial | This document. Doc defects fixed (section 3). No code defects fixed here. No tag |

### 1d. Testing-strategy properties

| Property | Status | Evidence |
|---|---|---|
| Acquisition survives source-permission removal | met (model + lab) | `test_acquisition_survives_source_permission_removal`; lab step |
| Knowledge monotone | met (model) | `test_knowledge_is_monotone_usability_is_not` |
| Usability not monotone | met (model + lab) | same; lab 401 after Pod deletion and after rotation |
| UID identity matters | met (model) | `same-name-recreation` case, `test_attribution_uses_uid_not_name`. No lab step |
| Unsupported scope visible | met | `admission-unsupported`, `test_unsupported_credential_is_visible` |
| Search limits do not establish safety | met | `test_search_limit_never_establishes_containment` |
| Read-only stays read-only | met | `test_api_never_mutates_clusters`; compose smoke checks non-root / read-only rootfs |
| Metamorphic (duplicates, irrelevant entities, reorderings) | met | `test_irrelevant_namespace_does_not_change_conclusions`, `test_input_order_does_not_change_result`, `test_duplicates_are_harmless_and_counted` |
| Adversarial input (fanout, oversized, hostile names, stored XSS) | partial | Depth/size/timestamp/duplicate-key tests in `tests/security/`; no stored-XSS test |

### 1e. Initial engineering targets

| Target | Status | Note |
|---|---|---|
| Core conformance, contradictions block release | partial | Every lab step agrees, but many rules have no lab step (S-TOK-1..3, S-WL-2..4, S-RBAC-*, S-SEC-1 list/watch) |
| Replay determinism | met | CI determinism step; `test_heldout_build_is_deterministic_and_committed` |
| Small-model agreement | met | Differential suites (300 examples in CI), held-out 44/44 |
| Warm demo 3–10 min | not met | Not measured. The live-lab job takes ~7m50s including cluster creation (cold), which is not the defined metric |
| Medium analysis < 10 s at 1,000 entities / 10,000 facts | not met | No scaling benchmark exists |
| Local usability (8-core / 16 GB reference) | not met | Not recorded |

---

## 2. Claims audit

### README.md

| Claim | Verdict | Action |
|---|---|---|
| "research-grade, version 0.1.0" | accurate | kept |
| "confirmed the model on 11/11 semantic spike steps" | **stale / understated**: the latest evidence is 17/17 x 3 runs plus collector | corrected; added "It is not production-ready" |
| "Supported semantics ... conformance **unverified**" | stale: several rules are lab-confirmed | corrected to "partial" |
| Benchmark table (0/6 vs 5/11 etc.) | accurate vs `benchmarks/reports/semantic-corpus.md`; caveats present | kept |
| "Real-cluster labels are the next milestone" | stale: a small lab-derived label set exists | replaced with the 6/6 vs 3/6 figures and their scope |
| Live lab "has **not** been run yet" | **false** (many runs) | corrected with receipts and run id |
| "Mutation suite ... caught every time" | accurate (4/4, `test_mutation.py`) | kept |
| "assumes control-plane changes propagate before the next step, which is a lab-testable assumption" | incomplete: the lab shows rotation does **not** propagate instantly | corrected |
| Planner "Found (cost 6)" plan | model-level; `test_flagship_plan_is_targeted_and_preserves_release` | kept (the table is presented as model output) |
| "No tokens or Secret bodies are stored" | supported by redaction tests and review E-2/E-3 fixes; U-4 (split/custom-encoded tokens) remains | kept; listed in the risk register |
| Production-ready | not claimed (checked: no occurrence) | now explicitly denied |

### docs/research/claims.md

| Claim | Old evidence text | Verdict | Action |
|---|---|---|---|
| C1 | "Lab step written, not run" | stale; lab-confirmed on v1.31.4 | corrected |
| C2 | "Not run" | stale; 401 ~0.01 s after deletion, 3/3 | corrected, with the no-bound caveat |
| C3 | hand-authored only | incomplete | added lab-derived 6/6 vs 3/6 with scope caveat |
| C4 | hand-authored only | `defender-race` never executed in the lab | clarified |
| C5, C6, C8 | as stated | accurate | kept |
| C7 | "Model only" | partly lab-backed; the naive plan's breakage is still model-only | corrected |

No overclaim was found that asserts more than the evidence supports **except** the README's
implicit "lab-testable" framing of propagation. Most defects were understatements, which made
the docs contradict each other.

---

## 3. Docs consistency

### Fixed in this audit (one commit per file)

| File | Stale statement | Correction |
|---|---|---|
| `README.md` | 11/11 steps; conformance "unverified"; lab "not been run yet"; next milestone | see section 2 |
| `docs/research/claims.md` | C1, C2, C3, C4, C7 evidence | see section 2 |
| `docs/semantics/supported.md` | "Conformance status: unverified ... No such receipt exists yet"; S-SEC-5 "lab steps written, not yet executed"; S-SEC-4 timing only 54.7 s | partial conformance with receipt reference; S-SEC-5 lab-confirmed; 2.4–16 s range |
| `docs/architecture/system.md` | Collector "planned", frontend "`web/` planned", lab supervisor "written, not executed" | implemented / executed with pointers |
| `docs/collector/README.md` | "Not yet run against a live cluster"; "wired but not yet run"; image "not built" | live runs recorded; what is still fake-only; image built in CI |
| `docs/threat_model/threat-model.md` | executor abuse "not executed"; "No frontend yet" (stored XSS row); "no per-user concurrency limits"; profile unverified "until lab receipts exist" | updated |
| `docs/tutorials/live-lab.md` | header "11-step spike ... written, not yet executed"; S-SEC-5 and collector second window "not yet executed" | updated with run 36244828581 |
| `CHANGELOG.md` | "3 runs x 15 steps" | 17 steps |
| `benchmarks/reports/semantic-corpus.{md,json}` | said "5 receipts" while `benchmarks/labels/lab-derived.json` holds 14 (labels regenerated in `b574b8f` without the report) | regenerated with `python benchmarks/run.py --repeat 3` (numbers unchanged, receipt counts 14/13) |

### Required changes to `docs/engineering/status.md` (not applied, per instruction)

1. Header "Last updated": add the phase 9 engine/evidence adversarial review, the S-SEC-5 lab
   receipt and the collector's second window.
2. Phase 2 row: remove "**Missing:** audit webhook path" or narrow it. The webhook receiver
   was exercised live (supervisor relay, second window). kube-apiserver's own webhook backend and the watch-expiry fault
   remain missing. Say "lab-confirmed for residual-token and targeted-containment".
3. Phase 6 row: "3 repeated runs x 15 steps" → "3 x 17 steps (latest
   `spike-summary-20260926T132141Z.json`, run 36244828581)".
4. Phase 8 row: "**Missing:** a lab receipt at t+d" is stale. The `s-sec-5-*` steps agree
   3/3. Note that `d` is measured in the same run.
5. Phase 9 row: "**Missing:** full adversarial review" is stale. Two adversarial reviews
   exist (`review-2026-09-26-adversarial-{api,engine}.md`). "uvicorn not in the lockfile" is
   stale: `uvicorn==0.30.6` is in the `api` extra and in `uv.lock`. The remaining gap is that
   `services/api/Dockerfile` still `pip install`s `.[api,postgres]` without the lock.
6. Phase 10 row: add "report regenerated in the final audit; no confidence intervals or
   scaling".
7. Phase 11 row: "Not yet reproduced in a fresh environment": portable checks were reproduced
   from a fresh clone by this audit (section 5), but still not by a third party.
8. Phase 12 row: "not started" → "audit done (`docs/engineering/final-audit.md`); release
   blockers listed there; no tag".
9. Known failure 2: "15/15 spike steps agree across 3 runs" → 17/17. Failure 1: add the
   targeted-containment window. Failure 3: the rotation range is now 2.4–16 s (10 s sync) and 54.7 s (default).
   Failure 6 (uvicorn) → replace it with "API image not built from the lockfile".
10. Add known risks: U-1 (possible-history expiry at analysis time) and A-3 list/watch
    being model-level only (section 4).
11. Next safe task: (a) and (b) partly done, (c) done. Replace with the section 6 priorities.

### Required changes to `docs/engineering/verification.md` (not applied)

1. Header "Environment ... No Docker daemon, kind, or kubectl. Date: 2026-09-25": mark it as
   the original local environment. CI and live-lab runs are the current evidence.
2. "Executed" table counts (122 passed, 1 skipped; mypy 9 files; 4,000/1,000/3,000 example
   runs) are historical. Add the current figures: CI 36244804735 portable **359 passed, 20
   skipped (BLOCKED)**, postgres **41 passed**, mypy 15 files, web 46 vitest + 6 Playwright.
3. Add a section for run 36244828581: spike 3 x 17 steps (incl. `s-sec-5-*` with `ack`
   2.56/13.73/15.96 s and old-credential refusal at 5.13/16.12/18.14 s), and collector 28/28
   with both windows.
4. "CI (run 36228425312)" table lists 5 jobs. Add `containers` or point to the newer run.
5. **"Not executed" table is stale in every row.** Container build/compose now runs in the CI
   `containers` job. The collector runs against a live API server (collect receipts).
   Frontend/Playwright runs in the CI web job. Replace the rows with what still has not run:
   kube-apiserver webhook backend, watch-expiry fault, held-out templates in the lab, list/watch Secret
   lab step, other Kubernetes versions, OIDC against a real IdP, scaling benchmarks, third-party
   reproduction.
6. Add the fresh-clone reproduction from section 5 of this file.

---

## 4. Residual risk register

Severity reflects impact on the project's central claim (no false containment) or on the
trust boundary. It is not a CVSS score.

| # | Risk | Source | Severity | Recommended next action |
|---|---|---|---|---|
| R1 | **Possible-history expiry evaluated at analysis time (U-1).** A seeded credential that had expired by `analysis_time` but was usable earlier may have yielded Secret knowledge that the conservative view misses. Both checkers agree, so differential testing cannot catch it | engine review U-1 | **High** (potential false containment in the conservative view; semantics undecided) | Decide the semantics in `supported.md` (evaluate the history phase over `[acquired_at, analysis_time]`). Add a positive case plus a negative control, and implement it in both checkers |
| R2 | S-SEC-1 list/watch knowledge is model-level only (A-3/E-4 fixed without a lab receipt) | engine review A-3 | Medium | Add a lab step: `list secrets`-only SA reads the Secret value |
| R3 | Attribution through deleted controller Pods (U-3): observed reads may be dropped, so a copied credential is missed | engine review U-3, E-1 partial | Medium | Emit a coverage gap "request from unknown Pod UID", which yields `unknown`, never containment |
| R4 | Split or custom-encoded tokens bypass pattern redaction (U-4) | engine review | Medium | Keep the allowlisted-field design and add an entropy heuristic on persisted free-text fields |
| R5 | Profile trust (U-2): direct API/CLI input can supply its own profile (e.g. shorter TTL) | engine review | Medium | Pin the profile server-side for API input and reject a mismatched `profile` |
| R6 | API image installs `.[api,postgres]` with pip, not from `uv.lock`, without hashes | starter #9, API review | Medium | Build from `uv export --frozen --no-hashes`/`--hashes` requirements. Set an expiry date on the exception |
| R7 | No release provenance, signing, or image SBOM; no release workflow | supply-chain.md | Medium (release blocker) | Add a tag-triggered, protected workflow with SLSA provenance and signing |
| R8 | Unbounded PostgreSQL job queue per principal; FIFO across clusters | API review | Medium | Per-principal/cluster quotas and fair scheduling |
| R9 | All limits (concurrency, SSE streams, memory store caps) are per process | status.md, API review | Low–Medium | Document it for multi-replica deployments or move limits to the DB |
| R10 | Synchronous analyze is not behind the heavy-work limiter | API review | Low | Put it behind the limiter or cap derivations per request |
| R11 | `last_error` exposes exception text to same-cluster viewers | API review | Low | Map to stable error codes |
| R12 | OIDC tested only with local keys/fake JWKS; `azp` unchecked; `sub` truncated to 200 chars | status.md, API review | Low–Medium | Integration test against a real IdP (e.g. Dex in CI). Check `azp` when `aud` is an array |
| R13 | Collector HTTP server lacks `WriteTimeout`/`IdleTimeout` (U-5) | engine review | Low | Set them |
| R14 | O-1 (a malformed expiry makes the whole bundle `invalid_input`), O-2 (CLI tracebacks, unvalidated case id from tampered input), O-3 (reference attacker reduced by `ref-*` UIDs) | engine review "Open" | Low | Fix them as listed. None causes false containment |
| R15 | **Single version, single cluster.** Every live result is Kubernetes v1.31.4 on an idle single-node kind cluster with Calico and `syncFrequency: 10s` on GitHub-hosted runners | receipts | High for generalization | Add a version matrix (e.g. 1.29–1.32) and a multi-node cluster. Record kubelet config in receipts |
| R16 | Many rules have no lab step: S-TOK-1..3 (expiry, audience, SA UID), S-WL-2..4 (controllers, cascade, exec), RBAC details, S-ADM-X | supported.md | Medium | Add lab steps in that order; each disagreement becomes a regression case |
| R17 | Lab labels circular or narrow: 16 hand-authored cases (same authors), 44 held-out labelled by the reference checker (same written semantics), 6 lab-derived objectives | benchmark report | High for research claims | Execute held-out templates in the lab. Get labels from a second author |
| R18 | S-SEC-5 `d` measured in the same run it validates | live-lab.md | Low | Predict `d` from kubelet config ahead of the run and compare |
| R19 | kind/kubectl checksums same-origin; Calico images tag-referenced inside a SHA-pinned manifest | supply-chain.md | Low | Commit expected checksums; vendor a digest-pinned Calico manifest |
| R20 | CI actions target Node 20 (deprecation annotations in both runs) | CI logs | Low | Bump pinned action SHAs |
| R21 | `ruff format` is not enforced: 38 of 98 files would be reformatted (fresh clone, section 5) | reproduction | Info | Enforce it or document that it is not used |
| R22 | Commits after `78ac404` (receipts, labels) have no CI run of their own | git log vs run heads | Info | Push triggers CI. Confirm green before tagging |
| R23 | Windows: symlink test needs privilege; CRLF checkouts break checksums (mitigated by `.gitattributes`) | reviews, section 5 | Info | Skip the symlink test with a BLOCKED reason when `os.symlink` raises `WinError 1314` |

---

## 5. Reproducibility (fresh clone, this host)

Host: Windows 11 Home 10.0.26200, Git Bash, uv 0.11.32. uv selected **CPython 3.12** (the
project requires `>=3.11`; CI uses 3.11.16). Clone path:
`<scratchpad>/repro/afterlock`, commit `b574b8f`.

```bash
git -c core.autocrlf=false clone https://github.com/rakshit-737/afterlock
cd afterlock
uv sync --frozen --extra dev --extra postgres --extra oidc --extra api
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run pytest -q -p no:cacheprovider tests/unit tests/security
uv run pytest -q -p no:cacheprovider          # full suite
python benchmarks/run.py --repeat 3           # report regeneration (then diffed)
```

| Step | Result |
|---|---|
| `uv sync --frozen ...` | ok, installs from lock (incl. `uvicorn==0.30.6`) |
| `ruff check .` | All checks passed |
| `ruff format --check .` | 38 files would be reformatted (not a CI check; R21) |
| `mypy` | Success: no issues found in 15 source files |
| `pytest tests/unit tests/security` | **236 passed, 1 failed** in 57.6 s. The failure is `tests/unit/test_evidence.py::test_symlinked_file_rejected` (`OSError [WinError 1314]`, host cannot create symlinks without privilege; known) |
| full `pytest` | **358 passed, 20 skipped (BLOCKED: PostgreSQL, live lab), 1 failed** (the same symlink test) in 502 s. This matches CI (359 passed there, where symlinks work) |
| `benchmarks/run.py --repeat 3` | Completed. It changed only the lab-label receipt counts (5 → 14/13) and the JSON fields behind them. Every metric is unchanged |

Not reproduced here: PostgreSQL tests (BLOCKED locally; green in CI postgres job), web/Playwright,
Go collector, containers, and the live lab (no Docker/kind on this host; green in the CI and
live-lab runs cited above).

---

## 6. Verdict

**AFTERLOCK 0.1.0 is a research-grade containment verifier with one live-validated scenario
family. It is not production-ready.** It is also not a general Kubernetes security tool.

What is **verified live** (Kubernetes v1.31.4, one idle single-node kind cluster, 3 repeated
runs, receipts committed):
- After the creator's RoleBinding is removed, the token of a previously created Pod still
  reads the Secret. Deleting the bound Pod makes that token fail (401, ~0.01 s).
- A copied downstream credential survives Kubernetes-side containment. It fails after
  acknowledged rotation, with a measured propagation window (S-SEC-5).
- The legitimate workload keeps working. The admission negative control denies (422). Network
  isolation is enforced (Calico).
- The collector-evidence path: bundles gathered from the live cluster reproduce the
  `residual_path` and `targeted-containment` conclusions, with restart gaps recorded and no
  credential material.

What is **model-level only**: token expiry, audience and SA-UID rules; controllers, cascades
and exec; RBAC details (groups, ClusterRoleBindings, resourceNames); list/watch Secret reads;
ordering races (`defender-race`); planner optimality beyond small candidate sets; the naive
plan breaking the release workload; all 44 held-out cases; every Kubernetes version other than
1.31.4.

Engineering quality is good for a research artifact. The core packages have zero runtime
dependencies. A separately written reference checker is enforced by tests. Differential,
mutation and adversarial suites have found and fixed real High-severity false-containment
bugs. CI is honest about BLOCKED checks. The docs understated progress more often than they
overstated it, and this audit fixed the inconsistencies.

### Release blockers (for a tagged research release)

1. Resolve R1 (possible-history expiry semantics). It is the one open item that could produce
   false containment.
2. Update `status.md` and `verification.md` as listed in section 3.
3. Build the API image from the lockfile, or document an exception with an expiry (R6).
4. Get a CI run on the final commit, then tag. Say "research-grade" in the release notes.

### Prioritized next steps

1. R1 semantics decision plus cases in both checkers.
2. Lab steps for S-TOK-1..3, S-SEC-1 list/watch, S-WL-2..4, `defender-race`, and the naive plan (R2, R16).
3. Kubernetes version matrix and a multi-node cluster (R15).
4. Execute held-out templates in the lab to get outcome-derived labels (R17).
5. Supply chain: lockfile-based image, release provenance and signing (R6, R7).
6. Observability and a scaling benchmark (prompt 17, the 1,000-entity target). Both are currently not met.
7. Third-party reproduction of `scripts/bootstrap` + `make demo` and a live-lab run on a non-GitHub host.
