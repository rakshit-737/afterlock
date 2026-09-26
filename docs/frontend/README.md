# Investigation frontend (`services/web`)

Phase 5 of the design (`docs/research/original-design.md`, prompt 12). A TypeScript +
React + Vite single-page app that consumes the **existing v1 HTTP API only**
(`docs/api/api.md`). It performs no reasoning and no authorization: every decision is
made by the API, and the UI shows results as returned.

## What it shows

| Area | Source | Notes |
|---|---|---|
| Token entry | memory only | Never written to web storage, cookies, or the URL. Reload forgets it. |
| Case creation | `POST /v1/cases` | Select `inventory.json`, `case.json`, `events.jsonl` (optionally `manifest.json` for ids), or one JSON file in the inline API shape. |
| Case list and detail | `GET /v1/cases`, `GET /v1/cases/{id}` | Case-level coverage gaps are shown before analysis. |
| Analysis | `POST /v1/cases/{id}/analyses` | Mode selection (`full` or a baseline) and an optional remediation JSON list; empty uses the case's remediation. |
| Conclusion | `result.conclusion` | Model conclusion and validation status are shown separately. `not_executed` is labeled **Model-level only**; only `lab_confirmed` is labeled **Lab confirmed**. |
| Objectives | `result.objectives` | `violated`, `possibly_violated`, `unknown` (with reasons), `satisfied_within_scope`, each as text plus color. |
| Legitimate operations | `result.legitimate_operations` | Preserved / Broken. |
| Witnesses | `result.witnesses` | Each step's fact, rule, interval, conditions, evidence, and `observed` / `assumed` / `inferred` status. |
| Timeline | `result.timeline`, `exposure_during_containment` | Attacker capabilities per interval; intervals with exposure during containment are flagged. |
| Coverage | `result.missing_coverage`, `analysis_bounds` | An un-exhausted bound is stated as "not exhausted", never as containment. |
| Explanation | `GET /v1/analyses/{id}/explanation` | Plain text, rendered in a `<pre>`. |
| Verification | `POST /v1/analyses/{id}/verification` | Reference-checker witness replay and exploration. Labeled as a model-level cross-check; it does not change validation status. |
| Plans | `POST /v1/cases/{id}/plans` | Proposed, best, cheapest security-only, and naive plans side by side; an `incomplete_search` says it is not evidence that no plan exists. |

| Provenance graph | `result.witnesses[*].steps` | The **selected** witness only (never the whole cluster), as a hand-rolled layered SVG: each step is a hyperedge drawn as premises → rule box → fact. Status is written in every node and repeated by border style (solid observed, dashed inferred, dotted assumed). Nodes are keyboard-focusable buttons. A table with the same content follows the graph. |
| Evidence drawer | the selected step | Opened from a graph node or the table: fact, status, rule, interval, evidence references, premises, checked conditions. Focus moves to the drawer; Escape or "Close evidence" returns it. Evidence references are record ids; the API does not serve source records. |
| Credential lifecycle | witnesses + `result.remediation` | Per credential (Kubernetes credential, secret version, downstream credential version): **acquired** (the step that establishes it), **valid** (the validity condition checked when it is used: `credential_usable`, `secret_version`, `service_accepts`), **rotated** (`rotate_downstream_credential` for its service), **revoked** (`delete_service_account` for the service account it authorized as). Every event names its source. This is a regrouping of what the result states, not new reasoning; other actions (e.g. deleting a bound pod) are visible in the timeline and objectives. |
| Background jobs | `*-jobs`, `GET /v1/jobs/{id}`, `POST /v1/jobs/{id}/cancel` | "Run as background jobs" routes analysis, verification and plan through the job endpoints. Job id, state, attempts, last error and a Cancel button are shown. A cancelled or failed job never shows a result. |

Still not built from design prompt 12: types generated from OpenAPI (types are
hand-written from the API source) and live SSE job progress (see below).

## Security properties

- All API strings are rendered as React text nodes. `scripts/lint-policy.mjs`
  (`npm run lint`) fails on `innerHTML`, `dangerouslySetInnerHTML`, `eval`,
  web storage, cookies, and external origins in shipped source. A test renders a
  hostile `<img onerror>` description and asserts no element is created.
- No inline scripts or styles; the production build emits only same-origin files, so
  the CSP in `nginx.conf` is `script-src 'self'; style-src 'self'; connect-src 'self'`
  with `default-src 'none'`.
- No CDN, web fonts, or third-party requests. Requests use `credentials: "omit"`.
- Late responses for a previously selected case are discarded, so results for
  different cases or analyses are never mixed on screen.

## Async jobs

`src/api/client.ts` returns a `Submission<T>` from long-running POSTs. The synchronous
endpoints yield `{state: "completed"}`; the `*-jobs` endpoints answer `202` and yield
`{state: "accepted", job: {id, statusUrl?}}` (from `job_id` and the `Location` header).
`settle()` resolves an accepted submission through a `JobApi`.

`src/api/jobs.ts` provides `PollingJobApi`, used by default:

- Polls `GET /v1/jobs/{id}` with capped exponential backoff (250 ms, ×1.6, max 3 s),
  reporting every observed record to the UI.
- `succeeded` resolves to what the synchronous endpoint would return
  (`{id: result_id, result}` for analyses, `result` otherwise); `failed` and
  `cancelled` reject (`JobFailedError`, `JobCancelledError`).
- Polling stops through an `AbortSignal` on unmount, case change, or token removal.
  Stopping polling does not cancel the job; the Cancel button calls
  `POST /v1/jobs/{id}/cancel`.
- Transport is isolated in a `JobWatcher` function. An SSE watcher over
  `GET /v1/jobs/{id}/events` can replace `pollingWatcher()` (falling back to it when the
  stream is unavailable) without changing `PollingJobApi` callers or the UI.

## Develop

Requires Node >= 20.19 (CI uses Node 22).

```bash
cd services/web
npm ci
npm run lint        # security policy checks
npm run typecheck   # tsc --noEmit (strict)
npm test            # vitest (jsdom)
npm run build       # dist/
AFTERLOCK_API_URL=http://127.0.0.1:8080 npm run dev   # proxies /v1 to the API
```

### End-to-end tests (Playwright)

```bash
npx playwright install chromium   # once; CI uses --with-deps
npm run e2e                        # playwright test
```

`playwright.config.ts` starts two servers: the real API
(`python -m uvicorn afterlock_api.app:app`, in-memory storage, a throwaway analyst
token for cluster `lab-local`, `PYTHONPATH` pinned to this checkout) and
`npm run build && vite preview`, which proxies `/v1` to it. It needs Python with the
`dev` extra and `uvicorn` installed; set `AFTERLOCK_E2E_PYTHON` to choose the
interpreter and `AFTERLOCK_E2E_API_PORT` / `AFTERLOCK_E2E_WEB_PORT` (defaults 18080 /
14173) to move the ports. `e2e/investigation.spec.ts` covers:

- uploading the `datasets/replay/residual-token` bundle, analyzing, and seeing
  **Residual path**, the provenance graph, the evidence drawer, and the credential
  lifecycle;
- a targeted remediation (`remove_binding release-reader-secret`,
  `rotate_downstream_credential canary-service`) giving **Contained within scope**;
- the async job path (analysis and plan jobs reach `succeeded`);
- the token never appearing in web storage, cookies, the URL, or the DOM;
- `@axe-core/playwright` (WCAG 2.0/2.1 A and AA tags) with zero serious or critical
  violations in light and dark color schemes, before and after analysis with the
  evidence drawer open.

Dev-only dependencies: `@playwright/test` (browser driver and runner) and
`@axe-core/playwright` (accessibility rules). Neither ships in the build. The graph is
hand-rolled SVG, so there is no graph library (Cytoscape was not needed for a single
witness's small DAG).

Test fixtures in `src/test/fixtures/` are real engine output for
`datasets/replay/residual-token` (result, reference verification, plan with
`max_length=4, max_evaluations=2000`), produced with the `afterlock` package.
They are UI fixtures only, not expected-output oracles; regenerate them if the
result schema changes.

## Deploy

`docker compose up --build` starts `web` on `127.0.0.1:8081`, serving the static build
from `nginxinc/nginx-unprivileged` (uid 101, read-only root filesystem, all
capabilities dropped) and proxying `/v1/` to the `api` service. Base images are pinned
by tag, not digest (release-hardening item).
