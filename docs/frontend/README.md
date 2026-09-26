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

Out of scope for this iteration (design prompt 12 items not yet built): provenance
graph (Cytoscape), evidence drawer, credential-lifecycle view, Playwright end-to-end
tests, and an automated accessibility audit. Types are hand-written from the API
source, not generated from OpenAPI.

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

## Async jobs (future)

`src/api/client.ts` returns a `Submission<T>` from the long-running POSTs
(analyses, verification, plans). Today the API answers synchronously and the client
yields `{state: "completed"}`. A `202 Accepted` response is mapped to
`{state: "accepted", job: {id, statusUrl?}}` (reads `job_id` or `id`, and the
`Location` header or `status_url`). To support job endpoints, implement the `JobApi`
interface (`wait`, `cancel`) against them and pass it to `<App jobs={...}>`; `settle()`
already routes accepted submissions through it. Without a `JobApi`, an accepted
submission raises a clear "no job support" error instead of showing a stale result.

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
