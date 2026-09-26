import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { AfterlockClient, ApiError, settle, type JobApi, type Submission } from "./api/client";
import { PollingJobApi } from "./api/jobs";
import type {
  AnalysisCreated,
  AnalysisRequest,
  CaseDetail,
  CoverageGap,
  Health,
  InlineBundle,
  JobRecord,
  PlanResult,
  VerificationResult,
} from "./api/types";
import { AnalysisForm } from "./components/AnalysisForm";
import { ErrorNote } from "./components/Badge";
import { JobStatus } from "./components/JobStatus";
import { CaseUpload } from "./components/CaseUpload";
import { PlanView } from "./components/PlanView";
import { Coverage, ResultView } from "./components/ResultView";
import { TokenPanel } from "./components/TokenPanel";
import { VerificationView } from "./components/VerificationView";

function message(e: unknown): string {
  if (e instanceof ApiError && e.status === 401) return `${e.message}. Check the API token.`;
  if (e instanceof ApiError && e.status === 403) return `${e.message}. Your token's role or cluster scope does not allow this.`;
  return e instanceof Error ? e.message : String(e);
}

export interface AppProps {
  /** Injected for tests; defaults to a same-origin client. */
  makeClient?: (getToken: () => string | null) => AfterlockClient;
  /** Job waiter; defaults to polling `GET /v1/jobs/{id}` (see api/jobs.ts). */
  jobs?: JobApi;
}

export function App({ makeClient, jobs }: AppProps) {
  const [token, setToken] = useState<string | null>(null);
  const tokenRef = useRef<string | null>(null);
  tokenRef.current = token;
  const client = useMemo(
    () => (makeClient ?? ((g) => new AfterlockClient({ getToken: g })))(() => tokenRef.current),
    [makeClient],
  );

  const jobApi = useMemo(() => jobs ?? new PollingJobApi(client), [jobs, client]);
  const [useJobs, setUseJobs] = useState(false);
  const [job, setJob] = useState<{ label: string; id: string; rec: JobRecord } | null>(null);
  const [cancelling, setCancelling] = useState(false);
  // Aborts in-flight job polling on unmount, case change, or token removal.
  const abort = useRef<AbortController | null>(null);
  const freshSignal = () => {
    abort.current?.abort();
    abort.current = new AbortController();
    return abort.current.signal;
  };
  useEffect(() => () => abort.current?.abort(), []);

  const [health, setHealth] = useState<Health | null>(null);
  const [cases, setCases] = useState<string[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [detail, setDetail] = useState<CaseDetail | null>(null);
  const [analysis, setAnalysis] = useState<AnalysisCreated | null>(null);
  const [explanation, setExplanation] = useState<string | null>(null);
  const [verification, setVerification] = useState<VerificationResult | null>(null);
  const [planResult, setPlanResult] = useState<PlanResult | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState("");
  // Guards against showing a late response for a previously selected case or analysis.
  const generation = useRef(0);

  useEffect(() => {
    client.health().then(setHealth, () => setHealth(null));
  }, [client]);

  const run = useCallback(async <T,>(label: string, fn: () => Promise<T>): Promise<T | undefined> => {
    const gen = generation.current;
    setBusy(label);
    setError(null);
    setStatus(`${label}…`);
    try {
      const v = await fn();
      if (gen !== generation.current) return undefined;
      setStatus(`${label}: done`);
      return v;
    } catch (e) {
      if (gen === generation.current) {
        setError(`${label} failed: ${message(e)}`);
        setStatus(`${label}: failed`);
      }
      return undefined;
    } finally {
      setBusy(null);
    }
  }, []);

  /** Resolve a submission; for an accepted job, track and show its state until it is terminal. */
  const resolve = useCallback(
    async <T,>(label: string, sub: Submission<T>): Promise<T> => {
      const gen = generation.current;
      const signal = freshSignal();
      if (sub.state === "accepted") {
        const id = sub.job.id;
        setCancelling(false);
        setJob({
          label,
          id,
          rec: { job_id: id, cluster_id: "", manifest_id: "", kind: "", state: "queued", attempts: 0, max_attempts: 0,
            cancel_requested: false, last_error: null, result_id: null },
        });
        return settle(sub, jobApi, signal, (rec) => {
          if (gen === generation.current) setJob({ label, id, rec });
        });
      }
      return settle(sub, jobApi, signal);
    },
    [jobApi],
  );

  async function cancelJob() {
    if (!job) return;
    setCancelling(true);
    try {
      await jobApi.cancel({ id: job.id });
    } catch (e) {
      setError(`Cancel failed: ${message(e)}`);
      setCancelling(false);
    }
  }

  const clearAnalysis = () => {
    setAnalysis(null);
    setExplanation(null);
    setVerification(null);
  };

  const refresh = useCallback(async () => {
    const list = await run("Load cases", () => client.listCases(200, 0));
    if (list) setCases(list.items);
  }, [client, run]);

  useEffect(() => {
    if (token) void refresh();
    else {
      generation.current++;
      abort.current?.abort();
      setJob(null);
      setCases([]);
      setSelected(null);
      setDetail(null);
      clearAnalysis();
      setPlanResult(null);
    }
  }, [token, refresh]);

  async function select(caseId: string) {
    generation.current++;
    abort.current?.abort();
    setJob(null);
    setSelected(caseId);
    setDetail(null);
    clearAnalysis();
    setPlanResult(null);
    const d = await run("Load case", () => client.getCase(caseId));
    if (d) setDetail(d);
  }

  async function createCase(b: InlineBundle) {
    const created = await run("Create case", () => client.createCase(b));
    if (created) {
      await refresh();
      await select(created.case_id);
    }
  }

  async function analyze(req: AnalysisRequest) {
    if (!selected) return;
    generation.current++;
    clearAnalysis();
    const a = await run("Analysis", async () => resolve("analysis", useJobs ? await client.submitAnalysisJob(selected, req) : await client.runAnalysis(selected, req)));
    if (!a) return;
    setAnalysis(a);
    const text = await run("Explanation", () => client.getExplanation(a.id));
    if (text !== undefined) setExplanation(text);
  }

  async function verify() {
    if (!analysis) return;
    const v = await run("Verification", async () => resolve("verification", useJobs ? await client.submitVerificationJob(analysis.id) : await client.verify(analysis.id)));
    if (v) setVerification(v);
  }

  async function makePlan(max_length: number, max_evaluations: number) {
    if (!selected) return;
    const p = await run("Plan", async () => {
      const req = { max_length, max_evaluations };
      return resolve("plan", useJobs ? await client.submitPlanJob(selected, req) : await client.plan(selected, req));
    });
    if (p) setPlanResult(p);
  }

  const caseGaps = (detail?.input?.coverage_gaps as CoverageGap[] | undefined) ?? [];

  return (
    <>
      <a href="#main" className="skip">
        Skip to content
      </a>
      <header className="top">
        <h1>AFTERLOCK investigation</h1>
        <p className="muted small">
          {health ? `API ${health.version} · storage ${health.storage}` : "API health unknown"} · results are model-level unless
          marked lab confirmed
        </p>
        <TokenPanel hasToken={!!token} onSet={setToken} onClear={() => setToken(null)} />
      </header>
      <p className="visually-hidden" role="status" aria-live="polite">
        {status}
      </p>
      <main id="main">
        <ErrorNote error={error} />
        {!token ? (
          <p>Enter an API token to list and analyze cases.</p>
        ) : (
          <div className="layout">
            <nav aria-labelledby="h-cases" className="panel cases">
              <h2 id="h-cases">Cases</h2>
              <button type="button" onClick={() => void refresh()} disabled={!!busy}>
                Refresh
              </button>
              {cases.length === 0 ? <p className="muted">No cases visible to this token.</p> : null}
              <ul className="plain">
                {cases.map((c) => (
                  <li key={c}>
                    <button
                      type="button"
                      className="link"
                      aria-current={c === selected ? "true" : undefined}
                      onClick={() => void select(c)}
                    >
                      {c}
                    </button>
                  </li>
                ))}
              </ul>
            </nav>
            <div className="content">
              <CaseUpload onSubmit={createCase} busy={!!busy} />
              {selected && detail ? (
                <section aria-labelledby="h-case" className="panel">
                  <h2 id="h-case">
                    Case <code>{detail.case_id}</code> <span className="muted small">cluster {detail.cluster_id}</span>
                  </h2>
                  <Coverage gaps={caseGaps} />
                  <div className="panel">
                    <label className="check" htmlFor="use-jobs">
                      <input id="use-jobs" type="checkbox" checked={useJobs} onChange={(e) => setUseJobs(e.target.checked)} />
                      Run as background jobs
                    </label>
                    <p className="muted small">
                      Uses the <code>*-jobs</code> endpoints: the API queues the work and this page polls the job until it
                      finishes. Leaving the case or the page stops polling; it does not cancel the job.
                    </p>
                  </div>
                  {job ? <JobStatus label={job.label} job={job.rec} onCancel={() => void cancelJob()} cancelling={cancelling} /> : null}
                  <AnalysisForm busy={!!busy} onRun={analyze} />
                  {analysis ? (
                    <>
                      <ResultView analysisId={analysis.id} result={analysis.result} />
                      <section aria-labelledby="h-explain" className="panel">
                        <h3 id="h-explain">Explanation</h3>
                        {explanation === null ? <p className="muted">Not loaded.</p> : <pre className="explain">{explanation}</pre>}
                      </section>
                      <div className="panel">
                        <button type="button" onClick={() => void verify()} disabled={!!busy}>
                          Run reference-checker verification
                        </button>
                      </div>
                      {verification ? <VerificationView v={verification} /> : null}
                    </>
                  ) : null}
                  <PlanForm busy={!!busy} onPlan={makePlan} />
                  {planResult ? <PlanView plan={planResult} /> : null}
                </section>
              ) : null}
            </div>
          </div>
        )}
      </main>
    </>
  );
}

function PlanForm({ busy, onPlan }: { busy: boolean; onPlan: (len: number, evals: number) => Promise<void> }) {
  const [len, setLen] = useState(4);
  const [evals, setEvals] = useState(2000);
  return (
    <form
      className="panel"
      aria-labelledby="h-planform"
      onSubmit={(e) => {
        e.preventDefault();
        void onPlan(len, evals);
      }}
    >
      <h3 id="h-planform">Search for a containment plan</h3>
      <div className="row">
        <div>
          <label htmlFor="max-length">Max actions (1–5)</label>
          <input id="max-length" type="number" min={1} max={5} value={len} onChange={(e) => setLen(Number(e.target.value))} />
        </div>
        <div>
          <label htmlFor="max-evals">Max evaluations (1–10000)</label>
          <input
            id="max-evals"
            type="number"
            min={1}
            max={10000}
            value={evals}
            onChange={(e) => setEvals(Number(e.target.value))}
          />
        </div>
      </div>
      <button type="submit" disabled={busy}>
        Search plans
      </button>
    </form>
  );
}
