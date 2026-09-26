// Thin client for the AFTERLOCK v1 HTTP API. It performs no reasoning: every
// authorization decision is made by the API, and results are shown as returned.
//
// Token handling: the token is supplied by a getter that reads in-memory state.
// The client never stores it and never includes it in error messages.
//
// Async jobs: long-running POSTs return a `Submission<T>`. The synchronous
// endpoints answer 201/200, which yields `{ state: "completed" }`. The `*-jobs`
// endpoints answer `202 Accepted` with a job reference, which yields
// `{ state: "accepted", job }`; `settle()` then waits on it through a `JobApi`
// (see ./jobs.ts for the polling implementation).

import type {
  AnalysisCreated,
  AnalysisRecord,
  AnalysisRequest,
  CaseCreated,
  CaseDetail,
  CaseList,
  Health,
  InlineBundle,
  JobOptions,
  JobRecord,
  PlanRequest,
  PlanResult,
  VerificationResult,
} from "./types";

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
    readonly body: unknown = null,
  ) {
    super(message);
    this.name = "ApiError";
  }

  get isAuth(): boolean {
    return this.status === 401 || this.status === 403;
  }
}

export interface JobRef {
  id: string;
  /** Optional URL the API gave for polling (Location header or body field). */
  statusUrl?: string;
}

export type Submission<T> = { state: "completed"; value: T } | { state: "accepted"; job: JobRef };

/**
 * Waits on and cancels asynchronous jobs. `wait` resolves with the job's value
 * (for analysis jobs `{id: result_id, result}`, otherwise `result`), rejects if
 * the job fails or is cancelled, and reports every observed job state through
 * `onUpdate`. Implemented by `PollingJobApi` in ./jobs.ts.
 */
export interface JobApi {
  wait<T>(job: JobRef, signal?: AbortSignal, onUpdate?: (job: JobRecord) => void): Promise<T>;
  cancel(job: JobRef): Promise<void>;
}

export class AsyncJobsUnsupportedError extends Error {
  constructor(readonly job: JobRef) {
    super(`The API accepted this request as background job ${job.id}, but this UI build has no job support yet.`);
    this.name = "AsyncJobsUnsupportedError";
  }
}

/** Resolve a submission to its value, waiting on a job if a JobApi is available. */
export async function settle<T>(
  sub: Submission<T>,
  jobs?: JobApi,
  signal?: AbortSignal,
  onUpdate?: (job: JobRecord) => void,
): Promise<T> {
  if (sub.state === "completed") return sub.value;
  if (!jobs) throw new AsyncJobsUnsupportedError(sub.job);
  return jobs.wait<T>(sub.job, signal, onUpdate);
}

export interface ClientOptions {
  /** Base URL of the API origin; "" means same origin (the default deployment). */
  baseUrl?: string;
  /** Returns the current bearer token, or null if none is entered. */
  getToken: () => string | null;
  fetchImpl?: typeof fetch;
}

type Accept = "json" | "text";

/** Render a FastAPI error body as a single human-readable line. */
export function describeErrorBody(body: unknown): string | null {
  if (body == null) return null;
  if (typeof body === "string") return body || null;
  if (typeof body !== "object") return String(body);
  const detail = (body as { detail?: unknown }).detail;
  const error = (body as { error?: unknown }).error;
  if (typeof error === "string") return error;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    return detail
      .map((d) => {
        if (d && typeof d === "object") {
          const loc = Array.isArray((d as { loc?: unknown }).loc) ? (d as { loc: unknown[] }).loc.join(".") : "";
          const msg = String((d as { msg?: unknown }).msg ?? "invalid");
          return loc ? `${loc}: ${msg}` : msg;
        }
        return String(d);
      })
      .join("; ");
  }
  if (detail && typeof detail === "object") {
    const d = detail as { conclusion?: unknown; error?: unknown };
    const parts = [d.conclusion, d.error].filter((x): x is string => typeof x === "string");
    if (parts.length) return parts.join(": ");
  }
  return null;
}

export class AfterlockClient {
  private readonly baseUrl: string;
  private readonly getToken: () => string | null;
  private readonly fetchImpl: typeof fetch;

  constructor(opts: ClientOptions) {
    this.baseUrl = (opts.baseUrl ?? "").replace(/\/+$/, "");
    this.getToken = opts.getToken;
    this.fetchImpl = opts.fetchImpl ?? ((input, init) => globalThis.fetch(input, init));
  }

  // ---- endpoints -------------------------------------------------------

  health(signal?: AbortSignal): Promise<Health> {
    return this.json<Health>("GET", "/v1/health", undefined, signal, false);
  }

  createCase(bundle: InlineBundle, signal?: AbortSignal): Promise<CaseCreated> {
    return this.json<CaseCreated>("POST", "/v1/cases", bundle, signal);
  }

  listCases(limit = 50, offset = 0, signal?: AbortSignal): Promise<CaseList> {
    const q = new URLSearchParams({ limit: String(limit), offset: String(offset) });
    return this.json<CaseList>("GET", `/v1/cases?${q}`, undefined, signal);
  }

  getCase(caseId: string, signal?: AbortSignal): Promise<CaseDetail> {
    return this.json<CaseDetail>("GET", `/v1/cases/${seg(caseId)}`, undefined, signal);
  }

  runAnalysis(caseId: string, req: AnalysisRequest, signal?: AbortSignal): Promise<Submission<AnalysisCreated>> {
    return this.submit<AnalysisCreated>(`/v1/cases/${seg(caseId)}/analyses`, req, signal);
  }

  getAnalysis(analysisId: string, signal?: AbortSignal): Promise<AnalysisRecord> {
    return this.json<AnalysisRecord>("GET", `/v1/analyses/${seg(analysisId)}`, undefined, signal);
  }

  getExplanation(analysisId: string, signal?: AbortSignal): Promise<string> {
    return this.request("GET", `/v1/analyses/${seg(analysisId)}/explanation`, undefined, signal, "text").then(
      (r) => r.body as string,
    );
  }

  verify(analysisId: string, signal?: AbortSignal): Promise<Submission<VerificationResult>> {
    return this.submit<VerificationResult>(`/v1/analyses/${seg(analysisId)}/verification`, undefined, signal);
  }

  plan(caseId: string, req: PlanRequest, signal?: AbortSignal): Promise<Submission<PlanResult>> {
    return this.submit<PlanResult>(`/v1/cases/${seg(caseId)}/plans`, req, signal);
  }

  // ---- asynchronous jobs (202 + Location) -------------------------------

  submitAnalysisJob(
    caseId: string,
    req: AnalysisRequest & JobOptions,
    signal?: AbortSignal,
  ): Promise<Submission<AnalysisCreated>> {
    return this.submit<AnalysisCreated>(`/v1/cases/${seg(caseId)}/analysis-jobs`, req, signal);
  }

  submitPlanJob(caseId: string, req: PlanRequest & JobOptions, signal?: AbortSignal): Promise<Submission<PlanResult>> {
    return this.submit<PlanResult>(`/v1/cases/${seg(caseId)}/plan-jobs`, req, signal);
  }

  submitVerificationJob(analysisId: string, opts: JobOptions = {}, signal?: AbortSignal): Promise<Submission<VerificationResult>> {
    return this.submit<VerificationResult>(`/v1/analyses/${seg(analysisId)}/verification-jobs`, opts, signal);
  }

  getJob(jobId: string, signal?: AbortSignal): Promise<JobRecord> {
    return this.json<JobRecord>("GET", `/v1/jobs/${seg(jobId)}`, undefined, signal);
  }

  cancelJob(jobId: string, signal?: AbortSignal): Promise<JobRecord> {
    return this.json<JobRecord>("POST", `/v1/jobs/${seg(jobId)}/cancel`, {}, signal);
  }

  // ---- transport -------------------------------------------------------

  private async json<T>(method: string, path: string, body: unknown, signal?: AbortSignal, auth = true): Promise<T> {
    const r = await this.request(method, path, body, signal, "json", auth);
    return r.body as T;
  }

  private async submit<T>(path: string, body: unknown, signal?: AbortSignal): Promise<Submission<T>> {
    const r = await this.request("POST", path, body ?? {}, signal, "json");
    if (r.status === 202) {
      const b = (r.body ?? {}) as { job_id?: unknown; id?: unknown; status_url?: unknown };
      const id = typeof b.job_id === "string" ? b.job_id : typeof b.id === "string" ? b.id : "";
      if (!id) throw new ApiError(202, "API accepted the request but returned no job id", r.body);
      const statusUrl = r.location ?? (typeof b.status_url === "string" ? b.status_url : undefined);
      return { state: "accepted", job: statusUrl ? { id, statusUrl } : { id } };
    }
    return { state: "completed", value: r.body as T };
  }

  private async request(
    method: string,
    path: string,
    body: unknown,
    signal: AbortSignal | undefined,
    accept: Accept,
    auth = true,
  ): Promise<{ status: number; body: unknown; location: string | undefined }> {
    const headers: Record<string, string> = { Accept: accept === "json" ? "application/json" : "text/plain" };
    if (auth) {
      const token = this.getToken();
      if (!token) throw new ApiError(401, "No API token entered.");
      headers.Authorization = `Bearer ${token}`;
    }
    const init: RequestInit = { method, headers, credentials: "omit", cache: "no-store", redirect: "error" };
    if (signal) init.signal = signal;
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(body);
    }
    let res: Response;
    try {
      res = await this.fetchImpl(`${this.baseUrl}${path}`, init);
    } catch (e) {
      if (e instanceof DOMException && e.name === "AbortError") throw e;
      throw new ApiError(0, "Network error: the API could not be reached.");
    }
    const text = await res.text();
    const ctype = res.headers.get("content-type") ?? "";
    let parsed: unknown = text;
    if (ctype.includes("application/json") && text) {
      try {
        parsed = JSON.parse(text);
      } catch {
        throw new ApiError(res.status, "API returned malformed JSON.");
      }
    }
    if (!res.ok) {
      const detail = describeErrorBody(parsed);
      throw new ApiError(res.status, `HTTP ${res.status}${detail ? `: ${detail}` : ""}`, parsed);
    }
    if (accept === "json" && typeof parsed === "string") {
      throw new ApiError(res.status, "API returned a non-JSON response.");
    }
    return { status: res.status, body: parsed, location: res.headers.get("location") ?? undefined };
  }
}

function seg(s: string): string {
  return encodeURIComponent(s);
}
