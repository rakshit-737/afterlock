// Asynchronous job support (docs/api/api.md, "Asynchronous jobs").
//
// `PollingJobApi` implements `JobApi` by polling `GET /v1/jobs/{id}` with
// capped exponential backoff until the job reaches a terminal state.
//
// Transport is isolated behind `JobWatcher`: a function that reports every
// observed job record and resolves with the terminal one. Polling is the only
// watcher today. A server-sent-events watcher over `GET /v1/jobs/{id}/events`
// can replace it later by implementing the same signature (and falling back to
// `pollJob` when the stream is unavailable) without touching `PollingJobApi`
// callers or the UI.

import type { AfterlockClient, JobApi, JobRef } from "./client";
import { TERMINAL_JOB_STATES, type JobRecord } from "./types";

export interface Backoff {
  /** First delay between polls, in ms. */
  initialMs: number;
  /** Multiplier applied after each non-terminal poll. */
  factor: number;
  /** Upper bound on the delay, in ms. */
  maxMs: number;
}

export const DEFAULT_BACKOFF: Backoff = { initialMs: 250, factor: 1.6, maxMs: 3000 };

export type JobWatcher = (
  client: Pick<AfterlockClient, "getJob">,
  job: JobRef,
  onUpdate: (job: JobRecord) => void,
  signal?: AbortSignal,
) => Promise<JobRecord>;

export class JobFailedError extends Error {
  constructor(readonly job: JobRecord) {
    super(`Job ${job.job_id} failed after ${job.attempts} attempt(s)${job.last_error ? `: ${job.last_error}` : ""}.`);
    this.name = "JobFailedError";
  }
}

export class JobCancelledError extends Error {
  constructor(readonly job: JobRecord) {
    super(`Job ${job.job_id} was cancelled; no result was published.`);
    this.name = "JobCancelledError";
  }
}

export const isTerminal = (state: string) => TERMINAL_JOB_STATES.includes(state);

function abortError(): DOMException {
  return new DOMException("The operation was aborted.", "AbortError");
}

/** Resolve after `ms`, or reject with AbortError as soon as `signal` aborts. */
export function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(abortError());
    const onAbort = () => {
      clearTimeout(timer);
      reject(abortError());
    };
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

/** Polling watcher with capped exponential backoff. */
export function pollingWatcher(backoff: Backoff = DEFAULT_BACKOFF, wait = sleep): JobWatcher {
  return async (client, job, onUpdate, signal) => {
    let delay = backoff.initialMs;
    for (;;) {
      if (signal?.aborted) throw abortError();
      const rec = await client.getJob(job.id, signal);
      onUpdate(rec);
      if (isTerminal(rec.state)) return rec;
      await wait(delay, signal);
      delay = Math.min(backoff.maxMs, Math.round(delay * backoff.factor));
    }
  };
}

/** Map a succeeded job to the value the synchronous endpoint would have returned. */
export function jobValue<T>(rec: JobRecord): T {
  if (rec.kind === "analysis") return { id: rec.result_id, result: rec.result } as T;
  return rec.result as T;
}

export class PollingJobApi implements JobApi {
  constructor(
    private readonly client: Pick<AfterlockClient, "getJob" | "cancelJob">,
    private readonly watcher: JobWatcher = pollingWatcher(),
  ) {}

  async wait<T>(job: JobRef, signal?: AbortSignal, onUpdate: (job: JobRecord) => void = () => {}): Promise<T> {
    const rec = await this.watcher(this.client, job, onUpdate, signal);
    if (rec.state === "succeeded") return jobValue<T>(rec);
    if (rec.state === "cancelled") throw new JobCancelledError(rec);
    throw new JobFailedError(rec);
  }

  async cancel(job: JobRef): Promise<void> {
    await this.client.cancelJob(job.id);
  }
}
