import { describe, expect, it, vi } from "vitest";
import { AfterlockClient, settle } from "./client";
import { JobCancelledError, JobFailedError, PollingJobApi, pollingWatcher, sleep } from "./jobs";
import type { JobRecord } from "./types";

function rec(state: string, extra: Partial<JobRecord> = {}): JobRecord {
  return {
    job_id: "job-1",
    cluster_id: "lab-local",
    manifest_id: "m-1",
    kind: "analysis",
    state,
    attempts: state === "queued" ? 0 : 1,
    max_attempts: 3,
    cancel_requested: false,
    last_error: null,
    result_id: null,
    ...extra,
  };
}

function scripted(states: JobRecord[]) {
  let i = 0;
  const getJob = vi.fn(async () => states[Math.min(i++, states.length - 1)]!);
  const cancelJob = vi.fn(async () => rec("cancelled"));
  return { getJob, cancelJob };
}

const noWait = vi.fn(async () => {});

describe("PollingJobApi", () => {
  it("polls with capped exponential backoff and returns the analysis value", async () => {
    const delays: number[] = [];
    const c = scripted([rec("queued"), rec("running"), rec("running"), rec("succeeded", { result_id: "an-9", result: { ok: 1 } })]);
    const api = new PollingJobApi(c, pollingWatcher({ initialMs: 100, factor: 2, maxMs: 300 }, async (ms) => void delays.push(ms)));
    const seen: string[] = [];
    const v = await api.wait({ id: "job-1" }, undefined, (j) => seen.push(j.state));
    expect(v).toEqual({ id: "an-9", result: { ok: 1 } });
    expect(seen).toEqual(["queued", "running", "running", "succeeded"]);
    expect(delays).toEqual([100, 200, 300]);
  });

  it("returns the raw result for plan and verification jobs", async () => {
    const c = scripted([rec("succeeded", { kind: "plan", result_id: "r-1", result: { schema: "afterlock.plan/1" } })]);
    await expect(new PollingJobApi(c, pollingWatcher(undefined, noWait)).wait({ id: "job-1" })).resolves.toEqual({
      schema: "afterlock.plan/1",
    });
  });

  it("rejects failed and cancelled jobs without a result", async () => {
    const failed = scripted([rec("failed", { attempts: 3, last_error: "invalid_input: bad" })]);
    const err = (await new PollingJobApi(failed, pollingWatcher(undefined, noWait))
      .wait({ id: "job-1" })
      .catch((e: unknown) => e)) as Error;
    expect(err).toBeInstanceOf(JobFailedError);
    expect(err.message).toContain("invalid_input: bad");
    const cancelled = scripted([rec("cancelled")]);
    await expect(new PollingJobApi(cancelled, pollingWatcher(undefined, noWait)).wait({ id: "job-1" })).rejects.toBeInstanceOf(
      JobCancelledError,
    );
  });

  it("stops polling when aborted (component unmount)", async () => {
    const c = scripted([rec("running")]);
    const ctl = new AbortController();
    const api = new PollingJobApi(c, pollingWatcher({ initialMs: 10_000, factor: 1, maxMs: 10_000 }));
    const p = api.wait({ id: "job-1" }, ctl.signal);
    await vi.waitFor(() => expect(c.getJob).toHaveBeenCalledTimes(1));
    ctl.abort();
    await expect(p).rejects.toMatchObject({ name: "AbortError" });
    expect(c.getJob).toHaveBeenCalledTimes(1);
  });

  it("sleep rejects immediately on an already-aborted signal", async () => {
    const ctl = new AbortController();
    ctl.abort();
    await expect(sleep(5, ctl.signal)).rejects.toMatchObject({ name: "AbortError" });
  });

  it("cancel posts to the cancel endpoint", async () => {
    const c = scripted([rec("running")]);
    await new PollingJobApi(c).cancel({ id: "job-1" });
    expect(c.cancelJob).toHaveBeenCalledWith("job-1");
  });
});

describe("job endpoints on AfterlockClient", () => {
  it("submits to *-jobs, reads Location, and polls /v1/jobs/{id}", async () => {
    const calls: { url: string; method: string; body: unknown }[] = [];
    const f = (async (url: RequestInfo | URL, init?: RequestInit) => {
      const u = String(url);
      calls.push({ url: u, method: init?.method ?? "GET", body: init?.body ? JSON.parse(String(init.body)) : undefined });
      const json = (status: number, body: unknown, headers: Record<string, string> = {}) =>
        new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });
      if (u.endsWith("/analysis-jobs")) return json(202, { job_id: "job-1", state: "queued", manifest_id: "m" }, { location: "/v1/jobs/job-1" });
      if (u.endsWith("/v1/jobs/job-1")) return json(200, rec("succeeded", { result_id: "an-1", result: { conclusion: {} } }));
      return json(404, { detail: "not found" });
    }) as unknown as typeof fetch;
    const client = new AfterlockClient({ getToken: () => "tok-0123456789abcdef", fetchImpl: f });
    const sub = await client.submitAnalysisJob("case-1", { mode: "full", max_attempts: 2 });
    expect(sub).toEqual({ state: "accepted", job: { id: "job-1", statusUrl: "/v1/jobs/job-1" } });
    const v = await settle(sub, new PollingJobApi(client, pollingWatcher(undefined, noWait)));
    expect(v).toEqual({ id: "an-1", result: { conclusion: {} } });
    expect(calls[0]).toMatchObject({ url: "/v1/cases/case-1/analysis-jobs", method: "POST", body: { mode: "full", max_attempts: 2 } });
    expect(calls[1]).toMatchObject({ url: "/v1/jobs/job-1", method: "GET" });
  });
});
