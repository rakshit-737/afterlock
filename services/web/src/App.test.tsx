import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { App } from "./App";
import { AfterlockClient } from "./api/client";
import { PollingJobApi, pollingWatcher } from "./api/jobs";
import planFixture from "./test/fixtures/residual-token.plan.json";
import resultFixture from "./test/fixtures/residual-token.result.json";

const TOKEN = "analyst-token-0123456789";

function fakeApi() {
  const seen: { method: string; path: string; auth: string | undefined }[] = [];
  const f = vi.fn(async (url: RequestInfo | URL, init?: RequestInit) => {
    const path = String(url);
    const method = init?.method ?? "GET";
    seen.push({ method, path, auth: (init?.headers as Record<string, string>)?.Authorization });
    const json = (status: number, body: unknown) =>
      new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    if (path === "/v1/health") return json(200, { status: "ok", version: "0.1.0", storage: "in-memory" });
    if (path.startsWith("/v1/cases?")) return json(200, { items: ["residual-token"], total: 1 });
    if (path === "/v1/cases/residual-token" && method === "GET")
      return json(200, { case_id: "residual-token", cluster_id: "lab-local", input: { coverage_gaps: [] }, diagnostics: {} });
    if (path === "/v1/cases/residual-token/analyses") return json(201, { id: "an-000001", result: resultFixture });
    if (path === "/v1/analyses/an-000001/explanation")
      return new Response("AFTERLOCK residual-token: Containment FAILS in the modeled state.", {
        status: 200,
        headers: { "content-type": "text/plain" },
      });
    if (path === "/v1/cases/residual-token/plans") return json(200, planFixture);
    return json(404, { detail: "not found" });
  });
  return { f: f as unknown as typeof fetch, seen };
}

afterEach(cleanup);

describe("App investigation flow", () => {
  it("keeps the token in memory, lists cases, analyzes and plans", { timeout: 30000 }, async () => {
    const setItem = vi.spyOn(Storage.prototype, "setItem");
    const { f, seen } = fakeApi();
    render(<App makeClient={(g) => new AfterlockClient({ getToken: g, fetchImpl: f })} />);

    fireEvent.change(screen.getByLabelText("API bearer token"), { target: { value: TOKEN } });
    fireEvent.click(screen.getByRole("button", { name: "Use token" }));
    fireEvent.click(await screen.findByRole("button", { name: "residual-token" }));

    await screen.findByRole("heading", { name: /Case residual-token/ });
    fireEvent.change(screen.getByLabelText("Mode"), { target: { value: "snapshot_only" } });
    fireEvent.click(screen.getByRole("button", { name: "Analyze" }));
    expect(await screen.findByText(/Containment FAILS in the modeled state/)).toBeTruthy();
    expect(screen.getByText("Model-level only")).toBeTruthy();

    const post = seen.find((s) => s.path.endsWith("/analyses"));
    expect(post?.auth).toBe(`Bearer ${TOKEN}`);

    fireEvent.click(screen.getByRole("button", { name: "Search plans" }));
    expect(await screen.findByText("search: optimal_within_bounds")).toBeTruthy();

    expect(setItem).not.toHaveBeenCalled();
    expect(document.cookie).toBe("");
    expect(document.body.textContent).not.toContain(TOKEN);

    fireEvent.click(screen.getByRole("button", { name: "Forget token" }));
    await waitFor(() => expect(screen.queryByText("residual-token")).toBeNull());
  });

  it("runs an analysis as a background job, shows its state, and cancels it", { timeout: 30000 }, async () => {
    let state = "running";
    const calls: string[] = [];
    const json = (status: number, body: unknown, headers: Record<string, string> = {}) =>
      new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });
    const job = () => ({
      job_id: "job-1", cluster_id: "lab-local", manifest_id: "m", kind: "analysis", state, attempts: 1, max_attempts: 3,
      cancel_requested: false, last_error: null, result_id: null,
    });
    const f = (async (url: RequestInfo | URL, init?: RequestInit) => {
      const path = String(url);
      const method = init?.method ?? "GET";
      calls.push(`${method} ${path}`);
      if (path === "/v1/health") return json(200, { status: "ok", version: "0.1.0", storage: "in-memory" });
      if (path.startsWith("/v1/cases?")) return json(200, { items: ["residual-token"], total: 1 });
      if (path === "/v1/cases/residual-token") return json(200, { case_id: "residual-token", cluster_id: "lab-local", input: {}, diagnostics: {} });
      if (path === "/v1/cases/residual-token/analysis-jobs")
        return json(202, { job_id: "job-1", state: "queued", manifest_id: "m" }, { location: "/v1/jobs/job-1" });
      if (path === "/v1/jobs/job-1/cancel") {
        state = "cancelled";
        return json(202, job());
      }
      if (path === "/v1/jobs/job-1") return json(200, job());
      return json(404, { detail: "not found" });
    }) as unknown as typeof fetch;
    let client: AfterlockClient | null = null;
    const make = (g: () => string | null) => (client = new AfterlockClient({ getToken: g, fetchImpl: f }));
    const jobs = new PollingJobApi(
      { getJob: (id, s) => client!.getJob(id, s), cancelJob: (id) => client!.cancelJob(id) },
      pollingWatcher({ initialMs: 5, factor: 1, maxMs: 5 }),
    );
    render(<App makeClient={make} jobs={jobs} />);
    fireEvent.change(screen.getByLabelText("API bearer token"), { target: { value: TOKEN } });
    fireEvent.click(screen.getByRole("button", { name: "Use token" }));
    fireEvent.click(await screen.findByRole("button", { name: "residual-token" }));
    await screen.findByRole("heading", { name: /Case residual-token/ });
    fireEvent.click(screen.getByLabelText("Run as background jobs"));
    fireEvent.click(screen.getByRole("button", { name: "Analyze" }));
    await waitFor(() => expect(screen.getByTestId("job-state").textContent).toBe("running"));
    fireEvent.click(screen.getByRole("button", { name: "Cancel job" }));
    await waitFor(() => expect(screen.getByTestId("job-state").textContent).toBe("cancelled"));
    expect((await screen.findByRole("alert")).textContent).toContain("was cancelled");
    expect(calls).toContain("POST /v1/jobs/job-1/cancel");
    expect(screen.queryByRole("heading", { name: "Conclusion" })).toBeNull();
  });

  it("stops polling on unmount", { timeout: 30000 }, async () => {
    let polls = 0;
    const f = (async (url: RequestInfo | URL) => {
      const path = String(url);
      const json = (status: number, body: unknown) =>
        new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
      if (path === "/v1/jobs/job-1") polls++;
      return json(200, { job_id: "job-1", state: "running", kind: "plan", attempts: 1, max_attempts: 3 });
    }) as unknown as typeof fetch;
    const client = new AfterlockClient({ getToken: () => TOKEN, fetchImpl: f });
    const ctl = new AbortController();
    const p = new PollingJobApi(client, pollingWatcher({ initialMs: 5, factor: 1, maxMs: 5 })).wait({ id: "job-1" }, ctl.signal);
    await waitFor(() => expect(polls).toBeGreaterThan(1));
    ctl.abort();
    await expect(p).rejects.toMatchObject({ name: "AbortError" });
    const n = polls;
    await new Promise((r) => setTimeout(r, 30));
    expect(polls).toBe(n);
  });

  it("surfaces API errors as alerts", async () => {
    const f = (async (url: RequestInfo | URL) =>
      String(url) === "/v1/health"
        ? new Response("{}", { status: 200, headers: { "content-type": "application/json" } })
        : new Response(JSON.stringify({ detail: "invalid token" }), {
            status: 401,
            headers: { "content-type": "application/json" },
          })) as unknown as typeof fetch;
    render(<App makeClient={(g) => new AfterlockClient({ getToken: g, fetchImpl: f })} />);
    fireEvent.change(screen.getByLabelText("API bearer token"), { target: { value: "wrong-token-000000" } });
    fireEvent.click(screen.getByRole("button", { name: "Use token" }));
    expect((await screen.findByRole("alert")).textContent).toContain("HTTP 401: invalid token");
  });
});
