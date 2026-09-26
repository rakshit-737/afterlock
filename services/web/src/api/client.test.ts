import { describe, expect, it, vi } from "vitest";
import { AfterlockClient, ApiError, AsyncJobsUnsupportedError, describeErrorBody, settle, type JobApi } from "./client";

type Call = { url: string; init: RequestInit };

function fakeFetch(status: number, body: unknown, headers: Record<string, string> = {}) {
  const calls: Call[] = [];
  const text = typeof body === "string" ? body : JSON.stringify(body);
  const ctype = typeof body === "string" ? "text/plain; charset=utf-8" : "application/json";
  const fn = vi.fn(async (url: RequestInfo | URL, init?: RequestInit) => {
    calls.push({ url: String(url), init: init ?? {} });
    return new Response(status === 204 ? null : text, { status, headers: { "content-type": ctype, ...headers } });
  });
  return { fn: fn as unknown as typeof fetch, calls };
}

const TOKEN = "t-0123456789abcdef";

function client(f: typeof fetch, token: string | null = TOKEN) {
  return new AfterlockClient({ baseUrl: "http://127.0.0.1:8080/", getToken: () => token, fetchImpl: f });
}

describe("AfterlockClient", () => {
  it("sends the bearer token and never sends cookies", async () => {
    const { fn, calls } = fakeFetch(200, { items: ["a"], total: 1 });
    const r = await client(fn).listCases(10, 5);
    expect(r).toEqual({ items: ["a"], total: 1 });
    expect(calls[0]!.url).toBe("http://127.0.0.1:8080/v1/cases?limit=10&offset=5");
    const h = calls[0]!.init.headers as Record<string, string>;
    expect(h.Authorization).toBe(`Bearer ${TOKEN}`);
    expect(calls[0]!.init.credentials).toBe("omit");
  });

  it("health does not require a token", async () => {
    const { fn, calls } = fakeFetch(200, { status: "ok", version: "0.1.0", storage: "in-memory" });
    await client(fn, null).health();
    expect((calls[0]!.init.headers as Record<string, string>).Authorization).toBeUndefined();
  });

  it("refuses authenticated calls without a token, without hitting the network", async () => {
    const { fn } = fakeFetch(200, {});
    await expect(client(fn, null).listCases()).rejects.toMatchObject({ status: 401 });
    expect(fn).not.toHaveBeenCalled();
  });

  it("encodes path segments", async () => {
    const { fn, calls } = fakeFetch(200, { id: "x" });
    await client(fn).getAnalysis("../etc passwd");
    expect(calls[0]!.url).toBe("http://127.0.0.1:8080/v1/analyses/..%2Fetc%20passwd");
  });

  it("posts JSON bodies for analyses and returns a completed submission on 201", async () => {
    const { fn, calls } = fakeFetch(201, { id: "an-000001", result: {} });
    const sub = await client(fn).runAnalysis("residual-token", { mode: "full", remediation: [{ kind: "wait" }] });
    expect(sub).toEqual({ state: "completed", value: { id: "an-000001", result: {} } });
    expect(calls[0]!.init.method).toBe("POST");
    expect(JSON.parse(String(calls[0]!.init.body))).toEqual({ mode: "full", remediation: [{ kind: "wait" }] });
    expect((calls[0]!.init.headers as Record<string, string>)["Content-Type"]).toBe("application/json");
  });

  it("verification POSTs an empty object body", async () => {
    const { fn, calls } = fakeFetch(200, { witnesses: {}, reference_exploration: { views: {} } });
    await client(fn).verify("an-000001");
    expect(calls[0]!.url).toMatch(/\/v1\/analyses\/an-000001\/verification$/);
    expect(calls[0]!.init.body).toBe("{}");
  });

  it("returns explanation as plain text", async () => {
    const { fn } = fakeFetch(200, "AFTERLOCK residual-token: Containment FAILS");
    expect(await client(fn).getExplanation("an-1")).toBe("AFTERLOCK residual-token: Containment FAILS");
  });

  it("maps a 202 Accepted to an accepted submission (future async jobs)", async () => {
    const { fn } = fakeFetch(202, { job_id: "job-7" }, { location: "/v1/jobs/job-7" });
    const sub = await client(fn).plan("c", { max_length: 2 });
    expect(sub).toEqual({ state: "accepted", job: { id: "job-7", statusUrl: "/v1/jobs/job-7" } });
    await expect(settle(sub)).rejects.toBeInstanceOf(AsyncJobsUnsupportedError);
    const jobs: JobApi = { wait: async <T,>() => ({ done: true }) as T, cancel: async () => {} };
    await expect(settle(sub, jobs)).resolves.toEqual({ done: true });
  });

  it("raises ApiError with the server detail and never echoes the token", async () => {
    const { fn } = fakeFetch(422, { detail: { conclusion: "invalid_input", error: "events line 3: bad" } });
    const err = await client(fn).createCase({ case_id: "c", cluster_id: "k", inventory: {}, case: {}, events: [] }).catch((e) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err.status).toBe(422);
    expect(err.message).toBe("HTTP 422: invalid_input: events line 3: bad");
    expect(err.message).not.toContain(TOKEN);
  });

  it("marks 401/403 as auth errors", async () => {
    const { fn } = fakeFetch(403, { detail: "analyst role for this cluster required" });
    const err = await client(fn).plan("c", {}).catch((e) => e);
    expect(err.isAuth).toBe(true);
    expect(err.message).toContain("analyst role");
  });

  it("wraps network failures", async () => {
    const f = (async () => {
      throw new TypeError("fetch failed");
    }) as unknown as typeof fetch;
    await expect(client(f).listCases()).rejects.toMatchObject({ status: 0 });
  });
});

describe("describeErrorBody", () => {
  it("formats pydantic validation lists", () => {
    expect(describeErrorBody({ detail: [{ loc: ["body", "mode"], msg: "bad mode" }] })).toBe("body.mode: bad mode");
  });
  it("handles top-level error keys and plain strings", () => {
    expect(describeErrorBody({ error: "request_too_large" })).toBe("request_too_large");
    expect(describeErrorBody("oops")).toBe("oops");
    expect(describeErrorBody(null)).toBeNull();
  });
});
