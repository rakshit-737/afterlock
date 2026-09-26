import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { App } from "./App";
import { AfterlockClient } from "./api/client";
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
