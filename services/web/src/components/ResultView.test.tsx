import { cleanup, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import type { AnalysisResult, PlanResult, VerificationResult } from "../api/types";
import planFixture from "../test/fixtures/residual-token.plan.json";
import resultFixture from "../test/fixtures/residual-token.result.json";
import verifyFixture from "../test/fixtures/residual-token.verify.json";
import { PlanView } from "./PlanView";
import { ResultView } from "./ResultView";
import { VerificationView } from "./VerificationView";

// Fixtures are real engine output for datasets/replay/residual-token (see docs/frontend/README.md).
const result = resultFixture as unknown as AnalysisResult;

afterEach(cleanup);

describe("ResultView on the residual-token engine result", () => {
  it("shows the model conclusion and that it is model-level only", () => {
    render(<ResultView analysisId="an-000001" result={result} />);
    expect(screen.getByText("Residual path")).toBeTruthy();
    const v = screen.getByTestId("validation");
    expect(v.textContent).toContain("Model-level only");
    expect(v.textContent).not.toContain("Lab confirmed");
  });

  it("lists every objective with a text status and witness link", () => {
    render(<ResultView analysisId="an-000001" result={result} />);
    for (const o of result.objectives) {
      const row = screen.getByTestId(`objective-${o.id}`);
      expect(within(row).getByText("Violated")).toBeTruthy();
      expect(within(row).getByRole("link").getAttribute("href")).toBe(`#w-${o.id}`);
    }
  });

  it("renders witness steps with rule and observed/assumed/inferred status", () => {
    const { container } = render(<ResultView analysisId="an-000001" result={result} />);
    expect(container.querySelector("#w-protect-secret")).not.toBeNull();
    expect(screen.getAllByText("R-READ-SECRET").length).toBeGreaterThan(0);
    expect(screen.getAllByText("[observed]").length).toBeGreaterThan(0);
    expect(screen.getAllByText("[inferred]").length).toBeGreaterThan(0);
  });

  it("shows the timeline with exposure during containment", () => {
    render(<ResultView analysisId="an-000001" result={result} />);
    const i0 = screen.getByTestId("interval-0");
    expect(i0.textContent).toContain("Exposure during containment");
    expect(i0.textContent).toContain("can_read_secret demo/release-credential");
    expect(screen.getByTestId("interval-1").textContent).toContain("remove_binding(name=ci-pod-creator, namespace=demo)");
  });

  it("shows legitimate operations as preserved or broken", () => {
    render(<ResultView analysisId="an-000001" result={result} />);
    expect(screen.getByTestId("legit-release-read").textContent).toContain("Preserved");
    const broken = { ...result, legitimate_operations: [{ id: "op", kind: "read_secret", preserved: false }] };
    cleanup();
    render(<ResultView analysisId="an-2" result={broken} />);
    expect(screen.getByTestId("legit-op").textContent).toContain("Broken");
  });

  it("distinguishes all four objective statuses and lab-confirmed validation", () => {
    const r: AnalysisResult = {
      ...result,
      conclusion: { ...result.conclusion, model: "unknown", validation: "lab_confirmed" },
      objectives: [
        { id: "a", kind: "k", status: "violated" },
        { id: "b", kind: "k", status: "possibly_violated" },
        { id: "c", kind: "k", status: "unknown", reasons: ["audit gap 12:00-12:05"] },
        { id: "d", kind: "k", status: "satisfied_within_scope", basis: "fixpoint_exhausted" },
      ],
      missing_coverage: [{ kind: "bounds_exceeded", view: "conservative_possible", detail: "derivation cap 10 reached" }],
      analysis_bounds: { exhausted: false },
    };
    render(<ResultView analysisId="an-3" result={r} />);
    expect(within(screen.getByTestId("objective-a")).getByText("Violated")).toBeTruthy();
    expect(within(screen.getByTestId("objective-b")).getByText("Possibly violated")).toBeTruthy();
    expect(within(screen.getByTestId("objective-c")).getByText("Unknown")).toBeTruthy();
    expect(screen.getByText("audit gap 12:00-12:05")).toBeTruthy();
    expect(within(screen.getByTestId("objective-d")).getByText("Satisfied within scope")).toBeTruthy();
    expect(screen.getByTestId("validation").textContent).toContain("Lab confirmed");
    expect(screen.getByText("derivation cap 10 reached")).toBeTruthy();
    expect(screen.getByText(/NOT exhausted/)).toBeTruthy();
  });

  it("renders hostile API strings as inert text", () => {
    const evil = "<img src=x onerror=alert(1)>";
    const r: AnalysisResult = {
      ...result,
      objectives: [{ id: "x", kind: "k", status: "violated", description: evil }],
    };
    const { container } = render(<ResultView analysisId="an-4" result={r} />);
    expect(container.querySelector("img")).toBeNull();
    expect(screen.getByText(evil)).toBeTruthy();
  });
});

describe("VerificationView", () => {
  it("shows witness replay and reference exploration as model-level", () => {
    render(<VerificationView v={verifyFixture as VerificationResult} />);
    expect(screen.getByTestId("verify-w-protect-secret").textContent).toContain("Replays");
    expect(screen.getAllByText("Complete", { selector: ".badge" }).length).toBe(2);
    expect(screen.getByText(/nothing was executed in a lab/)).toBeTruthy();
  });

  it("flags incomplete exploration and rejected witnesses", () => {
    const v: VerificationResult = {
      witnesses: { w: { valid: false, problems: ["step 2 not derivable"] } },
      reference_exploration: { views: { evidence_supported: { reachable_objectives: [], states: 50000, complete: false, unknown: [] } } },
    };
    render(<VerificationView v={v} />);
    expect(screen.getByText("Rejected")).toBeTruthy();
    expect(screen.getByText("step 2 not derivable")).toBeTruthy();
    expect(screen.getByText(/Incomplete: bound reached/)).toBeTruthy();
  });
});

describe("PlanView", () => {
  it("compares proposed, best and naive plans", () => {
    render(<PlanView plan={planFixture as unknown as PlanResult} />);
    expect(screen.getByText("search: optimal_within_bounds")).toBeTruthy();
    const best = screen.getByTestId("plan-best_plan");
    expect(within(best).getByText("rotate_downstream_credential(service=canary-service)")).toBeTruthy();
    expect(within(best).queryByText("Broken")).toBeNull();
    const naive = screen.getByTestId("plan-naive_containment");
    expect(within(naive).getAllByText("Broken").length).toBe(2);
    expect(within(screen.getByTestId("plan-proposed_remediation")).getByText("Residual path")).toBeTruthy();
  });

  it("states that an incomplete search is not evidence of absence", () => {
    const p = {
      ...(planFixture as unknown as PlanResult),
      search: { status: "incomplete_search", statement: "Evaluation cap 2000 reached before a valid plan was found." },
      best_plan: null,
    };
    render(<PlanView plan={p} />);
    const badge = screen.getByText("search: incomplete_search");
    expect(badge.className).toContain("badge-unknown");
    expect(within(screen.getByTestId("plan-best_plan")).getByText(/not evidence that none exists/)).toBeTruthy();
  });
});
