import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import type { AnalysisResult } from "../api/types";
import resultFixture from "../test/fixtures/residual-token.result.json";
import { CredentialLifecycleView } from "./CredentialLifecycleView";
import { ProvenanceView } from "./ProvenanceView";

const result = resultFixture as unknown as AnalysisResult;
afterEach(cleanup);

describe("ProvenanceView", () => {
  it("renders the selected witness as a graph and a table, and opens the evidence drawer", { timeout: 30000 }, () => {
    render(<ProvenanceView result={result} />);
    const graph = screen.getByRole("group", { name: /Provenance graph for w-protect-canary/ });
    const nodes = within(graph).getAllByRole("button");
    expect(nodes.length).toBe(5); // 3 facts + 2 rules
    fireEvent.click(within(graph).getByRole("button", { name: /Fact knows_secret demo release-credential 1, observed/ }));
    const drawer = screen.getByRole("complementary", { name: /Evidence for w-protect-canary step 1/ });
    expect(within(drawer).getByTestId("drawer-evidence").textContent).toContain("lab-audit#2");
    expect(document.activeElement?.id).toBe("h-drawer");
    fireEvent.click(within(drawer).getByRole("button", { name: "Close evidence" }));
    expect(screen.queryByRole("complementary")).toBeNull();
  });

  it("supports keyboard activation and witness switching", { timeout: 30000 }, () => {
    render(<ProvenanceView result={result} />);
    fireEvent.change(screen.getByLabelText("Witness"), { target: { value: "w-protect-secret" } });
    const graph = screen.getByRole("group", { name: /w-protect-secret/ });
    const rule = within(graph).getByRole("button", { name: /Rule R-READ-SECRET/ });
    fireEvent.keyDown(rule, { key: "Enter" });
    const drawer = screen.getByRole("complementary");
    expect(drawer.textContent).toContain("credential_usable");
    expect(within(drawer).getByTestId("drawer-evidence").textContent).toMatch(/derived by the rule/);
  });
});

describe("CredentialLifecycleView", () => {
  it("lists each credential with acquired/valid events and flags no rotation", { timeout: 30000 }, () => {
    render(<CredentialLifecycleView result={result} />);
    const k8s = screen.getByTestId("cred-kubernetes");
    expect(k8s.textContent).toContain("Acquired");
    expect(k8s.textContent).toContain("Valid");
    expect(k8s.textContent).toContain("No rotation or revocation in the sequence");
  });
});
