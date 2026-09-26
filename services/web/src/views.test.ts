import { describe, expect, it } from "vitest";
import type { AnalysisResult } from "./api/types";
import resultFixture from "./test/fixtures/residual-token.result.json";
import { credentialLifecycles } from "./lifecycle";
import { buildProvenance } from "./provenance";

const result = resultFixture as unknown as AnalysisResult;

describe("buildProvenance", () => {
  it("lays out a witness as premise -> rule -> conclusion hyperedges, left to right", () => {
    const w = result.witnesses.find((x) => x.id === "w-protect-canary")!;
    const g = buildProvenance(w);
    const facts = g.nodes.filter((n) => n.type === "fact");
    const rules = g.nodes.filter((n) => n.type === "rule");
    expect(facts).toHaveLength(3);
    expect(rules.map((r) => r.label)).toEqual(["R-DOWNSTREAM-CREDENTIAL", "R-USE-DOWNSTREAM"]);
    expect(g.edges).toHaveLength(4);
    for (const e of g.edges) {
      const a = g.nodes.find((n) => n.id === e.from)!;
      const b = g.nodes.find((n) => n.id === e.to)!;
      expect(b.layer).toBeGreaterThan(a.layer);
      expect(b.x).toBeGreaterThan(a.x);
    }
    expect(facts.find((f) => f.label.startsWith("knows_secret"))!.status).toBe("observed");
  });
});

describe("credentialLifecycles", () => {
  it("groups acquired and valid events per credential with their sources", () => {
    const cl = credentialLifecycles(result);
    const k8s = cl.find((c) => c.kind === "kubernetes")!;
    expect(k8s.events.map((e) => e.kind)).toEqual(["acquired", "valid"]);
    expect(k8s.events[0]).toMatchObject({ interval: -2, status: "observed", evidence: ["lab-audit#2"] });
    const secret = cl.find((c) => c.kind === "secret")!;
    expect(secret.label).toBe("secret demo/release-credential v1");
  });

  it("marks rotation and revocation only from remediation actions", () => {
    const r: AnalysisResult = {
      ...result,
      remediation: [
        { kind: "rotate_downstream_credential", service: "canary-service" },
        { kind: "delete_service_account", namespace: "demo", name: "release-reader" },
      ],
    };
    const cl = credentialLifecycles(r);
    expect(cl.find((c) => c.kind === "downstream")!.events.some((e) => e.kind === "rotated" && e.interval === 1)).toBe(true);
    expect(cl.find((c) => c.kind === "kubernetes")!.events.some((e) => e.kind === "revoked" && e.interval === 2)).toBe(true);
    expect(cl.find((c) => c.kind === "secret")!.events.some((e) => e.kind === "rotated")).toBe(false);
  });
});
