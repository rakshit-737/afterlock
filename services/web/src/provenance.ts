// Provenance graph for one witness: a pure, layered layout (no graph library).
//
// Each witness step is a hyperedge: its premises (and conditions) jointly derive
// its fact through a named rule. We draw it as fact nodes and one rule node per
// step: premise -> rule -> conclusion. Layers go left to right by derivation depth,
// so the graph is exactly the selected witness, never the whole cluster.

import type { Fact, Witness, WitnessStep } from "./api/types";
import { factText } from "./format";

export interface FactNode {
  type: "fact";
  id: string;
  label: string;
  status: string; // observed | assumed | inferred | premise (not itself a witness step)
  stepIndex: number | null;
  layer: number;
  x: number;
  y: number;
}

export interface RuleNode {
  type: "rule";
  id: string;
  label: string;
  stepIndex: number;
  layer: number;
  x: number;
  y: number;
}

export type GraphNode = FactNode | RuleNode;

export interface GraphEdge {
  from: string;
  to: string;
}

export interface ProvenanceGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
  width: number;
  height: number;
}

export const NODE_W = 240;
export const NODE_H = 44;
export const RULE_W = 150;
const COL_GAP = 60;
const ROW_GAP = 22;
const PAD = 12;

export const factKey = (f: Fact) => JSON.stringify(f);

/** Premise facts and conclusion of a step, as display ids. */
export function buildProvenance(w: Witness): ProvenanceGraph {
  const facts = new Map<string, FactNode>();
  const factLayer = new Map<string, number>();
  const edges: GraphEdge[] = [];
  const rules: RuleNode[] = [];

  // Steps are in derivation order; premises precede conclusions.
  const stepOf = new Map<string, number>();
  w.steps.forEach((s, i) => stepOf.set(factKey(s.fact), i));

  const ensureFact = (f: Fact, layer: number) => {
    const k = factKey(f);
    const idx = stepOf.get(k);
    const step = idx === undefined ? undefined : w.steps[idx];
    if (!facts.has(k)) {
      facts.set(k, {
        type: "fact",
        id: `f:${k}`,
        label: factText(f),
        status: step ? step.status : "premise",
        stepIndex: idx ?? null,
        layer,
        x: 0,
        y: 0,
      });
    }
    return facts.get(k)!;
  };

  w.steps.forEach((s: WitnessStep, i) => {
    const premises = s.premises ?? [];
    if (premises.length === 0) {
      factLayer.set(factKey(s.fact), 0);
      ensureFact(s.fact, 0);
      return;
    }
    let depth = 0;
    for (const p of premises) {
      const pl = factLayer.get(factKey(p)) ?? 0;
      if (!factLayer.has(factKey(p))) factLayer.set(factKey(p), 0);
      ensureFact(p, pl);
      depth = Math.max(depth, pl);
    }
    const ruleLayer = depth + 1;
    const conclLayer = depth + 2;
    factLayer.set(factKey(s.fact), conclLayer);
    const concl = ensureFact(s.fact, conclLayer);
    concl.layer = conclLayer;
    const rule: RuleNode = { type: "rule", id: `r:${i}`, label: s.rule, stepIndex: i, layer: ruleLayer, x: 0, y: 0 };
    rules.push(rule);
    for (const p of premises) edges.push({ from: `f:${factKey(p)}`, to: rule.id });
    edges.push({ from: rule.id, to: concl.id });
  });

  const nodes: GraphNode[] = [...facts.values(), ...rules];
  const byLayer = new Map<number, GraphNode[]>();
  for (const n of nodes) byLayer.set(n.layer, [...(byLayer.get(n.layer) ?? []), n]);
  const layers = [...byLayer.keys()].sort((a, b) => a - b);

  // Column x positions: fact columns are wide, rule columns narrow.
  const colX = new Map<number, number>();
  let x = PAD;
  const maxLayer = layers.length ? layers[layers.length - 1]! : 0;
  for (let l = 0; l <= maxLayer; l++) {
    colX.set(l, x);
    const hasFact = (byLayer.get(l) ?? []).some((n) => n.type === "fact");
    x += (hasFact ? NODE_W : RULE_W) + COL_GAP;
  }
  let maxRows = 0;
  for (const l of layers) {
    const col = byLayer.get(l)!;
    maxRows = Math.max(maxRows, col.length);
    col.forEach((n, row) => {
      n.x = colX.get(l)!;
      n.y = PAD + row * (NODE_H + ROW_GAP);
    });
  }
  return {
    nodes,
    edges,
    width: Math.max(x - COL_GAP + PAD, NODE_W + 2 * PAD),
    height: PAD * 2 + Math.max(1, maxRows) * (NODE_H + ROW_GAP) - ROW_GAP,
  };
}

export function nodeWidth(n: GraphNode): number {
  return n.type === "fact" ? NODE_W : RULE_W;
}

/** Shorten long labels for the SVG; the full text is in the accessible name and the table. */
export function clip(text: string, max: number): string {
  return text.length <= max ? text : `${text.slice(0, max - 1)}…`;
}
