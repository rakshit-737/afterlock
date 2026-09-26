import { useEffect, useMemo, useRef, useState } from "react";
import type { AnalysisResult, Witness, WitnessStep } from "../api/types";
import { factText, intervalText } from "../format";
import { buildProvenance, clip, NODE_H, nodeWidth, type GraphNode } from "../provenance";

const STATUS_TEXT: Record<string, string> = {
  observed: "observed (from evidence)",
  assumed: "assumed (declared)",
  inferred: "inferred (derived by a rule)",
  premise: "premise",
};

/** Selected-witness provenance graph (SVG) with a table alternative and an evidence drawer. */
export function ProvenanceView({ result }: { result: AnalysisResult }) {
  const [witnessId, setWitnessId] = useState(result.witnesses[0]?.id ?? "");
  const [open, setOpen] = useState<number | null>(null);
  const opener = useRef<HTMLElement | null>(null);
  const witness = result.witnesses.find((w) => w.id === witnessId) ?? result.witnesses[0];

  useEffect(() => {
    setWitnessId(result.witnesses[0]?.id ?? "");
    setOpen(null);
  }, [result]);

  if (!witness) {
    return (
      <section aria-labelledby="h-prov" className="panel">
        <h3 id="h-prov">Provenance</h3>
        <p className="muted">No witnesses, so there is no provenance to show.</p>
      </section>
    );
  }

  const show = (i: number, el: HTMLElement) => {
    opener.current = el;
    setOpen(i);
  };
  const close = () => {
    setOpen(null);
    opener.current?.focus();
  };

  return (
    <section aria-labelledby="h-prov" className="panel">
      <h3 id="h-prov">Provenance</h3>
      <label htmlFor="prov-witness">Witness</label>
      <select
        id="prov-witness"
        value={witness.id}
        onChange={(e) => {
          setWitnessId(e.target.value);
          setOpen(null);
        }}
      >
        {result.witnesses.map((w) => (
          <option key={w.id} value={w.id}>
            {w.id} (objective {w.objective}, view {w.view})
          </option>
        ))}
      </select>
      <p className="muted small">
        Each rule box is one derivation: its premises on the left jointly yield the fact on the right. Node borders show
        status: solid = observed, dashed = inferred, dotted = assumed; the status is also written in each node. Select a
        fact or rule to open its evidence.
      </p>
      <Graph witness={witness} onOpen={show} />
      <StepTable witness={witness} onOpen={show} />
      {open !== null && witness.steps[open] ? (
        <EvidenceDrawer witness={witness} index={open} step={witness.steps[open]} result={result} onClose={close} />
      ) : null}
    </section>
  );
}

function Graph({ witness, onOpen }: { witness: Witness; onOpen: (i: number, el: HTMLElement) => void }) {
  const g = useMemo(() => buildProvenance(witness), [witness]);
  const byId = new Map(g.nodes.map((n) => [n.id, n]));
  const titleId = `prov-title-${witness.id}`;
  return (
    <div className="graph-wrap">
      <svg
        className="prov-graph"
        role="group"
        aria-labelledby={titleId}
        width={g.width}
        height={g.height}
        viewBox={`0 0 ${g.width} ${g.height}`}
      >
        <title id={titleId}>{`Provenance graph for ${witness.id}, reaching ${factText(witness.goal)}`}</title>
        <defs>
          <marker id="prov-arrow" viewBox="0 0 10 10" refX="10" refY="5" markerWidth="7" markerHeight="7" orient="auto">
            <path d="M0,0 L10,5 L0,10 z" className="prov-arrowhead" />
          </marker>
        </defs>
        {g.edges.map((e, i) => {
          const a = byId.get(e.from)!;
          const b = byId.get(e.to)!;
          const x1 = a.x + nodeWidth(a);
          const y1 = a.y + NODE_H / 2;
          const x2 = b.x;
          const y2 = b.y + NODE_H / 2;
          const mx = (x1 + x2) / 2;
          return (
            <path
              key={i}
              className="prov-edge"
              d={`M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`}
              markerEnd="url(#prov-arrow)"
              aria-hidden="true"
            />
          );
        })}
        {g.nodes.map((n) => (
          <Node key={n.id} n={n} witness={witness} onOpen={onOpen} />
        ))}
      </svg>
    </div>
  );
}

function Node({ n, witness, onOpen }: { n: GraphNode; witness: Witness; onOpen: (i: number, el: HTMLElement) => void }) {
  const idx = n.stepIndex;
  const interactive = idx !== null;
  const status = n.type === "fact" ? n.status : "rule";
  const step = idx !== null ? witness.steps[idx] : undefined;
  const name =
    n.type === "fact"
      ? `Fact ${n.label}, ${STATUS_TEXT[n.status] ?? n.status}${step ? `, ${intervalText(step.interval)}` : ""}`
      : `Rule ${n.label}, derives step ${(idx ?? 0) + 1}`;
  const activate = (el: Element) => {
    if (idx !== null) onOpen(idx, el as HTMLElement);
  };
  const w = nodeWidth(n);
  return (
    <g
      className={`prov-node prov-${n.type} prov-${status}`}
      transform={`translate(${n.x},${n.y})`}
      {...(interactive
        ? {
            role: "button",
            tabIndex: 0,
            "aria-label": `${name}. Show evidence.`,
            onClick: (e: React.MouseEvent<SVGGElement>) => activate(e.currentTarget),
            onKeyDown: (e: React.KeyboardEvent<SVGGElement>) => {
              if (e.key === "Enter" || e.key === " ") {
                e.preventDefault();
                activate(e.currentTarget);
              }
            },
          }
        : { role: "img", "aria-label": name })}
    >
      <title>{name}</title>
      <rect width={w} height={NODE_H} rx={n.type === "rule" ? 14 : 4} />
      <text x={8} y={17} className="prov-label">
        {clip(n.label, n.type === "fact" ? 34 : 20)}
      </text>
      <text x={8} y={34} className="prov-sub">
        {n.type === "fact" ? `[${n.status}]` : "rule"}
      </text>
    </g>
  );
}

function StepTable({ witness, onOpen }: { witness: Witness; onOpen: (i: number, el: HTMLElement) => void }) {
  return (
    <table className="prov-table">
      <caption>Provenance of {witness.id} as a table (same content as the graph)</caption>
      <thead>
        <tr>
          <th scope="col">Step</th>
          <th scope="col">Fact</th>
          <th scope="col">Status</th>
          <th scope="col">Rule</th>
          <th scope="col">Premises</th>
          <th scope="col">Interval</th>
          <th scope="col">Evidence</th>
        </tr>
      </thead>
      <tbody>
        {witness.steps.map((s, i) => (
          <tr key={i}>
            <td>{i + 1}</td>
            <td>
              <code>{factText(s.fact)}</code>
            </td>
            <td>{s.status}</td>
            <td>
              <code>{s.rule}</code>
            </td>
            <td>
              {s.premises?.length ? (
                <ul className="compact">
                  {s.premises.map((p, j) => (
                    <li key={j}>
                      <code>{factText(p)}</code>
                    </li>
                  ))}
                </ul>
              ) : (
                <span className="muted">none</span>
              )}
            </td>
            <td>{intervalText(s.interval)}</td>
            <td>
              <button type="button" className="link" onClick={(e) => onOpen(i, e.currentTarget)}>
                Evidence for step {i + 1}
              </button>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function EvidenceDrawer({
  witness,
  index,
  step,
  result,
  onClose,
}: {
  witness: Witness;
  index: number;
  step: WitnessStep;
  result: AnalysisResult;
  onClose: () => void;
}) {
  const heading = useRef<HTMLHeadingElement>(null);
  useEffect(() => heading.current?.focus(), [index, witness.id]);
  const note = (step as WitnessStep & { note?: unknown }).note;
  return (
    <aside
      className="drawer"
      aria-labelledby="h-drawer"
      onKeyDown={(e) => {
        if (e.key === "Escape") onClose();
      }}
    >
      <h4 id="h-drawer" tabIndex={-1} ref={heading}>
        Evidence for {witness.id} step {index + 1}
      </h4>
      <dl className="kv">
        <dt>Fact</dt>
        <dd>
          <code>{factText(step.fact)}</code>
        </dd>
        <dt>Status</dt>
        <dd>{STATUS_TEXT[step.status] ?? step.status}</dd>
        <dt>Rule</dt>
        <dd>
          <code>{step.rule}</code>
        </dd>
        <dt>Interval</dt>
        <dd>{intervalText(step.interval)}</dd>
        <dt>Evidence references</dt>
        <dd data-testid="drawer-evidence">
          {step.evidence?.length ? (
            <ul className="compact">
              {step.evidence.map((e) => (
                <li key={e}>
                  <code>{e}</code>
                </li>
              ))}
            </ul>
          ) : step.status === "assumed" ? (
            "None: this step is a declared assumption (see Assumptions)."
          ) : step.status === "inferred" ? (
            "None directly: derived by the rule from the premises and conditions below."
          ) : (
            "None reported."
          )}
        </dd>
        <dt>Premises</dt>
        <dd>
          {step.premises?.length ? (
            <ul className="compact">
              {step.premises.map((p, j) => (
                <li key={j}>
                  <code>{factText(p)}</code>
                </li>
              ))}
            </ul>
          ) : (
            "none"
          )}
        </dd>
        <dt>Conditions checked</dt>
        <dd>
          {step.conditions?.length ? (
            <ul className="compact">
              {step.conditions.map((c, j) => (
                <li key={j}>
                  {c.check}
                  {Object.entries(c)
                    .filter(([k]) => k !== "check" && k !== "detail")
                    .map(([k, v]) => ` ${k}=${Array.isArray(v) ? v.map(String).join("|") : String(v)}`)
                    .join("")}
                  {c.detail ? `: ${c.detail}` : ""}
                </li>
              ))}
            </ul>
          ) : (
            "none"
          )}
        </dd>
        {typeof note === "string" ? (
          <>
            <dt>Note</dt>
            <dd>{note}</dd>
          </>
        ) : null}
      </dl>
      <p className="muted small">
        Evidence references are record identifiers from the case ({result.evidence_references.length} in this result). The
        API does not serve the source records themselves.
      </p>
      <button type="button" onClick={onClose}>
        Close evidence
      </button>
    </aside>
  );
}
