import type { VerificationResult } from "../api/types";
import { Badge } from "./Badge";

/**
 * Reference-checker output. This is an independent MODEL-LEVEL check (a second
 * implementation of the semantics), not a lab validation.
 */
export function VerificationView({ v }: { v: VerificationResult }) {
  const witnesses = Object.entries(v.witnesses);
  const views = Object.entries(v.reference_exploration.views ?? {});
  return (
    <section aria-labelledby="h-verification" className="panel">
      <h3 id="h-verification">Reference-checker verification</h3>
      <p className="muted small">
        Model-level cross-check by the independent reference checker. It does not change the validation status: nothing was
        executed in a lab.
      </p>
      <h4>Witness replay</h4>
      {witnesses.length === 0 ? <p className="muted">No witnesses to replay.</p> : null}
      <ul className="plain">
        {witnesses.map(([id, w]) => (
          <li key={id} data-testid={`verify-${id}`}>
            <Badge tone={w.valid ? "ok" : "bad"}>{w.valid ? "Replays" : "Rejected"}</Badge> <code>{id}</code>
            {w.problems.length ? (
              <ul className="compact">
                {w.problems.map((p, i) => (
                  <li key={i}>{p}</li>
                ))}
              </ul>
            ) : null}
          </li>
        ))}
      </ul>
      <h4>Reference exploration</h4>
      <table>
        <thead>
          <tr>
            <th scope="col">View</th>
            <th scope="col">Reachable objectives</th>
            <th scope="col">States</th>
            <th scope="col">Complete</th>
          </tr>
        </thead>
        <tbody>
          {views.map(([name, r]) => (
            <tr key={name}>
              <td>
                <code>{name}</code>
              </td>
              <td>{r.reachable_objectives.length ? r.reachable_objectives.join(", ") : "none"}</td>
              <td>{r.states}</td>
              <td>
                {r.complete ? (
                  <Badge tone="ok">Complete</Badge>
                ) : (
                  <Badge tone="unknown">Incomplete: bound reached, not a containment result</Badge>
                )}
                {r.unknown.length ? <div className="small">unknown: {r.unknown.map((u) => JSON.stringify(u)).join("; ")}</div> : null}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}
