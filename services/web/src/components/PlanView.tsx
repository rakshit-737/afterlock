import type { PlanCandidate, PlanResult } from "../api/types";
import { actionText, conclusionLabel, objectiveLabel } from "../format";
import { Badge } from "./Badge";

const ROWS: { key: "proposed_remediation" | "best_plan" | "cheapest_security_only_plan" | "naive_containment"; title: string }[] = [
  { key: "proposed_remediation", title: "Proposed remediation (from the case)" },
  { key: "best_plan", title: "Best plan (security and legitimate operations)" },
  { key: "cheapest_security_only_plan", title: "Cheapest security-only plan" },
  { key: "naive_containment", title: "Naive containment" },
];

export function PlanView({ plan }: { plan: PlanResult }) {
  // Statuses from packages/afterlock/planner.py; anything else (incomplete_search) is shown as unknown.
  const complete = plan.search.status === "optimal_within_bounds" || plan.search.status === "no_valid_plan_within_bounds";
  return (
    <section aria-labelledby="h-plan" className="panel">
      <h3 id="h-plan">Containment plan comparison</h3>
      <p>
        <Badge tone={complete ? "neutral" : "unknown"}>{`search: ${plan.search.status}`}</Badge> {plan.search.statement}
      </p>
      <p className="muted small">
        {plan.search.algorithm ?? ""}
        {plan.search.evaluations !== undefined ? ` · ${plan.search.evaluations} of ${plan.search.max_evaluations} evaluations` : ""}
        {plan.search.max_length !== undefined ? ` · max length ${plan.search.max_length}` : ""}. All outcomes are model-level.
      </p>
      <div className="plans">
        {ROWS.map(({ key, title }) => (
          <Candidate key={key} title={title} c={plan[key]} testId={`plan-${key}`} />
        ))}
      </div>
    </section>
  );
}

function Candidate({ title, c, testId }: { title: string; c: PlanCandidate | null; testId: string }) {
  return (
    <article className="plan" data-testid={testId} aria-label={title}>
      <h4>{title}</h4>
      {!c ? (
        <p className="muted">None found. This is not evidence that none exists.</p>
      ) : (
        <>
          <p>
            <Badge tone={conclusionLabel(c.model_conclusion).tone}>{conclusionLabel(c.model_conclusion).text}</Badge> · cost{" "}
            {c.cost}
          </p>
          <ol className="compact">
            {c.actions.map((a, i) => (
              <li key={i}>
                <code>{actionText(a)}</code>
              </li>
            ))}
          </ol>
          <h5>Objectives</h5>
          <ul className="compact">
            {Object.entries(c.objectives).map(([id, s]) => (
              <li key={id}>
                <code>{id}</code>: <Badge tone={objectiveLabel(s).tone}>{objectiveLabel(s).text}</Badge>
              </li>
            ))}
          </ul>
          <h5>Legitimate operations</h5>
          <ul className="compact">
            {Object.entries(c.legitimate_operations).map(([id, ok]) => (
              <li key={id}>
                <code>{id}</code>: <Badge tone={ok ? "ok" : "bad"}>{ok ? "Preserved" : "Broken"}</Badge>
              </li>
            ))}
          </ul>
          <p className="small">
            Exposure intervals: {c.exposure_intervals.length ? c.exposure_intervals.join(", ") : "none"}
          </p>
        </>
      )}
    </article>
  );
}
