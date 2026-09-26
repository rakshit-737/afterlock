import type { AnalysisResult, CoverageGap, Witness, WitnessStep } from "../api/types";
import { actionText, conclusionLabel, factText, intervalText, isoTime, objectiveLabel, validationLabel } from "../format";
import { Badge } from "./Badge";

export function ResultView({ analysisId, result }: { analysisId: string; result: AnalysisResult }) {
  return (
    <div className="result">
      <Conclusion analysisId={analysisId} result={result} />
      <Objectives result={result} />
      <LegitimateOperations result={result} />
      <Witnesses witnesses={result.witnesses} />
      <Timeline result={result} />
      <Coverage gaps={result.missing_coverage} bounds={result.analysis_bounds} />
      <Scope result={result} />
    </div>
  );
}

function Conclusion({ analysisId, result }: { analysisId: string; result: AnalysisResult }) {
  const model = conclusionLabel(result.conclusion.model);
  const validation = validationLabel(result.conclusion.validation);
  return (
    <section aria-labelledby="h-conclusion" className="panel">
      <h3 id="h-conclusion">Conclusion</h3>
      <dl className="kv">
        <dt>Model conclusion</dt>
        <dd>
          <Badge tone={model.tone}>{model.text}</Badge> <span className="muted">{model.meaning}</span>
        </dd>
        <dt>Validation</dt>
        <dd data-testid="validation">
          <Badge tone={validation.tone}>{validation.text}</Badge> <span className="muted">{validation.meaning}</span>
        </dd>
        <dt>Scope</dt>
        <dd>{result.conclusion.scope}</dd>
        <dt>Analysis</dt>
        <dd>
          <code>{analysisId}</code> · case <code>{result.case_id}</code> · mode <code>{result.engine.mode}</code> · profile{" "}
          <code>{result.semantic_profile.id}</code> · analysis time {isoTime(result.analysis_time)}
        </dd>
        <dt>Remediation sequence</dt>
        <dd>
          {result.remediation.length === 0 ? (
            <span className="muted">none</span>
          ) : (
            <ol className="compact">
              {result.remediation.map((a, i) => (
                <li key={i}>
                  <code>{actionText(a)}</code>
                </li>
              ))}
            </ol>
          )}
        </dd>
        <dt>Digests</dt>
        <dd className="mono small">
          input {result.input_digest}
          <br />
          result {result.result_digest}
        </dd>
      </dl>
      {result.note ? <p className="muted small">{result.note}</p> : null}
    </section>
  );
}

function Objectives({ result }: { result: AnalysisResult }) {
  return (
    <section aria-labelledby="h-objectives" className="panel">
      <h3 id="h-objectives">Protected objectives</h3>
      <table>
        <caption className="visually-hidden">Objective status after the remediation sequence</caption>
        <thead>
          <tr>
            <th scope="col">Objective</th>
            <th scope="col">Status</th>
            <th scope="col">Basis</th>
            <th scope="col">Witness / reasons</th>
          </tr>
        </thead>
        <tbody>
          {result.objectives.map((o) => {
            const l = objectiveLabel(o.status);
            return (
              <tr key={o.id} data-testid={`objective-${o.id}`}>
                <td>
                  <code>{o.id}</code>
                  {o.description ? <div>{o.description}</div> : null}
                </td>
                <td>
                  <Badge tone={l.tone}>{l.text}</Badge>
                  <div className="muted small">{l.meaning}</div>
                </td>
                <td>{o.basis ?? <span className="muted">none</span>}</td>
                <td>
                  {o.witness ? <a href={`#${o.witness}`}>{o.witness}</a> : null}
                  {o.reasons?.length ? (
                    <ul className="compact">
                      {o.reasons.map((r, i) => (
                        <li key={i}>{r}</li>
                      ))}
                    </ul>
                  ) : null}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </section>
  );
}

function LegitimateOperations({ result }: { result: AnalysisResult }) {
  return (
    <section aria-labelledby="h-legit" className="panel">
      <h3 id="h-legit">Legitimate operations after remediation</h3>
      {result.legitimate_operations.length === 0 ? (
        <p className="muted">No legitimate operations declared in the case.</p>
      ) : (
        <ul className="plain">
          {result.legitimate_operations.map((op) => (
            <li key={op.id} data-testid={`legit-${op.id}`}>
              <Badge tone={op.preserved ? "ok" : "bad"}>{op.preserved ? "Preserved" : "Broken"}</Badge> <code>{op.id}</code>{" "}
              {op.description ? <span>{op.description}</span> : null}
              {op.detail ? <div className="muted small">{op.detail}</div> : null}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function Witnesses({ witnesses }: { witnesses: Witness[] }) {
  return (
    <section aria-labelledby="h-witnesses" className="panel">
      <h3 id="h-witnesses">Witnesses</h3>
      <p className="muted small">
        Each step is labeled <strong>observed</strong> (from evidence), <strong>assumed</strong> (declared), or{" "}
        <strong>inferred</strong> (derived by a named rule).
      </p>
      {witnesses.length === 0 ? <p className="muted">No witnesses: no objective was reached.</p> : null}
      {witnesses.map((w) => (
        <details key={w.id} id={w.id} className="witness" open>
          <summary>
            <code>{w.id}</code> for objective <code>{w.objective}</code>, view <code>{w.view}</code>: reaches{" "}
            <code>{factText(w.goal)}</code>
          </summary>
          <ol className="steps">
            {w.steps.map((s, i) => (
              <Step key={i} step={s} />
            ))}
          </ol>
        </details>
      ))}
    </section>
  );
}

function Step({ step }: { step: WitnessStep }) {
  return (
    <li className={`step step-${step.status}`}>
      <div>
        <span className="step-status">[{step.status}]</span> <code>{factText(step.fact)}</code>
      </div>
      <div className="muted small">
        rule <code>{step.rule}</code> · {intervalText(step.interval)}
        {step.evidence?.length ? <> · evidence {step.evidence.join(", ")}</> : null}
      </div>
      {step.conditions?.length ? (
        <ul className="compact small">
          {step.conditions.map((c, i) => (
            <li key={i}>
              {c.check}
              {c.detail ? `: ${c.detail}` : ""}
              {Array.isArray(c.via) && c.via.length ? ` via ${(c.via as unknown[]).map(String).join(", ")}` : ""}
            </li>
          ))}
        </ul>
      ) : null}
    </li>
  );
}

function Timeline({ result }: { result: AnalysisResult }) {
  const exposed = new Set(result.exposure_during_containment.map((e) => e.interval));
  return (
    <section aria-labelledby="h-timeline" className="panel">
      <h3 id="h-timeline">Timeline</h3>
      <p className="muted small">Model intervals between defender actions and the attacker capabilities that hold in each.</p>
      <ol className="timeline">
        {result.timeline.map((t) => (
          <li key={t.interval} data-testid={`interval-${t.interval}`}>
            <div>
              <strong>Interval {t.interval}</strong> · {isoTime(t.time)} ·{" "}
              {t.defender_action ? (
                <>
                  after <code>{t.defender_action}</code>
                </>
              ) : (
                "before remediation"
              )}
              {exposed.has(t.interval) ? (
                <>
                  {" "}
                  <Badge tone="warn">Exposure during containment</Badge>
                </>
              ) : null}
            </div>
            {t.attacker_capabilities.length ? (
              <ul className="compact">
                {t.attacker_capabilities.map((c, i) => (
                  <li key={i}>
                    attacker capability: <code>{factText(c)}</code>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="muted small">No modeled attacker capability in this interval.</p>
            )}
            {t.notes.length ? (
              <ul className="compact muted small">
                {t.notes.map((n, i) => (
                  <li key={i}>{n}</li>
                ))}
              </ul>
            ) : null}
          </li>
        ))}
      </ol>
    </section>
  );
}

export function Coverage({ gaps, bounds }: { gaps: CoverageGap[]; bounds?: Record<string, unknown> & { exhausted?: boolean } }) {
  return (
    <section aria-labelledby="h-coverage" className="panel">
      <h3 id="h-coverage">Coverage gaps and missing coverage</h3>
      {gaps.length === 0 ? (
        <p className="muted">No coverage gaps reported by the engine. This does not prove completeness.</p>
      ) : (
        <ul className="plain">
          {gaps.map((g, i) => (
            <li key={g.id ?? i}>
              <Badge tone="unknown">{g.kind}</Badge> {g.detail ?? g.description ?? ""}
              {g.view ? <span className="muted small"> (view {g.view})</span> : null}
            </li>
          ))}
        </ul>
      )}
      {bounds ? (
        <p className="small">
          Search bounds: {bounds.exhausted ? "explored to fixpoint" : "NOT exhausted: a cap was reached, so absence of a path is not established"}.
        </p>
      ) : null}
    </section>
  );
}

function Scope({ result }: { result: AnalysisResult }) {
  return (
    <section aria-labelledby="h-scope" className="panel">
      <h3 id="h-scope">Assumptions and limitations</h3>
      <h4>Assumptions</h4>
      <ul className="compact">
        {result.assumptions.map((a, i) => (
          <li key={i}>{a}</li>
        ))}
      </ul>
      <h4>Limitations</h4>
      <ul className="compact">
        {result.limitations.map((a, i) => (
          <li key={i}>{a}</li>
        ))}
      </ul>
    </section>
  );
}
