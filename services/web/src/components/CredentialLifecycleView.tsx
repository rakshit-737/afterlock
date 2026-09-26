import type { AnalysisResult } from "../api/types";
import type { Tone } from "../format";
import { intervalText } from "../format";
import { credentialLifecycles, type LifecycleKind } from "../lifecycle";
import { Badge } from "./Badge";

const KIND: Record<LifecycleKind, { text: string; tone: Tone }> = {
  acquired: { text: "Acquired", tone: "bad" },
  valid: { text: "Valid", tone: "warn" },
  rotated: { text: "Rotated", tone: "ok" },
  revoked: { text: "Revoked", tone: "ok" },
};

export function CredentialLifecycleView({ result }: { result: AnalysisResult }) {
  const creds = credentialLifecycles(result);
  return (
    <section aria-labelledby="h-creds" className="panel">
      <h3 id="h-creds">Credential lifecycle</h3>
      <p className="muted small">
        Per credential, events as stated in the witnesses and the remediation sequence: acquired, checked valid when used,
        rotated, or revoked. Other actions (for example deleting a bound pod) can also end a credential's usability; the
        Timeline and objectives show the effect.
      </p>
      {creds.length === 0 ? <p className="muted">No credentials appear in the witnesses.</p> : null}
      {creds.map((c) => {
        const invalidated = c.events.some((e) => e.kind === "rotated" || e.kind === "revoked");
        return (
          <div key={c.id} className="cred" data-testid={`cred-${c.kind}`}>
            <h4>
              <code>{c.label}</code> <span className="muted small">({c.kind} credential)</span>{" "}
              {invalidated ? null : <Badge tone="warn">No rotation or revocation in the sequence</Badge>}
            </h4>
            <ol className="lifecycle">
              {c.events.map((e, i) => (
                <li key={i}>
                  <Badge tone={KIND[e.kind].tone}>{KIND[e.kind].text}</Badge> {intervalText(e.interval)} · {e.detail}
                  {e.status ? ` · ${e.status}` : ""}
                  {e.evidence?.length ? ` · evidence ${e.evidence.join(", ")}` : ""}
                  <span className="muted small"> (from {e.source})</span>
                </li>
              ))}
            </ol>
          </div>
        );
      })}
    </section>
  );
}
