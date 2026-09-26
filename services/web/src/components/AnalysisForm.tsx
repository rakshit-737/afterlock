import { useState } from "react";
import { ANALYSIS_MODES, type AnalysisMode, type AnalysisRequest, type RemediationAction } from "../api/types";
import { ErrorNote } from "./Badge";

const MODE_HELP: Record<AnalysisMode, string> = {
  full: "full: temporal analysis with credential lifecycle (default)",
  snapshot_only: "snapshot_only: baseline, evaluation only",
  history_without_lifecycle: "history_without_lifecycle: baseline, evaluation only",
  final_state_only: "final_state_only: baseline, evaluation only",
};

/** Parse the remediation textarea; empty means "use the case's own remediation". */
export function parseRemediation(text: string): RemediationAction[] | undefined {
  if (!text.trim()) return undefined;
  let v: unknown;
  try {
    v = JSON.parse(text);
  } catch {
    throw new Error("Remediation must be valid JSON.");
  }
  if (!Array.isArray(v) || !v.every((a) => a && typeof a === "object" && typeof (a as { kind?: unknown }).kind === "string")) {
    throw new Error('Remediation must be a JSON list of actions, each with a "kind".');
  }
  return v as RemediationAction[];
}

export function AnalysisForm({ busy, onRun }: { busy: boolean; onRun: (req: AnalysisRequest) => Promise<void> }) {
  const [mode, setMode] = useState<AnalysisMode>("full");
  const [remediation, setRemediation] = useState("");
  const [error, setError] = useState<string | null>(null);

  return (
    <form
      className="panel"
      aria-labelledby="h-run"
      onSubmit={(e) => {
        e.preventDefault();
        setError(null);
        let parsed: RemediationAction[] | undefined;
        try {
          parsed = parseRemediation(remediation);
        } catch (err) {
          setError(err instanceof Error ? err.message : String(err));
          return;
        }
        const req: AnalysisRequest = { mode };
        if (parsed) req.remediation = parsed;
        void onRun(req);
      }}
    >
      <h3 id="h-run">Run analysis</h3>
      <label htmlFor="mode">Mode</label>
      <select id="mode" value={mode} onChange={(e) => setMode(e.target.value as AnalysisMode)}>
        {ANALYSIS_MODES.map((m) => (
          <option key={m} value={m}>
            {MODE_HELP[m]}
          </option>
        ))}
      </select>
      <label htmlFor="remediation">Remediation sequence (JSON list, optional)</label>
      <textarea
        id="remediation"
        rows={5}
        spellCheck={false}
        value={remediation}
        onChange={(e) => setRemediation(e.target.value)}
        aria-describedby="remediation-help"
        placeholder='[{"kind": "remove_binding", "namespace": "demo", "name": "ci-pod-creator"}]'
      />
      <p id="remediation-help" className="muted small">
        Leave empty to analyze the remediation declared in the case. At most 32 actions.
      </p>
      <button type="submit" disabled={busy}>
        Analyze
      </button>
      <ErrorNote error={error} />
    </form>
  );
}
