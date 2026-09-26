import { useState } from "react";
import { assembleBundle, type NamedText } from "../api/bundle";
import type { InlineBundle } from "../api/types";
import { ErrorNote } from "./Badge";

/** Select replay-bundle files and create a case (POST /v1/cases). */
export function CaseUpload({ onSubmit, busy }: { onSubmit: (b: InlineBundle) => Promise<void>; busy: boolean }) {
  const [files, setFiles] = useState<NamedText[]>([]);
  const [caseId, setCaseId] = useState("");
  const [clusterId, setClusterId] = useState("");
  const [error, setError] = useState<string | null>(null);

  async function pick(list: FileList | null) {
    setError(null);
    if (!list) return;
    const read = await Promise.all(Array.from(list).map(async (f) => ({ name: f.name, text: await f.text() })));
    setFiles(read);
  }

  async function submit() {
    setError(null);
    let bundle: InlineBundle;
    try {
      bundle = assembleBundle(files, { case_id: caseId, cluster_id: clusterId });
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      return;
    }
    await onSubmit(bundle);
  }

  return (
    <form
      className="panel"
      aria-labelledby="h-upload"
      onSubmit={(e) => {
        e.preventDefault();
        void submit();
      }}
    >
      <h2 id="h-upload">Create a case from a replay bundle</h2>
      <label htmlFor="bundle-files">Bundle files</label>
      <input
        id="bundle-files"
        type="file"
        multiple
        accept=".json,.jsonl,application/json"
        onChange={(e) => void pick(e.target.files)}
        aria-describedby="bundle-help"
      />
      <p id="bundle-help" className="muted small">
        Select <code>inventory.json</code>, <code>case.json</code>, <code>events.jsonl</code> and optionally{" "}
        <code>manifest.json</code> from a replay bundle directory, or one JSON file in the inline API shape.
      </p>
      {files.length ? <p className="small">Selected: {files.map((f) => f.name).join(", ")}</p> : null}
      <div className="row">
        <div>
          <label htmlFor="case-id">Case ID (overrides manifest)</label>
          <input id="case-id" value={caseId} onChange={(e) => setCaseId(e.target.value)} autoComplete="off" />
        </div>
        <div>
          <label htmlFor="cluster-id">Cluster ID (overrides manifest)</label>
          <input id="cluster-id" value={clusterId} onChange={(e) => setClusterId(e.target.value)} autoComplete="off" />
        </div>
      </div>
      <button type="submit" disabled={busy || files.length === 0}>
        Create case
      </button>
      <ErrorNote error={error} />
    </form>
  );
}
