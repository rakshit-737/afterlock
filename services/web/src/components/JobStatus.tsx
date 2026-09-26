import type { JobRecord } from "../api/types";
import type { Tone } from "../format";
import { Badge } from "./Badge";

const TONE: Record<string, Tone> = {
  queued: "neutral",
  leased: "neutral",
  running: "warn",
  succeeded: "ok",
  failed: "bad",
  cancelled: "unknown",
};

const TERMINAL = ["succeeded", "failed", "cancelled"];

/** Current state of the background job, with a cancel button while it is not terminal. */
export function JobStatus({
  label,
  job,
  onCancel,
  cancelling,
}: {
  label: string;
  job: JobRecord;
  onCancel: () => void;
  cancelling: boolean;
}) {
  const terminal = TERMINAL.includes(job.state);
  return (
    <section aria-labelledby="h-job" className="panel">
      <h3 id="h-job">Background job: {label}</h3>
      <div className="job">
        <span>
          Job <code>{job.job_id}</code>
        </span>
        <span data-testid="job-state">
          <Badge tone={TONE[job.state] ?? "unknown"}>{job.state}</Badge>
        </span>
        <span className="small">
          attempt {job.attempts} of {job.max_attempts}
        </span>
        {job.cancel_requested && !terminal ? <span className="small">cancellation requested</span> : null}
        {!terminal ? (
          <button type="button" onClick={onCancel} disabled={cancelling || job.cancel_requested}>
            Cancel job
          </button>
        ) : null}
      </div>
      {job.last_error ? <p className="small">Last error: {job.last_error}</p> : null}
      {job.state === "cancelled" ? <p className="small">Cancelled jobs never publish a result.</p> : null}
    </section>
  );
}
