// Types for the AFTERLOCK v1 HTTP API (docs/api/api.md) and the public result
// schemas `afterlock.result/1` and `afterlock.plan/1`. Hand-written from the API
// source and real engine output; fields the UI does not use are typed loosely.
// Unknown enum values are tolerated (`| string`) so a newer engine never crashes the UI.

export type ModelConclusion = "residual_path" | "contained_within_scope" | "unknown" | "invalid_input";
export type ValidationStatus = "not_executed" | "lab_confirmed" | "lab_contradicted" | "validation_inconclusive";
export type ObjectiveStatus = "violated" | "possibly_violated" | "unknown" | "satisfied_within_scope";
export type AnalysisMode = "full" | "snapshot_only" | "history_without_lifecycle" | "final_state_only";

export const ANALYSIS_MODES: readonly AnalysisMode[] = [
  "full",
  "snapshot_only",
  "history_without_lifecycle",
  "final_state_only",
];

/** A fact tuple such as ["can_read_secret", "demo", "release-credential"]. */
export type Fact = (string | number | null)[];

export interface Health {
  status: string;
  version: string;
  storage: string;
}

export interface CoverageGap {
  id?: string;
  kind: string;
  description?: string;
  detail?: string;
  view?: string;
  evidence?: string[];
}

export interface InlineBundle {
  case_id: string;
  cluster_id: string;
  inventory: Record<string, unknown>;
  case: Record<string, unknown>;
  events: Record<string, unknown>[];
}

export interface CaseCreated {
  case_id: string;
  diagnostics: Record<string, unknown>;
  coverage_gaps: CoverageGap[];
}

export interface CaseList {
  items: string[];
  total: number;
}

export interface CaseDetail {
  case_id: string;
  cluster_id: string;
  input: Record<string, unknown>;
  diagnostics: Record<string, unknown>;
}

export type RemediationAction = Record<string, unknown> & { kind: string };

export interface AnalysisRequest {
  remediation?: RemediationAction[];
  mode?: AnalysisMode;
}

export interface Objective {
  id: string;
  kind: string;
  target?: unknown;
  description?: string;
  status: ObjectiveStatus | string;
  basis?: string | null;
  witness?: string;
  reasons?: string[];
}

export interface WitnessCondition {
  check: string;
  detail?: string;
  [key: string]: unknown;
}

export interface WitnessStep {
  fact: Fact;
  rule: string;
  interval: number;
  premises?: Fact[];
  conditions?: WitnessCondition[];
  status: string;
  evidence?: string[];
}

export interface Witness {
  id: string;
  objective: string;
  view: string;
  goal: Fact;
  steps: WitnessStep[];
}

export interface TimelineEntry {
  interval: number;
  time: number;
  defender_action: string | null;
  notes: string[];
  reconciled_pods: unknown[];
  attacker_capabilities: Fact[];
}

export interface ExposureEntry {
  interval: number;
  after_action: string | null;
  time: number;
  attacker_capabilities: Fact[];
}

export interface LegitimateOperation {
  id: string;
  kind: string;
  preserved: boolean;
  detail?: string;
  description?: string;
}

export interface AnalysisResult {
  schema: string;
  engine: { name: string; version: string; mode: string };
  case_id: string;
  cluster_id: string;
  input_digest: string;
  semantic_profile: { id: string; kubernetes_version?: string };
  analysis_time: number;
  remediation: RemediationAction[];
  conclusion: { model: ModelConclusion | string; validation: ValidationStatus | string; scope: string };
  objectives: Objective[];
  witnesses: Witness[];
  exposure_during_containment: ExposureEntry[];
  legitimate_operations: LegitimateOperation[];
  timeline: TimelineEntry[];
  assumptions: string[];
  evidence_references: string[];
  missing_coverage: CoverageGap[];
  analysis_bounds: Record<string, unknown> & { exhausted?: boolean };
  limitations: string[];
  note?: string;
  result_digest: string;
}

export interface AnalysisCreated {
  id: string;
  result: AnalysisResult;
}

export interface AnalysisRecord {
  id: string;
  case_id: string;
  result: AnalysisResult;
}

export interface ReferenceView {
  reachable_objectives: string[];
  states: number;
  complete: boolean;
  unknown: unknown[];
}

export interface VerificationResult {
  witnesses: Record<string, { valid: boolean; problems: string[] }>;
  reference_exploration: { views: Record<string, ReferenceView>; [key: string]: unknown };
}

export interface PlanRequest {
  max_length?: number;
  max_evaluations?: number;
}

export interface PlanCandidate {
  actions: RemediationAction[];
  cost: number;
  model_conclusion: string;
  objectives: Record<string, string>;
  legitimate_operations: Record<string, boolean>;
  exposure_intervals: number[];
  result_digest?: string;
}

export interface PlanResult {
  schema: string;
  case_id: string;
  input_digest: string;
  search: {
    status: string;
    statement: string;
    algorithm?: string;
    max_length?: number;
    max_evaluations?: number;
    evaluations?: number;
    [key: string]: unknown;
  };
  best_plan: PlanCandidate | null;
  cheapest_security_only_plan: PlanCandidate | null;
  proposed_remediation: PlanCandidate | null;
  naive_containment: PlanCandidate | null;
  [key: string]: unknown;
}

// ---- asynchronous jobs (docs/api/api.md, "Asynchronous jobs") ----------------

export type JobState = "queued" | "leased" | "running" | "succeeded" | "failed" | "cancelled";
export type JobKind = "analysis" | "plan" | "verification";
export const TERMINAL_JOB_STATES: readonly string[] = ["succeeded", "failed", "cancelled"];

/** `GET /v1/jobs/{id}` and `POST /v1/jobs/{id}/cancel`. */
export interface JobRecord {
  job_id: string;
  cluster_id: string;
  manifest_id: string;
  kind: JobKind | string;
  state: JobState | string;
  attempts: number;
  max_attempts: number;
  cancel_requested: boolean;
  last_error: string | null;
  result_id: string | null;
  result?: unknown;
}

export interface JobOptions {
  /** 1–10; the API defaults to 3. */
  max_attempts?: number;
}
