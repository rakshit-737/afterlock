// Pure presentation helpers. Every label is text; color is never the only signal.

import type { Fact } from "./api/types";

export type Tone = "bad" | "warn" | "unknown" | "ok" | "neutral";

interface Label {
  text: string;
  tone: Tone;
  /** One-sentence meaning, shown next to the label. */
  meaning: string;
}

const OBJECTIVE: Record<string, Label> = {
  violated: { text: "Violated", tone: "bad", meaning: "An evidence-supported attack path reaches this objective." },
  possibly_violated: {
    text: "Possibly violated",
    tone: "warn",
    meaning: "Only the conservative (possible) view reaches it; evidence does not establish the path.",
  },
  unknown: { text: "Unknown", tone: "unknown", meaning: "Containment cannot be established; see reasons and coverage." },
  satisfied_within_scope: {
    text: "Satisfied within scope",
    tone: "ok",
    meaning: "No supported attack continuation was found within the stated scope and assumptions.",
  },
};

const CONCLUSION: Record<string, Label> = {
  residual_path: { text: "Residual path", tone: "bad", meaning: "Containment fails in the modeled state." },
  contained_within_scope: {
    text: "Contained within scope",
    tone: "ok",
    meaning: "No supported attack continuation found within scope. This is not a proof of safety.",
  },
  unknown: { text: "Unknown", tone: "unknown", meaning: "Containment cannot be established." },
  invalid_input: { text: "Invalid input", tone: "unknown", meaning: "The input could not be analyzed." },
};

const VALIDATION: Record<string, Label> = {
  not_executed: {
    text: "Model-level only",
    tone: "neutral",
    meaning: "No lab validation was executed. The conclusion is a model result, not an observed outcome.",
  },
  lab_confirmed: { text: "Lab confirmed", tone: "ok", meaning: "An isolated lab run confirmed the model result." },
  lab_contradicted: { text: "Lab contradicted", tone: "bad", meaning: "An isolated lab run contradicted the model result." },
  validation_inconclusive: { text: "Validation inconclusive", tone: "unknown", meaning: "A lab run did not settle the question." },
};

function lookup(table: Record<string, Label>, value: string): Label {
  return table[value] ?? { text: value, tone: "unknown", meaning: "Unrecognized status reported by the API." };
}

export const objectiveLabel = (s: string) => lookup(OBJECTIVE, s);
export const conclusionLabel = (s: string) => lookup(CONCLUSION, s);
export const validationLabel = (s: string) => lookup(VALIDATION, s);

/** Readable fact text, e.g. `can_read_secret demo/release-credential`. */
export function factText(fact: Fact | unknown): string {
  if (!Array.isArray(fact) || fact.length === 0) return String(fact);
  const [pred, ...args] = fact;
  const shown = args.filter((a) => a !== null && a !== undefined).map(String);
  if (shown.length === 2 && /secret/.test(String(pred))) return `${String(pred)} ${shown[0]}/${shown[1]}`;
  return [String(pred), ...shown].join(" ");
}

/** Epoch seconds to an ISO-8601 UTC string. */
export function isoTime(epochSeconds: number): string {
  if (!Number.isFinite(epochSeconds)) return String(epochSeconds);
  return new Date(epochSeconds * 1000).toISOString().replace(".000Z", "Z");
}

export function intervalText(interval: number): string {
  if (interval < 0) return "before analysis (evidence)";
  if (interval === 0) return "before remediation";
  return `after remediation step ${interval}`;
}

/** Compact one-line rendering of a remediation action. */
export function actionText(action: Record<string, unknown>): string {
  const { kind, ...rest } = action;
  const args = Object.entries(rest)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}=${Array.isArray(v) ? `[${v.join(", ")}]` : String(v)}`);
  return `${String(kind)}(${args.join(", ")})`;
}
