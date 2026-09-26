// Assemble an inline replay bundle (POST /v1/cases body) from user-selected files.
// Accepted inputs:
//   - a replay bundle directory's files: inventory.json, case.json, events.jsonl
//     (optionally manifest.json, which supplies case_id and cluster_id), or
//   - one JSON file already in the inline shape {case_id, cluster_id, inventory, case, events}.
// Parsing only; all validation of content happens server-side.

import type { InlineBundle } from "./types";

export interface NamedText {
  name: string;
  text: string;
}

export class BundleParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BundleParseError";
  }
}

function parseObject(file: NamedText): Record<string, unknown> {
  let v: unknown;
  try {
    v = JSON.parse(file.text);
  } catch {
    throw new BundleParseError(`${file.name}: not valid JSON`);
  }
  if (!v || typeof v !== "object" || Array.isArray(v)) throw new BundleParseError(`${file.name}: expected a JSON object`);
  return v as Record<string, unknown>;
}

export function parseEvents(file: NamedText): Record<string, unknown>[] {
  const out: Record<string, unknown>[] = [];
  file.text.split(/\r?\n/).forEach((line, i) => {
    if (!line.trim()) return;
    let v: unknown;
    try {
      v = JSON.parse(line);
    } catch {
      throw new BundleParseError(`${file.name} line ${i + 1}: not valid JSON`);
    }
    if (!v || typeof v !== "object" || Array.isArray(v)) {
      throw new BundleParseError(`${file.name} line ${i + 1}: expected a JSON object`);
    }
    out.push(v as Record<string, unknown>);
  });
  return out;
}

const base = (name: string) => name.split(/[\\/]/).pop() ?? name;

export function assembleBundle(files: NamedText[], overrides: { case_id?: string; cluster_id?: string } = {}): InlineBundle {
  const byName = new Map(files.map((f) => [base(f.name), f]));
  let partial: Partial<InlineBundle> = {};

  const inline = files.length === 1 && files[0] && !["inventory.json", "case.json", "manifest.json"].includes(base(files[0].name));
  if (inline && files[0]) {
    const o = parseObject(files[0]);
    partial = o as Partial<InlineBundle>;
  } else {
    const manifest = byName.get("manifest.json");
    if (manifest) {
      const m = parseObject(manifest);
      if (typeof m.case_id === "string") partial.case_id = m.case_id;
      if (typeof m.cluster_id === "string") partial.cluster_id = m.cluster_id;
    }
    const inv = byName.get("inventory.json");
    const cs = byName.get("case.json");
    if (!inv) throw new BundleParseError("inventory.json is required");
    if (!cs) throw new BundleParseError("case.json is required");
    partial.inventory = parseObject(inv);
    partial.case = parseObject(cs);
    const ev = byName.get("events.jsonl");
    partial.events = ev ? parseEvents(ev) : [];
  }

  const case_id = overrides.case_id?.trim() || partial.case_id;
  const cluster_id = overrides.cluster_id?.trim() || partial.cluster_id;
  if (!case_id) throw new BundleParseError("case_id is required (enter it or include manifest.json)");
  if (!cluster_id) throw new BundleParseError("cluster_id is required (enter it or include manifest.json)");
  if (!partial.inventory || typeof partial.inventory !== "object") throw new BundleParseError("inventory is missing");
  if (!partial.case || typeof partial.case !== "object") throw new BundleParseError("case is missing");
  if (partial.events !== undefined && !Array.isArray(partial.events)) throw new BundleParseError("events must be a list");

  return { case_id, cluster_id, inventory: partial.inventory, case: partial.case, events: partial.events ?? [] };
}
