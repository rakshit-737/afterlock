// Credential lifecycle: a presentational regrouping of what the result already
// states, per credential. It adds no reasoning: every event cites the witness
// step, condition, or remediation action it was read from.
//
//   acquired - a witness step whose fact is possession/knowledge of the credential
//   valid    - a condition that checked the credential (credential_usable,
//              service_accepts, secret_version) in a step that used it
//   rotated  - a rotate_downstream_credential action for the credential's service
//   revoked  - a delete_service_account action for the credential's service account

import type { AnalysisResult, Fact, WitnessCondition } from "./api/types";
import { actionText } from "./format";

export type LifecycleKind = "acquired" | "valid" | "rotated" | "revoked";

export interface LifecycleEvent {
  kind: LifecycleKind;
  /** Model interval (-2/-1 evidence, 0 before remediation, n after step n). */
  interval: number;
  detail: string;
  source: string;
  status?: string;
  evidence?: string[];
}

export interface CredentialLifecycle {
  id: string;
  kind: "kubernetes" | "secret" | "downstream";
  label: string;
  events: LifecycleEvent[];
}

/** The condition that checks each credential kind's validity when it is used. */
const VALIDITY_CHECK: Record<CredentialLifecycle["kind"], string> = {
  kubernetes: "credential_usable",
  downstream: "service_accepts",
  secret: "secret_version",
};

const str = (v: unknown) => (v === null || v === undefined ? "" : String(v));

function credentialOf(fact: Fact): { id: string; kind: CredentialLifecycle["kind"]; label: string } | null {
  const [pred, ...a] = fact;
  if (pred === "possesses" && a[0] != null) return { id: `k8s:${str(a[0])}`, kind: "kubernetes", label: str(a[0]) };
  if (pred === "knows_secret" && a.length >= 2)
    return { id: `secret:${str(a[0])}/${str(a[1])}@${str(a[2])}`, kind: "secret", label: `secret ${str(a[0])}/${str(a[1])} v${str(a[2])}` };
  if (pred === "possesses_downstream" && a[0] != null)
    return { id: `downstream:${str(a[0])}@${str(a[1])}`, kind: "downstream", label: `${str(a[0])} credential v${str(a[1])}` };
  return null;
}

function conditionText(c: WitnessCondition): string {
  const rest = Object.entries(c)
    .filter(([k]) => k !== "check" && k !== "detail")
    .map(([k, v]) => `${k}=${Array.isArray(v) ? v.join("|") : str(v)}`)
    .join(", ");
  return `${c.check}${rest ? ` (${rest})` : ""}${c.detail ? `: ${c.detail}` : ""}`;
}

export function credentialLifecycles(result: AnalysisResult): CredentialLifecycle[] {
  const creds = new Map<string, CredentialLifecycle & { service?: string; usernames: Set<string> }>();
  const get = (f: Fact) => {
    const c = credentialOf(f);
    if (!c) return null;
    if (!creds.has(c.id)) {
      const service = c.kind === "downstream" ? str(f[1]) : undefined;
      creds.set(c.id, { ...c, events: [], usernames: new Set(), ...(service ? { service } : {}) });
    }
    return creds.get(c.id)!;
  };
  const seen = new Set<string>();
  const push = (cred: CredentialLifecycle, e: LifecycleEvent) => {
    const k = `${cred.id}|${e.kind}|${e.interval}|${e.detail}`;
    if (!seen.has(k)) {
      seen.add(k);
      cred.events.push(e);
    }
  };

  for (const w of result.witnesses) {
    w.steps.forEach((s, i) => {
      const own = get(s.fact);
      if (own) {
        const e: LifecycleEvent = {
          kind: "acquired",
          interval: s.interval,
          detail: `rule ${s.rule}`,
          source: `${w.id} step ${i + 1}`,
          status: s.status,
        };
        if (s.evidence?.length) e.evidence = s.evidence;
        push(own, e);
      }
      for (const p of s.premises ?? []) {
        const cred = get(p);
        if (!cred) continue;
        for (const c of s.conditions ?? []) {
          if (VALIDITY_CHECK[cred.kind] === c.check) {
            push(cred, { kind: "valid", interval: s.interval, detail: conditionText(c), source: `${w.id} step ${i + 1} (${s.rule})` });
          }
          if (c.check === "authorized" && typeof c.username === "string") {
            (cred as { usernames: Set<string> }).usernames.add(c.username);
          }
        }
      }
    });
  }

  result.remediation.forEach((a, i) => {
    const interval = i + 1;
    for (const cred of creds.values()) {
      if (a.kind === "rotate_downstream_credential" && cred.service && a.service === cred.service) {
        push(cred, { kind: "rotated", interval, detail: actionText(a), source: `remediation step ${interval}` });
      }
      if (a.kind === "delete_service_account") {
        const user = `system:serviceaccount:${str(a.namespace)}:${str(a.name)}`;
        if (cred.usernames.has(user)) {
          push(cred, { kind: "revoked", interval, detail: actionText(a), source: `remediation step ${interval}` });
        }
      }
    }
  });

  const order: Record<LifecycleKind, number> = { acquired: 0, valid: 1, rotated: 2, revoked: 3 };
  return [...creds.values()].map(({ id, kind, label, events }) => ({
    id,
    kind,
    label,
    events: [...events].sort((a, b) => a.interval - b.interval || order[a.kind] - order[b.kind]),
  }));
}
