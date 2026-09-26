import { describe, expect, it } from "vitest";
import { assembleBundle, BundleParseError, parseEvents } from "./bundle";

const manifest = { name: "manifest.json", text: JSON.stringify({ case_id: "residual-token", cluster_id: "lab-local" }) };
const inv = { name: "inventory.json", text: '{"objects": []}' };
const cs = { name: "case.json", text: '{"objectives": []}' };
const ev = { name: "events.jsonl", text: '{"event_id":"a"}\r\n\r\n{"event_id":"b"}\n' };

describe("assembleBundle", () => {
  it("builds an inline bundle from bundle-directory files, tolerating CRLF", () => {
    const b = assembleBundle([manifest, inv, cs, ev]);
    expect(b).toEqual({
      case_id: "residual-token",
      cluster_id: "lab-local",
      inventory: { objects: [] },
      case: { objectives: [] },
      events: [{ event_id: "a" }, { event_id: "b" }],
    });
  });

  it("lets typed ids override the manifest", () => {
    const b = assembleBundle([manifest, inv, cs], { case_id: "other", cluster_id: " c2 " });
    expect(b.case_id).toBe("other");
    expect(b.cluster_id).toBe("c2");
    expect(b.events).toEqual([]);
  });

  it("accepts a single inline JSON file", () => {
    const one = { name: "bundle.json", text: JSON.stringify({ case_id: "x", cluster_id: "y", inventory: {}, case: {}, events: [] }) };
    expect(assembleBundle([one]).case_id).toBe("x");
  });

  it("requires ids, inventory and case", () => {
    expect(() => assembleBundle([inv, cs])).toThrow(/case_id is required/);
    expect(() => assembleBundle([manifest, cs])).toThrow(/inventory.json is required/);
    expect(() => assembleBundle([manifest, inv])).toThrow(/case.json is required/);
  });

  it("reports the failing events line", () => {
    expect(() => parseEvents({ name: "events.jsonl", text: '{"a":1}\nnot json' })).toThrow("events.jsonl line 2: not valid JSON");
    expect(() => parseEvents({ name: "events.jsonl", text: "[1]" })).toThrow(BundleParseError);
  });
});
