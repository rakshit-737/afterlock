import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";
import { E2E_TOKEN } from "../playwright.config";

const BUNDLE = "../../datasets/replay/residual-token";
const FILES = ["inventory.json", "case.json", "events.jsonl", "manifest.json"].map((f) => `${BUNDLE}/${f}`);

// A targeted containment: cut the pod's secret-read binding and rotate the copied
// downstream credential (the engine's cheapest security-only plan for this case).
const TARGETED = JSON.stringify([
  { kind: "remove_binding", namespace: "demo", name: "release-reader-secret" },
  { kind: "rotate_downstream_credential", service: "canary-service" },
]);

let seq = 0;
const uniqueCase = (tag: string) => `e2e-${tag}-${Date.now().toString(36)}-${seq++}`;

async function enterToken(page: Page) {
  await page.goto("/");
  await page.getByLabel("API bearer token").fill(E2E_TOKEN);
  await page.getByRole("button", { name: "Use token" }).click();
  await expect(page.getByRole("button", { name: "Forget token" })).toBeVisible();
}

async function uploadCase(page: Page, caseId: string) {
  await page.getByLabel("Bundle files").setInputFiles(FILES);
  await page.getByLabel("Case ID (overrides manifest)").fill(caseId);
  await page.getByRole("button", { name: "Create case" }).click();
  await expect(page.getByRole("heading", { name: new RegExp(`Case ${caseId}`) })).toBeVisible();
}

const conclusion = (page: Page) => page.getByRole("region", { name: "Conclusion", exact: true });

test("upload residual-token bundle, analyze: residual path with provenance, evidence and credential lifecycle", async ({ page }) => {
  await enterToken(page);
  await uploadCase(page, uniqueCase("residual"));
  await page.getByRole("button", { name: "Analyze" }).click();
  await expect(conclusion(page)).toContainText("Residual path");
  await expect(conclusion(page)).toContainText("Model-level only");

  const graph = page.getByRole("group", { name: /Provenance graph for w-protect-canary/ });
  await expect(graph).toBeVisible();
  await graph.getByRole("button", { name: /Fact knows_secret demo release-credential 1, observed/ }).click();
  const drawer = page.getByRole("complementary", { name: /Evidence for w-protect-canary step 1/ });
  await expect(drawer.getByTestId("drawer-evidence")).toContainText("lab-audit#2");
  await page.keyboard.press("Escape");
  await expect(drawer).toBeHidden();

  await expect(page.getByTestId("cred-kubernetes")).toContainText("No rotation or revocation in the sequence");
});

test("targeted containment remediation is contained within scope", async ({ page }) => {
  await enterToken(page);
  await uploadCase(page, uniqueCase("contained"));
  await page.getByLabel("Remediation sequence (JSON list, optional)").fill(TARGETED);
  await page.getByRole("button", { name: "Analyze" }).click();
  await expect(conclusion(page)).toContainText("Contained within scope");
  await expect(page.getByTestId("objective-protect-secret")).toContainText("Satisfied within scope");
  await expect(page.getByTestId("objective-protect-canary")).toContainText("Satisfied within scope");
});

test("async job path: analysis runs as a background job and shows its state", async ({ page }) => {
  await enterToken(page);
  await uploadCase(page, uniqueCase("job"));
  await page.getByLabel("Run as background jobs").check();
  await page.getByRole("button", { name: "Analyze" }).click();
  await expect(page.getByTestId("job-state")).toHaveText("succeeded", { timeout: 45_000 });
  await expect(conclusion(page)).toContainText("Residual path");
  // Small bounds keep the plan job quick; the bound is reported, never read as containment.
  await page.getByLabel("Max actions (1–5)").fill("1");
  await page.getByLabel("Max evaluations (1–10000)").fill("20");
  await page.getByRole("button", { name: "Search plans" }).click();
  await expect(page.getByTestId("job-state")).toHaveText("succeeded", { timeout: 45_000 });
  await expect(page.getByText(/search: /).first()).toBeVisible();
});

test("the token never reaches web storage, cookies, the URL, or the DOM", async ({ page, context }) => {
  await enterToken(page);
  await uploadCase(page, uniqueCase("token"));
  await page.getByRole("button", { name: "Analyze" }).click();
  await expect(conclusion(page)).toContainText("Residual path");
  const leaks = await page.evaluate((t) => {
    const storages = [window.localStorage, window.sessionStorage];
    const inStorage = storages.some((s) => {
      for (let i = 0; i < s.length; i++) {
        const k = s.key(i) ?? "";
        if (k.includes(t) || (s.getItem(k) ?? "").includes(t)) return true;
      }
      return false;
    });
    const inputs = Array.from(document.querySelectorAll("input")).some((i) => i.value.includes(t));
    return {
      inStorage,
      storageSize: window.localStorage.length + window.sessionStorage.length,
      inDom: document.documentElement.outerHTML.includes(t),
      inputs,
      inUrl: location.href.includes(t),
      cookie: document.cookie,
    };
  }, E2E_TOKEN);
  expect(leaks).toEqual({ inStorage: false, storageSize: 0, inDom: false, inputs: false, inUrl: false, cookie: "" });
  expect(await context.cookies()).toEqual([]);
});

for (const scheme of ["light", "dark"] as const) {
  test(`no serious or critical axe violations (${scheme})`, async ({ page }) => {
    await page.emulateMedia({ colorScheme: scheme });
    await page.goto("/");
    const scan = async (where: string) => {
      const r = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]).analyze();
      const bad = r.violations.filter((v) => v.impact === "serious" || v.impact === "critical");
      expect(bad.map((v) => `${where}: ${v.id} (${v.impact}) ${v.nodes.map((n) => n.target.join(" ")).join(", ")}`)).toEqual([]);
    };
    await scan("token entry");
    await enterToken(page);
    await uploadCase(page, uniqueCase(`axe-${scheme}`));
    await page.getByRole("button", { name: "Analyze" }).click();
    await expect(conclusion(page)).toContainText("Residual path");
    await page
      .getByRole("group", { name: /Provenance graph/ })
      .getByRole("button", { name: /Rule R-USE-DOWNSTREAM/ })
      .click();
    await expect(page.getByRole("complementary")).toBeVisible();
    await scan("analysis result with evidence drawer");
  });
}
