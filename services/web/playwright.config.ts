// End-to-end tests against the real API (in-memory storage) and the production build
// served by `vite preview`, which proxies /v1 to the API (same origin, as in nginx).
//
// The API is started with a throwaway bearer token that exists only for this run.
// Override the Python interpreter with AFTERLOCK_E2E_PYTHON (default `python`; CI uses
// the uv-managed environment, activated by setup-uv).
import { defineConfig, devices } from "@playwright/test";

declare const process: { env: Record<string, string | undefined>; platform: string }; // avoids a @types/node dependency

export const E2E_TOKEN = "e2e-analyst-token-0123456789abcdef";
const API_PORT = Number(process.env.AFTERLOCK_E2E_API_PORT ?? 18080);
const WEB_PORT = Number(process.env.AFTERLOCK_E2E_WEB_PORT ?? 14173);
const PYTHON = process.env.AFTERLOCK_E2E_PYTHON ?? "python";
const CI = !!process.env.CI;

export default defineConfig({
  testDir: "e2e",
  fullyParallel: false,
  workers: 1,
  forbidOnly: CI,
  retries: 0,
  timeout: 60_000,
  reporter: CI ? [["list"], ["html", { open: "never" }]] : "list",
  use: {
    baseURL: `http://127.0.0.1:${WEB_PORT}`,
    trace: "retain-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: [
    {
      command: `${PYTHON} -m uvicorn afterlock_api.app:app --host 127.0.0.1 --port ${API_PORT}`,
      url: `http://127.0.0.1:${API_PORT}/v1/health`,
      // PYTHONPATH pins the API, worker and engine to this checkout even if another
      // checkout is installed in editable mode (relative to this directory).
      env: {
        AFTERLOCK_API_TOKENS: `${E2E_TOKEN}:analyst:lab-local`,
        PYTHONPATH: ["../../packages", "../api", "../worker"].join(process.platform === "win32" ? ";" : ":"),
      },
      reuseExistingServer: false,
      timeout: 60_000,
      stdout: "ignore",
      stderr: "pipe",
    },
    {
      command: `npm run build && npx vite preview --host 127.0.0.1 --port ${WEB_PORT} --strictPort`,
      url: `http://127.0.0.1:${WEB_PORT}/`,
      env: { AFTERLOCK_API_URL: `http://127.0.0.1:${API_PORT}` },
      reuseExistingServer: false,
      timeout: 180_000,
    },
  ],
});
