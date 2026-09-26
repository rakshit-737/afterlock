import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

// The dev server proxies /v1 to a locally running API so the browser only talks
// to its own origin (same as the nginx deployment and `connect-src 'self'`).
declare const process: { env: Record<string, string | undefined> }; // avoids a @types/node dependency
const apiTarget = process.env.AFTERLOCK_API_URL ?? "http://127.0.0.1:8080";

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: { "/v1": { target: apiTarget, changeOrigin: false } },
  },
  build: {
    outDir: "dist",
    sourcemap: false,
    // Emit every asset as a file (no data: URIs or inline code) so the CSP can
    // forbid 'unsafe-inline'.
    assetsInlineLimit: 0,
    modulePreload: { polyfill: false },
  },
  test: {
    environment: "jsdom",
    globals: true,
    include: ["src/**/*.test.{ts,tsx}"],
  },
});
