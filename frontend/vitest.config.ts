import { defineConfig } from "vitest/config";

export default defineConfig({
  test: { include: ["tests/signal/*.spec.ts"], environment: "node", testTimeout: 60_000 },
});
