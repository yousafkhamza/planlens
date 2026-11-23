import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    testTimeout: 60_000,
    coverage: {
      provider: "v8",
      include: ["src/**/*.ts"],
      exclude: ["src/bin.ts", "src/action/entry.ts", "src/web.ts"],
      reporter: ["text-summary", "lcov"],
      thresholds: { lines: 90, functions: 90, branches: 80, statements: 90 },
    },
  },
});
