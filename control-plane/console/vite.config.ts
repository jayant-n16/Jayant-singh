/// <reference types="vitest/config" />
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// The browser talks to the API under /api (same origin). In development Vite forwards /api to
// the local API; in production nginx does the same (deploy/console).
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      "/api": {
        target: process.env.OPLIA_API_URL ?? "http://localhost:8080",
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, ""),
      },
    },
  },
  build: { sourcemap: false, target: "es2022" },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
    include: ["src/**/*.test.{ts,tsx}"],
    restoreMocks: true,
  },
});
