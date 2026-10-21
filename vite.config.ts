import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The UI lives in ./ui and is built into ./dist, which Tauri embeds (src-tauri/tauri.conf.json).
export default defineConfig({
  root: "ui",
  plugins: [react()],
  clearScreen: false,
  server: { port: 5173, strictPort: true },
  build: {
    outDir: "../dist",
    emptyOutDir: true,
    target: "es2021",
    // Never ship source maps: they would expose the UI source inside the bundle.
    sourcemap: false,
    // Keep everything as files so the strict CSP (no inline scripts/styles) holds.
    assetsInlineLimit: 0,
  },
});
