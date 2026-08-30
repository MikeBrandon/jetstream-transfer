import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Tauri serves the built assets from disk, so relative paths are required.
export default defineConfig({
  plugins: [react()],
  base: "./",
  clearScreen: false,
  server: {
    port: 5173,
    strictPort: true,
  },
  build: {
    // WebView2 on Windows 11 is evergreen Chromium, so there is no reason to
    // ship down-levelled output.
    target: "chrome110",
    sourcemap: false,
    // Inline the font rather than emitting a separate request: the CSP forbids
    // remote fonts, and one fewer file is one fewer thing to get wrong.
    assetsInlineLimit: 200 * 1024,
  },
});
