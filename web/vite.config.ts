import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The interface is served from the panel's configured path, which is not known
// until the panel runs: it may be /admin or something unguessable. Relative
// asset URLs are what make one build work at any path.
export default defineConfig({
  plugins: [react()],
  base: "./",
  build: {
    // Straight into the Go package that embeds it, so a build and a
    // `go build` cannot drift apart.
    outDir: "../internal/panel/webui/dist",
    emptyOutDir: true,
    // One chunk is the right answer here: the whole interface is smaller than
    // the round trips splitting it would add on a phone.
    chunkSizeWarningLimit: 900,
  },
  server: {
    port: 5173,
    proxy: {
      // `npm run dev` talks to a panel running locally, so the interface can
      // be worked on without rebuilding the binary.
      "/admin/api": { target: "http://127.0.0.1:8080", changeOrigin: false },
    },
  },
});
