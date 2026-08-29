import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { fileURLToPath, URL } from "node:url";

// Node 只出现在构建期：产物为纯静态 dist，由 Python runtime 托管。
export default defineConfig({
  plugins: [react()],
  base: "/app/",
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./src", import.meta.url)),
    },
  },
  server: {
    port: 5173,
    proxy: {
      "/api": "http://127.0.0.1:8080",
      "/v1": "http://127.0.0.1:8080",
    },
  },
  build: {
    outDir: "dist",
    sourcemap: false,
  },
});
