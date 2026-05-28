import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Dev server proxies /api requests to the FastAPI backend on :8000 so the
// frontend and backend can run side by side without CORS friction.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": { target: "http://localhost:8000", changeOrigin: true },
    },
  },
});
