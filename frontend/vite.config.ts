import react from "@vitejs/plugin-react";
import { defineConfig, loadEnv } from "vite";

// The dev proxy target comes from VITE_DEV_BACKEND_URL.
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "VITE_");
  const backend = env.VITE_DEV_BACKEND_URL;

  return {
    plugins: [react()],
    server: {
      host: true,
      allowedHosts: [
        "chat.shubhammishra.online",
      ],
      proxy: backend
        ? {
            "/api": { target: backend, changeOrigin: true },
            "/ws": { target: backend, ws: true, changeOrigin: true },
          }
        : undefined,
    },
  };
});