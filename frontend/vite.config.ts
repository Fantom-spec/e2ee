import react from "@vitejs/plugin-react";
import { defineConfig, loadEnv } from "vite";

// The dev proxy target comes from VITE_DEV_BACKEND_URL (see .env.example), so
// no host or tunnel URL is hardcoded. If unset, no proxy is configured and the
// app must be given VITE_API_BASE_URL instead.
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "VITE_");
  const backend = env.VITE_DEV_BACKEND_URL;
  return {
    plugins: [react()],
    server: {
      host: true, // listen on the LAN so a phone on the same Wi-Fi can test
      proxy: backend
        ? {
            "/api": { target: backend, changeOrigin: true },
            "/ws": { target: backend, ws: true, changeOrigin: true },
          }
        : undefined,
    },
  };
});
