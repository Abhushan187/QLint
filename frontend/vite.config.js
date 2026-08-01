import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  // Pinned so the GitHub OAuth app's callback and the backend's FRONTEND_URL
  // always agree on where the frontend lives.
  server: {
    port: 5174,
    strictPort: true,
  },
});
