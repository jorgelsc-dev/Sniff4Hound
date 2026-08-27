import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";

// The landing page is served from the domain root; the MkDocs site is copied
// into /docs/ next to it by the docs-pages workflow, so nothing here may
// assume a subpath.
export default defineConfig({
  plugins: [vue()],
  base: "/",
  build: {
    outDir: "dist",
    emptyOutDir: true,
  },
});
