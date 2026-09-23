import { fileURLToPath, URL } from "node:url";
import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";
import vuetify from "vite-plugin-vuetify";

// Vite's own HTML-generation plugin hardcodes a `crossorigin` attribute on
// every module script/modulepreload/stylesheet tag it emits - there's no
// build option to turn it off. That's fine served over http(s), but under
// the desktop shell's file:// loading (see desktop/main.js's loadShell())
// Chromium refuses any crossorigin-mode request against the file: scheme
// outright ("CorsDisabledScheme", verified empirically against a real
// build - every asset failed to load and the app never mounted), even for
// a sibling file in the same folder. Stripping the attribute post-build is
// the standard workaround for this exact Vite+Electron combination.
const stripCrossoriginForFileProtocol = {
  name: "strip-crossorigin-for-file-protocol",
  transformIndexHtml: {
    order: "post",
    handler(html) {
      return html.replace(/\s+crossorigin(="[^"]*")?/g, "");
    },
  },
};

export default defineConfig({
  // Loaded natively by the Electron shell via loadFile() (a file:// URL),
  // not served over HTTP by the Python backend anymore - the default
  // root-absolute base ("/assets/...") resolves against the filesystem
  // root under file://, not the dist folder, so nothing loads. "./" keeps
  // every emitted reference relative to index.html itself, which works
  // under both file:// and http://.
  base: "./",
  plugins: [
    vue(),
    vuetify(),
    stripCrossoriginForFileProtocol,
  ],
  build: {
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (!id.includes("node_modules")) return undefined;
          if (id.includes("vuetify")) return "vuetify";
          if (id.includes("@mdi/font")) return "mdi";
          if (id.includes("vue-router")) return "vue-router";
          if (id.includes("/vue/")) return "vue-core";
          return "vendor";
        },
      },
    },
  },
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./src", import.meta.url)),
    },
  },
  server: {
    host: "0.0.0.0",
    port: 8080,
  },
  preview: {
    host: "0.0.0.0",
    port: 4173,
  },
});
