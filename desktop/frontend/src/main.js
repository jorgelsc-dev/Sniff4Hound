import { createApp } from "vue";
import App from "./App.vue";

// Bundled, never fetched at runtime - see the note in index.html. Variable
// fonts, so the whole weight axis costs one file each rather than one
// request per weight.
import "@fontsource-variable/inter";
import "@fontsource-variable/jetbrains-mono";

import "vuetify/styles";
import "@mdi/font/css/materialdesignicons.css";
import "./styles/app.css";
import { createVuetify } from "vuetify";
import { aliases, mdi } from "vuetify/iconsets/mdi";
import router from "./router";
import store from "./state/appStore";

const vuetify = createVuetify({
  icons: {
    defaultSet: "mdi",
    aliases,
    sets: { mdi },
  },
  theme: {
    defaultTheme: "sniff4houndDark",
    themes: {
      // Kept in lockstep with the custom properties in styles/app.css - the
      // two used to disagree (#06111d vs #03070d background, #0f1d2d vs the
      // --surface-* set), so a Vuetify-painted surface and a hand-styled one
      // sitting next to each other were visibly different shades of "dark".
      sniff4houndDark: {
        dark: true,
        colors: {
          background: "#080a0d",
          surface: "#12161b",
          "surface-bright": "#1e242b",
          "surface-variant": "#171c22",
          "on-surface-variant": "#9da9b8",
          primary: "#0fe8ff",
          secondary: "#8e63ff",
          error: "#ff647a",
          info: "#4b8fff",
          success: "#4ad7b7",
          warning: "#f5bb62",
        },
      },
    },
  },
});

store.initApiBase();
store.initNotifySound();
store.initNotifyKinds();
store.initTimeRange();
store.bootstrap();

createApp(App).use(vuetify).use(router).mount("#app");
