import { createApp } from "vue";
import App from "./App.vue";
import "./styles/app.css";

import "vuetify/styles";
import "@mdi/font/css/materialdesignicons.css";
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
      sniff4houndDark: {
        dark: true,
        colors: {
          background: "#06111d",
          surface: "#0f1d2d",
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
store.initTimeRange();
store.bootstrap();

createApp(App).use(vuetify).use(router).mount("#app");
