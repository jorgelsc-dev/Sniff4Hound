<template>
  <teleport to="body">
    <transition name="palette">
      <div v-if="store.state.commandPaletteOpen" class="palette" @click.self="close">
        <div class="palette__card" role="dialog" aria-modal="true" aria-label="Paleta de comandos">
          <div class="palette__search">
            <v-icon icon="mdi-magnify" size="19" />
            <input
              ref="input"
              v-model="query"
              type="text"
              class="palette__input"
              placeholder="Buscar vistas, ajustes y acciones..."
              aria-label="Buscar"
              autocomplete="off"
              spellcheck="false"
              @keydown.down.prevent="move(1)"
              @keydown.up.prevent="move(-1)"
              @keydown.enter.prevent="run(active)"
              @keydown.esc.prevent="close"
            >
            <kbd class="palette__hint">ESC</kbd>
          </div>

          <div ref="list" class="palette__results" role="listbox">
            <template v-for="group in grouped" :key="group.name">
              <div class="palette__group">{{ group.name }}</div>
              <button
                v-for="item in group.items"
                :key="item.id"
                type="button"
                class="palette__item"
                :class="{ 'is-active': item.id === activeId }"
                role="option"
                :aria-selected="item.id === activeId"
                :data-id="item.id"
                @click="run(item)"
                @mousemove="activeId = item.id"
              >
                <v-icon :icon="item.icon" size="18" class="palette__icon" />
                <span class="palette__label">
                  <i v-if="item.parent">{{ item.parent }} /</i>
                  {{ item.label }}
                </span>
                <span v-if="item.badge" class="palette__badge" :class="item.badgeClass">{{ item.badge }}</span>
              </button>
            </template>
            <p v-if="!results.length" class="palette__empty">Nada coincide con "{{ query }}".</p>
          </div>

          <footer class="palette__foot">
            <span><kbd>↑</kbd><kbd>↓</kbd> navegar</span>
            <span><kbd>↵</kbd> abrir</span>
            <span class="palette__foot-spacer" />
            <span>{{ results.length }} resultados</span>
          </footer>
        </div>
      </div>
    </transition>
  </teleport>
</template>

<script>
import store from "../../state/appStore";
import { matchesQuery, navDestinations } from "../../utils/navigation";
import { SETTINGS_NODES } from "../settings/settingsGraph";

export default {
  name: "CommandPalette",
  data() {
    return { store, query: "", activeId: "" };
  },
  computed: {
    runtime() {
      return this.store.state.runtime || {};
    },
    // Engine toggles are the only actions here that change anything. They read
    // their current state so the palette says "Detener" on something running
    // rather than offering an action that would be a no-op.
    actions() {
      return ["sniffer", "honeypot"].map((engine) => {
        const running = Boolean(this.runtime[engine]?.running);
        const name = engine === "sniffer" ? "Sniffer" : "Honeypot";
        return {
          id: `action:${engine}`,
          group: "Acciones",
          label: `${running ? "Detener" : "Iniciar"} ${name}`,
          icon: running ? "mdi-stop-circle-outline" : "mdi-play-circle-outline",
          keywords: `${engine} motor runtime start stop encender apagar`,
          badge: running ? "En ejecución" : "Detenido",
          badgeClass: running ? "is-on" : "",
          run: () => this.toggleEngine(engine, !running),
        };
      });
    },
    items() {
      return [
        ...navDestinations().map(item => ({
          ...item,
          id: `nav:${item.to}`,
          run: () => this.$router.push(item.to),
        })),
        ...this.actions,
        ...SETTINGS_NODES.map(node => ({
          id: `settings:${node.section}`,
          group: "Configuración",
          label: node.label,
          parent: "Settings",
          icon: node.icon,
          keywords: `${node.detail} ajustes configuracion`,
          run: () => this.$router.push({ path: "/settings", query: { section: node.section } }),
        })),
      ];
    },
    results() {
      return this.items.filter(item => matchesQuery(item, this.query));
    },
    grouped() {
      const order = ["Ir a", "Acciones", "Configuración"];
      return order
        .map(name => ({ name, items: this.results.filter(item => item.group === name) }))
        .filter(group => group.items.length);
    },
    active() {
      return this.results.find(item => item.id === this.activeId) || this.results[0];
    },
  },
  watch: {
    // Any keystroke can drop the highlighted row out of the result set; without
    // this the selection would silently point at nothing and Enter would open
    // whatever happened to be first.
    results(list) {
      if (!list.some(item => item.id === this.activeId)) {
        this.activeId = list.length ? list[0].id : "";
      }
    },
  },
  mounted() {
    document.addEventListener("keydown", this.handleKeydown);
  },
  beforeUnmount() {
    document.removeEventListener("keydown", this.handleKeydown);
  },
  methods: {
    handleKeydown(event) {
      const key = String(event.key || "").toLowerCase();
      if (key === "k" && (event.metaKey || event.ctrlKey)) {
        event.preventDefault();
        this.store.state.commandPaletteOpen ? this.close() : this.show();
      }
    },
    show() {
      this.store.state.commandPaletteOpen = true;
      this.query = "";
      this.activeId = this.results.length ? this.results[0].id : "";
      this.$nextTick(() => this.$refs.input?.focus());
    },
    close() {
      this.store.state.commandPaletteOpen = false;
    },
    move(delta) {
      const list = this.results;
      if (!list.length) return;
      const current = list.findIndex(item => item.id === this.activeId);
      const next = (current + delta + list.length) % list.length;
      this.activeId = list[next].id;
      this.$nextTick(() => {
        this.$refs.list
          ?.querySelector(`[data-id="${CSS.escape(this.activeId)}"]`)
          ?.scrollIntoView({ block: "nearest" });
      });
    },
    run(item) {
      if (!item) return;
      this.close();
      item.run();
    },
    toggleEngine(engine, shouldRun) {
      this.store.controlEngine(engine, shouldRun ? "start" : "stop").catch((err) => {
        this.store.pushNotification({
          kind: "runtime",
          severity: "high",
          title: `No se pudo ${shouldRun ? "iniciar" : "detener"} ${engine}`,
          message: (err && err.message) || "Error de runtime",
          groupKey: `runtime:${engine}:palette-error`,
        });
      });
    },
  },
};
</script>

<style scoped>
.palette {
  position: fixed;
  inset: 0;
  z-index: 2600;
  display: flex;
  justify-content: center;
  align-items: flex-start;
  padding: 12vh 20px 20px;
  background: #05080cc4;
  backdrop-filter: blur(4px);
}
.palette__card {
  width: min(620px, 100%);
  max-height: 62vh;
  display: flex;
  flex-direction: column;
  background: #12151b;
  border: 1px solid #2c3340;
  border-radius: 13px;
  box-shadow: 0 28px 70px #000b;
  overflow: hidden;
}
.palette__search {
  display: flex;
  align-items: center;
  gap: 11px;
  padding: 0 15px;
  height: 52px;
  border-bottom: 1px solid #242b36;
  color: #7f8b9c;
  flex: 0 0 auto;
}
.palette__input {
  flex: 1;
  min-width: 0;
  background: none;
  border: 0;
  outline: none;
  color: #e7ecf3;
  font-size: 14.5px;
}
.palette__input::placeholder { color: #626d7d; }
.palette__hint {
  font-size: 10px;
  color: #7c879a;
  background: #1d232d;
  border: 1px solid #2e3643;
  border-radius: 5px;
  padding: 2px 6px;
}
.palette__results { overflow-y: auto; padding: 6px; flex: 1; min-height: 0; }
.palette__group {
  font-size: 10px;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: #6d7889;
  padding: 10px 10px 5px;
}
.palette__item {
  width: 100%;
  display: flex;
  align-items: center;
  gap: 11px;
  padding: 9px 10px;
  border-radius: 7px;
  color: #d3dae4;
  text-align: left;
  font-size: 13.5px;
  border: 0;
  background: none;
  cursor: pointer;
}
.palette__item.is-active { background: #1f6feb24; color: #fff; box-shadow: inset 0 0 0 1px #1f6feb59; }
.palette__icon { color: #8794a6; flex: 0 0 auto; }
.palette__item.is-active .palette__icon { color: #54cbd8; }
.palette__label { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.palette__label i { font-style: normal; color: #6f7b8c; }
.palette__badge {
  font-size: 10px;
  color: #93a0b2;
  background: #1c232d;
  border-radius: 20px;
  padding: 2px 9px;
  flex: 0 0 auto;
}
.palette__badge.is-on { color: #4ad7b7; background: #4ad7b71f; }
.palette__empty { padding: 26px 12px; text-align: center; color: #6f7b8c; font-size: 13px; }
.palette__foot {
  display: flex;
  align-items: center;
  gap: 14px;
  padding: 8px 14px;
  border-top: 1px solid #242b36;
  font-size: 11px;
  color: #6f7b8c;
  flex: 0 0 auto;
}
.palette__foot-spacer { flex: 1; }
.palette__foot kbd {
  font-size: 10px;
  background: #1d232d;
  border: 1px solid #2e3643;
  border-radius: 4px;
  padding: 1px 5px;
  margin-right: 3px;
}
.palette-enter-active, .palette-leave-active { transition: opacity 140ms ease; }
.palette-enter-active .palette__card, .palette-leave-active .palette__card {
  transition: transform 160ms cubic-bezier(0.32, 0.72, 0, 1), opacity 140ms ease;
}
.palette-enter-from, .palette-leave-to { opacity: 0; }
.palette-enter-from .palette__card, .palette-leave-to .palette__card {
  opacity: 0;
  transform: translateY(-8px) scale(0.985);
}
@media (prefers-reduced-motion: reduce) {
  .palette-enter-active, .palette-leave-active,
  .palette-enter-active .palette__card, .palette-leave-active .palette__card { transition: none; }
}
</style>
