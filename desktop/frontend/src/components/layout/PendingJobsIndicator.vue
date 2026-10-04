<template>
  <teleport to="body">
    <transition name="pending">
      <div v-if="visible" class="pending" role="status" aria-live="polite">
        <div class="pending__head">
          <span class="pending__spinner" />
          <strong>{{ headline }}</strong>
        </div>
        <ul class="pending__list">
          <li v-for="task in shown.slice(0, 6)" :key="task.id" class="pending__row">
            <span class="pending__label">{{ task.label }}</span>
            <span class="pending__meta" :class="{ 'is-queued': task.queued }">
              {{ task.queued ? "en cola" : "cargando" }} · {{ elapsed(task) }}
            </span>
          </li>
        </ul>
        <div v-if="hidden > 0" class="pending__more">+{{ hidden }} más</div>
      </div>
    </transition>
  </teleport>
</template>

<script>
import store from "../../state/appStore";

// A task only shows once it has been running this long, so requests that
// finish instantly never flash the panel.
const APPEAR_MS = 200;
// Keep the panel for a moment after the last task ends, so back-to-back
// requests do not make it blink off and on.
const HIDE_MS = 1500;
const TICK_MS = 250;

export default {
  name: "PendingJobsIndicator",
  data() {
    return { store, now: Date.now(), lastActive: 0, timer: null };
  },
  computed: {
    shown() {
      return this.store.state.tasks
        .filter((task) => this.now - task.startedAt >= APPEAR_MS)
        .sort((a, b) => a.startedAt - b.startedAt);
    },
    hidden() {
      return Math.max(0, this.shown.length - 6);
    },
    visible() {
      return this.shown.length > 0 || (this.lastActive > 0 && this.now - this.lastActive < HIDE_MS);
    },
    headline() {
      const count = this.shown.length;
      const queued = this.shown.filter((task) => task.queued).length;
      const noun = count === 1 ? "tarea" : "tareas";
      return `Procesando ${count} ${noun}${queued ? ` · ${queued} en cola` : ""}`;
    },
  },
  mounted() {
    this.timer = setInterval(this.tick, TICK_MS);
  },
  beforeUnmount() {
    clearInterval(this.timer);
  },
  methods: {
    tick() {
      this.now = Date.now();
      if (this.shown.length > 0) this.lastActive = this.now;
    },
    elapsed(task) {
      return `${Math.max(0, Math.round((this.now - task.startedAt) / 1000))} s`;
    },
  },
};
</script>

<style scoped>
.pending {
  position: fixed;
  right: 18px;
  bottom: 18px;
  z-index: 1200;
  width: min(320px, calc(100vw - 36px));
  padding: 10px 12px;
  border-radius: 8px;
  border: 1px solid var(--stroke-strong);
  background: rgba(18, 24, 33, 0.94);
  backdrop-filter: blur(10px);
  box-shadow: 0 12px 32px rgba(0, 0, 0, 0.42);
  color: var(--text-soft);
  font-size: 12.5px;
  pointer-events: none;
}
.pending__head { display: flex; align-items: center; gap: 10px; margin-bottom: 6px; }
.pending__spinner {
  width: 13px; height: 13px; flex: 0 0 13px; border-radius: 50%;
  border: 2px solid #3a4756; border-top-color: #0fe8ff;
  animation: pending-spin 720ms linear infinite;
}
@keyframes pending-spin { to { transform: rotate(360deg); } }
.pending__list { list-style: none; margin: 0; padding: 0; display: grid; gap: 4px; }
.pending__row { display: flex; align-items: center; justify-content: space-between; gap: 10px; }
.pending__label { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.pending__meta { flex: 0 0 auto; color: var(--text-dim); font-variant-numeric: tabular-nums; }
.pending__meta.is-queued { color: #e4b96c; }
.pending__more { margin-top: 4px; color: var(--text-dim); }
.pending-enter-active, .pending-leave-active { transition: opacity 180ms ease, transform 180ms ease; }
.pending-enter-from, .pending-leave-to { opacity: 0; transform: translateY(6px); }
:global(body.sniff4hound-desktop-shell .pending) { right: 22px; width: min(320px, calc(100vw - 92px)); }
@media (max-width: 640px) { .pending { right: 12px; bottom: 76px; } }
@media (prefers-reduced-motion: reduce) {
  .pending__spinner { animation-duration: 2s; }
  .pending-enter-active, .pending-leave-active { transition: none; }
}
</style>
