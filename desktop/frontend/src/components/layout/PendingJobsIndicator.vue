<template>
  <teleport to="body">
    <transition name="pending">
      <div v-if="visible" class="pending" role="status" aria-live="polite">
        <span class="pending__spinner" />
        <span class="pending__text">{{ label }}</span>
      </div>
    </transition>
  </teleport>
</template>

<script>
import store from "../../state/appStore";

// A request only becomes a job once it outruns the backend's inline window,
// so by the time one exists it is already slow. Still held back briefly: a job
// that resolves on its first poll would otherwise flash the indicator for a
// frame or two, which reads as a glitch rather than as feedback.
const APPEAR_DELAY_MS = 350;

export default {
  name: "PendingJobsIndicator",
  data() {
    return { store, visible: false, timer: null };
  },
  computed: {
    pending() {
      return this.store.state.pendingJobs || 0;
    },
    label() {
      return this.pending > 1 ? `Procesando ${this.pending} peticiones...` : "Procesando...";
    },
  },
  watch: {
    pending: {
      immediate: true,
      handler(count) {
        clearTimeout(this.timer);
        if (count <= 0) {
          this.visible = false;
          return;
        }
        if (this.visible) return;
        this.timer = setTimeout(() => {
          // Re-checked on fire: the job may well have landed during the delay.
          this.visible = this.pending > 0;
        }, APPEAR_DELAY_MS);
      },
    },
  },
  beforeUnmount() {
    clearTimeout(this.timer);
  },
};
</script>

<style scoped>
.pending {
  position: fixed;
  right: 18px;
  bottom: 18px;
  z-index: 2400;
  display: flex;
  align-items: center;
  gap: 10px;
  max-width: min(360px, calc(100vw - 36px));
  padding: 9px 13px;
  border-radius: 8px;
  border: 1px solid var(--stroke-strong);
  background: rgba(18, 24, 33, 0.94);
  backdrop-filter: blur(10px);
  box-shadow: 0 12px 32px rgba(0, 0, 0, 0.42);
  color: var(--text-soft);
  font-size: 12.5px;
}
.pending__spinner {
  width: 13px;
  height: 13px;
  flex: 0 0 13px;
  border-radius: 50%;
  border: 2px solid #3a4756;
  border-top-color: #0fe8ff;
  animation: pending-spin 720ms linear infinite;
}
@keyframes pending-spin { to { transform: rotate(360deg); } }
.pending-enter-active, .pending-leave-active { transition: opacity 180ms ease, transform 180ms ease; }
.pending-enter-from, .pending-leave-to { opacity: 0; transform: translateY(6px); }
:global(body.sniff4hound-desktop-shell) .pending {
  right: 22px;
}
@media (max-width: 640px) {
  .pending {
    right: 12px;
    bottom: 76px;
  }
}
@media (prefers-reduced-motion: reduce) {
  .pending__spinner { animation-duration: 2s; }
  .pending-enter-active, .pending-leave-active { transition: none; }
}
</style>
