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
  bottom: 18px;
  left: 50%;
  transform: translateX(-50%);
  z-index: 2400;
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 8px 15px;
  border-radius: 20px;
  border: 1px solid #2f3a49;
  background: #121821ee;
  backdrop-filter: blur(6px);
  box-shadow: 0 10px 30px #0007;
  color: #d5dde8;
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
.pending-enter-from, .pending-leave-to { opacity: 0; transform: translateX(-50%) translateY(6px); }
@media (prefers-reduced-motion: reduce) {
  .pending__spinner { animation-duration: 2s; }
  .pending-enter-active, .pending-leave-active { transition: none; }
}
</style>
