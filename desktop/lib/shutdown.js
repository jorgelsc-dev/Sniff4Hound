"use strict";

const SHUTDOWN_DELAY_MS = 3000;

/** Begin cleanup immediately while keeping the window open for the countdown. */
function createShutdownController({ cleanup, close, now = Date.now, schedule = setTimeout }) {
  let deadline = 0;
  return {
    isPending: () => deadline !== 0,
    start() {
      if (deadline) return { deadline };
      deadline = now() + SHUTDOWN_DELAY_MS;
      schedule(close, SHUTDOWN_DELAY_MS);
      cleanup();
      return { deadline };
    },
  };
}

module.exports = { createShutdownController, SHUTDOWN_DELAY_MS };
