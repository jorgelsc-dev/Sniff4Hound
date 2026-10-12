"use strict";

/** Configure Chromium before app.whenReady(), including the launcher process. */
function configureGraphics({ app, platform, euid, launcherOnly }) {
  if (platform !== "linux") return;
  app.commandLine.appendSwitch("no-sandbox");
  // Elevated Chromium's GL initialization can lose access to the operator's
  // X11 credentials and to GLES libraries inside a private home directory.
  // This console needs no WebGL; software rendering avoids those GPU retries.
  // The waiting launcher also needs no hardware-accelerated renderer.
  if (euid === 0 || launcherOnly) app.disableHardwareAcceleration();
}

module.exports = { configureGraphics };
