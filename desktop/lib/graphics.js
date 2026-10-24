"use strict";

/** Graphics fallback for a manually root-launched shell. */
function graphicsSwitches({ platform, euid, env = {}, args = [] }) {
  if (platform !== "linux") return [];
  const switches = [];
  if (euid === 0 || env.SNIFF4HOUND_DESKTOP_NO_SANDBOX === "1") switches.push(["no-sandbox"]);
  if (euid === 0) {
    // Disabling hardware acceleration alone still allows Chromium to load
    // ANGLE/SwiftShader in a GPU child, which cannot enter a private HOME.
    // This console uses the CPU compositor and does not need WebGL.
    switches.push(["disable-gpu"], ["disable-software-rasterizer"]);
  }
  // Electron >= 38 automatically chooses Wayland. Use the authenticated X11
  // display for root when available (XWayland on a Wayland desktop), while
  // preserving an explicit platform choice and Wayland-only sessions.
  const explicitPlatform = args.some((arg) => arg === "--ozone-platform" || arg.startsWith("--ozone-platform="));
  if (euid === 0 && env.DISPLAY && !explicitPlatform) switches.push(["ozone-platform", "x11"]);
  return switches;
}

/** Configure Chromium before app.whenReady(). */
function configureGraphics({ app, platform, euid, env = process.env, args = process.argv }) {
  for (const [name, value] of graphicsSwitches({ platform, euid, env, args })) {
    app.commandLine.appendSwitch(name, value);
  }
  if (platform === "linux" && euid === 0) app.disableHardwareAcceleration();
}

module.exports = { configureGraphics, graphicsSwitches };
