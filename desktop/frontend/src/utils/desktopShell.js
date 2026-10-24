// Integration of the SPA with the desktop shell (desktop/main.js, preload.js).

// A file dropped on the window would otherwise make Chromium open it in place
// of the console. Views that accept drops still get their own events; only
// the browser's default of navigating to the file is cancelled.
export function blockFileDrops(target) {
  if (!target || typeof target.addEventListener !== "function") return;
  for (const type of ["dragover", "drop"]) {
    target.addEventListener(type, (event) => event.preventDefault());
  }
}
