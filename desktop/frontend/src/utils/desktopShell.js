// Integration of the SPA with the desktop shell (desktop/main.js, preload.js).

// Menu shortcuts (Ctrl+1..4, Tools) arrive as routes and are applied with the
// router in place, so a menu navigation keeps drafts, in-memory results and
// live streams instead of reloading the document. Returns a function that
// stops listening; a no-op outside the desktop shell.
export function installMenuNavigation(desktopApi, router) {
  if (!desktopApi || typeof desktopApi.onMenuNavigate !== "function" || !router) return () => {};
  const stop = desktopApi.onMenuNavigate((route) => {
    const target = String(route || "");
    // An in-app path only: "/", "/soc"... never "//host" or a full URL.
    if (!/^\/(?![/\\])/.test(target)) return;
    const current = router.currentRoute && router.currentRoute.value;
    if (current && current.fullPath === target) return;
    Promise.resolve(router.push(target)).catch(() => {
      // A guard cancelling the navigation leaves the current view in place.
    });
  });
  return typeof stop === "function" ? stop : () => {};
}

// A file dropped on the window would otherwise make Chromium open it in place
// of the console. Views that accept drops still get their own events; only
// the browser's default of navigating to the file is cancelled.
export function blockFileDrops(target) {
  if (!target || typeof target.addEventListener !== "function") return;
  for (const type of ["dragover", "drop"]) {
    target.addEventListener(type, (event) => event.preventDefault());
  }
}
