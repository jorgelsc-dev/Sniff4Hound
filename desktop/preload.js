const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("sniff4houndDesktop", {
  platform: process.platform,
  getConnectionDefaults: () => ipcRenderer.invoke("desktop-runtime:get-connection-defaults"),
  startLocal: () => ipcRenderer.invoke("desktop-runtime:start-local"),
  connectRemote: (payload) => ipcRenderer.invoke("desktop-runtime:connect-remote", payload || {}),
  showConnectionChooser: () => ipcRenderer.invoke("desktop-runtime:show-connection-chooser"),
  onRuntimeStatus: (handler) => {
    if (typeof handler !== "function") return;
    ipcRenderer.removeAllListeners("desktop-runtime:status");
    ipcRenderer.on("desktop-runtime:status", (_event, message) => handler(String(message || "")));
  },
  minimize: () => ipcRenderer.invoke("desktop-window:minimize"),
  maximize: () => ipcRenderer.invoke("desktop-window:maximize"),
  close: () => ipcRenderer.invoke("desktop-window:close"),
  openExternal: (url) => ipcRenderer.invoke("desktop-shell:open-external", String(url || "")),
  // HTTP through the main process, which speaks HTTP/3 to the pinned runtime.
  httpRequest: (payload) => ipcRenderer.invoke("desktop-http:request", payload || {}),
  httpStreamOpen: (payload) => ipcRenderer.invoke("desktop-http:stream-open", payload || {}),
  httpStreamClose: (id) => ipcRenderer.invoke("desktop-http:stream-close", { id: String(id || "") }),
  onHttpStream: (handler) => {
    if (typeof handler !== "function") return () => {};
    const listener = (_event, message) => handler(message);
    ipcRenderer.on("desktop-http:stream", listener);
    return () => ipcRenderer.removeListener("desktop-http:stream", listener);
  },
});
