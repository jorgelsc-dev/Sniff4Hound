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
});
