// Network access for the UI. Under the desktop shell every request goes through
// the main process (see desktop/main.js, "Renderer HTTP bridge"), which speaks
// HTTP/3 to the runtime. In a plain browser the native fetch is used instead.

export function desktopBridge() {
  if (typeof window === "undefined") return null;
  const bridge = window.sniff4houndDesktop;
  return bridge && typeof bridge.httpRequest === "function" ? bridge : null;
}

// A fetch-shaped result: the callers only read ok, status and the body text.
function responseFrom(result) {
  const status = Number(result.status) || 0;
  return {
    ok: status >= 200 && status < 300,
    status,
    text: async () => result.body,
    json: async () => JSON.parse(result.body),
  };
}

// Loopback runtimes are reached directly by the renderer: the loopback switch in
// the desktop shell lets Chromium run HTTP/3 to them. Only remote runtimes go
// through the main process bridge, which pins their CA.
export function isLoopbackUrl(url) {
  try {
    const host = new URL(String(url)).hostname.toLowerCase();
    return host === "localhost" || host === "127.0.0.1" || host === "::1" || host === "[::1]";
  } catch {
    return false;
  }
}

export function bridgeFor(url) {
  const bridge = desktopBridge();
  return bridge && !isLoopbackUrl(url) ? bridge : null;
}

export async function bridgedFetch(url, options = {}) {
  const bridge = bridgeFor(url);
  const target = String(url);
  if (!bridge || !target.startsWith("https://")) {
    return fetch(url, options);
  }
  const result = await bridge.httpRequest({
    url: target,
    method: options.method || "GET",
    headers: options.headers || {},
    body: options.body === undefined ? null : options.body,
  });
  return responseFrom(result);
}
