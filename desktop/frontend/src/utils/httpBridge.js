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
    try {
      return await fetch(url, options);
    } catch (error) {
      throw new Error(connectionErrorMessage(error), { cause: error });
    }
  }
  let result;
  try {
    result = await bridge.httpRequest({
      url: target,
      method: options.method || "GET",
      headers: options.headers || {},
      body: options.body === undefined ? null : options.body,
    });
  } catch (error) {
    throw new Error(connectionErrorMessage(error), { cause: error });
  }
  return responseFrom(result);
}


export function connectionErrorMessage(error) {
  const raw = String(error?.message || error || "").replace(/^Error invoking remote method '[^']+': (?:Error: )?/, "");
  if (/^El sensor|^La respuesta del sensor|^No se pudo/.test(raw)) return raw;
  if (/timed? ?out|timeout/i.test(raw)) return "El sensor tardó demasiado en responder. Reintenta o cambia de sensor.";
  if (/too large/i.test(raw)) return "La respuesta del sensor es demasiado grande. Reduce la búsqueda o el tamaño de página.";
  if (/certificate|cert_|CA\b|TLS/i.test(raw)) return "No se pudo verificar el certificado del sensor. Revisa la CA y vuelve a conectar.";
  if (/ECONN|ENOTFOUND|EHOST|network|fetch|socket|remote method/i.test(raw)) return "No se pudo conectar con el sensor. Comprueba la conexión o cambia de sensor.";
  return raw || "No se pudo completar la petición. Vuelve a intentarlo.";
}
