// Clipboard helper shared by every table/cell copy affordance.
//
// navigator.clipboard is only available in secure contexts, and Sniff4Hound is
// routinely opened over plain http:// on a LAN address (http://192.168.x.x:45678),
// where it is simply undefined. The textarea + execCommand fallback keeps the
// copy button working there instead of silently doing nothing.
export function copyText(value) {
  const text = value === null || value === undefined ? "" : String(value);
  if (!text) return Promise.resolve(false);

  if (
    typeof navigator !== "undefined" &&
    navigator.clipboard &&
    typeof navigator.clipboard.writeText === "function"
  ) {
    return navigator.clipboard
      .writeText(text)
      .then(() => true)
      .catch(() => copyTextFallback(text));
  }
  return Promise.resolve(copyTextFallback(text));
}

function copyTextFallback(text) {
  if (typeof document === "undefined") return false;
  const area = document.createElement("textarea");
  area.value = text;
  area.setAttribute("readonly", "readonly");
  area.style.position = "fixed";
  area.style.top = "-1000px";
  area.style.opacity = "0";
  document.body.appendChild(area);
  try {
    area.select();
    return Boolean(document.execCommand && document.execCommand("copy"));
  } catch {
    return false;
  } finally {
    // Runs before either return is handed back, so the offscreen textarea
    // is always removed.
    area.remove();
  }
}

export default { copyText };
