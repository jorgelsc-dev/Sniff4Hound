const SAFE_FAVICON_KEYS = new Set(["id", "ticket"]);

// Accept the backend's short-lived favicon ticket, but never propagate an
// arbitrary legacy URL (especially one containing an auth/session token).
export function buildFaviconPath(item = {}) {
  const fallbackId = String(item && item.id || "");
  const rawUrl = String(item && item.raw_url || "").trim();
  if (rawUrl.startsWith("/")) {
    try {
      const parsed = new URL(rawUrl, "https://sniff4hound.invalid");
      if (parsed.origin === "https://sniff4hound.invalid" && parsed.pathname === "/favicons/raw/") {
        const params = new URLSearchParams();
        for (const [key, value] of parsed.searchParams) {
          if (SAFE_FAVICON_KEYS.has(key) && value) params.set(key, value);
        }
        if (!params.has("id") && fallbackId) params.set("id", fallbackId);
        return `/favicons/raw/?${params.toString()}`;
      }
    } catch {
      // Fall through to the identifier-only compatibility URL.
    }
  }
  const params = new URLSearchParams();
  params.set("id", fallbackId);
  return `/favicons/raw/?${params.toString()}`;
}
