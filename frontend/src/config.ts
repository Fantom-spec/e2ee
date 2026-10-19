// Runtime-configurable API base. Empty string means same-origin.
const base = (import.meta.env.VITE_API_BASE_URL ?? "").replace(/\/+$/, "");

export function apiUrl(path: string): string {
  if (!path.startsWith("/")) {
    throw new Error("apiUrl expects an absolute path such as /api/health");
  }
  return `${base}${path}`;
}

/** WebSocket URL for the relay: wss:// when the page or API is https. */
export function wsUrl(path: string, query: string): string {
  const origin = base !== "" ? new URL(base) : new URL(window.location.href);
  const scheme = origin.protocol === "https:" ? "wss:" : "ws:";
  return `${scheme}//${origin.host}${path}?${query}`;
}
