import { apiUrl } from "./config";
import type { DirectoryApi } from "./crypto/engine.ts";

export interface User {
  id: string;
  username: string;
  display_name: string;
}

export interface LoginResult {
  token: string;
  expires_at: number;
  user: User;
}

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

/** Turn FastAPI error bodies ({detail: string | [{loc,msg}]}) into one line. */
function describe(status: number, body: unknown): string {
  if (typeof body === "object" && body !== null && "detail" in body) {
    const detail = (body as { detail: unknown }).detail;
    if (typeof detail === "string") return detail;
    if (Array.isArray(detail)) {
      return detail
        .map((d) => (typeof d === "object" && d !== null && "msg" in d ? String((d as { msg: unknown }).msg) : ""))
        .filter(Boolean)
        .join("; ");
    }
  }
  return `Request failed (HTTP ${status})`;
}

async function request<T>(path: string, init: RequestInit & { token?: string } = {}): Promise<T> {
  const headers = new Headers(init.headers);
  if (init.body !== undefined) headers.set("Content-Type", "application/json");
  if (init.token) headers.set("Authorization", `Bearer ${init.token}`);

  let response: Response;
  try {
    response = await fetch(apiUrl(path), { ...init, headers });
  } catch {
    throw new ApiError(0, "Cannot reach the server");
  }
  if (response.status === 204) return undefined as T;

  let body: unknown = null;
  try {
    body = await response.json();
  } catch {
    // Non-JSON body (e.g. an HTML error page from a misconfigured proxy).
    if (response.ok) throw new ApiError(response.status, "Unexpected response from the server");
  }
  if (!response.ok) throw new ApiError(response.status, describe(response.status, body));
  return body as T;
}

export const api = {
  register: (username: string, display_name: string, password: string) =>
    request<User>("/api/auth/register", {
      method: "POST",
      body: JSON.stringify({ username, display_name, password }),
    }),
  login: (username: string, password: string) =>
    request<LoginResult>("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    }),
  logout: (token: string) => request<void>("/api/auth/logout", { method: "POST", token }),
  me: (token: string) => request<User>("/api/auth/me", { token }),
  search: (token: string, q: string) =>
    request<User[]>(`/api/users/search?q=${encodeURIComponent(q)}`, { token }),
  wsTicket: (token: string) =>
    request<{ ticket: string; expires_in: number }>("/api/ws/ticket", { method: "POST", token }),
};

/** Key-directory and profile calls the encryption engine needs, bound to one session token. */
export function directoryApi(token: string): DirectoryApi {
  return {
    publishKeys: (body) => request("/api/keys", { method: "POST", token, body: JSON.stringify(body) }),
    keyStatus: () => request("/api/keys/status", { token }),
    fetchBundle: (userId) => request(`/api/keys/${encodeURIComponent(userId)}`, { token }),
    fetchIdentity: (userId) => request(`/api/keys/${encodeURIComponent(userId)}/identity`, { token }),
    fetchUser: (userId) => request(`/api/users/${encodeURIComponent(userId)}`, { token }),
  };
}
