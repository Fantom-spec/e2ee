import { useEffect, useRef, useState } from "react";
import { api } from "./api";
import { wsUrl } from "./config";
import type { ChatEngine } from "./crypto/engine.ts";

export type RelayStatus = "connecting" | "online" | "offline" | "session-ended";

const CLOSE_UNAUTHENTICATED = 4401;
const MAX_BACKOFF_MS = 15_000;

/** Lets the engine (created before the socket exists) send frames on whatever socket is current. */
export class RelayLink {
  socket: WebSocket | null = null;
  send = (frame: Record<string, unknown>): boolean => {
    if (this.socket === null || this.socket.readyState !== WebSocket.OPEN) return false;
    this.socket.send(JSON.stringify(frame));
    return true;
  };
}

/**
 * Keeps one WebSocket to the relay open while a token and an engine exist,
 * reconnecting with exponential backoff. Each attempt fetches a fresh
 * single-use ticket, so the long-lived token never appears in a URL. Every
 * frame is handed to the engine; the relay itself only ever carries ciphertext.
 */
export function useRelay(
  token: string | null,
  engine: ChatEngine | null,
  link: RelayLink,
  onSessionEnded: () => void,
): RelayStatus {
  const [status, setStatus] = useState<RelayStatus>("connecting");
  const endedRef = useRef(onSessionEnded);
  endedRef.current = onSessionEnded;

  useEffect(() => {
    if (!token || !engine) return;
    let cancelled = false;
    let timer: number | undefined;
    let attempt = 0;

    const schedule = () => {
      const delay = Math.min(MAX_BACKOFF_MS, 1000 * 2 ** attempt);
      attempt += 1;
      timer = window.setTimeout(() => void connect(), delay);
    };

    const connect = async () => {
      if (engine.hasFailed) return; // storage failure: stop; the UI tells the user to log in again
      setStatus("connecting");
      let ws: WebSocket;
      try {
        const { ticket } = await api.wsTicket(token);
        if (cancelled) return;
        ws = new WebSocket(wsUrl("/ws", `ticket=${encodeURIComponent(ticket)}`));
        link.socket = ws;
      } catch (error) {
        if (cancelled) return;
        if (error instanceof Error && "status" in error && (error as { status: number }).status === 401) {
          setStatus("session-ended");
          endedRef.current();
          return;
        }
        schedule();
        return;
      }
      ws.onmessage = (event: MessageEvent) => {
        let frame: unknown;
        try {
          frame = JSON.parse(String(event.data));
        } catch {
          return; // the relay only sends JSON
        }
        if (typeof frame === "object" && frame !== null && (frame as { type?: unknown }).type === "ready") {
          attempt = 0;
          setStatus("online");
        }
        engine.handleFrame(frame).catch(() => undefined); // failures surface through engine.hasFailed / notice
      };
      ws.onclose = (event: CloseEvent) => {
        if (link.socket === ws) link.socket = null;
        if (cancelled) return;
        engine.onDisconnected();
        if (event.code === CLOSE_UNAUTHENTICATED) {
          setStatus("session-ended");
          endedRef.current();
          return;
        }
        setStatus("offline");
        schedule();
      };
    };

    void connect();
    return () => {
      cancelled = true;
      if (timer !== undefined) window.clearTimeout(timer);
      link.socket?.close();
      link.socket = null;
    };
  }, [token, engine, link]);

  return status;
}
