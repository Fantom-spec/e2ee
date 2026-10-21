import { useEffect, useMemo, useState, useSyncExternalStore } from "react";
import { directoryApi, User } from "./api";
import ChatWindow from "./ChatWindow";
import type { ChatEngine } from "./crypto/engine.ts";
import { openEngine } from "./crypto/session.ts";
import UserSearch from "./UserSearch";
import { RelayLink, RelayStatus, useRelay } from "./useRelay";

const STATUS_TEXT: Record<RelayStatus, string> = {
  connecting: "Connecting to relay...",
  online: "Relay connected",
  offline: "Relay disconnected, retrying...",
  "session-ended": "Session ended",
};

interface Props {
  token: string;
  user: User;
  password: string;
  onLogout: () => void;
  onSessionEnded: () => void;
}

export default function ChatApp({ token, user, password, onLogout, onSessionEnded }: Props) {
  const link = useMemo(() => new RelayLink(), []);
  const [engine, setEngine] = useState<ChatEngine | null>(null);
  const [fatal, setFatal] = useState<string | null>(null);
  const [peerId, setPeerId] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    openEngine({ userId: user.id, password, api: directoryApi(token), sendFrame: link.send })
      .then((e) => !cancelled && setEngine(e))
      .catch((e: unknown) => !cancelled && setFatal(e instanceof Error ? e.message : "Could not start encrypted chat"));
    return () => {
      cancelled = true;
    };
  }, [token, user.id, password, link]);

  const status = useRelay(token, engine, link, onSessionEnded);

  if (fatal) {
    return (
      <section className="card">
        <h2>Encryption unavailable</h2>
        <p className="err" role="alert">{fatal}</p>
        <button type="button" onClick={onLogout}>Back to login</button>
      </section>
    );
  }
  if (!engine) return <p>Unlocking your encryption keys...</p>;

  return (
    <Ready engine={engine} token={token} user={user} status={status} peerId={peerId} setPeerId={setPeerId} onLogout={onLogout} />
  );
}

function trustBadge(c: { verified: boolean; keyChange?: unknown }): { cls: string; text: string; label: string } {
  if (c.keyChange) return { cls: "badge danger", text: "! Key changed", label: "Safety number changed" };
  if (c.verified) return { cls: "badge ok", text: "Verified", label: "Safety number verified" };
  return { cls: "badge warn", text: "unverified", label: "Safety number not verified" };
}

function Ready(props: {
  engine: ChatEngine; token: string; user: User; status: RelayStatus;
  peerId: string | null; setPeerId: (id: string | null) => void; onLogout: () => void;
}) {
  const { engine, token, user, status, peerId, setPeerId, onLogout } = props;
  useSyncExternalStore(engine.subscribe, engine.getVersion);
  const [startError, setStartError] = useState<string | null>(null);

  const open = async (u: User) => {
    setStartError(null);
    try {
      await engine.startConversation(u);
      setPeerId(u.id);
    } catch (e) {
      setStartError(e instanceof Error ? e.message : "Could not open conversation");
    }
  };

  const conversations = engine.conversations();

  return (
    <div className="layout" data-view={peerId ? "chat" : "list"}>
      <aside className="sidebar" aria-label="Conversations">
        <section className="card">
          <h2>{user.display_name} <span className="muted">@{user.username}</span></h2>
          <p className={status === "online" ? "ok" : "muted"} aria-live="polite">{STATUS_TEXT[status]}</p>
          {engine.hasFailed && (
            <p className="banner danger" role="alert">
              Saving to this browser failed, so chat is stopped to protect your messages. Reload and log in again.
            </p>
          )}
          {engine.notice && <p className="banner" role="status">{engine.notice}</p>}
          <button type="button" onClick={onLogout}>Log out</button>
        </section>

        <section className="card">
          <h2>Conversations</h2>
          {conversations.length === 0 && <p className="muted">None yet. Find someone below.</p>}
          <ul className="convs">
            {conversations.map(({ contact, last }) => {
              const badge = trustBadge(contact);
              return (
                <li key={contact.userId}>
                  <button
                    type="button"
                    className={`conv${contact.userId === peerId ? " active" : ""}`}
                    aria-current={contact.userId === peerId ? "true" : undefined}
                    onClick={() => setPeerId(contact.userId)}
                  >
                    <span className="conv-top">
                      <strong>{contact.displayName}</strong>
                      <span className={badge.cls} title={badge.label}>{badge.text}</span>
                    </span>
                    <span className="muted small">@{contact.username}</span>
                    {last && last.kind === "message" && (
                      <span className="muted preview">{last.dir === "out" ? "You: " : ""}{last.text.slice(0, 60)}</span>
                    )}
                  </button>
                </li>
              );
            })}
          </ul>
        </section>
        {startError && <p className="err" role="alert">{startError}</p>}
        <UserSearch token={token} onSelect={(u) => void open(u)} />
      </aside>

      <div className="main">
        {peerId ? (
          <ChatWindow key={peerId} engine={engine} peerId={peerId} onBack={() => setPeerId(null)} />
        ) : (
          <section className="card placeholder">
            <h2>Select a conversation</h2>
            <p className="muted">Pick a contact on the left, or search for someone to start an end-to-end encrypted chat.</p>
          </section>
        )}
      </div>
    </div>
  );
}

