import { useEffect, useMemo, useState, useSyncExternalStore } from "react";
import { directoryApi, User } from "./api";
import ChatWindow from "./ChatWindow";
import type { ChatEngine } from "./crypto/engine.ts";
import { openEngine } from "./crypto/session.ts";
import UserSearch from "./UserSearch";
import { RelayLink, RelayStatus, useRelay } from "./useRelay";

const STATUS_TEXT: Record<RelayStatus, string> = {
  connecting: "Connecting to relay…",
  online: "Relay connected",
  offline: "Relay disconnected, retrying…",
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
  if (!engine) return <p>Unlocking your encryption keys…</p>;

  return (
    <Ready engine={engine} token={token} user={user} status={status} peerId={peerId} setPeerId={setPeerId} onLogout={onLogout} />
  );
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

  return (
    <>
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

      {peerId ? (
        <ChatWindow engine={engine} peerId={peerId} onBack={() => setPeerId(null)} />
      ) : (
        <>
          <section className="card">
            <h2>Conversations</h2>
            {engine.conversations().length === 0 && <p className="muted">None yet. Find someone below.</p>}
            <ul className="list">
              {engine.conversations().map(({ contact, last }) => (
                <li key={contact.userId}>
                  <button type="button" className="link" onClick={() => setPeerId(contact.userId)}>
                    <strong>{contact.displayName}</strong> <span className="muted">@{contact.username}</span>
                    {contact.keyChange && <span className="err"> ⚠ safety number changed</span>}
                    {last && last.kind === "message" && <div className="muted preview">{last.dir === "out" ? "You: " : ""}{last.text.slice(0, 60)}</div>}
                  </button>
                </li>
              ))}
            </ul>
          </section>
          {startError && <p className="err" role="alert">{startError}</p>}
          <UserSearch token={token} onSelect={(u) => void open(u)} />
        </>
      )}
    </>
  );
}
