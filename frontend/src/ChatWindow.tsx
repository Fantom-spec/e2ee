import { FormEvent, useEffect, useRef, useState, useSyncExternalStore } from "react";
import type { ChatEngine } from "./crypto/engine.ts";
import SafetyPanel from "./SafetyPanel";

const STATUS_LABEL: Record<string, string> = {
  sending: "sending…",
  sent: "sent",
  delivered: "delivered",
  failed: "failed",
  received: "",
};

export default function ChatWindow({ engine, peerId, onBack }: { engine: ChatEngine; peerId: string; onBack: () => void }) {
  useSyncExternalStore(engine.subscribe, engine.getVersion);
  const [text, setText] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [showSafety, setShowSafety] = useState(false);
  const bottom = useRef<HTMLDivElement>(null);
  const contact = engine.contact(peerId);
  const messages = engine.messagesFor(peerId);

  useEffect(() => {
    void engine.refreshPeerIdentity(peerId);
  }, [engine, peerId]);
  useEffect(() => {
    bottom.current?.scrollIntoView?.({ block: "end" });
  }, [messages.length]);

  if (!contact) return null;
  const blocked = contact.keyChange !== undefined;

  const send = async (e: FormEvent) => {
    e.preventDefault();
    const body = text.trim();
    if (!body) return;
    setError(null);
    try {
      await engine.sendMessage(peerId, body);
      setText("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not send");
      if (contact.keyChange) setShowSafety(true);
    }
  };

  return (
    <section className="card chat">
      <header className="chat-head">
        <button type="button" className="link back" onClick={onBack}>← Back</button>
        <strong>{contact.displayName}</strong> <span className="muted">@{contact.username}</span>
        <span className={contact.verified ? "ok" : "muted"}>{contact.verified ? "✔ verified" : "not verified"}</span>
        <button type="button" onClick={() => setShowSafety((s) => !s)}>Safety number</button>
      </header>

      {blocked && (
        <p className="banner danger" role="alert">
          {contact.displayName}'s safety number changed. This can mean they reinstalled or switched
          browser, or that someone is impersonating them. Sending is blocked until you review it.
        </p>
      )}
      {showSafety && <SafetyPanel engine={engine} peerId={peerId} />}

      <div className="messages" aria-live="polite">
        {messages.length === 0 && <p className="muted">No messages yet. Say hello.</p>}
        {messages.map((m) =>
          m.kind === "system" ? (
            <p key={m.id} className="sys">{m.text}</p>
          ) : (
            <div key={m.id} className={`msg ${m.dir === "out" ? "out" : "in"}${m.status === "failed" ? " failed" : ""}`}>
              <span>{m.text}</span>
              <small>
                {new Date(m.ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })} {STATUS_LABEL[m.status]}
              </small>
            </div>
          ),
        )}
        <div ref={bottom} />
      </div>

      {error && <p className="err" role="alert">{error}</p>}
      <form onSubmit={(e) => void send(e)} className="row">
        <input
          value={text}
          onChange={(e) => setText(e.target.value)}
          placeholder={blocked ? "Review the safety number first" : "Type a message"}
          aria-label="Message"
          maxLength={4000}
          disabled={blocked || engine.hasFailed}
        />
        <button type="submit" disabled={blocked || engine.hasFailed || !text.trim()}>Send</button>
      </form>
      <p className="hint">{engine.isOnline ? "Connected" : "Offline: messages are stored encrypted and sent when you reconnect."}</p>
    </section>
  );
}
