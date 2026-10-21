import { FormEvent, useEffect, useRef, useState, useSyncExternalStore } from "react";
import type { ChatEngine } from "./crypto/engine.ts";
import SafetyPanel from "./SafetyPanel";

// Status is shown as symbol + word (never colour alone) and has a spoken label.
const STATUS: Record<string, { mark: string; label: string }> = {
  sending: { mark: "…", label: "sending" },
  sent: { mark: "✓", label: "sent to relay" },
  delivered: { mark: "✓✓", label: "delivered" },
  failed: { mark: "⚠", label: "failed, not delivered" },
  received: { mark: "", label: "" },
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
    void engine.refreshPeerIdentity(peerId); const timer = window.setInterval(() => void engine.refreshPeerIdentity(peerId), 15000);
  return () => window.clearInterval(timer); }, [engine, peerId]);
  useEffect(() => {
    bottom.current?.scrollIntoView?.({ block: "end" });
  }, [messages.length]);

  if (!contact) return null;
  const blocked = contact.keyChange !== undefined;
  const unverified = !blocked && !contact.verified;

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
      if (engine.contact(peerId)?.keyChange) setShowSafety(true);
    }
  };

  return (
    <section className="card chat">
      <header className="chat-head">
        <button type="button" className="secondary back" onClick={onBack} aria-label="Back to conversations">← Back</button>
        <div className="who">
          <strong>{contact.displayName}</strong> <span className="muted">@{contact.username}</span>
        </div>
        {blocked ? (
          <span className="badge danger">⚠ key changed</span>
        ) : contact.verified ? (
          <span className="badge ok">✔ verified</span>
        ) : (
          <span className="badge warn">unverified</span>
        )}
        <button type="button" className="secondary" aria-expanded={showSafety} onClick={() => setShowSafety((s) => !s)}>
          Safety number
        </button>
      </header>

      {blocked && (
        <div className="banner danger" role="alert">
          <strong>{contact.displayName}'s safety number changed.</strong> This can mean they reinstalled or switched
          browser, or that someone is impersonating them. Sending is blocked and new messages from them are held
          until you review the new number.
          {!showSafety && (
            <div><button type="button" onClick={() => setShowSafety(true)}>Review the new safety number</button></div>
          )}
        </div>
      )}
      {unverified && (
        <div className="banner" role="note">
          You have not verified {contact.displayName}'s safety number. Messages are encrypted, but nothing yet rules
          out that someone is intercepting this conversation.
          {!showSafety && contact.identityKey && (
            <div><button type="button" className="secondary" onClick={() => setShowSafety(true)}>Verify now</button></div>
          )}
        </div>
      )}
      {showSafety && <SafetyPanel engine={engine} peerId={peerId} />}

      <div className="messages" role="log" aria-live="polite" aria-label={`Messages with ${contact.displayName}`}>
        {messages.length === 0 && <p className="muted">No messages yet. Say hello.</p>}
        {messages.map((m) =>
          m.kind === "system" ? (
            <p key={m.id} className="sys">{m.text}</p>
          ) : (
            <div key={m.id} className={`msg ${m.dir === "out" ? "out" : "in"}${m.status === "failed" ? " failed" : ""}`}>
              <span>{m.text}</span>
              <small>
                {new Date(m.ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
                {m.dir === "out" && STATUS[m.status]?.label && (
                  <span className="status" title={STATUS[m.status].label}>
                    {" "}<span aria-hidden="true">{STATUS[m.status].mark}</span> {STATUS[m.status].label}
                  </span>
                )}
              </small>
            </div>
          ),
        )}
        <div ref={bottom} />
      </div>

      {error && <p className="err" role="alert">{error}</p>}
      <form onSubmit={(e) => void send(e)} className="row composer">
        <input
          value={text}
          onChange={(e) => setText(e.target.value)}
          placeholder={blocked ? "Review the safety number first" : "Type a message"}
          aria-label="Message"
          maxLength={4000}
          autoComplete="off"
          enterKeyHint="send"
          disabled={blocked || engine.hasFailed}
        />
        <button type="submit" disabled={blocked || engine.hasFailed || !text.trim()}>Send</button>
      </form>
      <p className="hint">{engine.isOnline ? "Connected" : "Offline: messages are stored encrypted and sent when you reconnect."}</p>
    </section>
  );
}
