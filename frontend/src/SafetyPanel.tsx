import { useEffect, useState, useSyncExternalStore } from "react";
import type { ChatEngine } from "./crypto/engine.ts";

function Digits({ value }: { value: string | null }) {
  return <code className="digits">{value ?? "…"}</code>;
}

export default function SafetyPanel({ engine, peerId }: { engine: ChatEngine; peerId: string }) {
  useSyncExternalStore(engine.subscribe, engine.getVersion);
  const contact = engine.contact(peerId);
  const [current, setCurrent] = useState<string | null>(null);
  const [pending, setPending] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const changed = contact?.keyChange !== undefined;
  const key = `${contact?.identityKey}|${contact?.keyChange?.newKey}`;

  useEffect(() => {
    let live = true;
    void engine.getSafetyNumber(peerId, "current").then((v) => live && setCurrent(v));
    void engine.getSafetyNumber(peerId, "pending").then((v) => live && setPending(v));
    return () => {
      live = false;
    };
  }, [engine, peerId, key]);

  if (!contact) return null;
  const run = async (fn: () => Promise<void>) => {
    setErr(null);
    try {
      await fn();
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Failed");
    }
  };

  return (
    <div className="safety">
      {changed ? (
        <>
          <p><strong>New safety number</strong> (the contact's key changed). Compare it with {contact.displayName} over a channel you trust, such as a call:</p>
          <Digits value={pending} />
          <p className="muted">Previously: <Digits value={current} /></p>
          <button type="button" onClick={() => void run(() => engine.acceptKeyChange(peerId))}>
            Accept the new key (unverified)
          </button>
        </>
      ) : current ? (
        <>
          <p>Compare these digits with {contact.displayName} over a channel you trust. If they match, nobody is intercepting this conversation.</p>
          <Digits value={current} />
          <button type="button" onClick={() => void run(() => engine.setVerified(peerId, !contact.verified))}>
            {contact.verified ? "Remove verified mark" : "Mark as verified"}
          </button>
        </>
      ) : (
        <p className="muted">No safety number yet. It appears after the first message is exchanged.</p>
      )}
      {err && <p className="err" role="alert">{err}</p>}
      <p className="hint">This is SecureChat's own comparison number, not Signal's. It only matches on SecureChat.</p>
    </div>
  );
}
