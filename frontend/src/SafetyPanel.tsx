import { useEffect, useState, useSyncExternalStore } from "react";
import type { ChatEngine } from "./crypto/engine.ts";

/** 12 groups of 5 digits, laid out as a grid so two people can read it aloud group by group. */
function Digits({ value, label }: { value: string | null; label: string }) {
  if (value === null) return <p className="muted">…</p>;
  return (
    <div className="digits" role="group" aria-label={label}>
      {value.split(" ").map((g, i) => (
        <code key={i}>{g}</code>
      ))}
    </div>
  );
}

function CopyButton({ value }: { value: string | null }) {
  const [done, setDone] = useState(false);
  if (!value) return null;
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setDone(true);
      window.setTimeout(() => setDone(false), 2000);
    } catch {
      setDone(false); // clipboard unavailable: the digits are selectable on screen
    }
  };
  return (
    <button type="button" className="secondary" onClick={() => void copy()}>
      {done ? "Copied" : "Copy number"}
    </button>
  );
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
          <p>
            <strong>New safety number.</strong> Compare it with {contact.displayName} over a channel you trust, such as
            a phone call. If it does not match what they read out, do not accept it.
          </p>
          <Digits value={pending} label="New safety number" />
          <CopyButton value={pending} />
          <p className="muted">Previous number (no longer in use):</p>
          <Digits value={current} label="Previous safety number" />
          <button type="button" onClick={() => void run(() => engine.acceptKeyChange(peerId))}>
            Accept the new key (stays unverified)
          </button>
        </>
      ) : current ? (
        <>
          <p>
            Compare these digits with {contact.displayName} over a channel you trust. If they match exactly, nobody is
            intercepting this conversation.
          </p>
          <Digits value={current} label="Safety number" />
          <CopyButton value={current} />
          <button type="button" onClick={() => void run(() => engine.setVerified(peerId, !contact.verified))}>
            {contact.verified ? "Remove verified mark" : "They match: mark as verified"}
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
