// Everything the client must remember between sessions. The whole object is
// serialised to JSON and encrypted by the Vault before it touches IndexedDB.

export interface StoredKeyPair {
  pub: string; // base64
  priv: string; // base64 (secret!)
}

export interface Contact {
  userId: string;
  username: string;
  displayName: string;
  /** Pinned identity public key (base64), set on first contact (trust on first use). */
  identityKey?: string;
  keyVersion?: number;
  /** The user compared safety numbers out of band and confirmed they match. */
  verified: boolean;
  verifiedKey?: string;
  /** A different identity key was seen; sending is blocked until the user accepts it. */
  keyChange?: { newKey: string; keyVersion?: number; detectedAt: number };
  lastIdentityCheck?: number;
}

export type MessageStatus = "sending" | "sent" | "delivered" | "failed" | "received";

export interface MessageRecord {
  id: string;
  kind: "message" | "system";
  dir: "in" | "out";
  text: string;
  /** Local time of sending or receipt (sender-supplied times are not trusted for ordering). */
  ts: number;
  status: MessageStatus;
  /** Outgoing only: the already-encrypted envelope, kept until the relay accepts it so a
   *  retry re-sends the SAME ciphertext instead of advancing the ratchet again. */
  envelope?: string;
}

export interface QuarantinedMessage {
  id: string;
  from: string;
  envelope: string;
  receivedAt: number;
}

export interface VaultState {
  v: 1;
  userId: string;
  registrationId: number;
  identity: StoredKeyPair;
  preKeys: Record<string, StoredKeyPair>;
  signedPreKeys: Record<string, StoredKeyPair>;
  signedPreKeySignatures: Record<string, string>;
  signedPreKeyId: number;
  nextPreKeyId: number;
  /** One-time prekey ids the server has accepted (never uploaded twice). */
  uploadedPreKeyIds: number[];
  /** Key version the server reported when we last published; detects replacement from elsewhere. */
  publishedKeyVersion: number | null;
  sessions: Record<string, string>;
  contacts: Record<string, Contact>;
  messages: Record<string, MessageRecord[]>;
  /** Per sender: ids already handled, so redelivered messages are never decrypted twice. */
  processed: Record<string, string[]>;
  quarantine: QuarantinedMessage[];
}

export class StateError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "StateError";
  }
}

export const MAX_PROCESSED_PER_SENDER = 5000;
export const MAX_QUARANTINE = 100;

function isRecord(x: unknown): x is Record<string, unknown> {
  return typeof x === "object" && x !== null && !Array.isArray(x);
}

/** Parse decrypted vault contents; reject anything that is not our own format. */
export function parseState(json: string, expectedUserId: string): VaultState {
  let raw: unknown;
  try {
    raw = JSON.parse(json);
  } catch {
    throw new StateError("stored state is not valid JSON");
  }
  if (!isRecord(raw) || raw.v !== 1) throw new StateError("stored state has an unsupported version");
  if (raw.userId !== expectedUserId) throw new StateError("stored state belongs to a different account");
  for (const field of ["preKeys", "signedPreKeys", "signedPreKeySignatures", "sessions", "contacts", "messages", "processed"]) {
    if (!isRecord(raw[field])) throw new StateError(`stored state is missing ${field}`);
  }
  if (!isRecord(raw.identity) || typeof raw.identity.pub !== "string" || typeof raw.identity.priv !== "string") {
    throw new StateError("stored state has no identity key");
  }
  if (typeof raw.registrationId !== "number" || !Array.isArray(raw.uploadedPreKeyIds) || !Array.isArray(raw.quarantine)) {
    throw new StateError("stored state is incomplete");
  }
  return raw as unknown as VaultState;
}

/** The Signal library addresses sessions as "name.deviceId"; we use the bare user id. */
export function peerOf(address: string): string {
  const i = address.lastIndexOf(".");
  return i === -1 ? address : address.slice(0, i);
}
