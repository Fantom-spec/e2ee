// Chat engine: everything between "the UI wants to send/read" and "bytes go to the relay".
//
// Responsibilities (and the rules this file enforces):
//  * All state-changing work runs one-at-a-time (runExclusive). Two overlapping
//    encrypt/decrypt calls on the same session could corrupt the ratchet.
//  * PERSIST BEFORE ACK / SEND: a received message is decrypted, written to the
//    encrypted local store, and only then acknowledged to the relay. An outgoing
//    message is encrypted and stored (with its ciphertext) before it is sent, so
//    a crash or dropped connection re-sends the SAME ciphertext rather than
//    re-encrypting and advancing the ratchet again.
//  * Duplicates are dropped by (sender, message id) before any decryption.
//  * Messages that fail authentication/decryption are discarded and never shown.
//    They are still acknowledged, so a bad message cannot be redelivered forever.
//  * Identity keys are pinned on first contact (trust on first use). A different
//    key blocks sending and quarantines incoming messages until the user
//    explicitly accepts the change.
//  * If local storage fails, the engine stops (fails closed) instead of
//    continuing with state that was not saved.

import { fromBase64 } from "./bytes.ts";
import { CipherError, IdentityChangedError } from "./cipher.ts";
import type { CipherBackend, PeerBundle } from "./cipher.ts";
import { decodeEnvelope, decodePlaintext, encodeEnvelope, encodePlaintext } from "./envelope.ts";
import { safetyNumber } from "./fingerprint.ts";
import { MAX_PROCESSED_PER_SENDER, MAX_QUARANTINE, parseState } from "./state.ts";
import type { Contact, MessageRecord, StoredKeyPair, VaultState } from "./state.ts";

export const INITIAL_PREKEYS = 50;
export const LOW_WATER_PREKEYS = 20;
export const REFILL_PREKEYS = 50;
export const IDENTITY_CHECK_INTERVAL_MS = 10_000;
const UPLOAD_CHUNK = 100;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export class EngineError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EngineError";
  }
}

export class KeyChangedError extends EngineError {
  peerId: string;
  constructor(peerId: string) {
    super("This contact's safety number changed. Review and accept the new key before sending.");
    this.name = "KeyChangedError";
    this.peerId = peerId;
  }
}

// --- what the engine needs from the outside world -------------------------

export interface PublicUser {
  id: string;
  username: string;
  display_name: string;
}

export interface BundleResponse {
  user_id: string;
  registration_id: number;
  identity_public: string;
  key_version: number;
  signed_prekey: { id: number; public: string; signature: string };
  one_time_prekey: { id: number; public: string } | null;
}

export interface KeyUploadBody {
  registration_id: number;
  identity_public: string;
  signed_prekey: { id: number; public: string; signature: string };
  one_time_prekeys: Array<{ id: number; public: string }>;
}

export interface DirectoryApi {
  publishKeys(body: KeyUploadBody): Promise<{ identity_changed: boolean; key_version: number; one_time_prekeys_remaining: number }>;
  keyStatus(): Promise<{ has_keys: boolean; key_version: number | null; one_time_prekeys_remaining: number }>;
  fetchBundle(userId: string): Promise<BundleResponse>;
  fetchIdentity(userId: string): Promise<{ identity_public: string; key_version: number }>;
  fetchUser(userId: string): Promise<PublicUser>;
}

export interface EngineDeps {
  userId: string;
  api: DirectoryApi;
  makeBackend: (getState: () => VaultState) => CipherBackend;
  /** Receives the serialised state; the caller encrypts and stores it. Must reject on failure. */
  persist: (stateJson: string) => Promise<void>;
  /** Returns false if the socket is not open. */
  sendFrame: (frame: Record<string, unknown>) => boolean;
  now: () => number;
  newId: () => string;
}

export interface ConversationSummary {
  contact: Contact;
  last: MessageRecord | undefined;
}

function toPeerBundle(b: BundleResponse): PeerBundle {
  try {
    return {
      registrationId: b.registration_id,
      identityKey: fromBase64(b.identity_public),
      signedPreKey: {
        id: b.signed_prekey.id,
        publicKey: fromBase64(b.signed_prekey.public),
        signature: fromBase64(b.signed_prekey.signature),
      },
      oneTimePreKey: b.one_time_prekey
        ? { id: b.one_time_prekey.id, publicKey: fromBase64(b.one_time_prekey.public) }
        : undefined,
    };
  } catch {
    throw new EngineError("The server returned an invalid key bundle.");
  }
}

export class ChatEngine {
  private readonly deps: EngineDeps;
  private readonly s: VaultState;
  private readonly backend: CipherBackend;
  private readonly listeners = new Set<() => void>();
  private chain: Promise<unknown> = Promise.resolve();
  private versionCounter = 0;
  private online = false;
  private failure: Error | null = null;
  private noticeText: string | null = null;

  private constructor(deps: EngineDeps, state: VaultState) {
    this.deps = deps;
    this.s = state;
    this.backend = deps.makeBackend(() => this.s);
  }

  /** First run for this account on this browser: generate keys and persist them. */
  static async createFresh(deps: EngineDeps): Promise<ChatEngine> {
    const generator = deps.makeBackend(() => {
      throw new EngineError("state is not available yet");
    });
    const { registrationId, identity } = await generator.generateIdentity();
    const signedPreKeyId = 1;
    const spk = await generator.generateSignedPreKey(identity, signedPreKeyId);
    const preKeys: Record<string, StoredKeyPair> = {};
    for (let id = 1; id <= INITIAL_PREKEYS; id++) preKeys[String(id)] = await generator.generatePreKey(id);
    const state: VaultState = {
      v: 1,
      userId: deps.userId,
      registrationId,
      identity,
      preKeys,
      signedPreKeys: { [String(signedPreKeyId)]: spk.keyPair },
      signedPreKeySignatures: { [String(signedPreKeyId)]: spk.signature },
      signedPreKeyId,
      nextPreKeyId: INITIAL_PREKEYS + 1,
      uploadedPreKeyIds: [],
      publishedKeyVersion: null,
      sessions: {},
      contacts: {},
      messages: {},
      processed: {},
      quarantine: [],
    };
    const engine = new ChatEngine(deps, state);
    await engine.save(); // keys are stored locally BEFORE anything is published
    return engine;
  }

  static fromJson(deps: EngineDeps, json: string): ChatEngine {
    return new ChatEngine(deps, parseState(json, deps.userId));
  }

  // --- observation (used by React via useSyncExternalStore) ---------------

  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  };
  getVersion = (): number => this.versionCounter;

  private emit(): void {
    this.versionCounter++;
    for (const l of [...this.listeners]) l();
  }

  get isOnline(): boolean {
    return this.online;
  }
  get notice(): string | null {
    return this.noticeText;
  }
  get hasFailed(): boolean {
    return this.failure !== null;
  }
  get ownIdentityKey(): string {
    return this.s.identity.pub;
  }

  contact(peerId: string): Contact | undefined {
    return this.s.contacts[peerId];
  }

  messagesFor(peerId: string): readonly MessageRecord[] {
    return this.s.messages[peerId] ?? [];
  }

  conversations(): ConversationSummary[] {
    const out: ConversationSummary[] = [];
    for (const contact of Object.values(this.s.contacts)) {
      const list = this.s.messages[contact.userId] ?? [];
      out.push({ contact, last: list[list.length - 1] });
    }
    return out.sort((a, b) => (b.last?.ts ?? 0) - (a.last?.ts ?? 0));
  }

  async getSafetyNumber(peerId: string, which: "current" | "pending" = "current"): Promise<string | null> {
    const c = this.s.contacts[peerId];
    const peerKey = which === "pending" ? c?.keyChange?.newKey : c?.identityKey;
    if (!c || !peerKey) return null;
    return safetyNumber(
      { userId: this.deps.userId, identityKey: fromBase64(this.s.identity.pub) },
      { userId: peerId, identityKey: fromBase64(peerKey) },
    );
  }

  // --- plumbing ------------------------------------------------------------

  private runExclusive<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.chain.then(() => {
      if (this.failure) throw this.failure;
      return fn();
    });
    this.chain = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  private async save(): Promise<void> {
    try {
      await this.deps.persist(JSON.stringify(this.s));
    } catch {
      this.failure = new EngineError("Could not save to this browser's storage. Reload the page and log in again.");
      this.emit();
      throw this.failure;
    }
  }

  private ack(from: string, id: string): void {
    this.deps.sendFrame({ type: "ack", id, from });
  }

  private transmit(peerId: string, rec: MessageRecord): void {
    if (rec.envelope) this.deps.sendFrame({ type: "send", id: rec.id, to: peerId, envelope: rec.envelope });
  }

  private addSystem(peerId: string, text: string): void {
    (this.s.messages[peerId] ??= []).push({
      id: `sys-${this.deps.newId()}`, kind: "system", dir: "in", text, ts: this.deps.now(), status: "received",
    });
  }

  private hasProcessed(from: string, id: string): boolean {
    return (this.s.processed[from] ?? []).includes(id);
  }

  private markProcessed(from: string, id: string): void {
    const list = (this.s.processed[from] ??= []);
    list.push(id);
    if (list.length > MAX_PROCESSED_PER_SENDER) list.splice(0, list.length - MAX_PROCESSED_PER_SENDER);
  }

  private async ensureContact(userId: string): Promise<Contact> {
    const existing = this.s.contacts[userId];
    if (existing) return existing;
    let username = "unknown";
    let displayName = "Unknown user";
    try {
      const u = await this.deps.api.fetchUser(userId);
      username = u.username;
      displayName = u.display_name;
    } catch {
      // Keep the placeholder; the profile can be refreshed later.
    }
    const contact: Contact = { userId, username, displayName, verified: false };
    this.s.contacts[userId] = contact;
    this.s.messages[userId] ??= [];
    return contact;
  }

  private flagKeyChange(c: Contact, newKey: string, keyVersion: number | undefined): void {
    if (c.keyChange?.newKey === newKey) return;
    const wasVerified = c.verified;
    c.keyChange = { newKey, keyVersion, detectedAt: this.deps.now() };
    c.verified = false; // an old verification says nothing about the new key
    this.addSystem(
      c.userId,
      wasVerified
        ? `The safety number with ${c.displayName} changed. You had verified this contact, so compare the new number with them before continuing.`
        : `The safety number with ${c.displayName} changed. Compare it with them before continuing.`,
    );
  }

  // --- key publication ------------------------------------------------------

  /** Publish identity/prekeys if needed and top up one-time prekeys. Call after login and on every (re)connect. */
  maintainKeys(): Promise<void> {
    return this.runExclusive(async () => {
      const status = await this.deps.api.keyStatus();

      if (status.has_keys && this.s.publishedKeyVersion !== null && status.key_version !== this.s.publishedKeyVersion) {
        // Someone (another browser logged into this account) replaced our identity. Re-publishing
        // would flip it back and forth, so stop and tell the user.
        this.noticeText =
          "Your encryption keys were replaced from another browser or device. Messages may not be readable here.";
        this.emit();
        return;
      }

      if (!status.has_keys) this.s.uploadedPreKeyIds = [];
      if (status.has_keys && status.one_time_prekeys_remaining < LOW_WATER_PREKEYS) {
        for (let i = 0; i < REFILL_PREKEYS; i++) {
          const id = this.s.nextPreKeyId++;
          this.s.preKeys[String(id)] = await this.backend.generatePreKey(id);
        }
        await this.save(); // new private keys are stored before their public halves are uploaded
      }

      const uploaded = new Set(this.s.uploadedPreKeyIds);
      const pending = Object.keys(this.s.preKeys).map(Number).filter((id) => !uploaded.has(id)).sort((a, b) => a - b);
      if (status.has_keys && pending.length === 0 && this.s.publishedKeyVersion !== null) return;

      const spkId = String(this.s.signedPreKeyId);
      do {
        const chunk = pending.splice(0, UPLOAD_CHUNK);
        const result = await this.deps.api.publishKeys({
          registration_id: this.s.registrationId,
          identity_public: this.s.identity.pub,
          signed_prekey: {
            id: this.s.signedPreKeyId,
            public: this.s.signedPreKeys[spkId].pub,
            signature: this.s.signedPreKeySignatures[spkId],
          },
          one_time_prekeys: chunk.map((id) => ({ id, public: this.s.preKeys[String(id)].pub })),
        });
        for (const id of chunk) uploaded.add(id);
        this.s.uploadedPreKeyIds = [...uploaded];
        this.s.publishedKeyVersion = result.key_version;
        await this.save();
      } while (pending.length > 0);
    });
  }

  // --- conversations ----------------------------------------------------------

  startConversation(user: PublicUser): Promise<void> {
    return this.runExclusive(async () => {
      if (user.id === this.deps.userId) throw new EngineError("You cannot message yourself.");
      const c = this.s.contacts[user.id];
      if (c) {
        c.username = user.username;
        c.displayName = user.display_name;
      } else {
        this.s.contacts[user.id] = { userId: user.id, username: user.username, displayName: user.display_name, verified: false };
      }
      this.s.messages[user.id] ??= [];
      await this.save();
      this.emit();
    });
  }

  /** Compare the contact's current server-side identity with the pinned one. */
  private async checkPeerIdentity(peerId: string, force: boolean): Promise<void> {
    const c = this.s.contacts[peerId];
    const now = this.deps.now();
    if (!force && c.lastIdentityCheck !== undefined && now - c.lastIdentityCheck < IDENTITY_CHECK_INTERVAL_MS) return;
    let ident: { identity_public: string; key_version: number };
    try {
      ident = await this.deps.api.fetchIdentity(peerId);
    } catch (e) {
      if ((e as { status?: number }).status === 404) {
        throw new EngineError(`${c.displayName} has not set up encryption yet. They need to log in once first.`);
      }
      throw e;
    }
    c.lastIdentityCheck = now;
    if (c.identityKey && c.identityKey !== ident.identity_public) this.flagKeyChange(c, ident.identity_public, ident.key_version);
  }

  /** Called when a conversation is opened; network problems are ignored here. */
  refreshPeerIdentity(peerId: string): Promise<void> {
    return this.runExclusive(async () => {
      if (!this.s.contacts[peerId]) return;
      try {
        await this.checkPeerIdentity(peerId, true);
      } catch {
        return;
      }
      await this.save();
      this.emit();
    });
  }

  private async ensureSession(peerId: string): Promise<void> {
    if (await this.backend.hasSession(peerId)) return;
    const c = this.s.contacts[peerId];
    let bundle: BundleResponse;
    try {
      bundle = await this.deps.api.fetchBundle(peerId);
    } catch (e) {
      if ((e as { status?: number }).status === 404) {
        throw new EngineError(`${c.displayName} has not set up encryption yet. They need to log in once first.`);
      }
      throw e;
    }
    if (bundle.user_id !== peerId) throw new EngineError("The server returned keys for the wrong user.");
    if (c.identityKey && c.identityKey !== bundle.identity_public) {
      this.flagKeyChange(c, bundle.identity_public, bundle.key_version);
      await this.save();
      this.emit(); throw new KeyChangedError(peerId);
    }
    try {
      await this.backend.processBundle(peerId, toPeerBundle(bundle));
    } catch (e) {
      if (e instanceof IdentityChangedError) {
        this.flagKeyChange(c, e.newKey, bundle.key_version);
        await this.save();
        this.emit(); throw new KeyChangedError(peerId);
      }
      if (e instanceof CipherError) throw new EngineError("The contact's key bundle failed verification, so no session was created.");
      throw e;
    }
    c.identityKey ??= bundle.identity_public; // trust on first use: pin it
    c.keyVersion = bundle.key_version;
  }

  sendMessage(peerId: string, text: string): Promise<void> {
    return this.runExclusive(async () => {
      const c = this.s.contacts[peerId];
      if (!c) throw new EngineError("Unknown contact.");
      if (c.keyChange) throw new KeyChangedError(peerId);
      const plaintext = encodePlaintext(text, this.deps.now()); // validates length before any state changes
      await this.checkPeerIdentity(peerId, false);
      if (c.keyChange) {
        await this.save();
        this.emit(); throw new KeyChangedError(peerId);
      }
      await this.ensureSession(peerId);
      const { type, body } = await this.backend.encrypt(peerId, plaintext);
      const rec: MessageRecord = {
        id: this.deps.newId(), kind: "message", dir: "out", text, ts: this.deps.now(),
        status: "sending", envelope: encodeEnvelope(type, body),
      };
      (this.s.messages[peerId] ??= []).push(rec);
      await this.save(); // ratchet advance + outbox entry are durable before the network is touched
      this.emit();
      this.transmit(peerId, rec);
    });
  }

  /** Re-send messages the relay has not accepted yet (same ciphertext, same id; the relay de-duplicates). */
  retryPending(): Promise<void> {
    return this.runExclusive(async () => {
      for (const [peerId, list] of Object.entries(this.s.messages)) {
        for (const rec of list) if (rec.dir === "out" && rec.status === "sending") this.transmit(peerId, rec);
      }
    });
  }

  // --- frames from the relay -----------------------------------------------------

  /** Never throws for a storage failure: that state is exposed through hasFailed so the UI can stop. */
  async handleFrame(frame: unknown): Promise<void> {
    try {
      await this.dispatchFrame(frame);
    } catch (e) {
      if (this.failure) return;
      throw e;
    }
  }

  private async dispatchFrame(frame: unknown): Promise<void> {
    if (typeof frame !== "object" || frame === null) return;
    const f = frame as Record<string, unknown>;
    switch (f.type) {
      case "ready":
        this.online = true;
        this.emit();
        await this.onConnected();
        return;
      case "message":
        await this.runExclusive(() => this.receive(f));
        return;
      case "accepted":
      case "delivered":
      case "error":
        await this.runExclusive(() => this.applyReceipt(f));
        return;
      default:
        return;
    }
  }

  onDisconnected(): void {
    this.online = false;
    this.emit();
  }

  private async onConnected(): Promise<void> {
    await this.retryPending();
    try {
      await this.maintainKeys();
    } catch {
      if (this.failure) return;
      this.noticeText = "Could not refresh encryption keys; will retry on the next connection.";
      this.emit();
    }
  }

  private async applyReceipt(f: Record<string, unknown>): Promise<void> {
    if (typeof f.id !== "string") return;
    let changed = false;
    for (const list of Object.values(this.s.messages)) {
      const rec = list.find((m) => m.id === f.id && m.dir === "out");
      if (!rec) continue;
      if (f.type === "accepted" && rec.status === "sending") {
        rec.status = "sent";
        delete rec.envelope;
        changed = true;
      } else if (f.type === "delivered" && (rec.status === "sending" || rec.status === "sent")) {
        rec.status = "delivered";
        delete rec.envelope;
        changed = true;
      } else if (f.type === "error" && rec.status === "sending" && f.code !== "rate_limited") {
        rec.status = "failed"; // the relay refused it permanently; rate limits are retried
        delete rec.envelope;
        changed = true;
      }
      break;
    }
    if (changed) {
      await this.save();
      this.emit();
    }
  }

  private async decryptInto(from: string, id: string, envelope: string, c: Contact): Promise<"stored" | "quarantined" | "discarded"> {
    let decoded;
    try {
      decoded = decodeEnvelope(envelope);
    } catch {
      this.addSystem(from, "A message in an unreadable format was discarded.");
      return "discarded";
    }
    try {
      const plain = await this.backend.decrypt(from, decoded.type, decoded.body);
      const msg = decodePlaintext(plain);
      (this.s.messages[from] ??= []).push({
        id, kind: "message", dir: "in", text: msg.text, ts: this.deps.now(), status: "received",
      });
      return "stored";
    } catch (e) {
      if (e instanceof IdentityChangedError) {
        this.flagKeyChange(c, e.newKey, undefined);
        return "quarantined";
      }
      // Authentication failure, replay, missing session, corrupt content: nothing is shown.
      this.addSystem(from, "A message could not be verified or decrypted and was discarded.");
      return "discarded";
    }
  }

  private async receive(f: Record<string, unknown>): Promise<void> {
    const { id, from, envelope } = f;
    if (typeof id !== "string" || !UUID_RE.test(id) || typeof from !== "string" || !UUID_RE.test(from) || typeof envelope !== "string") {
      return;
    }
    if (from === this.deps.userId) return; // we never receive our own messages
    if (this.hasProcessed(from, id)) {
      this.ack(from, id); // redelivery after a lost ack: do not decrypt twice
      return;
    }
    const contact = await this.ensureContact(from);
    const outcome = await this.decryptInto(from, id, envelope, contact);
    if (outcome === "quarantined") {
      this.s.quarantine.push({ id, from, envelope, receivedAt: this.deps.now() });
      if (this.s.quarantine.length > MAX_QUARANTINE) {
        this.s.quarantine.shift();
        this.addSystem(from, "Too many held messages; the oldest was dropped.");
      }
    }
    this.markProcessed(from, id);
    await this.save(); // durable BEFORE the relay is told it can forget the message
    this.ack(from, id);
    this.emit();
  }

  // --- trust decisions -------------------------------------------------------------

  /** The user accepts the contact's new identity key. Verification and the old session are reset. */
  acceptKeyChange(peerId: string): Promise<void> {
    return this.runExclusive(async () => {
      const c = this.s.contacts[peerId];
      if (!c?.keyChange) return;
      c.identityKey = c.keyChange.newKey;
      c.keyVersion = c.keyChange.keyVersion;
      c.verified = false;
      c.verifiedKey = undefined;
      delete c.keyChange;
      this.backend.deleteSession(peerId);
      this.addSystem(peerId, `You accepted the new safety number for ${c.displayName}. It is not verified.`);

      // Retry messages that were held back because of the unknown key.
      const held = this.s.quarantine.filter((q) => q.from === peerId);
      this.s.quarantine = this.s.quarantine.filter((q) => q.from !== peerId);
      for (const q of held) {
        const outcome = await this.decryptInto(peerId, q.id, q.envelope, c);
        if (outcome === "quarantined") this.s.quarantine.push(q);
      }
      await this.save();
      this.emit();
    });
  }

  /** Record that the user compared safety numbers out of band (or withdraw that). */
  setVerified(peerId: string, verified: boolean): Promise<void> {
    return this.runExclusive(async () => {
      const c = this.s.contacts[peerId];
      if (!c?.identityKey) throw new EngineError("No identity key is pinned for this contact yet.");
      if (c.keyChange) throw new EngineError("Resolve the safety-number change first.");
      c.verified = verified;
      c.verifiedKey = verified ? c.identityKey : undefined;
      await this.save();
      this.emit();
    });
  }
}
