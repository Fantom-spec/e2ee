// TEST DOUBLES. Nothing in this file is cryptography.
//
// FakeCipher mimics the *behaviour* the engine depends on (sessions, pinned
// identities, replay and tamper rejection) so the engine's own logic can be
// tested on its own. It protects nothing. Real encryption is tested separately
// against the actual Signal library in tests/signal/ (run with npm run test:signal).

import { fromBase64, toBase64, utf8 } from "../../src/crypto/bytes.ts";
import { CipherError, IdentityChangedError } from "../../src/crypto/cipher.ts";
import type { CipherBackend, PeerBundle } from "../../src/crypto/cipher.ts";
import { ChatEngine } from "../../src/crypto/engine.ts";
import type { BundleResponse, DirectoryApi, EngineDeps, KeyUploadBody, PublicUser } from "../../src/crypto/engine.ts";
import type { StoredKeyPair, VaultState } from "../../src/crypto/state.ts";

function randomKey(len = 33): string {
  const b = new Uint8Array(len);
  crypto.getRandomValues(b);
  return toBase64(b);
}

function fakeMac(sid: string, n: number, payload: string): string {
  let h = 17;
  for (const ch of `${sid}|${n}|${payload}`) h = (h * 31 + ch.charCodeAt(0)) >>> 0;
  return h.toString(16);
}

interface FakeSession {
  sid: string;
  initiator: boolean;
  pendingPreKey: boolean;
  sendN: number;
  seen: number[];
}

export interface FakeCipherStats {
  decryptCalls: number;
}

export function makeFakeCipher(stats: FakeCipherStats) {
  return (getState: () => VaultState): CipherBackend => {
    const sessions = (): Record<string, FakeSession> => getState().sessions as unknown as Record<string, FakeSession>;
    const pinned = (peerId: string): string | undefined => getState().contacts[peerId]?.identityKey;
    return {
      async generateIdentity() {
        const identity: StoredKeyPair = { pub: randomKey(), priv: randomKey(32) };
        return { registrationId: Math.floor(Math.random() * 16000), identity };
      },
      async generateSignedPreKey() {
        return { keyPair: { pub: randomKey(), priv: randomKey(32) }, signature: randomKey(64) };
      },
      async generatePreKey() {
        return { pub: randomKey(), priv: randomKey(32) };
      },
      async hasSession(peerId) {
        return sessions()[peerId] !== undefined;
      },
      async processBundle(peerId: string, bundle: PeerBundle) {
        const key = toBase64(bundle.identityKey);
        const pin = pinned(peerId);
        if (pin !== undefined && pin !== key) throw new IdentityChangedError(peerId, key);
        const c = getState().contacts[peerId];
        if (c) c.identityKey ??= key;
        sessions()[peerId] = { sid: randomKey(8), initiator: true, pendingPreKey: true, sendN: 0, seen: [] };
      },
      async encrypt(peerId, plaintext) {
        const s = sessions()[peerId];
        if (!s) throw new CipherError("no session");
        const n = s.sendN++;
        const p = toBase64(plaintext);
        const body = utf8.encode(JSON.stringify({ sid: s.sid, n, from: getState().identity.pub, p, mac: fakeMac(s.sid, n, p) }));
        return { type: s.pendingPreKey ? 3 : 1, body };
      },
      async decrypt(peerId, type, body) {
        stats.decryptCalls++;
        let j: { sid: string; n: number; from: string; p: string; mac: string };
        try {
          j = JSON.parse(utf8.decode(body));
          if (fakeMac(j.sid, j.n, j.p) !== j.mac) throw new Error("mac");
        } catch {
          throw new CipherError("authentication failed");
        }
        if (type === 3) {
          const pin = pinned(peerId);
          if (pin !== undefined && pin !== j.from) throw new IdentityChangedError(peerId, j.from);
          const c = getState().contacts[peerId];
          if (c) c.identityKey ??= j.from;
          const existing = sessions()[peerId];
          if (!existing || existing.sid !== j.sid) {
            sessions()[peerId] = { sid: j.sid, initiator: false, pendingPreKey: false, sendN: 0, seen: [] };
          }
        }
        const s = sessions()[peerId];
        if (!s || s.sid !== j.sid) throw new CipherError("no session");
        if (s.seen.includes(j.n)) throw new CipherError("duplicate message");
        s.seen.push(j.n);
        if (type === 1) s.pendingPreKey = false;
        return fromBase64(j.p);
      },
      deleteSession(peerId) {
        delete sessions()[peerId];
      },
    };
  };
}

// --- fake relay + key directory (mirrors the real server's rules) -----------

interface ServerUser {
  profile: PublicUser;
  engine?: ChatEngine;
  online: boolean;
  identity?: { registration_id: number; identity_public: string; key_version: number; spk: KeyUploadBody["signed_prekey"] };
  otps: Array<{ id: number; public: string }>;
}

interface QueuedMessage {
  id: string;
  from: string;
  to: string;
  envelope: string | null; // null once acknowledged
  delivered: boolean;
}

export class FakeServer {
  users = new Map<string, ServerUser>();
  messages: QueuedMessage[] = [];
  frames: Array<{ from: string; frame: Record<string, unknown> }> = []; // everything clients sent
  log: Array<{ id: string; from: string; to: string; envelope: string }> = []; // every envelope ever relayed
  /** Active-attacker hook: rewrite envelopes in transit to recipients. */
  tamper: ((envelope: string) => string) | null = null;
  private tasks: Array<() => Promise<void>> = [];

  addUser(id: string, username: string): void {
    this.users.set(id, { profile: { id, username, display_name: username[0].toUpperCase() + username.slice(1) }, online: false, otps: [] });
  }

  api(userId: string): DirectoryApi {
    const me = () => this.users.get(userId)!;
    return {
      publishKeys: async (body) => {
        const u = me();
        const changed = u.identity !== undefined && u.identity.identity_public !== body.identity_public;
        const version = u.identity === undefined ? 1 : u.identity.key_version + (changed ? 1 : 0);
        if (changed) u.otps = [];
        u.identity = { registration_id: body.registration_id, identity_public: body.identity_public, key_version: version, spk: body.signed_prekey };
        for (const k of body.one_time_prekeys) if (!u.otps.some((o) => o.id === k.id)) u.otps.push(k);
        return { identity_changed: changed, key_version: version, one_time_prekeys_remaining: u.otps.length };
      },
      keyStatus: async () => {
        const u = me();
        return { has_keys: u.identity !== undefined, key_version: u.identity?.key_version ?? null, one_time_prekeys_remaining: u.otps.length };
      },
      fetchBundle: async (target) => {
        const t = this.users.get(target);
        if (!t?.identity) throw Object.assign(new Error("No keys"), { status: 404 });
        const otp = t.otps.shift() ?? null;
        const b: BundleResponse = {
          user_id: target, registration_id: t.identity.registration_id, identity_public: t.identity.identity_public,
          key_version: t.identity.key_version, signed_prekey: t.identity.spk, one_time_prekey: otp,
        };
        return b;
      },
      fetchIdentity: async (target) => {
        const t = this.users.get(target);
        if (!t?.identity) throw Object.assign(new Error("No keys"), { status: 404 });
        return { identity_public: t.identity.identity_public, key_version: t.identity.key_version };
      },
      fetchUser: async (target) => {
        const t = this.users.get(target);
        if (!t) throw Object.assign(new Error("not found"), { status: 404 });
        return t.profile;
      },
    };
  }

  /** The relay as seen from one client's socket. */
  sendFrameFor(userId: string): (frame: Record<string, unknown>) => boolean {
    return (frame) => {
      const u = this.users.get(userId)!;
      if (!u.online) return false;
      this.frames.push({ from: userId, frame });
      this.tasks.push(async () => this.relay(userId, frame));
      return true;
    };
  }

  private deliver(to: string, frame: Record<string, unknown>): void {
    const u = this.users.get(to)!;
    if (u.online && u.engine) this.tasks.push(async () => u.engine!.handleFrame(frame));
  }

  private async relay(from: string, frame: Record<string, unknown>): Promise<void> {
    if (frame.type === "send") {
      const id = frame.id as string;
      const to = frame.to as string;
      const existing = this.messages.find((m) => m.from === from && m.id === id);
      if (!existing) {
        this.messages.push({ id, from, to, envelope: frame.envelope as string, delivered: false });
        this.log.push({ id, from, to, envelope: frame.envelope as string });
      }
      this.deliver(from, { type: "accepted", id, duplicate: existing !== undefined });
      if (!existing) {
        const env = this.tamper ? this.tamper(frame.envelope as string) : frame.envelope;
        this.deliver(to, { type: "message", id, from, envelope: env, created_at: 0 });
      }
    } else if (frame.type === "ack") {
      const m = this.messages.find((x) => x.id === frame.id && x.from === frame.from && x.to === from && !x.delivered);
      if (m) {
        m.delivered = true;
        m.envelope = null; // the relay erases ciphertext on acknowledgement
        this.deliver(m.from, { type: "delivered", id: m.id });
      }
    }
  }

  async connect(userId: string): Promise<void> {
    const u = this.users.get(userId)!;
    u.online = true;
    const pending = this.messages.filter((m) => m.to === userId && !m.delivered && m.envelope !== null);
    this.deliver(userId, { type: "ready", user_id: userId, pending: pending.length });
    for (const m of pending) this.deliver(userId, { type: "message", id: m.id, from: m.from, envelope: m.envelope, created_at: 0 });
    await this.flush();
  }

  disconnect(userId: string): void {
    const u = this.users.get(userId)!;
    u.online = false;
    u.engine?.onDisconnected();
  }

  async flush(): Promise<void> {
    while (this.tasks.length > 0) await this.tasks.shift()!();
  }
}

// --- convenience: build a client wired to the fake server -------------------

export interface TestClient {
  id: string;
  engine: ChatEngine;
  stats: FakeCipherStats;
  persisted: { json: string | null; calls: number };
  /** The last persisted state at the moment each ack frame was sent. */
  ackSnapshots: Array<string | null>;
  /** Make the n-th next persist call fail (1 = the very next one). */
  failPersistAt: { n: number | null };
  deps: EngineDeps;
}

let counter = 0;
/** Tests move this forward to let the engine's identity-check throttle expire. */
export const clock = { skewMs: 0 };

export async function makeClient(
  server: FakeServer,
  id: string,
  username: string,
  restoreFrom?: string,
  makeBackend?: EngineDeps["makeBackend"], // pass the real Signal backend for tests/signal
): Promise<TestClient> {
  if (!server.users.has(id)) server.addUser(id, username);
  const stats: FakeCipherStats = { decryptCalls: 0 };
  const persisted = { json: null as string | null, calls: 0 };
  const failPersistAt = { n: null as number | null };
  const ackSnapshots: Array<string | null> = [];
  const deps: EngineDeps = {
    userId: id,
    api: server.api(id),
    makeBackend: makeBackend ?? makeFakeCipher(stats),
    persist: async (json) => {
      persisted.calls++;
      if (failPersistAt.n !== null) {
        failPersistAt.n--;
        if (failPersistAt.n <= 0) {
          failPersistAt.n = null;
          throw new Error("disk full");
        }
      }
      persisted.json = json;
    },
    sendFrame: (frame) => {
      if (frame.type === "ack") ackSnapshots.push(persisted.json);
      return server.sendFrameFor(id)(frame);
    },
    now: () => 1_800_000_000_000 + ++counter * 1000 + clock.skewMs,
    newId: () => crypto.randomUUID(),
  };
  const engine = restoreFrom ? ChatEngine.fromJson(deps, restoreFrom) : await ChatEngine.createFresh(deps);
  server.users.get(id)!.engine = engine;
  return { id, engine, stats, persisted, ackSnapshots, failPersistAt, deps };
}

export const ALICE = "00000000-0000-4000-8000-00000000000a";
export const BOB = "00000000-0000-4000-8000-00000000000b";
export const CAROL = "00000000-0000-4000-8000-00000000000c";
