// CipherBackend implemented with @privacyresearch/libsignal-protocol-typescript
// (the Signal protocol: X3DH key agreement + Double Ratchet). All cryptography is
// done by that library; this file only stores its state and maps its calls and
// errors onto our interface. It contains NO cryptographic primitives of its own.
//
// STATUS: written against the library's documented API but NOT executed in the
// development sandbox (no npm access there). tests/signal/*.spec.ts exercise it
// with the real library; run them with `npm run test:signal` before trusting it.

import { Direction, KeyHelper, SessionBuilder, SessionCipher, SignalProtocolAddress } from "@privacyresearch/libsignal-protocol-typescript";
import type { KeyPairType, StorageType } from "@privacyresearch/libsignal-protocol-typescript";

import { binaryStringToBytes, bytesToBinaryString, fromBase64, toArrayBuffer, toBase64 } from "./bytes.ts";
import { CipherError, IdentityChangedError } from "./cipher.ts";
import type { CipherBackend, PeerBundle } from "./cipher.ts";
import { MESSAGE_TYPE_PREKEY, MESSAGE_TYPE_WHISPER } from "./envelope.ts";
import { peerOf } from "./state.ts";
import type { StoredKeyPair, VaultState } from "./state.ts";

const DEVICE_ID = 1;

function toStored(kp: KeyPairType<ArrayBuffer>): StoredKeyPair {
  return { pub: toBase64(new Uint8Array(kp.pubKey)), priv: toBase64(new Uint8Array(kp.privKey)) };
}

function fromStored(kp: StoredKeyPair): KeyPairType<ArrayBuffer> {
  return { pubKey: toArrayBuffer(fromBase64(kp.pub)), privKey: toArrayBuffer(fromBase64(kp.priv)) };
}

function sameBytes(a: ArrayBuffer, b64: string): boolean {
  return toBase64(new Uint8Array(a)) === b64;
}

/**
 * The library's storage interface, backed by the in-memory VaultState (the engine
 * persists that state encrypted). Trust policy = trust on first use: the first
 * identity key seen for a contact is pinned; a different one is refused.
 */
class VaultSignalStore implements StorageType {
  private readonly getState: () => VaultState;
  /** Set when isTrustedIdentity refuses a key, so the caller can raise a typed error. */
  rejection: { peerId: string; newKey: string } | null = null;

  clearRejection(): void {
    this.rejection = null;
  }

  /** Read through a method so control-flow analysis does not assume the value is still null. */
  currentRejection(): { peerId: string; newKey: string } | null {
    return this.rejection;
  }

  constructor(getState: () => VaultState) {
    this.getState = getState;
  }

  private get s(): VaultState {
    return this.getState();
  }

  async getIdentityKeyPair(): Promise<KeyPairType<ArrayBuffer> | undefined> {
    return fromStored(this.s.identity);
  }

  async getLocalRegistrationId(): Promise<number | undefined> {
    return this.s.registrationId;
  }

  async isTrustedIdentity(identifier: string, identityKey: ArrayBuffer, _direction: Direction): Promise<boolean> {
    const peerId = peerOf(identifier);
    const pinned = this.s.contacts[peerId]?.identityKey;
    if (pinned === undefined || sameBytes(identityKey, pinned)) return true;
    this.rejection = { peerId, newKey: toBase64(new Uint8Array(identityKey)) };
    return false;
  }

  async saveIdentity(encodedAddress: string, publicKey: ArrayBuffer): Promise<boolean> {
    const peerId = peerOf(encodedAddress);
    const contact = this.s.contacts[peerId];
    if (!contact) return false;
    if (contact.identityKey === undefined) {
      contact.identityKey = toBase64(new Uint8Array(publicKey)); // pin on first use
      return false;
    }
    return !sameBytes(publicKey, contact.identityKey); // never silently replace a pinned key
  }

  async loadPreKey(encodedAddress: string | number): Promise<KeyPairType<ArrayBuffer> | undefined> {
    const kp = this.s.preKeys[String(encodedAddress)];
    return kp ? fromStored(kp) : undefined;
  }

  async storePreKey(keyId: number | string, keyPair: KeyPairType<ArrayBuffer>): Promise<void> {
    this.s.preKeys[String(keyId)] = toStored(keyPair);
  }

  async removePreKey(keyId: number | string): Promise<void> {
    delete this.s.preKeys[String(keyId)]; // one-time prekeys are single use
  }

  async storeSession(encodedAddress: string, record: string): Promise<void> {
    this.s.sessions[peerOf(encodedAddress)] = record;
  }

  async loadSession(encodedAddress: string): Promise<string | undefined> {
    return this.s.sessions[peerOf(encodedAddress)];
  }

  async loadSignedPreKey(keyId: number | string): Promise<KeyPairType<ArrayBuffer> | undefined> {
    const kp = this.s.signedPreKeys[String(keyId)];
    return kp ? fromStored(kp) : undefined;
  }

  async storeSignedPreKey(keyId: number | string, keyPair: KeyPairType<ArrayBuffer>): Promise<void> {
    this.s.signedPreKeys[String(keyId)] = toStored(keyPair);
  }

  async removeSignedPreKey(keyId: number | string): Promise<void> {
    delete this.s.signedPreKeys[String(keyId)];
  }
}

export function createSignalBackend(getState: () => VaultState): CipherBackend {
  const store = new VaultSignalStore(getState);
  const address = (peerId: string) => new SignalProtocolAddress(peerId, DEVICE_ID);

  return {
    async generateIdentity() {
      const identity = await KeyHelper.generateIdentityKeyPair();
      return { registrationId: KeyHelper.generateRegistrationId(), identity: toStored(identity) };
    },

    async generateSignedPreKey(identity, keyId) {
      const spk = await KeyHelper.generateSignedPreKey(fromStored(identity), keyId);
      return { keyPair: toStored(spk.keyPair), signature: toBase64(new Uint8Array(spk.signature)) };
    },

    async generatePreKey(keyId) {
      const pk = await KeyHelper.generatePreKey(keyId);
      return toStored(pk.keyPair);
    },

    async hasSession(peerId) {
      return (await store.loadSession(address(peerId).toString())) !== undefined;
    },

    async processBundle(peerId: string, bundle: PeerBundle) {
      store.clearRejection();
      try {
        await new SessionBuilder(store, address(peerId)).processPreKey({
          registrationId: bundle.registrationId,
          identityKey: toArrayBuffer(bundle.identityKey),
          signedPreKey: {
            keyId: bundle.signedPreKey.id,
            publicKey: toArrayBuffer(bundle.signedPreKey.publicKey),
            signature: toArrayBuffer(bundle.signedPreKey.signature),
          },
          preKey: bundle.oneTimePreKey
            ? { keyId: bundle.oneTimePreKey.id, publicKey: toArrayBuffer(bundle.oneTimePreKey.publicKey) }
            : undefined,
        });
      } catch (e) {
        const rejected = store.currentRejection();
        if (rejected) throw new IdentityChangedError(rejected.peerId, rejected.newKey);
        throw new CipherError(e instanceof Error ? e.message : "bundle rejected");
      }
    },

    async encrypt(peerId, plaintext) {
      try {
        const msg = await new SessionCipher(store, address(peerId)).encrypt(toArrayBuffer(plaintext));
        if (typeof msg.body !== "string") throw new CipherError("library returned no ciphertext");
        if (msg.type !== MESSAGE_TYPE_WHISPER && msg.type !== MESSAGE_TYPE_PREKEY) {
          throw new CipherError("library returned an unknown message type");
        }
        return { type: msg.type, body: binaryStringToBytes(msg.body) };
      } catch (e) {
        if (e instanceof CipherError) throw e;
        throw new CipherError(e instanceof Error ? e.message : "encryption failed");
      }
    },

    async decrypt(peerId, type, body) {
      store.clearRejection();
      const cipher = new SessionCipher(store, address(peerId));
      const binary = bytesToBinaryString(body);
      try {
        let plain: ArrayBuffer;
        if (type === MESSAGE_TYPE_PREKEY) plain = await cipher.decryptPreKeyWhisperMessage(binary, "binary");
        else if (type === MESSAGE_TYPE_WHISPER) plain = await cipher.decryptWhisperMessage(binary, "binary");
        else throw new CipherError("unknown message type");
        return new Uint8Array(plain);
      } catch (e) {
        const rejected = store.currentRejection();
        if (rejected) throw new IdentityChangedError(rejected.peerId, rejected.newKey);
        if (e instanceof CipherError) throw e;
        throw new CipherError(e instanceof Error ? e.message : "decryption failed");
      }
    },

    deleteSession(peerId) {
      delete getState().sessions[peerId];
    },
  };
}
