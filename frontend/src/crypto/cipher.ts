// The seam between application logic and the protocol library.
//
// The chat engine talks only to this interface. signal.ts implements it with
// @privacyresearch/libsignal-protocol-typescript. To swap the protocol
// implementation (for example the official libsignal or vodozemac compiled to
// WASM), implement CipherBackend again; the engine does not change.

import type { StoredKeyPair } from "./state.ts";

export interface PeerBundle {
  registrationId: number;
  identityKey: Uint8Array;
  signedPreKey: { id: number; publicKey: Uint8Array; signature: Uint8Array };
  oneTimePreKey?: { id: number; publicKey: Uint8Array };
}

export interface CipherBackend {
  generateIdentity(): Promise<{ registrationId: number; identity: StoredKeyPair }>;
  generateSignedPreKey(identity: StoredKeyPair, keyId: number): Promise<{ keyPair: StoredKeyPair; signature: string }>;
  generatePreKey(keyId: number): Promise<StoredKeyPair>;
  hasSession(peerId: string): Promise<boolean>;
  /** Establish a session from a bundle. Throws IdentityChangedError if the peer's key differs from the pinned one. */
  processBundle(peerId: string, bundle: PeerBundle): Promise<void>;
  encrypt(peerId: string, plaintext: Uint8Array): Promise<{ type: number; body: Uint8Array }>;
  /** Throws IdentityChangedError for an untrusted identity, CipherError for anything else (tampering, replay, no session...). */
  decrypt(peerId: string, type: number, body: Uint8Array): Promise<Uint8Array>;
  deleteSession(peerId: string): void;
}

export class IdentityChangedError extends Error {
  peerId: string;
  newKey: string;
  constructor(peerId: string, newKey: string) {
    super("the contact's identity key changed");
    this.name = "IdentityChangedError";
    this.peerId = peerId;
    this.newKey = newKey;
  }
}

export class CipherError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CipherError";
  }
}
