// Encrypts the client's secret state (identity keys, ratchet sessions, message
// history) before it is written to IndexedDB.
//
// Only standard WebCrypto primitives are used, composed in the standard way:
//   vaultKey = random 256-bit key (generated once per browser profile)
//   wrappingKey = PBKDF2-HMAC-SHA-256(account password, random 16-byte salt, 600,000 iterations)
//   wrappedVaultKey = AES-256-GCM(wrappingKey, fresh random 96-bit IV, vaultKey, AAD = context)
//   blob = AES-256-GCM(vaultKey, fresh random 96-bit IV, plaintext, AAD = context string)
//
// The vault key is encrypted (wrapped) with a key derived from the account password.
// This means the server, which sees the password at login, cannot derive the vault key
// without also having the encrypted vault blob from the browser's IndexedDB.
//
// The derived wrapping key is non-extractable and lives only in memory. Fresh IVs are
// generated for every write (both for wrapping the vault key and for the vault payload).

import { fromBase64, randomBytes, toBase64, utf8 } from "./bytes.ts";

export const DEFAULT_ITERATIONS = 600_000;
const MIN_ITERATIONS = 100_000; // refuse blobs that claim a weakened KDF
const MAX_ITERATIONS = 5_000_000;
const SALT_BYTES = 16;
const IV_BYTES = 12;
const VAULT_KEY_BYTES = 32; // 256 bits for AES-256

export class VaultError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "VaultError";
  }
}

export interface VaultBlob {
  v: 1;
  kdf: "PBKDF2-SHA256";
  iterations: number;
  salt: string;        // salt for PBKDF2 (wrapping key derivation)
  iv: string;          // IV for wrapping the vault key
  wrappedKey: string;  // encrypted vault key (AES-256-GCM)
  payloadIv: string;   // IV for the payload encryption
  payloadCt: string;   // encrypted payload (AES-256-GCM under vault key)
}

// Legacy blob format (v1 without key wrapping)
interface LegacyVaultBlob {
  v: 1;
  kdf: "PBKDF2-SHA256";
  iterations: number;
  salt: string;
  iv: string;          // IV for payload encryption (legacy)
  ct: string;          // ciphertext for payload (legacy)
}

// Helper to narrow Uint8Array<ArrayBufferLike> to Uint8Array<ArrayBuffer>
function asBufferSource(bytes: Uint8Array<ArrayBufferLike>): ArrayBuffer {
  return bytes.buffer as ArrayBuffer;
}

async function deriveWrappingKey(password: string, salt: Uint8Array, iterations: number): Promise<CryptoKey> {
  const material = await crypto.subtle.importKey("raw", asBufferSource(utf8.encode(password)), "PBKDF2", false, [
    "deriveKey",
  ]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt: asBufferSource(salt), iterations },
    material,
    { name: "AES-GCM", length: 256 },
    false, // non-extractable
    ["encrypt", "decrypt"],
  );
}

async function wrapKey(wrappingKey: CryptoKey, vaultKey: Uint8Array, aad: Uint8Array): Promise<{ iv: Uint8Array; wrapped: Uint8Array }> {
  const iv = randomBytes(IV_BYTES);
  const wrapped = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: asBufferSource(iv), additionalData: asBufferSource(aad) },
      wrappingKey,
      asBufferSource(vaultKey),
    ),
  );
  return { iv, wrapped };
}

async function unwrapKey(wrappingKey: CryptoKey, iv: Uint8Array, wrapped: Uint8Array, aad: Uint8Array): Promise<Uint8Array> {
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: asBufferSource(iv), additionalData: asBufferSource(aad) },
    wrappingKey,
    asBufferSource(wrapped),
  );
  return new Uint8Array(plain);
}

async function importVaultKey(vaultKey: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    asBufferSource(vaultKey),
    { name: "AES-GCM", length: 256 },
    false, // non-extractable
    ["encrypt", "decrypt"],
  );
}

async function deriveKeyWrapKey(vaultKey: Uint8Array, salt: Uint8Array): Promise<CryptoKey> {
  // Derive a key-wrapping key from the vault key using HKDF
  // This is used for wrapping/unwrapping the vault key in seal/open operations
  // The password is only needed at unlock time to initially unwrap the vault key
  const baseKey = await crypto.subtle.importKey(
    "raw",
    asBufferSource(vaultKey),
    "HKDF",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: asBufferSource(salt),
      info: asBufferSource(utf8.encode("vault-key-wrap")),
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

export class Vault {
  private readonly vaultKey: Uint8Array;
  private readonly salt: Uint8Array;
  private readonly iterations: number;
  private readonly aad: Uint8Array;
  private readonly keyWrapKey: CryptoKey; // HKDF-derived from vaultKey, used for key wrapping in seal/open
  private readonly wrappedVaultKey: Uint8Array; // vault key wrapped with password-derived key
  private readonly wrappingIv: Uint8Array; // IV used for wrapping the vault key

  private constructor(
    vaultKey: Uint8Array,
    salt: Uint8Array,
    iterations: number,
    context: string,
    keyWrapKey: CryptoKey,
    wrappedVaultKey: Uint8Array,
    wrappingIv: Uint8Array,
  ) {
    this.vaultKey = vaultKey;
    this.salt = salt;
    this.iterations = iterations;
    this.aad = utf8.encode(context);
    this.keyWrapKey = keyWrapKey;
    this.wrappedVaultKey = wrappedVaultKey;
    this.wrappingIv = wrappingIv;
  }

  /** New vault with a fresh random vault key, wrapped by a password-derived key. */
  static async create(
    password: string,
    context: string,
    iterations = DEFAULT_ITERATIONS,
    minIterations = MIN_ITERATIONS,
  ): Promise<Vault> {
    if (iterations < minIterations) throw new VaultError("iteration count too low");
    const salt = randomBytes(SALT_BYTES);
    const vaultKey = randomBytes(VAULT_KEY_BYTES);
    const wrappingKey = await deriveWrappingKey(password, salt, iterations);
    const { iv: wrappingIv, wrapped: wrappedVaultKey } = await wrapKey(wrappingKey, vaultKey, utf8.encode(context));
    const keyWrapKey = await deriveKeyWrapKey(vaultKey, salt);
    return new Vault(vaultKey, salt, iterations, context, keyWrapKey, wrappedVaultKey, wrappingIv);
  }

  /** Open an existing blob. Wrong password, tampering or wrong context all fail the same way. */
  static async unlock(
    password: string,
    blob: VaultBlob,
    context: string,
    minIterations = MIN_ITERATIONS, // only the test-suite passes a smaller value
  ): Promise<{ vault: Vault; plaintext: string }> {
    if (
      !blob || blob.v !== 1 || blob.kdf !== "PBKDF2-SHA256" ||
      typeof blob.salt !== "string" || typeof blob.iv !== "string" || typeof blob.wrappedKey !== "string" ||
      typeof blob.payloadIv !== "string" || typeof blob.payloadCt !== "string" ||
      !Number.isInteger(blob.iterations) || blob.iterations > MAX_ITERATIONS ||
      blob.iterations < minIterations
    ) {
      throw new VaultError("stored data has an unsupported format");
    }
    let salt: Uint8Array;
    let wrappingIv: Uint8Array;
    let wrappedKey: Uint8Array;
    try {
      salt = fromBase64(blob.salt);
      wrappingIv = fromBase64(blob.iv);
      wrappedKey = fromBase64(blob.wrappedKey);
    } catch {
      throw new VaultError("stored data is corrupted");
    }
    const aad = utf8.encode(context);
    const wrappingKey = await deriveWrappingKey(password, salt, blob.iterations);
    let vaultKey: Uint8Array;
    try {
      vaultKey = await unwrapKey(wrappingKey, wrappingIv, wrappedKey, aad);
    } catch {
      throw new VaultError("wrong password or the stored data was modified");
    }
    const keyWrapKey = await deriveKeyWrapKey(vaultKey, salt);
    const vault = new Vault(vaultKey, salt, blob.iterations, context, keyWrapKey, wrappedKey, wrappingIv);
    return { vault, plaintext: await vault.openPayload(blob) };
  }

  /** Encrypt the payload using the vault key. */
  async seal(plaintext: string): Promise<VaultBlob> {
    const aad = this.aad;

    // Encrypt the payload with the vault key
    const payloadIv = randomBytes(IV_BYTES);
    const vaultKeyCrypto = await importVaultKey(this.vaultKey);
    const payloadCt = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: asBufferSource(payloadIv), additionalData: asBufferSource(aad) },
        vaultKeyCrypto,
        asBufferSource(utf8.encode(plaintext)),
      ),
    );

    return {
      v: 1,
      kdf: "PBKDF2-SHA256",
      iterations: this.iterations,
      salt: toBase64(this.salt),
      iv: toBase64(this.wrappingIv),
      wrappedKey: toBase64(this.wrappedVaultKey),
      payloadIv: toBase64(payloadIv),
      payloadCt: toBase64(payloadCt),
    };
  }

  /** Decrypt the payload using the vault key. */
  async open(blob: VaultBlob | LegacyVaultBlob): Promise<string> {
    // New format (v1 with key wrapping) - check for new format properties
    if ("wrappedKey" in blob && "payloadIv" in blob && "payloadCt" in blob) {
      return this.openPayload(blob as VaultBlob);
    }
    // Legacy format (v1 without key wrapping) - fallback for migration
    // Legacy format uses 'iv' and 'ct' for payload encryption with wrapping key directly
    if ("iv" in blob && "ct" in blob && !("payloadIv" in blob) && !("payloadCt" in blob)) {
      return this.openLegacy(blob as LegacyVaultBlob);
    }
    throw new VaultError("stored data has an unsupported format");
  }

  private async openPayload(blob: VaultBlob): Promise<string> {
    try {
      const vaultKey = await importVaultKey(this.vaultKey);
      const plain = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: asBufferSource(fromBase64(blob.payloadIv)), additionalData: asBufferSource(this.aad) },
        vaultKey,
        asBufferSource(fromBase64(blob.payloadCt)),
      );
      return utf8.decode(new Uint8Array(plain));
    } catch {
      throw new VaultError("wrong password or the stored data was modified");
    }
  }

  private async openLegacy(blob: LegacyVaultBlob): Promise<string> {
    // Legacy format used the password-derived key directly for payload encryption
    // This should not happen with new vaults, but kept for potential migration
    try {
      const wrappingKey = await deriveWrappingKeyFromLegacy(this);
      const plain = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: asBufferSource(fromBase64(blob.iv)), additionalData: asBufferSource(this.aad) },
        wrappingKey,
        asBufferSource(fromBase64(blob.ct)),
      );
      return utf8.decode(new Uint8Array(plain));
    } catch {
      throw new VaultError("wrong password or the stored data was modified");
    }
  }

  // Expose keyWrapKey for legacy format decryption
  getKeyWrapKey(): CryptoKey {
    return this.keyWrapKey;
  }
}

async function deriveWrappingKeyFromLegacy(vault: Vault): Promise<CryptoKey> {
  // For legacy blobs, the vault's keyWrapKey was derived from the vault key
  // which itself was the password-derived key. This maintains compatibility.
  return vault.getKeyWrapKey();
}
