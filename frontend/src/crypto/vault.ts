// Encrypts the client's secret state (identity keys, ratchet sessions, message
// history) before it is written to IndexedDB.
//
// Only standard WebCrypto primitives are used, composed in the standard way:
//   key  = PBKDF2-HMAC-SHA-256(account password, random 16-byte salt, 600,000 iterations)
//   blob = AES-256-GCM(key, fresh random 96-bit IV, plaintext, AAD = context string)
// The derived key is non-extractable and lives only in memory. A fresh IV is
// generated for every write.
//
// Limitation (documented in SECURITY.md): the vault password is the account
// password, which the server also sees at login. This protects a copied
// browser profile against someone WITHOUT the password, not against a
// malicious server that also gets the profile.

import { fromBase64, randomBytes, toBase64, utf8 } from "./bytes.ts";

export const DEFAULT_ITERATIONS = 600_000;
const MIN_ITERATIONS = 100_000; // refuse blobs that claim a weakened KDF
const MAX_ITERATIONS = 5_000_000;
const SALT_BYTES = 16;
const IV_BYTES = 12;

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
  salt: string;
  iv: string;
  ct: string;
}

async function deriveKey(password: string, salt: Uint8Array, iterations: number): Promise<CryptoKey> {
  const material = await crypto.subtle.importKey("raw", utf8.encode(password) as BufferSource, "PBKDF2", false, [
    "deriveKey",
  ]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt: salt as BufferSource, iterations },
    material,
    { name: "AES-GCM", length: 256 },
    false, // non-extractable
    ["encrypt", "decrypt"],
  );
}

export class Vault {
  private readonly key: CryptoKey;
  private readonly salt: Uint8Array;
  private readonly iterations: number;
  private readonly aad: Uint8Array;

  private constructor(key: CryptoKey, salt: Uint8Array, iterations: number, context: string) {
    this.key = key;
    this.salt = salt;
    this.iterations = iterations;
    this.aad = utf8.encode(context);
  }

  /** New vault with a fresh salt. `context` binds ciphertext to its owner. */
  static async create(
    password: string,
    context: string,
    iterations = DEFAULT_ITERATIONS,
    minIterations = MIN_ITERATIONS,
  ): Promise<Vault> {
    if (iterations < minIterations) throw new VaultError("iteration count too low");
    const salt = randomBytes(SALT_BYTES);
    return new Vault(await deriveKey(password, salt, iterations), salt, iterations, context);
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
      typeof blob.salt !== "string" || typeof blob.iv !== "string" || typeof blob.ct !== "string" ||
      !Number.isInteger(blob.iterations) || blob.iterations > MAX_ITERATIONS ||
      blob.iterations < minIterations
    ) {
      throw new VaultError("stored data has an unsupported format");
    }
    let salt: Uint8Array;
    try {
      salt = fromBase64(blob.salt);
    } catch {
      throw new VaultError("stored data is corrupted");
    }
    const vault = new Vault(await deriveKey(password, salt, blob.iterations), salt, blob.iterations, context);
    return { vault, plaintext: await vault.open(blob) };
  }

  async seal(plaintext: string): Promise<VaultBlob> {
    const iv = randomBytes(IV_BYTES);
    const ct = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv as BufferSource, additionalData: this.aad as BufferSource },
        this.key,
        utf8.encode(plaintext) as BufferSource,
      ),
    );
    return {
      v: 1,
      kdf: "PBKDF2-SHA256",
      iterations: this.iterations,
      salt: toBase64(this.salt),
      iv: toBase64(iv),
      ct: toBase64(ct),
    };
  }

  async open(blob: VaultBlob): Promise<string> {
    try {
      const plain = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: fromBase64(blob.iv) as BufferSource, additionalData: this.aad as BufferSource },
        this.key,
        fromBase64(blob.ct) as BufferSource,
      );
      return utf8.decode(new Uint8Array(plain));
    } catch {
      throw new VaultError("wrong password or the stored data was modified");
    }
  }
}
