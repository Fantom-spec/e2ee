// Glue between the password, the encrypted vault, IndexedDB and the chat engine.

import { ChatEngine } from "./engine.ts";
import type { DirectoryApi } from "./engine.ts";
import { loadVaultBlob, saveVaultBlob } from "./idb.ts";
import { createSignalBackend } from "./signal.ts";
import { Vault } from "./vault.ts";

const contextFor = (userId: string) => `securechat-vault-v1:${userId}`;

export class UnlockError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UnlockError";
  }
}

export interface OpenOptions {
  userId: string;
  password: string;
  api: DirectoryApi;
  sendFrame: (frame: Record<string, unknown>) => boolean;
}

/**
 * Unlock this browser's key vault with the account password (or create it on
 * first use) and return a ready ChatEngine. A wrong password or tampered
 * storage makes unlock fail; we never fall back to creating new keys over it.
 */
export async function openEngine(opts: OpenOptions): Promise<ChatEngine> {
  if (!globalThis.isSecureContext || !globalThis.crypto?.subtle || !globalThis.indexedDB) {
    throw new UnlockError("This page needs HTTPS (or localhost) and a browser with Web Crypto and IndexedDB.");
  }
  const context = contextFor(opts.userId);
  let blob;
  try {
    blob = await loadVaultBlob(opts.userId);
  } catch {
    throw new UnlockError("Browser storage is unavailable (private mode?). Encrypted chat needs local storage.");
  }

  let vault: Vault;
  let stateJson: string | null = null;
  if (blob) {
    try {
      const unlocked = await Vault.unlock(opts.password, blob, context);
      vault = unlocked.vault;
      stateJson = unlocked.plaintext;
    } catch {
      throw new UnlockError(
        "Could not unlock the encryption keys stored in this browser. The password may have changed, or the data is damaged.",
      );
    }
  } else {
    vault = await Vault.create(opts.password, context);
  }

  const deps = {
    userId: opts.userId,
    api: opts.api,
    makeBackend: createSignalBackend,
    persist: async (json: string) => saveVaultBlob(opts.userId, await vault.seal(json)),
    sendFrame: opts.sendFrame,
    now: () => Date.now(),
    newId: () => crypto.randomUUID(),
  };
  try {
    return stateJson !== null ? ChatEngine.fromJson(deps, stateJson) : await ChatEngine.createFresh(deps);
  } catch (e) {
    throw new UnlockError(e instanceof Error ? e.message : "Could not start encrypted chat.");
  }
}
