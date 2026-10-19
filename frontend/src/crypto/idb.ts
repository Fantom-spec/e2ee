// Minimal IndexedDB wrapper: one encrypted vault blob per account. Only
// ciphertext (see vault.ts) is ever written here, never keys or messages in clear.

import type { VaultBlob } from "./vault.ts";

const DB_NAME = "securechat";
const STORE = "vaults";

function open(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error("IndexedDB unavailable"));
    req.onblocked = () => reject(new Error("IndexedDB is blocked"));
  });
}

async function run<T>(mode: IDBTransactionMode, fn: (s: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  const db = await open();
  try {
    return await new Promise<T>((resolve, reject) => {
      const tx = db.transaction(STORE, mode);
      const req = fn(tx.objectStore(STORE));
      let result: T;
      req.onsuccess = () => {
        result = req.result;
      };
      tx.oncomplete = () => resolve(result); // resolve only once the write is durable
      tx.onerror = () => reject(tx.error ?? new Error("IndexedDB error"));
      tx.onabort = () => reject(tx.error ?? new Error("IndexedDB transaction aborted"));
    });
  } finally {
    db.close();
  }
}

export async function loadVaultBlob(userId: string): Promise<VaultBlob | null> {
  const v = await run<unknown>("readonly", (s) => s.get(userId));
  return v === undefined ? null : (v as VaultBlob);
}

export async function saveVaultBlob(userId: string, blob: VaultBlob): Promise<void> {
  await run("readwrite", (s) => s.put(blob, userId));
}
