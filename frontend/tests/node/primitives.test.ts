// Run with: npm run test:unit   (Node's built-in test runner, no extra packages)
import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  binaryStringToBytes, bytesToBinaryString, concat, fromBase64, toArrayBuffer, toBase64, u32be, utf8,
} from "../../src/crypto/bytes.ts";
import {
  decodeEnvelope, decodePlaintext, encodeEnvelope, encodePlaintext, EnvelopeError, MAX_TEXT_CHARS,
} from "../../src/crypto/envelope.ts";
import { safetyNumber } from "../../src/crypto/fingerprint.ts";
import { Vault, VaultError } from "../../src/crypto/vault.ts";
import type { VaultBlob } from "../../src/crypto/vault.ts";

const LOW = 1_000; // test-only KDF cost
const key = (n: number, len = 33) => new Uint8Array(len).fill(n);

describe("bytes", () => {
  it("base64 round-trips arbitrary bytes, including large buffers", () => {
    const data = new Uint8Array(100_000).map((_, i) => (i * 31) % 256);
    assert.deepEqual(fromBase64(toBase64(data)), data);
    assert.equal(toBase64(new Uint8Array([0, 255, 128])), "AP+A");
  });
  it("binary strings round-trip and reject code points above 255", () => {
    const b = new Uint8Array([0, 1, 200, 255]);
    assert.deepEqual(binaryStringToBytes(bytesToBinaryString(b)), b);
    assert.throws(() => binaryStringToBytes("Ā"));
  });
  it("toArrayBuffer copies exactly the viewed range", () => {
    const view = new Uint8Array([1, 2, 3, 4, 5]).subarray(1, 4);
    assert.deepEqual(new Uint8Array(toArrayBuffer(view)), new Uint8Array([2, 3, 4]));
  });
  it("concat, u32be and utf8 behave", () => {
    assert.deepEqual(concat(new Uint8Array([1]), new Uint8Array([2, 3])), new Uint8Array([1, 2, 3]));
    assert.deepEqual(u32be(258), new Uint8Array([0, 0, 1, 2]));
    assert.equal(utf8.decode(utf8.encode("héllo ✓")), "héllo ✓");
    assert.throws(() => utf8.decode(new Uint8Array([0xff, 0xfe])));
  });
});

describe("envelope", () => {
  it("round-trips type and body", () => {
    const body = new Uint8Array([9, 8, 7, 6]);
    for (const type of [1, 3]) {
      const d = decodeEnvelope(encodeEnvelope(type, body));
      assert.equal(d.type, type);
      assert.deepEqual(d.body, body);
    }
  });
  it("rejects unsupported types on encode", () => {
    assert.throws(() => encodeEnvelope(2, new Uint8Array([1])), EnvelopeError);
  });
  it("rejects malformed envelopes", () => {
    const wrap = (o: unknown) => toBase64(utf8.encode(JSON.stringify(o)));
    const bad: Array<[string, string]> = [
      ["not base64", "***"],
      ["not json", toBase64(utf8.encode("nope"))],
      ["array", wrap([])],
      ["extra field", wrap({ v: 1, t: 1, b: "AA==", x: 1 })],
      ["missing field", wrap({ v: 1, t: 1 })],
      ["wrong version", wrap({ v: 2, t: 1, b: "AA==" })],
      ["wrong type", wrap({ v: 1, t: 2, b: "AA==" })],
      ["body not string", wrap({ v: 1, t: 1, b: 5 })],
      ["body not base64", wrap({ v: 1, t: 1, b: "***" })],
      ["empty body", wrap({ v: 1, t: 1, b: "" })],
    ];
    for (const [name, env] of bad) assert.throws(() => decodeEnvelope(env), EnvelopeError, name);
  });
  it("plaintext round-trips unicode and enforces limits", () => {
    const d = decodePlaintext(encodePlaintext("héllo ✓ 😀", 1_700_000_000_000));
    assert.deepEqual(d, { text: "héllo ✓ 😀", sentAt: 1_700_000_000_000 });
    assert.throws(() => encodePlaintext("", 1), EnvelopeError);
    assert.throws(() => encodePlaintext("x".repeat(MAX_TEXT_CHARS + 1), 1), EnvelopeError);
  });
  it("decodePlaintext rejects wrong shapes", () => {
    const enc = (o: unknown) => utf8.encode(JSON.stringify(o));
    for (const bad of [enc([]), enc({ v: 2, text: "a", sent_at: 1 }), enc({ v: 1, text: 5, sent_at: 1 }),
      enc({ v: 1, text: "a", sent_at: "x" }), enc({ v: 1, text: "", sent_at: 1 }), utf8.encode("junk")]) {
      assert.throws(() => decodePlaintext(bad), EnvelopeError);
    }
  });
});

describe("safety number", () => {
  const alice = { userId: "00000000-0000-4000-8000-00000000000a", identityKey: key(1) };
  const bob = { userId: "00000000-0000-4000-8000-00000000000b", identityKey: key(2) };

  it("is 12 groups of 5 digits", async () => {
    assert.match(await safetyNumber(alice, bob), /^(\d{5} ){11}\d{5}$/);
  });
  it("is identical for both parties regardless of argument order", async () => {
    assert.equal(await safetyNumber(alice, bob), await safetyNumber(bob, alice));
  });
  it("changes if either identity key changes by a single bit", async () => {
    const base = await safetyNumber(alice, bob);
    const flipped = key(2);
    flipped[10] ^= 1;
    assert.notEqual(await safetyNumber(alice, { ...bob, identityKey: flipped }), base);
    assert.notEqual(await safetyNumber({ ...alice, identityKey: key(3) }, bob), base);
  });
  it("binds keys to user ids (swapping keys between users changes the number)", async () => {
    const swapped = await safetyNumber({ ...alice, identityKey: bob.identityKey }, { ...bob, identityKey: alice.identityKey });
    assert.notEqual(swapped, await safetyNumber(alice, bob));
  });
  it("is deterministic", async () => {
    assert.equal(await safetyNumber(alice, bob), await safetyNumber(alice, bob));
  });
});

describe("vault", () => {
  const CTX = "securechat-vault-v1|user-1";

  it("seals and opens, and the blob contains no plaintext", async () => {
    const vault = await Vault.create("hunter2-hunter2", CTX, LOW, LOW);
    const secret = "TOP-SECRET-MARKER-12345";
    const blob = await vault.seal(JSON.stringify({ secret }));
    assert.ok(!JSON.stringify(blob).includes(secret));
    const reopened = await Vault.unlock("hunter2-hunter2", blob, CTX, LOW);
    assert.equal(JSON.parse(reopened.plaintext).secret, secret);
  });
  it("uses a fresh IV for every seal", async () => {
    const vault = await Vault.create("pw-pw-pw-pw-pw", CTX, LOW, LOW);
    const a = await vault.seal("same");
    const b = await vault.seal("same");
    assert.notEqual(a.iv, b.iv);
    assert.notEqual(a.ct, b.ct);
  });
  it("a wrong password fails", async () => {
    const vault = await Vault.create("right-password", CTX, LOW, LOW);
    const blob = await vault.seal("data");
    await assert.rejects(Vault.unlock("wrong-password", blob, CTX, LOW), VaultError);
  });
  it("tampering with ciphertext, IV or salt is detected", async () => {
    const vault = await Vault.create("right-password", CTX, LOW, LOW);
    const blob = await vault.seal("data");
    const flip = (b64: string) => {
      const bytes = fromBase64(b64);
      bytes[0] ^= 1;
      return toBase64(bytes);
    };
    for (const field of ["ct", "iv", "salt"] as const) {
      const tampered: VaultBlob = { ...blob, [field]: flip(blob[field]) };
      await assert.rejects(Vault.unlock("right-password", tampered, CTX, LOW), VaultError, field);
    }
  });
  it("binds the blob to its context (cannot be moved to another account)", async () => {
    const vault = await Vault.create("right-password", CTX, LOW, LOW);
    const blob = await vault.seal("data");
    await assert.rejects(Vault.unlock("right-password", blob, "securechat-vault-v1|user-2", LOW), VaultError);
  });
  it("refuses weakened or malformed parameters unless explicitly allowed", async () => {
    const vault = await Vault.create("right-password", CTX, LOW, LOW);
    const blob = await vault.seal("data");
    await assert.rejects(Vault.unlock("right-password", blob, CTX), VaultError); // default floor is 100,000
    await assert.rejects(Vault.create("pw", CTX, LOW), VaultError);
    await assert.rejects(Vault.unlock("right-password", { ...blob, iterations: 50_000_000 }, CTX, LOW), VaultError);
    await assert.rejects(Vault.unlock("right-password", { ...blob, kdf: "x" } as unknown as VaultBlob, CTX, LOW), VaultError);
    await assert.rejects(Vault.unlock("right-password", null as unknown as VaultBlob, CTX, LOW), VaultError);
  });
  it("a seal after reopening still opens with the same password (salt/iterations preserved)", async () => {
    const v1 = await Vault.create("right-password", CTX, LOW, LOW);
    const { vault: v2 } = await Vault.unlock("right-password", await v1.seal("one"), CTX, LOW);
    const second = await v2.seal("two");
    assert.equal((await Vault.unlock("right-password", second, CTX, LOW)).plaintext, "two");
  });
});
