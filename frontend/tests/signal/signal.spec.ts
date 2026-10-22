// Tests of the REAL protocol library through the real engine. Run: npm run test:signal
// (requires `npm install`). These have NOT been executed in the environments used to write
// them (npm was blocked), so no result is claimed; run them and keep the output as evidence.
import { describe, expect, it, beforeEach } from "vitest";

import { decodeEnvelope, encodeEnvelope } from "../../src/crypto/envelope.ts";
import { createSignalBackend } from "../../src/crypto/signal.ts";
import { ALICE, BOB, FakeServer, clock, makeClient } from "../helpers/fakes.ts";
import type { TestClient } from "../helpers/fakes.ts";

let server: FakeServer;
let alice: TestClient;
let bob: TestClient;

const texts = (c: TestClient, peer: string) =>
  c.engine.messagesFor(peer).filter((m) => m.kind === "message").map((m) => m.text);

async function start(): Promise<void> {
  server = new FakeServer();
  alice = await makeClient(server, ALICE, "alice", undefined, createSignalBackend);
  bob = await makeClient(server, BOB, "bobby", undefined, createSignalBackend);
  await server.connect(ALICE);
  await server.connect(BOB);
  await alice.engine.startConversation(server.users.get(BOB)!.profile);
}

describe("real Signal protocol through the chat engine", () => {
  beforeEach(start, 60_000);

  it("delivers a message end to end and both sides derive the same safety number", async () => {
    await alice.engine.sendMessage(BOB, "hello over real crypto");
    await server.flush();
    expect(texts(bob, ALICE)).toEqual(["hello over real crypto"]);
    await bob.engine.startConversation(server.users.get(ALICE)!.profile);
    await bob.engine.sendMessage(ALICE, "reply");
    await server.flush();
    expect(texts(alice, BOB)).toEqual(["hello over real crypto", "reply"]);
    const a = await alice.engine.getSafetyNumber(BOB);
    expect(a).toBeTruthy();
    expect(a).toBe(await bob.engine.getSafetyNumber(ALICE));
  });

  it("the relay never sees the plaintext", async () => {
    await alice.engine.sendMessage(BOB, "MARKER-PLAINTEXT-XYZ");
    await server.flush();
    const seen = JSON.stringify([server.frames, server.log, server.messages]);
    expect(seen).not.toContain("MARKER-PLAINTEXT-XYZ");
  });

  it("rejects a tampered ciphertext and shows nothing", async () => {
    server.tamper = (env) => {
      const { type, body } = decodeEnvelope(env);
      body[body.length - 1] ^= 1; // flips a bit in the MAC
      return encodeEnvelope(type, body);
    };
    await alice.engine.sendMessage(BOB, "tamper me");
    await server.flush();
    expect(texts(bob, ALICE)).toEqual([]);
    expect(bob.persisted.json).not.toContain("tamper me");
  });

  it("rejects a replayed ciphertext delivered under a new message id", async () => {
    await alice.engine.sendMessage(BOB, "once only");
    await server.flush();
    const sent = server.log[0];
    await bob.engine.handleFrame({ type: "message", id: crypto.randomUUID(), from: ALICE, envelope: sent.envelope });
    expect(texts(bob, ALICE)).toEqual(["once only"]);
  });

  it("does not decrypt a redelivered duplicate twice", async () => {
    await alice.engine.sendMessage(BOB, "dup");
    await server.flush();
    const sent = server.log[0];
    await bob.engine.handleFrame({ type: "message", id: sent.id, from: ALICE, envelope: sent.envelope });
    expect(texts(bob, ALICE)).toEqual(["dup"]);
  });

  it("flags a changed identity key and blocks sending until accepted", async () => {
    await alice.engine.sendMessage(BOB, "hi");
    await server.flush();
    server.disconnect(BOB);
    const bob2 = await makeClient(server, BOB, "bobby", undefined, createSignalBackend);
    await server.connect(BOB);
    clock.skewMs += 60_000;
    await expect(alice.engine.sendMessage(BOB, "to new bob")).rejects.toThrow(/safety number/);
    expect(alice.engine.contact(BOB)?.keyChange).toBeTruthy();
    await alice.engine.acceptKeyChange(BOB);
    await alice.engine.sendMessage(BOB, "after accept");
    await server.flush();
    expect(texts(bob2, ALICE)).toEqual(["after accept"]);
  });

  /** Alice and Bob each send once, so Alice's next message is an ordinary ratchet message (type 1), not a pre-key message. */
  async function establish(): Promise<void> {
    await alice.engine.sendMessage(BOB, "a1");
    await server.flush();
    await bob.engine.startConversation(server.users.get(ALICE)!.profile);
    await bob.engine.sendMessage(ALICE, "b1");
    await server.flush();
  }

  it("rejects a ciphertext whose MAC was altered (ordinary ratchet message)", async () => {
    await establish();
    server.tamper = (env) => {
      const { type, body } = decodeEnvelope(env);
      expect(type).toBe(1); // the last 8 bytes of a type-1 message are the MAC
      body[body.length - 1] ^= 1;
      return encodeEnvelope(type, body);
    };
    await alice.engine.sendMessage(BOB, "MAC-TAMPER");
    await server.flush();
    expect(bob.engine.messagesFor(ALICE).filter((m) => m.kind === "message" && m.dir === "in").map((m) => m.text)).toEqual(["a1"]);
    expect(bob.persisted.json).not.toContain("MAC-TAMPER");
  });

  it("rejects a truncated ciphertext", async () => {
    await establish();
    server.tamper = (env) => {
      const { type, body } = decodeEnvelope(env);
      return encodeEnvelope(type, body.slice(0, body.length - 12));
    };
    await alice.engine.sendMessage(BOB, "TRUNCATED");
    await server.flush();
    expect(bob.engine.messagesFor(ALICE).filter((m) => m.kind === "message" && m.dir === "in").map((m) => m.text)).toEqual(["a1"]);
  });

  it("encrypts the same plaintext to different ciphertext every time (the ratchet advances)", async () => {
    await establish();
    await alice.engine.sendMessage(BOB, "same words");
    await alice.engine.sendMessage(BOB, "same words");
    await server.flush();
    const bodies = server.log.filter((m) => m.from === ALICE).slice(-2).map((m) => m.envelope);
    expect(bodies[0]).not.toBe(bodies[1]);
    expect(texts(bob, ALICE).slice(-2)).toEqual(["same words", "same words"]);
  });

  it("decrypts messages that arrive out of order (skipped message keys)", async () => {
    await establish();
    server.disconnect(BOB); // hold delivery so the test controls the order
    for (const t of ["o1", "o2", "o3"]) await alice.engine.sendMessage(BOB, t);
    await server.flush(); // the relay queues them (Bob is offline) and records the envelopes
    const sent = server.log.filter((m) => m.from === ALICE).slice(-3);
    for (const m of [sent[2], sent[0], sent[1]]) {
      await bob.engine.handleFrame({ type: "message", id: m.id, from: ALICE, envelope: m.envelope });
    }
    expect(texts(bob, ALICE).slice(-3).sort()).toEqual(["o1", "o2", "o3"]);
  });

  it("survives a restart from persisted state with the real ratchet", async () => {
    await alice.engine.sendMessage(BOB, "m1");
    await server.flush();
    const json = bob.persisted.json!;
    server.disconnect(BOB);
    const bob2 = await makeClient(server, BOB, "bobby", json, createSignalBackend);
    await server.connect(BOB);
    await alice.engine.sendMessage(BOB, "m2");
    await server.flush();
    expect(texts(bob2, ALICE)).toEqual(["m1", "m2"]);
  });
});
