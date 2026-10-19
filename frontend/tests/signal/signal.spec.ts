// Tests of the REAL protocol library through the real engine. Run: npm run test:signal
// (requires `npm install`). Not executed in the development sandbox (no npm access);
// results must be produced on a machine with the dependencies installed.
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
