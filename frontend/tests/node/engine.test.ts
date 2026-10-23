// Engine logic tests. They use a FAKE cipher (see tests/helpers/fakes.ts), so they
// prove how the engine handles duplicates, tampering results, persistence order,
// key changes, etc. They do NOT prove the encryption itself; that is
// tests/signal/ against the real library.
import assert from "node:assert/strict";
import { beforeEach, describe, it } from "node:test";

import { decodeEnvelope, encodeEnvelope } from "../../src/crypto/envelope.ts";
import { ChatEngine, EngineError, KeyChangedError } from "../../src/crypto/engine.ts";
import { StateError } from "../../src/crypto/state.ts";
import { ALICE, BOB, CAROL, FakeServer, clock, makeClient } from "../helpers/fakes.ts";
import type { TestClient } from "../helpers/fakes.ts";

let server: FakeServer;
let alice: TestClient;
let bob: TestClient;

async function connectBoth(): Promise<void> {
  await server.connect(ALICE);
  await server.connect(BOB);
}

async function begin(from: TestClient, toId: string): Promise<void> {
  await from.engine.startConversation(server.users.get(toId)!.profile);
}

const texts = (c: TestClient, peer: string) =>
  c.engine.messagesFor(peer).filter((m) => m.kind === "message").map((m) => m.text);
const systemNotes = (c: TestClient, peer: string) =>
  c.engine.messagesFor(peer).filter((m) => m.kind === "system").map((m) => m.text);

beforeEach(async () => {
  server = new FakeServer();
  alice = await makeClient(server, ALICE, "alice");
  bob = await makeClient(server, BOB, "bobby");
});

describe("key publication", () => {
  it("publishes identity and one-time prekeys on first connect, and not again", async () => {
    await server.connect(ALICE);
    const u = server.users.get(ALICE)!;
    assert.equal(u.identity?.key_version, 1);
    assert.equal(u.otps.length, 50);
    const calls = alice.persisted.calls;
    await alice.engine.maintainKeys();
    assert.equal(alice.persisted.calls, calls); // nothing new to upload, nothing saved
    assert.equal(u.otps.length, 50);
  });

  it("refills one-time prekeys when the server runs low, never re-uploading old ids", async () => {
    await server.connect(ALICE);
    const u = server.users.get(ALICE)!;
    u.otps.splice(0, 40); // other people consumed 40
    await alice.engine.maintainKeys();
    assert.equal(u.otps.length, 60); // 10 left + 50 new
    const ids = u.otps.map((o) => o.id);
    assert.equal(new Set(ids).size, ids.length);
  });

  it("does not publish when another browser replaced the account's keys", async () => {
    await server.connect(ALICE);
    const u = server.users.get(ALICE)!;
    u.identity!.key_version = 2; // someone else published a new identity
    u.identity!.identity_public = "AAAA";
    await alice.engine.maintainKeys();
    assert.equal(u.identity!.identity_public, "AAAA"); // we did not fight over it
    assert.match(alice.engine.notice ?? "", /replaced from another browser/);
  });
});

describe("messaging", () => {
  it("delivers a message end to end and reports delivery", async () => {
    await connectBoth();
    await begin(alice, BOB);
    await alice.engine.sendMessage(BOB, "hello bob");
    await server.flush();
    assert.deepEqual(texts(bob, ALICE), ["hello bob"]);
    assert.equal(bob.engine.contact(ALICE)?.username, "alice"); // unknown sender's profile was fetched
    assert.equal(alice.engine.messagesFor(BOB)[0].status, "delivered");
    assert.equal(alice.engine.messagesFor(BOB)[0].envelope, undefined); // ciphertext dropped after delivery
    assert.equal(server.messages[0].envelope, null); // relay erased it on ack
  });

  it("supports a back-and-forth conversation", async () => {
    await connectBoth();
    await begin(alice, BOB);
    await alice.engine.sendMessage(BOB, "1");
    await server.flush();
    await begin(bob, ALICE);
    await bob.engine.sendMessage(ALICE, "2");
    await server.flush();
    await alice.engine.sendMessage(BOB, "3");
    await server.flush();
    assert.deepEqual(texts(alice, BOB), ["1", "2", "3"]);
    assert.deepEqual(texts(bob, ALICE), ["1", "2", "3"]);
  });

  it("the relay only ever sees ciphertext envelopes, not the text", async () => {
    await connectBoth();
    await begin(alice, BOB);
    await alice.engine.sendMessage(BOB, "MARKER-PLAINTEXT-XYZ");
    await server.flush();
    const everythingTheServerSaw = JSON.stringify([server.frames, server.log, server.messages]);
    assert.ok(!everythingTheServerSaw.includes("MARKER-PLAINTEXT-XYZ"));
  });

  it("delivers to an offline recipient after reconnect", async () => {
    await server.connect(BOB); // Bob logs in once (publishes keys), then goes offline
    server.disconnect(BOB);
    await server.connect(ALICE);
    await begin(alice, BOB);
    await alice.engine.sendMessage(BOB, "while you were out");
    await server.flush();
    assert.equal(alice.engine.messagesFor(BOB)[0].status, "sent");
    await server.connect(BOB);
    assert.deepEqual(texts(bob, ALICE), ["while you were out"]);
    assert.equal(alice.engine.messagesFor(BOB)[0].status, "delivered");
  });

  it("rejects oversized text before changing any state", async () => {
    await connectBoth();
    await begin(alice, BOB);
    const calls = alice.persisted.calls;
    await assert.rejects(alice.engine.sendMessage(BOB, "x".repeat(4001)));
    await assert.rejects(alice.engine.sendMessage(BOB, ""));
    assert.equal(alice.persisted.calls, calls);
  });

  it("explains when the contact has not published keys", async () => {
    await server.connect(ALICE);
    server.addUser(CAROL, "carol"); // registered but never logged in with this build
    await begin(alice, CAROL);
    await assert.rejects(alice.engine.sendMessage(CAROL, "hi"), /not set up encryption/);
  });
});

describe("reliability and durability", () => {
  it("persists a received message BEFORE acknowledging it", async () => {
    await connectBoth();
    await begin(alice, BOB);
    await alice.engine.sendMessage(BOB, "durable first");
    await server.flush();
    assert.equal(bob.ackSnapshots.length, 1);
    assert.ok(bob.ackSnapshots[0]!.includes("durable first"));
  });

  it("drops a redelivered duplicate without decrypting it again, but re-acknowledges", async () => {
    await connectBoth();
    await begin(alice, BOB);
    await alice.engine.sendMessage(BOB, "once");
    await server.flush();
    const sent = server.log[0];
    const decrypts = bob.stats.decryptCalls;
    await bob.engine.handleFrame({ type: "message", id: sent.id, from: ALICE, envelope: sent.envelope });
    assert.deepEqual(texts(bob, ALICE), ["once"]);
    assert.equal(bob.stats.decryptCalls, decrypts); // not decrypted a second time
    assert.equal(bob.ackSnapshots.length, 2); // acknowledged again so the relay can forget it
  });

  it("a replayed ciphertext under a NEW message id is rejected, not shown twice", async () => {
    await connectBoth();
    await begin(alice, BOB);
    await alice.engine.sendMessage(BOB, "no replays");
    await server.flush();
    const sent = server.log[0];
    await bob.engine.handleFrame({ type: "message", id: crypto.randomUUID(), from: ALICE, envelope: sent.envelope });
    assert.deepEqual(texts(bob, ALICE), ["no replays"]);
    assert.ok(systemNotes(bob, ALICE).some((n) => /discarded/.test(n)));
  });

  it("discards a tampered message: nothing is displayed, it is acknowledged, a notice is recorded", async () => {
    server.tamper = (env) => {
      const { type, body } = decodeEnvelope(env);
      body[Math.floor(body.length / 2)] ^= 1;
      return encodeEnvelope(type, body);
    };
    await connectBoth();
    await begin(alice, BOB);
    await alice.engine.sendMessage(BOB, "TAMPER-ME");
    await server.flush();
    assert.deepEqual(texts(bob, ALICE), []);
    assert.ok(!bob.persisted.json!.includes("TAMPER-ME"));
    assert.ok(systemNotes(bob, ALICE).some((n) => /could not be verified or decrypted/.test(n)));
    assert.equal(bob.ackSnapshots.length, 1); // acked so it is not redelivered forever
  });

  it("discards malformed envelopes and ignores malformed frames", async () => {
    await connectBoth();
    await bob.engine.handleFrame({ type: "message", id: crypto.randomUUID(), from: ALICE, envelope: "###" });
    assert.ok(systemNotes(bob, ALICE).some((n) => /unreadable format/.test(n)));
    const calls = bob.persisted.calls;
    for (const bad of [null, "x", 5, { type: "message" }, { type: "message", id: "no", from: ALICE, envelope: "AA==" },
      { type: "message", id: crypto.randomUUID(), from: "nope", envelope: "AA==" }, { type: "mystery" }]) {
      await bob.engine.handleFrame(bad);
    }
    assert.equal(bob.persisted.calls, calls);
  });

  it("ignores messages claiming to come from the user themselves", async () => {
    await connectBoth();
    await bob.engine.handleFrame({ type: "message", id: crypto.randomUUID(), from: BOB, envelope: "AA==" });
    assert.equal(bob.ackSnapshots.length, 0);
    assert.equal(bob.engine.conversations().length, 0);
  });

  it("keeps an unsent message (with its ciphertext) and re-sends the SAME ciphertext on reconnect", async () => {
    await server.connect(BOB);
    await server.connect(ALICE);
    await begin(alice, BOB);
    server.disconnect(ALICE); // network drops
    await alice.engine.sendMessage(BOB, "sent while offline");
    assert.equal(alice.engine.messagesFor(BOB)[0].status, "sending");
    const stored = JSON.parse(alice.persisted.json!);
    const savedEnvelope: string = stored.messages[BOB][0].envelope; // durable before any network use
    assert.ok(savedEnvelope);
    assert.equal(server.frames.filter((f) => f.frame.type === "send").length, 0);

    await server.connect(ALICE); // reconnect
    await server.flush();
    const sends = server.frames.filter((f) => f.frame.type === "send");
    assert.equal(sends.length, 1);
    assert.equal(sends[0].frame.envelope, savedEnvelope); // identical ciphertext, no second encryption
    assert.deepEqual(texts(bob, ALICE), ["sent while offline"]);
    assert.equal(alice.engine.messagesFor(BOB)[0].status, "delivered");
  });

  it("retrying an already-accepted message is harmless (relay de-duplicates)", async () => {
    await connectBoth();
    await begin(alice, BOB);
    await alice.engine.sendMessage(BOB, "idempotent");
    const rec = alice.engine.messagesFor(BOB)[0];
    // Simulate a lost "accepted": resend the same frame before any receipt is processed.
    server.sendFrameFor(ALICE)({ type: "send", id: rec.id, to: BOB, envelope: rec.envelope });
    await server.flush();
    assert.deepEqual(texts(bob, ALICE), ["idempotent"]);
  });

  it("rate-limit errors are retried later; other relay errors mark the message failed", async () => {
    await server.connect(ALICE);
    await server.connect(BOB);
    await begin(alice, BOB);
    server.disconnect(ALICE);
    await alice.engine.sendMessage(BOB, "m1");
    await alice.engine.sendMessage(BOB, "m2");
    const [m1, m2] = alice.engine.messagesFor(BOB);
    await alice.engine.handleFrame({ type: "error", id: m1.id, code: "rate_limited" });
    await alice.engine.handleFrame({ type: "error", id: m2.id, code: "queue_full" });
    assert.equal(alice.engine.messagesFor(BOB)[0].status, "sending");
    assert.equal(alice.engine.messagesFor(BOB)[1].status, "failed");
    assert.equal(alice.engine.messagesFor(BOB)[1].envelope, undefined);
  });

  it("fails closed if local storage fails while sending: nothing is sent, nothing else proceeds", async () => {
    await connectBoth();
    await begin(alice, BOB);
    alice.failPersistAt.n = 1;
    await assert.rejects(alice.engine.sendMessage(BOB, "will not go out"), EngineError);
    assert.equal(server.frames.filter((f) => f.frame.type === "send").length, 0);
    assert.ok(alice.engine.hasFailed);
    await assert.rejects(alice.engine.sendMessage(BOB, "again"), /Could not save/);
  });

  it("does not acknowledge a received message if it could not be saved", async () => {
    await connectBoth();
    await begin(alice, BOB);
    await alice.engine.sendMessage(BOB, "unsaved");
    bob.failPersistAt.n = 1;
    await server.flush();
    assert.equal(bob.ackSnapshots.length, 0); // relay keeps it queued for redelivery
    assert.ok(bob.engine.hasFailed);
    assert.ok(!(bob.persisted.json ?? "").includes("unsaved")); // never reached storage
  });

  it("restores from persisted state and keeps working", async () => {
    await connectBoth();
    await begin(alice, BOB);
    await alice.engine.sendMessage(BOB, "before restart");
    await server.flush();
    const json = alice.persisted.json!;
    server.disconnect(ALICE);
    const alice2 = await makeClient(server, ALICE, "alice", json);
    assert.deepEqual(texts(alice2, BOB), ["before restart"]);
    await server.connect(ALICE);
    await alice2.engine.sendMessage(BOB, "after restart");
    await server.flush();
    assert.deepEqual(texts(bob, ALICE), ["before restart", "after restart"]);
  });

  it("rejects stored state that is corrupt or belongs to another account", async () => {
    await server.connect(ALICE);
    const json = alice.persisted.json!;
    assert.throws(() => ChatEngine.fromJson(alice.deps, "not json"), StateError);
    assert.throws(() => ChatEngine.fromJson({ ...alice.deps, userId: BOB }, json), StateError);
    assert.throws(() => ChatEngine.fromJson(alice.deps, JSON.stringify({ v: 1, userId: ALICE })), StateError);
  });
});

describe("identity keys and verification", () => {
  async function exchange(): Promise<void> {
    await connectBoth();
    await begin(alice, BOB);
    await alice.engine.sendMessage(BOB, "hi");
    await server.flush();
  }

  /** Bob loses his browser data and registers again with brand-new keys. */
  async function bobReregisters(): Promise<TestClient> {
    server.disconnect(BOB);
    const bob2 = await makeClient(server, BOB, "bobby");
    await server.connect(BOB);
    return bob2;
  }

  it("both sides compute the same safety number", async () => {
    await exchange();
    await begin(bob, ALICE);
    const a = await alice.engine.getSafetyNumber(BOB);
    const b = await bob.engine.getSafetyNumber(ALICE);
    assert.ok(a);
    assert.equal(a, b);
  });

  it("pins the identity on first contact and lets the user verify it", async () => {
    await exchange();
    assert.ok(alice.engine.contact(BOB)?.identityKey);
    await alice.engine.setVerified(BOB, true);
    assert.equal(alice.engine.contact(BOB)?.verified, true);
    await alice.engine.setVerified(BOB, false);
    assert.equal(alice.engine.contact(BOB)?.verified, false);
  });

  it("refuses to verify a contact with no pinned key", async () => {
    await connectBoth();
    await begin(alice, BOB);
    await assert.rejects(alice.engine.setVerified(BOB, true), EngineError);
  });

  it("blocks sending when the contact's identity key changed, and invalidates verification", async () => {
    await exchange();
    await alice.engine.setVerified(BOB, true);
    await bobReregisters();
    clock.skewMs += 60_000; // let the throttled identity check run
    const before = server.frames.filter((f) => f.frame.type === "send").length;
    await assert.rejects(alice.engine.sendMessage(BOB, "to the new bob?"), KeyChangedError);
    assert.equal(server.frames.filter((f) => f.frame.type === "send").length, before); // nothing sent
    const c = alice.engine.contact(BOB)!;
    assert.ok(c.keyChange);
    assert.equal(c.verified, false);
    assert.ok(systemNotes(alice, BOB).some((n) => /had verified this contact/.test(n)));
    await assert.rejects(alice.engine.setVerified(BOB, true), /Resolve the safety-number change/);
    assert.notEqual(await alice.engine.getSafetyNumber(BOB, "pending"), await alice.engine.getSafetyNumber(BOB, "current"));
  });

  it("after the user accepts the new key, messaging works again with a fresh session", async () => {
    await exchange();
    const bob2 = await bobReregisters();
    clock.skewMs += 60_000;
    await assert.rejects(alice.engine.sendMessage(BOB, "blocked"), KeyChangedError);
    await alice.engine.acceptKeyChange(BOB);
    assert.equal(alice.engine.contact(BOB)?.keyChange, undefined);
    assert.equal(alice.engine.contact(BOB)?.verified, false);
    await alice.engine.sendMessage(BOB, "hello new bob");
    await server.flush();
    assert.deepEqual(texts(bob2, ALICE), ["hello new bob"]);
  });

  it("holds an incoming message from a changed identity until the user accepts the key", async () => {
    await exchange();
    const bob2 = await bobReregisters();
    await begin(bob2, ALICE);
    await bob2.engine.sendMessage(ALICE, "it is really me");
    await server.flush();
    assert.deepEqual(texts(alice, BOB), ["hi"]); // not shown yet
    assert.ok(alice.engine.contact(BOB)?.keyChange);
    assert.equal(JSON.parse(alice.persisted.json!).quarantine.length, 1); // held as ciphertext, not displayed
    assert.equal(alice.ackSnapshots.length >= 1, true);
    await alice.engine.acceptKeyChange(BOB);
    assert.deepEqual(texts(alice, BOB), ["hi", "it is really me"]);
  });

  it("detects a changed key when a conversation is opened", async () => {
    await exchange();
    await bobReregisters();
    await alice.engine.refreshPeerIdentity(BOB);
    assert.ok(alice.engine.contact(BOB)?.keyChange);
  });

  it("creates a contact for an unknown sender with the profile the server reports", async () => {
    await connectBoth();
    const carol = await makeClient(server, CAROL, "carol");
    await server.connect(CAROL);
    await begin(carol, ALICE);
    await carol.engine.sendMessage(ALICE, "hi from carol");
    await server.flush();
    assert.equal(alice.engine.contact(CAROL)?.displayName, "Carol");
    assert.deepEqual(texts(alice, CAROL), ["hi from carol"]);
  });
});

describe("restart, replay and identity handling across restarts", () => {
  async function exchange(): Promise<void> {
    await connectBoth();
    await begin(alice, BOB);
    await alice.engine.sendMessage(BOB, "first");
    await server.flush();
  }

  it("a duplicate delivered after the recipient restarted is still not decrypted again", async () => {
    await exchange();
    const sent = server.log[0];
    server.disconnect(BOB);
    const bob2 = await makeClient(server, BOB, "bobby", bob.persisted.json!);
    await server.connect(BOB);
    await bob2.engine.handleFrame({ type: "message", id: sent.id, from: ALICE, envelope: sent.envelope });
    assert.deepEqual(texts(bob2, ALICE), ["first"]);
    assert.equal(bob2.stats.decryptCalls, 0); // dedup happened before any decryption
  });

  it("a replayed ciphertext under a new id is still rejected after a restart", async () => {
    await exchange();
    const sent = server.log[0];
    server.disconnect(BOB);
    const bob2 = await makeClient(server, BOB, "bobby", bob.persisted.json!);
    await server.connect(BOB);
    await bob2.engine.handleFrame({ type: "message", id: crypto.randomUUID(), from: ALICE, envelope: sent.envelope });
    assert.deepEqual(texts(bob2, ALICE), ["first"]);
    assert.ok(systemNotes(bob2, ALICE).some((n) => /discarded/.test(n)));
  });

  it("a pinned and verified identity survives a restart", async () => {
    await exchange();
    await alice.engine.setVerified(BOB, true);
    server.disconnect(ALICE);
    const alice2 = await makeClient(server, ALICE, "alice", alice.persisted.json!);
    assert.equal(alice2.engine.contact(BOB)?.verified, true);
    assert.equal(alice2.engine.contact(BOB)?.identityKey, alice.engine.contact(BOB)?.identityKey);
    assert.equal(await alice2.engine.getSafetyNumber(BOB), await alice.engine.getSafetyNumber(BOB));
  });

  it("a held message and the key-change warning survive a restart", async () => {
    await exchange();
    await alice.engine.setVerified(BOB, true);
    server.disconnect(BOB);
    const bob2 = await makeClient(server, BOB, "bobby");
    await server.connect(BOB);
    await begin(bob2, ALICE);
    await bob2.engine.sendMessage(ALICE, "from the new key");
    await server.flush();
    assert.ok(alice.engine.contact(BOB)?.keyChange);
    server.disconnect(ALICE);
    const alice2 = await makeClient(server, ALICE, "alice", alice.persisted.json!);
    const c = alice2.engine.contact(BOB)!;
    assert.ok(c.keyChange); // still flagged after a restart
    assert.equal(c.verified, false); // the old verification was withdrawn
    await assert.rejects(() => alice2.engine.sendMessage(BOB, "nope"), KeyChangedError);
    await alice2.engine.acceptKeyChange(BOB);
    assert.deepEqual(texts(alice2, BOB), ["first", "from the new key"]);
  });

  it("notifies the UI when sending discovers that the contact's key changed (so the list and badges refresh)", async () => {
    await exchange();
    await alice.engine.setVerified(BOB, true);
    server.disconnect(BOB);
    await makeClient(server, BOB, "bobby");
    await server.connect(BOB);
    clock.skewMs += 60_000;
    let notified = 0;
    alice.engine.subscribe(() => notified++);
    const before = alice.engine.getVersion();
    await assert.rejects(() => alice.engine.sendMessage(BOB, "x"), KeyChangedError);
    assert.ok(alice.engine.getVersion() > before);
    assert.ok(notified > 0);
    assert.ok(alice.engine.contact(BOB)?.keyChange);
  });

  it("accepting a key change leaves the contact unverified until re-verified", async () => {
    await exchange();
    await alice.engine.setVerified(BOB, true);
    server.disconnect(BOB);
    await makeClient(server, BOB, "bobby");
    await server.connect(BOB);
    clock.skewMs += 60_000;
    await assert.rejects(() => alice.engine.sendMessage(BOB, "x"), KeyChangedError);
    await alice.engine.acceptKeyChange(BOB);
    const c = alice.engine.contact(BOB)!;
    assert.equal(c.verified, false);
    assert.equal(c.verifiedKey, undefined);
    assert.equal(c.keyChange, undefined);
  });

  it("a truncated ciphertext is discarded and nothing is shown", async () => {
    server.tamper = (env) => {
      const { type, body } = decodeEnvelope(env);
      return encodeEnvelope(type, body.slice(0, Math.max(1, body.length - 8)));
    };
    await connectBoth();
    await begin(alice, BOB);
    await alice.engine.sendMessage(BOB, "TRUNCATE-ME");
    await server.flush();
    assert.deepEqual(texts(bob, ALICE), []);
    assert.ok(systemNotes(bob, ALICE).some((n) => /could not be verified or decrypted/.test(n)));
  });

  it("a message with an unknown type field is discarded as unreadable", async () => {
    await connectBoth();
    await begin(alice, BOB);
    await alice.engine.sendMessage(BOB, "typed");
    await server.flush();
    const forged = btoa(JSON.stringify({ v: 1, t: 9, b: "AAAA" }));
    await bob.engine.handleFrame({ type: "message", id: crypto.randomUUID(), from: ALICE, envelope: forged });
    assert.deepEqual(texts(bob, ALICE), ["typed"]);
    assert.ok(systemNotes(bob, ALICE).some((n) => /unreadable format/.test(n)));
  });

  it("a failed message does not leave plaintext or private keys in what the relay saw", async () => {
    await connectBoth();
    await begin(alice, BOB);
    await alice.engine.sendMessage(BOB, "MARKER-NOT-ON-RELAY");
    await server.flush();
    const seen = JSON.stringify([server.frames, server.log, server.messages]);
    assert.ok(!seen.includes("MARKER-NOT-ON-RELAY"));
    assert.ok(!seen.includes(JSON.parse(alice.persisted.json!).identity.priv)); // private identity key never left the client
  });
});
