// Safety number: a human-comparable digest of BOTH parties' identity keys.
//
// This is NOT Signal's numeric-fingerprint algorithm and is not interoperable
// with it. It is a plain SHA-512 hash of public data (user ids and public
// identity keys, in a canonical order, with a domain-separation prefix),
// shown as 12 groups of 5 digits so two people can read it to each other.
// If both screens show the same number, neither side is being given a
// substituted identity key. Nothing secret is involved.
//
// Each 5-byte slice of the digest is reduced modulo 100000. The tiny bias this
// introduces does not matter for a comparison aid (about 199 bits remain).

import { concat, u32be, utf8 } from "./bytes.ts";

const DOMAIN = "SecureChat-safety-number-v1";
const GROUPS = 12;

export interface Party {
  userId: string;
  identityKey: Uint8Array;
}

function encodeParty(p: Party): Uint8Array {
  const id = utf8.encode(p.userId);
  return concat(u32be(id.length), id, u32be(p.identityKey.length), p.identityKey);
}

export async function safetyNumber(a: Party, b: Party): Promise<string> {
  // Canonical order so both users compute the same value.
  const [first, second] = a.userId <= b.userId ? [a, b] : [b, a];
  const preimage = concat(utf8.encode(DOMAIN), new Uint8Array([0]), encodeParty(first), encodeParty(second));
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-512", preimage as BufferSource));
  const groups: string[] = [];
  for (let i = 0; i < GROUPS; i++) {
    let n = 0n;
    for (const byte of digest.subarray(i * 5, i * 5 + 5)) n = (n << 8n) | BigInt(byte);
    groups.push((n % 100000n).toString().padStart(5, "0"));
  }
  return groups.join(" ");
}
