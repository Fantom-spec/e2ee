// Wire format for what the relay carries. The server treats the whole string
// as an opaque blob; only clients interpret it.
//
//   envelope  = base64( utf8( JSON {"v":1,"t":<type>,"b":"<base64 ciphertext>"} ) )
//   plaintext = utf8( JSON {"v":1,"text":"...","sent_at":<unix ms>} )   (encrypted by the Signal session)
//
// "t" is the Signal message type: 1 = ordinary message, 3 = pre-key message
// (the first message of a session). It is not secret and the library needs it
// to choose the right decrypt call.

import { fromBase64, toBase64, utf8 } from "./bytes.ts";

export const ENVELOPE_VERSION = 1;
export const MAX_TEXT_CHARS = 4000;
export const MESSAGE_TYPE_WHISPER = 1;
export const MESSAGE_TYPE_PREKEY = 3;

export class EnvelopeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EnvelopeError";
  }
}

export interface DecodedEnvelope {
  type: number;
  body: Uint8Array;
}

export function encodeEnvelope(type: number, body: Uint8Array): string {
  if (type !== MESSAGE_TYPE_WHISPER && type !== MESSAGE_TYPE_PREKEY) {
    throw new EnvelopeError(`unsupported message type ${type}`);
  }
  const json = JSON.stringify({ v: ENVELOPE_VERSION, t: type, b: toBase64(body) });
  return toBase64(utf8.encode(json));
}

export function decodeEnvelope(envelope: string): DecodedEnvelope {
  let parsed: unknown;
  try {
    parsed = JSON.parse(utf8.decode(fromBase64(envelope)));
  } catch {
    throw new EnvelopeError("envelope is not valid");
  }
  if (typeof parsed !== "object" || parsed === null) throw new EnvelopeError("envelope is not an object");
  const o = parsed as Record<string, unknown>;
  const keys = Object.keys(o).sort().join(",");
  if (keys !== "b,t,v") throw new EnvelopeError("envelope has unexpected fields");
  if (o.v !== ENVELOPE_VERSION) throw new EnvelopeError("unsupported envelope version");
  if (o.t !== MESSAGE_TYPE_WHISPER && o.t !== MESSAGE_TYPE_PREKEY) throw new EnvelopeError("unsupported message type");
  if (typeof o.b !== "string") throw new EnvelopeError("envelope body missing");
  let body: Uint8Array;
  try {
    body = fromBase64(o.b);
  } catch {
    throw new EnvelopeError("envelope body is not base64");
  }
  if (body.length === 0) throw new EnvelopeError("envelope body is empty");
  return { type: o.t, body };
}

export function encodePlaintext(text: string, sentAt: number): Uint8Array {
  if (text.length === 0 || text.length > MAX_TEXT_CHARS) {
    throw new EnvelopeError(`message must be 1-${MAX_TEXT_CHARS} characters`);
  }
  return utf8.encode(JSON.stringify({ v: 1, text, sent_at: sentAt }));
}

export interface DecodedPlaintext {
  text: string;
  sentAt: number;
}

/** Strict parse of decrypted content. Anything else is treated as invalid. */
export function decodePlaintext(bytes: Uint8Array): DecodedPlaintext {
  let parsed: unknown;
  try {
    parsed = JSON.parse(utf8.decode(bytes));
  } catch {
    throw new EnvelopeError("message content is not valid");
  }
  if (typeof parsed !== "object" || parsed === null) throw new EnvelopeError("message content is not an object");
  const o = parsed as Record<string, unknown>;
  if (o.v !== 1 || typeof o.text !== "string" || typeof o.sent_at !== "number") {
    throw new EnvelopeError("message content has the wrong shape");
  }
  if (o.text.length === 0 || o.text.length > MAX_TEXT_CHARS) throw new EnvelopeError("message length out of range");
  if (!Number.isFinite(o.sent_at)) throw new EnvelopeError("message timestamp invalid");
  return { text: o.text, sentAt: o.sent_at };
}
