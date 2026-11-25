/**
 * The values this package signs with the server secret. Each is
 * `<numbers…>.<nonce>.<mac>`, where the MAC covers a fixed domain, the session token and
 * every other part, so a value made for one purpose or session is worthless for another.
 * Nothing here is stored: a value is checked by recomputing its MAC.
 */
const encoder = new TextEncoder();

const DOMAIN = {
  challenge: "dbsc.challenge.v1",
  bound: "dbsc.bound-cookie.v2",
  freshProof: "dbsc.fresh-proof.v1",
} as const;

/** What a challenge is for. A registration challenge never answers a refresh, and the reverse. */
export type DbscChallengePurpose = "register" | "refresh";

export interface CreateDbscChallengeInput {
  secret: string;
  purpose: DbscChallengePurpose;
  sessionToken: string;
  nowMs: number;
}

/** A challenge the browser signs as its proof's `jti`: `<issued ms>.<nonce>.<mac>`. */
export async function createDbscChallenge(input: CreateDbscChallengeInput): Promise<string> {
  const issued = String(input.nowMs);
  const nonce = randomId();
  const mac = await sign(
    input.secret,
    DOMAIN.challenge,
    input.purpose,
    input.sessionToken,
    nonce,
    issued,
  );
  return `${issued}.${nonce}.${mac}`;
}

export interface ReadDbscChallengeInput {
  secret: string;
  purpose: DbscChallengePurpose;
  sessionToken: string;
  challenge: unknown;
  nowMs: number;
  ttlSeconds: number;
}

/**
 * When the challenge was issued, or `null` when it was not made by this server for this
 * purpose and session, or is older than `ttlSeconds`. Up to 30 seconds of clock skew
 * between instances is tolerated.
 */
export async function readDbscChallenge(
  input: ReadDbscChallengeInput,
): Promise<{ issuedAtMs: number } | null> {
  const parts = splitParts(input.challenge, 3);
  if (!parts) return null;
  const [issued, nonce, mac] = parts;
  if (!isDigits(issued)) return null;
  const age = input.nowMs - Number(issued);
  if (age > input.ttlSeconds * 1000 || age < -30_000) return null;
  const valid = await verify(
    input.secret,
    mac,
    DOMAIN.challenge,
    input.purpose,
    input.sessionToken,
    nonce,
    issued,
  );
  return valid ? { issuedAtMs: Number(issued) } : null;
}

export interface CreateBoundTokenInput {
  secret: string;
  sessionToken: string;
  expiresAtMs: number;
  /**
   * The nonce of the fresh-proof challenge the browser held when its key signed the
   * refresh that minted this cookie, if any. Only a cookie that names a challenge answers
   * it, so whether a cookie came after a challenge never rests on comparing clocks.
   */
  answers?: string | null;
}

/** No fresh-proof challenge: `-` is never a nonce. */
const NO_CHALLENGE = "-";

/** The bound cookie's value: `<expires s>.<answered nonce or ->.<nonce>.<mac>`. */
export async function createBoundToken(input: CreateBoundTokenInput): Promise<string> {
  const expires = String(Math.floor(input.expiresAtMs / 1000));
  const answers = input.answers && isNonce(input.answers) ? input.answers : NO_CHALLENGE;
  const nonce = randomId();
  const mac = await sign(input.secret, DOMAIN.bound, input.sessionToken, nonce, expires, answers);
  return `${expires}.${answers}.${nonce}.${mac}`;
}

export interface ReadBoundTokenInput {
  secret: string;
  sessionToken: string;
  token: string | null | undefined;
  nowMs: number;
}

/**
 * The cookie's expiry and the fresh-proof challenge it answers, or `null` unless it is
 * live and minted for this session.
 */
export async function readBoundToken(
  input: ReadBoundTokenInput,
): Promise<{ expiresAtMs: number; answers: string | null } | null> {
  const parts = splitParts(input.token, 4);
  if (!parts) return null;
  const [expires, answers, nonce, mac] = parts;
  if (!isDigits(expires) || (answers !== NO_CHALLENGE && !isNonce(answers))) return null;
  if (Number(expires) * 1000 <= input.nowMs) return null;
  const valid = await verify(
    input.secret,
    mac,
    DOMAIN.bound,
    input.sessionToken,
    nonce,
    expires,
    answers,
  );
  if (!valid) return null;
  return {
    expiresAtMs: Number(expires) * 1000,
    answers: answers === NO_CHALLENGE ? null : answers,
  };
}

export interface CreateFreshProofTokenInput {
  secret: string;
  sessionToken: string;
  action: string;
  nowMs: number;
}

/** A fresh-proof challenge for one action: `<issued ms>.<nonce>.<mac>`. */
export async function createFreshProofToken(input: CreateFreshProofTokenInput): Promise<string> {
  const issued = String(input.nowMs);
  const nonce = randomId();
  const mac = await sign(
    input.secret,
    DOMAIN.freshProof,
    input.sessionToken,
    input.action,
    nonce,
    issued,
  );
  return `${issued}.${nonce}.${mac}`;
}

export interface ReadFreshProofTokenInput extends Omit<CreateFreshProofTokenInput, "nowMs"> {
  token: string | null | undefined;
  nowMs: number;
  ttlSeconds: number;
}

/**
 * When the fresh-proof challenge was issued and its nonce, or `null` unless it is live and
 * for this action.
 */
export async function readFreshProofToken(
  input: ReadFreshProofTokenInput,
): Promise<{ issuedAtMs: number; nonce: string } | null> {
  const parts = splitParts(input.token, 3);
  if (!parts) return null;
  const [issued, nonce, mac] = parts;
  if (!isDigits(issued)) return null;
  const age = input.nowMs - Number(issued);
  if (age < 0 || age > input.ttlSeconds * 1000) return null;
  const valid = await verify(
    input.secret,
    mac,
    DOMAIN.freshProof,
    input.sessionToken,
    input.action,
    nonce,
    issued,
  );
  return valid ? { issuedAtMs: Number(issued), nonce } : null;
}

/**
 * The nonce in a fresh-proof challenge, unverified, for `createBoundToken`'s `answers`.
 * A refresh doesn't know the action the challenge is for, so it can't check the MAC; the
 * answer is checked in full when the bound cookie is compared against the challenge.
 */
export function readFreshProofNonce(token: string | null | undefined): string | null {
  const parts = splitParts(token, 3);
  return parts && isNonce(parts[1]) ? parts[1] : null;
}

function splitParts(value: unknown, count: 3): [string, string, string] | null;
function splitParts(value: unknown, count: 4): [string, string, string, string] | null;
function splitParts(value: unknown, count: number): string[] | null {
  if (typeof value !== "string") return null;
  const parts = value.split(".");
  if (parts.length !== count || parts.some((part) => part.length === 0)) return null;
  return parts;
}

function isDigits(value: string): boolean {
  return /^\d{1,16}$/.test(value);
}

function isNonce(value: string): boolean {
  return /^[A-Za-z0-9_-]{16,64}$/.test(value);
}

function randomId(): string {
  return base64UrlEncode(crypto.getRandomValues(new Uint8Array(16)));
}

async function sign(secret: string, ...parts: string[]): Promise<string> {
  const key = await importKey(secret);
  const mac = await crypto.subtle.sign("HMAC", key, encoder.encode(parts.join("\0")));
  return base64UrlEncode(new Uint8Array(mac));
}

/** Constant-time: WebCrypto's HMAC verify compares in constant time. */
async function verify(secret: string, mac: string, ...parts: string[]): Promise<boolean> {
  const bytes = base64UrlDecode(mac);
  if (!bytes) return false;
  return crypto.subtle.verify(
    "HMAC",
    await importKey(secret),
    bytes,
    encoder.encode(parts.join("\0")),
  );
}

function importKey(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
}

function base64UrlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlDecode(value: string): Uint8Array<ArrayBuffer> | null {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) return null;
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  try {
    const binary = atob(base64 + "=".repeat((4 - (base64.length % 4)) % 4));
    return Uint8Array.from(binary, (char) => char.charCodeAt(0));
  } catch {
    // A length no base64 string can have.
    return null;
  }
}
