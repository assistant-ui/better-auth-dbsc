import {
  calculateJwkThumbprint,
  compactVerify,
  decodeProtectedHeader,
  importJWK,
  type JWK,
} from "jose";
import { DbscError } from "./errors.ts";

export type DbscAlgorithm = "ES256" | "RS256";

export const DBSC_ALGORITHMS: readonly DbscAlgorithm[] = ["ES256", "RS256"];

/** A device public key as stored after registration: a public JWK with `alg` set. */
export type DbscPublicKey = JWK & { alg: DbscAlgorithm };

export interface DbscProofClaims {
  jti: string;
  aud?: string | string[];
  iat?: number | string;
  authorization?: string;
  [claim: string]: unknown;
}

interface BaseVerifyInput {
  /** The challenge the server issued. The proof's `jti` must equal it. */
  challenge: string;
  /**
   * Origin the proof is for, e.g. `https://app.example.com`. When the JWT carries `aud`,
   * every audience must be a URL on this origin. Omit to skip the audience check.
   */
  expectedOrigin?: string;
}

export interface VerifyRegistrationProofInput extends BaseVerifyInput {
  /** Algorithms the server offered in `Secure-Session-Registration`. */
  algorithms?: readonly DbscAlgorithm[];
  /** Expected `authorization` claim, when the registration header carried one. */
  authorization?: string;
}

export interface VerifyRegistrationProofResult {
  publicKey: DbscPublicKey;
  /** RFC 7638 thumbprint of `publicKey`, for comparing keys. */
  thumbprint: string;
  algorithm: DbscAlgorithm;
  claims: DbscProofClaims;
}

export interface VerifyRefreshProofInput extends BaseVerifyInput {
  /** The key bound at registration. */
  publicKey: DbscPublicKey;
}

export interface VerifyRefreshProofResult {
  claims: DbscProofClaims;
}

const ACCEPTED_TYPES = new Set(["dbsc+jwt", "jwt"]);
const MIN_RSA_MODULUS_BITS = 2048;

/**
 * Verifies the registration proof the browser sends in `Secure-Session-Response`.
 * The JWT is self-signed by the new device key, which travels in the JOSE header as
 * `jwk` (current spec) or in the payload as `jwk` / `key` (earlier Chrome builds).
 */
export async function verifyRegistrationProof(
  jwt: string,
  input: VerifyRegistrationProofInput,
): Promise<VerifyRegistrationProofResult> {
  const algorithms = input.algorithms ?? DBSC_ALGORITHMS;
  const header = readHeader(jwt);
  const algorithm = readAlgorithm(header.alg, algorithms);
  const unverifiedPayload = readUnverifiedPayload(jwt);
  const embedded = header.jwk ?? unverifiedPayload.jwk ?? unverifiedPayload.key;
  const publicKey = toPublicKey(embedded, algorithm);

  const claims = await verifySignature(jwt, publicKey);
  checkClaims(claims, input);
  if (input.authorization !== undefined && claims.authorization !== input.authorization) {
    throw new DbscError(
      "AUTHORIZATION_MISMATCH",
      "The registration proof's `authorization` claim does not match the value the server issued.",
    );
  }
  return { publicKey, thumbprint: await calculateJwkThumbprint(publicKey), algorithm, claims };
}

/** Verifies a refresh proof against the key bound at registration. */
export async function verifyRefreshProof(
  jwt: string,
  input: VerifyRefreshProofInput,
): Promise<VerifyRefreshProofResult> {
  const header = readHeader(jwt);
  readAlgorithm(header.alg, [input.publicKey.alg]);
  // A refresh proof must not introduce a key; any embedded key is ignored and the
  // signature is checked against the bound key only.
  const claims = await verifySignature(jwt, input.publicKey);
  checkClaims(claims, input);
  return { claims };
}

/**
 * The proof JWT from a `Secure-Session-Response` value: an sf-string, or a bare JWT as
 * earlier drafts sent it. Parameters are ignored.
 */
export function parseProofHeader(header: string | null | undefined): string | null {
  return /^\s*"?([\w-]+\.[\w-]+\.[\w-]*)"?\s*(;|$)/.exec(header ?? "")?.[1] ?? null;
}

/** The proof's `jti`, read without verifying anything. Use it only to find the challenge. */
export function readUnverifiedChallenge(jwt: string): string | null {
  try {
    const jti = readUnverifiedPayload(jwt).jti;
    return typeof jti === "string" ? jti : null;
  } catch {
    return null;
  }
}

/** Parses a stored public key, or returns `null` when it is missing or not a DBSC key. */
export function parseStoredPublicKey(value: unknown): DbscPublicKey | null {
  if (typeof value !== "string" || value.length === 0) return null;
  try {
    const jwk = JSON.parse(value) as JWK;
    if (!isDbscAlgorithm(jwk.alg)) return null;
    return toPublicKey(jwk, jwk.alg);
  } catch {
    return null;
  }
}

function isDbscAlgorithm(value: unknown): value is DbscAlgorithm {
  return value === "ES256" || value === "RS256";
}

function readHeader(jwt: string) {
  if (typeof jwt !== "string" || jwt.split(".").length !== 3) {
    throw new DbscError(
      "MALFORMED_PROOF",
      "The DBSC proof must be a compact JWS with three segments.",
    );
  }
  let header;
  try {
    header = decodeProtectedHeader(jwt);
  } catch (cause) {
    throw new DbscError("MALFORMED_PROOF", "The DBSC proof has an unreadable JOSE header.", {
      cause,
    });
  }
  if (typeof header.typ === "string" && !ACCEPTED_TYPES.has(header.typ.toLowerCase())) {
    throw new DbscError(
      "UNSUPPORTED_TYPE",
      `The DBSC proof has \`typ\` "${header.typ}"; expected "dbsc+jwt".`,
    );
  }
  return header;
}

function readAlgorithm(alg: unknown, allowed: readonly DbscAlgorithm[]): DbscAlgorithm {
  if (typeof alg === "string" && (allowed as readonly string[]).includes(alg))
    return alg as DbscAlgorithm;
  throw new DbscError(
    "UNSUPPORTED_ALGORITHM",
    `The DBSC proof uses \`alg\` ${JSON.stringify(alg)}; expected one of ${allowed.join(", ")}.`,
  );
}

function readUnverifiedPayload(jwt: string): Record<string, unknown> {
  try {
    const segment = jwt.split(".")[1] ?? "";
    const parsed: unknown = JSON.parse(new TextDecoder().decode(base64UrlDecode(segment)));
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed))
      return parsed as Record<string, unknown>;
  } catch {
    // Reported below with a stable code.
  }
  throw new DbscError("MALFORMED_PROOF", "The DBSC proof payload is not a JSON object.");
}

function toPublicKey(value: unknown, algorithm: DbscAlgorithm): DbscPublicKey {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new DbscError(
      "INVALID_PUBLIC_KEY",
      "The registration proof does not carry a public key. Expected a JWK in the JOSE header `jwk`.",
    );
  }
  const jwk = value as JWK;
  if ("d" in jwk || "p" in jwk || "q" in jwk) {
    throw new DbscError(
      "INVALID_PUBLIC_KEY",
      "The DBSC key must be a public JWK; it contains private members.",
    );
  }
  if (algorithm === "ES256") {
    if (
      jwk.kty !== "EC" ||
      jwk.crv !== "P-256" ||
      typeof jwk.x !== "string" ||
      typeof jwk.y !== "string"
    ) {
      throw new DbscError(
        "INVALID_PUBLIC_KEY",
        "An ES256 DBSC key must be an EC P-256 JWK with `x` and `y`.",
      );
    }
    return { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y, alg: "ES256" };
  }
  if (jwk.kty !== "RSA" || typeof jwk.n !== "string" || typeof jwk.e !== "string") {
    throw new DbscError(
      "INVALID_PUBLIC_KEY",
      "An RS256 DBSC key must be an RSA JWK with `n` and `e`.",
    );
  }
  if (modulusBits(jwk.n) < MIN_RSA_MODULUS_BITS) {
    throw new DbscError(
      "INVALID_PUBLIC_KEY",
      `An RS256 DBSC key must be at least ${MIN_RSA_MODULUS_BITS} bits.`,
    );
  }
  return { kty: "RSA", n: jwk.n, e: jwk.e, alg: "RS256" };
}

async function verifySignature(jwt: string, publicKey: DbscPublicKey): Promise<DbscProofClaims> {
  let payload: Uint8Array;
  try {
    const key = await importJWK(publicKey, publicKey.alg);
    // compactVerify checks the signature only. Claims are checked by hand because
    // browsers have sent `iat` as a string, which jwtVerify would reject.
    ({ payload } = await compactVerify(jwt, key, { algorithms: [publicKey.alg] }));
  } catch (cause) {
    throw new DbscError(
      "INVALID_SIGNATURE",
      "The DBSC proof signature does not verify with the session key.",
      {
        cause,
      },
    );
  }
  let claims: unknown;
  try {
    claims = JSON.parse(new TextDecoder().decode(payload));
  } catch {
    claims = null;
  }
  if (!claims || typeof claims !== "object" || Array.isArray(claims)) {
    throw new DbscError("MALFORMED_PROOF", "The DBSC proof payload is not a JSON object.");
  }
  return claims as DbscProofClaims;
}

function checkClaims(claims: DbscProofClaims, input: BaseVerifyInput): void {
  if (typeof claims.jti !== "string" || !timingSafeEqual(claims.jti, input.challenge)) {
    throw new DbscError(
      "CHALLENGE_MISMATCH",
      "The DBSC proof's `jti` does not match the current challenge.",
    );
  }
  if (input.expectedOrigin === undefined || claims.aud === undefined) return;
  const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (audiences.length === 0) {
    throw new DbscError("AUDIENCE_MISMATCH", "A present DBSC `aud` must name an audience.");
  }
  for (const audience of audiences) {
    if (typeof audience !== "string" || originOf(audience) !== input.expectedOrigin) {
      throw new DbscError(
        "AUDIENCE_MISMATCH",
        `The DBSC proof's \`aud\` ${JSON.stringify(audience)} is not on ${input.expectedOrigin}.`,
      );
    }
  }
}

function originOf(url: string): string | null {
  try {
    return new URL(url).origin;
  } catch {
    return null;
  }
}

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function modulusBits(n: string): number {
  try {
    return base64UrlDecode(n).length * 8;
  } catch {
    return 0;
  }
}

function base64UrlDecode(value: string): Uint8Array {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(base64 + "=".repeat((4 - (base64.length % 4)) % 4));
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}
