import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import {
  createBoundToken,
  createDbscChallenge,
  createFreshProofToken,
  formatChallengeHeader,
  formatCookieAttributes,
  formatRegistrationHeader,
  parseSfString,
  parseProofHeader,
  parseStoredPublicKey,
  readBoundToken,
  readDbscChallenge,
  readFreshProofNonce,
  readFreshProofToken,
  verifyRefreshProof,
  verifyRegistrationProof,
  type DbscError,
} from "../src/core/index.ts";
import { Device } from "./helpers.ts";

async function codeOf(promise: Promise<unknown>): Promise<string | undefined> {
  try {
    await promise;
    return undefined;
  } catch (error) {
    return (error as DbscError).code;
  }
}

describe("verifyRegistrationProof", () => {
  it("returns the device key with private members stripped", async () => {
    const device = await Device.create();
    const result = await verifyRegistrationProof(await device.registrationProof("c1"), {
      challenge: "c1",
    });
    expect(result.algorithm).toBe("ES256");
    expect(result.thumbprint).toMatch(/^[\w-]{43}$/);
    expect(result.publicKey).toEqual({
      ...pick(device.publicJwk, ["kty", "crv", "x", "y"]),
      alg: "ES256",
    });
  });

  it("accepts the key in the payload, as earlier Chrome builds sent it", async () => {
    const device = await Device.create();
    const asJwk = await device.sign({ typ: "dbsc+jwt" }, { jti: "c1", jwk: device.publicJwk });
    const asKey = await device.sign({ typ: "jwt" }, { jti: "c1", key: device.publicJwk });
    await expect(verifyRegistrationProof(asJwk, { challenge: "c1" })).resolves.toBeTruthy();
    await expect(verifyRegistrationProof(asKey, { challenge: "c1" })).resolves.toBeTruthy();
  });

  it("accepts a string `iat`", async () => {
    const device = await Device.create();
    const jwt = await device.sign(
      { typ: "dbsc+jwt", jwk: device.publicJwk },
      { jti: "c1", iat: "1725579055" },
    );
    await expect(verifyRegistrationProof(jwt, { challenge: "c1" })).resolves.toBeTruthy();
  });

  it("rejects a key that does not match the signature", async () => {
    const signer = await Device.create();
    const other = await Device.create();
    const jwt = await signer.sign({ typ: "dbsc+jwt", jwk: other.publicJwk }, { jti: "c1" });
    expect(await codeOf(verifyRegistrationProof(jwt, { challenge: "c1" }))).toBe(
      "INVALID_SIGNATURE",
    );
  });

  it("rejects a private JWK", async () => {
    const { privateKey } = await generateKeyPair("ES256", { extractable: true });
    const privateJwk = await exportJWK(privateKey);
    // The key check runs before the signature check, so the signature can be anything.
    const jwt = `${b64url({ alg: "ES256", typ: "dbsc+jwt", jwk: privateJwk })}.${b64url({ jti: "c1" })}.sig`;
    expect(await codeOf(verifyRegistrationProof(jwt, { challenge: "c1" }))).toBe(
      "INVALID_PUBLIC_KEY",
    );
  });

  it("rejects RSA keys under 2048 bits", async () => {
    // jose will not generate a weak key, so use WebCrypto. The key size is checked
    // before the signature, so the signature can be anything.
    const pair = await crypto.subtle.generateKey(
      {
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: 1024,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      true,
      ["sign", "verify"],
    );
    const { kty, n, e } = await crypto.subtle.exportKey("jwk", pair.publicKey);
    const jwt = `${b64url({ alg: "RS256", typ: "dbsc+jwt", jwk: { kty, n, e } })}.${b64url({ jti: "c1" })}.sig`;
    expect(await codeOf(verifyRegistrationProof(jwt, { challenge: "c1" }))).toBe(
      "INVALID_PUBLIC_KEY",
    );
  });

  it("rejects unknown `typ`, unoffered `alg`, missing key, and garbage", async () => {
    const device = await Device.create();
    const wrongType = await device.sign({ typ: "at+jwt", jwk: device.publicJwk }, { jti: "c1" });
    const noKey = await device.sign({ typ: "dbsc+jwt" }, { jti: "c1" });
    expect(await codeOf(verifyRegistrationProof(wrongType, { challenge: "c1" }))).toBe(
      "UNSUPPORTED_TYPE",
    );
    expect(await codeOf(verifyRegistrationProof(noKey, { challenge: "c1" }))).toBe(
      "INVALID_PUBLIC_KEY",
    );
    expect(
      await codeOf(
        verifyRegistrationProof(await device.registrationProof("c1"), {
          challenge: "c1",
          algorithms: ["RS256"],
        }),
      ),
    ).toBe("UNSUPPORTED_ALGORITHM");
    expect(await codeOf(verifyRegistrationProof("not.a.jwt", { challenge: "c1" }))).toBe(
      "MALFORMED_PROOF",
    );
    expect(await codeOf(verifyRegistrationProof("", { challenge: "c1" }))).toBe("MALFORMED_PROOF");
  });

  it("rejects `alg: none`", async () => {
    const device = await Device.create();
    const header = b64url({ alg: "none", typ: "dbsc+jwt", jwk: device.publicJwk });
    expect(
      await codeOf(
        verifyRegistrationProof(`${header}.${b64url({ jti: "c1" })}.`, { challenge: "c1" }),
      ),
    ).toBe("UNSUPPORTED_ALGORITHM");
  });

  it("rejects HS256 signed with the public key as the secret (E1: algorithm confusion)", async () => {
    const device = await Device.create();
    const secret = new TextEncoder().encode(JSON.stringify(device.publicJwk));
    const jwt = await new SignJWT({ jti: "c1" })
      .setProtectedHeader({ alg: "HS256", typ: "dbsc+jwt", jwk: device.publicJwk })
      .sign(secret);
    expect(await codeOf(verifyRegistrationProof(jwt, { challenge: "c1" }))).toBe(
      "UNSUPPORTED_ALGORITHM",
    );
  });

  it("rejects an RSA key presented for ES256", async () => {
    const rsa = await Device.create("RS256");
    const ec = await Device.create("ES256");
    const jwt = await ec.sign({ typ: "dbsc+jwt", jwk: rsa.publicJwk }, { jti: "c1" });
    expect(await codeOf(verifyRegistrationProof(jwt, { challenge: "c1" }))).toBe(
      "INVALID_PUBLIC_KEY",
    );
  });

  it("checks `authorization` when the server issued one", async () => {
    const device = await Device.create();
    const jwt = await device.registrationProof("c1", { authorization: "abc" });
    await expect(
      verifyRegistrationProof(jwt, { challenge: "c1", authorization: "abc" }),
    ).resolves.toBeTruthy();
    expect(
      await codeOf(verifyRegistrationProof(jwt, { challenge: "c1", authorization: "xyz" })),
    ).toBe("AUTHORIZATION_MISMATCH");
  });

  it("checks every audience against the expected origin", async () => {
    const device = await Device.create();
    const ok = await device.registrationProof("c1", {
      aud: ["http://localhost:3000/a", "http://localhost:3000/b"],
    });
    const mixed = await device.registrationProof("c1", {
      aud: ["http://localhost:3000/a", "https://evil.example/"],
    });
    const input = { challenge: "c1", expectedOrigin: "http://localhost:3000" };
    await expect(verifyRegistrationProof(ok, input)).resolves.toBeTruthy();
    expect(await codeOf(verifyRegistrationProof(mixed, input))).toBe("AUDIENCE_MISMATCH");
  });
});

describe("verifyRefreshProof", () => {
  it("verifies against the stored key and ignores an embedded one", async () => {
    const device = await Device.create();
    const thief = await Device.create();
    const { publicKey } = await verifyRegistrationProof(await device.registrationProof("c1"), {
      challenge: "c1",
    });

    await expect(
      verifyRefreshProof(await device.refreshProof("c2"), { publicKey, challenge: "c2" }),
    ).resolves.toBeTruthy();
    const smuggled = await thief.sign({ typ: "dbsc+jwt", jwk: thief.publicJwk }, { jti: "c2" });
    expect(await codeOf(verifyRefreshProof(smuggled, { publicKey, challenge: "c2" }))).toBe(
      "INVALID_SIGNATURE",
    );
    expect(
      await codeOf(
        verifyRefreshProof(await device.refreshProof("old"), { publicKey, challenge: "c2" }),
      ),
    ).toBe("CHALLENGE_MISMATCH");
  });

  it("rejects a proof signed with a different algorithm than the bound key", async () => {
    const device = await Device.create();
    const rsa = await Device.create("RS256");
    const { publicKey } = await verifyRegistrationProof(await device.registrationProof("c1"), {
      challenge: "c1",
    });
    expect(
      await codeOf(
        verifyRefreshProof(await rsa.refreshProof("c2"), { publicKey, challenge: "c2" }),
      ),
    ).toBe("UNSUPPORTED_ALGORITHM");
  });
});

describe("parseStoredPublicKey", () => {
  it("round-trips a stored key and rejects junk", async () => {
    const device = await Device.create();
    const { publicKey } = await verifyRegistrationProof(await device.registrationProof("c1"), {
      challenge: "c1",
    });
    expect(parseStoredPublicKey(JSON.stringify(publicKey))).toEqual(publicKey);
    expect(parseStoredPublicKey(null)).toBeNull();
    expect(parseStoredPublicKey("{")).toBeNull();
    expect(parseStoredPublicKey(JSON.stringify({ ...publicKey, alg: "HS256" }))).toBeNull();
  });
});

describe("headers", () => {
  it("formats registration and challenge headers as structured fields", () => {
    expect(
      formatRegistrationHeader({
        algorithms: ["ES256", "RS256"],
        challenge: "abc",
        path: "/api/auth/dbsc/register",
      }),
    ).toBe('(ES256 RS256);path="/api/auth/dbsc/register";challenge="abc"');
    expect(
      formatRegistrationHeader({
        algorithms: ["ES256"],
        challenge: "a",
        path: "/r",
        authorization: 'x"y\\z',
      }),
    ).toBe('(ES256);path="/r";challenge="a";authorization="x\\"y\\\\z"');
    expect(formatChallengeHeader({ challenge: "c", sessionId: "s1" })).toBe('"c";id="s1"');
  });

  it("refuses values a structured field cannot carry", () => {
    expect(() => formatChallengeHeader({ challenge: "c\n", sessionId: "s" })).toThrow(TypeError);
    expect(() => formatRegistrationHeader({ algorithms: [], challenge: "c", path: "/r" })).toThrow(
      TypeError,
    );
  });

  it("parses sf-strings and bare tokens", () => {
    expect(parseSfString('"abc"')).toBe("abc");
    expect(parseSfString('"a\\"b"')).toBe('a"b');
    expect(parseSfString("abc")).toBe("abc");
    expect(parseSfString('"unterminated')).toBeNull();
    expect(parseSfString('"bad\\escape"')).toBeNull();
    expect(parseSfString(null)).toBeNull();
  });

  it("formats cookie attributes in Set-Cookie form", () => {
    expect(
      formatCookieAttributes({ path: "/", httpOnly: true, secure: true, sameSite: "lax" }),
    ).toBe("Path=/; HttpOnly; Secure; SameSite=Lax");
    expect(formatCookieAttributes({ domain: "example.com", sameSite: "none", secure: true })).toBe(
      "Domain=example.com; Path=/; Secure; SameSite=None",
    );
  });
});

describe("signed values", () => {
  const secret = "s".repeat(32);
  const now = 1_800_000_000_000;

  it("reads a challenge only for its purpose, session, and lifetime", async () => {
    const challenge = await createDbscChallenge({
      secret,
      purpose: "refresh",
      sessionToken: "t1",
      nowMs: now,
    });
    expect(challenge).toMatch(/^\d+\.[\w-]{22}\.[\w-]{43}$/);
    const read = (input: Partial<Parameters<typeof readDbscChallenge>[0]>) =>
      readDbscChallenge({
        secret,
        purpose: "refresh",
        sessionToken: "t1",
        challenge,
        nowMs: now,
        ttlSeconds: 60,
        ...input,
      });

    expect(await read({})).toEqual({ issuedAtMs: now });
    expect(await read({ purpose: "register" })).toBeNull();
    expect(await read({ sessionToken: "t2" })).toBeNull();
    expect(await read({ secret: "x".repeat(32) })).toBeNull();
    expect(await read({ nowMs: now + 61_000 })).toBeNull();
    expect(await read({ challenge: challenge.replace(/^\d+/, String(now + 1)) })).toBeNull();
    for (const junk of [null, 42, "", "a.b", "a.b.c.d", `${now}..mac`]) {
      expect(await read({ challenge: junk })).toBeNull();
    }
  });

  it("reads a bound cookie only for its session and before expiry", async () => {
    const challenge = await createFreshProofToken({
      secret,
      sessionToken: "t1",
      action: "/change-email",
      nowMs: now,
    });
    const answers = readFreshProofNonce(challenge)!;
    expect(answers).toBe(challenge.split(".")[1]);
    const token = await createBoundToken({
      secret,
      sessionToken: "t1",
      expiresAtMs: now + 60_000,
      answers,
    });
    expect(await readBoundToken({ secret, sessionToken: "t1", token, nowMs: now })).toEqual({
      expiresAtMs: now + 60_000,
      answers,
    });
    const plain = await createBoundToken({ secret, sessionToken: "t1", expiresAtMs: now + 60_000 });
    expect(plain).toMatch(/^\d+\.-\.[\w-]{22}\.[\w-]{43}$/);
    expect(await readBoundToken({ secret, sessionToken: "t1", token: plain, nowMs: now })).toEqual({
      expiresAtMs: now + 60_000,
      answers: null,
    });
    expect(await readBoundToken({ secret, sessionToken: "t2", token, nowMs: now })).toBeNull();
    expect(
      await readBoundToken({ secret, sessionToken: "t1", token, nowMs: now + 60_000 }),
    ).toBeNull();
    // Pushing the expiry out or naming another challenge breaks the MAC.
    const [expires, , nonce, mac] = token.split(".");
    for (const forged of [
      `${Number(expires) + 86_400}.${answers}.${nonce}.${mac}`,
      `${expires}.-.${nonce}.${mac}`,
      `${expires}.${"A".repeat(22)}.${nonce}.${mac}`,
    ]) {
      expect(
        await readBoundToken({ secret, sessionToken: "t1", token: forged, nowMs: now }),
      ).toBeNull();
    }
    for (const junk of [null, "", "abc", "1.2.3", "a.b.c.d"]) {
      expect(
        await readBoundToken({ secret, sessionToken: "t1", token: junk, nowMs: now }),
      ).toBeNull();
    }
  });

  it("reads a fresh-proof challenge only for its action", async () => {
    const token = await createFreshProofToken({
      secret,
      sessionToken: "t1",
      action: "/change-email",
      nowMs: now,
    });
    const read = (input: Partial<Parameters<typeof readFreshProofToken>[0]>) =>
      readFreshProofToken({
        secret,
        sessionToken: "t1",
        action: "/change-email",
        token,
        nowMs: now,
        ttlSeconds: 60,
        ...input,
      });
    expect(await read({})).toEqual({ issuedAtMs: now, nonce: token.split(".")[1] });
    expect(await read({ action: "/delete-user" })).toBeNull();
    expect(await read({ nowMs: now + 61_000 })).toBeNull();
    expect(await read({ nowMs: now - 1 })).toBeNull();
    for (const junk of [null, "", "a.b", "1.-.c"]) expect(readFreshProofNonce(junk)).toBeNull();
  });
});

describe("parseProofHeader", () => {
  it("reads an sf-string or a bare JWT", () => {
    expect(parseProofHeader('"a.b.c"')).toBe("a.b.c");
    expect(parseProofHeader("a.b.c")).toBe("a.b.c");
    expect(parseProofHeader('"a.b.c";param=1')).toBe("a.b.c");
    expect(parseProofHeader("not a jwt")).toBeNull();
    expect(parseProofHeader(null)).toBeNull();
  });
});

function pick<T extends object>(value: T, keys: string[]) {
  return Object.fromEntries(Object.entries(value).filter(([key]) => keys.includes(key)));
}

function b64url(value: unknown): string {
  return btoa(JSON.stringify(value)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
