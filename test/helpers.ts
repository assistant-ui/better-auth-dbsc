import { DatabaseSync } from "node:sqlite";
import { betterAuth, type BetterAuthOptions } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { exportJWK, generateKeyPair, SignJWT, type CryptoKey, type JWK } from "jose";
import { dbsc, type DbscOptions } from "../src/index.ts";

export const ORIGIN = "http://localhost:3000";
export const BASE = `${ORIGIN}/api/auth`;
export const BOUND_COOKIE = "better-auth.dbsc_token";
export const FRESH_PROOF_COOKIE = "better-auth.dbsc_fresh_proof";

/** A clock the plugin reads through its `now` option. */
export class Clock {
  constructor(public ms = Date.now()) {}
  now = () => this.ms;
  advance(seconds: number) {
    this.ms += seconds * 1000;
  }
}

/** A Better Auth instance on a fresh in-memory SQLite database, migrated for real. */
export async function createTestAuth(
  pluginOptions: DbscOptions = {},
  extra: Partial<BetterAuthOptions> = {},
  /** Install `dbsc()` after `extra.plugins` instead of before them. */
  { dbscLast = false }: { dbscLast?: boolean } = {},
) {
  const clock = new Clock();
  const database = new DatabaseSync(":memory:");
  const options = {
    baseURL: ORIGIN,
    secret: "test-secret-that-is-long-enough-for-better-auth-0123456789",
    database,
    emailAndPassword: { enabled: true },
    // Better Auth skips the origin check under NODE_ENV=test. Turn it back on so the
    // tests see what production sees.
    advanced: { disableOriginCheck: false },
    logger: { disabled: true },
    ...extra,
    plugins: dbscLast
      ? [...(extra.plugins ?? []), dbsc({ now: clock.now, ...pluginOptions })]
      : [dbsc({ now: clock.now, ...pluginOptions }), ...(extra.plugins ?? [])],
  } satisfies BetterAuthOptions;
  const { runMigrations } = await getMigrations(options);
  await runMigrations();
  const auth = betterAuth(options);
  return { auth, database, clock };
}

type Auth = Awaited<ReturnType<typeof createTestAuth>>["auth"];

/** The slice of a browser this protocol needs: a cookie jar. */
export class Browser {
  readonly cookies = new Map<string, string>();

  constructor(private readonly auth: Auth) {}

  get cookieHeader() {
    return [...this.cookies].map(([name, value]) => `${name}=${value}`).join("; ");
  }

  async fetch(path: string, init: RequestInit = {}): Promise<Response> {
    const headers = new Headers(init.headers);
    if (this.cookies.size > 0 && !headers.has("cookie")) headers.set("cookie", this.cookieHeader);
    const response = await this.auth.handler(new Request(`${BASE}${path}`, { ...init, headers }));
    for (const line of response.headers.getSetCookie()) {
      const [pair = "", ...attributes] = line.split(";");
      const eq = pair.indexOf("=");
      const name = pair.slice(0, eq).trim();
      const value = pair.slice(eq + 1).trim();
      const expired = attributes.some((attr) => /^\s*max-age=0\s*$/i.test(attr)) || value === "";
      if (expired) this.cookies.delete(name);
      else this.cookies.set(name, value);
    }
    return response;
  }

  signUp(email = `user-${crypto.randomUUID()}@example.com`) {
    return this.post("/sign-up/email", {
      email,
      password: "correct-horse-battery",
      name: "Test User",
    });
  }

  signIn(email: string) {
    return this.post("/sign-in/email", { email, password: "correct-horse-battery" });
  }

  post(path: string, body: unknown) {
    return this.fetch(path, {
      method: "POST",
      headers: { "content-type": "application/json", origin: ORIGIN },
      body: JSON.stringify(body),
    });
  }

  async getSession(): Promise<{
    session: Record<string, unknown>;
    user: Record<string, unknown>;
  } | null> {
    return (await this.fetch("/get-session")).json();
  }

  async status(): Promise<string> {
    return (await (await this.fetch("/dbsc/get-status")).json()).state;
  }

  /** A DBSC refresh as Chrome sends it: the session id header, and a proof when given. */
  refresh(proof?: string, sessionId = '"better-auth"') {
    const headers: Record<string, string> = { "sec-secure-session-id": sessionId };
    if (proof) headers["secure-session-response"] = proof;
    return this.fetch("/dbsc/refresh", { method: "POST", headers });
  }

  register(proof: string) {
    return this.fetch("/dbsc/register", {
      method: "POST",
      headers: { "secure-session-response": proof },
    });
  }
}

/** A device key pair, standing in for the TPM-backed key Chrome would create. */
export class Device {
  private constructor(
    readonly alg: "ES256" | "RS256",
    private readonly privateKey: CryptoKey,
    readonly publicJwk: JWK,
  ) {}

  static async create(alg: "ES256" | "RS256" = "ES256") {
    const { privateKey, publicKey } = await generateKeyPair(alg, { extractable: true });
    return new Device(alg, privateKey, await exportJWK(publicKey));
  }

  /** Registration proof: self-signed, key in the JOSE header (current spec). */
  registrationProof(challenge: string, claims: Record<string, unknown> = {}) {
    return new SignJWT({ jti: challenge, aud: `${BASE}/dbsc/register`, ...claims })
      .setProtectedHeader({ alg: this.alg, typ: "dbsc+jwt", jwk: this.publicJwk })
      .setIssuedAt()
      .sign(this.privateKey);
  }

  /** Refresh proof: signed by the bound key, no key attached. */
  refreshProof(challenge: string, claims: Record<string, unknown> = {}) {
    return new SignJWT({ jti: challenge, aud: `${BASE}/dbsc/refresh`, ...claims })
      .setProtectedHeader({ alg: this.alg, typ: "dbsc+jwt" })
      .setIssuedAt()
      .sign(this.privateKey);
  }

  /** Signs arbitrary header and payload, for malformed-proof tests. */
  sign(header: Record<string, unknown>, payload: Record<string, unknown>) {
    return new SignJWT(payload)
      .setProtectedHeader({ alg: this.alg, ...header })
      .sign(this.privateKey);
  }
}

/** The challenge in a `Secure-Session-Registration` or `Secure-Session-Challenge` value. */
export function challengeFrom(header: string | null): string {
  const match = header?.match(/challenge="([^"]+)"/) ?? header?.match(/^"([^"]+)"/);
  if (!match?.[1]) throw new Error(`No challenge in header: ${header}`);
  return match[1];
}

/** Signs up, then registers the device the way Chrome would. */
export async function signUpAndBind(auth: Auth, options: { device?: Device; email?: string } = {}) {
  const browser = new Browser(auth);
  const device = options.device ?? (await Device.create());
  const signUp = await browser.signUp(options.email);
  const registration = challengeFrom(signUp.headers.get("secure-session-registration"));
  const register = await browser.register(await device.registrationProof(registration));
  return { browser, device, register, registration };
}

/** Refreshes the bound cookie through the 403 round trip, like Chrome. */
export async function refreshLikeChrome(browser: Browser, device: Device) {
  const challenged = await browser.refresh();
  const challenge = challengeFrom(challenged.headers.get("secure-session-challenge"));
  return browser.refresh(await device.refreshProof(challenge));
}
