import type { BetterAuthPlugin } from "better-auth";
import { createAuthEndpoint, dispatchAuthEndpoint, sessionMiddleware } from "better-auth/api";
import { admin, bearer, jwt, multiSession, openAPI } from "better-auth/plugins";
import { describe, expect, it } from "vitest";
import packageJson from "../package.json" with { type: "json" };
import { dbscClient } from "../src/client.ts";
import {
  createMemoryDbscStore,
  dbsc,
  DBSC_ERROR_CODES,
  resolveDbscOptions,
  type DbscOptions,
} from "../src/index.ts";
import {
  BOUND_COOKIE,
  Browser,
  challengeFrom,
  createTestAuth,
  Device,
  ORIGIN,
  refreshLikeChrome,
  signUpAndBind,
  FRESH_PROOF_COOKIE,
} from "./helpers.ts";

const CHALLENGE = /^\d+\.[\w-]{22}\.[\w-]{43}$/;

describe("registration", () => {
  it("does not let a replayed registration outlive the first bound cookie", async () => {
    const { auth, clock } = await createTestAuth();
    const browser = new Browser(auth);
    const device = await Device.create();
    const signUp = await browser.signUp();
    const proof = await device.registrationProof(
      challengeFrom(signUp.headers.get("secure-session-registration")),
    );
    expect((await browser.register(proof)).status).toBe(200);

    // A lost answer can still be fetched again, but the cookie it gets dates from the
    // challenge: replays never stretch access past boundCookieMaxAge (300 s).
    clock.advance(290);
    expect((await browser.register(proof)).status).toBe(200);
    clock.advance(20);
    expect(await browser.getSession()).toBeNull();
  });

  it("offers DBSC on sign-up under both header names", async () => {
    const { auth } = await createTestAuth();
    const response = await new Browser(auth).signUp();

    expect(response.status).toBe(200);
    const standard = response.headers.get("secure-session-registration");
    expect(standard).toMatch(
      /^\(ES256 RS256\);path="\/api\/auth\/dbsc\/register";challenge="[^"]+"$/,
    );
    expect(challengeFrom(standard)).toMatch(CHALLENGE);
    expect(response.headers.get("sec-session-registration")).toBe(standard);
  });

  it("binds the session and returns the session config", async () => {
    const { auth } = await createTestAuth();
    const { browser, register } = await signUpAndBind(auth);

    expect(register.status).toBe(200);
    expect(await register.json()).toEqual({
      session_identifier: "better-auth",
      refresh_url: "/api/auth/dbsc/refresh",
      scope: {
        origin: ORIGIN,
        include_site: false,
        scope_specification: [{ type: "exclude", path: "/api/auth/dbsc/" }],
      },
      allowed_refresh_initiators: ["*"],
      credentials: [
        { type: "cookie", name: BOUND_COOKIE, attributes: "Path=/; HttpOnly; SameSite=Lax" },
      ],
    });
    expect(browser.cookies.has(BOUND_COOKIE)).toBe(true);
    expect(await browser.status()).toBe("bound");
    // The next challenge comes up front, so the first refresh needs no 403 round trip.
    const next = register.headers.get("secure-session-challenge");
    expect(next).toMatch(/^"[^"]+";id="better-auth"$/);
    expect(challengeFrom(next)).toMatch(CHALLENGE);
  });

  it("sets the bound cookie with exactly the attributes it advertises", async () => {
    const { auth } = await createTestAuth({}, { baseURL: "https://app.example.com" });
    const signUp = await auth.handler(
      new Request("https://app.example.com/api/auth/sign-up/email", {
        method: "POST",
        headers: { "content-type": "application/json", origin: "https://app.example.com" },
        body: JSON.stringify({
          email: "secure@example.com",
          password: "correct-horse-battery",
          name: "S",
        }),
      }),
    );
    const cookies = signUp.headers
      .getSetCookie()
      .map((line) => line.split(";")[0])
      .join("; ");
    const device = await Device.create();
    const challenge = challengeFrom(signUp.headers.get("secure-session-registration"));
    const register = await auth.handler(
      new Request("https://app.example.com/api/auth/dbsc/register", {
        method: "POST",
        headers: {
          cookie: cookies,
          "secure-session-response": await device.registrationProof(challenge, {
            aud: "https://app.example.com/api/auth/dbsc/register",
          }),
        },
      }),
    );
    const body = await register.json();
    expect(register.status, JSON.stringify(body)).toBe(200);
    const credential = body.credentials[0];
    expect(credential).toEqual({
      type: "cookie",
      name: "__Secure-better-auth.dbsc_token",
      attributes: "Path=/; HttpOnly; Secure; SameSite=Lax",
    });

    const setCookie = register.headers
      .getSetCookie()
      .find((line) => line.startsWith(`${credential.name}=`));
    const attributes = (setCookie ?? "")
      .split(";")
      .slice(1)
      .map((part) => part.trim().toLowerCase())
      .filter((part) => !/^(max-age|expires)=/.test(part));
    expect(new Set(attributes)).toEqual(new Set(credential.attributes.toLowerCase().split("; ")));
    expect(setCookie).toMatch(/Max-Age=300/);
  });

  it("accepts RS256 device keys", async () => {
    const { auth } = await createTestAuth();
    const { browser, register } = await signUpAndBind(auth, {
      device: await Device.create("RS256"),
    });
    expect(register.status).toBe(200);
    expect(await browser.status()).toBe("bound");
  });

  it("refuses a challenge this server did not issue for this session", async () => {
    const { auth } = await createTestAuth();
    const device = await Device.create();
    const a = new Browser(auth);
    const b = new Browser(auth);
    const aSignUp = await a.signUp();
    await b.signUp();

    const forged = await a.register(
      await device.registrationProof(`${Date.now()}.forged.not-a-mac`),
    );
    expect(forged.status).toBe(400);
    // Session A's challenge does not register session B.
    const crossed = await b.register(
      await device.registrationProof(
        challengeFrom(aSignUp.headers.get("secure-session-registration")),
      ),
    );
    expect(crossed.status).toBe(400);
    expect(await b.status()).toBe("unbound");
  });

  it("does not take a refresh challenge for a registration", async () => {
    const { auth } = await createTestAuth();
    const browser = new Browser(auth);
    await browser.signUp();
    // An unbound session gets no refresh challenge from the refresh endpoint, so mint one
    // the way the server would for a bound session and try to register with it.
    const { createDbscChallenge } = await import("../src/index.ts");
    const token = decodeURIComponent(browser.cookies.get("better-auth.session_token")!).split(
      ".",
    )[0]!;
    const refreshChallenge = await createDbscChallenge({
      secret: "test-secret-that-is-long-enough-for-better-auth-0123456789",
      purpose: "refresh",
      sessionToken: token,
      nowMs: Date.now(),
    });
    const device = await Device.create();
    expect((await browser.register(await device.registrationProof(refreshChallenge))).status).toBe(
      400,
    );
  });

  it("answers a repeated registration from the same key, and refuses another key", async () => {
    const { auth } = await createTestAuth();
    const { browser, device, registration } = await signUpAndBind(auth);

    // A lost answer: the browser sends the same registration again.
    const again = await browser.register(await device.registrationProof(registration));
    expect(again.status).toBe(200);

    const thief = await Device.create();
    const takeover = await browser.register(await thief.registrationProof(registration));
    expect(takeover.status).toBe(400);
    expect((await takeover.json()).code).toBe("DBSC_BOUND_TO_OTHER_KEY");
  });

  it("refuses an expired registration challenge", async () => {
    const { auth, clock } = await createTestAuth({ challengeExpiresIn: 60 });
    const browser = new Browser(auth);
    const signUp = await browser.signUp();
    clock.advance(61);
    const device = await Device.create();
    const response = await browser.register(
      await device.registrationProof(
        challengeFrom(signUp.headers.get("secure-session-registration")),
      ),
    );
    expect(response.status).toBe(400);
  });

  it("refuses an algorithm the server did not offer", async () => {
    const { auth } = await createTestAuth({ algorithms: ["ES256"] });
    const browser = new Browser(auth);
    const signUp = await browser.signUp();
    expect(signUp.headers.get("secure-session-registration")).toMatch(/^\(ES256\);/);
    const device = await Device.create("RS256");
    const response = await browser.register(
      await device.registrationProof(
        challengeFrom(signUp.headers.get("secure-session-registration")),
      ),
    );
    expect(response.status).toBe(400);
  });

  it("refuses a proof addressed to another origin", async () => {
    const { auth } = await createTestAuth();
    const browser = new Browser(auth);
    const device = await Device.create();
    const signUp = await browser.signUp();
    const response = await browser.register(
      await device.registrationProof(
        challengeFrom(signUp.headers.get("secure-session-registration")),
        {
          aud: "https://evil.example/api/auth/dbsc/register",
        },
      ),
    );
    expect(response.status).toBe(400);
    expect((await response.json()).code).toBe("DBSC_INVALID_PROOF");
  });

  it("keeps the proof's error as the cause on every supported Better Auth", async () => {
    const { auth } = await createTestAuth();
    const browser = new Browser(auth);
    const device = await Device.create();
    const signUp = await browser.signUp();
    const proof = await device.registrationProof(
      challengeFrom(signUp.headers.get("secure-session-registration")),
      { aud: "https://evil.example/api/auth/dbsc/register" },
    );
    const refusal = await auth.api
      .registerDbscSession({
        headers: new Headers({ cookie: browser.cookieHeader, "secure-session-response": proof }),
      })
      .catch((error: unknown) => error);
    expect(refusal).toMatchObject({ body: { code: "DBSC_INVALID_PROOF" } });
    expect((refusal as Error).cause).toMatchObject({ code: "AUDIENCE_MISMATCH" });
  });

  it("needs a signed-in session", async () => {
    const { auth } = await createTestAuth();
    const device = await Device.create();
    const response = await new Browser(auth).register(await device.registrationProof("anything"));
    expect(response.status).toBe(401);
  });

  it("does not re-register when Better Auth rolls the session expiry", async () => {
    // updateAge 0 makes every get-session refresh the session and set `newSession`.
    const { auth } = await createTestAuth({}, { session: { updateAge: 0 } });
    const browser = new Browser(auth);
    const signUp = await browser.signUp();
    const rolled = await browser.fetch("/get-session");
    expect(rolled.headers.get("secure-session-registration")).toBeNull();
    // The sign-in's challenge still registers.
    const device = await Device.create();
    const register = await browser.register(
      await device.registrationProof(
        challengeFrom(signUp.headers.get("secure-session-registration")),
      ),
    );
    expect(register.status).toBe(200);
  });

  it("lets shouldRegister skip a session, and honors the header names", async () => {
    const seen: (string | undefined)[] = [];
    const off = await createTestAuth({
      shouldRegister: (ctx) => {
        seen.push(ctx.context.newSession?.user.email);
        return false;
      },
    });
    const email = "skip@example.com";
    expect(
      (await new Browser(off.auth).signUp(email)).headers.get("secure-session-registration"),
    ).toBeNull();
    expect(seen).toEqual([email]);

    const standard = await createTestAuth({ advanced: { headers: "standard" } });
    const response = await new Browser(standard.auth).signUp();
    expect(response.headers.get("secure-session-registration")).not.toBeNull();
    expect(response.headers.get("sec-session-registration")).toBeNull();
  });
});

describe("refresh", () => {
  it("needs the session id header only the browser sends", async () => {
    const { auth } = await createTestAuth();
    const { browser } = await signUpAndBind(auth);
    const response = await browser.fetch("/dbsc/refresh", { method: "POST" });
    expect(response.status).toBe(400);
  });

  it("answers a proof-less refresh with 403 and a fresh challenge", async () => {
    const { auth } = await createTestAuth();
    const { browser } = await signUpAndBind(auth);
    const response = await browser.refresh();
    expect(response.status).toBe(403);
    expect(response.headers.get("secure-session-challenge")).toMatch(/^"[^"]+";id="better-auth"$/);
    expect(response.headers.get("sec-session-challenge")).toBe(
      response.headers.get("secure-session-challenge"),
    );
  });

  it("issues a new bound cookie for a valid proof, and only once", async () => {
    const { auth } = await createTestAuth();
    const { browser, device, register } = await signUpAndBind(auth);
    const proof = await device.refreshProof(
      challengeFrom(register.headers.get("secure-session-challenge")),
    );
    browser.cookies.delete(BOUND_COOKIE);

    const refresh = await browser.refresh(proof);
    expect(refresh.status).toBe(200);
    expect((await refresh.json()).session_identifier).toBe("better-auth");
    expect(await browser.status()).toBe("bound");

    browser.cookies.delete(BOUND_COOKIE);
    const replay = await browser.refresh(proof);
    expect(replay.status).toBe(403);
    expect(browser.cookies.has(BOUND_COOKIE)).toBe(false);
  });

  it("spends a proof once even when requests race", async () => {
    const { auth } = await createTestAuth();
    const { browser, device, register } = await signUpAndBind(auth);
    const proof = await device.refreshProof(
      challengeFrom(register.headers.get("secure-session-challenge")),
    );
    const results = await Promise.all([
      browser.refresh(proof),
      browser.refresh(proof),
      browser.refresh(proof),
    ]);
    expect(results.map((response) => response.status).sort()).toEqual([200, 403, 403]);
  });

  it("refuses an older challenge once a newer one is spent", async () => {
    const { auth, clock } = await createTestAuth();
    const { browser, device, register } = await signUpAndBind(auth);
    const older = challengeFrom(register.headers.get("secure-session-challenge"));
    clock.advance(1);
    expect((await refreshLikeChrome(browser, device)).status).toBe(200);
    expect((await browser.refresh(await device.refreshProof(older))).status).toBe(403);
  });

  it("refuses a proof from any key but the bound one, without spending the challenge", async () => {
    const { auth } = await createTestAuth();
    const { browser, device, register } = await signUpAndBind(auth);
    const thief = await Device.create();
    const challenge = challengeFrom(register.headers.get("secure-session-challenge"));

    expect((await browser.refresh(await thief.refreshProof(challenge))).status).toBe(403);
    expect((await browser.refresh(await device.refreshProof(challenge))).status).toBe(200);
  });

  it("refuses an expired challenge with a new one", async () => {
    const { auth, clock } = await createTestAuth({ challengeExpiresIn: 60 });
    const { browser, device, register } = await signUpAndBind(auth);
    const challenge = challengeFrom(register.headers.get("secure-session-challenge"));
    clock.advance(61);
    const response = await browser.refresh(await device.refreshProof(challenge));
    expect(response.status).toBe(403);
    expect(challengeFrom(response.headers.get("secure-session-challenge"))).not.toBe(challenge);
  });

  it("ends the browser's DBSC session when there is nothing to refresh", async () => {
    const { auth } = await createTestAuth();
    const { browser } = await signUpAndBind(auth);
    expect(await (await browser.refresh(undefined, '"another-app"')).json()).toEqual({
      continue: false,
    });
    expect(await (await new Browser(auth).refresh()).json()).toEqual({ continue: false });

    const plain = new Browser(auth);
    await plain.signUp();
    expect(await (await plain.refresh()).json()).toEqual({ continue: false });
  });
});

describe("enforcement", () => {
  it("leaves sessions alone in browsers without DBSC", async () => {
    const { auth } = await createTestAuth();
    const browser = new Browser(auth);
    await browser.signUp();
    expect(browser.cookies.has(BOUND_COOKIE)).toBe(false);
    expect(await browser.getSession()).not.toBeNull();
    expect(await browser.status()).toBe("unbound");
    expect((await browser.fetch("/list-sessions")).status).toBe(200);
  });

  it("treats a bound session without its bound cookie as signed out", async () => {
    const { auth } = await createTestAuth();
    const { browser } = await signUpAndBind(auth);
    expect(await browser.getSession()).not.toBeNull();

    browser.cookies.delete(BOUND_COOKIE);
    expect(await browser.getSession()).toBeNull();
    expect((await browser.fetch("/list-sessions")).status).toBe(401);
    expect(await browser.status()).toBe("no-session");
  });

  it("never lets a copied cookie sign the owner out", async () => {
    const { auth } = await createTestAuth();
    const { browser: owner } = await signUpAndBind(auth);
    const thief = new Browser(auth);
    thief.cookies.set("better-auth.session_token", owner.cookies.get("better-auth.session_token")!);

    expect((await thief.post("/revoke-sessions", {})).status).toBe(401);
    await thief.post("/sign-out", {});
    expect(await owner.getSession()).not.toBeNull();
  });

  it("refuses an expired bound cookie until the browser refreshes", async () => {
    const { auth, clock } = await createTestAuth({ boundCookieMaxAge: 60 });
    const { browser, device } = await signUpAndBind(auth);
    clock.advance(61);
    // The jar still sends the cookie; the server does not trust its own Max-Age.
    expect(await browser.getSession()).toBeNull();
    expect((await refreshLikeChrome(browser, device)).status).toBe(200);
    expect(await browser.getSession()).not.toBeNull();
  });

  it("refuses a bound cookie minted for another session", async () => {
    const { auth } = await createTestAuth();
    const a = await signUpAndBind(auth);
    const b = await signUpAndBind(auth);
    b.browser.cookies.set(BOUND_COOKIE, a.browser.cookies.get(BOUND_COOKIE)!);
    expect(await b.browser.getSession()).toBeNull();
  });

  it("applies to auth.api.getSession calls from server code", async () => {
    const { auth } = await createTestAuth();
    const { browser } = await signUpAndBind(auth);
    expect(
      await auth.api.getSession({ headers: new Headers({ cookie: browser.cookieHeader }) }),
    ).not.toBeNull();
    browser.cookies.delete(BOUND_COOKIE);
    expect(
      await auth.api.getSession({ headers: new Headers({ cookie: browser.cookieHeader }) }),
    ).toBeNull();
  });

  it("does not answer from session.cookieCache for a copied cookie", async () => {
    const { auth } = await createTestAuth(
      {},
      { session: { cookieCache: { enabled: true, maxAge: 300 } } },
    );
    const { browser } = await signUpAndBind(auth);
    expect(await browser.getSession()).not.toBeNull();
    expect([...browser.cookies.keys()].some((name) => name.endsWith("session_data"))).toBe(true);
    browser.cookies.delete(BOUND_COOKIE);
    expect(await browser.getSession()).toBeNull();
  });

  it("refuses a bound session sent as a bearer token", async () => {
    const { auth } = await createTestAuth({}, { plugins: [bearer()] });
    const { browser } = await signUpAndBind(auth);
    const token = decodeURIComponent(browser.cookies.get("better-auth.session_token")!);
    const viaBearer = new Browser(auth);
    const headers = { authorization: `Bearer ${token}` };
    expect((await viaBearer.fetch("/get-session", { headers })).status).toBe(401);
    expect((await viaBearer.fetch("/list-sessions", { headers })).status).toBe(401);
  });

  it("lets a user whose device key is gone sign in again", async () => {
    const { auth } = await createTestAuth();
    const email = "returning@example.com";
    const { browser } = await signUpAndBind(auth, { email });
    browser.cookies.delete(BOUND_COOKIE);

    const signIn = await browser.signIn(email);
    expect(signIn.status).toBe(200);
    expect(signIn.headers.get("secure-session-registration")).not.toBeNull();
    expect(await browser.status()).toBe("unbound");
  });

  it("observes without refusing when enforcement is off, and honors exclude", async () => {
    const observe = await createTestAuth({ enforcement: { enabled: false } });
    const a = await signUpAndBind(observe.auth);
    a.browser.cookies.delete(BOUND_COOKIE);
    expect(await a.browser.getSession()).not.toBeNull();

    const excluded = await createTestAuth({ enforcement: { exclude: ["/list-sessions"] } });
    const b = await signUpAndBind(excluded.auth);
    b.browser.cookies.delete(BOUND_COOKIE);
    expect((await b.browser.fetch("/list-sessions")).status).toBe(200);
    expect(await b.browser.getSession()).toBeNull();
  });

  it("clears the DBSC cookies on sign-out and drops the binding with the session", async () => {
    const { auth, database } = await createTestAuth();
    const { browser } = await signUpAndBind(auth);
    const rows = () =>
      (database.prepare('select count(*) as n from "dbscSession"').get() as { n: number }).n;
    expect(rows()).toBe(1);

    const response = await browser.post("/sign-out", {});
    expect(response.status).toBe(200);
    expect(browser.cookies.has(BOUND_COOKIE)).toBe(false);
    expect(rows()).toBe(0);
  });
});

const SESSION_COOKIE = "better-auth.session_token";

/** The signed session token in a jar, as `bearer()` hands it out in `set-auth-token`. */
const tokenOf = (browser: Browser) => decodeURIComponent(browser.cookies.get(SESSION_COOKIE)!);
const multiCookieOf = (browser: Browser) =>
  [...browser.cookies].find(([name]) => name.startsWith(`${SESSION_COOKIE}_multi-`))!;

// Better Auth merges before hooks in order and the last `cookie` written wins, so every
// carrier is tested with dbsc() both before and after the plugin that reads it.
for (const dbscLast of [false, true]) {
  describe(`other session carriers, dbsc() ${dbscLast ? "after" : "before"} the others`, () => {
    const withBearer = () => createTestAuth({}, { plugins: [bearer()] }, { dbscLast });
    const withMultiSession = (plugins: BetterAuthPlugin[] = []) =>
      createTestAuth({}, { plugins: [multiSession(), ...plugins] }, { dbscLast });

    it("refuses a stolen cookie sent again as a bearer token", async () => {
      const { auth } = await withBearer();
      const { browser: owner } = await signUpAndBind(auth);
      const thief = new Browser(auth);
      thief.cookies.set(SESSION_COOKIE, owner.cookies.get(SESSION_COOKIE)!);
      const headers = { authorization: `Bearer ${tokenOf(owner)}` };
      expect((await thief.fetch("/get-session", { headers })).status).toBe(401);
      expect((await thief.fetch("/list-sessions", { headers })).status).toBe(401);
      expect(await owner.getSession()).not.toBeNull();
    });

    it("refuses a stolen bearer token next to the thief's own session cookie", async () => {
      const { auth } = await withBearer();
      const { browser: owner } = await signUpAndBind(auth);
      const thief = new Browser(auth);
      await thief.signUp();
      for (const token of [tokenOf(owner), tokenOf(owner).split(".")[0]!]) {
        const headers = { authorization: `Bearer ${token}` };
        expect((await thief.fetch("/get-session", { headers })).status).toBe(401);
        expect((await thief.fetch("/list-sessions", { headers })).status).toBe(401);
      }
    });

    it("refuses a stolen bearer token alone", async () => {
      const { auth } = await withBearer();
      const { browser: owner } = await signUpAndBind(auth);
      const headers = { authorization: `Bearer ${tokenOf(owner)}` };
      expect((await new Browser(auth).fetch("/get-session", { headers })).status).toBe(401);
    });

    it("lets the bound browser send its own session as a bearer token", async () => {
      const { auth } = await withBearer();
      const { browser } = await signUpAndBind(auth);
      const headers = { authorization: `Bearer ${tokenOf(browser)}` };
      const response = await browser.fetch("/get-session", { headers });
      expect(response.status).toBe(200);
      expect((await response.json()).session.token).toBe(tokenOf(browser).split(".")[0]);
    });

    it("refuses a bound browser that sends another session as a bearer token", async () => {
      const { auth } = await withBearer();
      const { browser } = await signUpAndBind(auth);
      const other = new Browser(auth);
      await other.signUp();
      const headers = { authorization: `Bearer ${tokenOf(other)}` };
      expect((await browser.fetch("/get-session", { headers })).status).toBe(401);
    });

    it("ignores a bearer token that names no session, such as an OAuth access token", async () => {
      // Without bearer(): with it, the endpoint itself reads such a token as signed out.
      const { auth } = await createTestAuth({}, {}, { dbscLast });
      const { browser } = await signUpAndBind(auth);
      const headers = { authorization: "Bearer an-oauth-access-token" };
      expect((await browser.fetch("/list-sessions", { headers })).status).toBe(200);
    });

    it("leaves unbound sessions alone over bearer", async () => {
      const { auth } = await withBearer();
      const plain = new Browser(auth);
      await plain.signUp();
      const headers = { authorization: `Bearer ${tokenOf(plain)}` };
      const response = await new Browser(auth).fetch("/get-session", { headers });
      expect(response.status).toBe(200);
      expect(await response.json()).not.toBeNull();
    });

    it("does not leak a bound session through a copied multiSession() cookie", async () => {
      const events: Record<string, unknown>[] = [];
      const { auth } = await createTestAuth(
        { onEvent: (event) => void events.push(event) },
        { plugins: [multiSession()] },
        { dbscLast },
      );
      const { browser: owner } = await signUpAndBind(auth);
      const [name, value] = multiCookieOf(owner);
      const ownerSession = await owner.getSession();
      const thief = new Browser(auth);
      await thief.signUp();
      thief.cookies.set(name, value);

      const list = await thief.fetch("/multi-session/list-device-sessions");
      expect(list.status).toBe(200);
      const listed = (await list.json()) as { session: { id: string } }[];
      expect(listed.map(({ session }) => session.id)).not.toContain(ownerSession!.session.id);
      const sessionToken = tokenOf(owner).split(".")[0]!;
      expect((await thief.post("/multi-session/set-active", { sessionToken })).status).toBe(401);
      expect((await thief.post("/multi-session/revoke", { sessionToken })).status).toBe(401);
      expect((await thief.getSession())?.user.id).not.toBe(ownerSession!.user.id);
      expect(await owner.getSession()).not.toBeNull();
      expect(events).toContainEqual({
        type: "credential_missing",
        sessionId: ownerSession!.session.id,
        userId: ownerSession!.user.id,
        via: "multi-session",
      });
    });

    it("refuses a copied multiSession() cookie sent with a bearer token", async () => {
      const { auth } = await withMultiSession([bearer()]);
      const { browser: owner } = await signUpAndBind(auth);
      const thief = new Browser(auth);
      await thief.signUp();
      thief.cookies.set(...multiCookieOf(owner));
      const headers = { authorization: `Bearer ${tokenOf(thief)}` };
      const list = await thief.fetch("/multi-session/list-device-sessions", { headers });
      expect(list.status).toBe(401);
    });

    it("keeps multiSession() working for the bound browser", async () => {
      const { auth } = await withMultiSession();
      const { browser } = await signUpAndBind(auth);
      const list = await browser.fetch("/multi-session/list-device-sessions");
      expect(((await list.json()) as unknown[]).length).toBe(1);
      const sessionToken = tokenOf(browser).split(".")[0]!;
      expect((await browser.post("/multi-session/set-active", { sessionToken })).status).toBe(200);
    });

    /** A bound admin impersonating a plain user: the jar holds both sessions. */
    const impersonating = async (pluginOptions: DbscOptions = {}) => {
      const { auth, database } = await createTestAuth(
        pluginOptions,
        { plugins: [admin()] },
        { dbscLast },
      );
      const { browser: adminBrowser } = await signUpAndBind(auth);
      const adminSession = await adminBrowser.getSession();
      database
        .prepare('update "user" set "role" = ? where "id" = ?')
        .run("admin", adminSession!.user.id as string);
      const target = new Browser(auth);
      await target.signUp();
      const userId = (await target.getSession())!.user.id;
      const response = await adminBrowser.post("/admin/impersonate-user", { userId });
      expect(response.status).toBe(200);
      return { auth, adminBrowser, adminSession: adminSession! };
    };

    it("does not leak a bound admin session through a copied admin_session cookie", async () => {
      const events: Record<string, unknown>[] = [];
      const { auth, adminBrowser, adminSession } = await impersonating({
        onEvent: (event) => void events.push(event),
      });
      const thief = new Browser(auth);
      for (const [name, value] of adminBrowser.cookies) {
        if (name === SESSION_COOKIE || name.endsWith("admin_session"))
          thief.cookies.set(name, value);
      }

      const stop = await thief.post("/admin/stop-impersonating", {});
      expect(stop.status).not.toBe(200);
      expect(await stop.text()).not.toContain(adminSession.user.email);
      // The copied impersonation session is plain: the thief is the target user, not the admin.
      expect((await thief.getSession())?.user.id).not.toBe(adminSession.user.id);
      expect(events).toContainEqual({
        type: "credential_missing",
        sessionId: adminSession.session.id,
        userId: adminSession.user.id,
        via: "admin-session",
      });
    });

    it("lets the bound admin stop impersonating", async () => {
      const { adminBrowser, adminSession } = await impersonating();
      const stop = await adminBrowser.post("/admin/stop-impersonating", {});
      expect(stop.status).toBe(200);
      expect((await stop.json()).user.id).toBe(adminSession.user.id);
      expect((await adminBrowser.getSession())?.session.id).toBe(adminSession.session.id);
    });

    it("does not mint a jwt() token from a copied cookie", async () => {
      const { auth } = await createTestAuth({}, { plugins: [jwt()] }, { dbscLast });
      const { browser: owner } = await signUpAndBind(auth);
      expect((await owner.fetch("/token")).status).toBe(200);
      const thief = new Browser(auth);
      thief.cookies.set(SESSION_COOKIE, owner.cookies.get(SESSION_COOKIE)!);
      expect((await thief.fetch("/token")).status).toBe(401);
      const session = await thief.fetch("/get-session");
      expect(session.headers.get("set-auth-jwt")).toBeNull();
      expect(await session.json()).toBeNull();
    });
  });
}

describe("enabled", () => {
  it("does nothing while off, and enforces again once back on", async () => {
    let on = true;
    const { auth } = await createTestAuth({ enabled: () => on });
    const { browser, device } = await signUpAndBind(auth);
    browser.cookies.delete(BOUND_COOKIE);

    on = false;
    expect(
      (await new Browser(auth).signUp()).headers.get("secure-session-registration"),
    ).toBeNull();
    expect(await browser.getSession()).not.toBeNull();
    expect(await browser.status()).toBe("off");
    expect(await (await browser.refresh()).json()).toEqual({ continue: false });
    expect((await browser.register(await device.registrationProof("x"))).status).toBe(400);

    on = true;
    expect(await browser.getSession()).toBeNull();
    expect((await refreshLikeChrome(browser, device)).status).toBe(200);
    expect(await browser.getSession()).not.toBeNull();
  });
});

describe("store", () => {
  it("keeps bindings wherever the store puts them", async () => {
    const store = createMemoryDbscStore();
    const { auth, database } = await createTestAuth({ store });
    const { browser, device } = await signUpAndBind(auth);
    const session = await browser.getSession();

    expect(store.bindings.get(session?.session.id as string)?.thumbprint).toBeTypeOf("string");
    expect(
      (database.prepare('select count(*) as n from "dbscSession"').get() as { n: number }).n,
    ).toBe(0);
    browser.cookies.delete(BOUND_COOKIE);
    expect(await browser.getSession()).toBeNull();
    expect((await refreshLikeChrome(browser, device)).status).toBe(200);
  });

  it("releases a binding in a custom store when its session ends", async () => {
    const store = createMemoryDbscStore();
    const { auth } = await createTestAuth({ store });
    const signedOut = await signUpAndBind(auth);
    expect(store.bindings.size).toBe(1);
    await signedOut.browser.post("/sign-out", {});
    expect(store.bindings.size).toBe(0);

    const revoked = await signUpAndBind(auth);
    expect(store.bindings.size).toBe(1);
    await revoked.browser.post("/revoke-sessions", {});
    expect(store.bindings.size).toBe(0);
  });

  it("releases a binding in a custom store when its user is deleted", async () => {
    const store = createMemoryDbscStore();
    const { auth } = await createTestAuth({ store }, { user: { deleteUser: { enabled: true } } });
    const { browser } = await signUpAndBind(auth);
    expect(store.bindings.size).toBe(1);
    expect((await browser.post("/delete-user", {})).status).toBe(200);
    expect(store.bindings.size).toBe(0);
  });

  it("releases a binding in a custom store when Better Auth finds its session expired", async () => {
    const store = createMemoryDbscStore();
    const { auth, database } = await createTestAuth({ store });
    const { browser } = await signUpAndBind(auth);
    expect(store.bindings.size).toBe(1);
    database
      .prepare('update "session" set "expiresAt" = ?')
      .run(new Date(Date.now() - 1000).toISOString());
    expect(await browser.getSession()).toBeNull();
    expect(store.bindings.size).toBe(0);
  });

  it("refuses to start when sessions live only in secondary storage", async () => {
    const memory = new Map<string, string>();
    const secondaryStorage = {
      get: (key: string) => memory.get(key) ?? null,
      set: (key: string, value: string) => void memory.set(key, value),
      delete: (key: string) => void memory.delete(key),
      getAndDelete: (key: string) => {
        const value = memory.get(key) ?? null;
        memory.delete(key);
        return value;
      },
      increment: (key: string) => {
        const next = Number(memory.get(key) ?? 0) + 1;
        memory.set(key, String(next));
        return next;
      },
    };
    const { auth } = await createTestAuth({}, { secondaryStorage });
    await expect(auth.$context).rejects.toThrow(/storeSessionInDatabase/);
  });
});

describe("freshProof", () => {
  it("makes a bound session prove itself again before a sensitive action", async () => {
    const { auth, clock } = await createTestAuth({ freshProof: { paths: ["/update-user"] } });
    const { browser, device } = await signUpAndBind(auth);
    clock.advance(1);

    const first = await browser.post("/update-user", { name: "New Name" });
    expect(first.status).toBe(403);
    expect((await first.json()).code).toBe("DBSC_FRESH_PROOF_REQUIRED");
    expect(browser.cookies.has(BOUND_COOKIE)).toBe(false);
    const freshProof = browser.cookies.get(FRESH_PROOF_COOKIE);
    expect(freshProof).toBeTypeOf("string");

    // Chrome sees the bound cookie gone, refreshes with its key, then retries.
    clock.advance(1);
    expect((await refreshLikeChrome(browser, device)).status).toBe(200);
    expect((await browser.post("/update-user", { name: "New Name" })).status).toBe(200);

    // The answered challenge is spent, even if a copy of it is sent again.
    browser.cookies.set(FRESH_PROOF_COOKIE, freshProof!);
    expect((await browser.post("/update-user", { name: "Again" })).status).toBe(403);
  });

  it("is not answered by a bound cookie from before the challenge", async () => {
    const { auth, clock } = await createTestAuth({ freshProof: { paths: ["/update-user"] } });
    const { browser } = await signUpAndBind(auth);
    const copiedBound = browser.cookies.get(BOUND_COOKIE)!;
    clock.advance(1);
    await browser.post("/update-user", { name: "x" });

    browser.cookies.set(BOUND_COOKIE, copiedBound);
    expect((await browser.post("/update-user", { name: "x" })).status).toBe(403);
  });

  it("is not answered by a copied cookie minted on a server whose clock runs ahead", async () => {
    const { auth, clock } = await createTestAuth({ freshProof: { paths: ["/update-user"] } });
    const { browser, device } = await signUpAndBind(auth);
    // An instance 10 s ahead renews the bound cookie; the next request lands on one that isn't.
    clock.advance(10);
    expect((await refreshLikeChrome(browser, device)).status).toBe(200);
    clock.advance(-10);
    const copiedBound = browser.cookies.get(BOUND_COOKIE)!;
    expect((await browser.post("/update-user", { name: "x" })).status).toBe(403);

    // The thief ignores the response that deletes the bound cookie.
    browser.cookies.set(BOUND_COOKIE, copiedBound);
    expect((await browser.post("/update-user", { name: "x" })).status).toBe(403);
  });

  it("lets plain sessions through", async () => {
    const { auth } = await createTestAuth({ freshProof: { paths: ["/update-user"] } });
    const browser = new Browser(auth);
    await browser.signUp();
    expect((await browser.post("/update-user", { name: "x" })).status).toBe(200);
  });

  it("works for your own routes through auth.api.requireFreshProof", async () => {
    const { auth, clock } = await createTestAuth();
    const call = (cookie: string) =>
      auth.api.requireFreshProof({
        headers: new Headers({ cookie }),
        body: { action: "delete-account" },
        returnHeaders: true,
      });

    expect((await call("")).response.state).toBe("no-session");
    const plain = new Browser(auth);
    await plain.signUp();
    expect((await call(plain.cookieHeader)).response.state).toBe("unbound");

    const { browser, device } = await signUpAndBind(auth);
    clock.advance(1);
    const challenged = await call(browser.cookieHeader);
    expect(challenged.response.state).toBe("challenge");
    const freshProof = challenged.headers
      .getSetCookie()
      .find((line) => line.startsWith(`${FRESH_PROOF_COOKIE}=`))!;
    browser.cookies.set(
      FRESH_PROOF_COOKIE,
      freshProof.split(";")[0]!.slice(FRESH_PROOF_COOKIE.length + 1),
    );

    clock.advance(1);
    await refreshLikeChrome(browser, device);
    expect((await call(browser.cookieHeader)).response.state).toBe("answered");
  });

  it("is not reachable over HTTP", async () => {
    const { auth } = await createTestAuth();
    const response = await new Browser(auth).post("/dbsc/require-fresh-proof", { action: "x" });
    expect(response.status).toBe(404);
  });

  it("sends a navigation back to itself instead of answering it with JSON", async () => {
    const { auth, clock } = await createTestAuth({
      freshProof: { paths: ["/list-sessions", "/update-user"] },
    });
    const { browser, device } = await signUpAndBind(auth);
    clock.advance(1);
    const navigate = { "sec-fetch-mode": "navigate" };

    const first = await browser.fetch("/list-sessions?from=menu", { headers: navigate });
    expect(first.status).toBe(307);
    expect(first.headers.get("location")).toBe("/api/auth/list-sessions?from=menu");
    expect(browser.cookies.has(BOUND_COOKIE)).toBe(false);
    expect(browser.cookies.get(FRESH_PROOF_COOKIE)).toBeTypeOf("string");

    // Chrome holds the redirected request, refreshes with its key, then follows it.
    clock.advance(1);
    await refreshLikeChrome(browser, device);
    const followed = await browser.fetch("/list-sessions?from=menu", { headers: navigate });
    expect(followed.status).toBe(200);

    // A fetch from a page still gets the JSON refusal it can act on.
    clock.advance(1);
    const fetched = await browser.post("/update-user", { name: "x" });
    expect(fetched.status).toBe(403);
    expect((await fetched.json()).code).toBe("DBSC_FRESH_PROOF_REQUIRED");

    // A form post keeps its method and body through a 307.
    const { browser: other } = await signUpAndBind(auth);
    clock.advance(1);
    const form = await other.fetch("/update-user", {
      method: "POST",
      headers: { ...navigate, origin: ORIGIN, "content-type": "application/json" },
      body: JSON.stringify({ name: "From A Form" }),
    });
    expect(form.status).toBe(307);
    expect(form.headers.get("location")).toBe("/api/auth/update-user");
  });

  it("does not challenge an endpoint that an answered one runs inside its own request", async () => {
    // The OAuth provider's consent and continue endpoints re-enter `/oauth2/authorize`
    // through the hook pipeline with the same request. This plugin does the same.
    const inner = createAuthEndpoint(
      "/inner",
      { method: "POST", use: [sessionMiddleware] },
      (ctx) => ctx.json({ inner: true }),
    );
    const outer = createAuthEndpoint(
      "/outer",
      { method: "POST", use: [sessionMiddleware] },
      async (ctx) =>
        dispatchAuthEndpoint(inner, {
          ...ctx,
          asResponse: false,
          returnHeaders: false,
          returnStatus: false,
        } as never),
    );
    const nesting = { id: "nesting", endpoints: { inner, outer } } satisfies BetterAuthPlugin;
    const { auth, clock } = await createTestAuth(
      { freshProof: { paths: ["/outer", "/inner"] } },
      { plugins: [nesting] },
    );
    const { browser, device } = await signUpAndBind(auth);
    clock.advance(1);

    expect((await browser.post("/outer", {})).status).toBe(403);
    clock.advance(1);
    await refreshLikeChrome(browser, device);
    const answered = await browser.post("/outer", {});
    expect(answered.status).toBe(200);
    expect(await answered.json()).toEqual({ inner: true });

    // Called on its own, the inner endpoint still needs its own proof.
    clock.advance(1);
    expect((await browser.post("/inner", {})).status).toBe(403);
  });
});

describe("freshProof unbound policies", () => {
  it("denies plain sessions on paths that need a device-bound session", async () => {
    const { auth, clock } = await createTestAuth({
      freshProof: { paths: { "/update-user": { unbound: "deny" }, "/change-email": {} } },
    });
    const plain = new Browser(auth);
    await plain.signUp();
    const denied = await plain.post("/update-user", { name: "x" });
    expect(denied.status).toBe(403);
    expect((await denied.json()).code).toBe("DBSC_BINDING_REQUIRED");

    // A bound session gets there with a fresh proof.
    const { browser, device } = await signUpAndBind(auth);
    clock.advance(1);
    expect((await browser.post("/update-user", { name: "x" })).status).toBe(403);
    clock.advance(1);
    await refreshLikeChrome(browser, device);
    expect((await browser.post("/update-user", { name: "x" })).status).toBe(200);
  });

  it("asks plain sessions to be recent under fresh-session", async () => {
    const { auth, clock } = await createTestAuth(
      { freshProof: { paths: ["/update-user"], unbound: "fresh-session" } },
      { session: { freshAge: 60 } },
    );
    const plain = new Browser(auth);
    await plain.signUp();
    expect((await plain.post("/update-user", { name: "x" })).status).toBe(200);
    clock.advance(61);
    const stale = await plain.post("/update-user", { name: "x" });
    expect(stale.status).toBe(403);
    expect((await stale.json()).code).toBe("SESSION_NOT_FRESH");
  });

  it("checks both the cookie and the bearer session, whichever the endpoint reads", async () => {
    const { auth, database } = await createTestAuth(
      { freshProof: { paths: ["/update-user"], unbound: "fresh-session" } },
      { session: { freshAge: 60 }, plugins: [bearer()] },
    );
    const stale = new Browser(auth);
    await stale.signUp();
    const staleToken = decodeURIComponent(stale.cookies.get("better-auth.session_token")!);
    database
      .prepare('update "session" set "createdAt" = ? where "token" = ?')
      .run(new Date(Date.now() - 3_600_000).toISOString(), staleToken.split(".")[0]!);
    const fresh = new Browser(auth);
    await fresh.signUp();
    const response = await fresh.fetch("/update-user", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        origin: ORIGIN,
        authorization: `Bearer ${staleToken}`,
      },
      body: JSON.stringify({ name: "x" }),
    });
    expect(response.status).toBe(403);
    expect((await response.json()).code).toBe("SESSION_NOT_FRESH");
  });
});

describe("onEvent", () => {
  it("reports the lifecycle and theft signals without key material", async () => {
    const events: Record<string, unknown>[] = [];
    const { auth } = await createTestAuth({ onEvent: (event) => void events.push(event) });
    const { browser, device, register, registration } = await signUpAndBind(auth);
    const session = await browser.getSession();
    const ids = { sessionId: session?.session.id, userId: session?.user.id };
    const next = challengeFrom(register.headers.get("secure-session-challenge"));

    await browser.refresh();
    await browser.refresh(await (await Device.create()).refreshProof(next));
    await browser.refresh(await device.refreshProof(next));
    browser.cookies.delete(BOUND_COOKIE);
    await browser.getSession();
    await browser.refresh(undefined, '"another-app"');

    expect(events).toEqual([
      { type: "registered", ...ids },
      { type: "refresh_challenged", ...ids, reason: "missing_proof" },
      { type: "proof_rejected", ...ids, reason: "INVALID_SIGNATURE" },
      { type: "refreshed", ...ids },
      { type: "credential_missing", ...ids, via: "cookie" },
      { type: "terminated", reason: "other_identifier" },
    ]);
    const serialized = JSON.stringify(events);
    const sessionToken = decodeURIComponent(
      browser.cookies.get("better-auth.session_token")!,
    ).split(".")[0]!;
    for (const secret of [sessionToken, registration, next, device.publicJwk.x!]) {
      expect(serialized).not.toContain(secret);
    }
  });

  it("never changes a response when the handler throws", async () => {
    const { auth } = await createTestAuth({
      onEvent: () => {
        throw new Error("telemetry is down");
      },
    });
    const { register } = await signUpAndBind(auth);
    expect(register.status).toBe(200);
  });
});

describe("threat model", () => {
  it("writes nothing when it hands out a challenge (D1: challenge flood)", async () => {
    const { auth, database } = await createTestAuth();
    const { browser } = await signUpAndBind(auth);
    const snapshot = () => JSON.stringify(database.prepare('select * from "dbscSession"').all());
    const verifications = () =>
      (database.prepare('select count(*) as n from "verification"').get() as { n: number }).n;
    const before = snapshot();
    for (let i = 0; i < 5; i++) expect((await browser.refresh()).status).toBe(403);
    expect(snapshot()).toBe(before);
    expect(verifications()).toBe(0);
  });

  it("does not let garbage proofs spend a challenge (D2: lockout by replay)", async () => {
    const { auth } = await createTestAuth();
    const { browser, device, register } = await signUpAndBind(auth);
    const challenge = challengeFrom(register.headers.get("secure-session-challenge"));
    for (const garbage of [
      "a.b.c",
      `${challenge}.x.y`,
      await (await Device.create()).refreshProof(challenge),
    ]) {
      expect((await browser.refresh(garbage)).status).toBe(403);
    }
    expect((await browser.refresh(await device.refreshProof(challenge))).status).toBe(200);
  });
});

describe("rateLimit", () => {
  it("limits register and refresh through Better Auth's limiter", async () => {
    const { auth } = await createTestAuth(
      { rateLimit: { window: 60, max: 2 } },
      { rateLimit: { enabled: true, storage: "memory" } },
    );
    const { browser } = await signUpAndBind(auth);
    const statuses = [];
    for (let i = 0; i < 3; i++) statuses.push((await browser.refresh()).status);
    expect(statuses).toContain(429);
  });

  it("leaves register and refresh unlimited when turned off", async () => {
    const { auth } = await createTestAuth(
      { rateLimit: { enabled: false, max: 2 } },
      { rateLimit: { enabled: true, storage: "memory" } },
    );
    const { browser } = await signUpAndBind(auth);
    const statuses = [];
    for (let i = 0; i < 3; i++) statuses.push((await browser.refresh()).status);
    expect(statuses).toEqual([403, 403, 403]);
  });
});

describe("options", () => {
  it("reports every invalid option at once", () => {
    expect(() =>
      resolveDbscOptions({
        algorithms: [],
        boundCookieMaxAge: 0,
        challengeExpiresIn: 1.5,
        scope: { origin: "https://example.com/path", exclude: ["static"] },
        enforcement: { exclude: ["admin"] },
        freshProof: { paths: ["change-email"], expiresIn: -1 },
        rateLimit: { window: 0 },
        onEvent: "metrics" as unknown as DbscOptions["onEvent"],
        advanced: { sessionIdentifier: "" },
      }),
    ).toThrowErrorMatchingInlineSnapshot(`
      [BetterAuthError: Invalid dbsc() options:
        - \`algorithms\` must be a non-empty list of "ES256" and/or "RS256".
        - \`boundCookieMaxAge\` must be a positive integer.
        - \`challengeExpiresIn\` must be a positive integer.
        - \`scope.origin\` must be an origin such as \`https://app.example.com\`, with no path.
        - \`scope.exclude\` entries must be paths starting with \`/\`, such as \`/admin/\`.
        - \`enforcement.exclude\` entries must be paths starting with \`/\`, such as \`/admin/\`.
        - \`freshProof.paths\` entries must be paths starting with \`/\`, such as \`/admin/\`.
        - \`freshProof.expiresIn\` must be a positive integer.
        - \`rateLimit.window\` must be a positive integer.
        - \`onEvent\` must be a function.
        - \`advanced.sessionIdentifier\` must be non-empty printable ASCII.]
    `);
  });

  it("refuses a path that needs a fresh proof but is excluded from enforcement", () => {
    for (const exclude of ["/update-user", "/"]) {
      expect(() =>
        resolveDbscOptions({
          enforcement: { exclude: [exclude] },
          freshProof: { paths: ["/update-user"] },
        }),
      ).toThrow("`freshProof.paths` entry `/update-user` is excluded by `enforcement.exclude`");
    }
    expect(() =>
      resolveDbscOptions({
        enforcement: { exclude: ["/admin/"] },
        freshProof: { paths: { "/change-email": {}, "/admin/ban-user": { unbound: "deny" } } },
      }),
    ).toThrow("`freshProof.paths` entry `/admin/ban-user` is excluded by `enforcement.exclude`");
  });
});

describe("better auth conventions", () => {
  it("carries the package version and the same error codes on server and client", () => {
    const server = dbsc();
    const client = dbscClient();
    expect(server.version).toBe(packageJson.version);
    expect(client.version).toBe(packageJson.version);
    expect(server.$ERROR_CODES).toBe(DBSC_ERROR_CODES);
    expect(client.$ERROR_CODES).toBe(DBSC_ERROR_CODES);
    expect(DBSC_ERROR_CODES.DBSC_CREDENTIAL_REQUIRED).toMatchObject({
      code: "DBSC_CREDENTIAL_REQUIRED",
      message: "This request carries a device-bound session without its device credential",
    });
  });

  it("documents its HTTP endpoints in Better Auth's OpenAPI schema, and only those", async () => {
    const { auth } = await createTestAuth({}, { plugins: [openAPI()] });
    // `createTestAuth` types the API from dbsc() alone; openAPI() adds this endpoint.
    const api = auth.api as typeof auth.api & {
      generateOpenAPISchema(): Promise<{
        paths: Record<string, { get?: { description?: string } }>;
      }>;
    };
    const schema = await api.generateOpenAPISchema();
    const paths = Object.keys(schema.paths).filter((path) => path.startsWith("/dbsc/"));
    expect(paths.sort()).toEqual(["/dbsc/get-status", "/dbsc/refresh", "/dbsc/register"]);
    expect(schema.paths["/dbsc/get-status"]?.get?.description).toMatch(/bound to this device/);
  });
});
