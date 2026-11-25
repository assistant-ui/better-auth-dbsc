# @assistant-ui/better-auth-dbsc

**Device Bound Session Credentials for Better Auth: a stolen session cookie stops working on any other machine.**

When a browser with DBSC support signs in, it creates a key in the TPM. Today that means Chrome 146+ on Windows. Every few minutes the browser proves it still holds the key. The server accepts the session only alongside a short-lived cookie that only that key can renew. Cookies copied to another machine stop working within five minutes.

Browsers without DBSC ignore the registration header and keep using the normal Better Auth session. Nothing changes for them.

```sh
pnpm add @assistant-ui/better-auth-dbsc
```

```ts
import { betterAuth } from "better-auth";
import { dbsc } from "@assistant-ui/better-auth-dbsc";

export const auth = betterAuth({
  database,
  emailAndPassword: { enabled: true },
  plugins: [dbsc()],
});
```

Then add the `dbscSession` table (see [Schema](#schema)).

## What it does not do

- It does not protect sessions in browsers without DBSC. They work exactly as before, unless you refuse them on chosen paths with [`freshProof`](#freshproof-sensitive-actions).
- It does not stop malware running on the user's machine right now, because that malware can ask the TPM to sign. It stops cookies from being stolen and used somewhere else later.
- It does not work for bearer-token clients. A bearer client can't renew the bound cookie, so a bound session is refused over `Authorization: Bearer` unless the same request also carries that session's live bound cookie. Unbound sessions keep working over bearer. See [Other ways a session arrives](#other-ways-a-session-arrives).
- It has not been tested against real Chrome. See [Limits](#limits).

The threats it covers, and the ones it doesn't, are mapped in [docs/threat-model.md](docs/threat-model.md).

## How it works

```
sign-in ──▶ 200 + Secure-Session-Registration: (ES256 RS256);path="/api/auth/dbsc/register";challenge="c1"
                                  │
browser makes a TPM key, signs c1 ▼
POST /api/auth/dbsc/register   Secure-Session-Response: <JWT, jti=c1, jwk=public key>
        ◀── 200 session config + Set-Cookie: better-auth.dbsc_token (5 min)
            Secure-Session-Challenge: "c2";id="better-auth"

… 5 minutes later, before the next request …
POST /api/auth/dbsc/refresh    Sec-Secure-Session-Id: "better-auth"
        ◀── 403 + Secure-Session-Challenge: "c3"   (browser signs c3 and retries)
POST /api/auth/dbsc/refresh    Secure-Session-Response: <JWT, jti=c3>
        ◀── 200 + fresh dbsc_token + next challenge
        ◀── 200 {"continue": false} when the session is gone, unbound, or DBSC is off
```

Challenges are stateless: an HMAC under your Better Auth secret, bound to the session token and to one purpose (`register` or `refresh`). Issuing one writes nothing. A refresh proof is spent with one atomic write after its signature verifies, so a replay loses and garbage spends nothing.

Every request then goes through one check:

| Session | Bound cookie | Result |
|---|---|---|
| Not bound | any | Allowed. This is every browser without DBSC. |
| Bound | live, and minted for this session | Allowed. |
| Bound | missing, expired, or for another session | The session cookie is dropped from the request, so every endpoint sees a signed-out user and `getSession` returns `null`. With `Authorization: Bearer`: `401 DBSC_CREDENTIAL_REQUIRED`. |

Dropping the cookie, rather than revoking the session, means someone holding a copied cookie can't sign the owner out. Sign-in and sign-up still work for that request, so a user whose key is gone signs in again and gets a new session.

The check runs on every Better Auth endpoint and on `auth.api.*` calls from your own routes, such as `auth.api.getSession({ headers })`.

### Other ways a session arrives

The check reads every session token in the request, not only the session cookie, because plugins can hand an endpoint a different one:

- **`bearer()`** turns `Authorization: Bearer <token>` into the session cookie in its own hook. That hook may run after this one and rebuilds the cookie header from the original request, so dropping a cookie can't be relied on. The rule is: a request with `Authorization: Bearer` that carries any bound session, through the cookie, the bearer token, a `multiSession()` cookie or `admin_session`, gets `401 DBSC_CREDENTIAL_REQUIRED` unless the bound cookie proves every bound session in it and the session cookie and the bearer token name that one session (or no session). So the bound browser can still send its own session as a bearer token, a bearer token that isn't a session token (an OAuth access token) is left alone, and plain sessions over bearer work as before. A stolen token is refused however it is sent: as a bearer token, next to the copied cookie, or next to the thief's own session cookie.
- **`multiSession()`** keeps a `<session cookie>_multi-<token>` cookie per signed-in account. A copied one is dropped like the session cookie, so it can't list, switch to, or revoke the owner's session. In a DBSC browser only one session at a time has a live bound cookie, so switching back to another bound account there means signing in to it again, and sign-out revokes only the sessions the request proves. The others expire as usual.
- **`admin()`** keeps the admin's own session token in an `admin_session` cookie while they impersonate someone, and `/admin/stop-impersonating` swaps it back in. A copied one naming a bound session without its live bound cookie is dropped too, so it can't hand the admin's session or profile to whoever holds a copy of the impersonation session.

Helpers that read cookies without calling Better Auth are outside this check. `getCookieCache()` decodes the `session.cookieCache` cookie on its own, so in middleware it answers a copied pair of cookies with the owner's session; `getSessionCookie()` only says a cookie is there. Treat both as hints for redirects, and authorize with `auth.api.getSession({ headers })`. The same goes for a third-party plugin that carries a session token somewhere this list doesn't name.

## Schema

One table, one row per bound session, deleted with its session:

| Column | Type | Purpose |
|---|---|---|
| `sessionId` | string, unique, references `session.id` | The bound session. |
| `userId` | string, indexed, references `user.id` | Its user, for listing a user's bound devices. |
| `publicKey` | string | The device's public JWK, JSON-encoded, with `alg`. |
| `thumbprint` | string | RFC 7638 thumbprint of the key. |
| `lastRefreshAt` | date | Issue time of the newest refresh challenge spent. Older ones are refused. |
| `lastFreshProofAt` | date | Issue time of the newest fresh-proof challenge spent. |
| `proofCount` | number | How many proofs this binding has spent. |
| `createdAt` | date | When the session was bound. |

Generate the migration for your database the usual way:

```sh
npx @better-auth/cli generate   # or: npx @better-auth/cli migrate
```

The SQLite output is checked in at [`migrations/sqlite/0001_dbsc_session.sql`](migrations/sqlite/0001_dbsc_session.sql) and regenerated with `pnpm generate:migrations`. Rename the model or its fields with `schema`, for example `dbsc({ schema: { dbscSession: { modelName: "dbsc_session" } } })`.

To keep bindings somewhere else, such as Redis, KV, or an existing table, pass a [`store`](#store).

## Options

Every option is optional. The shape follows Better Auth's own plugins:
- **Optional features** are an object with `enabled`, like `session.cookieCache`.
- **Durations** are `maxAge` or `expiresIn`, in seconds.
- **Callbacks:** `onEvent` gets every DBSC event, like the Stripe plugin's `onEvent`, and `shouldRegister` decides which sessions are offered DBSC.
- **Protocol details** live under `advanced`.

These are the defaults:

```ts
dbsc({
  enabled: true, // or () => flags.dbsc, read on every request
  algorithms: ["ES256", "RS256"],
  boundCookieMaxAge: 300,
  challengeExpiresIn: 300,
  scope: { origin: undefined, includeSite: false, exclude: [], rules: [] },
  enforcement: { enabled: true, exclude: [] },
  freshProof: undefined, // { paths, unbound: "allow", expiresIn: 60 }
  rateLimit: { enabled: true, window: 60, max: 600 },
  onEvent: undefined, // (event) => void
  shouldRegister: undefined, // (ctx) => boolean
  now: Date.now, // the clock, for tests
  store: undefined, // the dbscSession table through Better Auth's adapter
  schema: undefined, // rename the model or its fields
  advanced: {
    sessionIdentifier: "better-auth",
    allowedRefreshInitiators: ["*"],
    headers: "both", // "standard" | "legacy" | "both"
  },
});
```

Invalid options throw at startup with every problem listed at once:

```
BetterAuthError: Invalid dbsc() options:
  - `boundCookieMaxAge` must be a positive integer.
  - `onEvent` must be a function.
```

| Option | What it controls |
|---|---|
| `enabled` | A kill switch, read on every request. Off means nothing is read, written, advertised, or refused. Bound sessions fall back to the plain cookie at once, and browsers are told to end their DBSC sessions at their next refresh. Turning it back on restores every binding. |
| `algorithms` | Signing algorithms offered, in preference order. Only `ES256` and `RS256` are accepted. |
| `boundCookieMaxAge` | Seconds a copied cookie keeps working. Shorter means more refreshes. |
| `challengeExpiresIn` | Seconds a registration or refresh challenge is accepted. |
| `scope.origin` | The origin the DBSC session covers. Defaults to the origin of Better Auth's `baseURL`. |
| `scope.includeSite` | Cover every subdomain of the site. On `app.example.com` the browser first checks `https://example.com/.well-known/device-bound-sessions` for a `registering_origins` entry. Only turn this on if you serve that file. |
| `scope.exclude` | Path prefixes the browser never holds for a refresh, such as `/assets/`. The DBSC endpoints are always excluded. |
| `scope.rules` | Raw `scope_specification` entries, sent after `exclude`, for anything `exclude` can't express. |
| `enforcement.enabled` | `true` drops the cookie of a bound session that has no live bound cookie. `false` binds sessions but never drops or refuses anything. That's how to roll this out: watch `onEvent`, then turn it on. |
| `enforcement.exclude` | Paths left alone, such as `["/health/"]`. A trailing `/` matches child paths. A `freshProof` path can't be excluded: `dbsc()` refuses to start rather than skip its proof. |
| `freshProof` | Paths that need a proof made after the request arrived. See [freshProof](#freshproof-sensitive-actions). |
| `rateLimit` | Per-address limit on `/dbsc/register` and `/dbsc/refresh`, through Better Auth's own limiter, which is on in production by default. Set it generously, because an office shares one address. |
| `onEvent` | Receives registrations, refreshes, refusals, and theft signals. See [Events](#events). |
| `shouldRegister` | Decides per sign-in whether to offer DBSC, for example only for some users. It runs only when a response issues a session token the request didn't carry. Return `false` to skip. |
| `now` | The clock in milliseconds, for tests. |
| `store` | A `DbscStore`, or `(ctx) => DbscStore`, to keep bindings outside the default table. See [Store](#store). |
| `schema` | Renames the `dbscSession` model or its fields. |
| `advanced.sessionIdentifier` | The browser keys DBSC sessions by site and this value. One value per app means a new sign-in replaces the old DBSC session instead of adding another. Give apps that share a site different values. |
| `advanced.allowedRefreshInitiators` | Sites whose links and redirects may trigger a refresh. `["*"]` lets a user coming back from an OAuth provider arrive signed in. `[]` allows same-site only. |
| `advanced.headers` | `"standard"` sends `Secure-Session-*`, from the W3C draft and shipping Chrome. `"legacy"` sends `Sec-Session-*`, from the origin trial. `"both"` sends both. Request headers are always read under both names. |

## freshProof: sensitive actions

The bound cookie lives five minutes, so a thief who copies it inside that window can use it until it expires. For endpoints whose effects outlast that window, such as adding a passkey, changing the email, or deleting the account, ask for a proof made after the request arrived:

```ts
dbsc({
  freshProof: {
    paths: {
      "/change-email": {},
      "/passkey/add-passkey": {},
      "/delete-user": { unbound: "deny" }, // only from a device-bound session
    },
    unbound: "fresh-session", // everything else: plain sessions must be recent
    expiresIn: 60,
  },
});
```

On a bound session, the first attempt is refused with `403 DBSC_FRESH_PROOF_REQUIRED` and its bound cookie removed. The browser refreshes with its key, and the retry passes once. A copied cookie can't answer, however fresh it is: the refresh writes the challenge's nonce into the new bound cookie, and only a cookie that names the challenge answers it. No clocks are compared, so instances whose clocks differ can't make an old cookie look newer.

A navigation (`Sec-Fetch-Mode: navigate`), such as a link to `/oauth2/authorize` or a form post, gets `307` back to the same URL instead, because the browser would show a JSON 403 to the user. The browser holds the redirected request, refreshes with its key, and follows it. A `307` keeps a form post's method and body.

An endpoint that another endpoint runs inside the same request is checked once. The OAuth provider's consent and continue endpoints re-enter `/oauth2/authorize` through the hook pipeline, so listing both `/oauth2/consent` and `/oauth2/authorize` asks for one proof, not two.

`unbound` decides what sessions that aren't bound get on those paths:
- `"allow"` passes them.
- `"fresh-session"` passes them only while they're younger than Better Auth's `session.freshAge`, else `403 SESSION_NOT_FRESH`.
- `"deny"` refuses them with `403 DBSC_BINDING_REQUIRED`.

For your own routes, call the same check from server code:

```ts
const { headers, response } = await auth.api.requireFreshProof({
  headers: request.headers,
  body: { action: "export-data" },
  returnHeaders: true,
});

if (response.state === "challenge") {
  // Send `headers` back with a 403. The browser refreshes with its key; the retry answers.
  return new Response(null, { status: 403, headers });
}
// "answered": bound, and proven since the challenge.
// "unbound", "no-session", "off": apply your own policy.
```

`requireFreshProof` is server-only and has no HTTP route.

## Status

`GET /api/auth/dbsc/get-status`, `auth.api.getDbscStatus({ headers })`, or `authClient.dbsc.getStatus()` answers `{ state }`:

| `state` | Meaning |
|---|---|
| `"bound"` | Bound to a device key and proven by a live bound cookie. |
| `"unbound"` | A plain session. |
| `"no-session"` | Signed out, or a bound session without its cookie. |
| `"off"` | `enabled` is false. |

## Events

```ts
dbsc({
  onEvent(event) {
    if (event.type === "proof_rejected") revokeUserSessions(event.userId);
    metrics.increment(`dbsc.${event.type}`);
  },
  shouldRegister: (ctx) => !ctx.context.newSession?.user.email.endsWith("@bots.example.com"),
});
```

| `type` | When |
|---|---|
| `registered` | The request created a session binding. Concurrent retries with the same key share that binding and emit one event. |
| `registration_refused` | With a `reason`: `invalid_challenge`, `invalid_proof`, `bound_to_other_key`, or `disabled`. |
| `refreshed` | A bound cookie was renewed. |
| `refresh_challenged` | With a `reason`: `missing_proof` (normal), `stale_challenge`, or `replayed`. |
| `proof_rejected` | A refresh carried a proof the bound key didn't sign. This is the strongest theft signal. The binding is untouched, so revoke the session here if you'd rather sign the owner out. |
| `credential_missing` | A bound session arrived without its bound cookie, `via` `cookie`, `bearer`, `multi-session` or `admin-session`. Once per session per request. One now and then is normal. A burst means a copied cookie. |
| `fresh_proof_challenged`, `fresh_proof_answered` | The `freshProof` round trip, with the `action`. |
| `unbound_refused` | A plain session was refused on a `freshProof` path, with the `policy`. |
| `terminated` | The browser was told to end its DBSC session: `disabled`, `no_session`, `not_bound`, or `other_identifier`. |

Events carry session ids, user ids, and reason codes, never keys, challenges, or cookies. `onEvent` runs through Better Auth's background task handler when one is configured. If it throws, the error is logged and the response doesn't change.

## Endpoints

| Path | Server | Client | Called by |
|---|---|---|---|
| `POST /dbsc/register` | `auth.api.registerDbscSession` | — | The browser, after sign-in. |
| `POST /dbsc/refresh` | `auth.api.refreshDbscSession` | — | The browser, when the bound cookie lapses. |
| `GET /dbsc/get-status` | `auth.api.getDbscStatus` | `authClient.dbsc.getStatus` | Your app. |
| none, server-only | `auth.api.requireFreshProof` | — | Your server code. |

The three HTTP endpoints carry OpenAPI metadata, so Better Auth's `openAPI()` plugin documents them.

## Error codes

`DBSC_ERROR_CODES` is built with Better Auth's `defineErrorCodes`, and each entry is a `{ code, message }`. Errors are thrown with `APIError.from`, and the codes are on `$ERROR_CODES` for both the server and the client plugin.

| Code | Status | When |
|---|---|---|
| `DBSC_CREDENTIAL_REQUIRED` | 401 | A request with `Authorization: Bearer` carried a bound session without its live bound cookie, or alongside another session. |
| `DBSC_FRESH_PROOF_REQUIRED` | 403 | A `freshProof` path needs a proof the browser hasn't made yet. |
| `DBSC_BINDING_REQUIRED` | 403 | A `freshProof` path with `unbound: "deny"` got a plain session. |
| `SESSION_NOT_FRESH` | 403 | Better Auth's own code, for `unbound: "fresh-session"`. |
| `DBSC_CHALLENGE_REQUIRED` | 403 | A refresh needs a proof over the new challenge. The browser retries. |
| `DBSC_SESSION_ID_REQUIRED` | 400 | A refresh without `Sec-Secure-Session-Id`, so not from the browser. |
| `DBSC_DISABLED`, `DBSC_PROOF_REQUIRED`, `DBSC_INVALID_CHALLENGE`, `DBSC_INVALID_PROOF`, `DBSC_BOUND_TO_OTHER_KEY` | 400 | A registration was refused. `DBSC_INVALID_PROOF` carries the `DbscError` as its `cause`. |
| `DBSC_SESSION_REQUIRED` | 401 | A registration without a signed-in session. |

## Store

```ts
interface DbscStore {
  find(sessionId: string): Promise<DbscBinding | null>;
  bind(binding: DbscBinding): Promise<boolean>; // false if the session was already bound
  spend(sessionId: string, kind: "refresh" | "fresh-proof", issuedAtMs: number): Promise<boolean>;
  delete(sessionId: string): Promise<void>; // the session ended: drop the binding and its spend state
}
```

`delete` runs whenever Better Auth deletes a session: sign-out, `revoke-session(s)`, a deleted user, or an expired session it comes across. Better Auth leaves sessions that expire unseen in place, so prune bindings whose session is gone the way you prune sessions. Don't expire a binding on a fixed TTL: sessions roll forward, and a binding that lapses before its session turns it back into a plain session. If sessions live only in `secondaryStorage`, Better Auth runs no delete hooks, so pruning is all there is.

`bind` and `spend` must be atomic. Of two racing registrations, at most one binds, and of two requests carrying the same proof, at most one spends. `spend` also refuses a challenge older than the newest one spent. The default store does this with one guarded `incrementOne`. `createMemoryDbscStore()` is there for tests and single-instance development.

If sessions live only in `secondaryStorage`, the default store refuses to start, because its rows reference `session.id`. Set `session.storeSessionInDatabase: true` or pass a `store`.

## Client

The browser drives DBSC by itself, so the client needs no code. The client plugin adds types, the error codes, and `getStatus`:

```ts
import { createAuthClient } from "better-auth/react";
import { dbscClient } from "@assistant-ui/better-auth-dbsc/client";

export const authClient = createAuthClient({ plugins: [dbscClient()] });
const { data } = await authClient.dbsc.getStatus(); // { state: "bound" | ... }
```

## Building blocks

`@assistant-ui/better-auth-dbsc/core` exports the protocol pieces without Better Auth, for another framework or your own middleware:

```ts
import {
  formatRegistrationHeader,
  formatChallengeHeader,
  verifyRegistrationProof,
  verifyRefreshProof,
  createDbscChallenge,
  readDbscChallenge,
  createBoundToken,
  readBoundToken,
  createFreshProofToken,
  readFreshProofToken,
  readFreshProofNonce,
} from "@assistant-ui/better-auth-dbsc/core";

const { publicKey, thumbprint } = await verifyRegistrationProof(jwt, {
  challenge,
  expectedOrigin: "https://app.example.com",
});
```

Failures throw `DbscError` with a stable `code`: `MALFORMED_PROOF`, `UNSUPPORTED_ALGORITHM`, `UNSUPPORTED_TYPE`, `INVALID_PUBLIC_KEY`, `INVALID_SIGNATURE`, `CHALLENGE_MISMATCH`, `AUTHORIZATION_MISMATCH`, or `AUDIENCE_MISMATCH`.

## Try it locally

You don't need Chrome to exercise the cryptography. The tests play the browser with [`jose`](https://github.com/panva/jose). They create ES256 and RS256 key pairs, sign registration and refresh proofs, and send them to a real Better Auth instance on in-memory SQLite.

```sh
pnpm install
pnpm test        # registration, refresh, replay races, enforcement, freshProof, events, threat model
pnpm example     # http://localhost:3000: a sign-up form and a protected /me route
                 # listens on 127.0.0.1 (HOST to change); random secret per run unless BETTER_AUTH_SECRET
```

CI runs lint, format, typecheck, tests, the build and a check of the packed tarball on Node 22 and 24, plus the tests against Better Auth 1.7.0, the oldest release `peerDependencies` admits.

## Releasing

```sh
pnpm release     # bumpp: commits "chore: release vX.Y.Z", tags vX.Y.Z, pushes
```

The tag runs the release workflow in the `npm-publish` environment, which waits for a required reviewer to approve and accepts only `v*` tags. It checks the tag against `package.json`, runs every check again, publishes to npm with provenance through trusted publishing (no npm token), and creates the GitHub release. A version already on npm (such as a first release published by hand) skips the publish and still gets its GitHub release. A prerelease such as `0.2.0-beta.1` publishes under the `next` dist-tag.

npm's trusted publisher must name the environment: `npm trust github @assistant-ui/better-auth-dbsc --repo assistant-ui/better-auth-dbsc --file release.yml --env npm-publish --allow-publish`.

## Limits

- **Not tested against real Chrome.** The wire format follows the W3C Editor's Draft (November 2026). Because Chrome builds have differed, the proof parser also accepts the key in the payload (`jwk` or `key`) and a string `iat`. Try it on Chrome 146+ on Windows before relying on it.
- **Paths outside `freshProof` stay exposed for up to `boundCookieMaxAge`.** Someone who copies both cookies can use them until the bound cookie expires.
- **DBSC requests skip Better Auth's origin check.** The browser's registration and refresh requests aren't guaranteed to carry `Origin`. On those two endpoints the CSRF defense is the signed proof over a server challenge, and refresh also requires the `Sec-Secure-Session-Id` header, which a page can't send cross-site without a preflight.
- **Two database reads per request for each session token it carries.** The gate reads the session and its binding (`findSession`, then the `dbscSession` row) to know whether a bound cookie is required. This happens on every Better Auth call, `getSession` included, even with `session.cookieCache` on. Each `multiSession()` or `admin_session` cookie adds two more.
- **The `authorization` registration parameter isn't sent.** `verifyRegistrationProof` checks it when you pass one.
- **Only the SQLite migration is checked in.** Postgres and MySQL come from the Better Auth CLI and haven't been tested here.
