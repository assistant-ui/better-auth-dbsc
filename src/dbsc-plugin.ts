import type { BetterAuthPlugin, InferOptionSchema, Session } from "better-auth";
import { BASE_ERROR_CODES, BetterAuthError } from "better-auth";
import { APIError, createAuthEndpoint, createAuthMiddleware } from "better-auth/api";
import { mergeSchema } from "better-auth/db";
import {
  DBSC_TERMINATE,
  formatCookieAttributes,
  type DbscScopeRule,
  type DbscSessionConfig,
} from "./core/config.ts";
import {
  formatChallengeHeader,
  formatRegistrationHeader,
  getDbscHeaderNames,
  parseSfString,
  readDbscHeader,
  type DbscHeaderNames,
} from "./core/headers.ts";
import {
  DBSC_ALGORITHMS,
  parseProofHeader,
  readUnverifiedChallenge,
  verifyRefreshProof,
  verifyRegistrationProof,
  type DbscAlgorithm,
} from "./core/proof.ts";
import {
  createBoundToken,
  createDbscChallenge,
  createFreshProofToken,
  readBoundToken,
  readDbscChallenge,
  readFreshProofNonce,
  readFreshProofToken,
} from "./core/token.ts";
import {
  createAdapterDbscStore,
  dbscSchema,
  type DbscBinding,
  type DbscStore,
  type DbscStoreAdapter,
} from "./store.ts";
import { DBSC_ERROR_CODES } from "./error-codes.ts";
import packageJson from "../package.json" with { type: "json" };

export { DBSC_ERROR_CODES };

export const DBSC_REGISTER_PATH = "/dbsc/register";
export const DBSC_REFRESH_PATH = "/dbsc/refresh";
/** Cookie keys passed to Better Auth's cookie factory, so `advanced.cookies.<key>` applies. */
export const DBSC_COOKIE_KEYS = { bound: "dbsc_token", freshProof: "dbsc_fresh_proof" } as const;

/**
 * What a session that is not bound to a device gets on a `freshProof` path.
 *
 * - `"allow"`: passes; the endpoint's own checks stand. Browsers without DBSC keep working.
 * - `"fresh-session"`: passes only while the session is younger than Better Auth's
 *   `session.freshAge`, else `403 SESSION_NOT_FRESH`.
 * - `"deny"`: `403 DBSC_BINDING_REQUIRED`. Only DBSC browsers get through: use it for
 *   the few routes that must resist malware reading the browser profile.
 */
export type DbscUnboundPolicy = "allow" | "fresh-session" | "deny";

export interface DbscFreshProofRule {
  /** Overrides `freshProof.unbound` for this path. */
  unbound?: DbscUnboundPolicy;
}

export type DbscRefusalReason =
  | "invalid_challenge"
  | "invalid_proof"
  | "bound_to_other_key"
  | "disabled";

/**
 * One DBSC event, for `onEvent`. Events carry session and user ids and reason codes,
 * never keys, challenges, cookies, or tokens.
 */
export type DbscEvent =
  | { type: "registered"; sessionId: string; userId: string }
  | { type: "registration_refused"; sessionId: string; userId: string; reason: DbscRefusalReason }
  | { type: "refreshed"; sessionId: string; userId: string }
  | {
      type: "refresh_challenged";
      sessionId: string;
      userId: string;
      reason: "missing_proof" | "stale_challenge" | "replayed";
    }
  /**
   * A refresh for a bound session carried a proof the bound key did not sign: the
   * strongest theft signal. The binding is untouched; revoke the session here if you
   * would rather sign the owner out than let a thief keep trying.
   */
  | { type: "proof_rejected"; sessionId: string; userId: string; reason: string }
  /**
   * A bound session arrived without a live bound cookie and was treated as signed out.
   * Expected now and then from a real browser; a burst of them is a copied cookie.
   */
  | {
      type: "credential_missing";
      sessionId: string;
      userId: string;
      via: DbscCarrier;
    }
  | { type: "fresh_proof_challenged"; sessionId: string; userId: string; action: string }
  | { type: "fresh_proof_answered"; sessionId: string; userId: string; action: string }
  | {
      type: "unbound_refused";
      sessionId: string;
      userId: string;
      action: string;
      policy: DbscUnboundPolicy;
    }
  | { type: "terminated"; reason: "disabled" | "no_session" | "not_bound" | "other_identifier" };

/** Where a request carries a session token: see `dbsc()`'s gate. */
export type DbscCarrier = "cookie" | "bearer" | "multi-session";

type HookContext = Parameters<Parameters<typeof createAuthMiddleware>[0]>[0];
type AuthContext = HookContext["context"];
type Awaitable<T> = T | Promise<T>;

export interface DbscOptions {
  /**
   * Turns DBSC on or off, read on every request. Off means nothing is read, written,
   * advertised, or refused: bound sessions fall back to the plain session cookie at once,
   * and browsers are told to end their DBSC sessions at the next refresh. Turning it back
   * on restores every binding.
   * @default true
   */
  enabled?: boolean | (() => Awaitable<boolean>);
  /**
   * Signing algorithms offered to the browser, in preference order.
   * @default ["ES256", "RS256"]
   */
  algorithms?: DbscAlgorithm[];
  /**
   * Lifetime of the bound cookie, in seconds. When it lapses, the browser holds the next
   * request and renews the cookie by signing a challenge with the device key.
   * @default 300
   */
  boundCookieMaxAge?: number;
  /**
   * How long a registration or refresh challenge is accepted after it is issued, in seconds.
   * @default 300
   */
  challengeExpiresIn?: number;
  /** The DBSC session scope sent to the browser. */
  scope?: {
    /** Defaults to the origin of Better Auth's `baseURL`. */
    origin?: string;
    /**
     * Cover every subdomain of the site, not only the origin. On a subdomain the browser
     * first checks `/.well-known/device-bound-sessions` on the site.
     * @default false
     */
    includeSite?: boolean;
    /**
     * Path prefixes the browser never holds a request for, such as static assets. The
     * DBSC endpoints themselves are always excluded.
     */
    exclude?: string[];
    /** Raw `scope_specification` rules, sent after `exclude`. */
    rules?: DbscScopeRule[];
  };
  /**
   * What happens to a bound session that arrives without a live bound cookie: its session
   * cookie (and any `multiSession()` cookie naming it) is dropped from the request, as if
   * absent. Every endpoint then behaves as signed out, `getSession` answers `null`, and the
   * session itself is untouched, so a copied cookie can never sign the owner out. A request
   * with `Authorization: Bearer` that carries a bound session is refused with 401 unless
   * the bound cookie proves it and the bearer token names that same session.
   */
  enforcement?: {
    /**
     * `false` binds sessions but never drops or refuses anything. For rollouts.
     * @default true
     */
    enabled?: boolean;
    /** Paths left alone. A trailing `/` matches child paths. */
    exclude?: string[];
  };
  /**
   * Endpoints whose effects outlast a copied cookie (adding a passkey, changing the
   * email) and so need a proof made after the request arrived. On a bound session the
   * first attempt is refused with `403 DBSC_FRESH_PROOF_REQUIRED` and the bound cookie
   * removed; the browser refreshes with its key and the retry passes once. Use
   * `auth.api.requireFreshProof` for your own routes.
   */
  freshProof?: {
    /**
     * Better Auth endpoint paths, such as `/change-email`, or a map of path to rule
     * when some paths need a different `unbound` policy.
     */
    paths: string[] | Record<string, DbscFreshProofRule>;
    /**
     * What sessions that are not bound get on these paths.
     * @default "allow"
     */
    unbound?: DbscUnboundPolicy;
    /**
     * How long a fresh-proof challenge waits for its retry, in seconds.
     * @default 60
     */
    expiresIn?: number;
  };
  /**
   * Rate limit for the register and refresh endpoints, per client address, through
   * Better Auth's own limiter. Generous by default: an office shares one address.
   */
  rateLimit?: {
    /** @default true */
    enabled?: boolean;
    /** In seconds. @default 60 */
    window?: number;
    /** @default 600 */
    max?: number;
  };
  /**
   * Called for registrations, refreshes, refusals, and theft signals, like the Stripe
   * plugin's `onEvent`. Runs through Better Auth's background task handler when one is
   * configured; a throw is logged and never changes the response.
   */
  onEvent?: (event: DbscEvent) => Awaitable<void>;
  /**
   * Decide whether a new session is offered DBSC. Runs only when a response issues a
   * session token the request did not carry; session refreshes never re-register.
   */
  shouldRegister?: (ctx: HookContext) => Awaitable<boolean>;
  /** The clock, in milliseconds. For tests. */
  now?: () => number;
  /**
   * Where bindings live. Defaults to a `dbscSession` table through Better Auth's adapter.
   * Pass a store, or a function that builds one from Better Auth's context.
   */
  store?: DbscStore | ((context: AuthContext) => DbscStore);
  /** Rename the `dbscSession` model or its fields. */
  schema?: InferOptionSchema<typeof dbscSchema>;
  /** Protocol details. The defaults suit almost every app. */
  advanced?: {
    /**
     * The browser keys DBSC sessions by site and this identifier, so one value per app
     * means a new sign-in replaces the old DBSC session instead of piling up. Give apps
     * that share a site different identifiers.
     * @default "better-auth"
     */
    sessionIdentifier?: string;
    /**
     * Origins whose requests may make the browser refresh. `["*"]` lets a link or
     * redirect from any site (an OAuth provider, another app) arrive with a fresh bound
     * cookie instead of reading as signed out. Pass `[]` for same-site only.
     * @default ["*"]
     */
    allowedRefreshInitiators?: string[];
    /**
     * Response header names to send: `Secure-Session-*` (`"standard"`), the origin
     * trial's `Sec-Session-*` (`"legacy"`), or both. Request headers are always read
     * under both names.
     * @default "both"
     */
    headers?: DbscHeaderNames;
  };
}

export interface ResolvedDbscOptions {
  enabled: () => Awaitable<boolean>;
  algorithms: DbscAlgorithm[];
  boundCookieMaxAge: number;
  challengeExpiresIn: number;
  scope: {
    origin: string | undefined;
    includeSite: boolean;
    exclude: string[];
    rules: DbscScopeRule[];
  };
  enforcement: { enabled: boolean; exclude: string[] };
  freshProof: { paths: Map<string, DbscUnboundPolicy>; expiresIn: number };
  rateLimit: { enabled: boolean; window: number; max: number };
  onEvent: DbscOptions["onEvent"];
  shouldRegister: DbscOptions["shouldRegister"];
  now: () => number;
  store: ((context: AuthContext) => DbscStore) | undefined;
  advanced: {
    sessionIdentifier: string;
    allowedRefreshInitiators: string[];
    headers: DbscHeaderNames;
  };
}

/** Validates options and fills defaults. Every problem is reported at once. */
export function resolveDbscOptions(options: DbscOptions = {}): ResolvedDbscOptions {
  const issues: string[] = [];
  const positiveInteger = (value: number, key: string) => {
    if (!Number.isInteger(value) || value <= 0)
      issues.push(`\`${key}\` must be a positive integer.`);
  };
  const paths = (values: string[], key: string) => {
    if (values.some((path) => typeof path !== "string" || !path.startsWith("/"))) {
      issues.push(`\`${key}\` entries must be paths starting with \`/\`, such as \`/admin/\`.`);
    }
  };

  const enabled = options.enabled ?? true;
  if (typeof enabled !== "boolean" && typeof enabled !== "function") {
    issues.push("`enabled` must be a boolean or a function that returns one.");
  }
  const algorithms = options.algorithms ?? [...DBSC_ALGORITHMS];
  if (algorithms.length === 0 || algorithms.some((alg) => !DBSC_ALGORITHMS.includes(alg))) {
    issues.push('`algorithms` must be a non-empty list of "ES256" and/or "RS256".');
  }
  const boundCookieMaxAge = options.boundCookieMaxAge ?? 300;
  positiveInteger(boundCookieMaxAge, "boundCookieMaxAge");
  const challengeExpiresIn = options.challengeExpiresIn ?? 300;
  positiveInteger(challengeExpiresIn, "challengeExpiresIn");
  if (options.scope?.origin !== undefined && !isOrigin(options.scope.origin)) {
    issues.push(
      "`scope.origin` must be an origin such as `https://app.example.com`, with no path.",
    );
  }
  const scopeExclude = options.scope?.exclude ?? [];
  paths(scopeExclude, "scope.exclude");
  const enforcementExclude = options.enforcement?.exclude ?? [];
  paths(enforcementExclude, "enforcement.exclude");
  const unboundDefault = options.freshProof?.unbound ?? "allow";
  const policies = ["allow", "fresh-session", "deny"];
  const freshProofEntries: [string, DbscUnboundPolicy][] = Array.isArray(options.freshProof?.paths)
    ? options.freshProof.paths.map((path) => [path, unboundDefault])
    : Object.entries(options.freshProof?.paths ?? {}).map(([path, rule]) => [
        path,
        rule.unbound ?? unboundDefault,
      ]);
  paths(
    freshProofEntries.map(([path]) => path),
    "freshProof.paths",
  );
  if (
    freshProofEntries.some(([, policy]) => !policies.includes(policy)) ||
    !policies.includes(unboundDefault)
  ) {
    issues.push('`freshProof.unbound` must be "allow", "fresh-session", or "deny".');
  }
  // An excluded path skips the whole gate, fresh proof included, so the weaker option
  // would win without a word. Refuse to guess.
  for (const [path] of freshProofEntries) {
    const excludes = enforcementExclude.filter((entry) => typeof entry === "string");
    if (typeof path === "string" && isExcluded(path, excludes)) {
      issues.push(
        `\`freshProof.paths\` entry \`${path}\` is excluded by \`enforcement.exclude\`, which would skip its fresh proof. Remove it from one of them.`,
      );
    }
  }
  const freshProofExpiresIn = options.freshProof?.expiresIn ?? 60;
  positiveInteger(freshProofExpiresIn, "freshProof.expiresIn");
  const rateLimit = {
    enabled: options.rateLimit?.enabled ?? true,
    window: options.rateLimit?.window ?? 60,
    max: options.rateLimit?.max ?? 600,
  };
  positiveInteger(rateLimit.window, "rateLimit.window");
  positiveInteger(rateLimit.max, "rateLimit.max");
  for (const key of ["onEvent", "shouldRegister", "now"] as const) {
    if (options[key] !== undefined && typeof options[key] !== "function") {
      issues.push(`\`${key}\` must be a function.`);
    }
  }
  const sessionIdentifier = options.advanced?.sessionIdentifier ?? "better-auth";
  if (!/^[\x20-\x7e]+$/.test(sessionIdentifier)) {
    issues.push("`advanced.sessionIdentifier` must be non-empty printable ASCII.");
  }
  const headers = options.advanced?.headers ?? "both";
  if (!["standard", "legacy", "both"].includes(headers)) {
    issues.push('`advanced.headers` must be "standard", "legacy", or "both".');
  }
  if (issues.length > 0) {
    throw new BetterAuthError(`Invalid dbsc() options:\n  - ${issues.join("\n  - ")}`);
  }

  const store = options.store;
  return {
    enabled: typeof enabled === "function" ? enabled : () => enabled,
    algorithms,
    boundCookieMaxAge,
    challengeExpiresIn,
    scope: {
      origin: options.scope?.origin,
      includeSite: options.scope?.includeSite ?? false,
      exclude: scopeExclude,
      rules: options.scope?.rules ?? [],
    },
    enforcement: { enabled: options.enforcement?.enabled ?? true, exclude: enforcementExclude },
    freshProof: { paths: new Map(freshProofEntries), expiresIn: freshProofExpiresIn },
    rateLimit,
    onEvent: options.onEvent,
    shouldRegister: options.shouldRegister,
    now: options.now ?? Date.now,
    store: store === undefined ? undefined : typeof store === "function" ? store : () => store,
    advanced: {
      sessionIdentifier,
      allowedRefreshInitiators: options.advanced?.allowedRefreshInitiators ?? ["*"],
      headers,
    },
  };
}

/** What the request carries, after checking it against its binding. */
type SessionState =
  | { kind: "none" }
  | { kind: "plain"; token: string; session: Session }
  | {
      kind: "bound";
      token: string;
      session: Session;
      binding: DbscBinding;
      /** The fresh-proof challenge nonce the bound cookie answers, if any. */
      answers: string | null;
    }
  | { kind: "unproven"; session: Session };

export type FreshProofState = "off" | "no-session" | "unbound" | "answered" | "challenge";
export type DbscStatusState = "off" | "no-session" | "unbound" | "bound";

/** `{ action: string }`, as a Standard Schema so the endpoint is typed without a schema library. */
const freshProofBody = {
  "~standard": {
    version: 1,
    vendor: "@assistant-ui/better-auth-dbsc",
    validate(value: unknown) {
      const action = (value as { action?: unknown } | null | undefined)?.action;
      return typeof action === "string" && action.length > 0
        ? { value: { action } }
        : {
            issues: [
              {
                message: "`body.action` must name the action, such as `delete-account`.",
                path: ["action"],
              },
            ],
          };
    },
    types: undefined as unknown as { input: { action: string }; output: { action: string } },
  },
} as const;

const sessionConfigResponse = {
  description: "The DBSC session config, as the browser expects it",
  content: {
    "application/json": {
      schema: {
        type: "object",
        properties: {
          session_identifier: { type: "string" },
          refresh_url: { type: "string" },
          scope: { type: "object" },
          allowed_refresh_initiators: { type: "array", items: { type: "string" } },
          credentials: { type: "array", items: { type: "object" } },
          continue: { type: "boolean" },
        },
      },
    },
  },
} as const;

/**
 * Device Bound Session Credentials for Better Auth.
 *
 * Browsers that support DBSC bind the session to a hardware-backed key and keep a
 * short-lived cookie fresh by signing server challenges. Browsers that do not ignore the
 * registration header and keep using the plain session cookie.
 */
export const dbsc = <O extends DbscOptions>(options?: O) => {
  const config = resolveDbscOptions(options);

  /** Telemetry never changes a response: a throwing handler is logged, not rethrown. */
  async function emit(ctx: HookContext, event: DbscEvent) {
    const handler = config.onEvent;
    if (!handler) return;
    await ctx.context.runInBackgroundOrAwait(Promise.resolve().then(() => handler(event)));
  }

  /**
   * Requests that answered a `freshProof` path. An endpoint dispatched inside the same
   * request (the OAuth provider's consent re-enters `/oauth2/authorize` this way) is not
   * challenged again: the answer was spent on the outer one, so it could never pass.
   */
  const answeredRequests = new WeakSet<Request>();

  const storeFor = (context: AuthContext): DbscStore =>
    config.store?.(context) ??
    createAdapterDbscStore(context.adapter as unknown as DbscStoreAdapter);

  /** Reads the session the request carries and whether it is proven. No writes. */
  async function sessionState(ctx: HookContext): Promise<SessionState> {
    return stateFor(ctx, (await readSessionToken(ctx)) ?? readBearerToken(ctx));
  }

  /**
   * Reads one session token's session and whether the bound cookie proves it: two reads,
   * the session and its binding. No writes.
   */
  async function stateFor(ctx: HookContext, token: string | null): Promise<SessionState> {
    if (!token) return { kind: "none" };
    const found = await ctx.context.internalAdapter.findSession(token);
    if (!found || new Date(found.session.expiresAt).getTime() <= config.now())
      return { kind: "none" };
    const binding = await storeFor(ctx.context).find(found.session.id);
    if (!binding) return { kind: "plain", token, session: found.session };
    const bound = await readBoundToken({
      secret: ctx.context.secret,
      sessionToken: token,
      token: ctx.getCookie(cookies(ctx).bound.name),
      nowMs: config.now(),
    });
    if (!bound) return { kind: "unproven", session: found.session };
    return {
      kind: "bound",
      token,
      session: found.session,
      binding,
      answers: bound.answers,
    };
  }

  /**
   * Checks every session token the request carries, not only the one the endpoint will
   * read: the session cookie, `Authorization: Bearer` (the `bearer()` plugin turns it into
   * the session cookie in its own before hook, which may run after this one and rebuilds
   * the cookie header from the original request), and `multiSession()`'s per-session
   * cookies. A bound session that the bound cookie does not prove must not reach any
   * endpoint by any of them.
   *
   * - With a bearer token, dropping cookies cannot work, because `bearer()` may write the
   *   cookie header after this hook. So a request that carries a bound session is refused
   *   with 401 unless the bound cookie proves every bound session in it and the bearer
   *   token and the session cookie, where they name a session, name that same one.
   * - Without one, every cookie naming an unproven bound session is dropped.
   *
   * Returns the cookies to drop and the sessions an endpoint may act as.
   */
  async function gate(ctx: HookContext): Promise<{
    drop: Set<string>;
    sessions: Exclude<SessionState, { kind: "none" | "unproven" }>[];
  }> {
    const sessionCookie = ctx.context.authCookies.sessionToken.name;
    const cookieToken = await readSessionToken(ctx);
    const bearerToken = readBearerToken(ctx);
    const carried: { via: DbscCarrier; token: string; cookie?: string }[] = [];
    if (cookieToken) carried.push({ via: "cookie", token: cookieToken, cookie: sessionCookie });
    if (bearerToken) carried.push({ via: "bearer", token: bearerToken });
    for (const name of cookieNames(ctx.headers)) {
      // `multiSession()` reads every signed cookie whose name contains `_multi-`.
      if (!name.includes("_multi-")) continue;
      const token = await ctx.getSignedCookie(name, ctx.context.secret);
      if (typeof token === "string" && token)
        carried.push({ via: "multi-session", token, cookie: name });
    }

    const states = new Map<string, Promise<SessionState>>();
    const stateOf = (token: string | null) => {
      if (!token) return Promise.resolve<SessionState>({ kind: "none" });
      let state = states.get(token);
      if (!state) states.set(token, (state = stateFor(ctx, token)));
      return state;
    };
    const resolved = await Promise.all(
      carried.map(async (carrier) => ({ ...carrier, state: await stateOf(carrier.token) })),
    );
    const unproven = resolved.filter(({ state }) => state.kind === "unproven");
    const reported = new Set<string>();
    for (const { via, token, state } of unproven) {
      if (reported.has(token) || state.kind !== "unproven") continue;
      reported.add(token);
      await emit(ctx, { type: "credential_missing", ...ids(state.session), via });
    }
    const cookieState = await stateOf(cookieToken);
    const bearerState = await stateOf(bearerToken);

    if (bearerToken) {
      const bound = resolved.some(
        ({ state }) => state.kind === "bound" || state.kind === "unproven",
      );
      if (bound) {
        // Every bound session here is proven, so all of them are the one the bound cookie names.
        const proven = (state: SessionState) => state.kind === "none" || state.kind === "bound";
        if (unproven.length > 0 || !proven(bearerState) || !proven(cookieState)) {
          throw APIError.from("UNAUTHORIZED", DBSC_ERROR_CODES.DBSC_CREDENTIAL_REQUIRED);
        }
      }
    }

    const drop = new Set(unproven.flatMap(({ cookie }) => (cookie ? [cookie] : [])));
    const sessions = [cookieState, bearerState].filter(
      (state): state is Exclude<SessionState, { kind: "none" | "unproven" }> =>
        state.kind === "plain" || state.kind === "bound",
    );
    return { drop, sessions: sessions.filter((state, i) => sessions.indexOf(state) === i) };
  }

  /**
   * A fresh proof for `action`: answered once by a bound cookie that a refresh minted
   * while the browser held this action's challenge, or a new challenge with the bound
   * cookie removed so the browser refreshes before the retry. The cookie names the
   * challenge it answers: comparing issue times would trust clocks that differ between
   * instances, and a copied cookie from a node running ahead would look newer.
   */
  async function checkFreshProof(
    ctx: HookContext,
    state: Extract<SessionState, { kind: "bound" }>,
    action: string,
  ): Promise<"answered" | "challenge"> {
    const { bound, freshProof } = cookies(ctx);
    const challenge = await readFreshProofToken({
      secret: ctx.context.secret,
      sessionToken: state.token,
      action,
      token: ctx.getCookie(freshProof.name),
      nowMs: config.now(),
      ttlSeconds: config.freshProof.expiresIn,
    });
    if (
      challenge &&
      state.answers === challenge.nonce &&
      (await storeFor(ctx.context).spend(state.session.id, "fresh-proof", challenge.issuedAtMs))
    ) {
      ctx.setCookie(freshProof.name, "", { ...freshProof.attributes, maxAge: 0 });
      await emit(ctx, { type: "fresh_proof_answered", ...ids(state.session), action });
      return "answered";
    }
    const next = await createFreshProofToken({
      secret: ctx.context.secret,
      sessionToken: state.token,
      action,
      nowMs: config.now(),
    });
    ctx.setCookie(bound.name, "", { ...bound.attributes, maxAge: 0 });
    ctx.setCookie(freshProof.name, next, freshProof.attributes);
    await emit(ctx, { type: "fresh_proof_challenged", ...ids(state.session), action });
    return "challenge";
  }

  /** Applies a `freshProof` path's policy to a session that is not bound. */
  async function unboundPolicy(
    ctx: HookContext,
    state: Extract<SessionState, { kind: "plain" }>,
    action: string,
    policy: DbscUnboundPolicy,
  ) {
    if (policy === "allow") return;
    if (policy === "fresh-session") {
      const freshAge = ctx.context.sessionConfig.freshAge;
      if (
        freshAge === 0 ||
        config.now() - new Date(state.session.createdAt).getTime() < freshAge * 1000
      )
        return;
    }
    await emit(ctx, { type: "unbound_refused", ...ids(state.session), action, policy });
    throw APIError.from(
      "FORBIDDEN",
      policy === "deny"
        ? DBSC_ERROR_CODES.DBSC_BINDING_REQUIRED
        : BASE_ERROR_CODES.SESSION_NOT_FRESH,
    );
  }

  function cookies(ctx: HookContext) {
    return {
      bound: ctx.context.createAuthCookie(DBSC_COOKIE_KEYS.bound, {
        maxAge: config.boundCookieMaxAge,
      }),
      freshProof: ctx.context.createAuthCookie(DBSC_COOKIE_KEYS.freshProof, {
        maxAge: config.freshProof.expiresIn,
      }),
    };
  }

  async function setBoundCookie(
    ctx: HookContext,
    sessionToken: string,
    { expiresAtMs, answers = null }: { expiresAtMs: number; answers?: string | null },
  ) {
    const { bound } = cookies(ctx);
    const value = await createBoundToken({
      secret: ctx.context.secret,
      sessionToken,
      expiresAtMs,
      answers,
    });
    // The value is a MAC over the session token already, so a plain cookie is enough.
    const maxAge = Math.max(0, Math.ceil((expiresAtMs - config.now()) / 1000));
    ctx.setCookie(bound.name, value, { ...bound.attributes, maxAge });
  }

  async function setRefreshChallenge(ctx: HookContext, sessionToken: string) {
    const challenge = await createDbscChallenge({
      secret: ctx.context.secret,
      purpose: "refresh",
      sessionToken,
      nowMs: config.now(),
    });
    const value = formatChallengeHeader({
      challenge,
      sessionId: config.advanced.sessionIdentifier,
    });
    for (const name of getDbscHeaderNames("challenge", config.advanced.headers))
      ctx.setHeader(name, value);
  }

  function sessionConfig(ctx: HookContext): DbscSessionConfig {
    const { bound } = cookies(ctx);
    const base = basePath(ctx);
    const exclude = [`${base}/dbsc/`, ...config.scope.exclude].map((path) => ({
      type: "exclude" as const,
      path,
    }));
    return {
      session_identifier: config.advanced.sessionIdentifier,
      refresh_url: `${base}${DBSC_REFRESH_PATH}`,
      scope: {
        origin: appOrigin(ctx),
        include_site: config.scope.includeSite,
        scope_specification: [...exclude, ...config.scope.rules],
      },
      ...(config.advanced.allowedRefreshInitiators.length > 0
        ? { allowed_refresh_initiators: config.advanced.allowedRefreshInitiators }
        : {}),
      credentials: [
        {
          type: "cookie",
          name: bound.name,
          attributes: formatCookieAttributes({
            ...bound.attributes,
            sameSite:
              typeof bound.attributes.sameSite === "string" ? bound.attributes.sameSite : undefined,
          }),
        },
      ],
    };
  }

  async function terminate(
    ctx: HookContext,
    reason: Extract<DbscEvent, { type: "terminated" }>["reason"],
  ) {
    const { bound } = cookies(ctx);
    ctx.setCookie(bound.name, "", { ...bound.attributes, maxAge: 0 });
    await emit(ctx, { type: "terminated", reason });
    return ctx.json(DBSC_TERMINATE);
  }

  function appOrigin(ctx: HookContext): string {
    return config.scope.origin ?? new URL(ctx.context.baseURL).origin;
  }

  const enforced = (path: string | undefined) =>
    config.enforcement.enabled &&
    path !== DBSC_REGISTER_PATH &&
    path !== DBSC_REFRESH_PATH &&
    !isExcluded(path, config.enforcement.exclude);

  return {
    id: "dbsc",
    version: packageJson.version,
    schema: mergeSchema(dbscSchema, options?.schema),

    init(ctx) {
      if (
        !config.store &&
        ctx.options.secondaryStorage &&
        !ctx.options.session?.storeSessionInDatabase
      ) {
        throw new BetterAuthError(
          "dbsc() keeps bindings in a `dbscSession` table that references `session`, but sessions " +
            "live only in `secondaryStorage`. Set `session.storeSessionInDatabase: true`, or pass " +
            "your own `store` to dbsc().",
        );
      }
      // The browser sends registration and refresh itself, with the session cookie and
      // no `Origin` the spec promises, so Better Auth's origin check would refuse them.
      // On these two endpoints a signed proof over a server challenge is the CSRF
      // defense, and a page on another site cannot set the DBSC request headers.
      const skip = ctx.skipOriginCheck;
      const paths = [DBSC_REGISTER_PATH, DBSC_REFRESH_PATH];
      return {
        // A binding goes with its session, whichever way Better Auth ends it. The default
        // table also cascades; a custom store has only this.
        options: {
          databaseHooks: {
            session: {
              delete: {
                async after(session: { id: string }) {
                  await storeFor(ctx).delete(session.id);
                },
              },
            },
          },
        },
        ...(skip === true
          ? {}
          : { context: { skipOriginCheck: Array.isArray(skip) ? [...skip, ...paths] : paths } }),
      };
    },

    endpoints: {
      /**
       * ### Endpoint
       *
       * POST `/dbsc/register`
       *
       * ### API Methods
       *
       * **server:**
       * `auth.api.registerDbscSession`
       *
       * The browser calls this itself: it posts a proof signed by its new key over the
       * challenge from the sign-in response. Your code never needs to.
       */
      registerDbscSession: createAuthEndpoint(
        DBSC_REGISTER_PATH,
        {
          method: "POST",
          disableBody: true,
          requireHeaders: true,
          metadata: {
            openapi: {
              summary: "Register a device-bound session",
              description:
                "Called by the browser after sign-in. Takes a proof in `Secure-Session-Response`, binds the session to the device key, sets the bound cookie, and returns the DBSC session config.",
              responses: { 200: sessionConfigResponse },
            },
          },
        },
        async (ctx) => {
          if (!(await config.enabled())) {
            throw APIError.from("BAD_REQUEST", DBSC_ERROR_CODES.DBSC_DISABLED);
          }
          const proof = parseProofHeader(readDbscHeader(ctx.headers!, "response"));
          if (!proof) throw APIError.from("BAD_REQUEST", DBSC_ERROR_CODES.DBSC_PROOF_REQUIRED);
          const token = await readSessionToken(ctx);
          const found = token ? await ctx.context.internalAdapter.findSession(token) : null;
          if (!token || !found || new Date(found.session.expiresAt).getTime() <= config.now()) {
            throw APIError.from("UNAUTHORIZED", DBSC_ERROR_CODES.DBSC_SESSION_REQUIRED);
          }

          const jti = readUnverifiedChallenge(proof);
          const challenge = await readDbscChallenge({
            secret: ctx.context.secret,
            purpose: "register",
            sessionToken: token,
            challenge: jti,
            nowMs: config.now(),
            ttlSeconds: config.challengeExpiresIn,
          });
          const refused = async (
            reason: DbscRefusalReason,
            error: (typeof DBSC_ERROR_CODES)[keyof typeof DBSC_ERROR_CODES],
            cause?: unknown,
          ) => {
            await emit(ctx, { type: "registration_refused", ...ids(found.session), reason });
            // Set directly: Better Auth releases before `APIError.from` took a cause ignore
            // the third argument, and `peerDependencies` admits them.
            const refusal = APIError.from("BAD_REQUEST", error);
            if (cause !== undefined) refusal.cause = cause;
            return refusal;
          };
          if (!jti || !challenge) {
            throw await refused("invalid_challenge", DBSC_ERROR_CODES.DBSC_INVALID_CHALLENGE);
          }

          let verified;
          try {
            verified = await verifyRegistrationProof(proof, {
              challenge: jti,
              algorithms: config.algorithms,
              expectedOrigin: appOrigin(ctx),
            });
          } catch (error) {
            // The `DbscError` is the cause, so its code reaches logs without leaking to the browser.
            throw await refused("invalid_proof", DBSC_ERROR_CODES.DBSC_INVALID_PROOF, error);
          }

          // The same key again, while its challenge lives, is a registration whose answer
          // was lost: it gets the answer again and nothing is written. Any other key is refused.
          const store = storeFor(ctx.context);
          const { session } = found;
          const existing = await store.find(session.id);
          const bound = existing
            ? existing.thumbprint === verified.thumbprint
            : (await store.bind({
                sessionId: session.id,
                userId: session.userId,
                publicKey: verified.publicKey,
                thumbprint: verified.thumbprint,
              })) || (await store.find(session.id))?.thumbprint === verified.thumbprint;
          if (!bound) {
            throw await refused("bound_to_other_key", DBSC_ERROR_CODES.DBSC_BOUND_TO_OTHER_KEY);
          }
          if (!existing) await emit(ctx, { type: "registered", ...ids(session) });

          // The cookie lives from the challenge, not from now: a replayed registration
          // proof gets the same answer again, never more time. It answers no fresh proof.
          await setBoundCookie(ctx, token, {
            expiresAtMs: challenge.issuedAtMs + config.boundCookieMaxAge * 1000,
          });
          await setRefreshChallenge(ctx, token);
          return ctx.json(sessionConfig(ctx));
        },
      ),

      /**
       * ### Endpoint
       *
       * POST `/dbsc/refresh`
       *
       * ### API Methods
       *
       * **server:**
       * `auth.api.refreshDbscSession`
       *
       * The browser calls this itself when the bound cookie lapses. No proof, or a stale
       * one: 403 with a new challenge. The bound key's proof: a new cookie. A session that
       * is over or not bound ends the browser's DBSC session.
       */
      refreshDbscSession: createAuthEndpoint(
        DBSC_REFRESH_PATH,
        {
          method: "POST",
          disableBody: true,
          requireHeaders: true,
          metadata: {
            openapi: {
              summary: "Refresh a device-bound session",
              description:
                "Called by the browser when the bound cookie lapses. Answers 403 with a `Secure-Session-Challenge` until the request carries a proof signed by the bound key, then sets a new bound cookie.",
              responses: {
                200: sessionConfigResponse,
                403: { description: "Sign the challenge in `Secure-Session-Challenge` and retry." },
              },
            },
          },
        },
        async (ctx) => {
          // Only the browser's own refresh carries this header; a page cannot set it.
          const claimedId = readDbscHeader(ctx.headers!, "sessionId");
          if (claimedId === null) {
            throw APIError.from("BAD_REQUEST", DBSC_ERROR_CODES.DBSC_SESSION_ID_REQUIRED);
          }
          if (!(await config.enabled())) return terminate(ctx, "disabled");
          if (parseSfString(claimedId) !== config.advanced.sessionIdentifier)
            return terminate(ctx, "other_identifier");

          const token = await readSessionToken(ctx);
          const found = token ? await ctx.context.internalAdapter.findSession(token) : null;
          if (!token || !found || new Date(found.session.expiresAt).getTime() <= config.now()) {
            return terminate(ctx, "no_session");
          }
          const store = storeFor(ctx.context);
          const binding = await store.find(found.session.id);
          if (!binding) return terminate(ctx, "not_bound");

          const askAgain = async (reason: "missing_proof" | "stale_challenge" | "replayed") => {
            await emit(ctx, { type: "refresh_challenged", ...ids(found.session), reason });
            await setRefreshChallenge(ctx, token);
            throw APIError.from("FORBIDDEN", DBSC_ERROR_CODES.DBSC_CHALLENGE_REQUIRED);
          };
          const proof = parseProofHeader(readDbscHeader(ctx.headers!, "response"));
          if (!proof) return askAgain("missing_proof");
          const jti = readUnverifiedChallenge(proof);
          const challenge = await readDbscChallenge({
            secret: ctx.context.secret,
            purpose: "refresh",
            sessionToken: token,
            challenge: jti,
            nowMs: config.now(),
            ttlSeconds: config.challengeExpiresIn,
          });
          if (!jti || !challenge) return askAgain("stale_challenge");
          try {
            await verifyRefreshProof(proof, {
              publicKey: binding.publicKey,
              challenge: jti,
              expectedOrigin: appOrigin(ctx),
            });
          } catch (error) {
            // Not the bound key. A 403 changes nothing for the device that has it, and
            // the challenge is not spent, so garbage cannot lock the owner out.
            const reason =
              error instanceof Error && "code" in error ? String(error.code) : "INVALID_PROOF";
            await emit(ctx, { type: "proof_rejected", ...ids(found.session), reason });
            await setRefreshChallenge(ctx, token);
            throw APIError.from("FORBIDDEN", DBSC_ERROR_CODES.DBSC_CHALLENGE_REQUIRED);
          }
          // Spent only after the signature verifies.
          if (!(await store.spend(found.session.id, "refresh", challenge.issuedAtMs)))
            return askAgain("replayed");

          await emit(ctx, { type: "refreshed", ...ids(found.session) });
          // The browser holds a fresh-proof challenge while it refreshes for one: this
          // cookie names it, and only a cookie that names a challenge answers it.
          await setBoundCookie(ctx, token, {
            expiresAtMs: config.now() + config.boundCookieMaxAge * 1000,
            answers: readFreshProofNonce(ctx.getCookie(cookies(ctx).freshProof.name)),
          });
          await setRefreshChallenge(ctx, token);
          return ctx.json(sessionConfig(ctx));
        },
      ),

      /**
       * ### Endpoint
       *
       * GET `/dbsc/get-status`
       *
       * ### API Methods
       *
       * **server:**
       * `auth.api.getDbscStatus`
       *
       * **client:**
       * `authClient.dbsc.getStatus`
       *
       * Whether the current session is bound to this device:
       * `{ state: "bound" | "unbound" | "no-session" | "off" }`. For a "this device is
       * protected" line in account settings.
       */
      getDbscStatus: createAuthEndpoint(
        "/dbsc/get-status",
        {
          method: "GET",
          requireHeaders: true,
          metadata: {
            openapi: {
              summary: "Get the device binding of the current session",
              description:
                "Answers whether the current session is bound to this device, proven by a live bound cookie.",
              responses: {
                200: {
                  description: "Successful response",
                  content: {
                    "application/json": {
                      schema: {
                        type: "object",
                        properties: {
                          state: {
                            type: "string",
                            enum: ["bound", "unbound", "no-session", "off"],
                          },
                        },
                        required: ["state"],
                      },
                    },
                  },
                },
              },
            },
          },
        },
        async (ctx) => {
          const answer = (state: DbscStatusState) => ctx.json({ state });
          if (!(await config.enabled())) return answer("off");
          const session = await sessionState(ctx);
          if (session.kind === "bound") return answer("bound");
          if (session.kind === "plain") return answer("unbound");
          return answer("no-session");
        },
      ),

      /**
       * ### Endpoint
       *
       * Server only. No HTTP route.
       *
       * ### API Methods
       *
       * **server:**
       * `auth.api.requireFreshProof`
       *
       * A fresh proof for one of your own routes or server actions:
       * `await auth.api.requireFreshProof({ headers, body: { action: "delete-account" } })`.
       *
       * - `answered`: a bound session proved itself after this action's challenge. Go on.
       * - `challenge`: refuse the request and forward the `Set-Cookie` headers (call with
       *   `returnHeaders: true`, or use the `nextCookies()` plugin). The client retries once.
       * - `unbound`: a plain session; apply whatever fresh-proof you use without DBSC.
       * - `no-session` and `off`: nothing was checked.
       */
      requireFreshProof: createAuthEndpoint(
        "/dbsc/require-fresh-proof",
        {
          method: "POST",
          body: freshProofBody,
          requireHeaders: true,
          metadata: { SERVER_ONLY: true },
        },
        async (ctx) => {
          const answer = (state: FreshProofState) => ctx.json({ state });
          if (!(await config.enabled())) return answer("off");
          const session = await sessionState(ctx);
          if (session.kind === "none" || session.kind === "unproven") return answer("no-session");
          if (session.kind === "plain") return answer("unbound");
          return answer(await checkFreshProof(ctx, session, `app:${ctx.body.action}`));
        },
      ),
    },

    hooks: {
      before: [
        {
          matcher: (ctx) => enforced(ctx.path),
          handler: createAuthMiddleware(async (ctx) => {
            if (!(await config.enabled())) return;
            const { drop, sessions } = await gate(ctx);
            // As if those cookies were absent: the endpoint answers as signed out, and
            // nothing it does can touch the owner's session.
            const result =
              drop.size > 0
                ? { context: { headers: withoutCookies(ctx.headers, drop) } }
                : undefined;
            const policy = ctx.path ? config.freshProof.paths.get(ctx.path) : undefined;
            if (!policy) return result;
            for (const state of sessions) {
              if (state.kind === "plain") await unboundPolicy(ctx, state, ctx.path!, policy);
            }
            const state = sessions.find((state) => state.kind === "bound");
            if (state?.kind === "bound") {
              if (ctx.request && answeredRequests.has(ctx.request)) return result;
              if ((await checkFreshProof(ctx, state, ctx.path!)) === "answered") {
                if (ctx.request) answeredRequests.add(ctx.request);
                return result;
              }
              if (ctx.request && ctx.headers?.get("sec-fetch-mode") === "navigate") {
                // A navigation shows whatever comes back, so a JSON 403 would strand the
                // user. Sent back to itself, the browser holds it, refreshes with its key,
                // and follows it. 307 keeps a form post's method and body.
                const url = new URL(ctx.request.url);
                ctx.responseHeaders?.set("location", `${url.pathname}${url.search}`);
                throw new APIError("TEMPORARY_REDIRECT", undefined, ctx.responseHeaders);
              }
              // `APIError.from` takes no headers, and the fresh-proof cookies must reach the browser.
              const { code, message } = DBSC_ERROR_CODES.DBSC_FRESH_PROOF_REQUIRED;
              throw new APIError("FORBIDDEN", { code, message }, ctx.responseHeaders);
            }
            return result;
          }),
        },
      ],
      after: [
        {
          matcher: () => true,
          handler: createAuthMiddleware(async (ctx) => {
            if (ctx.path === "/sign-out") {
              // Everything registered has a reverse. The binding goes with its session row.
              const { bound, freshProof } = cookies(ctx);
              ctx.setCookie(bound.name, "", { ...bound.attributes, maxAge: 0 });
              ctx.setCookie(freshProof.name, "", { ...freshProof.attributes, maxAge: 0 });
              return;
            }
            const issued = ctx.context.newSession;
            if (!issued) return;
            // `newSession` is also set when an existing session is refreshed. Only a token
            // the request did not carry is a new session worth registering.
            if ((await readSessionToken(ctx)) === issued.session.token) return;
            if (!(await config.enabled())) return;
            if (config.shouldRegister && !(await config.shouldRegister(ctx))) return;

            const challenge = await createDbscChallenge({
              secret: ctx.context.secret,
              purpose: "register",
              sessionToken: issued.session.token,
              nowMs: config.now(),
            });
            const value = formatRegistrationHeader({
              algorithms: config.algorithms,
              challenge,
              path: `${basePath(ctx)}${DBSC_REGISTER_PATH}`,
            });
            for (const name of getDbscHeaderNames("registration", config.advanced.headers))
              ctx.setHeader(name, value);
          }),
        },
      ],
    },

    rateLimit: !config.rateLimit.enabled
      ? undefined
      : [
          {
            pathMatcher: (path: string) =>
              path === DBSC_REGISTER_PATH || path === DBSC_REFRESH_PATH,
            window: config.rateLimit.window,
            max: config.rateLimit.max,
          },
        ],

    $ERROR_CODES: DBSC_ERROR_CODES,

    options: options as NoInfer<O>,
  } satisfies BetterAuthPlugin;
};

function ids(session: Session) {
  return { sessionId: session.id, userId: session.userId };
}

async function readSessionToken(ctx: HookContext): Promise<string | null> {
  const token = await ctx.getSignedCookie(
    ctx.context.authCookies.sessionToken.name,
    ctx.context.secret,
  );
  return typeof token === "string" && token ? token : null;
}

/**
 * The session token in `Authorization: Bearer`, read the way the `bearer()` plugin reads
 * it, which turns it into the session cookie in its own hook. Not verified: here it can
 * only cause a refusal, so a bad signature counts the same as a good one.
 */
function readBearerToken(ctx: HookContext): string | null {
  const value = ctx.request?.headers.get("authorization") || ctx.headers?.get("authorization");
  if (!value || value.slice(0, 7).toLowerCase() !== "bearer ") return null;
  const token = value.slice(7).trim();
  if (!token) return null;
  // `bearer()` decodes a signed token that has `%` and takes an unsigned one as it is.
  const decoded = token.includes(".") && token.includes("%") ? tryDecode(token) : token;
  return decoded.split(".")[0] || null;
}

function tryDecode(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

/** The names in the `Cookie` header. */
function cookieNames(headers: Headers | undefined): string[] {
  return (headers?.get("cookie") ?? "")
    .split(";")
    .map((pair) => pair.slice(0, Math.max(0, pair.indexOf("="))).trim())
    .filter(Boolean);
}

/** A copy of `headers` with every pair named in `names` removed from `Cookie`. */
function withoutCookies(headers: Headers | undefined, names: Set<string>): Headers {
  const copy = new Headers(headers);
  const kept = (copy.get("cookie") ?? "")
    .split(";")
    .map((pair) => pair.trim())
    .filter((pair) => pair && !names.has(pair.slice(0, Math.max(0, pair.indexOf("="))).trim()));
  copy.set("cookie", kept.join("; "));
  return copy;
}

function basePath(ctx: HookContext): string {
  return new URL(ctx.context.baseURL).pathname.replace(/\/+$/, "");
}

function isExcluded(path: string | undefined, exclude: string[]): boolean {
  if (!path) return false;
  return exclude.some((entry) => (entry.endsWith("/") ? path.startsWith(entry) : path === entry));
}

function isOrigin(value: string): boolean {
  try {
    return new URL(value).origin === value;
  } catch {
    return false;
  }
}
