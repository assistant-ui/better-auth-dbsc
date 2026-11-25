import type { DbscPublicKey } from "./core/proof.ts";

/** A session bound to a device key. */
export interface DbscBinding {
  sessionId: string;
  userId: string;
  publicKey: DbscPublicKey;
  /** RFC 7638 thumbprint of `publicKey`. Two registrations agree when thumbprints match. */
  thumbprint: string;
}

/** A proof that answers a challenge: a DBSC refresh, or a fresh proof for one action. */
export type DbscProofKind = "refresh" | "fresh-proof";

/**
 * Where bindings live. The default keeps them in a `dbscSession` table through Better
 * Auth's adapter. Bring your own to keep them in Redis, a KV store, or an existing table.
 */
export interface DbscStore {
  /** The binding for this session, or `null` for a plain session. */
  find(sessionId: string): Promise<DbscBinding | null>;
  /**
   * Stores the binding unless the session already has one, and says whether it was
   * stored. Must be atomic: two racing registrations bind at most one key.
   */
  bind(binding: DbscBinding): Promise<boolean>;
  /**
   * Spends a proof over a challenge issued at `issuedAtMs`. Answers `false` when that
   * challenge, or a later one of the same kind, was spent already. Must be atomic: of
   * two requests carrying the same proof, at most one gets `true`.
   */
  spend(sessionId: string, kind: DbscProofKind, issuedAtMs: number): Promise<boolean>;
  /**
   * Removes the binding and anything spent for it. Called whenever Better Auth deletes the
   * session: sign-out, revocation, a deleted user, or an expired session it comes across.
   * Better Auth leaves sessions that expire unseen in place, so prune bindings whose
   * session is gone the same way you prune sessions.
   */
  delete(sessionId: string): Promise<void>;
}

export const DBSC_MODEL = "dbscSession";

export const dbscSchema = {
  [DBSC_MODEL]: {
    fields: {
      sessionId: {
        type: "string",
        required: true,
        unique: true,
        input: false,
        references: { model: "session", field: "id", onDelete: "cascade" },
      },
      userId: {
        type: "string",
        required: true,
        input: false,
        index: true,
        references: { model: "user", field: "id", onDelete: "cascade" },
      },
      /** The device's public JWK, JSON-encoded, with `alg`. */
      publicKey: { type: "string", required: true, input: false },
      thumbprint: { type: "string", required: true, input: false },
      /** Issue time of the newest refresh challenge spent. Older ones are refused. */
      lastRefreshAt: { type: "date", required: true, input: false },
      /** Issue time of the newest fresh-proof challenge spent. */
      lastFreshProofAt: { type: "date", required: true, input: false },
      /** How many proofs this binding has spent. */
      proofCount: { type: "number", required: true, defaultValue: 0, input: false },
      createdAt: { type: "date", required: true, input: false },
    },
  },
} as const;

interface DbscRow {
  sessionId: string;
  userId: string;
  publicKey: string;
  thumbprint: string;
}

/** The slice of Better Auth's adapter the default store uses. */
export interface DbscStoreAdapter {
  findOne<T>(data: {
    model: string;
    where: { field: string; value: unknown }[];
  }): Promise<T | null>;
  create<T>(data: { model: string; data: Record<string, unknown> }): Promise<T>;
  delete(data: { model: string; where: { field: string; value: unknown }[] }): Promise<void>;
  incrementOne<T>(data: {
    model: string;
    where: { field: string; value: unknown; operator?: "lt" | "eq" }[];
    increment: Record<string, number>;
    set?: Record<string, unknown>;
  }): Promise<T | null>;
}

/**
 * The default store: one `dbscSession` row per bound session, deleted with its session.
 * `spend` is a guarded `incrementOne`, so a proof is spent once across every instance.
 */
export function createAdapterDbscStore(adapter: DbscStoreAdapter): DbscStore {
  return {
    async find(sessionId) {
      const row = await adapter.findOne<DbscRow>({
        model: DBSC_MODEL,
        where: [{ field: "sessionId", value: sessionId }],
      });
      if (!row) return null;
      return {
        sessionId: row.sessionId,
        userId: row.userId,
        publicKey: JSON.parse(row.publicKey) as DbscPublicKey,
        thumbprint: row.thumbprint,
      };
    },

    async bind(binding) {
      const epoch = new Date(0);
      try {
        await adapter.create({
          model: DBSC_MODEL,
          data: {
            sessionId: binding.sessionId,
            userId: binding.userId,
            publicKey: JSON.stringify(binding.publicKey),
            thumbprint: binding.thumbprint,
            lastRefreshAt: epoch,
            lastFreshProofAt: epoch,
            proofCount: 0,
            createdAt: new Date(),
          },
        });
        return true;
      } catch (error) {
        // A unique violation on `sessionId` means another registration won. Anything
        // else is a real failure and is rethrown.
        const existing = await adapter.findOne<DbscRow>({
          model: DBSC_MODEL,
          where: [{ field: "sessionId", value: binding.sessionId }],
        });
        if (existing) return false;
        throw error;
      }
    },

    async spend(sessionId, kind, issuedAtMs) {
      const field = kind === "refresh" ? "lastRefreshAt" : "lastFreshProofAt";
      const issuedAt = new Date(issuedAtMs);
      const row = await adapter.incrementOne({
        model: DBSC_MODEL,
        where: [
          { field: "sessionId", value: sessionId },
          { field, value: issuedAt, operator: "lt" },
        ],
        increment: { proofCount: 1 },
        set: { [field]: issuedAt },
      });
      return row !== null;
    },

    async delete(sessionId) {
      // The foreign key usually removed the row with its session already.
      await adapter.delete({
        model: DBSC_MODEL,
        where: [{ field: "sessionId", value: sessionId }],
      });
    },
  };
}

/** A store in process memory, for tests and single-instance development. */
export function createMemoryDbscStore(): DbscStore & { bindings: Map<string, DbscBinding> } {
  const bindings = new Map<string, DbscBinding>();
  const spent = new Map<string, number>();
  return {
    bindings,
    async find(sessionId) {
      return bindings.get(sessionId) ?? null;
    },
    async bind(binding) {
      if (bindings.has(binding.sessionId)) return false;
      bindings.set(binding.sessionId, binding);
      return true;
    },
    async spend(sessionId, kind, issuedAtMs) {
      if (!bindings.has(sessionId)) return false;
      const key = `${kind}:${sessionId}`;
      if ((spent.get(key) ?? -1) >= issuedAtMs) return false;
      spent.set(key, issuedAtMs);
      return true;
    },
    async delete(sessionId) {
      bindings.delete(sessionId);
      for (const kind of ["refresh", "fresh-proof"]) spent.delete(`${kind}:${sessionId}`);
    },
  };
}
