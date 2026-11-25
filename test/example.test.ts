import { once } from "node:events";
import type { AddressInfo } from "node:net";
import { afterAll, describe, expect, it } from "vitest";

describe("example", () => {
  const env = { ...process.env };
  afterAll(() => {
    process.env = env;
  });

  it("never runs on a checked-in secret, and listens on loopback only", async () => {
    process.env.DATABASE_PATH = ":memory:";
    process.env.PORT = "0";
    delete process.env.BETTER_AUTH_SECRET;
    delete process.env.HOST;

    const { auth } = await import("../example/auth.ts");
    const { secret } = await auth.$context;
    expect(secret).not.toBe("dev-only-secret-change-me-0123456789abcdef");
    expect(secret.length).toBeGreaterThanOrEqual(32);

    const { server } = await import("../example/server.ts");
    if (!server.listening) await once(server, "listening");
    expect((server.address() as AddressInfo).address).toBe("127.0.0.1");
    server.close();
  });
});
