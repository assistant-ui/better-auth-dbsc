import { randomBytes } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { betterAuth } from "better-auth";
import { dbsc } from "../src/index.ts";

// The secret signs every DBSC challenge and bound cookie, so a known one lets anyone forge
// them. Without BETTER_AUTH_SECRET each run gets a new one, and sessions end on restart.
const secret = process.env.BETTER_AUTH_SECRET || randomBytes(32).toString("base64url");
if (!process.env.BETTER_AUTH_SECRET) {
  console.warn("BETTER_AUTH_SECRET is not set: using a random secret for this run only.");
}

export const auth = betterAuth({
  baseURL: process.env.BETTER_AUTH_URL ?? "http://localhost:3000",
  secret,
  database: new DatabaseSync(process.env.DATABASE_PATH ?? "example.db"),
  emailAndPassword: { enabled: true },
  plugins: [dbsc()],
});
