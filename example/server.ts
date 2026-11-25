import { createServer } from "node:http";
import { toNodeHandler } from "better-auth/node";
import { auth } from "./auth.ts";

const authHandler = toNodeHandler(auth);
const port = Number(process.env.PORT ?? 3000);
// Loopback only, unless you ask for more: this is a demo, not a deployment.
const host = process.env.HOST ?? "127.0.0.1";

const page = `<!doctype html>
<meta charset="utf-8">
<title>DBSC example</title>
<form id="auth">
  <input name="email" type="email" placeholder="email" required>
  <input name="password" type="password" placeholder="password" minlength="8" required>
  <button name="mode" value="sign-up">Sign up</button>
  <button name="mode" value="sign-in">Sign in</button>
</form>
<button id="me">GET /me</button>
<pre id="out"></pre>
<script type="module">
  const out = document.querySelector("#out");
  document.querySelector("#auth").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = new FormData(event.target);
    const mode = event.submitter.value;
    const response = await fetch("/api/auth/" + mode + "/email", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: form.get("email"), password: form.get("password"), name: "Example" }),
    });
    out.textContent = response.status + " " + (response.headers.get("secure-session-registration") ?? "(no registration header)");
  });
  document.querySelector("#me").addEventListener("click", async () => {
    const response = await fetch("/me");
    out.textContent = response.status + "\\n" + JSON.stringify(await response.json(), null, 2);
  });
</script>`;

export const server = createServer(async (req, res) => {
  if (req.url?.startsWith("/api/auth/")) return authHandler(req, res);
  if (req.url === "/me") {
    // App routes go through auth.api, so DBSC enforcement applies here too.
    const headers = new Headers(req.headers as Record<string, string>);
    const session = await auth.api.getSession({ headers });
    const { state } = await auth.api.getDbscStatus({ headers });
    res.writeHead(session ? 200 : 401, { "content-type": "application/json" });
    return res.end(JSON.stringify(session ? { user: session.user.email, dbsc: state } : null));
  }
  res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
  res.end(page);
}).listen(port, host, () => console.log(`http://localhost:${port}`));
