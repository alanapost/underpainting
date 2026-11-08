// Run: node --test app/server.test.mjs
import test from "node:test";
process.env.BASE_URL = "https://members.test";
process.env.OIDC_ISSUER = "https://idp.test";
process.env.OIDC_CLIENT_ID = "cid";
process.env.OIDC_CLIENT_SECRET = "secret";
process.env.SESSION_SECRET = "x".repeat(40);
process.env.ROOM_WORK_SESSION = "https://example.daily.co/ws-test";
process.env.ROOM_ONE_TO_ONE = "https://example.daily.co/oo-test";

let groups = ["one-on-one"];
globalThis.fetch = (input) => {
  const u = String(input instanceof Request ? input.url : input);
  const json = (o) => Promise.resolve(new Response(JSON.stringify(o)));
  if (u.endsWith("/.well-known/openid-configuration")) {
    return json({ authorization_endpoint: "https://idp.test/authorize", token_endpoint: "https://idp.test/token", userinfo_endpoint: "https://idp.test/userinfo", end_session_endpoint: "https://idp.test/api/oidc/end-session" });
  }
  if (u === "https://idp.test/token") return json({ access_token: "at" });
  if (u === "https://idp.test/userinfo") return json({ sub: "u1", email: "m@test", given_name: "Sam", groups });
  return Promise.reject(new Error("unexpected fetch " + u));
};

const { handler } = await import("./server.mjs");
const assert = (c, m) => { if (!c) throw new Error(m); };
const cookieOf = (r, name) => r.headers.getSetCookie().find((c) => c.startsWith(name + "=")).split(";")[0];

async function signIn() {
  const start = await handler(new Request("https://members.test/login?next=/one-on-one"));
  const loc = new URL(start.headers.get("location"));
  assert(loc.origin === "https://idp.test" && loc.searchParams.get("code_challenge_method") === "S256", "login redirect");
  const cb = await handler(new Request(`https://members.test/callback?code=c&state=${loc.searchParams.get("state")}`, { headers: { cookie: cookieOf(start, "up_login") } }));
  assert(cb.status === 302 && cb.headers.get("location") === "/one-on-one", "callback redirect");
  return cookieOf(cb, "up_session");
}

test("signed-out visitors are sent to sign in", async () => {
  const r = await handler(new Request("https://members.test/"));
  assert(r.status === 302 && r.headers.get("location") === "/login?next=%2F", "redirect");
});

test("1:1 member sees rooms and 1:1 page; room links only after sign-in", async () => {
  groups = ["one-on-one"];
  const c = await signIn();
  const home = await (await handler(new Request("https://members.test/", { headers: { cookie: c } }))).text();
  assert(home.includes("Welcome back, Sam") && home.includes("ws-test") && home.includes("/one-on-one"), "home content");
  const oo = await handler(new Request("https://members.test/one-on-one", { headers: { cookie: c } }));
  assert(oo.status === 200 && (await oo.text()).includes("oo-test"), "1:1 page");
});

test("community member doesn't get the 1:1 page", async () => {
  groups = ["community"];
  const c = await signIn();
  const home = await (await handler(new Request("https://members.test/", { headers: { cookie: c } }))).text();
  assert(!home.includes("/one-on-one") && !home.includes("oo-test"), "no 1:1 on home");
  const oo = await handler(new Request("https://members.test/one-on-one", { headers: { cookie: c } }));
  assert(oo.status === 302, "1:1 blocked");
});

test("signed-in non-member gets the membership page", async () => {
  groups = [];
  const c = await signIn();
  const r = await handler(new Request("https://members.test/", { headers: { cookie: c } }));
  assert(r.status === 403 && !(await r.text()).includes("ws-test"), "no rooms");
});

test("tampered cookie is rejected", async () => {
  groups = ["community"];
  const c = await signIn();
  const bad = c.replace(/.$/, (ch) => (ch === "A" ? "B" : "A"));
  const r = await handler(new Request("https://members.test/", { headers: { cookie: bad } }));
  assert(r.status === 302, "redirect to login");
});

test("static files are served, others are not", async () => {
  const css = await handler(new Request("https://members.test/members/style.css"));
  assert(css.status === 200 && css.headers.get("content-type") === "text/css", "css");
  const secret = await handler(new Request("https://members.test/app/main.ts"));
  assert(secret.status === 302, "source not served");
});

test("sign out clears the session and goes to Pocket ID", async () => {
  const r = await handler(new Request("https://members.test/logout"));
  assert(r.headers.get("location").startsWith("https://idp.test/api/oidc/end-session"), "end session");
  assert(r.headers.getSetCookie().some((c) => c.startsWith("up_session=;")), "cookie cleared");
});
