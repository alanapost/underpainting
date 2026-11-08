// Underpainting members app: signs members in through Pocket ID and serves their page.
// Runs on Deno (Deno Deploy, or `deno run` anywhere). No database. Settings come from env vars:
//   BASE_URL            https://members.underpainting.club
//   OIDC_ISSUER         https://login.underpainting.club
//   OIDC_CLIENT_ID, OIDC_CLIENT_SECRET   from the Pocket ID app
//   SESSION_SECRET      32+ random characters
//   ROOM_WORK_SESSION, ROOM_ONE_TO_ONE   Daily room URLs (kept out of the public repo)
//   GROUP_COMMUNITY (default "community"), GROUP_ONE_ON_ONE (default "one-on-one"), GROUP_ADMIN (default "admin")

const env = (k: string, d?: string) => {
  const v = Deno.env.get(k) ?? d;
  if (v === undefined) throw new Error(`Missing env var ${k}`);
  return v;
};
const BASE_URL = env("BASE_URL", "http://localhost:8000");
const ISSUER = env("OIDC_ISSUER", "https://login.underpainting.club");
const G_COMMUNITY = env("GROUP_COMMUNITY", "community");
const G_ONE = env("GROUP_ONE_ON_ONE", "one-on-one");
const G_ADMIN = env("GROUP_ADMIN", "admin");
const ROOT = new URL("../", import.meta.url); // repo root
const COOKIE = "up_session";
const SESSION_DAYS = 14;

type Session = { sub: string; email: string; name: string; groups: string[]; exp: number };

// ---------- signed cookies (HMAC-SHA256) ----------
const enc = new TextEncoder();
let keyP: Promise<CryptoKey> | undefined;
const key = () =>
  keyP ??= crypto.subtle.importKey("raw", enc.encode(env("SESSION_SECRET")), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
const b64u = (b: Uint8Array) => btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const unb64u = (s: string) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));

async function seal(data: unknown): Promise<string> {
  const body = b64u(enc.encode(JSON.stringify(data)));
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", await key(), enc.encode(body)));
  return `${body}.${b64u(sig)}`;
}
async function unseal<T>(token: string | undefined): Promise<T | null> {
  if (!token) return null;
  const [body, sig] = token.split(".");
  if (!body || !sig) return null;
  try {
    const ok = await crypto.subtle.verify("HMAC", await key(), unb64u(sig), enc.encode(body));
    return ok ? JSON.parse(new TextDecoder().decode(unb64u(body))) as T : null;
  } catch {
    return null;
  }
}
const getCookie = (req: Request, name: string) =>
  req.headers.get("cookie")?.split(/;\s*/).find((c) => c.startsWith(name + "="))?.slice(name.length + 1);
const setCookie = (name: string, value: string, maxAge: number) =>
  `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;

// ---------- OIDC (authorization code + PKCE, confidential client) ----------
type Discovery = { authorization_endpoint: string; token_endpoint: string; userinfo_endpoint: string; end_session_endpoint?: string };
let discP: Promise<Discovery> | undefined;
const discovery = () =>
  discP ??= fetch(`${ISSUER}/.well-known/openid-configuration`).then((r) => {
    if (!r.ok) { discP = undefined; throw new Error(`Discovery failed: ${r.status}`); }
    return r.json();
  });
const randomStr = () => b64u(crypto.getRandomValues(new Uint8Array(32)));
const sha256 = async (s: string) => b64u(new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(s))));

async function login(req: Request): Promise<Response> {
  const d = await discovery();
  const state = randomStr(), verifier = randomStr();
  const next = new URL(req.url).searchParams.get("next") ?? "/";
  const u = new URL(d.authorization_endpoint);
  u.search = new URLSearchParams({
    response_type: "code", client_id: env("OIDC_CLIENT_ID"), redirect_uri: `${BASE_URL}/callback`,
    scope: "openid profile email groups", state, code_challenge: await sha256(verifier), code_challenge_method: "S256",
  }).toString();
  return new Response(null, {
    status: 302,
    headers: { location: u.toString(), "set-cookie": setCookie("up_login", await seal({ state, verifier, next: next.startsWith("/") ? next : "/" }), 600) },
  });
}

async function callback(req: Request): Promise<Response> {
  const url = new URL(req.url);
  const pending = await unseal<{ state: string; verifier: string; next: string }>(getCookie(req, "up_login"));
  if (!pending || url.searchParams.get("state") !== pending.state || !url.searchParams.get("code")) return redirect("/login");
  const d = await discovery();
  const tok = await fetch(d.token_endpoint, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", authorization: "Basic " + btoa(`${env("OIDC_CLIENT_ID")}:${env("OIDC_CLIENT_SECRET")}`) },
    body: new URLSearchParams({ grant_type: "authorization_code", code: url.searchParams.get("code")!, redirect_uri: `${BASE_URL}/callback`, code_verifier: pending.verifier }),
  });
  if (!tok.ok) return page("Sign-in problem", `<p>Sign-in didn't finish (${tok.status}). <a href="/login">Try again</a>.</p>`, null, 502);
  const { access_token } = await tok.json();
  const ui = await fetch(d.userinfo_endpoint, { headers: { authorization: `Bearer ${access_token}` } });
  if (!ui.ok) return page("Sign-in problem", `<p>Couldn't read your account (${ui.status}). <a href="/login">Try again</a>.</p>`, null, 502);
  const info = await ui.json();
  const s: Session = {
    sub: info.sub, email: info.email ?? "", name: info.given_name ?? info.name ?? "",
    groups: Array.isArray(info.groups) ? info.groups : [], exp: Date.now() + SESSION_DAYS * 864e5,
  };
  const h = new Headers({ location: pending.next });
  h.append("set-cookie", setCookie(COOKIE, await seal(s), SESSION_DAYS * 86400));
  h.append("set-cookie", setCookie("up_login", "", 0));
  return new Response(null, { status: 302, headers: h });
}

async function logout(): Promise<Response> {
  let dest = "https://underpainting.club/";
  try {
    const d = await discovery();
    if (d.end_session_endpoint) {
      const u = new URL(d.end_session_endpoint);
      u.searchParams.set("client_id", env("OIDC_CLIENT_ID"));
      u.searchParams.set("post_logout_redirect_uri", "https://underpainting.club/");
      dest = u.toString();
    }
  } catch { /* fall back to the home page */ }
  return new Response(null, { status: 302, headers: { location: dest, "set-cookie": setCookie(COOKIE, "", 0) } });
}

// ---------- pages ----------
const esc = (s: string) => s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]!));
const redirect = (to: string) => new Response(null, { status: 302, headers: { location: to } });
const isMember = (s: Session) => s.groups.some((g) => [G_COMMUNITY, G_ONE, G_ADMIN].includes(g));
const hasOne = (s: Session) => s.groups.some((g) => [G_ONE, G_ADMIN].includes(g));

const LINKS = {
  plan: "https://plan.underpainting.club",
  chat: "https://chat.underpainting.club",
  book: "https://book.underpainting.club/paint/one-on-one",
  billing: "https://billing.stripe.com/p/login/3cIfZga4H9mp8Fwaj28Ra00",
  contact: "mailto:hello@underpainting.club?subject=Member%20question",
};

function page(title: string, body: string, s: Session | null, status = 200, scripts = ""): Response {
  const right = s ? `<a class="back" href="/logout">Sign out</a>` : "";
  const html = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow"><title>${esc(title)} · Underpainting</title>
<link rel="icon" href="/brand/favicon.svg"><link rel="stylesheet" href="/members/style.css"></head>
<body>
<header><div class="wrap"><a class="wordmark" href="/">Underpainting</a>${right}</div></header>
<main class="wrap">
${body}
</main>
<footer><div class="wrap">Questions? <a href="${LINKS.contact}">hello@underpainting.club</a></div></footer>
<script src="/members/vendor/daily-js-0.94.0.js"></script>
<script src="/members/members.js"></script>
${scripts}</body></html>`;
  return new Response(html, { status, headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" } });
}

function sessionBlock(room: string): string {
  return `    <p class="when" id="ws-when">Wednesdays, 10–11:30am Pacific (1–2:30pm Eastern)</p>
    <div class="actions">
      <a class="btn" id="ws-join" href="${esc(room)}" onclick="return joinRoom(this.href, 'ws-stage')">Join the work session</a>
      <a id="ws-cal" href="/members/work-session.ics" download>Add to calendar</a>
      <a id="ws-plan" href="${LINKS.plan}" hidden>Open your plan</a>
    </div>
    <div class="stage" id="ws-stage"></div>`;
}

function home(s: Session): Response {
  const one = hasOne(s);
  const ws = env("ROOM_WORK_SESSION");
  const hello = s.name ? `Welcome back, ${esc(s.name)}` : "Welcome back";
  const body = `  <div class="intro"><h1>${hello}</h1></div>

  <section class="cols">
    <div>
      <h2>Plan</h2>
      <p class="muted">Your next steps, and what’s done.</p>
      <p class="go"><a href="${LINKS.plan}">Open your plan</a></p>
    </div>
    <div>
      <h2>Chat</h2>
      <p class="muted">Ask, share, show what you made.</p>
      <p class="go"><a href="${LINKS.chat}">Open chat</a></p>
    </div>
  </section>

  <section>
    <h2>Session</h2>
${sessionBlock(ws)}
${one ? `    <p class="note"><a href="/one-on-one">Your 1:1</a>: join or book a session.</p>` : ""}
  </section>

  <section>
    <h2>Settings</h2>
    <ul class="links">
      <li><a href="${ISSUER}/settings/account"><span>Sign-in</span><span>Passkeys and email</span></a></li>
      <li><a href="${LINKS.billing}"><span>Membership</span><span>Card, plan or cancel</span></a></li>
      <li><a href="${LINKS.chat}/account/preferences"><span>Chat</span><span>Notifications and profile</span></a></li>
${one ? `      <li><a href="${LINKS.plan}/user/settings/general"><span>Plan</span><span>Name, email reminders, time zone</span></a></li>
      <li><a href="/one-on-one#book"><span>Scheduling</span><span>Book; reschedule from your booking email</span></a></li>` : ""}
      <li><a href="mailto:hello@underpainting.club?subject=Please%20delete%20my%20account"><span>Delete account</span><span>We remove you everywhere</span></a></li>
    </ul>
  </section>`;
  return page("Members", body, s, 200,
    `<script>if (document.body.dataset.live === '1') joinRoom(${JSON.stringify(ws)}, 'ws-stage', true);</script>\n`);
}

function oneOnOne(s: Session): Response {
  const room = env("ROOM_ONE_TO_ONE");
  const body = `  <div class="intro">
    <h1>Your 1:1</h1>
    <p>Two 45-minute sessions a month, on your plan and what comes next.</p>
  </div>
  <section>
    <p class="eyebrow">Session starting?</p>
    <div class="actions">
      <a class="btn" href="${esc(room)}" onclick="return joinRoom(this.href, 'oo-stage')">Join your 1:1</a>
      <a href="${LINKS.plan}">Open your plan</a>
    </div>
    <div class="stage" id="oo-stage"></div>
    <p class="note">Your booking email has the time. You’ll wait at the door for a moment until we let you in.</p>
  </section>
  <section id="book">
    <h2>Book a session</h2>
    <div id="tymeslot-booking" data-username="paint/one-on-one" data-locale="en" data-max-width="900"></div>
    <p class="note">Calendar not showing? <a href="${LINKS.book}">Book on the booking page</a>.</p>
  </section>`;
  return page("Your 1:1", body, s, 200, `<script src="https://book.underpainting.club/embed.js" async></script>\n`);
}

function notMember(s: Session): Response {
  return page("Membership", `  <div class="intro"><h1>No active membership</h1>
    <p>You’re signed in as ${esc(s.email)}, but this account isn’t linked to a membership yet.</p></div>
  <section><div class="actions"><a class="btn" href="https://underpainting.club/#membership">See membership</a>
  <a href="${LINKS.contact}">Email us</a></div></section>`, s, 403);
}

// ---------- static files from the repo (styles, scripts, fonts, brand) ----------
const TYPES: Record<string, string> = { css: "text/css", js: "text/javascript", woff2: "font/woff2", svg: "image/svg+xml", png: "image/png", ico: "image/x-icon", ics: "text/calendar", txt: "text/plain" };
const STATIC = /^\/(members\/(style\.css|members\.js|work-session\.ics|vendor\/[\w.-]+)|fonts\/[\w.-]+|brand\/[\w.-]+\.(svg|png|ico))$/;

async function serveStatic(path: string): Promise<Response | null> {
  if (!STATIC.test(path) || path.includes("..")) return null;
  try {
    const data = await Deno.readFile(new URL("." + path, ROOT));
    return new Response(data, { headers: { "content-type": TYPES[path.split(".").pop()!] ?? "application/octet-stream", "cache-control": "public, max-age=3600" } });
  } catch {
    return null;
  }
}

// ---------- router ----------
export async function handler(req: Request): Promise<Response> {
  const { pathname } = new URL(req.url);
  if (pathname === "/healthz") return new Response("ok");
  if (pathname === "/login") return login(req);
  if (pathname === "/callback") return callback(req);
  if (pathname === "/logout") return logout();
  const file = await serveStatic(pathname);
  if (file) return file;

  const s = await unseal<Session>(getCookie(req, COOKIE));
  if (!s || s.exp < Date.now()) return redirect(`/login?next=${encodeURIComponent(pathname)}`);
  if (!isMember(s)) return notMember(s);
  if (pathname === "/" || pathname === "/work-session") return home(s);
  if (pathname === "/one-on-one") return hasOne(s) ? oneOnOne(s) : redirect("/");
  return page("Not found", `<div class="intro"><h1>Page not found</h1><p><a href="/">Back to your page</a></p></div>`, s, 404);
}

if (import.meta.main) Deno.serve(handler);
