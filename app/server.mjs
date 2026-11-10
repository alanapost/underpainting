import { createServer } from "node:http";
import { readFile, writeFile, rename, mkdir } from "node:fs/promises";
import { timingSafeEqual } from "node:crypto";
import { pathToFileURL } from "node:url";

// Underpainting members app: signs members in through Pocket ID and serves their page.
// Plain Node 20+ with no dependencies: `node app/server.mjs` (PORT, default 8000). No database. Settings come from env vars:
//   BASE_URL            https://members.underpainting.club
//   OIDC_ISSUER         https://login.underpainting.club
//   OIDC_CLIENT_ID, OIDC_CLIENT_SECRET   from the Pocket ID app
//   SESSION_SECRET      32+ random characters
//   ROOM_WORK_SESSION, ROOM_ONE_TO_ONE   Daily room URLs (kept out of the public repo)
//   ROOM_INTRO          optional; intro-call room, listed on /host
//   VIKUNJA_TOKEN       optional; read-only token (projects + tasks) of the account that owns members' plans
//   VIKUNJA_URL (default https://plan.underpainting.club)
//   TYMESLOT_WEBHOOK_TOKEN  optional; token set on Tymeslot's webhook to POST /hooks/tymeslot
//   DATA_DIR (default /data; a Fly volume) holds bookings.json
//   SESSIONS_PER_MONTH (default 2)
//   DAILY_API_KEY       lets admins get host links at /host (rooms are created there if missing)
//   GROUP_COMMUNITY (default "community"), GROUP_ONE_ON_ONE (default "one-on-one"), GROUP_ADMIN (default "admin")

const env = (k, d) => {
  const v = process.env[k] ?? d;
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


// ---------- signed cookies (HMAC-SHA256) ----------
const enc = new TextEncoder();
let keyP;
const key = () =>
  keyP ??= crypto.subtle.importKey("raw", enc.encode(env("SESSION_SECRET")), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
const b64u = (b) => btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const unb64u = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));

async function seal(data) {
  const body = b64u(enc.encode(JSON.stringify(data)));
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", await key(), enc.encode(body)));
  return `${body}.${b64u(sig)}`;
}
async function unseal(token) {
  if (!token) return null;
  const [body, sig] = token.split(".");
  if (!body || !sig) return null;
  try {
    const ok = await crypto.subtle.verify("HMAC", await key(), unb64u(sig), enc.encode(body));
    return ok ? JSON.parse(new TextDecoder().decode(unb64u(body))) : null;
  } catch {
    return null;
  }
}
const getCookie = (req, name) =>
  req.headers.get("cookie")?.split(/;\s*/).find((c) => c.startsWith(name + "="))?.slice(name.length + 1);
const setCookie = (name, value, maxAge) =>
  `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;

// ---------- OIDC (authorization code + PKCE, confidential client) ----------
let discP;
const discovery = () =>
  discP ??= fetch(`${ISSUER}/.well-known/openid-configuration`).then((r) => {
    if (!r.ok) { discP = undefined; throw new Error(`Discovery failed: ${r.status}`); }
    return r.json();
  });
const randomStr = () => b64u(crypto.getRandomValues(new Uint8Array(32)));
const sha256 = async (s) => b64u(new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(s))));

// Only same-site paths: "//evil.com", "/\\evil.com" and tab tricks all resolve off-site and fall back to "/".
function safeNext(next) {
  try {
    const u = new URL(next, "https://members.invalid");
    return u.origin === "https://members.invalid" && next.startsWith("/") ? u.pathname + u.search : "/";
  } catch { return "/"; }
}

async function login(req) {
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
    headers: { location: u.toString(), "set-cookie": setCookie("up_login", await seal({ state, verifier, next: safeNext(next) }), 600) },
  });
}

async function callback(req) {
  const url = new URL(req.url);
  const pending = await unseal(getCookie(req, "up_login"));
  if (!pending || url.searchParams.get("state") !== pending.state || !url.searchParams.get("code")) return redirect("/login");
  const d = await discovery();
  const tok = await fetch(d.token_endpoint, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", authorization: "Basic " + btoa(`${env("OIDC_CLIENT_ID")}:${env("OIDC_CLIENT_SECRET")}`) },
    body: new URLSearchParams({ grant_type: "authorization_code", code: url.searchParams.get("code"), redirect_uri: `${BASE_URL}/callback`, code_verifier: pending.verifier }),
  });
  if (!tok.ok) return page("Sign-in problem", `<p>Sign-in didn't finish (${tok.status}). <a href="/login">Try again</a>.</p>`, null, 502);
  const { access_token } = await tok.json();
  const ui = await fetch(d.userinfo_endpoint, { headers: { authorization: `Bearer ${access_token}` } });
  if (!ui.ok) return page("Sign-in problem", `<p>Couldn't read your account (${ui.status}). <a href="/login">Try again</a>.</p>`, null, 502);
  const info = await ui.json();
  const s = {
    sub: info.sub, email: info.email ?? "", name: info.given_name ?? info.name ?? "", user: info.preferred_username ?? "",
    groups: Array.isArray(info.groups) ? info.groups : [], exp: Date.now() + SESSION_DAYS * 864e5,
  };
  const h = new Headers({ location: pending.next });
  h.append("set-cookie", setCookie(COOKIE, await seal(s), SESSION_DAYS * 86400));
  h.append("set-cookie", setCookie("up_login", "", 0));
  return new Response(null, { status: 302, headers: h });
}

async function logout() {
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
const esc = (s) => s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const redirect = (to) => new Response(null, { status: 302, headers: { location: to } });
const isMember = (s) => s.groups.some((g) => [G_COMMUNITY, G_ONE, G_ADMIN].includes(g));
const hasOne = (s) => s.groups.some((g) => [G_ONE, G_ADMIN].includes(g));

const LINKS = {
  plan: "https://plan.underpainting.club",
  chat: "https://chat.underpainting.club",
  book: "https://book.underpainting.club/paint/one-on-one",
  billing: "https://billing.stripe.com/p/login/3cIfZga4H9mp8Fwaj28Ra00",
  contact: "mailto:hello@underpainting.club?subject=Member%20question",
};

function page(title, body, s, status = 200, scripts = "") {
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

function sessionBlock(room) {
  return `    <p class="when" id="ws-when">Wednesdays, 10–11:30am Pacific (1–2:30pm Eastern)</p>
    <div class="actions">
      <a class="btn" id="ws-join" href="${esc(room)}" onclick="return joinRoom(this.href, 'ws-stage')">Join the work session</a>
      <a id="ws-cal" href="/members/work-session.ics" download>Add to calendar</a>
      <a id="ws-plan" href="${LINKS.plan}" hidden>Open your plan</a>
    </div>
    <div class="stage" id="ws-stage"></div>`;
}

// ---------- plan next steps (Vikunja, read-only; fails quietly to just the link) ----------
const VIKUNJA = process.env.VIKUNJA_URL ?? "https://plan.underpainting.club";
let planMap = { at: 0, projects: [] }; // [{ id, people: [{ username, email }] }], cached 10 min

async function vk(path) {
  const r = await fetch(`${VIKUNJA}/api/v1${path}`, { headers: { authorization: `Bearer ${process.env.VIKUNJA_TOKEN}` }, signal: AbortSignal.timeout(4000) });
  if (!r.ok) throw new Error(`Vikunja ${path} ${r.status}`);
  return r.json();
}

async function findPlan(s) {
  if (Date.now() - planMap.at > 600e3) {
    const projects = await vk("/projects?per_page=100");
    const withPeople = await Promise.all(projects.map(async (p) => ({ id: p.id, people: await vk(`/projects/${p.id}/users`).catch(() => []) })));
    planMap = { at: Date.now(), projects: withPeople };
  }
  const user = (s.user ?? "").replace(/ /g, "-").toLowerCase(), email = (s.email ?? "").toLowerCase();
  return planMap.projects.find((p) => p.people.some((u) =>
    (user && (u.username ?? "").toLowerCase() === user) || (email && (u.email ?? "").toLowerCase() === email)));
}

async function nextSteps(s) {
  if (!process.env.VIKUNJA_TOKEN) return null;
  try {
    const p = await findPlan(s);
    if (!p) return null;
    // Prefer the Plan board: "Now" cards, then "Next", in board order.
    const views = await vk(`/projects/${p.id}/views`).catch(() => []);
    const board = views.find((v) => v.view_kind === "kanban");
    if (board) {
      const buckets = await vk(`/projects/${p.id}/views/${board.id}/tasks`).catch(() => null);
      if (Array.isArray(buckets)) {
        const pick = (name) => (buckets.find((b) => (b.title ?? "").trim().toLowerCase() === name)?.tasks ?? []).filter((t) => !t.done);
        const tasks = [...pick("now"), ...pick("next")];
        if (buckets.some((b) => /^(now|next)$/i.test((b.title ?? "").trim()))) return { project: p.id, tasks: tasks.slice(0, 3) };
      }
    }
    const q = new URLSearchParams({ filter: "done = false", per_page: "3" });
    q.append("sort_by", "due_date"); q.append("order_by", "asc"); q.append("sort_by", "position"); q.append("order_by", "asc");
    const tasks = await vk(`/projects/${p.id}/tasks?${q}`);
    return { project: p.id, tasks: (tasks ?? []).slice(0, 3) };
  } catch (e) {
    console.error(String(e));
    return null;
  }
}

function planBlock(steps) {
  if (!steps) return `      <p class="muted">Your next steps, and what’s done.</p>
      <p class="go"><a href="${LINKS.plan}">Open your plan</a></p>`;
  const items = steps.tasks.map((t) => `        <li><a href="${VIKUNJA}/tasks/${t.id}">${esc(t.title ?? "")}</a></li>`).join("\n");
  return `${items ? `      <ul class="steps">\n${items}\n      </ul>` : `      <p class="muted">Nothing open right now.</p>`}
      <p class="go"><a href="${VIKUNJA}/projects/${steps.project}">Open your plan</a></p>`;
}

async function home(s) {
  const one = hasOne(s);
  const ones = await myOnes(s);
  const ws = env("ROOM_WORK_SESSION");
  const hello = s.name ? `Welcome back, ${esc(s.name)}` : "Welcome back";
  const body = `  <div class="intro"><h1>${hello}</h1></div>

  <section class="cols">
    <div>
      <h2>Plan</h2>
${planBlock(await nextSteps(s))}
    </div>
    <div>
      <h2>Chat</h2>
      <p class="muted">Ask, share, show what you made.</p>
      <p class="go"><a href="${LINKS.chat}">Open chat</a></p>
    </div>
  </section>

  <section>
    <h2>Session</h2>
${ones?.live ? oneStatus(ones) : sessionBlock(ws)}
${ones && !ones.live ? oneStatus(ones) : ""}
${one ? `    <p class="note"><a href="/one-on-one">Your 1:1</a>: join or book a session.</p>` : ""}
${isAdmin(s) ? `    <p class="note"><a href="/host">Host links</a> (only you see this).</p>` : ""}
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

// ---------- 1:1 bookings (from Tymeslot webhooks, kept in one JSON file) ----------
const DATA_DIR = process.env.DATA_DIR ?? "/data";
const PER_MONTH = Number(process.env.SESSIONS_PER_MONTH ?? 2);
const ONE_SLUG = "one-on-one";
let bookings = null; // { [uid]: { email, start, end, status, slug, name, reschedule } }

async function loadBookings() {
  if (bookings) return bookings;
  try { bookings = JSON.parse(await readFile(`${DATA_DIR}/bookings.json`, "utf8")); } catch { bookings = {}; }
  return bookings;
}
async function saveBookings() {
  await mkdir(DATA_DIR, { recursive: true });
  await writeFile(`${DATA_DIR}/bookings.json.tmp`, JSON.stringify(bookings));
  await rename(`${DATA_DIR}/bookings.json.tmp`, `${DATA_DIR}/bookings.json`);
}

async function tymeslotHook(req) {
  const want = process.env.TYMESLOT_WEBHOOK_TOKEN, got = req.headers.get("x-tymeslot-token") ?? "";
  if (!want || got.length !== want.length || !timingSafeEqual(Buffer.from(got), Buffer.from(want))) return new Response("no", { status: 401 });
  const body = await req.json().catch(() => null);
  const m = body?.data?.meeting;
  if (!m?.uid) return new Response("ok"); // test pings and other events
  await loadBookings();
  bookings[m.uid] = {
    email: (m.attendee?.email ?? "").toLowerCase(), name: m.attendee?.name ?? "",
    start: m.start_time, end: m.end_time, status: m.status ?? "", slug: m.booking_page?.slug ?? "",
    reschedule: m.urls?.reschedule ?? "",
  };
  const cutoff = Date.now() - 400 * 864e5; // keep about a year
  for (const [k, b] of Object.entries(bookings)) if (Date.parse(b.end) < cutoff) delete bookings[k];
  await saveBookings();
  return new Response("ok");
}

const ptMonth = (t) => new Intl.DateTimeFormat("en-CA", { timeZone: "America/Los_Angeles", year: "numeric", month: "2-digit" }).format(t);
const live = (b, now) => Date.parse(b.start) - 10 * 60e3 <= now && now <= Date.parse(b.end);

async function myOnes(s, now = Date.now()) {
  if (!s.groups.includes(G_ONE) || !s.email) return null;
  const all = Object.values(await loadBookings()).filter((b) => b.email === s.email.toLowerCase() && b.slug === ONE_SLUG && !/cancel/i.test(b.status));
  const month = all.filter((b) => ptMonth(new Date(b.start)) === ptMonth(new Date(now)));
  const next = all.filter((b) => Date.parse(b.end) >= now).sort((a, b) => Date.parse(a.start) - Date.parse(b.start))[0] ?? null;
  return { used: month.filter((b) => Date.parse(b.end) < now).length, booked: month.length, left: Math.max(0, PER_MONTH - month.length), next, live: next && live(next, now) };
}

const whenText = (iso) => `<time class="local" datetime="${esc(iso)}">${esc(new Date(iso).toLocaleString("en-US", { timeZone: "America/Los_Angeles", weekday: "long", month: "long", day: "numeric", hour: "numeric", minute: "2-digit" }))} Pacific</time>`;

function oneStatus(o) {
  if (!o) return "";
  if (o.live) return `    <p class="when live"><span class="dot" aria-hidden="true"></span>Your 1:1 is starting</p>
    <div class="actions">
      <a class="btn" href="${esc(env("ROOM_ONE_TO_ONE"))}" onclick="return joinRoom(this.href, 'oo-stage')">Join your 1:1</a>
      <a href="${LINKS.plan}">Open your plan</a>
    </div>
    <div class="stage" id="oo-stage"></div>`;
  const count = `${o.used} of ${PER_MONTH} sessions used this month${o.booked > o.used ? `, ${o.booked - o.used} booked` : ""}.`;
  if (o.next) return `    <p>Your next 1:1 is ${whenText(o.next.start)}.${o.next.reschedule ? ` <a href="${esc(o.next.reschedule)}">Reschedule</a>` : ""}</p>
    <p class="muted">${count}</p>`;
  if (o.left > 0) return `    <p>You have ${o.left} 1:1 ${o.left === 1 ? "session" : "sessions"} left this month. <a href="/one-on-one#book">Book one now</a> while there's time on the calendar.</p>
    <p class="muted">${count}</p>`;
  return `    <p class="muted">${count}</p>`;
}

function oneOnOne(s, o) {
  const room = env("ROOM_ONE_TO_ONE");
  const body = `  <div class="intro">
    <h1>Your 1:1</h1>
    <p>Two 45-minute sessions a month, on your plan and what comes next.</p>
  </div>
  <section>
${o ? oneStatus(o) + "\n" : ""}${o?.live ? "" : `    <div class="actions">
      <a class="btn" href="${esc(room)}" onclick="return joinRoom(this.href, 'oo-stage')">Join your 1:1</a>
      <a href="${LINKS.plan}">Open your plan</a>
    </div>
    <div class="stage" id="oo-stage"></div>
`}    <p class="note">You’ll wait at the door for a moment until you’re let in.</p>
  </section>
  <section id="book">
    <h2>Book a session</h2>
    <div id="tymeslot-booking" data-username="paint/one-on-one" data-locale="en" data-max-width="900"></div>
    <p class="note">Calendar not showing? <a href="${LINKS.book}">Book on the booking page</a>.</p>
  </section>`;
  return page("Your 1:1", body, s, 200, `<script src="https://book.underpainting.club/embed.js" async></script>\n`);
}

// ---------- host links for admins (Daily owner tokens, made fresh each visit) ----------
const isAdmin = (s) => s.groups.includes(G_ADMIN);
const roomName = (url) => new URL(url).pathname.replace(/^\//, "");

async function daily(path, body) {
  const r = await fetch(`https://api.daily.co/v1${path}`, {
    method: body ? "POST" : "GET",
    headers: { authorization: `Bearer ${env("DAILY_API_KEY")}`, "content-type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  return { ok: r.ok, status: r.status, data: await r.json().catch(() => ({})) };
}

async function hostLink(roomUrl) {
  const name = roomName(roomUrl);
  const room = await daily(`/rooms/${name}`);
  if (room.status === 404) {
    const made = await daily("/rooms", { name, privacy: "private", properties: { enable_knocking: true, enable_prejoin_ui: true } });
    if (!made.ok) throw new Error(`Couldn't create room ${name} (${made.status})`);
  } else if (!room.ok) throw new Error(`Couldn't check room ${name} (${room.status})`);
  const tok = await daily("/meeting-tokens", { properties: { room_name: name, is_owner: true, exp: Math.floor(Date.now() / 1000) + 6 * 3600 } });
  if (!tok.ok || !tok.data.token) throw new Error(`Couldn't make a host link for ${name} (${tok.status})`);
  return `${roomUrl}?t=${tok.data.token}`;
}

async function host(s) {
  let body;
  try {
    const intro = process.env.ROOM_INTRO;
    const [ws, oo, ic] = await Promise.all([hostLink(env("ROOM_WORK_SESSION")), hostLink(env("ROOM_ONE_TO_ONE")), intro ? hostLink(intro) : null]);
    body = `  <div class="intro"><h1>Host</h1><p>Host links let you admit people at the door. They last 6 hours; reload this page for fresh ones.</p></div>
  <section><div class="actions">
    <a class="btn" href="${esc(ws)}" target="_blank" rel="noopener">Host the work session</a>
    <a href="${esc(oo)}" target="_blank" rel="noopener">Host a 1:1</a>
    ${ic ? `<a href="${esc(ic)}" target="_blank" rel="noopener">Host an intro call</a>` : ""}
  </div></section>`;
  } catch (e) {
    body = `  <div class="intro"><h1>Host</h1><p>${esc(String(e.message ?? e))}. Check DAILY_API_KEY in the app's secrets.</p></div>`;
  }
  return page("Host", body, s);
}

function notMember(s) {
  return page("Membership", `  <div class="intro"><h1>No active membership</h1>
    <p>You’re signed in as ${esc(s.email)}, but this account isn’t linked to a membership yet.</p></div>
  <section><div class="actions"><a class="btn" href="https://underpainting.club/#membership">See membership</a>
  <a href="${LINKS.contact}">Email us</a></div></section>`, s, 403);
}

// ---------- static files from the repo (styles, scripts, fonts, brand) ----------
const TYPES = { css: "text/css", js: "text/javascript", woff2: "font/woff2", svg: "image/svg+xml", png: "image/png", ico: "image/x-icon", ics: "text/calendar", txt: "text/plain" };
const STATIC = /^\/(members\/(style\.css|members\.js|work-session\.ics|vendor\/[\w.-]+)|fonts\/[\w.-]+|brand\/[\w.-]+\.(svg|png|ico))$/;

async function serveStatic(path) {
  if (!STATIC.test(path) || path.includes("..")) return null;
  try {
    const data = await readFile(new URL("." + path, ROOT));
    return new Response(data, { headers: { "content-type": TYPES[path.split(".").pop()] ?? "application/octet-stream", "cache-control": "public, max-age=3600" } });
  } catch {
    return null;
  }
}

// ---------- router ----------
export { safeNext };
export async function handler(req) {
  const { pathname } = new URL(req.url);
  if (pathname === "/healthz") return new Response("ok");
  if (pathname === "/login") return login(req);
  if (pathname === "/callback") return callback(req);
  if (pathname === "/logout") return logout();
  if (pathname === "/hooks/tymeslot" && req.method === "POST") return tymeslotHook(req);
  const file = await serveStatic(pathname);
  if (file) return file;

  const s = await unseal(getCookie(req, COOKIE));
  if (!s || s.exp < Date.now()) return redirect(`/login?next=${encodeURIComponent(pathname)}`);
  if (!isMember(s)) return notMember(s);
  if (pathname === "/" || pathname === "/work-session") return home(s);
  if (pathname === "/one-on-one") return hasOne(s) ? oneOnOne(s, await myOnes(s)) : redirect("/");
  if (pathname === "/host") return isAdmin(s) ? host(s) : redirect("/");
  return page("Not found", `<div class="intro"><h1>Page not found</h1><p><a href="/">Back to your page</a></p></div>`, s, 404);
}

// ---------- Node HTTP adapter ----------
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const port = Number(process.env.PORT ?? 8000);
  createServer(async (nreq, nres) => {
    try {
      const chunks = [];
      if (nreq.method !== "GET" && nreq.method !== "HEAD") for await (const c of nreq) chunks.push(c);
      const req = new Request(new URL(nreq.url, BASE_URL), { method: nreq.method, headers: nreq.headers, body: chunks.length ? Buffer.concat(chunks) : undefined });
      const res = await handler(req);
      const headers = {};
      res.headers.forEach((v, k) => { if (k !== "set-cookie") headers[k] = v; });
      const cookies = res.headers.getSetCookie();
      if (cookies.length) headers["set-cookie"] = cookies;
      nres.writeHead(res.status, headers);
      nres.end(Buffer.from(await res.arrayBuffer()));
    } catch (e) {
      console.error(e);
      nres.writeHead(500, { "content-type": "text/plain" }).end("Something went wrong.");
    }
  }).listen(port, () => console.log(`members app on :${port}`));
}
