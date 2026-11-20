// server.js — MONSTER ARENA // deliberately vulnerable top-down shooter lab.
//
//   node server.js        (always vulnerable — there is no "secure" mode)
//
// Localhost-only university software-security lab. A real-looking browser game
// sits on top of a JSON API. Four planted bugs form one chain:
//
//   Stage 1  REPLAY   (A04)  POST /api/kill credits every time it is called ->
//                            replay it to vault onto the podium.
//   Stage 2  XSS      (A03)  landing on the podium fires a global-chat
//                            announcement that renders your NAME as raw HTML ->
//                            the GameMaster's browser runs it -> steal its token.
//   Stage 3  SQLi     (A03)  GET /api/players/search?q= concatenates q into SQL.
//   Stage 4  MD5      (A02)  the dump hands you unsalted MD5 hashes -> rockyou.
//
// Every planted bug is tagged `VULN(stage-N, OWASP)` with a matching `FIX:`.
// See VULNERABILITIES.md for the full register. NOTHING here is safe to deploy.

const express = require('express');
const crypto = require('crypto');
const { JSDOM, VirtualConsole } = require('jsdom');
const { FLAGS, md5, seedPlayers, buildSqlDb } = require('./db');

const PORT = process.env.PORT || 3003;
const HOST = '127.0.0.1'; // localhost only — never bind beyond this machine.

const app = express();
app.use(express.json());

// ---- Live state (re-seeded on every start) -----------------------------
let players = seedPlayers().map((p) => {
  // The app stores ONLY MD5 of the password (the dump payoff in stage 4).
  const q = { ...p, passwordMd5: md5(p.password), gold: 0, exp: (p.level - 1) * 100 };
  delete q.password;
  return q;
});
let nextPlayerId = Math.max(...players.map((p) => p.id)) + 1;

const sessions = new Map();         // token -> playerId
const announcedPodium = new Set();  // playerId -> already announced (fire once)

let chat = [];                      // { id, kind:'chat'|'announce', name, text }
let nextChatId = 1;

let monsters = [];                  // alive server-spawned monsters
let nextMonsterId = 1;

let sqlDB = null;                   // sql.js SQLite (backs the search; SQLi target)

// The GameMaster is "logged in" from boot — this is the session the stored XSS
// steals. Issued once at startup; the bot (below) carries it in its browser.
const ADMIN_TOKEN = crypto.randomBytes(24).toString('hex');

// Stage-2 exfil sink: a self-contained, localhost-only drop box. The stolen
// token lands here and the attacker reads it back from /api/collect/peek — so
// the lab needs no external listener and never phones home off this machine.
const collected = [];

// ---- Game-balance constants --------------------------------------------
const REWARD = { score: 25, exp: 20, gold: 10 };        // per kill
const MONSTER_HP = 14;                            // very tanky on purpose (grind is hopeless)
const MONSTER_SPAWN_MS = 30 * 1000;               // one new monster every 30s
const MAX_MONSTERS = 3;                            // few on screen at once
const WORLD = { w: 2200, h: 2000 };

function levelFor(exp) { return 1 + Math.floor(exp / 100); }

function findByUsername(u) { return players.find((p) => p.username === u); }
function findById(id) { return players.find((p) => p.id === id); }
function playerByToken(req) {
  const m = (req.headers['authorization'] || '').match(/^Bearer\s+(.+)$/i);
  if (!m) return null;
  const id = sessions.get(m[1].trim());
  return id == null ? null : findById(id);
}
function requireAuth(req, res) {
  const p = playerByToken(req);
  if (!p) { res.status(401).json({ error: 'unauthenticated' }); return null; }
  return p;
}

// Leaderboard, highest score first. Ties broken by id so ranks are stable.
function ranked() {
  return [...players].sort((a, b) => b.score - a.score || a.id - b.id);
}
function rankOf(playerId) {
  return ranked().findIndex((p) => p.id === playerId) + 1;
}

// ========================================================================
// Web UI (HTML pages). Thin client; the browser holds the bearer token in
// localStorage('ma_token') and drives everything from fetch().
// ========================================================================
app.get('/',         (req, res) => res.type('html').send(PAGE_LANDING));
app.get('/login',    (req, res) => res.type('html').send(PAGE_LOGIN));
app.get('/register', (req, res) => res.type('html').send(PAGE_REGISTER));
app.get('/game',     (req, res) => res.type('html').send(PAGE_GAME));

// ========================================================================
// POST /api/register { username, password, displayName? } -> { token }
// ========================================================================
app.post('/api/register', (req, res) => {
  const { username, password } = req.body || {};
  let { displayName } = req.body || {};
  if (typeof username !== 'string' || typeof password !== 'string' ||
      username.length < 3 || password.length < 1) {
    return res.status(400).json({ error: 'username (3+) and password required' });
  }
  // VULN(stage-1, OWASP A07): username enumeration — a taken name returns a
  // distinct 409, so an attacker can map valid accounts before brute forcing.
  // FIX: register behind email verification; never confirm existence to an
  //      unauthenticated caller with a distinguishable status.
  if (findByUsername(username)) {
    return res.status(409).json({ error: 'username taken' });
  }
  if (typeof displayName !== 'string' || !displayName.length) displayName = username;
  const p = {
    id: nextPlayerId++, username, passwordMd5: md5(password), role: 'player',
    displayName, email: '', score: 0, level: 1, exp: 0, gold: 0, stash: 'empty locker',
  };
  players.push(p);
  const token = crypto.randomBytes(24).toString('hex');
  sessions.set(token, p.id);
  return res.status(200).json({ token });
});

// ========================================================================
// POST /api/login { username, password } -> { token }
// ========================================================================
app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  if (typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'username and password required' });
  }
  const user = findByUsername(username);
  // VULN(stage-1, OWASP A07): user enumeration (404 unknown vs 401 wrong pass)
  // AND no rate limit / lockout, so online password guessing runs unbounded.
  // FIX: one generic 401 for both cases, plus per-account throttling/lockout.
  if (!user) return res.status(404).json({ error: 'no such user' });
  // VULN(stage-4, OWASP A02): passwords kept as UNSALTED MD5 — a fast, broken
  // hash. Verification just MD5s the input and compares.
  // FIX: store a slow salted KDF (bcrypt/argon2/scrypt) and verify against it.
  if (user.passwordMd5 !== md5(password)) {
    return res.status(401).json({ error: 'invalid password' });
  }
  const token = crypto.randomBytes(24).toString('hex');
  sessions.set(token, user.id);
  return res.status(200).json({ token });
});

// ========================================================================
// GET /api/me (auth) -> own record + private stash.
//   The admin's own record carries F2 (proof you hijacked the GameMaster).
//   A cracked player's stash carries F4 (proof you cracked + logged in).
// ========================================================================
app.get('/api/me', (req, res) => {
  const p = requireAuth(req, res);
  if (!p) return;
  const body = {
    id: p.id, username: p.username, displayName: p.displayName, role: p.role,
    score: p.score, level: p.level, exp: p.exp, gold: p.gold, stash: p.stash,
  };
  if (p.role === 'admin') body.flag = FLAGS.F2; // you are holding the GameMaster's token
  return res.status(200).json(body);
});

// ========================================================================
// PATCH /api/account (auth) { displayName?, email? } — edit your profile.
//   This is how you arm the stage-2 payload: set displayName to your XSS.
// ========================================================================
app.patch('/api/account', (req, res) => {
  const p = requireAuth(req, res);
  if (!p) return;
  const b = req.body || {};
  // VULN(stage-2, OWASP A03): displayName is stored verbatim with no output
  // encoding at the sink (see the chat announcement renderer). Storing raw is
  // fine; the bug is failing to encode on the way OUT into HTML.
  // FIX: context-aware output encoding when the name is rendered (escape HTML).
  if (typeof b.displayName === 'string' && b.displayName.length <= 200) p.displayName = b.displayName;
  if (typeof b.email === 'string' && b.email.length <= 200) p.email = b.email;
  return res.status(200).json({ id: p.id, displayName: p.displayName, email: p.email });
});

// ========================================================================
// GET /api/monsters (auth) -> currently-alive monsters the server spawned.
//   Each carries a one-time `nonce` the HONEST client returns on a kill. The
//   kill route ignores it (stage 1), but it is here so the replay bug is a
//   missing check, not a missing field.
// ========================================================================
app.get('/api/monsters', (req, res) => {
  const p = requireAuth(req, res);
  if (!p) return;
  return res.status(200).json({
    monsters: monsters.map((m) => ({ id: m.id, nonce: m.nonce, x: m.x, y: m.y, hp: m.hp, maxHp: m.maxHp, type: m.type })),
  });
});

// ========================================================================
// POST /api/kill (auth) { id?, nonce? } -> credits a kill, returns new totals.
// ========================================================================
app.post('/api/kill', (req, res) => {
  const p = requireAuth(req, res);
  if (!p) return;

  // VULN(stage-1, OWASP A04): the kill is credited on EVERY request. The route
  // never checks that the monster exists, is alive, belongs to this player, or
  // that the nonce was not already spent — so the exact same request replays
  // for unlimited score/exp/gold. Resend it in Burp/curl/ffuf to vault the
  // leaderboard; legit play (1 slow monster / 30s) never could.
  // FIX: make kills idempotent + server-authoritative — issue a one-time nonce
  //      per spawned monster, verify it is unspent AND the monster is alive,
  //      then atomically consume it. A replayed nonce must earn nothing (409).
  p.score += REWARD.score;
  p.exp += REWARD.exp;
  p.gold += REWARD.gold;
  p.level = levelFor(p.exp);

  // If the client named a real live monster, retire it (cosmetic — the credit
  // above already happened regardless, which is exactly the bug).
  const mid = Number(req.body && req.body.id);
  if (Number.isInteger(mid)) monsters = monsters.filter((m) => m.id !== mid);

  const rank = rankOf(p.id);
  const body = { score: p.score, exp: p.exp, gold: p.gold, level: p.level, rank };

  // Breaking onto the podium (top 3) fires the vulnerable announcement once.
  if (rank <= 3 && !announcedPodium.has(p.id)) {
    announcedPodium.add(p.id);
    pushAnnouncement(p.displayName, 'smashed into the TOP 3!');
    body.flag = FLAGS.F1; // proof you beat a wall only replay can beat
  }
  return res.status(200).json(body);
});

// ========================================================================
// POST /api/cashout (auth) { gold } -> bank the loot the client has been
//   carrying. Collectables are tallied CLIENT-SIDE in the browser's
//   localStorage ('ma_backpack'); this route banks whatever the client claims.
// ========================================================================
app.post('/api/cashout', (req, res) => {
  const p = requireAuth(req, res);
  if (!p) return;

  // VULN(stage-1, OWASP A04 Insecure Design / "never trust the client"): the
  // player's loot lives in the BROWSER (localStorage 'ma_backpack') and this
  // route banks the self-reported total with no server-side truth to check it
  // against. Open DevTools -> Application -> Local Storage, set ma_backpack to
  // {"gold":999999}, bank it, and seize the leaderboard. (The request is also
  // replayable — resend it in Burp to bank the same loot again and again.)
  // FIX: never trust client-held state for anything that counts. Keep the loot
  //      tally SERVER-side, credit only server-issued one-time collectable ids,
  //      and ignore any client-supplied total.
  let gold = Number(req.body && req.body.gold);
  if (!Number.isFinite(gold) || gold <= 0) return res.status(400).json({ error: 'nothing to bank' });
  gold = Math.floor(gold);
  p.gold += gold;
  p.score += gold;                 // banked loot converts straight to leaderboard score
  p.exp += Math.floor(gold / 2);
  p.level = levelFor(p.exp);

  const rank = rankOf(p.id);
  const body = { score: p.score, exp: p.exp, gold: p.gold, level: p.level, rank, banked: gold };
  if (rank <= 3 && !announcedPodium.has(p.id)) {
    announcedPodium.add(p.id);
    pushAnnouncement(p.displayName, 'smashed into the TOP 3!');
    body.flag = FLAGS.F1;
  }
  return res.status(200).json(body);
});

// ========================================================================
// GET /api/scoreboard (public) -> top 10. Names are DATA here; the client
//   escapes them on render (this surface is NOT the XSS — the announcement is).
// ========================================================================
app.get('/api/scoreboard', (req, res) => {
  const board = ranked().slice(0, 10).map((p, i) => ({
    rank: i + 1, name: p.displayName, score: p.score, level: p.level,
  }));
  return res.status(200).json({ board });
});

// ========================================================================
// Global chat.  GET returns recent messages; POST appends a normal message.
// ========================================================================
app.get('/api/chat', (req, res) => {
  const p = requireAuth(req, res);
  if (!p) return;
  return res.status(200).json({ messages: chat.slice(-40) });
});

app.post('/api/chat', (req, res) => {
  const p = requireAuth(req, res);
  if (!p) return;
  const text = (req.body && typeof req.body.text === 'string') ? req.body.text : '';
  if (!text.trim()) return res.status(400).json({ error: 'empty message' });
  // Normal chat text is NOT the sink — the client escapes it on render. This is
  // the deliberate counter-example: ordinary user input here is handled safely.
  chat.push({ id: nextChatId++, kind: 'chat', name: p.displayName, text: text.slice(0, 300) });
  if (chat.length > 200) chat = chat.slice(-200);
  return res.status(200).json({ ok: true });
});

function pushAnnouncement(name, text) {
  chat.push({ id: nextChatId++, kind: 'announce', name, text });
  if (chat.length > 200) chat = chat.slice(-200);
}

// ========================================================================
// GET /api/players/search?q= (auth) — find other players by name.
//   Reachable by any logged-in player (it is a normal game feature).
// ========================================================================
app.get('/api/players/search', (req, res) => {
  const p = requireAuth(req, res);
  if (!p) return;
  const q = typeof req.query.q === 'string' ? req.query.q : '';

  // VULN(stage-3, OWASP A03): q is concatenated straight into the SQL string in
  // a single quoted-string context -> classic SQL injection. Results reflect
  // in-band (great for UNION); a broken query is signalled ONLY by HTTP 500 and
  // no DB error text leaks. The SELECT lists 4 columns, so UNION with 4.
  // FIX: parameterize — `... LIKE $q` bound to '%'+q+'%'. Input becomes data,
  //      never SQL; a lone quote is then just a character (200, no rows).
  const sql =
    "SELECT id, username, display_name, score FROM players " +
    "WHERE (username || ' ' || display_name) LIKE '%" + q + "%'";
  try {
    const out = sqlDB.exec(sql);
    const results = out.length
      ? out[0].values.map((row) => {
          const o = {};
          out[0].columns.forEach((c, i) => { o[c] = row[i]; });
          return o;
        })
      : [];
    return res.status(200).json({ results });
  } catch (e) {
    // Reflect the break ONLY through the status code — no error text.
    return res.status(500).json({ error: 'search failed' });
  }
});

// ========================================================================
// Stage-2 exfil drop box (localhost-only convenience collector).
//   GET /api/collect?c=<data>     -> store the captured value, return a 1x1 gif
//   GET /api/collect/peek         -> read back what the XSS captured
// ========================================================================
const GIF_1x1 = Buffer.from('R0lGODlhAQABAAD/ACwAAAAAAQABAAACADs=', 'base64');
app.get('/api/collect', (req, res) => {
  const c = typeof req.query.c === 'string' ? req.query.c : '';
  if (c) { collected.push(c); if (collected.length > 50) collected.shift(); console.log('[collect] captured:', c); }
  res.type('gif').send(GIF_1x1);
});
app.get('/api/collect/peek', (req, res) => {
  res.status(200).json({ captured: collected[collected.length - 1] || null, log: collected });
});

// ---- Fallback 404 (JSON, no redirects) ---------------------------------
app.use((req, res) => res.status(404).json({ error: 'not found' }));

// ========================================================================
// The GameMaster bot — the victim browser for the stored XSS (stage 2).
//
// The real GameMaster is "watching global chat". We model that browser with
// jsdom: on a timer it renders any NEW announcements through the SAME raw-name
// sink the game client uses, in a window that already holds the GameMaster's
// bearer token in localStorage. If your podium name is an XSS payload, it runs
// here with the admin session in scope and beacons the token to wherever the
// payload says. The window is shimmed so ordinary exfil primitives (new Image,
// fetch, sendBeacon, and <img onerror>/<svg onload>) all work — jsdom does not
// load images on its own. Beacons are clamped to LOCALHOST so nothing can leave
// this machine (no telephone-home); point your payload at /api/collect.
// ========================================================================
function isLocalhostUrl(u) {
  try { const h = new URL(u).hostname; return h === 'localhost' || h === '127.0.0.1' || h === '[::1]' || h === '::1'; }
  catch (e) { return false; }
}

// The announcement sink, rendered identically to the game client (see BOOT).
function announcementInnerHTML(name, text) {
  // VULN(stage-2, OWASP A03): `name` is interpolated as raw HTML with no
  // encoding. Normal chat uses esc(); announcements do not — that inconsistency
  // is the whole bug. (Mirrored in the client's renderChat.)
  return '🏆 <b>' + name + '</b> ' + text;
}

let botSeenAnnounceId = 0;
async function gameMasterBotTick() {
  const fresh = chat.filter((m) => m.kind === 'announce' && m.id > botSeenAnnounceId);
  if (!fresh.length) return;
  botSeenAnnounceId = Math.max(...fresh.map((m) => m.id));
  for (const m of fresh) {
    try { await renderAnnouncementInVictimBrowser(m); } catch (e) { /* keep the bot alive */ }
  }
}

function renderAnnouncementInVictimBrowser(m) {
  return new Promise((resolve) => {
    const vc = new VirtualConsole(); // swallow page console noise
    const dom = new JSDOM('<!doctype html><html><body><div id="chat"></div></body></html>', {
      runScripts: 'dangerously', url: `http://localhost:${PORT}/game`, virtualConsole: vc,
      beforeParse(window) {
        // This browser is already signed in as the GameMaster.
        window.localStorage.setItem('ma_token', ADMIN_TOKEN);
        // Victim-browser shims: make exfil primitives actually fire, but only
        // ever to localhost so the lab cannot reach off this machine.
        const beacon = (u) => { try { if (isLocalhostUrl(String(u))) fetch(String(u)).catch(() => {}); } catch (e) {} };
        window.fetch = (u) => { beacon(u); return Promise.resolve({ ok: true, text: () => Promise.resolve('') }); };
        if (window.navigator) window.navigator.sendBeacon = (u) => { beacon(u); return true; };
        function ShimImage() { const o = {}; Object.defineProperty(o, 'src', { set(v) { beacon(v); } }); return o; }
        window.Image = ShimImage;
      },
    });
    const w = dom.window;
    // Render the announcement through the vulnerable sink, exactly like the client.
    w.document.getElementById('chat').innerHTML = announcementInnerHTML(m.name, m.text);
    // Faithfully "attempt to load" each resource so on* handlers fire in jsdom.
    w.document.querySelectorAll('img').forEach((el) => el.dispatchEvent(new w.Event('error')));
    w.document.querySelectorAll('svg,iframe,body,video,audio').forEach((el) => el.dispatchEvent(new w.Event('load')));
    setTimeout(() => { try { w.close(); } catch (e) {} resolve(); }, 400);
  });
}

// ---- Monster spawner ---------------------------------------------------
function spawnMonster() {
  if (monsters.length >= MAX_MONSTERS) return;
  const types = ['grunt', 'brute', 'spitter'];
  // Deterministic-ish scatter without Math.random dependence at import time.
  const x = 200 + Math.floor(Math.random() * (WORLD.w - 400));
  const y = 200 + Math.floor(Math.random() * (WORLD.h - 400));
  monsters.push({
    id: nextMonsterId++, nonce: crypto.randomBytes(8).toString('hex'),
    x, y, hp: MONSTER_HP, maxHp: MONSTER_HP, type: types[nextMonsterId % types.length],
  });
}

// ---- Startup -----------------------------------------------------------
(async () => {
  sqlDB = await buildSqlDb();
  sessions.set(ADMIN_TOKEN, 1); // GameMaster (id 1) is logged in from boot

  // A few monsters so the arena is not empty on first load.
  spawnMonster(); spawnMonster();
  setInterval(spawnMonster, MONSTER_SPAWN_MS);
  setInterval(() => { gameMasterBotTick().catch(() => {}); }, 6000);

  // Some ambient chat so the channel looks alive. The seeded announcement is the
  // breadcrumb: on arrival everyone sees the server print a PLAYER'S NAME in a
  // special highlighted line — the hint that names flow into chat markup, and
  // the thing a curious student pokes at (it is the stage-2 XSS sink).
  chat.push({ id: nextChatId++, kind: 'chat', name: 'noob_slayer', text: 'where do i get the shotgun??' });
  pushAnnouncement('xX_sniper_Xx', 'smashed into the TOP 3!');
  chat.push({ id: nextChatId++, kind: 'chat', name: 'dark_knight', text: 'gg wp, how did you climb so fast lol' });

  app.listen(PORT, HOST, () => {
    console.log('==================================================');
    console.log('  MONSTER ARENA  //  deliberately vulnerable lab');
    console.log('  http://localhost:' + PORT + '      (localhost only)');
    console.log('  Classroom use only. Never deploy. Bugs are on purpose.');
    console.log('==================================================');
  });
})();

// ########################################################################
// ## Browser client (inline templates). Retro arcade styling; the four  ##
// ## bugs live in the API above — the client just drives them.          ##
// ########################################################################

// Projector-friendly palette: light backgrounds, near-black ink, strong
// saturated accents. No dark-on-dark, no pale text — reads on medium projectors.
const STYLE = `
  :root{--bg:#eef1e6;--panel:#ffffff;--ink:#14241b;--muted:#3f5a48;--accent:#15803d;--accent2:#b45309;--border:#14241b;--err:#b4231a}
  *{box-sizing:border-box}
  body{margin:0;min-height:100vh;background:var(--bg);color:var(--ink);font:16px/1.5 ui-monospace,Menlo,Consolas,monospace}
  a{color:var(--accent);text-decoration:none;font-weight:bold}
  h1,h2{font-family:"Press Start 2P",ui-monospace,monospace}
  .brand{font:18px/1 "Press Start 2P",monospace;color:var(--accent);text-transform:uppercase;letter-spacing:1px}
  .center{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}
  .panel{background:var(--panel);border:3px solid var(--border);box-shadow:6px 6px 0 var(--border);padding:26px}
  .auth{width:min(94vw,380px)}
  label{display:block;font:10px/1 "Press Start 2P",monospace;color:var(--muted);text-transform:uppercase;margin:18px 0 8px}
  input{width:100%;padding:11px 12px;font:16px ui-monospace,monospace;border:2px solid var(--border);background:#fbfcf7;color:var(--ink)}
  input:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 2px #cdebd6}
  button,.btn{margin-top:22px;display:inline-block;padding:12px 18px;font:11px/1 "Press Start 2P",monospace;text-transform:uppercase;border:2px solid var(--border);background:var(--accent);color:#fff;cursor:pointer;box-shadow:3px 3px 0 var(--border)}
  button:hover,.btn:hover{background:#0f6b31}
  .muted{color:var(--muted)} .err{color:var(--err);min-height:1.2em;margin-top:12px;font-size:14px;font-weight:bold}
  .link{margin-top:18px;font-size:13px}
`;

const HEAD =
  '<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">' +
  '<title>MONSTER ARENA</title>' +
  '<link rel="preconnect" href="https://fonts.googleapis.com">' +
  '<link href="https://fonts.googleapis.com/css2?family=Press+Start+2P&display=swap" rel="stylesheet">' +
  '<style>' + STYLE + '</style>';

// Shared client helpers. NOTE esc(): normal chat + scoreboard use it; the chat
// ANNOUNCEMENT branch deliberately does not (that is the stage-2 sink).
const BOOT = `
  function api(p,o){o=o||{};var t=localStorage.getItem('ma_token');o.headers=Object.assign({'Content-Type':'application/json'},o.headers||{});if(t){o.headers['Authorization']='Bearer '+t;}return fetch(p,o);}
  function esc(s){return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
  function logout(){localStorage.removeItem('ma_token');location.href='/login';}
`;

function doc(inner, script) {
  return '<!doctype html><html lang="en"><head>' + HEAD + '</head><body>' + inner +
    '<script>' + BOOT + (script || '') + '</script></body></html>';
}

const PAGE_LANDING = doc(
  '<div class="center"><div class="panel" style="max-width:560px;text-align:center">' +
    '<div class="brand" style="font-size:26px;margin-bottom:14px">MONSTER ARENA</div>' +
    '<p class="muted">Top-down survival. Kill monsters, bank gold &amp; EXP, climb the public leaderboard, talk trash in global chat.</p>' +
    '<a class="btn" href="/game">Play</a>' +
    '<div class="link"><a href="/login">Sign in</a> &middot; <a href="/register">Create account</a></div>' +
  '</div></div>',
  "if(localStorage.getItem('ma_token')){location.href='/game';}"
);

const PAGE_LOGIN = doc(
  '<div class="center"><div class="panel auth">' +
    '<div class="brand" style="margin-bottom:16px">SIGN IN</div>' +
    '<form id="f" autocomplete="off">' +
      '<label>Username</label><input name="username" autofocus required>' +
      '<label>Password</label><input name="password" type="password" required>' +
      '<button type="submit">Enter arena</button>' +
      '<div class="err" id="err"></div>' +
    '</form>' +
    '<div class="link muted">No account? <a href="/register">Register</a></div>' +
  '</div></div>',
  "var f=document.getElementById('f'),e=document.getElementById('err');" +
  "f.addEventListener('submit',function(ev){ev.preventDefault();e.textContent='';" +
  "fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:f.username.value.trim(),password:f.password.value})})" +
  ".then(function(r){return r.json().then(function(j){return {ok:r.ok,j:j};});})" +
  ".then(function(x){if(x.ok&&x.j.token){localStorage.setItem('ma_token',x.j.token);location.href='/game';return;}e.textContent='Incorrect username or password.';})" +
  ".catch(function(){e.textContent='Something went wrong.';});});"
);

const PAGE_REGISTER = doc(
  '<div class="center"><div class="panel auth">' +
    '<div class="brand" style="margin-bottom:16px">NEW PLAYER</div>' +
    '<form id="f" autocomplete="off">' +
      '<label>Username</label><input name="username" autofocus required>' +
      '<label>Display name</label><input name="displayName" placeholder="shown on the leaderboard">' +
      '<label>Password</label><input name="password" type="password" required>' +
      '<button type="submit">Create &amp; play</button>' +
      '<div class="err" id="err"></div>' +
    '</form>' +
    '<div class="link muted">Have an account? <a href="/login">Sign in</a></div>' +
  '</div></div>',
  "var f=document.getElementById('f'),e=document.getElementById('err');" +
  "f.addEventListener('submit',function(ev){ev.preventDefault();e.textContent='';" +
  "fetch('/api/register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:f.username.value.trim(),displayName:f.displayName.value.trim(),password:f.password.value})})" +
  ".then(function(r){return r.json().then(function(j){return {ok:r.ok,j:j};});})" +
  ".then(function(x){if(x.ok&&x.j.token){localStorage.setItem('ma_token',x.j.token);location.href='/game';return;}e.textContent=(x.j&&x.j.error)||'Could not register.';})" +
  ".catch(function(){e.textContent='Something went wrong.';});});"
);

// The game page: canvas arena on the left, HUD + leaderboard + chat on the
// right. Movement WASD, aim/shoot mouse, ESC pauses. Kills POST /api/kill.
const PAGE_GAME = '<!doctype html><html lang="en"><head>' + HEAD +
  '<style>' + GAME_CSS() + '</style></head><body>' + GAME_BODY() +
  '<script>' + BOOT + GAME_JS() + '</script></body></html>';

function GAME_CSS() {
  return `
  body{overflow:hidden;background:#dfe4d6;cursor:none}
  #wrap{display:flex;height:100vh;width:100vw}
  #arena{flex:1;position:relative;background:#4e7d3c;overflow:hidden}
  canvas{display:block;width:100%;height:100%}
  #side{width:304px;min-width:304px;background:#f4f1e8;color:var(--ink);border-left:3px solid var(--border);display:flex;flex-direction:column;overflow:hidden}
  .box{border-bottom:2px solid var(--border);padding:12px 14px}
  .t{font:9px/1 "Press Start 2P",monospace;color:var(--accent);text-transform:uppercase;margin-bottom:10px;letter-spacing:1px}
  .chips{display:flex;gap:6px;flex-wrap:wrap}
  .chip{background:#fff;border:2px solid var(--border);padding:5px 8px;font-size:12px;border-radius:4px;color:var(--ink)}
  .chip b{color:var(--accent2)}
  ol{margin:0;padding-left:20px;list-style:none;counter-reset:rk}
  ol li{counter-increment:rk;font-size:13px;margin:4px 0;display:flex;justify-content:space-between;gap:8px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;color:var(--ink)}
  ol li::before{content:counter(rk);color:var(--muted);margin-right:7px;font-weight:bold}
  ol li.me{color:var(--accent);font-weight:bold} ol li .sc{color:var(--accent2);font-weight:bold}
  #chatlog{flex:1;overflow:auto;padding:10px 14px;font-size:14px;line-height:1.5;background:#fff}
  #chatlog .msg{margin:3px 0;word-break:break-word;color:var(--ink)} #chatlog .msg b{color:#1d4ed8}
  #chatlog .ann{margin:7px 0;color:#b4231a;font-weight:bold;word-break:break-word}
  #chatform{display:flex;border-top:2px solid var(--border)}
  #chatform input{border:none;border-radius:0;background:#fff;color:var(--ink)}
  #chatform button{margin:0;border-radius:0;box-shadow:none;border:none;padding:10px 12px;font-size:9px}
  .overlay{position:absolute;inset:0;display:none;align-items:center;justify-content:center;flex-direction:column;z-index:8;text-align:center}
  #pause{background:rgba(238,241,230,.92);color:var(--ink)} #pause .brand{font-size:26px;margin-bottom:10px}
  #dead{background:rgba(120,20,20,.55)} #dead .brand{font-size:40px;color:#fff;text-shadow:3px 3px 0 #7a0000}
  .pill{position:absolute;bottom:12px;left:50%;transform:translateX(-50%);background:#f4f1e8;border:2px solid var(--border);padding:7px 12px;font-size:12px;color:var(--ink);border-radius:20px;z-index:6;pointer-events:none;font-weight:bold}
  #toast{position:absolute;top:16px;left:50%;transform:translateX(-50%);z-index:7;font:12px/1.4 "Press Start 2P",monospace;color:#fff;background:var(--accent2);border:2px solid var(--border);padding:8px 12px;opacity:0;transition:opacity .3s;pointer-events:none;text-align:center}
  a.btn.sm{margin:0;padding:7px 10px;font-size:9px}
  `;
}

function GAME_BODY() {
  return '<div id="wrap">' +
    '<div id="arena">' +
      '<canvas id="c"></canvas>' +
      '<div id="toast"></div>' +
      '<div class="pill">WASD move &middot; MOUSE aim &middot; CLICK/HOLD shoot &middot; R reload &middot; 1&ndash;3 weapons &middot; ESC pause</div>' +
      '<div id="pause" class="overlay"><div class="brand">PAUSED</div><div class="muted">press ESC to resume</div></div>' +
      '<div id="dead" class="overlay"><div class="brand">WASTED</div><div class="muted">respawning&hellip;</div></div>' +
    '</div>' +
    '<div id="side">' +
      '<div class="box"><div class="t">Pilot</div>' +
        '<div class="chips"><span class="chip" id="who">@&mdash;</span>' +
        '<span class="chip">LV <b id="lvl">1</b></span>' +
        '<span class="chip">SCORE <b id="score">0</b></span>' +
        '<span class="chip">GOLD <b id="gold">0</b></span></div>' +
        '<div style="display:flex;gap:8px;align-items:center;margin-top:10px">' +
          '<span class="chip" style="flex:1">CARRYING <b id="carry">0</b></span>' +
          '<a href="#" id="bankbtn" class="btn sm" style="background:var(--accent2);color:#2a1e00">Bank [E]</a>' +
        '</div>' +
      '</div>' +
      '<div class="box"><div class="t">Leaderboard</div><ol id="board"></ol></div>' +
      '<div class="box" style="flex:1;display:flex;flex-direction:column;padding:0;min-height:0">' +
        '<div class="t" style="padding:12px 14px 2px">Global chat</div>' +
        '<div id="chatlog"></div>' +
        '<form id="chatform" autocomplete="off"><input id="chatin" placeholder="say something..." maxlength="300"><button type="submit">Send</button></form>' +
      '</div>' +
      '<div class="box" style="text-align:center;padding:10px"><a href="#" id="out" class="btn sm" style="background:#20303f;color:#9fb4c4">Sign out</a></div>' +
    '</div>' +
  '</div>';
}

function GAME_JS() {
  // Compact but juicy canvas client. SECURITY-RELEVANT, unchanged in contract:
  //  - claimKill() -> POST /api/kill   (stage-1 replay bug lives server-side)
  //  - renderChat() announcement branch injects m.name as RAW HTML (stage-2 sink)
  //  - renderBoard() escapes names (safe counter-example)
  // Everything else is game feel: procedural art, particles, audio, HUD.
  return `
  if(!localStorage.getItem('ma_token')){location.href='/login';}
  var $=function(i){return document.getElementById(i);};
  $('out').onclick=function(e){e.preventDefault();logout();};
  $('bankbtn').onclick=function(e){e.preventDefault();bank();};
  function updateCarry(){ var el=$('carry'); if(el) el.textContent=carrying(); }
  setInterval(updateCarry,600);

  // ---------- SECURITY-RELEVANT RENDERERS ----------
  function renderChat(msgs){
    var el=$('chatlog'); if(!el) return;
    el.innerHTML=msgs.map(function(m){
      if(m.kind==='announce'){
        // VULN(stage-2): announcement NAME injected as raw HTML (no esc()).
        return '<div class="ann">\\uD83C\\uDFC6 <b>'+m.name+'</b> '+esc(m.text)+'</div>';
      }
      return '<div class="msg"><b>'+esc(m.name)+'</b>: '+esc(m.text)+'</div>'; // escaped: safe
    }).join('');
    el.scrollTop=el.scrollHeight;
  }
  function renderBoard(board){
    $('board').innerHTML=board.map(function(r){
      var mine=(r.name===me.display)?' class="me"':'';
      return '<li'+mine+'><span>'+esc(r.name)+'</span><span class="sc">'+r.score+'</span></li>'; // escaped: safe
    }).join('');
  }

  // ---------- audio (synth, no assets) ----------
  var AC=null; function audio(){ if(!AC){ try{ AC=new (window.AudioContext||window.webkitAudioContext)(); }catch(e){} } return AC; }
  function sfx(type){ var c=audio(); if(!c) return; var t=c.currentTime; var o=c.createOscillator(),g=c.createGain(); o.connect(g); g.connect(c.destination);
    var cfg={shoot:[220,90,'square',0.05],shot:[140,70,'sawtooth',0.05],hit:[320,70,'square',0.04],death:[90,260,'sawtooth',0.09],hurt:[150,200,'triangle',0.09],pickup:[660,140,'sine',0.08],level:[520,300,'triangle',0.1],reload:[300,120,'square',0.05],dry:[120,60,'square',0.04]}[type]||[300,80,'square',0.05];
    o.type=cfg[2]; o.frequency.setValueAtTime(cfg[0],t); o.frequency.exponentialRampToValueAtTime(Math.max(40,cfg[0]*0.4),t+cfg[1]/1000);
    g.gain.setValueAtTime(cfg[3],t); g.gain.exponentialRampToValueAtTime(0.0001,t+cfg[1]/1000); o.start(t); o.stop(t+cfg[1]/1000+0.02);
  }

  // ---------- world + props (generated once) ----------
  var WORLD={w:2200,h:2000};
  function rnd(a,b){return a+Math.random()*(b-a);}
  var props=[]; (function(){
    for(var i=0;i<46;i++) props.push({k:'tree',x:rnd(60,WORLD.w-60),y:rnd(60,WORLD.h-60),r:rnd(26,44)});
    for(var j=0;j<40;j++) props.push({k:'rock',x:rnd(40,WORLD.w-40),y:rnd(40,WORLD.h-40),r:rnd(9,18)});
    for(var b=0;b<26;b++) props.push({k:'bush',x:rnd(40,WORLD.w-40),y:rnd(40,WORLD.h-40),r:rnd(12,20)});
    for(var c=0;c<16;c++) props.push({k:'crate',x:rnd(60,WORLD.w-60),y:rnd(60,WORLD.h-60),r:16});
    props.push({k:'car',x:WORLD.w*0.3,y:WORLD.h*0.28,r:60});
  })();
  // grass tufts + dirt patches as cheap texture
  var tufts=[]; for(var g=0;g<900;g++){ tufts.push({x:rnd(0,WORLD.w),y:rnd(0,WORLD.h),s:rnd(2,5),d:Math.random()<0.12}); }

  // ---------- state ----------
  var cv=$('c'),ctx=cv.getContext('2d');
  var W=0,H=0; function resize(){W=cv.width=cv.clientWidth;H=cv.height=cv.clientHeight;} window.addEventListener('resize',resize); resize();
  var me={x:WORLD.w/2,y:WORLD.h/2,hp:100,maxHp:100,armor:50,maxArmor:100,angle:0,level:1,score:0,gold:0,username:'',display:'',dead:false,deadT:0,flash:0};
  var WEAPONS=[
    {name:'RIFLE',  mag:30, reserve0:60, rate:95,  spread:0.06, pellets:1, spd:14, recoil:5,  col:'#ffd23f'},
    {name:'PISTOL', mag:12, reserve0:48, rate:240, spread:0.03, pellets:1, spd:12, recoil:3,  col:'#9fe8ff'},
    {name:'SHOTGUN',mag:6,  reserve0:18, rate:650, spread:0.30, pellets:8, spd:12, recoil:14, col:'#ff8a3f'}
  ];
  // ---- per-weapon ammo lives in localStorage ('ma_ammo') and is READ every use,
  // so it is tamperable: set reserve/mag huge in DevTools for infinite ammo. Ammo
  // boxes add spare rounds. (Client-side only cheat — same "trust the client"
  // theme as the loot backpack.) ----
  function ammoDefaults(){ var d={}; WEAPONS.forEach(function(w){ d[w.name]={mag:w.mag,reserve:w.reserve0}; }); return d; }
  function loadAmmo(){ try{ var a=JSON.parse(localStorage.getItem('ma_ammo')); if(!a||typeof a!=='object') return ammoDefaults();
    WEAPONS.forEach(function(w){ var s=a[w.name]; if(!s||typeof s.mag!=='number'||typeof s.reserve!=='number') a[w.name]={mag:w.mag,reserve:w.reserve0}; }); return a;
  }catch(e){ return ammoDefaults(); } }
  function saveAmmo(a){ localStorage.setItem('ma_ammo',JSON.stringify(a)); }
  var wi=0, reloading=0, lastShot=0, muzzle=0;
  var keys={},mouse={x:0,y:0,down:false},bullets=[],mons=[],parts=[],floats=[],casings=[],pickups=[],feed=[];
  var shake=0, lastPickup=0, lastHurt=0, prevScore=0;

  function toast(t){ var el=$('toast'); el.textContent=t; el.style.opacity='1'; clearTimeout(el._t); el._t=setTimeout(function(){el.style.opacity='0';},1600); }

  // ---------- input ----------
  window.addEventListener('keydown',function(e){ audio();
    var k=e.key.toLowerCase();
    if(e.key==='Escape'){ if(me.dead) return; paused=!paused; $('pause').style.display=paused?'flex':'none'; return; }
    if(k==='r'){ reload(); }
    if(k==='e'){ bank(); }
    if(k==='1'){ switchW(0);} if(k==='2'){ switchW(1);} if(k==='3'){ switchW(2);}
    keys[k]=true;
  });
  window.addEventListener('keyup',function(e){ keys[e.key.toLowerCase()]=false; });
  cv.addEventListener('mousemove',function(e){ var r=cv.getBoundingClientRect(); mouse.x=e.clientX-r.left; mouse.y=e.clientY-r.top; });
  cv.addEventListener('mousedown',function(){ audio(); mouse.down=true; }); window.addEventListener('mouseup',function(){ mouse.down=false; });
  var paused=false;

  function switchW(n){ if(n===wi||reloading) return; wi=n; muzzle=0; toast(WEAPONS[n].name); }
  function reload(){ var w=WEAPONS[wi], a=loadAmmo(), st=a[w.name];
    if(reloading||st.mag>=w.mag||st.reserve<=0){ if(st.reserve<=0&&st.mag<=0) toast('NO AMMO — find a box'); return; }
    reloading=Date.now(); sfx('reload');
    setTimeout(function(){ var a2=loadAmmo(), s2=a2[w.name]; var take=Math.min(w.mag-s2.mag,s2.reserve); s2.mag+=take; s2.reserve-=take; saveAmmo(a2); reloading=0; },700); }

  // ---------- combat ----------
  function shoot(){
    var w=WEAPONS[wi], now=Date.now();
    if(reloading||now-lastShot<w.rate) return;
    var a=loadAmmo(), st=a[w.name];
    if(st.mag<=0){ if(now-lastShot>300){ sfx('dry'); lastShot=now; if(st.reserve>0) reload(); } return; }
    lastShot=now; st.mag--; saveAmmo(a); muzzle=6; shake=Math.max(shake,w.recoil*0.4);
    var base=me.angle;
    for(var p=0;p<w.pellets;p++){
      var a=base+(Math.random()-0.5)*w.spread*2;
      bullets.push({x:me.x+Math.cos(base)*22,y:me.y+Math.sin(base)*22,dx:Math.cos(a)*w.spd,dy:Math.sin(a)*w.spd,life:60,col:w.col});
    }
    // eject casing
    casings.push({x:me.x,y:me.y,dx:Math.cos(base-1.4)*rnd(1,2.5),dy:Math.sin(base-1.4)*rnd(1,2.5),life:40,rot:rnd(0,6)});
    sfx(w.pellets>1?'shot':'shoot');
  }
  function claimKill(m){
    // THE REPLAYABLE REQUEST (stage-1). Honest client sends it once per kill;
    // the server credits every call. Students resend it in devtools/Burp/ffuf.
    api('/api/kill',{method:'POST',body:JSON.stringify({id:m.id,nonce:m.nonce})})
      .then(function(r){return r.json();}).then(function(d){ if(!d) return;
        me.score=d.score; me.gold=d.gold;
        if(d.level>me.level){ sfx('level'); toast('LEVEL UP  '+d.level); }
        me.level=d.level; syncHud();
        if(d.flag){ toast('\\uD83C\\uDFC6 '+d.flag); }
      });
  }
  function hurt(dmg){
    if(me.dead) return; var now=Date.now(); if(now-lastHurt<380) return; lastHurt=now;
    var a=Math.min(me.armor,dmg); me.armor-=a; me.hp-=(dmg-a); me.flash=1; shake=Math.max(shake,7); sfx('hurt');
    if(me.hp<=0){ me.hp=0; die(); }
  }
  function die(){ me.dead=true; me.deadT=Date.now(); $('dead').style.display='flex';
    for(var i=0;i<40;i++) parts.push({x:me.x,y:me.y,dx:rnd(-4,4),dy:rnd(-4,4),life:rnd(20,45),col:'#ff3030',r:rnd(2,5)});
    setTimeout(function(){ me.dead=false; me.hp=me.maxHp; me.armor=Math.min(me.armor+30,me.maxArmor); me.x=WORLD.w/2; me.y=WORLD.h/2;
      mons=mons.filter(function(m){return Math.hypot(m.x-me.x,m.y-me.y)>320;}); $('dead').style.display='none'; },1600);
  }
  function killMonster(m){
    m.dead=true; sfx('death'); shake=Math.max(shake,4);
    for(var i=0;i<14;i++) parts.push({x:m.x,y:m.y,dx:rnd(-3.5,3.5),dy:rnd(-3.5,3.5),life:rnd(16,34),col:Math.random()<0.5?'#8b1a1a':'#c0392b',r:rnd(2,5)});
    floats.push({x:m.x,y:m.y,t:'+'+25,life:44,col:'#ffd23f'});
    feed.unshift({t:m.type.toUpperCase()+' down',life:150}); if(feed.length>5) feed.pop();
    claimKill(m);
  }

  // ---------- pickups ----------
  var nextPickupId=1;
  function spawnPickup(){
    var types=[{k:'med',col:'#ff4a4a'},{k:'armor',col:'#43d675'},{k:'ammo',col:'#ffd23f'},{k:'gold',col:'#ffcf3f'}];
    var t=types[Math.floor(Math.random()*types.length)];
    var ang=rnd(0,6.28),dist=rnd(220,520);
    pickups.push({id:nextPickupId++,k:t.k,col:t.col,x:Math.max(40,Math.min(WORLD.w-40,me.x+Math.cos(ang)*dist)),y:Math.max(40,Math.min(WORLD.h-40,me.y+Math.sin(ang)*dist)),bob:rnd(0,6)});
    if(pickups.length>8) pickups.shift();
  }
  // ---- loot backpack: stored CLIENT-SIDE in localStorage (tamperable!) ----
  function loadBag(){ try{ var b=JSON.parse(localStorage.getItem('ma_backpack')); return (b&&typeof b.gold==='number')?b:{gold:0}; }catch(e){ return {gold:0}; } }
  function saveBag(b){ localStorage.setItem('ma_backpack',JSON.stringify(b)); }
  function carrying(){ return loadBag().gold; }
  function grab(p){
    sfx('pickup');
    if(p.k==='med'){ me.hp=Math.min(me.maxHp,me.hp+40); floats.push({x:p.x,y:p.y,t:'+40 HP',life:40,col:'#ff6b6b'}); }
    else if(p.k==='armor'){ me.armor=Math.min(me.maxArmor,me.armor+40); floats.push({x:p.x,y:p.y,t:'+40 ARMOR',life:40,col:'#43d675'}); }
    else if(p.k==='ammo'){ var w=WEAPONS[wi], a=loadAmmo(); a[w.name].reserve+=w.mag*2; saveAmmo(a); floats.push({x:p.x,y:p.y,t:'+'+(w.mag*2)+' AMMO',life:40,col:'#ffd23f'}); }
    else { // gold coin -> stash loot in the browser's OWN backpack (no server call)
      var bag=loadBag(); bag.gold+=15; saveBag(bag); floats.push({x:p.x,y:p.y,t:'+15 LOOT',life:40,col:'#ffcf3f'}); }
  }
  function bank(){
    var bag=loadBag();
    // BANK THE BACKPACK. The server trusts whatever gold the client reports
    // (stage-1 client-trust bug) — tamper localStorage, or replay this request.
    if(bag.gold<=0){ toast('nothing to bank'); return; }
    api('/api/cashout',{method:'POST',body:JSON.stringify({gold:bag.gold})})
      .then(function(r){return r.json();}).then(function(d){ if(!d||d.error){ toast('nothing to bank'); return; }
        me.score=d.score; me.gold=d.gold;
        if(d.level>me.level){ sfx('level'); toast('LEVEL UP  '+d.level); }
        me.level=d.level; syncHud();
        toast('BANKED $'+d.banked);
        if(d.flag){ toast('\\uD83C\\uDFC6 '+d.flag); }
        saveBag({gold:0});
      });
  }

  // ---------- server sync ----------
  function syncHud(){ $('lvl').textContent=me.level; $('score').textContent=me.score; $('gold').textContent=me.gold; }
  function pullMe(){ api('/api/me').then(function(r){ if(r.status===401){logout();return;} return r.json(); }).then(function(d){ if(!d) return;
    me.username=d.username; me.display=d.displayName; me.level=d.level; me.score=d.score; me.gold=d.gold;
    $('who').textContent='@'+d.username; syncHud();
  }); }
  function pullMonsters(){ api('/api/monsters').then(function(r){return r.json();}).then(function(d){ if(!d||!d.monsters) return;
    var have={}; mons.forEach(function(m){have[m.id]=m;});
    mons=d.monsters.map(function(s){ var ex=have[s.id]; if(ex) return ex;
      return {id:s.id,nonce:s.nonce,x:s.x,y:s.y,hp:s.hp,maxHp:s.maxHp,type:s.type,ph:Math.random()*6,atk:0}; });
  }); }
  function pullBoard(){ fetch('/api/scoreboard').then(function(r){return r.json();}).then(function(d){ if(d&&d.board) renderBoard(d.board); }); }
  function pullChat(){ api('/api/chat').then(function(r){return r.json();}).then(function(d){ if(d&&d.messages) renderChat(d.messages); }); }

  $('chatform').addEventListener('submit',function(e){ e.preventDefault(); var i=$('chatin'); if(!i.value.trim()) return;
    api('/api/chat',{method:'POST',body:JSON.stringify({text:i.value})}).then(function(){ i.value=''; pullChat(); }); });

  // ---------- update ----------
  function update(){
    if(paused||me.dead) return;
    me.angle=Math.atan2(mouse.y-H/2,mouse.x-W/2);
    var sp=3.3;
    if(keys['w'])me.y-=sp; if(keys['s'])me.y+=sp; if(keys['a'])me.x-=sp; if(keys['d'])me.x+=sp;
    me.x=Math.max(18,Math.min(WORLD.w-18,me.x)); me.y=Math.max(18,Math.min(WORLD.h-18,me.y));
    if(mouse.down) shoot();
    if(me.flash>0) me.flash-=0.06;
    if(muzzle>0) muzzle--;
    if(shake>0) shake*=0.86;

    bullets.forEach(function(b){ b.x+=b.dx; b.y+=b.dy; b.life--; });
    bullets=bullets.filter(function(b){ return b.life>0; });
    casings.forEach(function(c){ c.x+=c.dx; c.y+=c.dy; c.dx*=0.9; c.dy*=0.9; c.life--; });
    casings=casings.filter(function(c){return c.life>0;});
    parts.forEach(function(p){ p.x+=p.dx; p.y+=p.dy; p.dx*=0.92; p.dy*=0.92; p.life--; });
    parts=parts.filter(function(p){return p.life>0;});
    floats.forEach(function(f){ f.y-=0.6; f.life--; });
    floats=floats.filter(function(f){return f.life>0;});

    mons.forEach(function(m){ var a=Math.atan2(me.y-m.y,me.x-m.x); var spd=m.type==='brute'?0.7:(m.type==='spitter'?1.0:1.2);
      m.x+=Math.cos(a)*spd; m.y+=Math.sin(a)*spd; m.ph+=0.15;
      if(Math.hypot(me.x-m.x,me.y-m.y)<32){ hurt(m.type==='brute'?16:9); }
    });
    // bullet vs monster
    bullets.forEach(function(b){ for(var i=0;i<mons.length;i++){ var m=mons[i]; if(m.hp>0&&Math.hypot(b.x-m.x,b.y-m.y)<(m.type==='brute'?28:22)){
      m.hp--; b.life=0; sfx('hit'); parts.push({x:b.x,y:b.y,dx:rnd(-1.5,1.5),dy:rnd(-1.5,1.5),life:10,col:'#ffce54',r:2}); break; } } });
    mons.filter(function(m){return m.hp<=0&&!m.dead;}).forEach(killMonster);
    mons=mons.filter(function(m){return !m.dead;});

    // pickups
    var now=Date.now(); if(now-lastPickup>5500){ lastPickup=now; spawnPickup(); }
    pickups.forEach(function(p){ p.bob+=0.08; if(Math.hypot(me.x-p.x,me.y-p.y)<26){ p.got=true; grab(p);} });
    pickups=pickups.filter(function(p){return !p.got;});

    feed.forEach(function(f){f.life--;}); feed=feed.filter(function(f){return f.life>0;});
  }

  // ---------- draw helpers ----------
  function shadow(sx,sy,r){ ctx.fillStyle='rgba(0,0,0,0.28)'; ctx.beginPath(); ctx.ellipse(sx,sy+r*0.5,r*0.9,r*0.4,0,0,6.3); ctx.fill(); }
  function drawTree(sx,sy,r){ shadow(sx,sy,r); ctx.fillStyle='#5a3a21'; ctx.fillRect(sx-4,sy-2,8,10);
    ctx.fillStyle='#1f5d2a'; ctx.beginPath(); ctx.arc(sx,sy-r*0.5,r,0,6.3); ctx.fill();
    ctx.fillStyle='#2b7a37'; ctx.beginPath(); ctx.arc(sx-r*0.35,sy-r*0.7,r*0.6,0,6.3); ctx.fill();
    ctx.fillStyle='#39913f'; ctx.beginPath(); ctx.arc(sx+r*0.3,sy-r*0.4,r*0.5,0,6.3); ctx.fill(); }
  function drawRock(sx,sy,r){ shadow(sx,sy,r); ctx.fillStyle='#6b7280'; ctx.beginPath(); ctx.arc(sx,sy,r,0,6.3); ctx.fill(); ctx.fillStyle='#8b93a0'; ctx.beginPath(); ctx.arc(sx-r*0.3,sy-r*0.3,r*0.5,0,6.3); ctx.fill(); }
  function drawBush(sx,sy,r){ shadow(sx,sy,r*0.8); ctx.fillStyle='#24712f'; ctx.beginPath(); ctx.arc(sx-r*0.4,sy,r*0.6,0,6.3); ctx.arc(sx+r*0.4,sy,r*0.6,0,6.3); ctx.arc(sx,sy-r*0.3,r*0.7,0,6.3); ctx.fill(); }
  function drawCrate(sx,sy,r){ shadow(sx,sy,r); ctx.fillStyle='#8a5a2b'; ctx.fillRect(sx-r,sy-r,r*2,r*2); ctx.strokeStyle='#5f3d1c'; ctx.lineWidth=3; ctx.strokeRect(sx-r,sy-r,r*2,r*2); ctx.beginPath(); ctx.moveTo(sx-r,sy-r); ctx.lineTo(sx+r,sy+r); ctx.moveTo(sx+r,sy-r); ctx.lineTo(sx-r,sy+r); ctx.stroke(); }
  function drawCar(sx,sy){ shadow(sx,sy,60); ctx.save(); ctx.translate(sx,sy); ctx.rotate(0.5);
    ctx.fillStyle='#3a4a2a'; ctx.fillRect(-34,-60,68,120); ctx.fillStyle='#2a3620'; ctx.fillRect(-28,-44,56,34); ctx.fillRect(-28,8,56,36);
    ctx.fillStyle='#161d12'; ctx.fillRect(-30,-62,60,8); ctx.fillRect(-30,54,60,8); ctx.restore(); }

  function drawMonster(m,camx,camy){ var sx=m.x-camx,sy=m.y-camy; var wob=Math.sin(m.ph)*2;
    var R=m.type==='brute'?22:(m.type==='spitter'?15:17);
    // high-contrast, non-green so they pop on the grass (projector-safe)
    var col=m.type==='brute'?'#c01818':(m.type==='spitter'?'#1f5fd0':'#9a1fb0');
    shadow(sx,sy,R);
    ctx.fillStyle=col; ctx.beginPath(); ctx.arc(sx,sy+wob,R,0,6.3); ctx.fill();
    ctx.lineWidth=3; ctx.strokeStyle='#120a1a'; ctx.stroke();
    ctx.fillStyle='rgba(0,0,0,0.22)'; ctx.beginPath(); ctx.arc(sx,sy+wob+R*0.3,R*0.7,0,3.14); ctx.fill();
    // eyes toward player
    var a=Math.atan2(me.y-m.y,me.x-m.x);
    ctx.fillStyle='#ffe34d'; ctx.beginPath(); ctx.arc(sx+Math.cos(a)*5-3,sy+wob-3,2.5,0,6.3); ctx.arc(sx+Math.cos(a)*5+3,sy+wob-3,2.5,0,6.3); ctx.fill();
    // hp bar
    var bw=R*2; ctx.fillStyle='#000'; ctx.fillRect(sx-bw/2,sy-R-10,bw,4);
    ctx.fillStyle=m.hp/m.maxHp>0.5?'#43d675':(m.hp/m.maxHp>0.25?'#ffd23f':'#ff4a4a'); ctx.fillRect(sx-bw/2,sy-R-10,bw*(m.hp/m.maxHp),4);
  }
  function drawPlayer(){ ctx.save(); ctx.translate(W/2,H/2);
    shadow(0,0,16);
    ctx.rotate(me.angle);
    // legs/body (dark outline so it reads on bright grass)
    ctx.fillStyle='#123a5e'; ctx.fillRect(-12,-12,24,24);
    ctx.lineWidth=2; ctx.strokeStyle='#07131f'; ctx.strokeRect(-12,-12,24,24);
    ctx.fillStyle='#2e7fc4'; ctx.beginPath(); ctx.arc(0,0,11,0,6.3); ctx.fill(); ctx.stroke();
    // gun
    ctx.fillStyle='#0d141c'; ctx.fillRect(8,-3,20,6);
    if(muzzle>0){ ctx.fillStyle='rgba(255,210,80,'+(muzzle/6)+')'; ctx.beginPath(); ctx.arc(30,0,8+muzzle,0,6.3); ctx.fill();
      ctx.fillStyle='#fff'; ctx.beginPath(); ctx.arc(30,0,4,0,6.3); ctx.fill(); }
    ctx.restore();
  }

  // ---------- render ----------
  function draw(){
    var camx=me.x-W/2+(Math.random()-0.5)*shake, camy=me.y-H/2+(Math.random()-0.5)*shake;
    // ground (brighter grass reads better on a projector)
    ctx.fillStyle='#5a8f44'; ctx.fillRect(0,0,W,H);
    // tufts (only visible)
    for(var i=0;i<tufts.length;i++){ var t=tufts[i]; var sx=t.x-camx,sy=t.y-camy; if(sx<-10||sy<-10||sx>W+10||sy>H+10) continue;
      ctx.fillStyle=t.d?'#7a6338':(i%2?'#4e8038':'#689b4e'); ctx.fillRect(sx,sy,t.s,t.s); }
    // world border
    ctx.strokeStyle='#243f16'; ctx.lineWidth=10; ctx.strokeRect(-camx,-camy,WORLD.w,WORLD.h);
    // props sorted by y for depth
    var vis=props.filter(function(p){var sx=p.x-camx,sy=p.y-camy;return sx>-80&&sy>-120&&sx<W+80&&sy<H+80;}).sort(function(a,b){return a.y-b.y;});
    vis.forEach(function(p){ var sx=p.x-camx,sy=p.y-camy;
      if(p.k==='tree')drawTree(sx,sy,p.r); else if(p.k==='rock')drawRock(sx,sy,p.r); else if(p.k==='bush')drawBush(sx,sy,p.r); else if(p.k==='crate')drawCrate(sx,sy,p.r); else if(p.k==='car')drawCar(sx,sy); });
    // pickups
    pickups.forEach(function(p){ var sx=p.x-camx,sy=p.y-camy+Math.sin(p.bob)*3; shadow(sx,sy+8,10);
      ctx.fillStyle='#0b1118'; ctx.fillRect(sx-11,sy-11,22,22); ctx.strokeStyle=p.col; ctx.lineWidth=2; ctx.strokeRect(sx-11,sy-11,22,22);
      ctx.fillStyle=p.col; if(p.k==='med'){ ctx.fillRect(sx-2,sy-7,4,14); ctx.fillRect(sx-7,sy-2,14,4); } else if(p.k==='armor'){ ctx.beginPath(); ctx.moveTo(sx,sy-8); ctx.lineTo(sx+7,sy-4); ctx.lineTo(sx+5,sy+8); ctx.lineTo(sx-5,sy+8); ctx.lineTo(sx-7,sy-4); ctx.closePath(); ctx.fill(); } else if(p.k==='gold'){ ctx.beginPath(); ctx.arc(sx,sy,7,0,6.3); ctx.fill(); ctx.fillStyle='#8a5e13'; ctx.font='bold 10px ui-monospace,monospace'; ctx.textAlign='center'; ctx.fillText('$',sx,sy+4); ctx.textAlign='left'; } else { ctx.fillRect(sx-7,sy-4,14,9); } });
    // casings + particles
    casings.forEach(function(c){ var sx=c.x-camx,sy=c.y-camy; ctx.fillStyle='rgba(200,170,60,'+(c.life/40)+')'; ctx.fillRect(sx,sy,3,2); });
    parts.forEach(function(p){ var sx=p.x-camx,sy=p.y-camy; ctx.globalAlpha=Math.max(0,p.life/34); ctx.fillStyle=p.col; ctx.fillRect(sx-p.r/2,sy-p.r/2,p.r,p.r); ctx.globalAlpha=1; });
    // monsters
    mons.forEach(function(m){ drawMonster(m,camx,camy); });
    // bullets (tracers)
    bullets.forEach(function(b){ var sx=b.x-camx,sy=b.y-camy; ctx.strokeStyle=b.col; ctx.lineWidth=2; ctx.beginPath(); ctx.moveTo(sx,sy); ctx.lineTo(sx-b.dx*1.2,sy-b.dy*1.2); ctx.stroke(); });
    // floats
    floats.forEach(function(f){ var sx=f.x-camx,sy=f.y-camy; ctx.globalAlpha=Math.max(0,f.life/44); ctx.font='bold 15px ui-monospace,monospace'; ctx.textAlign='center'; ctx.lineWidth=4; ctx.lineJoin='round'; ctx.strokeStyle='#0a140a'; ctx.strokeText(f.t,sx,sy); ctx.fillStyle=f.col; ctx.fillText(f.t,sx,sy); ctx.globalAlpha=1; ctx.textAlign='left'; });
    // player
    drawPlayer();
    // atmosphere: soft spotlight + hurt flash + low-hp vignette
    var grd=ctx.createRadialGradient(W/2,H/2,120,W/2,H/2,Math.max(W,H)*0.7);
    grd.addColorStop(0,'rgba(0,0,0,0)'); grd.addColorStop(1,'rgba(0,0,0,0.28)'); ctx.fillStyle=grd; ctx.fillRect(0,0,W,H);
    if(me.flash>0){ ctx.fillStyle='rgba(255,0,0,'+(me.flash*0.4)+')'; ctx.fillRect(0,0,W,H); }
    if(me.hp<30&&!me.dead){ var v=ctx.createRadialGradient(W/2,H/2,H*0.3,W/2,H/2,H*0.7); v.addColorStop(0,'rgba(0,0,0,0)'); v.addColorStop(1,'rgba(180,0,0,0.35)'); ctx.fillStyle=v; ctx.fillRect(0,0,W,H); }
    drawHUD();
    drawCrosshair();
  }

  function bar(x,y,w,h,pct,col){ ctx.fillStyle='#1a241c'; ctx.fillRect(x,y,w,h); ctx.fillStyle=col; ctx.fillRect(x,y,w*Math.max(0,Math.min(1,pct)),h); ctx.strokeStyle='#0a140a'; ctx.lineWidth=2; ctx.strokeRect(x,y,w,h); }
  // outlined text: dark stroke + bright fill, reads on any projector
  function otext(txt,x,y){ ctx.lineWidth=4; ctx.lineJoin='round'; ctx.strokeStyle='#0a140a'; ctx.strokeText(txt,x,y); ctx.fillText(txt,x,y); }
  function panel(x,y,w,h){ ctx.fillStyle='rgba(10,20,14,0.72)'; ctx.fillRect(x,y,w,h); ctx.strokeStyle='#0a140a'; ctx.lineWidth=2; ctx.strokeRect(x,y,w,h); }
  function drawHUD(){
    // health + armor bottom-left (on a dark backing)
    panel(10,H-74,250,66);
    ctx.textAlign='left'; ctx.font='9px "Press Start 2P",monospace';
    ctx.fillStyle='#ff8a8a'; otext('HP',20,H-50); bar(48,H-60,200,14,me.hp/me.maxHp,'#e23b3b');
    ctx.fillStyle='#8af0ad'; otext('AR',20,H-26); bar(48,H-36,200,14,me.armor/me.maxArmor,'#2ea85a');
    // weapon + ammo bottom-right (on a dark backing)
    panel(W-210,H-122,200,114);
    var w=WEAPONS[wi], st=loadAmmo()[w.name];
    ctx.textAlign='right'; ctx.font='9px "Press Start 2P",monospace';
    for(var i=0;i<WEAPONS.length;i++){ ctx.fillStyle=i===wi?'#8af0ad':'#c7d2bd'; otext((i+1)+' '+WEAPONS[i].name,W-20,H-98+i*16); }
    ctx.fillStyle=st.mag===0?'#ff7a7a':'#ffd23f'; ctx.font='20px "Press Start 2P",monospace';
    otext(reloading?'RELOAD':(st.mag+' / '+st.reserve),W-20,H-22);
    ctx.textAlign='left';
    // carrying loot (center-bottom)
    var carry=carrying();
    if(carry>0){ ctx.textAlign='center'; ctx.font='12px "Press Start 2P",monospace';
      var cw=('CARRYING $'+carry+'   [E] BANK').length*9+20; panel(W/2-cw/2,H-40,cw,26);
      ctx.fillStyle='#ffd23f'; otext('CARRYING $'+carry+'   [E] BANK',W/2,H-22); ctx.textAlign='left'; }
    // kill feed top-left
    ctx.font='bold 12px ui-monospace,monospace';
    for(var f=0;f<feed.length;f++){ ctx.globalAlpha=Math.min(1,feed[f].life/40); ctx.fillStyle='#ffd0b0'; otext('\\u2620 '+feed[f].t,16,26+f*18); ctx.globalAlpha=1; }
    // minimap top-right
    var mw=150,mh=136,mx=W-mw-16,my=16; ctx.fillStyle='rgba(10,20,14,0.82)'; ctx.fillRect(mx,my,mw,mh); ctx.strokeStyle='#0a140a'; ctx.lineWidth=2; ctx.strokeRect(mx,my,mw,mh);
    var sxk=mw/WORLD.w, syk=mh/WORLD.h;
    mons.forEach(function(m){ ctx.fillStyle='#ff4a4a'; ctx.fillRect(mx+m.x*sxk-1,my+m.y*syk-1,4,4); });
    pickups.forEach(function(p){ ctx.fillStyle=p.col; ctx.fillRect(mx+p.x*sxk-1,my+p.y*syk-1,3,3); });
    ctx.fillStyle='#7df0a3'; ctx.fillRect(mx+me.x*sxk-2,my+me.y*syk-2,5,5);
  }
  function drawCrosshair(){ if(paused||me.dead) return; ctx.strokeStyle='#0a140a'; ctx.lineWidth=3;
    var m=mouse; ctx.beginPath(); ctx.arc(m.x,m.y,9,0,6.3); ctx.moveTo(m.x-14,m.y); ctx.lineTo(m.x-4,m.y); ctx.moveTo(m.x+4,m.y); ctx.lineTo(m.x+14,m.y); ctx.moveTo(m.x,m.y-14); ctx.lineTo(m.x,m.y-4); ctx.moveTo(m.x,m.y+4); ctx.lineTo(m.x,m.y+14); ctx.stroke(); }

  function loop(){ update(); draw(); requestAnimationFrame(loop); }

  pullMe(); pullMonsters(); pullBoard(); pullChat();
  setInterval(pullMe,4000); setInterval(pullMonsters,3000); setInterval(pullBoard,3000); setInterval(pullChat,2500);
  requestAnimationFrame(loop);
  `;
}
