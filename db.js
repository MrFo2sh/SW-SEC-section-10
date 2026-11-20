// db.js — seed data for the MONSTER ARENA shooter lab.
//
// TEACHING LAB NOTE: passwords are stored as UNSALTED MD5 on purpose. MD5 is a
// fast, broken-for-passwords hash; unsalted + fast = rockyou falls in seconds.
// A real app MUST use a slow, salted KDF (bcrypt/argon2/scrypt). Do not copy this.
//
// Localhost-only university software-security lab. Everything here is vulnerable
// by design. Nothing is safe to deploy.

const crypto = require('crypto');
const initSqlJs = require('sql.js');

// VULN(stage-4, OWASP A02): the app's one and only password hash is unsalted
// MD5 — fast and broken for passwords. The SQLite `players.password_md5` column
// (and the live auth check in server.js) use this, so a dump feeds straight
// into john/hashcat + rockyou.
// FIX: use a slow, salted password hash (bcrypt/argon2/scrypt) with a per-user
//      salt and a sensible work factor; never MD5/SHA-1/SHA-256 for passwords.
function md5(s) {
  return crypto.createHash('md5').update(s).digest('hex');
}

// ---- Flags (proof-of-success constants) --------------------------------
const FLAGS = {
  F1: 'FLAG{replay_kill_highscore}',    // replay the kill request to inflate score
  F2: 'FLAG{stored_xss_admin_token}',   // steal the GameMaster's session via stored XSS
  F3: 'FLAG{sqli_player_search_dump}',  // SQL injection in the player search
  F4: 'FLAG{md5_rockyou_cracked}',      // crack a dumped MD5 hash and log in
};

// ---- Player roster -----------------------------------------------------
// id 1 is the GameMaster (admin). Its password is long + random and is NOT on
// any wordlist: you are NOT meant to crack it. You steal its session with XSS.
// Everyone else uses a weak rockyou password -> their MD5 cracks instantly.
//
// `stash` is a player's private locker, returned only by GET /api/me for that
// player. One stash holds F4 — you reach it by cracking that player's hash and
// logging in as them.
function seedPlayers() {
  return [
    { id: 1, username: 'GameMaster',   password: 'Zx9#Qv!m2_Lp7', role: 'admin', score: 999999, level: 99,
      displayName: 'GameMaster', email: 'gm@monsterarena.local',
      stash: 'balance patch notes: nerf the plasma rifle before the tournament' },

    // The top-3 cutoff is deliberately high: a monster spawns once every 30s and
    // takes many hits, so legit play cannot reach ~3000 in a class. The ONLY way
    // onto the public podium (which fires the vulnerable announcement) is to
    // replay the kill request. These two seed the #2 / #3 wall you must beat.
    { id: 2, username: 'xX_sniper_Xx',  password: 'iloveyou',  role: 'player', score: 5200, level: 24,
      displayName: 'xX_sniper_Xx', email: 'sniper@monsterarena.local',
      stash: 'note to self: stop feeding the boss' },

    { id: 3, username: 'noob_slayer',   password: 'princess',  role: 'player', score: 3100, level: 17,
      displayName: 'noob_slayer', email: 'noob@monsterarena.local',
      stash: 'where do i find the shotgun' },

    { id: 4, username: 'dark_knight',   password: 'password1', role: 'player', score: 0, level: 1,
      displayName: 'dark_knight', email: 'dk@monsterarena.local',
      stash: 'the medkit respawns near the rocks' },

    // This is the account that holds F4. Weak password -> crackable from the dump.
    { id: 5, username: 'pro_gamer_99',  password: 'qwerty',    role: 'player', score: 0, level: 1,
      displayName: 'pro_gamer_99', email: 'pro@monsterarena.local',
      stash: FLAGS.F4 },

    { id: 6, username: 'mike_the_tank', password: 'monkey',    role: 'player', score: 0, level: 1,
      displayName: 'mike_the_tank', email: 'mike@monsterarena.local',
      stash: 'remember to buy more ammo' },

    { id: 7, username: 'lara_croft',    password: 'dragon',    role: 'player', score: 0, level: 1,
      displayName: 'lara_croft', email: 'lara@monsterarena.local',
      stash: 'the camo car is just scenery, stop shooting it' },

    { id: 8, username: 'ghost_recon',   password: 'football',  role: 'player', score: 0, level: 1,
      displayName: 'ghost_recon', email: 'ghost@monsterarena.local',
      stash: 'afk brb' },
  ];
}

// ---- SQLite database (backs the player search; the SQLi target) --------
// Built once at startup with sql.js (in-memory SQLite). The `players` table
// carries the MD5 password hashes (the dump payoff). A `secrets` table carries
// F3 and a fake platform key. Mirrors the live roster above.
async function buildSqlDb() {
  const SQL = await initSqlJs();
  const db = new SQL.Database();
  db.run(
    'CREATE TABLE players (id INTEGER PRIMARY KEY, username TEXT, display_name TEXT, ' +
    'score INTEGER, email TEXT, role TEXT, password_md5 TEXT);' +
    'CREATE TABLE secrets (id INTEGER PRIMARY KEY, label TEXT, value TEXT);'
  );
  const insP = db.prepare('INSERT INTO players VALUES (?,?,?,?,?,?,?)');
  for (const p of seedPlayers()) {
    insP.run([p.id, p.username, p.displayName, p.score, p.email, p.role, md5(p.password)]);
  }
  insP.free();
  const insS = db.prepare('INSERT INTO secrets VALUES (?,?,?)');
  insS.run([1, 'platform_signing_key', 'gm_live_sk_7c4f1a9e2b8d60']);
  insS.run([2, 'flag', FLAGS.F3]);
  insS.free();
  return db;
}

module.exports = { FLAGS, md5, seedPlayers, buildSqlDb };
