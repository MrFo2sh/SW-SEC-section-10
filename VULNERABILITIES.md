# MONSTER ARENA — vulnerability register

> ⚠️ This app is **deliberately insecure** and exists only to be attacked in a
> classroom on localhost. Every bug below is planted on purpose, labelled in the
> source with a `VULN(stage-N, OWASP)` comment and a matching `FIX:`. **Never
> deploy.**

The four stages chain into one story:

```
  STAGE 1  replay the kill request  ──▶  vault onto the public podium
                                         └▶ your name fires in global chat …
  STAGE 2  … and your name is an XSS  ──▶ the GameMaster's browser runs it
                                         └▶ steal the admin session token
  STAGE 3  (any player) inject the search ──▶ dump the players table
  STAGE 4  the dump is unsalted MD5   ──▶ rockyou cracks it → log in as them
```

Two independent entry points (Stage 1→2 and Stage 3→4); a student can start on
either side.

---

## Register

| # | Stage | OWASP | File:line | The bug | Trigger | Real fix |
|---|-------|-------|-----------|---------|---------|----------|
| 1 | 1 | A04 Insecure Design (replay) | `POST /api/kill` ~`server.js:205` | The kill is credited on **every** call — no check that the monster exists, is alive, belongs to you, or that the one-time `nonce` was already spent. | Resend the same kill request (devtools / Burp Repeater / ffuf) hundreds of times to vault onto the podium. | Server-authoritative, idempotent kills: one-time nonce per spawned monster, verified unspent **and** monster alive, atomically consumed; a replay earns nothing (409). |
| 1c | 1 | A04 Insecure Design (client-trust) | `POST /api/cashout` ~`server.js:244` | Collectables are tallied **in the browser** (`localStorage['ma_backpack']`); this route banks whatever gold total the client reports, with no server-side truth to check it against. | DevTools → Local Storage → set `ma_backpack` to `{"gold":999999}` → press **E** to bank → instant #1. (The request is also replayable.) | Never trust client-held state: keep the loot tally server-side, credit only server-issued one-time collectable ids, ignore any client-supplied total. |
| 2 | 2 | A03 Injection (XSS) | `server.js:344` + client `server.js:596` | The top-3 chat **announcement** interpolates the player's `displayName` into HTML with **no output encoding**. Normal chat text *is* escaped — only the announcement is not. | Set your display name to an XSS payload (`PATCH /api/account`), then replay onto the podium. The GameMaster bot renders it and runs it. | Context-aware **output encoding** at the sink — escape HTML when rendering the name, exactly like the normal-chat branch already does. (Storing raw is fine; encoding on output is the fix.) |
| 2b | 2 | A05 / A07 | `server.js:175` | Session token is held in `localStorage` (`ma_token`) — readable by any script, so XSS → full account takeover. | Payload reads `localStorage.getItem('ma_token')` and beacons it out. | Keep session tokens in `HttpOnly` cookies so script cannot read them; add CSP to blunt injection. |
| 3 | 3 | A03 Injection (SQLi) | `server.js:281` | `GET /api/players/search?q=` concatenates `q` straight into a SQL string in a single quoted-string context. Results reflect in-band; a broken query signals only via HTTP 500 (no DB error text). | `q=zzz' UNION SELECT id,username,password_md5,role FROM players-- ` (4 columns). sqlmap works directly. | **Parameterize**: `... LIKE $q` bound to `'%'+q+'%'`. Input becomes data, never SQL. |
| 4 | 4 | A02 Cryptographic Failures | `db.js:13` + auth at `server.js:140` | Passwords are stored as **unsalted MD5** — a fast, broken-for-passwords hash. The dump hands over `password_md5` directly. | Feed the dumped hashes to `john --format=raw-md5 --wordlist=rockyou.txt`; the weak ones fall in seconds. Log in with the recovered password. | Slow, salted KDF (bcrypt / argon2 / scrypt) with a per-user salt and a real work factor. |
| 1b | 1 | A07 Auth failures | `server.js:109`, `server.js:136` | Username **enumeration** (register → 409 "taken"; login → 404 unknown vs 401 wrong password) and **no rate limit / lockout** on login. | ffuf the username (match 401/409) to map accounts, then ffuf the password (match 200). | One generic 401 for both failure cases; per-account throttling and lockout; no distinguishable "exists" signal to an anonymous caller. |

---

## The deliberate counter-examples (NOT bugs — teaching contrast)

These exist so students see that the *same* data can be handled safely:

- **Normal global chat** (`server.js` chat POST + client `renderChat` `msg` branch) escapes user text with `esc()` → no XSS. Only the *announcement* branch is unsafe. The lesson: a sanitiser you apply in one place but forget in another is worse than none.
- **Scoreboard** (`renderBoard`) escapes names → the same hostile display name that pops in the announcement is inert here.
- **Client-side ammo** lives in `localStorage['ma_ammo']` and *is* trivially tamperable — but the server never sees it, so editing it only buys you infinite ammo locally. Contrast with the loot **backpack** (`ma_backpack`): identical client storage, but because `/api/cashout` *trusts* it, tampering there is a real exploit. The lesson: tampering client state only matters where a server trusts that state — authority, not storage, is the line.

---

## Why cracking the GameMaster is *not* the intended path (Stage 2 vs 4)

`GameMaster` (id 1) uses a long random password (`Zx9#Qv!m2_Lp7`) that is **not**
in any wordlist — its MD5 is in the dump but will not crack. That is deliberate:
Stage 4 teaches that *weak* passwords fall to a fast hash, while Stage 2 teaches
that you did not need the admin's password at all — stealing its **session** with
XSS skips authentication entirely. Strong passwords do not save a system that
leaks its sessions.
