<div align="center">

# 🛰️ Find My Steam Deck

### Find your Steam Deck. Nobody else can.

A **zero-knowledge** find-my-device & recovery system for the Steam Deck — a [Decky Loader](https://decky.xyz) plugin, an identity-plane server, and a full-screen owner dashboard.
The server stores only ciphertext it can never read. Location and control belong to you and your password alone.

[![zero-knowledge](https://img.shields.io/badge/design-zero--knowledge-38bdf8)](#how-the-two-planes-fit)
[![crypto](https://img.shields.io/badge/crypto-Argon2id%20%2B%20X25519%20%2B%20Ed25519-8b5cf6)](#how-the-two-planes-fit)
[![platform](https://img.shields.io/badge/platform-Steam%20Deck%20%2F%20Decky-1a9fff)](https://decky.xyz)
[![server](https://img.shields.io/badge/server-Node%20%2B%20Postgres-34d399)](#running-it)
[![tests](https://img.shields.io/badge/tests-interop%20%C2%B7%20server%20%C2%B7%20e2e%20%C2%B7%20device-f0b429)](#property-checklist--all-verified-by-tests)

**[Live →](https://findmydeck.0xbanana.com)**

</div>

---

<div align="center">

![Landing page](docs/media/landing.png)

</div>

## What it does

Your Deck quietly seals encrypted Wi-Fi location reports and uploads them. When it goes missing you open the dashboard, decrypt the reports **in your own browser**, and watch it on a live map. Ring it to find it under the couch, or flip it to **Lost** — a full-screen banner takes over the Deck with your message and an anonymous two-way chat so whoever has it can reach you without ever seeing who you are.

The twist: **the server is blind.** A full breach of it yields opaque blobs, upload timestamps, source IPs, and `HMAC(pepper, steamid)` — never a location, never the ability to flip a Deck into tracking mode.

<table>
<tr>
<td width="50%" valign="top">

### 🗺️ Locate on a map
Sealed Wi-Fi scans decrypt **only in your browser**, then plot a live trail with accuracy, battery, and timestamps. The server never sees where your Deck is.

</td>
<td width="50%" valign="top">

### 📢 Ring & recover
Play a loud siren to find it nearby (Android-style), or flip it to **Lost** for a full-screen takeover and a private, PII-free chat with whoever has it.

</td>
</tr>
<tr>
<td width="50%" valign="top">

### 🔒 Only you hold the key
Your password derives the keys that decrypt reports and sign commands — on-device, then wiped. A full server breach still can't read or track a thing.

</td>
<td width="50%" valign="top">

### 🔋 Practically free on battery
Event-driven checks (wake, game exit, QAM open, network connect) plus a lazy hourly heartbeat. Passive scans, no GPS, no busy-wait. Under ~1%/day in normal use.

</td>
</tr>
</table>

## Screenshots

<div align="center">

**Owner dashboard — decrypted report history plotted on a full-screen dark map**

Each point is a report the Deck sent (per wake / scan / upload), decrypted in your browser and geolocated — snapshots, not continuous GPS. A stationary Deck stacks on one dot; the trail appears when it actually moved.

![Dashboard](docs/media/demo-dashboard.png)

**On the Deck when marked Lost — full-screen takeover + anonymous chat**

![Lost screen](docs/media/demo-lost.png)

</div>

There's also a SteamID-gated operator page at `/admin` — sealed-safe operational counts only (installs, active devices, reports stored), never location or personal data.

## How the two planes fit

The whole design is a split: **identity** answers *who are you and may you ask*, **crypto** answers *is this secret and did the owner really command it* — and the two never share a secret.

```mermaid
flowchart LR
    subgraph Deck["🎮 Steam Deck (Decky plugin)"]
        S[Passive Wi-Fi scan] --> SEAL[Seal to box_pk<br/>X25519]
        CMD[Verify command sig<br/>Ed25519 + counter]
    end
    subgraph Server["☁️ Server — SEES ONLY CIPHERTEXT"]
        DB[(Postgres<br/>blobs · HMAC ids · pubkeys)]
    end
    subgraph Owner["🧑 Owner browser / dashboard"]
        PW[password] --> KDF[Argon2id 256 MiB] --> K[box + sign keypairs]
        OPEN[Open sealed reports] --> MAP[Live map]
        SIGN[Sign mode command]
    end
    SEAL -->|POST sealed blob| DB
    DB -->|relays byte-exact| OPEN
    SIGN -->|payload + sig| DB
    DB -->|relays byte-exact| CMD
    Steam[Steam OpenID 2.0] -.authorizes session.-> Server
```

- **Identity plane (server).** Steam OpenID 2.0, validated server-side (`check_authentication`). Sessions are HMAC-signed httpOnly cookies. Every device-scoped route passes `requireDeviceOwner`; uploads use per-device bearer tokens, revocable in isolation. The DB stores `HMAC(pepper, steamid64)`, never a raw SteamID.
- **Crypto plane (client).** password → Argon2id (256 MiB, versioned params) → X25519 box keypair (reports sealed to `box_pk`) + Ed25519 sign keypair (commands). The device keeps only **public** keys, its id, and its token. A command applies only if the signature verifies against the enrolled `sign_pk` **and** a monotonic counter strictly advances — checked on-device **and** server-side. The server relays `{payload, sig}` byte-exact and can never originate a mode change.

The same crypto core runs three ways and is proven wire-compatible by tests: TypeScript (`libsodium-wrappers-sumo`) in the browser and QAM, Python via `ctypes`→`libsodium` on the Deck, and PyNaCl on the test side.

## Enrollment (the consent gate)

1. Sign in to the dashboard through Steam → **Enroll a new Deck** → a 5-minute, single-use, 6-character pair code.
2. On the Deck: Decky → **Find My Deck** → enter the pair code and choose a recovery password.
3. The QAM frontend derives the keypairs **on-device**, sends **public keys only**, wipes the password and secret keys, and stores `device_id` + `device_token`.

Enrolling a Deck needs both physical possession of it **and** your authenticated dashboard session — you can only set up a Deck you actually hold and control.

## Modes

| mode | what shows on the Deck | reporting |
|---|---|---|
| **`normal`** | nothing | passive Wi-Fi scan on wake / network-connect, ~hourly |
| **`lost`** | full-screen takeover: owner's message, anonymous contact code, "connect me to Wi-Fi" nudge, two-way chat | ~5 min |
| **Play sound** | loud siren until dismissed (works in any mode) | — |

Failed uploads park the already-sealed blob in a disk outbox and drain oldest-first on the next network touch. Marking the Deck recovered (`→ normal`) clears the relay chat automatically.

## Alerts (metadata-only)

Point a webhook (Discord / Slack / ntfy / any https sink) at your account and get pinged when it matters (email delivery is wired but off until a mail-provider key is set):

- **A finder messaged you** through the recovery relay.
- **Your Lost Deck checked in** — the first report after you mark it Lost ("it's alive, location updated").
- **Your Lost Deck went quiet** — no check-in for 3h while Lost (maybe off or out of range).

These fire on **server-visible metadata only** — a message arrived, a report arrived, a `last_seen` gap. The server still can't read your battery or location (both sealed), so there is deliberately **no** "alert when it leaves home" geofence — that would require reading a location the server never holds. Normal-mode suspend is never alerted (Decks sleep constantly; that would be noise). Webhook targets are https-only with a loopback/private-range SSRF guard.

## Running it

```bash
npm install                     # server + dashboard deps
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt

# Postgres: per-app role + db (schema auto-creates on boot)
createdb findmydeck && createuser fmsd_app        # plus pg_hba entries

npm run build:dashboard
# env (a systemd EnvironmentFile in production):
#   DATABASE_URL=postgres://fmsd_app:...@127.0.0.1:5432/findmydeck
#   FMSD_BASE_URL=https://findmydeck.0xbanana.com
#   FMSD_PEPPER=<hex32>          # HMAC pepper — rotating it orphans accounts
#   FMSD_SESSION_SECRET=<hex32>  # cookie signing — rotating it logs everyone out
npm start

# plugin: cd plugin && npm install && npm run build && bash build.sh
# then install out/findmydeck-plugin.zip via Decky → "install from zip"

FMSD_TEST_DATABASE_URL=postgres://fmsd_app:...@127.0.0.1:5432/findmydeck_test \
  FMSD_PYTHON=.venv/bin/python npm test    # interop + server + e2e + plugin units
```

`FMSD_DEV_FAKE_STEAM=1` enables `/auth/dev-login?steamid=<id64>` for local testing only — never set it in production.

### Repository layout

```
crypto/ts/crypto.mjs        canonical client crypto (browser + QAM + tests)
crypto/py/fmsd_crypto.py     wire-compatible Python side (PyNaCl, tooling + tests)
server/                      identity-plane API (Express), Postgres, Steam OpenID
plugin/                      Decky plugin — main.py backend + React QAM frontend
  py_modules/fmsd_crypto.py    device crypto via ctypes→libsodium (no PyNaCl on Deck)
dashboard/                   owner SPA: Steam login, sign commands, decrypt + map
tests/                       interop (TS↔Py), server HTTP, plugin units, full e2e
```

## Honest limitations (said out loud)

- **The password is unrecoverable by design.** It is the decryption key and the signing key. Lose it → re-enroll from scratch; old reports stay sealed forever. The UI says this at enrollment and at every unlock.
- **Source IPs** are the one location signal that can't be sealed away. They're logged only for per-device rate limiting and rotated fast — disclosed here, not hidden.
- **No reports while suspended or off.** They arrive in bursts on wake/charge. Design expectation, not a bug.
- **A SteamOS reimage wipes Decky** and the plugin with it. This shines for the lost-couch / airbnb / left-in-the-car case and the pre-wipe window — not against a wipe-first thief.
- **Geolocation** resolves in the owner's browser (Wi-Fi → coordinates); single-AP environments may not resolve.

## Property checklist — all verified by tests

- Server never receives password / seed / secret keys — enrollment sends pubkeys only (`tests/e2e.test.mjs`)
- Server cannot decrypt reports — sealed-box round-trip proven both directions (`tests/interop.test.mjs`)
- Server cannot forge mode changes — garbage sig rejected at `PUT`; device re-verifies independently (`tests/server.test.mjs`, `tests/test_plugin.py`)
- `openid.claimed_id` validated server-side; a client-supplied SteamID is trusted nowhere (`server/steam.js`)
- DB stores `HMAC(pepper, steamid)` only (`server/app.js`)
- Cross-account access → `403` on every device route (`tests/server.test.mjs`)
- Two-gate set-mode: the session authorizes the request, the signature authorizes the command (`tests/e2e.test.mjs`)
- Replay blocked by a monotonic counter, server-side (`409`) and on-device (`tests/test_plugin.py`)

---

<div align="center">

Architecture cribbed with thanks from [FMD (FindMyDevice)](https://gitlab.com/Nulide/findmydevice) · GPLv3-compatible spirit.

Built for the Deck. 🎮

</div>
