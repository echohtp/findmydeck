// Postgres storage — spec §2.3. The server stores only ciphertext
// (reports.blob), public keys, and HMAC'd identity. No plaintext location,
// no raw SteamID beside blobs, no key material.
//
// House pattern (same as jackpot/efta on this host): per-app role + db,
// DATABASE_URL like postgres://fmsd_app:...@127.0.0.1:40870/findmydeck

import pg from 'pg';

// BIGINT (int8) arrives as string by default; our bigints are epoch-ms and
// row counters, all < 2^53, so plain Numbers are safe and keep JSON sane.
pg.types.setTypeParser(20, Number);

const SCHEMA = `
  CREATE TABLE IF NOT EXISTS accounts (
    account_key    TEXT PRIMARY KEY,
    created_at     BIGINT NOT NULL,
    notify_webhook TEXT,              -- owner alert sink (Discord/Slack/ntfy/custom)
    notify_email   TEXT               -- owner alert email (needs an email provider key)
  );
  CREATE TABLE IF NOT EXISTS devices (
    device_id   TEXT PRIMARY KEY,
    account_key TEXT NOT NULL REFERENCES accounts(account_key),
    name        TEXT NOT NULL,
    box_pk      TEXT NOT NULL,
    sign_pk     TEXT NOT NULL,
    salt        TEXT NOT NULL,
    kdf         TEXT NOT NULL,        -- JSON, versioned (§1.1)
    token_hash  TEXT,                 -- sha256(device_token); NULL = revoked
    counter     BIGINT NOT NULL DEFAULT 0,
    mode        TEXT NOT NULL DEFAULT 'normal',
    ring_counter BIGINT NOT NULL DEFAULT 0,   -- owner-triggered "play sound"
    last_seen   BIGINT,
    -- Alert bookkeeping (metadata only — never location/battery):
    lost_checkin_notified BOOLEAN NOT NULL DEFAULT false,  -- fired "it checked in"
    lost_quiet_notified   BOOLEAN NOT NULL DEFAULT false,  -- fired "gone quiet"
    created_at  BIGINT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS reports (
    id          BIGSERIAL PRIMARY KEY,
    device_id   TEXT NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
    blob        TEXT NOT NULL,        -- opaque sealed box, base64
    received_at BIGINT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS commands (
    device_id   TEXT PRIMARY KEY REFERENCES devices(device_id) ON DELETE CASCADE,
    payload     TEXT NOT NULL,        -- exact signed string; relayed verbatim
    sig         TEXT NOT NULL,
    counter     BIGINT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS pair_codes (
    code        TEXT PRIMARY KEY,
    account_key TEXT NOT NULL REFERENCES accounts(account_key),
    expires_at  BIGINT NOT NULL
  );
  -- Recovery relay (spec §4). A finder who types the lost-mode contact code
  -- can leave a message; the owner reads/replies in the dashboard. Keyed by
  -- the code only — no owner PII is stored anywhere (server holds just the
  -- HMAC'd SteamID). Both sides stay anonymous.
  CREATE TABLE IF NOT EXISTS relay_threads (
    contact     TEXT PRIMARY KEY,
    device_id   TEXT NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
    created_at  BIGINT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS relay_messages (
    id          BIGSERIAL PRIMARY KEY,
    contact     TEXT NOT NULL REFERENCES relay_threads(contact) ON DELETE CASCADE,
    sender      TEXT NOT NULL,        -- 'finder' | 'owner'
    body        TEXT NOT NULL,
    created_at  BIGINT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_reports_device ON reports(device_id, received_at);
  CREATE INDEX IF NOT EXISTS idx_devices_token ON devices(token_hash);
  CREATE INDEX IF NOT EXISTS idx_relay_msgs ON relay_messages(contact, id);
  -- Migrations for existing databases (no-ops on a fresh one):
  ALTER TABLE devices ADD COLUMN IF NOT EXISTS ring_counter BIGINT NOT NULL DEFAULT 0;
  ALTER TABLE devices ADD COLUMN IF NOT EXISTS lost_checkin_notified BOOLEAN NOT NULL DEFAULT false;
  ALTER TABLE devices ADD COLUMN IF NOT EXISTS lost_quiet_notified BOOLEAN NOT NULL DEFAULT false;
  ALTER TABLE accounts ADD COLUMN IF NOT EXISTS notify_webhook TEXT;
  ALTER TABLE accounts ADD COLUMN IF NOT EXISTS notify_email TEXT;
  -- Collapse the old covert 'stolen' mode into 'lost'.
  UPDATE devices SET mode = 'lost' WHERE mode = 'stolen';
`;

export async function openDb(connectionString = process.env.DATABASE_URL) {
  if (!connectionString) throw new Error('DATABASE_URL not set');
  const pool = new pg.Pool({ connectionString, max: 10 });
  await pool.query(SCHEMA);
  return pool;
}
