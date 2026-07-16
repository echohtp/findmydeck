// Find My Steam Deck — identity-plane server (spec §2).
// Everything here is the Identity plane: it authorizes WHO may act.
// It never sees a password, seed, or secret key, cannot decrypt any
// report, and cannot originate a mode change (commands must carry a
// signature verifiable against the enrolled sign_pk).

import crypto from 'node:crypto';
import express from 'express';
import { makeRelyingParty, authUrl, verifyReturn } from './steam.js';
import { appleLocate } from './apple_geo.js';
import { verifyCommand } from '../crypto/ts/crypto.mjs';

const MODES = new Set(['normal', 'lost']);
const PAIR_TTL_MS = 5 * 60 * 1000;
const SESSION_TTL_MS = 7 * 24 * 3600 * 1000;
const MAX_BLOB_BYTES = 64 * 1024;
// Retention: sealed reports are kept 7 days — enough to review recent
// movement, bounded so the DB (all ciphertext) never grows without limit.
const REPORT_RETENTION_MS = 7 * 24 * 3600 * 1000;

/** Delete sealed reports older than maxAgeMs. Exposed for scheduling + tests. */
export function pruneOldReports(db, maxAgeMs = REPORT_RETENTION_MS) {
  return db.query('DELETE FROM reports WHERE received_at < $1', [Date.now() - maxAgeMs]);
}

const now = () => Date.now();
const sha256hex = (s) => crypto.createHash('sha256').update(s).digest('hex');
const hmacHex = (key, msg) => crypto.createHmac('sha256', key).update(msg).digest('hex');

// --- tiny signed-cookie session (value.exp.hmac) --------------------------
function sessionCookie(secret, accountKey) {
  const exp = now() + SESSION_TTL_MS;
  const body = `${accountKey}.${exp}`;
  return `${body}.${hmacHex(secret, body)}`;
}

function readSession(secret, cookieHeader) {
  const m = /(?:^|;\s*)fmsd_session=([^;]+)/.exec(cookieHeader || '');
  if (!m) return null;
  const parts = decodeURIComponent(m[1]).split('.');
  if (parts.length !== 3) return null;
  const [accountKey, exp, mac] = parts;
  const body = `${accountKey}.${exp}`;
  const expect = hmacHex(secret, body);
  if (mac.length !== expect.length) return null;
  if (!crypto.timingSafeEqual(Buffer.from(mac), Buffer.from(expect))) return null;
  if (Number(exp) < now()) return null;
  return accountKey;
}

// --- per-device upload rate limit (spec §2.7): 30 reports / 10 min --------
function makeRateLimiter(max = 30, windowMs = 10 * 60 * 1000) {
  const hits = new Map();
  return (id) => {
    const t = now();
    const arr = (hits.get(id) || []).filter((x) => t - x < windowMs);
    if (arr.length >= max) return false;
    arr.push(t);
    hits.set(id, arr);
    return true;
  };
}

/** @param {{db: import('pg').Pool}} opts — db comes from openDb() (Postgres). */
export function createApp({
  db,
  baseUrl = 'http://localhost:8451',
  pepper = process.env.FMSD_PEPPER,
  sessionSecret = process.env.FMSD_SESSION_SECRET,
  devFakeSteam = process.env.FMSD_DEV_FAKE_STEAM === '1',
} = {}) {
  if (!db) throw new Error('createApp requires a db pool (openDb)');
  if (!pepper) {
    pepper = crypto.randomBytes(32).toString('hex');
    console.warn('FMSD_PEPPER not set — using ephemeral pepper; account keys will not survive restart');
  }
  if (!sessionSecret) {
    sessionSecret = crypto.randomBytes(32).toString('hex');
    console.warn('FMSD_SESSION_SECRET not set — sessions will not survive restart');
  }

  const app = express();
  app.set('trust proxy', 'loopback'); // behind nginx: honor X-Forwarded-* from localhost only
  app.use(express.json({ limit: '128kb' }));
  const rp = makeRelyingParty(baseUrl);
  const allowReport = makeRateLimiter();
  // 6-digit pair codes are a 10^6 space: single-use + 5 min TTL + this
  // per-IP attempt limit keep online guessing out of reach.
  const allowEnroll = makeRateLimiter(10, 10 * 60 * 1000);

  const q = (text, params) => db.query(text, params).then((r) => r.rows);
  const one = async (text, params) => (await q(text, params))[0];

  // Enforce report retention: sweep on boot, then every 6h. unref() so the
  // timer never keeps the process (or a test runner) alive.
  const sweepReports = () => pruneOldReports(db).catch(() => {});
  sweepReports();
  setInterval(sweepReports, 6 * 3600 * 1000).unref?.();

  const accountKey = (steamid64) => hmacHex(pepper, steamid64); // §2.3 — raw SteamID never stored
  // Admin is gated by the account_key of a fixed SteamID (still no raw
  // SteamID stored — we just derive the same HMAC to compare against).
  const adminSteamId = process.env.FMSD_ADMIN_STEAMID || '76561198035568909';
  const adminKey = accountKey(adminSteamId);

  const ensureAccount = (key) =>
    q('INSERT INTO accounts (account_key, created_at) VALUES ($1, $2) ON CONFLICT DO NOTHING', [key, now()]);

  // --- owner notifications (metadata only — never location or battery) -----
  // Alerts fire on server-visible metadata: a finder message arrived, a Lost
  // Deck checked in, a Lost Deck went quiet. Nothing sealed is ever read.
  const emailEnabled = () => !!process.env.FMSD_RESEND_KEY;

  // Basic SSRF guard: https only, no loopback/link-local/private literals.
  function safeWebhook(url) {
    if (!/^https:\/\//i.test(url)) return false;
    let host;
    try { host = new URL(url).hostname.toLowerCase(); } catch { return false; }
    if (host === 'localhost' || host.endsWith('.local') || host === '::1') return false;
    if (/^(127\.|10\.|192\.168\.|169\.254\.|0\.)/.test(host)) return false;
    if (/^172\.(1[6-9]|2\d|3[01])\./.test(host)) return false;
    if (/^(fe80|fc|fd)/.test(host)) return false;
    return true;
  }

  async function sendWebhook(url, payload) {
    if (!safeWebhook(url)) return;
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 5000);
    try {
      const line = `${payload.title}\n${payload.text}`;
      await fetch(url, {
        method: 'POST', signal: ctrl.signal,
        headers: { 'content-type': 'application/json' },
        // content = Discord, text = Slack, plus structured fields for custom sinks.
        body: JSON.stringify({ content: line, text: line, ...payload }),
      });
    } catch { /* fire-and-forget */ } finally { clearTimeout(t); }
  }

  async function sendEmail(to, subject, text) {
    if (!emailEnabled()) return;
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 8000);
    try {
      await fetch('https://api.resend.com/emails', {
        method: 'POST', signal: ctrl.signal,
        headers: { authorization: `Bearer ${process.env.FMSD_RESEND_KEY}`, 'content-type': 'application/json' },
        body: JSON.stringify({
          from: process.env.FMSD_MAIL_FROM || 'Find My Deck <noreply@findmydeck.0xbanana.com>',
          to, subject, text,
        }),
      });
    } catch { /* fire-and-forget */ } finally { clearTimeout(t); }
  }

  // Deliver to whatever sinks the account configured. Async + swallows errors:
  // must never delay or fail the request that triggered it.
  async function notify(key, msg) {
    try {
      const a = await one('SELECT notify_webhook, notify_email FROM accounts WHERE account_key = $1', [key]);
      if (!a) return;
      const payload = { event: msg.event, title: msg.title, text: msg.text, device: msg.device || '', ts: now() };
      if (a.notify_webhook) await sendWebhook(a.notify_webhook, payload);
      if (a.notify_email) await sendEmail(a.notify_email, msg.title, msg.text);
    } catch { /* never throw into the caller */ }
  }

  async function notifyDeviceOwner(deviceId, msg) {
    const d = await one('SELECT name, account_key FROM devices WHERE device_id = $1', [deviceId]);
    if (d) notify(d.account_key, { ...msg, device: d.name });
  }

  // Lost-quiet sweep: a Deck you marked Lost that stops checking in for a
  // while may be off or out of range — alert once. Normal-mode suspend is
  // never alerted (Decks sleep constantly; that would be pure noise).
  const LOST_QUIET_MS = 3 * 3600 * 1000;
  const sweepLostQuiet = async () => {
    try {
      const stale = await q(
        `UPDATE devices SET lost_quiet_notified = true
           WHERE mode = 'lost' AND lost_quiet_notified = false
             AND last_seen IS NOT NULL AND last_seen < $1
         RETURNING name, account_key`, [now() - LOST_QUIET_MS]);
      for (const d of stale) {
        notify(d.account_key, {
          event: 'lost_quiet',
          title: `⚠️ "${d.name}" has gone quiet`,
          text: `Your lost Deck "${d.name}" hasn't checked in for over 3 hours — it may be powered off or out of Wi-Fi range.`,
          device: d.name,
        });
      }
    } catch { /* ignore */ }
  };
  setInterval(sweepLostQuiet, 15 * 60 * 1000).unref?.();

  function setSession(res, key) {
    const secure = baseUrl.startsWith('https') ? '; Secure' : '';
    res.setHeader('Set-Cookie',
      `fmsd_session=${encodeURIComponent(sessionCookie(sessionSecret, key))}; HttpOnly; SameSite=Lax; Path=/${secure}; Max-Age=${SESSION_TTL_MS / 1000}`);
  }

  // --- auth middleware (spec §2.5 — the entire horizontal-authz story) ----
  function requireSession(req, res, next) {
    const key = readSession(sessionSecret, req.headers.cookie);
    if (!key) return res.status(401).json({ error: 'not logged in' });
    req.accountKey = key;
    next();
  }

  async function requireDeviceOwner(req, res, next) {
    const device = await one('SELECT * FROM devices WHERE device_id = $1', [req.params.device]);
    if (!device) return res.status(404).json({ error: 'no such device' });
    if (device.account_key !== req.accountKey) return res.status(403).json({ error: 'not your device' });
    req.device = device;
    next();
  }

  async function requireDeviceToken(req, res, next) {
    const auth = req.headers.authorization || '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'missing token' });
    const device = await one('SELECT * FROM devices WHERE token_hash = $1', [sha256hex(token)]);
    if (!device || device.device_id !== req.params.device) return res.status(401).json({ error: 'bad token' });
    req.device = device;
    next();
  }

  // --- Steam login (spec §2.1/2.2) ----------------------------------------
  app.get('/auth/steam', async (_req, res) => {
    try {
      res.redirect(await authUrl(rp));
    } catch {
      res.status(502).json({ error: 'steam openid unavailable' });
    }
  });

  app.get('/auth/steam/return', async (req, res) => {
    const steamid = await verifyReturn(rp, req.originalUrl);
    if (!steamid) return res.status(403).send('Steam login failed');
    const key = accountKey(steamid);
    await ensureAccount(key);
    setSession(res, key);
    res.redirect('/');
  });

  // Test/dev only: mint a session for a fake SteamID without hitting Steam.
  if (devFakeSteam) {
    app.get('/auth/dev-login', async (req, res) => {
      const steamid = String(req.query.steamid || '');
      if (!/^\d{17}$/.test(steamid)) return res.status(400).json({ error: 'bad steamid' });
      const key = accountKey(steamid);
      await ensureAccount(key);
      setSession(res, key);
      res.json({ ok: true });
    });
  }

  app.post('/auth/logout', (_req, res) => {
    res.setHeader('Set-Cookie', 'fmsd_session=; HttpOnly; Path=/; Max-Age=0');
    res.json({ ok: true });
  });

  app.get('/v1/me', requireSession, (req, res) => res.json({ ok: true }));

  // Owner alert settings (webhook + optional email). Metadata alerts only.
  app.get('/v1/notify', requireSession, async (req, res) => {
    const a = await one('SELECT notify_webhook, notify_email FROM accounts WHERE account_key = $1', [req.accountKey]);
    res.json({ webhook: a?.notify_webhook || '', email: a?.notify_email || '', email_enabled: emailEnabled() });
  });

  app.put('/v1/notify', requireSession, async (req, res) => {
    const webhook = String(req.body?.webhook || '').trim().slice(0, 500);
    const email = String(req.body?.email || '').trim().slice(0, 200);
    if (webhook && !safeWebhook(webhook)) {
      return res.status(400).json({ error: 'webhook must be an https URL to a public host' });
    }
    if (email && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
      return res.status(400).json({ error: 'invalid email' });
    }
    await ensureAccount(req.accountKey);
    await q('UPDATE accounts SET notify_webhook = $1, notify_email = $2 WHERE account_key = $3',
      [webhook || null, email || null, req.accountKey]);
    res.json({ ok: true });
  });

  // Send a test alert to the configured sinks so the owner can confirm wiring.
  app.post('/v1/notify/test', requireSession, async (req, res) => {
    await notify(req.accountKey, {
      event: 'test',
      title: '🛰 Find My Deck — test alert',
      text: 'Your alerts are wired up. You’ll get pings like this for finder messages and Lost-Deck check-ins.',
    });
    res.json({ ok: true });
  });

  // Delete the whole account: every device, its sealed reports, relay threads,
  // commands, pending pair codes, alert settings — all of it. Irreversible.
  app.delete('/v1/account', requireSession, async (req, res) => {
    const key = req.accountKey;
    // Devices cascade to reports/commands/relay_threads/relay_messages; pair
    // codes and the account row reference the account directly, so drop them
    // in FK order.
    await q('DELETE FROM pair_codes WHERE account_key = $1', [key]);
    await q('DELETE FROM devices WHERE account_key = $1', [key]);
    await q('DELETE FROM accounts WHERE account_key = $1', [key]);
    res.setHeader('Set-Cookie', 'fmsd_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0');
    res.json({ ok: true });
  });

  // --- pairing: browser session -> short-lived code typed into the Deck ---
  // Enrollment consent gate (spec §2.4): the code proves a validated Steam
  // login, physical presence at the Deck proves possession.
  app.post('/v1/pair', requireSession, async (req, res) => {
    const code = String(crypto.randomInt(0, 1_000_000)).padStart(6, '0');
    await q('INSERT INTO pair_codes (code, account_key, expires_at) VALUES ($1, $2, $3)',
      [code, req.accountKey, now() + PAIR_TTL_MS]);
    res.json({ code, expires_in: PAIR_TTL_MS / 1000 });
  });

  async function consumePairCode(code) {
    // DELETE ... RETURNING: atomic single-use even under concurrent redemption.
    const row = await one('DELETE FROM pair_codes WHERE code = $1 RETURNING account_key, expires_at',
      [String(code || '').toUpperCase()]);
    if (!row || row.expires_at < now()) return null;
    return row.account_key;
  }

  // --- enrollment (spec §2.4) ----------------------------------------------
  app.post('/v1/enroll', async (req, res) => {
    if (!allowEnroll(req.ip)) return res.status(429).json({ error: 'too many attempts, wait a few minutes' });
    const { box_pk, sign_pk, salt, kdf, device_name, pair_code } = req.body || {};
    const key = pair_code
      ? await consumePairCode(pair_code)
      : readSession(sessionSecret, req.headers.cookie);
    if (!key) return res.status(401).json({ error: 'not authorized to enroll' });
    for (const [k, v] of Object.entries({ box_pk, sign_pk, salt })) {
      if (typeof v !== 'string' || !/^[A-Za-z0-9+/=]{20,100}$/.test(v)) {
        return res.status(400).json({ error: `bad ${k}` });
      }
    }
    if (!kdf || kdf.alg !== 'argon2id' || !Number.isInteger(kdf.v)) {
      return res.status(400).json({ error: 'bad kdf' });
    }
    const device_id = crypto.randomUUID();
    const device_token = crypto.randomBytes(32).toString('hex');
    await q(`INSERT INTO devices
        (device_id, account_key, name, box_pk, sign_pk, salt, kdf, token_hash, counter, mode, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 0, 'normal', $9)`,
      [device_id, key, String(device_name || 'Steam Deck').slice(0, 64),
        box_pk, sign_pk, salt, JSON.stringify(kdf), sha256hex(device_token), now()]);
    res.json({ device_id, device_token });
  });

  // --- reports (spec §2.7): opaque blobs in, token-auth, rate-limited ------
  app.post('/v1/reports/:device', requireDeviceToken, async (req, res) => {
    const blob = req.body?.blob;
    if (typeof blob !== 'string' || blob.length > MAX_BLOB_BYTES || !/^[A-Za-z0-9+/=]+$/.test(blob)) {
      return res.status(400).json({ error: 'bad blob' });
    }
    if (!allowReport(req.device.device_id)) return res.status(429).json({ error: 'rate limited' });
    await q('INSERT INTO reports (device_id, blob, received_at) VALUES ($1, $2, $3)',
      [req.device.device_id, blob, now()]);
    // A fresh report means it's alive — clear any "gone quiet" latch.
    const dev = await one(
      `UPDATE devices SET last_seen = $1, lost_quiet_notified = false
         WHERE device_id = $2 RETURNING name, account_key, mode, lost_checkin_notified`,
      [now(), req.device.device_id]);
    // Alert once when a Deck you marked Lost first phones home.
    if (dev && dev.mode === 'lost' && !dev.lost_checkin_notified) {
      await q('UPDATE devices SET lost_checkin_notified = true WHERE device_id = $1', [req.device.device_id]);
      notify(dev.account_key, {
        event: 'lost_checkin',
        title: `📍 "${dev.name}" just checked in`,
        text: `Your lost Deck "${dev.name}" reported a fresh location. Open the dashboard to see where it is.`,
        device: dev.name,
      });
    }
    res.status(204).end();
  });

  // --- commands (spec §2.6): two-gate set-mode ------------------------------
  app.put('/v1/command/:device', requireSession, requireDeviceOwner, async (req, res) => {
    const { payload, sig } = req.body || {};
    if (typeof payload !== 'string' || typeof sig !== 'string') {
      return res.status(400).json({ error: 'need payload+sig' });
    }
    // Gate 2 sanity check with the PUBLIC key only — the server holds no
    // signing material; this just refuses to store junk it would relay.
    if (!(await verifyCommand(payload, sig, req.device.sign_pk))) {
      return res.status(400).json({ error: 'signature does not verify against enrolled sign_pk' });
    }
    let cmd;
    try { cmd = JSON.parse(payload); } catch { return res.status(400).json({ error: 'payload not JSON' }); }
    if (!MODES.has(cmd.mode)) return res.status(400).json({ error: 'bad mode' });
    if (!Number.isInteger(cmd.counter)) return res.status(400).json({ error: 'bad counter' });
    // Server-side monotonicity (§2.6), enforced atomically in the UPDATE
    // guard so two racing PUTs can't both land.
    const bumped = await one(
      'UPDATE devices SET counter = $1, mode = $2 WHERE device_id = $3 AND counter < $1 RETURNING device_id',
      [cmd.counter, cmd.mode, req.device.device_id]);
    if (!bumped) return res.status(409).json({ error: 'counter must advance' });
    // Fresh Lost session — re-arm the check-in / gone-quiet alerts.
    if (cmd.mode === 'lost') {
      await q('UPDATE devices SET lost_checkin_notified = false, lost_quiet_notified = false WHERE device_id = $1',
        [req.device.device_id]);
    }
    await q(`INSERT INTO commands (device_id, payload, sig, counter) VALUES ($1, $2, $3, $4)
             ON CONFLICT (device_id) DO UPDATE SET payload = $2, sig = $3, counter = $4`,
      [req.device.device_id, payload, sig, cmd.counter]);
    // Recovery threads follow the current Lost session. Returning to Normal
    // (Deck recovered) clears the conversation; a fresh Lost session drops any
    // stale threads and keeps only the active code. Messages cascade-delete.
    const activeContact = cmd.mode === 'lost' && typeof cmd.contact === 'string' ? cmd.contact : '';
    await q('DELETE FROM relay_threads WHERE device_id = $1 AND contact <> $2',
      [req.device.device_id, activeContact]);
    if (activeContact) {
      await q(`INSERT INTO relay_threads (contact, device_id, created_at) VALUES ($1, $2, $3)
               ON CONFLICT (contact) DO NOTHING`, [activeContact, req.device.device_id, now()]);
    }
    res.json({ ok: true, counter: cmd.counter });
  });

  // --- recovery relay (spec §4) --------------------------------------------
  // Finder-facing, keyed by the contact code from the lost banner. Public
  // (a finder has no account) but the code is the unguessable capability.
  const relayInfo = async (code) => {
    const t = await one('SELECT device_id FROM relay_threads WHERE contact = $1', [code]);
    if (!t) return null;
    const cmd = await one('SELECT payload FROM commands WHERE device_id = $1', [t.device_id]);
    let ownerMessage = '';
    try { ownerMessage = JSON.parse(cmd?.payload || '{}').message || ''; } catch { /* ignore */ }
    const msgs = await q(
      'SELECT sender, body, created_at FROM relay_messages WHERE contact = $1 ORDER BY id', [code]);
    return { ownerMessage, messages: msgs };
  };

  app.get('/v1/found/:code', async (req, res) => {
    const info = await relayInfo(req.params.code.toUpperCase());
    if (!info) return res.status(404).json({ error: 'unknown or expired code' });
    res.json(info);
  });

  app.post('/v1/found/:code', async (req, res) => {
    const code = req.params.code.toUpperCase();
    if (!allowEnroll(req.ip)) return res.status(429).json({ error: 'slow down' });
    const body = String(req.body?.body || '').slice(0, 1000).trim();
    if (!body) return res.status(400).json({ error: 'empty message' });
    const t = await one('SELECT device_id FROM relay_threads WHERE contact = $1', [code]);
    if (!t) return res.status(404).json({ error: 'unknown or expired code' });
    await q('INSERT INTO relay_messages (contact, sender, body, created_at) VALUES ($1, $2, $3, $4)',
      [code, 'finder', body, now()]);
    notifyDeviceOwner(t.device_id, {
      event: 'finder_message',
      title: '✉️ Someone messaged you about your Deck',
      text: `A finder wrote: “${body.slice(0, 140)}”. Reply from the dashboard.`,
    });
    res.json({ ok: true });
  });

  // Device side: the Deck itself posts a finder message to its own thread
  // (token-authed), so the holder can message the owner straight from the
  // lost screen without visiting the recovery URL.
  const deviceContact = async (deviceId) => {
    const cmd = await one('SELECT payload FROM commands WHERE device_id = $1', [deviceId]);
    try { return JSON.parse(cmd?.payload || '{}').contact || ''; } catch { return ''; }
  };

  app.post('/v1/message/:device', requireDeviceToken, async (req, res) => {
    const text = String(req.body?.body || '').slice(0, 1000).trim();
    if (!text) return res.status(400).json({ error: 'empty message' });
    const contact = await deviceContact(req.device.device_id);
    if (!contact) return res.status(409).json({ error: 'device is not in lost mode' });
    await q(`INSERT INTO relay_threads (contact, device_id, created_at) VALUES ($1, $2, $3)
             ON CONFLICT (contact) DO NOTHING`, [contact, req.device.device_id, now()]);
    await q('INSERT INTO relay_messages (contact, sender, body, created_at) VALUES ($1, $2, $3, $4)',
      [contact, 'finder', text, now()]);
    notifyDeviceOwner(req.device.device_id, {
      event: 'finder_message',
      title: '✉️ Message from whoever has your Deck',
      text: `“${text.slice(0, 140)}” — reply from the dashboard.`,
    });
    res.json({ ok: true });
  });

  // Device reads its own thread (token-authed) — powers the on-Deck chat.
  app.get('/v1/message/:device', requireDeviceToken, async (req, res) => {
    const contact = await deviceContact(req.device.device_id);
    if (!contact) return res.json({ messages: [] });
    const messages = await q(
      'SELECT sender, body, created_at FROM relay_messages WHERE contact = $1 ORDER BY id', [contact]);
    res.json({ messages });
  });

  // Owner side: read/reply to a device's recovery threads.
  app.get('/v1/relay/:device', requireSession, requireDeviceOwner, async (req, res) => {
    res.json(await q(
      `SELECT m.contact, m.sender, m.body, m.created_at
         FROM relay_messages m JOIN relay_threads t ON t.contact = m.contact
        WHERE t.device_id = $1 ORDER BY m.id`, [req.device.device_id]));
  });

  app.post('/v1/relay/:device', requireSession, requireDeviceOwner, async (req, res) => {
    const { contact, body } = req.body || {};
    const text = String(body || '').slice(0, 1000).trim();
    if (!text) return res.status(400).json({ error: 'empty message' });
    const t = await one('SELECT contact FROM relay_threads WHERE contact = $1 AND device_id = $2',
      [String(contact || '').toUpperCase(), req.device.device_id]);
    if (!t) return res.status(404).json({ error: 'no such thread' });
    await q('INSERT INTO relay_messages (contact, sender, body, created_at) VALUES ($1, $2, $3, $4)',
      [t.contact, 'owner', text, now()]);
    res.json({ ok: true });
  });

  app.get('/v1/command/:device', requireDeviceToken, async (req, res) => {
    const row = await one('SELECT payload, sig FROM commands WHERE device_id = $1', [req.device.device_id]);
    if (!row) return res.status(204).end();
    res.json(row); // relayed verbatim; device verifies sig + counter itself
  });

  // "Play sound" (like Android). Ringing is a loud noise, not a tracking or
  // decryption capability, so it's gated by the session only (Gate 1) — no
  // password/signature — to stay one-tap. A monotonic counter the device
  // compares against; bumping it makes the Deck ring on its next check.
  app.put('/v1/ring/:device', requireSession, requireDeviceOwner, async (req, res) => {
    const row = await one('UPDATE devices SET ring_counter = ring_counter + 1 WHERE device_id = $1 RETURNING ring_counter',
      [req.device.device_id]);
    res.json({ ok: true, ring: row.ring_counter });
  });

  app.get('/v1/ring/:device', requireDeviceToken, (req, res) => {
    res.json({ ring: req.device.ring_counter || 0 });
  });

  // --- owner reads (spec §2.9) ----------------------------------------------
  app.get('/v1/devices', requireSession, async (req, res) => {
    // last_finder_msg = newest finder message across the device's threads;
    // the client badges it against a locally-stored "seen" timestamp.
    res.json(await q(
      `SELECT d.device_id, d.name, d.mode, d.last_seen,
              (SELECT max(m.created_at) FROM relay_messages m
                 JOIN relay_threads t ON t.contact = m.contact
                WHERE t.device_id = d.device_id AND m.sender = 'finder') AS last_finder_msg
         FROM devices d
        WHERE d.account_key = $1 AND d.token_hash IS NOT NULL`,
      [req.accountKey]));
  });

  app.get('/v1/reports/:device', requireSession, requireDeviceOwner, async (req, res) => {
    const limit = Math.min(Number(req.query.limit) || 200, 1000);
    res.json(await q(
      'SELECT blob, received_at FROM reports WHERE device_id = $1 ORDER BY received_at DESC LIMIT $2',
      [req.device.device_id, limit]));
  });

  app.get('/v1/salt/:device', requireSession, requireDeviceOwner, (req, res) => {
    res.json({
      salt: req.device.salt,
      kdf: JSON.parse(req.device.kdf),
      box_pk: req.device.box_pk,
      counter: req.device.counter,
    });
  });

  // --- geolocation proxy ----------------------------------------------------
  // beacondb sends no CORS headers, so the owner's browser cannot call it
  // directly. We relay. TRADEOFF vs the pure-browser ideal (spec §5): the
  // server sees BSSIDs transiently while resolving an owner-initiated Locate.
  // It is session-authed, never stored, never logged. Reports at rest stay
  // sealed and there is still no passive location history.
  app.post('/v1/geolocate', requireSession, async (req, res) => {
    const aps = (req.body?.wifiAccessPoints || []).slice(0, 40);
    if (!Array.isArray(aps) || aps.length === 0) return res.status(400).json({ error: 'no APs' });
    const gkey = process.env.FMSD_GOOGLE_GEOLOCATION_KEY;
    const bssids = aps.map((a) => ({ bssid: a.macAddress || a.bssid, rssi: a.signalStrength ?? a.rssi }))
      .filter((a) => a.bssid);
    try {
      if (gkey) {
        // Google (opt-in, needs billing). considerIp:false => WiFi-only.
        const r = await fetch(`https://www.googleapis.com/geolocation/v1/geolocate?key=${gkey}`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ considerIp: false, wifiAccessPoints: aps }),
          signal: AbortSignal.timeout(15000),
        });
        if (r.status === 404) return res.json({ located: false });
        if (!r.ok) return res.status(502).json({ error: `google ${r.status}` });
        const g = await r.json();
        return res.json({ located: true, lat: g.location.lat, lon: g.location.lng, accuracy: g.accuracy });
      }
      // Default: Apple's keyless service (best free coverage). Fall back to
      // beacondb only if Apple errors or knows none of the APs.
      try {
        const a = await appleLocate(bssids);
        if (a.located) return res.json(a);
      } catch (e) {
        console.warn('apple geolocation failed, trying beacondb:', e.message);
      }
      const r = await fetch('https://beacondb.net/v1/geolocate', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ wifiAccessPoints: aps }),
        signal: AbortSignal.timeout(15000),
      });
      if (!r.ok) return res.json({ located: false });
      const b = await r.json();
      // beacondb sets fallback:"ipf" when it geolocated the REQUESTER's IP
      // (this server) instead of the WiFi — not a Deck fix.
      if (b.fallback || !b.location) return res.json({ located: false });
      return res.json({ located: true, lat: b.location.lat, lon: b.location.lng, accuracy: b.accuracy });
    } catch (e) {
      res.status(502).json({ error: `geolocation failed: ${e.message}` });
    }
  });

  // --- admin (single fixed account) ----------------------------------------
  function requireAdmin(req, res, next) {
    if (req.accountKey !== adminKey) return res.status(403).json({ error: 'not admin' });
    next();
  }

  app.get('/v1/admin/stats', requireSession, requireAdmin, async (_req, res) => {
    const dayAgo = now() - 86400000;
    const weekAgo = now() - 7 * 86400000;
    const scalar = async (sql, params) => Number(Object.values((await one(sql, params)) || { n: 0 })[0] || 0);
    const [
      accounts, devices, lost, active24, enrolled7d,
      reports, reports24, threads, messages, pairPending,
    ] = await Promise.all([
      scalar('SELECT count(*) n FROM accounts'),
      scalar('SELECT count(*) n FROM devices'),
      scalar("SELECT count(*) n FROM devices WHERE mode = 'lost'"),
      scalar('SELECT count(*) n FROM devices WHERE last_seen > $1', [dayAgo]),
      scalar('SELECT count(*) n FROM devices WHERE created_at > $1', [weekAgo]),
      scalar('SELECT count(*) n FROM reports'),
      scalar('SELECT count(*) n FROM reports WHERE received_at > $1', [dayAgo]),
      scalar('SELECT count(*) n FROM relay_threads'),
      scalar('SELECT count(*) n FROM relay_messages'),
      scalar('SELECT count(*) n FROM pair_codes WHERE expires_at > $1', [now()]),
    ]);
    const recent = await q(
      'SELECT created_at, mode, last_seen FROM devices ORDER BY created_at DESC LIMIT 20');
    res.json({
      generated_at: now(),
      accounts, devices, installs: devices, lost, normal: devices - lost,
      active_24h: active24, enrolled_7d: enrolled7d,
      reports, reports_24h: reports24, relay_threads: threads, relay_messages: messages,
      pair_codes_pending: pairPending, recent,
    });
  });

  // --- revocation (spec §2.8) -----------------------------------------------
  app.delete('/v1/devices/:device', requireSession, requireDeviceOwner, async (req, res) => {
    await q('DELETE FROM devices WHERE device_id = $1', [req.device.device_id]); // reports/commands cascade
    res.json({ ok: true });
  });

  // eslint-disable-next-line no-unused-vars
  app.use((err, _req, res, _next) => {
    console.error('fmsd server error:', err);
    res.status(500).json({ error: 'internal error' });
  });

  return app;
}
