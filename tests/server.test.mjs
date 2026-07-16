// End-to-end server tests over real HTTP: enrollment (session + pair code),
// report upload, two-gate set-mode, replay, horizontal authz, revocation.
// Uses dev fake-Steam login; crypto uses a cheap test KDF (params are
// versioned/stored per device, so this exercises the same code paths).

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createApp } from '../server/app.js';
import { openDb } from '../server/db.js';
import {
  deriveKeys, genSalt, seal, sealOpen, signCommand,
} from '../crypto/ts/crypto.mjs';

// Cheap-but-real Argon2id for tests (mem 8 MiB). v:1 keeps validation happy.
const TEST_KDF = { v: 1, alg: 'argon2id', ops: 1, mem: 8388608 };

let server; let base;
const OWNER = '76561198000000001';
const STRANGER = '76561198000000002';

function client() {
  let cookie = '';
  return {
    async req(method, path, { body, token, raw } = {}) {
      const headers = {};
      if (cookie) headers.cookie = cookie;
      if (token) headers.authorization = `Bearer ${token}`;
      if (body !== undefined) headers['content-type'] = 'application/json';
      const res = await fetch(base + path, {
        method, headers, body: body === undefined ? undefined : JSON.stringify(body), redirect: 'manual',
      });
      const setCookie = res.headers.get('set-cookie');
      if (setCookie) cookie = setCookie.split(';')[0];
      if (raw) return res;
      const text = await res.text();
      return { status: res.status, body: text ? JSON.parse(text) : null };
    },
  };
}

let db;
before(async () => {
  db = await openDb(process.env.FMSD_TEST_DATABASE_URL);
  await db.query('TRUNCATE accounts, devices, reports, commands, pair_codes CASCADE');
  const app = createApp({
    db, devFakeSteam: true,
    pepper: 'test-pepper', sessionSecret: 'test-secret',
  });
  await new Promise((resolve) => { server = app.listen(0, resolve); });
  base = `http://127.0.0.1:${server.address().port}`;
});

after(async () => { server.close(); await db.end(); });

test('full lifecycle', async (t) => {
  const owner = client();
  const salt = await genSalt();
  const keys = await deriveKeys('hunter2 but actually long', salt, TEST_KDF);

  await t.test('unauthenticated requests are rejected', async () => {
    assert.equal((await owner.req('GET', '/v1/devices')).status, 401);
    assert.equal((await owner.req('POST', '/v1/enroll', { body: {} })).status, 401);
  });

  await owner.req('GET', `/auth/dev-login?steamid=${OWNER}`);

  let deviceId; let deviceToken;
  await t.test('enroll via pair code (the Deck path)', async () => {
    const { body: { code } } = await owner.req('POST', '/v1/pair');
    const deck = client(); // no session — simulates the plugin
    const r = await deck.req('POST', '/v1/enroll', {
      body: {
        pair_code: code, box_pk: keys.boxPk, sign_pk: keys.signPk,
        salt, kdf: TEST_KDF, device_name: 'Living room Deck',
      },
    });
    assert.equal(r.status, 200);
    ({ device_id: deviceId, device_token: deviceToken } = r.body);
    assert.ok(deviceId && deviceToken);
    // pair code is single-use
    const again = await deck.req('POST', '/v1/enroll', {
      body: { pair_code: code, box_pk: keys.boxPk, sign_pk: keys.signPk, salt, kdf: TEST_KDF },
    });
    assert.equal(again.status, 401);
  });

  await t.test('device uploads sealed report with token; owner reads blob back', async () => {
    const payload = JSON.stringify({ v: 1, seq: 1, ts: 1, wifi: [], bt: [], batt: 0.5, flag_ack: 0 });
    const blob = await seal(payload, keys.boxPk);
    const deck = client();
    assert.equal((await deck.req('POST', `/v1/reports/${deviceId}`, { body: { blob }, token: deviceToken })).status, 204);
    assert.equal((await deck.req('POST', `/v1/reports/${deviceId}`, { body: { blob }, token: 'wrong' })).status, 401);

    const list = await owner.req('GET', `/v1/reports/${deviceId}`);
    assert.equal(list.status, 200);
    assert.equal(list.body.length, 1);
    assert.equal(await sealOpen(list.body[0].blob, keys.boxPk, keys.boxSk), payload);
  });

  await t.test('salt endpoint returns enrollment kdf', async () => {
    const r = await owner.req('GET', `/v1/salt/${deviceId}`);
    assert.equal(r.status, 200);
    assert.deepEqual(r.body.kdf, TEST_KDF);
    assert.equal(r.body.salt, salt);
  });

  await t.test('two-gate set-mode: signed command accepted, device fetches it', async () => {
    const { payload, sig } = await signCommand(
      { mode: 'lost', counter: 1, issued_at: 2, message: '', contact: 'AB12-CD' }, keys.signSk,
    );
    const put = await owner.req('PUT', `/v1/command/${deviceId}`, { body: { payload, sig } });
    assert.equal(put.status, 200);

    const deck = client();
    const got = await deck.req('GET', `/v1/command/${deviceId}`, { token: deviceToken });
    assert.equal(got.status, 200);
    assert.equal(got.body.payload, payload); // relayed byte-exact
    assert.equal(got.body.sig, sig);

    const devs = await owner.req('GET', '/v1/devices');
    assert.equal(devs.body[0].mode, 'lost');
  });

  await t.test('server cannot forge: unsigned/garbage command rejected', async () => {
    const forged = JSON.stringify({ mode: 'lost', counter: 5, issued_at: 3, message: '', contact: '' });
    const r = await owner.req('PUT', `/v1/command/${deviceId}`, { body: { payload: forged, sig: 'AAAA' } });
    assert.equal(r.status, 400);
  });

  await t.test('replay blocked server-side: counter must advance', async () => {
    const { payload, sig } = await signCommand(
      { mode: 'normal', counter: 1, issued_at: 4, message: '', contact: '' }, keys.signSk,
    );
    assert.equal((await owner.req('PUT', `/v1/command/${deviceId}`, { body: { payload, sig } })).status, 409);
  });

  await t.test('horizontal authz: another account gets 403 on every device route', async () => {
    const other = client();
    await other.req('GET', `/auth/dev-login?steamid=${STRANGER}`);
    for (const [m, p] of [
      ['GET', `/v1/reports/${deviceId}`], ['GET', `/v1/salt/${deviceId}`],
      ['DELETE', `/v1/devices/${deviceId}`],
    ]) {
      assert.equal((await other.req(m, p)).status, 403, `${m} ${p}`);
    }
    const { payload, sig } = await signCommand(
      { mode: 'lost', counter: 9, issued_at: 5, message: '', contact: '' }, keys.signSk,
    );
    assert.equal((await other.req('PUT', `/v1/command/${deviceId}`, { body: { payload, sig } })).status, 403);
  });

  await t.test('revocation kills uploads and hides device', async () => {
    assert.equal((await owner.req('DELETE', `/v1/devices/${deviceId}`)).status, 200);
    const deck = client();
    const blob = await seal('{}', keys.boxPk);
    assert.equal((await deck.req('POST', `/v1/reports/${deviceId}`, { body: { blob }, token: deviceToken })).status, 401);
    assert.equal((await owner.req('GET', '/v1/devices')).body.length, 0);
  });
});

test('recovery relay: finder <-> owner via contact code, no PII', async () => {
  const owner = client();
  await owner.req('GET', `/auth/dev-login?steamid=${OWNER}`);
  const salt = await genSalt();
  const keys = await deriveKeys('relay test password 55', salt, TEST_KDF);
  const { body: { device_id } } = await owner.req('POST', '/v1/enroll', {
    body: { box_pk: keys.boxPk, sign_pk: keys.signPk, salt, kdf: TEST_KDF, device_name: 'relay' },
  });

  // Owner sets lost with a contact code → opens a thread.
  const CODE = 'ABCD-99';
  const { payload, sig } = await signCommand({
    mode: 'lost', counter: 1, issued_at: 1, message: 'please call me', contact: CODE,
  }, keys.signSk);
  assert.equal((await owner.req('PUT', `/v1/command/${device_id}`, { body: { payload, sig } })).status, 200);

  // Finder (no session) reads the code page and leaves a message.
  const finder = client();
  const info = await finder.req('GET', `/v1/found/${CODE}`);
  assert.equal(info.status, 200);
  assert.equal(info.body.ownerMessage, 'please call me');
  assert.equal((await finder.req('POST', `/v1/found/${CODE}`, { body: { body: 'at the cafe, call 555-0148' } })).status, 200);

  // Owner sees it and replies.
  const inbox = await owner.req('GET', `/v1/relay/${device_id}`);
  assert.equal(inbox.body.length, 1);
  assert.equal(inbox.body[0].sender, 'finder');
  assert.equal((await owner.req('POST', `/v1/relay/${device_id}`, { body: { contact: CODE, body: 'on my way, thank you!' } })).status, 200);

  // Finder polls, sees the reply.
  const after = await finder.req('GET', `/v1/found/${CODE}`);
  assert.equal(after.body.messages.length, 2);
  assert.equal(after.body.messages[1].sender, 'owner');

  // The Deck itself can chat via token auth (on-device lost screen).
  const deckTokenRow = await db.query('SELECT token_hash FROM devices WHERE device_id=$1', [device_id]);
  // (token isn't recoverable from hash; re-enroll a fresh device to get one)
  const owner2 = client();
  await owner2.req('GET', `/auth/dev-login?steamid=${OWNER}`);
  const salt2 = await genSalt();
  const k2 = await deriveKeys('deck chat pw 88', salt2, TEST_KDF);
  const { body: dev2 } = await owner2.req('POST', '/v1/enroll', {
    body: { box_pk: k2.boxPk, sign_pk: k2.signPk, salt: salt2, kdf: TEST_KDF, device_name: 'chat' },
  });
  const s2 = await signCommand({ mode: 'lost', counter: 1, issued_at: 1, message: 'hi', contact: 'CHAT-77' }, k2.signSk);
  await owner2.req('PUT', `/v1/command/${dev2.device_id}`, { body: s2 });
  const deck = client();
  assert.equal((await deck.req('POST', `/v1/message/${dev2.device_id}`, { body: { body: 'holding your deck safe' }, token: dev2.device_token })).status, 200);
  const deckThread = await deck.req('GET', `/v1/message/${dev2.device_id}`, { token: dev2.device_token });
  assert.equal(deckThread.body.messages.length, 1);
  assert.equal(deckThread.body.messages[0].sender, 'finder');
  assert.ok(deckTokenRow.rows.length === 1);

  // Recovering the Deck (→ normal) clears the conversation.
  const back = await signCommand({ mode: 'normal', counter: 2, issued_at: 3, message: '', contact: '' }, keys.signSk);
  assert.equal((await owner.req('PUT', `/v1/command/${device_id}`, { body: back })).status, 200);
  assert.equal((await finder.req('GET', `/v1/found/${CODE}`)).status, 404);
  assert.equal((await owner.req('GET', `/v1/relay/${device_id}`)).body.length, 0);

  // Unknown code and cross-account are both refused.
  assert.equal((await finder.req('GET', '/v1/found/NOPE-00')).status, 404);
  const other = client();
  await other.req('GET', `/auth/dev-login?steamid=${STRANGER}`);
  assert.equal((await other.req('GET', `/v1/relay/${device_id}`)).status, 403);
});

test('play sound: owner rings (session-only), device reads counter (token)', async () => {
  const owner = client();
  await owner.req('GET', `/auth/dev-login?steamid=${OWNER}`);
  const salt = await genSalt();
  const keys = await deriveKeys('ring test password 66', salt, TEST_KDF);
  const { body: { device_id, device_token } } = await owner.req('POST', '/v1/enroll', {
    body: { box_pk: keys.boxPk, sign_pk: keys.signPk, salt, kdf: TEST_KDF, device_name: 'ring' },
  });
  const deck = client();
  assert.equal((await deck.req('GET', `/v1/ring/${device_id}`, { token: device_token })).body.ring, 0);
  // Ring needs no signature — session only.
  const r1 = await owner.req('PUT', `/v1/ring/${device_id}`);
  assert.equal(r1.status, 200);
  assert.equal(r1.body.ring, 1);
  assert.equal((await owner.req('PUT', `/v1/ring/${device_id}`)).body.ring, 2);
  assert.equal((await deck.req('GET', `/v1/ring/${device_id}`, { token: device_token })).body.ring, 2);
  // Stranger can't ring someone else's Deck.
  const other = client();
  await other.req('GET', `/auth/dev-login?steamid=${STRANGER}`);
  assert.equal((await other.req('PUT', `/v1/ring/${device_id}`)).status, 403);
});

test('admin stats gated to the operator SteamID', async () => {
  const ADMIN = '76561198035568909'; // matches the app's default admin id
  const call = async (steamid) => {
    const c = client();
    await c.req('GET', `/auth/dev-login?steamid=${steamid}`);
    return c.req('GET', '/v1/admin/stats');
  };
  assert.equal((await call(STRANGER)).status, 403);
  const ok = await call(ADMIN);
  assert.equal(ok.status, 200);
  assert.ok(typeof ok.body.installs === 'number');
  assert.ok(Array.isArray(ok.body.recent));
});

test('report rate limit enforced per device', async () => {
  const owner = client();
  await owner.req('GET', `/auth/dev-login?steamid=${OWNER}`);
  const salt = await genSalt();
  const keys = await deriveKeys('another good password 77', salt, TEST_KDF);
  const r = await owner.req('POST', '/v1/enroll', {
    body: { box_pk: keys.boxPk, sign_pk: keys.signPk, salt, kdf: TEST_KDF, device_name: 'rl' },
  });
  const { device_id, device_token } = r.body;
  const blob = await seal('{}', keys.boxPk);
  const deck = client();
  let limited = false;
  for (let i = 0; i < 40; i++) {
    const res = await deck.req('POST', `/v1/reports/${device_id}`, { body: { blob }, token: device_token });
    if (res.status === 429) { limited = true; break; }
  }
  assert.ok(limited, 'expected a 429 within 40 rapid uploads');
});

test('notification settings: round-trip + unsafe webhook rejected', async () => {
  const owner = client();
  await owner.req('GET', `/auth/dev-login?steamid=${OWNER}`);

  // https public URL + email persist and read back.
  const ok = await owner.req('PUT', '/v1/notify', {
    body: { webhook: 'https://discord.com/api/webhooks/x/y', email: 'me@example.com' },
  });
  assert.equal(ok.status, 200);
  const got = await owner.req('GET', '/v1/notify');
  assert.equal(got.body.webhook, 'https://discord.com/api/webhooks/x/y');
  assert.equal(got.body.email, 'me@example.com');

  // SSRF guard: http and private/loopback hosts are refused.
  for (const bad of ['http://discord.com/x', 'https://127.0.0.1/x', 'https://169.254.169.254/latest']) {
    const r = await owner.req('PUT', '/v1/notify', { body: { webhook: bad } });
    assert.equal(r.status, 400, `expected 400 for ${bad}`);
  }
  // Invalid email refused.
  assert.equal((await owner.req('PUT', '/v1/notify', { body: { email: 'nope' } })).status, 400);

  // A session is required.
  assert.equal((await client().req('GET', '/v1/notify')).status, 401);
});
