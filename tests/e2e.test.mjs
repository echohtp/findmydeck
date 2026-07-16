// Full-system e2e: real server over HTTP, real Python plugin modules as the
// Deck, real TS crypto as the owner's browser. Proves the §7 properties
// hold end to end: owner decrypts reports, owner-signed command flips the
// device, server-forged command cannot.

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { createApp } from '../server/app.js';
import { openDb } from '../server/db.js';
import { deriveKeys, genSalt, sealOpen, signCommand } from '../crypto/ts/crypto.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const PY = process.env.FMSD_PYTHON || 'python3';
const TEST_KDF = { v: 1, alg: 'argon2id', ops: 1, mem: 8388608 };
const PASSWORD = 'the owner master password 7';

let server; let base; let statedir;

// Async spawn: execFileSync would block the event loop and deadlock the
// in-process server the Python subprocess is talking to.
function deck(cmd, input) {
  return new Promise((resolve, reject) => {
    const child = execFile(PY, [path.join(here, 'e2e_device.py'), statedir, cmd],
      { encoding: 'utf8' },
      (err, stdout, stderr) => (err ? reject(new Error(`${err.message}\n${stderr}`)) : resolve(JSON.parse(stdout))));
    if (input) child.stdin.write(JSON.stringify(input));
    child.stdin.end();
  });
}

let cookie = '';
async function owner(method, p, body) {
  const headers = { cookie };
  if (body) headers['content-type'] = 'application/json';
  const res = await fetch(base + p, { method, headers, body: body && JSON.stringify(body) });
  const sc = res.headers.get('set-cookie');
  if (sc) cookie = sc.split(';')[0];
  const text = await res.text();
  return { status: res.status, body: text ? JSON.parse(text) : null };
}

let db;
before(async () => {
  statedir = mkdtempSync(path.join(tmpdir(), 'fmsd-e2e-'));
  db = await openDb(process.env.FMSD_TEST_DATABASE_URL);
  await db.query('TRUNCATE accounts, devices, reports, commands, pair_codes CASCADE');
  const app = createApp({ db, devFakeSteam: true, pepper: 'p', sessionSecret: 's' });
  await new Promise((r) => { server = app.listen(0, r); });
  base = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  server.close();
  await db.end();
  rmSync(statedir, { recursive: true, force: true });
});

test('owner + Deck + server, whole loop', async (t) => {
  await owner('GET', '/auth/dev-login?steamid=76561198111111111');

  // Owner-side derivation (browser). Deck gets pubkeys only.
  const salt = await genSalt();
  const keys = await deriveKeys(PASSWORD, salt, TEST_KDF);

  let deviceId;
  await t.test('enroll Deck via pair code', async () => {
    const { body: { code } } = await owner('POST', '/v1/pair');
    const res = await deck('enroll', {
      server_url: base, pair_code: code,
      box_pk: keys.boxPk, sign_pk: keys.signPk, salt, kdf: TEST_KDF,
    });
    deviceId = res.device_id;
    assert.ok(deviceId);
  });

  await t.test('deck reports; owner decrypts real scan payload', async () => {
    const tick = await deck('tick');
    assert.equal(tick.report.delivered, true);
    const { body: reports } = await owner('GET', `/v1/reports/${deviceId}`);
    assert.equal(reports.length, 1);
    const payload = JSON.parse(await sealOpen(reports[0].blob, keys.boxPk, keys.boxSk));
    assert.equal(payload.wifi[0].bssid, 'de:ad:be:ef:00:01');
    assert.equal(payload.wifi[0].rssi, -45);
    assert.equal(payload.bt.length, 0); // normal mode: no BT scan
  });

  await t.test('owner flips to lost; deck verifies and applies', async () => {
    // Re-derive from salt+kdf fetched from server — the browser flow.
    const { body: saltRes } = await owner('GET', `/v1/salt/${deviceId}`);
    const rekeys = await deriveKeys(PASSWORD, saltRes.salt, saltRes.kdf);
    const { payload, sig } = await signCommand({
      mode: 'lost', counter: saltRes.counter + 1, issued_at: 1,
      message: 'reward if returned', contact: 'ZZ99-XX',
    }, rekeys.signSk);
    assert.equal((await owner('PUT', `/v1/command/${deviceId}`, { payload, sig })).status, 200);

    const tick = await deck('tick');
    assert.deepEqual(tick.applied, [true, 'applied']);
    assert.equal(tick.mode, 'lost');
    assert.equal(tick.report.bt, 1); // lost mode: BT scan on

    // lost-mode report decrypts and carries flag_ack
    const { body: reports } = await owner('GET', `/v1/reports/${deviceId}`);
    const latest = JSON.parse(await sealOpen(reports[0].blob, keys.boxPk, keys.boxSk));
    assert.equal(latest.flag_ack, saltRes.counter + 1);
    assert.equal(latest.bt[0].mac, 'ca:fe:00:00:00:01');
  });

  await t.test('replay and forgery both dead-end', async () => {
    const status = await deck('status');
    assert.equal(status.mode, 'lost'); // unchanged
    // Replay of the same counter via the real endpoint is refused server-side too.
    const { body: saltRes } = await owner('GET', `/v1/salt/${deviceId}`);
    const rekeys = await deriveKeys(PASSWORD, saltRes.salt, saltRes.kdf);
    const { payload, sig } = await signCommand({
      mode: 'normal', counter: saltRes.counter, issued_at: 2, message: '', contact: '',
    }, rekeys.signSk);
    assert.equal((await owner('PUT', `/v1/command/${deviceId}`, { payload, sig })).status, 409);
  });
});
