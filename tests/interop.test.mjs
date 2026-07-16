// Cross-language round-trip: everything in spec §1.4, both directions.
// TS derive == Py derive; Py seal -> TS open; TS seal -> Py open;
// TS sign -> Py verify; Py sign -> TS verify; tamper cases fail.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

import {
  KDF_V1, deriveKeys, genSalt, seal, sealOpen, signCommand, verifyCommand, toB64, wipe,
} from '../crypto/ts/crypto.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const PY = process.env.FMSD_PYTHON || 'python3';

function py(cmd, input) {
  const out = execFileSync(PY, [path.join(here, '../crypto/py/cli.py'), cmd], {
    input: JSON.stringify(input),
    cwd: path.join(here, '../crypto/py'),
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
  });
  return JSON.parse(out);
}

const PASSWORD = 'correct horse battery staple 9';

test('interop: full round-trip TS <-> Python', async (t) => {
  const salt = await genSalt();

  // One full-cost Argon2id derive on each side, same inputs.
  const ts = await deriveKeys(PASSWORD, salt, KDF_V1);
  const pyKeys = py('derive', { password: PASSWORD, salt, kdf: KDF_V1 });

  await t.test('derive: identical public keys', () => {
    assert.equal(ts.boxPk, pyKeys.box_pk);
    assert.equal(ts.signPk, pyKeys.sign_pk);
  });

  await t.test('derive: different password => different keys', async () => {
    const other = await deriveKeys(PASSWORD + '!', salt, KDF_V1);
    assert.notEqual(other.boxPk, ts.boxPk);
    wipe(other.boxSk, other.signSk);
  });

  const report = JSON.stringify({
    v: 1, seq: 7, ts: 1760000000000,
    wifi: [{ bssid: 'aa:bb:cc:dd:ee:ff', rssi: -48, ch: 6, freq: 2437 }],
    bt: [], batt: 0.83, flag_ack: 3,
  });

  await t.test('reports: Python seals, TS opens (the production direction)', async () => {
    const { blob } = py('seal', { payload: report, box_pk: pyKeys.box_pk });
    assert.equal(await sealOpen(blob, ts.boxPk, ts.boxSk), report);
  });

  await t.test('reports: TS seals, Python opens', async () => {
    const blob = await seal(report, ts.boxPk);
    const { payload } = py('open', { blob, box_sk: pyKeys.box_sk });
    assert.equal(payload, report);
  });

  await t.test('reports: wrong key cannot open', async () => {
    const blob = await seal(report, ts.boxPk);
    const stranger = await deriveKeys('some other password 42', salt, KDF_V1);
    await assert.rejects(() => sealOpen(blob, ts.boxPk, stranger.boxSk));
    wipe(stranger.boxSk, stranger.signSk);
  });

  const command = { mode: 'stolen', counter: 4, issued_at: 1760000001000, message: '', contact: '7F3K-Q2' };

  await t.test('commands: TS signs, Python verifies (the production direction)', async () => {
    const { payload, sig } = await signCommand(command, ts.signSk);
    assert.equal(py('verify', { payload, sig, sign_pk: ts.signPk }).ok, true);
    // Tampered payload string must fail — even a semantically equal re-serialization.
    assert.equal(py('verify', { payload: payload + ' ', sig, sign_pk: ts.signPk }).ok, false);
    const tampered = JSON.stringify({ ...command, counter: 99 });
    assert.equal(py('verify', { payload: tampered, sig, sign_pk: ts.signPk }).ok, false);
  });

  await t.test('commands: Python signs, TS verifies', async () => {
    const { payload, sig } = py('sign', { command, sign_seed: pyKeys.sign_seed });
    assert.equal(await verifyCommand(payload, sig, ts.signPk), true);
    assert.equal(await verifyCommand(payload.replace('stolen', 'normal'), sig, ts.signPk), false);
  });

  await t.test('commands: signature from another identity rejected', async () => {
    const stranger = await deriveKeys('attacker password 1234', salt, KDF_V1);
    const { payload, sig } = await signCommand(command, stranger.signSk);
    assert.equal(await verifyCommand(payload, sig, ts.signPk), false);
    assert.equal(py('verify', { payload, sig, sign_pk: ts.signPk }).ok, false);
    wipe(stranger.boxSk, stranger.signSk);
  });

  await t.test('base64 helpers agree', async () => {
    assert.equal(await toB64(new Uint8Array([0, 1, 2, 250, 251, 252])), 'AAEC+vv8');
  });

  wipe(ts.boxSk, ts.signSk);
});
