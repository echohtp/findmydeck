// Apple response parser: decode a synthetic wloc response with a known
// location and confirm lat/lon/accuracy come out right, plus the real
// "unknown BSSID" sentinel is rejected.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseResponse } from '../server/apple_geo.js';

function varint(nBig) {
  let v = BigInt.asUintN(64, nBig);
  const out = [];
  for (;;) {
    let b = Number(v & 0x7fn);
    v >>= 7n;
    if (v !== 0n) b |= 0x80;
    out.push(b);
    if (v === 0n) break;
  }
  return Buffer.from(out);
}

// Build one WifiDevice { mac, Location{ lat, lon, acc } } inside the
// 10-byte Apple header + field-2 framing parseResponse expects.
function synth(mac, latE8, lonE8, acc) {
  const loc = Buffer.concat([
    Buffer.from([0x08]), varint(BigInt(latE8)),
    Buffer.from([0x10]), varint(BigInt(lonE8)),
    Buffer.from([0x18]), varint(BigInt(acc)),
  ]);
  const macBuf = Buffer.from(mac, 'ascii');
  const dev = Buffer.concat([
    Buffer.from([0x0a, macBuf.length]), macBuf,
    Buffer.from([0x12, loc.length]), loc,
  ]);
  const framed = Buffer.concat([Buffer.from([0x12, dev.length]), dev]);
  const header = Buffer.from([0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, framed.length]);
  return Buffer.concat([header, framed]);
}

test('parses a known location', () => {
  const buf = synth('e0:63:da:4a:6d:8a', 3777490000, -12241940000, 35);
  const m = parseResponse(buf);
  const loc = m.get('e0:63:da:4a:6d:8a');
  assert.ok(loc, 'BSSID present');
  assert.ok(Math.abs(loc.lat - 37.7749) < 1e-6);
  assert.ok(Math.abs(loc.lon - -122.4194) < 1e-6);
  assert.equal(loc.acc, 35);
});

test('rejects the unknown-location sentinel', () => {
  const buf = synth('00:00:00:00:00:00', -18000000000, -18000000000, -1);
  assert.equal(parseResponse(buf).size, 0);
});
