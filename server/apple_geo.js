// Apple WiFi location service — keyless BSSID geolocation.
//
// Apple's gs-loc.apple.com/clls/wloc endpoint (the same one iOS uses) takes
// BSSIDs and returns their surveyed lat/lon, crowdsourced from every iPhone.
// No API key, no billing. Unofficial/reverse-engineered — format is stable
// but could change without notice; beacondb stays as fallback.
//
// Wire format (well documented via iSniff-GPS):
//   fixed header + protobuf { repeated bssid; limit fields }
//   response protobuf { repeated WifiDevice { mac; Location{ lat,lon,acc } } }
// lat/lon are int64 * 1e8; the sentinel -18000000000 means "unknown".

const ENDPOINT = 'https://gs-loc.apple.com/clls/wloc';
const HEADER = Buffer.from([
  0x00, 0x01, 0x00, 0x05, 0x65, 0x6e, 0x5f, 0x55, 0x53, // "en_US"
  0x00, 0x13, 0x63, 0x6f, 0x6d, 0x2e, 0x61, 0x70, 0x70, 0x6c, 0x65,
  0x2e, 0x6c, 0x6f, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x64, // "com.apple.locationd"
  0x00, 0x0a, 0x38, 0x2e, 0x31, 0x2e, 0x31, 0x32, 0x42, 0x34, 0x31, 0x31, // "8.1.12B411"
  0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
]);
const UNKNOWN = -18000000000;

function buildBody(bssids) {
  // Each entry: field2(len-delim) -> { field1(string) = mac }
  let body = Buffer.alloc(0);
  for (const mac of bssids) {
    const macBuf = Buffer.from(mac, 'ascii');
    body = Buffer.concat([body, Buffer.from([0x12, macBuf.length + 2, 0x0a, macBuf.length]), macBuf]);
  }
  // field3 varint 0 (return neighbors), field4 varint 1 (single lookup)
  body = Buffer.concat([body, Buffer.from([0x18, 0x00, 0x20, 0x01])]);
  return Buffer.concat([HEADER, Buffer.from([body.length]), body]);
}

// Minimal protobuf reader for the response shape we expect.
function readVarint(buf, pos) {
  let result = 0n; let shift = 0n; let p = pos;
  for (;;) {
    const b = buf[p]; p += 1;
    result |= BigInt(b & 0x7f) << shift;
    if ((b & 0x80) === 0) break;
    shift += 7n;
  }
  return [result, p];
}

function parseLocation(buf, start, end) {
  let lat = null; let lon = null; let acc = null;
  let p = start;
  while (p < end) {
    const [tag, np] = readVarint(buf, p); p = np;
    const field = Number(tag >> 3n); const wire = Number(tag & 7n);
    if (wire === 0) {
      const [v, np2] = readVarint(buf, p); p = np2;
      // signed int64 stored as-is (two's complement in the varint's low 64 bits)
      let sv = BigInt.asIntN(64, v);
      if (field === 1) lat = Number(sv) / 1e8;
      else if (field === 2) lon = Number(sv) / 1e8;
      else if (field === 3) acc = Number(sv);
    } else if (wire === 2) {
      const [len, np2] = readVarint(buf, p); p = np2 + Number(len);
    } else { break; }
  }
  return { lat, lon, acc };
}

export function parseResponse(buf) {
  // Skip Apple's leading header bytes (10) before the protobuf stream.
  const out = new Map();
  let p = 10;
  while (p < buf.length) {
    const [tag, np] = readVarint(buf, p); p = np;
    const field = Number(tag >> 3n); const wire = Number(tag & 7n);
    if (wire !== 2) { // only care about length-delimited WifiDevice (field 2)
      if (wire === 0) { const [, n2] = readVarint(buf, p); p = n2; continue; }
      break;
    }
    const [len, np2] = readVarint(buf, p); p = np2;
    const end = p + Number(len);
    if (field === 2) {
      // WifiDevice: field1 = mac string, field2 = Location submessage
      let q = p; let mac = null; let loc = null;
      while (q < end) {
        const [t, nq] = readVarint(buf, q); q = nq;
        const f = Number(t >> 3n); const w = Number(t & 7n);
        if (w !== 2) { if (w === 0) { const [, n3] = readVarint(buf, q); q = n3; continue; } break; }
        const [l, nq2] = readVarint(buf, q); q = nq2;
        if (f === 1) mac = buf.slice(q, q + Number(l)).toString('ascii');
        else if (f === 2) loc = parseLocation(buf, q, q + Number(l));
        q += Number(l);
      }
      if (mac && loc && loc.lat !== null && loc.lat !== UNKNOWN / 1e8) out.set(mac.toLowerCase(), loc);
    }
    p = end;
  }
  return out;
}

/**
 * @param {{bssid:string, rssi?:number}[]} aps
 * @returns {Promise<{located:boolean, lat?:number, lon?:number, accuracy?:number}>}
 */
export async function appleLocate(aps) {
  // Query the strongest few (short bodies keep the length prefix single-byte).
  const top = [...aps].sort((a, b) => (b.rssi ?? -100) - (a.rssi ?? -100)).slice(0, 5);
  const req = buildBody(top.map((a) => a.bssid.toLowerCase()));
  const r = await fetch(ENDPOINT, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'User-Agent': 'locationd/1753.17 CFNetwork/711.1.12 Darwin/14.0.0',
      'Accept-Charset': 'utf-8',
    },
    body: req,
    signal: AbortSignal.timeout(15000),
  });
  if (!r.ok) throw new Error(`apple ${r.status}`);
  const known = parseResponse(Buffer.from(await r.arrayBuffer()));

  // RSSI-weight the APs Apple actually knows. Closer AP (stronger signal) ->
  // more pull toward its surveyed point.
  let sw = 0; let lat = 0; let lon = 0; let bestAcc = Infinity;
  for (const ap of top) {
    const loc = known.get(ap.bssid.toLowerCase());
    if (!loc) continue;
    const w = Math.max(1, 100 + (ap.rssi ?? -80)); // -80dBm -> 20, -40 -> 60
    sw += w; lat += loc.lat * w; lon += loc.lon * w;
    if (loc.acc > 0) bestAcc = Math.min(bestAcc, loc.acc);
  }
  if (sw === 0) return { located: false };
  return { located: true, lat: lat / sw, lon: lon / sw, accuracy: Number.isFinite(bestAcc) ? bestAcc : 50 };
}
