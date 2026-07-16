// Owner dashboard — spec §5. All crypto is client-side: the password is
// typed here, keys are derived here, blobs are decrypted here, commands are
// signed here. The server only ever sees {payload, sig} and ciphertext.
// Geolocation (BSSID -> lat/lon) is proxied through our server (beacondb/
// Apple have no CORS); see server /v1/geolocate for the tradeoff.
//
// UI model: one persistent full-screen dark map as the canvas, with floating
// glass panels layered over it. Selecting a device plots its report trail.

import L from 'leaflet';
import 'leaflet/dist/leaflet.css';
import {
  deriveKeys, sealOpen, signCommand, wipe,
} from '../../crypto/ts/crypto.mjs';

const app = document.getElementById('app');
const GEOLOCATE = '/v1/geolocate';

const api = async (method, path, body) => {
  const res = await fetch(path, {
    method, headers: body ? { 'content-type': 'application/json' } : {},
    body: body && JSON.stringify(body),
  });
  if (res.status === 401) { renderLogin(); throw new Error('not logged in'); }
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || `HTTP ${res.status}`);
  return res.status === 204 ? null : res.json();
};

const h = (html) => { const t = document.createElement('template'); t.innerHTML = html.trim(); return t.content.firstChild; };
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

// Unambiguous contact code: no 0/O/1/I/L/B to avoid the "I typed it wrong"
// failure. Reads XXXX-XX, ~30 bits of entropy — plenty behind a lost Deck.
const CODE_ALPHABET = 'ACDEFGHJKMNPQRTUVWXYZ2346789';
function makeContactCode() {
  const buf = crypto.getRandomValues(new Uint8Array(6));
  const s = [...buf].map((b) => CODE_ALPHABET[b % CODE_ALPHABET.length]).join('');
  return `${s.slice(0, 4)}-${s.slice(4)}`;
}

// ------------------------------------------------------------- the map
let map = null;
let layerGroup = null;

function ensureMap() {
  if (map) return map;
  map = L.map('map', { zoomControl: true, attributionControl: true }).setView([20, 0], 2);
  const bases = {
    '🌑 Dark': L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
      attribution: '© OpenStreetMap © CARTO', maxZoom: 20, subdomains: 'abcd',
    }),
    '🛰 Satellite': L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}', {
      attribution: 'Tiles © Esri', maxZoom: 19,
    }),
    '🗺 Streets': L.tileLayer('https://{s}.basemaps.cartocdn.com/rastertiles/voyager/{z}/{x}/{y}{r}.png', {
      attribution: '© OpenStreetMap © CARTO', maxZoom: 20, subdomains: 'abcd',
    }),
  };
  // Remember the last choice; default to Dark (the good look).
  const saved = localStorage.getItem('fmsd_basemap');
  (bases[saved] || bases['🌑 Dark']).addTo(map);
  L.control.layers(bases, null, { position: 'bottomright', collapsed: true }).addTo(map);
  L.control.scale({ metric: true, imperial: true, position: 'bottomleft' }).addTo(map);
  map.on('baselayerchange', (e) => localStorage.setItem('fmsd_basemap', e.name));
  layerGroup = L.layerGroup().addTo(map);
  return map;
}

function markerIcon(latest) {
  const c = latest ? '#f2585b' : '#38bdf8';
  const size = latest ? 20 : 14;
  return L.divIcon({
    className: '', iconSize: [size, size], iconAnchor: [size / 2, size / 2],
    html: `<div class="pin ${latest ? 'pin-latest' : ''}" style="width:${size}px;height:${size}px;background:${c}"></div>`,
  });
}

// Markers for the currently plotted fixes, index-aligned with the fixes
// array (newest-first) so the history list can focus any one of them.
let fixMarkers = [];

// Great-circle distance in metres between [lat,lon] pairs.
function metersBetween(a, b) {
  const R = 6371000, toRad = Math.PI / 180;
  const dLat = (b[0] - a[0]) * toRad, dLon = (b[1] - a[1]) * toRad;
  const s = Math.sin(dLat / 2) ** 2
    + Math.cos(a[0] * toRad) * Math.cos(b[0] * toRad) * Math.sin(dLon / 2) ** 2;
  return 2 * R * Math.asin(Math.sqrt(s));
}

// Collapse fixes at the "same place" into one point. Two fixes are the same
// place when their centres fall within each other's error (or ~20 m floor) —
// Wi-Fi fixes jitter tens of metres while stationary, so this de-noises the
// map into places visited, each with a visit count and a time span.
function clusterFixes(fixes) {
  const clusters = [];
  for (const f of fixes) {
    const c = clusters.find((cl) =>
      metersBetween([cl.lat, cl.lon], [f.lat, f.lon]) <= Math.max(cl.accuracy, f.accuracy, 20));
    if (c) {
      c.members.push(f);
      c.lat = c.members.reduce((s, m) => s + m.lat, 0) / c.members.length;
      c.lon = c.members.reduce((s, m) => s + m.lon, 0) / c.members.length;
      c.accuracy = Math.min(c.accuracy, f.accuracy);
      c.first = Math.min(c.first, f.ts);
      c.last = Math.max(c.last, f.ts);
    } else {
      clusters.push({
        lat: f.lat, lon: f.lon, accuracy: f.accuracy, members: [f],
        first: f.ts, last: f.ts, ts: f.ts, batt: f.batt, ssid: f.ssid,
      });
    }
  }
  // ts = most recent sighting; keep clusters newest-first (fixes came in that order).
  clusters.forEach((c) => { c.ts = c.last; c.count = c.members.length; });
  return clusters;
}

function fixPopupHtml(f, latest, meta) {
  const span = f.count > 1
    ? `Seen ${f.count}× · ${new Date(f.first).toLocaleString()} → ${new Date(f.last).toLocaleString()}`
    : new Date(f.ts).toLocaleString();
  return `<div style="min-width:170px">
      <b style="color:${latest ? '#f2585b' : '#38bdf8'}">${latest ? '📍 Latest place' : 'Earlier place'}</b><br>
      ${meta.name ? `<b>${esc(meta.name)}</b><br>` : ''}
      ${span}<br>
      Accuracy ±${Math.round(f.accuracy)} m
      ${f.ssid ? `<br>Wi-Fi “${esc(f.ssid)}”` : ''}
      ${f.batt >= 0 ? `<br>Battery ${Math.round(f.batt * 100)}%` : ''}
    </div>`;
}

function plotFixes(fixes, meta = {}) {
  ensureMap();
  layerGroup.clearLayers();
  fixMarkers = [];
  if (!fixes.length) { map.setView([20, 0], 2); return; }
  const pts = fixes.map((f) => [f.lat, f.lon]); // newest-first
  if (pts.length > 1) {
    L.polyline([...pts].reverse(), { color: '#38bdf8', weight: 2, opacity: 0.5, dashArray: '4 6' }).addTo(layerGroup);
  }
  let latestMarker = null;
  fixes.forEach((f, i) => {
    const latest = i === 0;
    L.circle([f.lat, f.lon], { radius: f.accuracy, color: latest ? '#f2585b' : '#38bdf8', weight: 1, opacity: 0.4, fillOpacity: 0.06 }).addTo(layerGroup);
    const mk = L.marker([f.lat, f.lon], { icon: markerIcon(latest) }).addTo(layerGroup);
    mk.bindPopup(fixPopupHtml(f, latest, meta));
    fixMarkers[i] = mk;
    if (latest) latestMarker = mk;
  });
  // Zoom out a touch so the pin sits in context, not glued to the max zoom.
  if (pts.length > 1) map.fitBounds(pts, { padding: [160, 160], maxZoom: 15 });
  else map.setView(pts[0], 14);
  setTimeout(() => { map.invalidateSize(); if (latestMarker) latestMarker.openPopup(); }, 60);
}

// Pan to a plotted fix and open its popup (used by the history list).
function focusFix(i) {
  const mk = fixMarkers[i];
  if (!mk) return;
  map.setView(mk.getLatLng(), Math.max(map.getZoom(), 15), { animate: true });
  mk.openPopup();
}

// -------------------------------------------------------------- crypto
function askPassword(reason) {
  return new Promise((resolve) => {
    const dlg = h(`
      <dialog class="glass" style="border:1px solid var(--glass-brd);color:var(--ink);max-width:400px;background:var(--glass)">
        <form method="dialog">
          <p style="font-weight:700;font-size:18px">${esc(reason)}</p>
          <p class="muted" style="font-size:14px">Deriving takes a few seconds (Argon2id, 256&nbsp;MiB) — that's the protection.
          This password can't be reset: it <em>is</em> the key.</p>
          <label>Recovery password</label>
          <input type="password" name="pw" autofocus required minlength="1">
          <div class="row" style="margin-top:16px;justify-content:flex-end">
            <button type="button" class="ghost" id="pwcancel">Cancel</button>
            <button value="ok" class="primary">Continue</button>
          </div>
        </form>
      </dialog>`);
    dlg.style.background = 'var(--glass)';
    // Cancel is a plain button (not a submit) so Enter triggers the sole
    // submit — Continue — instead of closing on the first button.
    dlg.querySelector('#pwcancel').onclick = () => { dlg.returnValue = 'cancel'; dlg.close('cancel'); };
    document.body.append(dlg);
    dlg.addEventListener('close', () => {
      const pw = dlg.returnValue === 'ok' ? dlg.querySelector('input').value : null;
      dlg.remove();
      resolve(pw || null);
    });
    dlg.showModal();
  });
}

async function deriveFor(deviceId, reason) {
  const pw = await askPassword(reason);
  if (!pw) return null;
  const { salt, kdf, box_pk, counter } = await api('GET', `/v1/salt/${deviceId}`);
  const keys = await deriveKeys(pw, salt, kdf);
  return { keys, box_pk, counter };
}

// ---------------------------------------------------- geolocation + cache
function apKey(wifi) { return wifi.map((ap) => ap.bssid).sort().join(','); }
function cacheGet(key) { try { return JSON.parse(localStorage.getItem('fmsd_fix_' + key) || 'null'); } catch { return null; } }
function cacheSet(key, val) { try { localStorage.setItem('fmsd_fix_' + key, JSON.stringify(val)); } catch { /* quota */ } }

async function resolveWifi(wifi) {
  if (!wifi.length) return null;
  const key = apKey(wifi);
  const cached = cacheGet(key);
  if (cached !== null) return cached.located ? cached : null;
  const res = await fetch(GEOLOCATE, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ wifiAccessPoints: wifi.map((ap) => ({ macAddress: ap.bssid, signalStrength: ap.rssi, channel: ap.ch })) }),
  });
  if (!res.ok) return null;
  const data = await res.json();
  if (!data.located) { cacheSet(key, { located: false }); return null; }
  const fix = { located: true, lat: data.lat, lon: data.lon, accuracy: data.accuracy };
  cacheSet(key, fix);
  return fix;
}

function btRecurrence(reports) {
  const seen = new Map();
  for (const r of reports) for (const b of (r.bt || [])) seen.set(b.mac, (seen.get(b.mac) || 0) + 1);
  return [...seen.entries()].filter(([, n]) => n > 1).sort((a, b) => b[1] - a[1]);
}

// ============================================================ views
function renderLogin() {
  // Cinematic hero: a live dark map with an animated radar pin and a decrypted
  // trail leading into it, echoing the product. Glass panels float above.
  ensureMap();
  layerGroup.clearLayers();
  const hero = [30.2672, -97.7431];
  // Center west of the pin so the radar sits in the visible right half,
  // clear of the left hero panel — a "mission control" look.
  map.setView([hero[0], hero[1] - 0.019], 15, { animate: false });
  // A decrypted-looking trail leading into the live radar pin.
  const trail = [
    [30.2607, -97.7392], [30.2631, -97.7405], [30.2653, -97.7419], [hero[0], hero[1]],
  ];
  L.polyline(trail, { color: '#38bdf8', weight: 2.5, opacity: 0.7, dashArray: '3 8' }).addTo(layerGroup);
  trail.slice(0, -1).forEach((p) =>
    L.marker(p, { icon: markerIcon(false), interactive: false }).addTo(layerGroup));
  L.circle(hero, { radius: 140, color: '#f2585b', weight: 1, opacity: 0.35, fillColor: '#f2585b', fillOpacity: 0.05 }).addTo(layerGroup);
  L.marker(hero, { icon: radarIcon(), interactive: false }).addTo(layerGroup);
  setTimeout(() => map.invalidateSize(), 60);

  injectLoginFx();
  const feature = (icon, title, body) => `
    <div class="lf-feat">
      <div class="lf-feat-ic">${icon}</div>
      <div><div class="lf-feat-t">${title}</div><div class="muted lf-feat-b">${body}</div></div>
    </div>`;
  const chip = (t) => `<span class="lf-chip">${t}</span>`;

  // pointer-events:none on the scrim lets the map stay pannable; each panel
  // re-enables events so its controls work.
  app.replaceChildren(h(`
    <div class="lf-root">
      <div class="lf-glow"></div>
      <div class="lf-wrap">

        <header class="glass lf-nav">
          <div class="brand"><span class="logo">🛰</span> Find My Deck</div>
          <div class="row" style="gap:10px">
            <a href="https://github.com/echohtp/findmydeck" target="_blank" rel="noopener"><button class="ghost lf-gh">★ GitHub</button></a>
            <a href="/auth/steam"><button class="primary">Sign in with Steam</button></a>
          </div>
        </header>

        <div class="lf-hero">
          <div class="glass lf-card">
            <div class="lf-eyebrow"><span class="lf-live"></span> ZERO-KNOWLEDGE · FIND MY DEVICE</div>
            <h1 class="lf-h1">Find your Steam&nbsp;Deck.<br><span class="lf-grad">Nobody else can.</span></h1>
            <p class="muted lf-sub">
              A find-my-device plugin for the Deck, built zero-knowledge. Your Deck seals its own
              location — the server stores ciphertext it can’t read, and only your password unlocks it.
            </p>
            <div class="lf-cta">
              <a href="/auth/steam"><button class="primary lf-primary">Sign in with Steam</button></a>
              <a href="/findmydeck-plugin.zip"><button class="lf-ghost2">↓ Download the plugin</button></a>
            </div>
            <div class="lf-chips">
              ${chip('🔒 Sealed reports')}${chip('🗺 Decrypts in your browser')}${chip('🔑 Your key alone')}
            </div>
            <div class="lf-feats">
              ${feature('🗺️', 'See where it’s been', 'Sealed Wi-Fi scans decrypt only in your browser, then plot a trail on the map.')}
              ${feature('📢', 'Ring &amp; recover', 'Play a sound to find it nearby, or flip it to Lost with a private finder chat.')}
              ${feature('🔒', 'Only you hold the key', 'Your password derives the keys. A full server breach still can’t track a thing.')}
            </div>
          </div>
        </div>

        <p class="faint lf-foot">
          Zero-knowledge by design · Steam login only reveals your public ID · <a href="/privacy">Privacy</a> · <a href="https://github.com/echohtp/findmydeck" target="_blank" rel="noopener">GitHub</a>
        </p>
      </div>
    </div>`));
}

// Animated radar pin for the hero map — expanding rings + a glowing core.
function radarIcon() {
  return L.divIcon({
    className: '', iconSize: [44, 44], iconAnchor: [22, 22],
    html: `<div class="lf-radar"><span class="lf-ring"></span><span class="lf-ring lf-ring2"></span><span class="lf-core"></span></div>`,
  });
}

let loginFxInjected = false;
function injectLoginFx() {
  if (loginFxInjected) return;
  loginFxInjected = true;
  document.head.append(h(`<style>
    .lf-root{position:fixed;inset:0;z-index:20;overflow:hidden;pointer-events:none;
      background:linear-gradient(90deg, rgba(7,10,18,.94) 0%, rgba(7,10,18,.86) 32%, rgba(7,10,18,.45) 62%, rgba(7,10,18,.18) 100%)}
    .lf-glow{position:fixed;top:-24vh;left:8vw;width:70vw;height:70vh;pointer-events:none;
      background:radial-gradient(closest-side, rgba(56,189,248,.14), transparent 70%);filter:blur(24px)}
    .lf-wrap{height:100%;display:flex;flex-direction:column;padding:16px clamp(14px,4vw,44px) 16px;box-sizing:border-box}
    .lf-nav{pointer-events:auto;display:flex;justify-content:space-between;align-items:center;padding:10px 16px;border-radius:14px;flex:none}
    .lf-gh{font-size:13px}
    .lf-hero{flex:1;min-height:0;display:flex;align-items:center;justify-content:flex-start;padding:1.5vh 0}
    .lf-card{pointer-events:auto;max-width:480px;width:100%;padding:clamp(20px,2.6vw,32px);text-align:left;position:relative;
      border-radius:22px;box-shadow:0 30px 90px rgba(0,0,0,.6);animation:lf-rise .7s cubic-bezier(.2,.8,.2,1) both}
    .lf-card::before{content:"";position:absolute;inset:0;border-radius:22px;padding:1px;pointer-events:none;
      background:linear-gradient(140deg, rgba(56,189,248,.55), rgba(139,92,246,.35) 40%, transparent 70%);
      -webkit-mask:linear-gradient(#000 0 0) content-box,linear-gradient(#000 0 0);-webkit-mask-composite:xor;mask-composite:exclude}
    .lf-eyebrow{display:inline-flex;align-items:center;gap:8px;font-size:11px;font-weight:700;letter-spacing:1.5px;
      color:var(--accent);background:rgba(56,189,248,.10);border:1px solid rgba(56,189,248,.22);
      padding:5px 11px;border-radius:999px}
    .lf-live{width:7px;height:7px;border-radius:50%;background:#34d399;box-shadow:0 0 0 0 rgba(52,211,153,.7);animation:lf-blip 1.8s infinite}
    .lf-h1{font-size:clamp(28px,4.2vw,44px);line-height:1.05;margin:12px 0 10px;letter-spacing:-1px;font-weight:800}
    .lf-grad{background:linear-gradient(100deg,#7dd3fc,#38bdf8 40%,#818cf8);-webkit-background-clip:text;background-clip:text;
      -webkit-text-fill-color:transparent;background-size:200% auto;animation:lf-shine 6s linear infinite}
    .lf-sub{font-size:15.5px;line-height:1.55;margin:0;max-width:440px}
    .lf-cta{margin-top:20px;display:flex;gap:12px;justify-content:flex-start;flex-wrap:wrap}
    .lf-primary{font-size:15px;padding:12px 22px;box-shadow:0 10px 30px rgba(56,189,248,.35)}
    .lf-primary:hover{transform:translateY(-1px)}
    .lf-ghost2{font-size:15px;padding:12px 20px;background:rgba(255,255,255,.05)}
    .lf-chips{display:flex;gap:8px;justify-content:flex-start;flex-wrap:wrap;margin-top:14px}
    .lf-chip{font-size:12px;color:var(--ink-dim);background:rgba(255,255,255,.05);border:1px solid var(--glass-brd);
      padding:5px 11px;border-radius:999px}
    .lf-feats{display:grid;grid-template-columns:1fr 1fr 1fr;gap:14px;margin-top:18px;padding-top:16px;border-top:1px solid var(--glass-brd);text-align:left}
    .lf-feat{display:flex;flex-direction:column;gap:5px;align-items:flex-start}
    .lf-feat-ic{font-size:19px;line-height:1}
    .lf-feat-t{font-weight:700;font-size:13px;line-height:1.25}
    .lf-feat-b{font-size:11.5px;line-height:1.45}
    .lf-foot{pointer-events:auto;text-align:center;margin:0;flex:none;font-size:10.5px}
    @media(max-height:720px){.lf-feat-b{display:none}.lf-h1{font-size:clamp(26px,3.6vw,38px)}.lf-sub{font-size:14.5px}}
    @media(max-width:560px){.lf-feats{grid-template-columns:1fr}.lf-feat{flex-direction:row;gap:10px}}
    .lf-radar{position:relative;width:26px;height:26px}
    .lf-radar .lf-core{position:absolute;inset:9px;border-radius:50%;background:#f2585b;box-shadow:0 0 14px 3px rgba(242,88,91,.8)}
    .lf-radar .lf-ring{position:absolute;inset:0;border-radius:50%;border:2px solid rgba(242,88,91,.7);animation:lf-radar 2.4s ease-out infinite}
    .lf-radar .lf-ring2{animation-delay:1.2s}
    @keyframes lf-radar{0%{transform:scale(.3);opacity:.9}100%{transform:scale(1.6);opacity:0}}
    @keyframes lf-blip{0%{box-shadow:0 0 0 0 rgba(52,211,153,.6)}70%{box-shadow:0 0 0 7px rgba(52,211,153,0)}100%{box-shadow:0 0 0 0 rgba(52,211,153,0)}}
    @keyframes lf-shine{to{background-position:200% center}}
    @keyframes lf-rise{from{opacity:0;transform:translateY(16px) scale(.985)}to{opacity:1;transform:none}}
    @media(prefers-reduced-motion:reduce){.lf-card,.lf-grad,.lf-live,.lf-radar .lf-ring{animation:none}}
  </style>`));
}

let devices = [];
let selectedId = null;
let drawerOpen = false; // device controls collapsed until the row is clicked

// Build the collapsible controls drawer for one Deck. The drawer element is
// passed to the flows as their container, so #pout stays scoped to it.
// Plain-language reporting health from last_seen (no decryption needed).
function deviceHealth(d) {
  if (!d.last_seen) return { cls: 'idle', text: 'No reports yet — open Find My Deck on the Deck to send one.' };
  const age = Date.now() - d.last_seen;
  if (age < 2 * 3600 * 1000) return { cls: 'ok', text: `✓ Reporting normally · last check-in ${timeAgo(d.last_seen)}` };
  return { cls: 'warn', text: `⚠ Quiet · last check-in ${timeAgo(d.last_seen)} (Deck may be asleep or off)` };
}

function buildDeviceDrawer(d) {
  const drawer = h('<div class="drawer col"></div>');
  const hp = deviceHealth(d);
  drawer.append(h(`<div class="health ${hp.cls}">${hp.text}</div>`));

  const seg = h('<div><label>Mode</label><div class="seg"></div></div>');
  for (const m of ['normal', 'lost']) {
    const b = h(`<button class="${m === d.mode ? 'on ' + m : ''}">${m === 'normal' ? 'Normal' : 'Lost'}</button>`);
    b.onclick = () => setMode(d, m, drawer);
    seg.querySelector('.seg').append(b);
  }
  drawer.append(seg);
  drawer.append(h('<input id="lostmsg" placeholder="Message shown to finder (lost mode)">'));

  const ring = h('<button class="primary" style="width:100%">🔊 Play sound on Deck</button>');
  ring.onclick = async () => {
    const out = drawer.querySelector('#pout');
    const flash = (html) => { out.innerHTML = html; setTimeout(() => { if (out.innerHTML === html) out.innerHTML = ''; }, 4000); };
    try { await api('PUT', `/v1/ring/${d.device_id}`); flash('<div class="glass" style="padding:10px">🔊 Ringing the Deck…</div>'); }
    catch (e) { flash(`<div style="color:var(--stolen)">${esc(e.message)}</div>`); }
  };
  drawer.append(ring);

  const actions = h('<div class="row"></div>');
  const locate = h('<button class="primary" style="flex:1">📍 Locate</button>');
  locate.onclick = () => locateFlow(d, drawer);
  const msgs = h(`<button style="flex:1">✉ Messages${hasUnread(d) ? ' <span class="badge">new</span>' : ''}</button>`);
  msgs.onclick = () => {
    markSeen(d);
    app.querySelectorAll('.badge').forEach((b) => b.remove());
    relayFlow(d, drawer);
  };
  actions.append(locate, msgs);
  drawer.append(actions);

  const revoke = h('<button class="ghost danger" style="width:100%">Revoke this Deck</button>');
  revoke.onclick = async () => {
    if (!confirm(`Revoke "${d.name}"? Deletes its token and all reports.`)) return;
    await api('DELETE', `/v1/devices/${d.device_id}`);
    drawerOpen = false;
    await loadDevices(false);
  };
  drawer.append(revoke);
  drawer.append(h('<div id="pout" class="col"></div>'));
  return drawer;
}

async function loadDevices(keepSelection = true) {
  devices = await api('GET', '/v1/devices');
  if (!keepSelection || !devices.find((d) => d.device_id === selectedId)) {
    selectedId = devices[0]?.device_id || null;
  }
  renderShell();
}

function selected() { return devices.find((d) => d.device_id === selectedId) || null; }

// Unread = a finder message newer than the last time the owner opened the
// thread for this device (tracked locally).
function seenTs(id) { return Number(localStorage.getItem('fmsd_seen_' + id) || 0); }
function markSeen(d) { if (d.last_finder_msg) localStorage.setItem('fmsd_seen_' + d.device_id, String(d.last_finder_msg)); }
function hasUnread(d) { return d.last_finder_msg && d.last_finder_msg > seenTs(d.device_id); }

function renderShell() {
  ensureMap();
  const d = selected();
  const panel = h(`
    <div class="layer tl glass panel col" style="padding:0">
      <div class="panel-hd">
        <div class="brand"><span class="logo">🛰</span> Find My Deck</div>
        <div class="row" style="gap:6px">
          <button class="ghost" id="alerts" title="Alerts">🔔</button>
          <button class="ghost" id="logout" title="Sign out">⎋</button>
        </div>
      </div>
      <div class="panel-bd col" id="pbody"></div>
      <div style="padding:12px 16px;border-top:1px solid var(--glass-brd)">
        <button class="primary" id="enroll" style="width:100%">+ Enroll a new Deck</button>
        <div id="paircode"></div>
        <div class="row faint" style="justify-content:center;gap:14px;margin-top:10px;font-size:11px">
          <a href="/privacy" target="_blank" rel="noopener">Privacy</a>
          <a href="https://github.com/echohtp/findmydeck" target="_blank" rel="noopener">GitHub</a>
          <a href="#" id="delacct" style="color:var(--stolen)">Delete account</a>
        </div>
      </div>
    </div>`);
  const body = panel.querySelector('#pbody');

  // Device list — each row is a header; clicking it opens a drawer with that
  // Deck's controls (collapsed by default, so the panel stays compact).
  if (!devices.length) body.append(h('<div class="empty">No Decks enrolled yet.</div>'));
  for (const dev of devices) {
    const isSel = dev.device_id === selectedId;
    const open = isSel && drawerOpen;
    const btn = h(`
      <button class="devbtn ${isSel ? 'active' : ''} ${open ? 'open' : ''}">
        <span class="dot ${esc(dev.mode)}"></span>
        <span style="flex:1">
          <div style="font-weight:600">${esc(dev.name)}${hasUnread(dev) ? ' <span class="badge">new</span>' : ''}</div>
          <div class="faint">${dev.last_seen ? 'seen ' + timeAgo(dev.last_seen) : 'never seen'}</div>
        </span>
        <span class="pill ${esc(dev.mode)}">${esc(dev.mode)}</span>
        <span class="chev">▸</span>
      </button>`);
    btn.onclick = () => {
      if (dev.device_id === selectedId) { drawerOpen = !drawerOpen; }
      else { selectedId = dev.device_id; drawerOpen = true; }
      renderShell();
      if (drawerOpen) autoLocate();
    };
    body.append(btn);
    if (open) body.append(buildDeviceDrawer(dev));
  }

  panel.querySelector('#logout').onclick = async () => { await api('POST', '/auth/logout'); location.reload(); };
  panel.querySelector('#alerts').onclick = () => alertsModal();
  panel.querySelector('#enroll').onclick = () => enrollFlow(panel.querySelector('#paircode'));
  panel.querySelector('#delacct').onclick = (e) => { e.preventDefault(); deleteAccountFlow(); };
  app.replaceChildren(panel);
}

// Irreversible: wipe every device, report, relay thread and setting. Double
// confirm (typed) because there is no undo and no server-side backup.
async function deleteAccountFlow() {
  const n = devices.length;
  if (!confirm(`Delete your account and ALL data?\n\nThis erases ${n} enrolled Deck${n === 1 ? '' : 's'}, every sealed report, all recovery chats, and your alert settings. It cannot be undone.`)) return;
  const typed = prompt('This is permanent. Type DELETE to confirm.');
  if (typed !== 'DELETE') return;
  try {
    await api('DELETE', '/v1/account');
    location.reload();
  } catch (e) { alert(`Could not delete: ${e.message}`); }
}

// Alerts settings: a webhook sink (Discord/Slack/ntfy/custom) + optional
// email. Alerts fire on metadata only — finder messages and Lost-Deck
// check-ins — so this never weakens the zero-knowledge guarantee.
async function alertsModal() {
  let cur = { webhook: '' };
  try { cur = await api('GET', '/v1/notify'); } catch { /* show blank */ }
  const dlg = h(`
    <dialog class="glass" style="border:1px solid var(--glass-brd);color:var(--ink);max-width:440px;background:var(--glass)">
      <div style="font-weight:700;font-size:18px;margin-bottom:2px">🔔 Alerts</div>
      <p class="muted" style="font-size:13px;margin-top:4px">
        Get pinged when a finder messages you or a Lost Deck checks in or goes quiet. Metadata only — never your location.</p>
      <label>Webhook URL <span class="faint">(Discord / Slack / ntfy / any https)</span></label>
      <input id="wh" placeholder="https://discord.com/api/webhooks/…" value="${esc(cur.webhook)}">
      <div class="faint" style="font-size:11.5px;margin-top:6px">Tip: a Discord channel → Integrations → Webhooks gives you a URL in seconds.</div>
      <div id="amsg" class="faint" style="min-height:16px;margin-top:8px"></div>
      <div class="row" style="margin-top:8px;justify-content:space-between">
        <button class="ghost" id="atest" type="button">Send test</button>
        <div class="row" style="gap:8px">
          <button class="ghost" id="acancel" type="button">Close</button>
          <button class="primary" id="asave" type="button">Save</button>
        </div>
      </div>
    </dialog>`);
  document.body.append(dlg);
  const msg = dlg.querySelector('#amsg');
  const vals = () => ({ webhook: dlg.querySelector('#wh').value.trim() });
  dlg.querySelector('#asave').onclick = async () => {
    try { await api('PUT', '/v1/notify', vals()); msg.textContent = '✅ Saved.'; }
    catch (e) { msg.textContent = e.message; }
  };
  dlg.querySelector('#atest').onclick = async () => {
    msg.textContent = 'Saving + sending…';
    try { await api('PUT', '/v1/notify', vals()); await api('POST', '/v1/notify/test'); msg.textContent = '📨 Test sent — check your sink.'; }
    catch (e) { msg.textContent = e.message; }
  };
  dlg.querySelector('#acancel').onclick = () => { dlg.close(); dlg.remove(); };
  dlg.showModal();
}

function timeAgo(ts) {
  const s = Math.floor((Date.now() - ts) / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

async function enrollFlow(out) {
  try {
    const { code, expires_in } = await api('POST', '/v1/pair');
    const until = Date.now() + expires_in * 1000;
    out.innerHTML = '';
    const box = h(`<div class="glass" style="margin-top:10px;padding:12px;text-align:center">
      <div class="faint">Enter on the Deck → Find My Deck</div>
      <div class="toast-code">${esc(code)}</div>
      <div class="faint" id="cd"></div>
    </div>`);
    out.append(box);
    const cd = box.querySelector('#cd');
    const tick = () => {
      const left = Math.max(0, Math.round((until - Date.now()) / 1000));
      cd.textContent = left ? `expires in ${Math.floor(left / 60)}:${String(left % 60).padStart(2, '0')}` : 'expired';
      if (left) setTimeout(tick, 1000);
    };
    tick();
  } catch (e) { out.innerHTML = `<div class="faint" style="color:var(--stolen)">${esc(e.message)}</div>`; }
}

async function setMode(d, mode, body) {
  const out = body.querySelector('#pout');
  out.innerHTML = '<div class="row"><span class="spin"></span> Signing…</div>';
  try {
    const ctx = await deriveFor(d.device_id, `Set "${d.name}" to ${mode.toUpperCase()}`);
    if (!ctx) { out.innerHTML = ''; return; }
    const contact = mode === 'lost' ? makeContactCode() : '';
    const { payload, sig } = await signCommand({
      mode, counter: ctx.counter + 1, issued_at: Date.now(),
      message: (body.querySelector('#lostmsg')?.value || '').slice(0, 200), contact,
    }, ctx.keys.signSk);
    wipe(ctx.keys.boxSk, ctx.keys.signSk);
    await api('PUT', `/v1/command/${d.device_id}`, { payload, sig });
    out.innerHTML = `<div class="glass" style="padding:10px">✅ Signed — applies next time the Deck is online${contact ? `.<br>Finder code: <b>${contact}</b>` : '.'}</div>`;
    await loadDevices();
  } catch (e) { out.innerHTML = `<div style="color:var(--stolen)">${esc(e.message)}</div>`; }
}

async function locateFlow(d, body) {
  const out = body.querySelector('#pout');
  out.innerHTML = '<div class="row"><span class="spin"></span> Deriving key…</div>';
  try {
    const ctx = await deriveFor(d.device_id, `Decrypt locations for "${d.name}"`);
    if (!ctx) { out.innerHTML = ''; return; }
    const rows = await api('GET', `/v1/reports/${d.device_id}?limit=100`);
    const reports = [];
    for (const r of rows) {
      try { reports.push({ at: r.received_at, ...JSON.parse(await sealOpen(r.blob, ctx.box_pk, ctx.keys.boxSk)) }); } catch { /* old key gen */ }
    }
    wipe(ctx.keys.boxSk, ctx.keys.signSk);
    if (!reports.length) { out.innerHTML = '<div class="empty">No decryptable reports yet.</div>'; plotFixes([]); return; }
    reports.sort((a, b) => b.at - a.at);
    out.innerHTML = '<div class="row"><span class="spin"></span> Resolving Wi-Fi…</div>';

    const fixes = [];
    let noMatch = 0;
    for (const r of reports.slice(0, 100)) {
      try { const f = await resolveWifi(r.wifi || []); if (f) fixes.push({ ...f, ts: r.ts, batt: r.batt, ssid: r.ssid }); else noMatch += 1; } catch { noMatch += 1; }
    }
    // Collapse jittery same-place pings into distinct places before plotting.
    const places = clusterFixes(fixes);
    plotFixes(places, { name: d.name });

    const recurring = btRecurrence(reports);
    out.innerHTML = '';
    out.append(closeBar(out, 'Location'));
    out.append(h(`<div class="glass" style="padding:12px">
      <div class="kv"><span class="k">Places</span><span class="v">${places.length}</span></div>
      <div class="kv"><span class="k">Latest place</span><span class="v">${places[0] ? '±' + Math.round(places[0].accuracy) + 'm' : '—'}</span></div>
      <div class="kv"><span class="k">Reports</span><span class="v">${reports.length}</span></div>
      ${noMatch ? `<div class="kv"><span class="k">No Wi-Fi match</span><span class="v">${noMatch}</span></div>` : ''}
    </div>`));
    if (!places.length) {
      out.append(h(`<div class="faint">No Wi-Fi-based fix yet. beacondb/Apple didn't recognize these access points — a scan with more nearby networks, or a busier area, resolves better.</div>`));
    }
    if (recurring.length) {
      out.append(h(`<div class="glass" style="padding:10px">
        <div class="faint" style="margin-bottom:4px">Recurring Bluetooth (travelling with the Deck)</div>
        ${recurring.map(([mac, n]) => `<div class="kv"><span class="k">${esc(mac)}</span><span class="v">×${n}</span></div>`).join('')}
      </div>`));
    }

    // History — distinct places over the retained window (7 days), newest
    // first. Nearby jittery pings are clustered into one place with a visit
    // count. Click a row to fly the map to it.
    if (places.length) {
      const hist = h(`<div class="glass" style="padding:10px">
        <div class="faint" style="margin-bottom:6px">History · ${places.length} place${places.length > 1 ? 's' : ''} (last 7 days)</div>
        <div class="histlist"></div></div>`);
      const list = hist.querySelector('.histlist');
      places.forEach((p, i) => {
        const visits = p.count > 1 ? `${p.count} pings · ` : '';
        const row = h(`<button class="histrow${i === 0 ? ' latest' : ''}" title="${esc(new Date(p.first).toLocaleString())} → ${esc(new Date(p.last).toLocaleString())}">
          <span class="hr-dot"></span>
          <span class="hr-main">
            <span class="hr-when">${i === 0 ? 'Latest · ' : ''}${timeAgo(p.last)}</span>
            <span class="hr-sub">${p.ssid ? '📶 ' + esc(p.ssid) + ' · ' : ''}${visits}±${Math.round(p.accuracy)} m${p.batt >= 0 ? ' · 🔋 ' + Math.round(p.batt * 100) + '%' : ''}</span>
          </span></button>`);
        row.onclick = () => focusFix(i);
        list.append(row);
      });
      out.append(hist);
    }
  } catch (e) { out.innerHTML = `<div style="color:var(--stolen)">${esc(e.message)}</div>`; }
}

function closeBar(out, title) {
  const bar = h(`<div class="row" style="justify-content:space-between"><label style="margin:0">${esc(title)}</label><button class="ghost" style="padding:2px 10px">✕ Close</button></div>`);
  bar.querySelector('button').onclick = () => { out.innerHTML = ''; };
  return bar;
}

async function relayFlow(d, body) {
  const out = body.querySelector('#pout');
  out.innerHTML = '<div class="row"><span class="spin"></span> Loading…</div>';
  try {
    const msgs = await api('GET', `/v1/relay/${d.device_id}`);
    if (!msgs.length) {
      out.replaceChildren(closeBar(out, 'Messages'), h(`<div class="faint">No finder messages yet. In lost mode a finder can reach you at
        <code>${location.host}/found/&lt;code&gt;</code> — no contact details are exchanged.</div>`));
      return;
    }
    const threads = {};
    for (const m of msgs) (threads[m.contact] ||= []).push(m);
    const wrap = h('<div class="col"></div>');
    wrap.append(closeBar(out, 'Messages'));
    for (const [code, thread] of Object.entries(threads)) {
      const box = h(`<div class="glass" style="padding:10px">
        <div class="faint">Thread ${esc(code)} · ${location.host}/found/${esc(code)}</div></div>`);
      for (const m of thread) {
        box.append(h(`<div class="msg ${m.sender}">${esc(m.body)}<div class="faint">${m.sender === 'owner' ? 'you' : 'finder'} · ${new Date(m.created_at).toLocaleString()}</div></div>`));
      }
      const reply = h('<div class="row" style="margin-top:8px"><input placeholder="Reply" style="flex:1"><button class="primary">Send</button></div>');
      reply.querySelector('button').onclick = async () => {
        const b = reply.querySelector('input').value.trim();
        if (!b) return;
        await api('POST', `/v1/relay/${d.device_id}`, { contact: code, body: b });
        relayFlow(d, body);
      };
      box.append(reply);
      wrap.append(box);
    }
    out.replaceChildren(wrap);
  } catch (e) { out.innerHTML = `<div style="color:var(--stolen)">${esc(e.message)}</div>`; }
}

// Auto-clear the map when switching devices (reports need the password).
function autoLocate() { ensureMap(); layerGroup && layerGroup.clearLayers(); map.setView([20, 0], 2); }

// ---------------------------------------------------------------- boot
async function main() {
  ensureMap();
  try {
    await api('GET', '/v1/me');
    await loadDevices();
    // Poll so a new finder message badges without a manual reload — but not
    // while a sub-panel (Messages/Locate) is open, to avoid wiping it.
    setInterval(() => {
      const pout = document.getElementById('pout');
      if (devices.length && !(pout && pout.innerHTML.trim())) loadDevices().catch(() => {});
    }, 30000);
  } catch { /* renderLogin shown on 401 */ }
}
main();
