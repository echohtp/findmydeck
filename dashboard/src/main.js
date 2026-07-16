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

function plotFixes(fixes, meta = {}) {
  ensureMap();
  layerGroup.clearLayers();
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
    const when = new Date(f.ts).toLocaleString();
    mk.bindPopup(`<div style="min-width:160px">
        <b style="color:${latest ? '#f2585b' : '#38bdf8'}">${latest ? '📍 Latest position' : 'Earlier position'}</b><br>
        ${meta.name ? `<b>${esc(meta.name)}</b><br>` : ''}
        ${when}<br>
        Accuracy ±${Math.round(f.accuracy)} m
        ${f.batt >= 0 ? `<br>Battery ${Math.round(f.batt * 100)}%` : ''}
      </div>`);
    if (latest) latestMarker = mk;
  });
  // Zoom out a touch so the pin sits in context, not glued to the max zoom.
  if (pts.length > 1) map.fitBounds(pts, { padding: [160, 160], maxZoom: 15 });
  else map.setView(pts[0], 14);
  setTimeout(() => { map.invalidateSize(); if (latestMarker) latestMarker.openPopup(); }, 60);
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
  ensureMap();
  const feature = (icon, title, body) => `
    <div class="glass" style="padding:20px;flex:1;min-width:220px">
      <div style="font-size:28px">${icon}</div>
      <div style="font-weight:700;font-size:18px;margin:6px 0 4px">${title}</div>
      <div class="muted">${body}</div>
    </div>`;
  const step = (n, title, body) => `
    <div style="display:flex;gap:14px;align-items:flex-start">
      <div style="flex:none;width:32px;height:32px;border-radius:50%;background:var(--accent);color:var(--accent-ink);font-weight:800;display:grid;place-items:center">${n}</div>
      <div><div style="font-weight:600">${title}</div><div class="muted">${body}</div></div>
    </div>`;

  app.replaceChildren(h(`
    <div style="position:fixed;inset:0;z-index:20;overflow-y:auto;
                background:radial-gradient(1100px 600px at 50% -5%, rgba(20,38,58,.94), rgba(10,15,24,.97) 60%)">
      <div style="max-width:920px;margin:0 auto;padding:6vh 20px 40px">

        <header style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8vh">
          <div class="brand"><span class="logo">🛰</span> Find My Deck</div>
          <a href="/auth/steam"><button class="primary">Sign in with Steam</button></a>
        </header>

        <div style="text-align:center;max-width:720px;margin:0 auto">
          <div style="font-size:56px">🛰</div>
          <h1 style="font-size:40px;line-height:1.1;margin:12px 0 10px">Find your Steam Deck.<br>Even if someone took it.</h1>
          <p style="font-size:18px" class="muted">
            A zero-knowledge anti-theft plugin. The server stores only ciphertext it can't read —
            location and control belong to you and your password alone.
          </p>
          <div style="margin-top:22px;display:flex;gap:12px;justify-content:center;flex-wrap:wrap">
            <a href="/auth/steam"><button class="primary" style="font-size:16px;padding:12px 22px">Sign in with Steam</button></a>
            <a href="/findmydeck-plugin.zip"><button style="font-size:16px;padding:12px 22px">Download the plugin</button></a>
          </div>
        </div>

        <div style="display:flex;gap:14px;flex-wrap:wrap;margin:9vh 0 0">
          ${feature('🗺️', 'Locate on a map', 'Sealed Wi-Fi scans decrypt only in your browser, then plot a live trail — the server never sees where your Deck is.')}
          ${feature('📢', 'Ring & recover', 'Play a sound to find it nearby, or flip it to Lost for a full-screen banner and a private chat with whoever has it.')}
          ${feature('🔒', 'Only you hold the key', 'Your password derives the keys that decrypt reports and sign commands. A full server breach still can’t read or track a thing.')}
        </div>

        <div class="glass" style="padding:26px;margin-top:22px">
          <h2 style="margin-top:0;font-size:24px">How it works</h2>
          <div style="display:flex;flex-direction:column;gap:16px;margin-top:14px">
            ${step(1, 'Install the Decky plugin', 'On your Steam Deck, install from URL and enroll with a 6-digit pair code.')}
            ${step(2, 'Pick a recovery password', 'Derived on-device into keys that never leave it. We literally cannot reset it — that’s the point.')}
            ${step(3, 'Lose it? Locate, ring, or chat', 'From here you track it on a map, ring it, or open a private line to an honest finder — no personal details shared.')}
          </div>
        </div>

        <p class="faint" style="text-align:center;margin-top:28px">
          Zero-knowledge by design · Steam login only reveals your public ID · Your password is unrecoverable on purpose
        </p>
      </div>
    </div>`));
}

let devices = [];
let selectedId = null;

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
        <button class="ghost" id="logout" title="Sign out">⎋</button>
      </div>
      <div class="panel-bd col" id="pbody"></div>
      <div style="padding:12px 16px;border-top:1px solid var(--glass-brd)">
        <button class="primary" id="enroll" style="width:100%">+ Enroll a new Deck</button>
        <div id="paircode"></div>
      </div>
    </div>`);
  const body = panel.querySelector('#pbody');

  // device switcher (collapses to nothing when only one, but still shown for clarity)
  if (!devices.length) body.append(h('<div class="empty">No Decks enrolled yet.</div>'));
  for (const dev of devices) {
    const btn = h(`
      <button class="devbtn ${dev.device_id === selectedId ? 'active' : ''}">
        <span class="dot ${esc(dev.mode)}"></span>
        <span style="flex:1">
          <div style="font-weight:600">${esc(dev.name)}${hasUnread(dev) ? ' <span class="badge">new</span>' : ''}</div>
          <div class="faint">${dev.last_seen ? 'seen ' + timeAgo(dev.last_seen) : 'never seen'}</div>
        </span>
        <span class="pill ${esc(dev.mode)}">${esc(dev.mode)}</span>
      </button>`);
    btn.onclick = () => { selectedId = dev.device_id; renderShell(); autoLocate(); };
    body.append(btn);
  }

  // controls for the selected device, inline in the same panel
  if (d) {
    body.append(h('<div style="height:1px;background:var(--glass-brd);margin:4px 0"></div>'));
    const seg = h('<div><label>Mode</label><div class="seg"></div></div>');
    for (const m of ['normal', 'lost']) {
      const label = m === 'normal' ? 'Normal' : 'Lost';
      const b = h(`<button class="${m === d.mode ? 'on ' + m : ''}">${label}</button>`);
      b.onclick = () => setMode(d, m, body);
      seg.querySelector('.seg').append(b);
    }
    body.append(seg);
    body.append(h('<input id="lostmsg" placeholder="Message shown to finder (lost mode)">'));

    const ring = h('<button class="primary" style="width:100%">🔊 Play sound on Deck</button>');
    ring.onclick = async () => {
      const out = body.querySelector('#pout');
      // Fire-and-forget: flash a transient confirmation, never persist it.
      const flash = (html) => { out.innerHTML = html; setTimeout(() => { if (out.innerHTML === html) out.innerHTML = ''; }, 4000); };
      try { await api('PUT', `/v1/ring/${d.device_id}`); flash('<div class="glass" style="padding:10px">🔊 Ringing the Deck…</div>'); }
      catch (e) { flash(`<div style="color:var(--stolen)">${esc(e.message)}</div>`); }
    };
    body.append(ring);

    const actions = h('<div class="row"></div>');
    const locate = h('<button class="primary" style="flex:1">📍 Locate</button>');
    locate.onclick = () => locateFlow(d, body);
    const msgs = h(`<button style="flex:1">✉ Messages${hasUnread(d) ? ' <span class="badge">new</span>' : ''}</button>`);
    msgs.onclick = () => {
      markSeen(d);
      app.querySelectorAll('.badge').forEach((b) => b.remove()); // clear in place
      relayFlow(d, body);
    };
    actions.append(locate, msgs);
    body.append(actions);

    const revoke = h('<button class="ghost danger" style="width:100%">Revoke this Deck</button>');
    revoke.onclick = async () => {
      if (!confirm(`Revoke "${d.name}"? Deletes its token and all reports.`)) return;
      await api('DELETE', `/v1/devices/${d.device_id}`);
      await loadDevices(false);
    };
    body.append(revoke);
    body.append(h('<div id="pout" class="col"></div>'));
  }

  panel.querySelector('#logout').onclick = async () => { await api('POST', '/auth/logout'); location.reload(); };
  panel.querySelector('#enroll').onclick = () => enrollFlow(panel.querySelector('#paircode'));
  app.replaceChildren(panel);
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
    const rows = await api('GET', `/v1/reports/${d.device_id}?limit=50`);
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
    for (const r of reports.slice(0, 50)) {
      try { const f = await resolveWifi(r.wifi || []); if (f) fixes.push({ ...f, ts: r.ts, batt: r.batt }); else noMatch += 1; } catch { noMatch += 1; }
    }
    plotFixes(fixes, { name: d.name });

    const recurring = btRecurrence(reports);
    out.innerHTML = '';
    out.append(closeBar(out, 'Location'));
    out.append(h(`<div class="glass" style="padding:12px">
      <div class="kv"><span class="k">Fixes plotted</span><span class="v">${fixes.length}</span></div>
      <div class="kv"><span class="k">Latest fix</span><span class="v">${fixes[0] ? '±' + Math.round(fixes[0].accuracy) + 'm' : '—'}</span></div>
      <div class="kv"><span class="k">Reports</span><span class="v">${reports.length}</span></div>
      ${noMatch ? `<div class="kv"><span class="k">No Wi-Fi match</span><span class="v">${noMatch}</span></div>` : ''}
    </div>`));
    if (!fixes.length) {
      out.append(h(`<div class="faint">No Wi-Fi-based fix yet. beacondb/Apple didn't recognize these access points — a scan with more nearby networks, or a busier area, resolves better.</div>`));
    }
    if (recurring.length) {
      out.append(h(`<div class="glass" style="padding:10px">
        <div class="faint" style="margin-bottom:4px">Recurring Bluetooth (travelling with the Deck)</div>
        ${recurring.map(([mac, n]) => `<div class="kv"><span class="k">${esc(mac)}</span><span class="v">×${n}</span></div>`).join('')}
      </div>`));
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
