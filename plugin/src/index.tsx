// Find My Steam Deck — QAM frontend.
//
// Enrollment happens HERE (spec §1.1): password -> Argon2id -> keypairs,
// public keys go to the backend, password + secret keys are wiped from
// memory before the call returns. The Python backend never sees them.
//
// Covertness rule (spec §3): when the device is in `stolen` mode this panel
// renders exactly as it does in `normal` mode. Only `lost` is visible.

import {
  PanelSection, PanelSectionRow, TextField, ButtonItem, Field, staticClasses,
  Navigation, DialogButton,
} from '@decky/ui';
import {
  callable, definePlugin, toaster, useQuickAccessVisible, routerHook, addEventListener, removeEventListener,
} from '@decky/api';
import { useEffect, useRef, useState } from 'react';

const LOST_ROUTE = '/findmydeck/lost';
const RING_ROUTE = '/findmydeck/ring';

// Single source of truth for reacting to a mode change, deduped so the
// backend event and any frontend poll can both call it without double-firing.
let lastReacted: string | null = null;
function reactToMode(mode: string, command?: { message?: string } | null) {
  if (mode === lastReacted) return;
  lastReacted = mode;
  if (mode === 'lost') {
    toaster.toast({
      title: 'This Steam Deck is marked LOST',
      body: command?.message || 'Tap to see how to return it.',
      icon: <span>🛰</span>,
      critical: true,
      duration: 20000,
      onClick: () => Navigation.Navigate(LOST_ROUTE),
    });
    Navigation.Navigate(LOST_ROUTE); // force the full-screen surface
  }
  // Leaving lost is handled by LostScreen itself (it NavigateBacks when the
  // mode clears), so no exit logic is needed here.
}
import { KDF_V1, deriveKeys, genSalt, wipe } from '../../crypto/ts/crypto.mjs';

type Status = {
  enrolled: boolean; server_url?: string; device_id?: string; mode?: string;
  seq?: number; counter?: number; queued?: number;
  last_report_ts?: number; last_report_ok?: boolean;
  command?: { message?: string; contact?: string } | null;
  backend_error?: string;
};

function ago(ts?: number): string {
  if (!ts) return 'never';
  const s = Math.floor((Date.now() - ts) / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

const getStatus = callable<[], Status>('get_status');
const enrollBackend = callable<
  [string, string, string, string, string, object, string],
  { ok: boolean; error?: string; device_id?: string }
>('enroll');
const unenroll = callable<[], { ok: boolean }>('unenroll');
// Event-driven check: poll for a command + report if due. Cheap enough to
// fire on UI events instead of a hot timer.
const eventCheck = callable<[string], { ok: boolean; mode?: string }>('event_check');

type ChatMsg = { sender: 'owner' | 'finder'; body: string; created_at: number };
const getMessages = callable<[], { ok: boolean; messages: ChatMsg[] }>('get_messages');
const sendMessage = callable<[string], { ok: boolean }>('send_message');

const MIN_PASSWORD_LEN = 6;

function EnrollForm({ onDone }: { onDone: () => void }) {
  // Default to the hosted instance; editable for self-hosters.
  const [server, setServer] = useState('https://findmydeck.0xbanana.com');
  const [pairCode, setPairCode] = useState('');
  const [name, setName] = useState('My Steam Deck');
  const [pw, setPw] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');

  const submit = async () => {
    if (pw.length < MIN_PASSWORD_LEN) return setErr(`Password must be ${MIN_PASSWORD_LEN}+ characters.`);
    if (!pairCode.trim()) return setErr('Enter the pair code from the dashboard.');
    setBusy(true); setErr('');
    try {
      const salt = await genSalt();
      // ~256 MiB Argon2id: takes a few seconds on the Deck — that is the point.
      const keys = await deriveKeys(pw, salt, KDF_V1);
      setPw(''); // discard password state immediately after derive
      const res = await enrollBackend(
        server.trim(), pairCode.trim(), keys.boxPk, keys.signPk, salt, KDF_V1, name.trim(),
      );
      wipe(keys.boxSk, keys.signSk); // secrets never leave this function
      if (!res.ok) { setErr(res.error || 'enrollment failed'); return; }
      onDone();
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <PanelSection title="Set up Find My Deck">
      <PanelSectionRow>
        <Field description={
          'Your password becomes the only key that can read this Deck\'s location '
          + 'or change its mode. It is never uploaded and CANNOT be reset — '
          + 'if you lose it, re-enroll from scratch.'} />
      </PanelSectionRow>
      <PanelSectionRow><TextField label="Server URL" value={server} onChange={(e) => setServer(e.target.value)} /></PanelSectionRow>
      <PanelSectionRow><TextField label="Pair code (6 digits, from dashboard)" mustBeNumeric value={pairCode} onChange={(e) => setPairCode(e.target.value)} /></PanelSectionRow>
      <PanelSectionRow><TextField label="Device name" value={name} onChange={(e) => setName(e.target.value)} /></PanelSectionRow>
      <PanelSectionRow><TextField label="Recovery password (type carefully — cannot be reset)" bIsPassword value={pw} onChange={(e) => setPw(e.target.value)} /></PanelSectionRow>
      {err && <PanelSectionRow><Field description={err} /></PanelSectionRow>}
      <PanelSectionRow>
        <ButtonItem layout="below" disabled={busy} onClick={submit}>
          {busy ? 'Deriving keys…' : 'Enroll this Deck'}
        </ButtonItem>
      </PanelSectionRow>
    </PanelSection>
  );
}

// Full-screen lost surface (spec §6 "visible overlay"). Registered as a
// router route; the plugin force-navigates here when the Deck enters lost
// mode. Not a swipe-proof lock (that fights Gamescope) — a loud, hard-to-
// miss banner an honest finder will act on, with a way back to WiFi settings.
// A looping two-tone siren via Web Audio — no asset to bundle. Rings on the
// lost screen so an awake Deck is audible (help a finder notice / locate it
// by ear). Autoplay is allowed in the Game Mode browser; a button is the
// fallback if a platform ever blocks it.
function useSiren(on: boolean) {
  const ref = useRef<{ ctx: AudioContext; stop: () => void } | null>(null);
  const start = () => {
    if (ref.current) return;
    try {
      const ctx = new (window.AudioContext || (window as any).webkitAudioContext)();
      const gain = ctx.createGain(); gain.gain.value = 0.18; gain.connect(ctx.destination);
      const osc = ctx.createOscillator(); osc.type = 'sine'; osc.connect(gain); osc.start();
      // sweep 640<->960 Hz every 0.7s
      const lfo = ctx.createOscillator(); lfo.frequency.value = 1.4; lfo.type = 'triangle';
      const lfoGain = ctx.createGain(); lfoGain.gain.value = 160;
      lfo.connect(lfoGain); lfoGain.connect(osc.frequency); osc.frequency.value = 800; lfo.start();
      ref.current = { ctx, stop: () => { osc.stop(); lfo.stop(); ctx.close(); } };
    } catch { /* audio unavailable */ }
  };
  const stop = () => { ref.current?.stop(); ref.current = null; };
  useEffect(() => {
    if (on) start(); else stop();
    return stop;
  }, [on]);
  return { start, stop };
}

function LostScreen() {
  const [status, setStatus] = useState<Status | null>(null);
  const [muted, setMuted] = useState(false);
  useEffect(() => {
    const load = () => getStatus().then(setStatus).catch(() => {});
    load();
    const t = setInterval(load, 10000); // leave promptly once owner clears lost
    return () => clearInterval(t);
  }, []);
  const isLost = (status?.mode ?? 'lost') === 'lost';
  const siren = useSiren(isLost && !muted);
  const [chatOpen, setChatOpen] = useState(false);

  // Owner set it back to normal/stolen → get out of the way.
  useEffect(() => {
    if (status && status.mode !== 'lost') Navigation.NavigateBack();
  }, [status?.mode]);

  const cmd = status?.command || {};
  return (
    <div style={{
      position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column',
      alignItems: 'center', justifyContent: 'center', textAlign: 'center',
      padding: '3vw', gap: '1.2rem',
      background: 'linear-gradient(160deg, #12263a, #0a1622)', color: '#fff',
    }}>
      <div style={{ fontSize: '4rem' }}>🛰</div>
      <div style={{ fontSize: '2rem', fontWeight: 700 }}>This Steam Deck is lost</div>
      <div style={{ fontSize: '1.4rem', maxWidth: '70ch', opacity: 0.95 }}>
        {cmd.message || 'This device belongs to someone who is looking for it. Thank you for helping return it.'}
      </div>
      {!chatOpen && (
        <button
          onClick={() => setChatOpen(true)}
          style={{
            fontSize: '1.5rem', fontWeight: 800, color: '#0a1420', cursor: 'pointer',
            background: '#38bdf8', border: 'none', borderRadius: '16px',
            padding: '1.1rem 2.4rem', boxShadow: '0 10px 30px rgba(56,189,248,.4)',
          }}
        >
          💬 Message the owner
        </button>
      )}
      {chatOpen && <LostChat />}
      <div style={{ fontSize: '1.05rem', opacity: 0.8, maxWidth: '60ch' }}>
        Also helpful: connect this Deck to any Wi-Fi network so its owner can locate it.
      </div>
      <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap', justifyContent: 'center' }}>
        <DialogButton style={{ maxWidth: '260px' }} onClick={() => { setMuted((m) => !m); if (muted) siren.start(); else siren.stop(); }}>
          {muted ? '🔊 Sound on' : '🔇 Silence'}
        </DialogButton>
        <DialogButton style={{ maxWidth: '260px' }} onClick={() => Navigation.NavigateBack()}>
          Dismiss
        </DialogButton>
      </div>
    </div>
  );
}

// On-Deck chat with the owner. The holder can message and see replies right
// here — same relay thread as the /found/<code> web page.
function LostChat() {
  const [msgs, setMsgs] = useState<ChatMsg[]>([]);
  const [text, setText] = useState('');
  const [busy, setBusy] = useState(false);
  const load = () => getMessages().then((r) => setMsgs(r.messages || [])).catch(() => {});
  useEffect(() => { load(); const t = setInterval(load, 8000); return () => clearInterval(t); }, []);

  const send = async () => {
    const body = text.trim();
    if (!body) return;
    setBusy(true);
    try { if ((await sendMessage(body)).ok) { setText(''); await load(); } } finally { setBusy(false); }
  };

  return (
    <div style={{
      width: 'min(560px, 92vw)', background: '#ffffff10', border: '1px solid #ffffff22',
      borderRadius: '14px', padding: '14px', display: 'flex', flexDirection: 'column', gap: '8px',
    }}>
      <div style={{ fontSize: '1rem', fontWeight: 600 }}>Message the owner</div>
      <div style={{ fontSize: '.85rem', opacity: 0.7 }}>Private — no contact details are shared either way.</div>
      {msgs.length > 0 && (
        <div style={{ maxHeight: '30vh', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '6px' }}>
          {msgs.map((m, i) => (
            <div key={i} style={{
              alignSelf: m.sender === 'finder' ? 'flex-end' : 'flex-start',
              background: m.sender === 'finder' ? '#38bdf833' : '#ffffff16',
              padding: '7px 11px', borderRadius: '10px', maxWidth: '85%', fontSize: '1rem',
            }}>
              {m.body}
              <div style={{ fontSize: '.75rem', opacity: 0.6 }}>{m.sender === 'finder' ? 'you' : 'owner'}</div>
            </div>
          ))}
        </div>
      )}
      <TextField value={text} onChange={(e) => setText(e.target.value)} placeholder="Type a message to the owner…" />
      <DialogButton disabled={busy || !text.trim()} onClick={send}>
        {busy ? 'Sending…' : 'Send to owner'}
      </DialogButton>
    </div>
  );
}

// "Play sound" surface (Android-style ring). Mounting plays the siren; Stop
// navigates back, which unmounts and stops it. Works in any mode.
function RingScreen() {
  useSiren(true);
  return (
    <div style={{
      position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column',
      alignItems: 'center', justifyContent: 'center', textAlign: 'center', gap: '1.4rem',
      background: 'linear-gradient(160deg, #1a2a3f, #0a1622)', color: '#fff',
    }}>
      <div style={{ fontSize: '5rem', animation: 'none' }}>📢</div>
      <div style={{ fontSize: '2rem', fontWeight: 800 }}>Find My Deck is ringing</div>
      <div style={{ fontSize: '1.3rem', opacity: 0.9, maxWidth: '60ch' }}>
        The owner is trying to locate this Steam Deck.
      </div>
      <button onClick={() => Navigation.NavigateBack()} style={{
        fontSize: '1.4rem', fontWeight: 800, color: '#0a1420', background: '#38bdf8',
        border: 'none', borderRadius: '16px', padding: '1rem 2.6rem', cursor: 'pointer',
      }}>Stop sound</button>
    </div>
  );
}

function LostBanner({ command }: { command: NonNullable<Status['command']> }) {
  // Rendered only from a signature-verified command (backend refuses others),
  // so a compromised server cannot plant a hostile contact channel here.
  return (
    <PanelSection title="This Deck is marked LOST">
      <PanelSectionRow>
        <Field label="Message from the owner" description={command.message || 'Please help return this device.'} />
      </PanelSectionRow>
      {command.contact && (
        <PanelSectionRow>
          <Field label="Contact the owner" description={`Enter code ${command.contact} at the recovery site to reach them (anonymously).`} />
        </PanelSectionRow>
      )}
      <PanelSectionRow>
        <Field description="If you found this device: connecting it to any WiFi network is the single most helpful thing you can do." />
      </PanelSectionRow>
    </PanelSection>
  );
}

function Content() {
  const [status, setStatus] = useState<Status | null>(null);
  const [loadErr, setLoadErr] = useState('');
  const prevMode = useRef<string | null>(null);
  const refresh = () => getStatus()
    .then((s) => { setStatus(s); setLoadErr(''); notifyLost(s); })
    .catch((e) => setLoadErr(String(e)));

  // Pop a real Steam toast when the Deck ENTERS lost mode (once per
  // transition). Never for stolen — that mode is covert by design.
  const notifyLost = (s: Status) => {
    const mode = s.mode ?? 'normal';
    // Keep the dedupe baseline in sync; the backend event drives transitions.
    if (prevMode.current !== null && mode !== prevMode.current) reactToMode(mode, s.command);
    prevMode.current = mode;
  };

  // Opening the QAM is itself an event — check for a pending command and
  // report, then refresh the display. While the panel stays open, refresh
  // slowly just to keep the "updated Xm ago" line honest.
  const qamVisible = useQuickAccessVisible();
  useEffect(() => {
    if (qamVisible) eventCheck('qam-open').then(refresh).catch(() => refresh());
    else refresh();
  }, [qamVisible]);
  useEffect(() => {
    if (!qamVisible) return undefined;
    const t = setInterval(refresh, 30000);
    return () => clearInterval(t);
  }, [qamVisible]);

  const backendProblem = loadErr || status?.backend_error;
  if (backendProblem) {
    return (
      <PanelSection title="Find My Deck — backend error">
        <PanelSectionRow><Field description={backendProblem} /></PanelSectionRow>
        <PanelSectionRow>
          <Field description="Try reinstalling the plugin; if it persists, check ~/homebrew/logs on the Deck." />
        </PanelSectionRow>
        <PanelSectionRow>
          <ButtonItem layout="below" onClick={refresh}>Retry</ButtonItem>
        </PanelSectionRow>
      </PanelSection>
    );
  }
  if (!status) return <PanelSection title="Find My Deck">…</PanelSection>;
  if (!status.enrolled) return <EnrollForm onDone={refresh} />;
  if (status.mode === 'lost' && status.command) return <LostBanner command={status.command} />;

  // `normal` AND `stolen` render identically — covert by design.
  const stale = status.last_report_ok === false || (status.queued ?? 0) > 0;
  return (
    <PanelSection title="Find My Deck">
      <PanelSectionRow>
        <Field label="Protection" description={stale ? 'Active — waiting for network' : 'Active'} />
      </PanelSectionRow>
      <PanelSectionRow>
        <Field label="Location updated" description={ago(status.last_report_ts)} />
      </PanelSectionRow>
      <PanelSectionRow>
        <Field description="Updates automatically every hour and whenever the Deck wakes on WiFi." />
      </PanelSectionRow>
      <PanelSectionRow>
        <ButtonItem layout="below" onClick={() => { if (confirm('Stop protecting this Deck and erase its enrollment?')) unenroll().then(refresh); }}>
          Unenroll this Deck
        </ButtonItem>
      </PanelSectionRow>
    </PanelSection>
  );
}

export default definePlugin(() => {
  // Fire an event-driven check when a game exits (the Deck returns to the
  // library — a natural, battery-cheap moment to sync). Runs plugin-wide,
  // so it works even if the QAM panel is never opened.
  routerHook.addRoute(LOST_ROUTE, LostScreen, { exact: true });

  // Backend-pushed mode changes — fires even when the QAM is closed / in a
  // game. This is the reliable lost-mode trigger.
  const onMode = (mode: string, command?: { message?: string } | null) => reactToMode(mode, command);
  addEventListener('fmsd_mode', onMode);

  // Backend-pushed "play sound" — ring the Deck now.
  routerHook.addRoute(RING_ROUTE, RingScreen, { exact: true });
  const onRing = () => {
    toaster.toast({ title: 'Find My Deck', body: 'Ringing this Deck…', icon: <span>📢</span>, critical: true });
    Navigation.Navigate(RING_ROUTE);
  };
  addEventListener('fmsd_ring', onRing);

  let unregister: (() => void) | undefined;
  try {
    const sc = (window as unknown as { SteamClient?: any }).SteamClient;
    const reg = sc?.GameSessions?.RegisterForAppLifetimeNotifications?.((u: { bRunning: boolean }) => {
      if (!u.bRunning) eventCheck('game-exit').catch(() => {});
    });
    unregister = reg?.unregister?.bind(reg);
  } catch { /* not in Game Mode / API shape changed — events just won't fire */ }

  // On load, if already lost, jump straight to the full-screen surface.
  getStatus().then((s) => { if (s.mode) reactToMode(s.mode, s.command); }).catch(() => {});

  // Persistence watchdog: while the Deck is lost, keep re-asserting the
  // full-screen surface if someone navigated away from it — so dismissing
  // it doesn't make it stay gone. Guarded so it never interrupts while the
  // finder is already on the screen (their chat input keeps focus).
  const onLostRoute = () => { try { return (window.location?.pathname || '').includes('findmydeck'); } catch { return false; } };
  const watchdog = setInterval(() => {
    getStatus().then((s) => {
      if (s.mode === 'lost' && !onLostRoute()) {
        lastReacted = null;        // allow reactToMode to fire again
        reactToMode('lost', s.command);
      }
    }).catch(() => {});
  }, 45000);

  return {
    name: 'Find My Steam Deck',
    titleView: <div className={staticClasses.Title}>Find My Deck</div>,
    content: <Content />,
    icon: <span>🛰</span>,
    onDismount() {
      unregister?.();
      removeEventListener('fmsd_mode', onMode);
      removeEventListener('fmsd_ring', onRing);
      routerHook.removeRoute(LOST_ROUTE);
      routerHook.removeRoute(RING_ROUTE);
    },
  };
});
