// Production entry: env-driven, binds loopback (nginx terminates TLS),
// serves the built dashboard, drains pg pool on shutdown.
//
// Required env (via systemd EnvironmentFile):
//   DATABASE_URL          postgres://fmsd_app:...@127.0.0.1:40870/findmydeck
//   FMSD_BASE_URL         https://deck.0xbanana.com
//   FMSD_PEPPER           32-byte hex — account_key HMAC; rotating it orphans accounts
//   FMSD_SESSION_SECRET   32-byte hex — cookie signing; rotating it logs everyone out
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import { createApp } from './app.js';
import { openDb } from './db.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const port = Number(process.env.PORT || 8451);
const host = process.env.HOST || '127.0.0.1';
const baseUrl = process.env.FMSD_BASE_URL || `http://localhost:${port}`;

for (const key of ['DATABASE_URL', 'FMSD_PEPPER', 'FMSD_SESSION_SECRET']) {
  if (!process.env[key]) {
    console.error(`fatal: ${key} not set`);
    process.exit(1);
  }
}

const db = await openDb(process.env.DATABASE_URL);
const app = createApp({ db, baseUrl });
// Finder recovery page (spec §4): /found/<code> serves the relay UI.
app.get('/found/:code', (_req, res) =>
  res.sendFile(path.join(here, '../dashboard/dist/found.html')));
// Admin page (access gated by the /v1/admin/stats endpoint, not this route).
app.get('/admin', (_req, res) =>
  res.sendFile(path.join(here, '../dashboard/dist/admin.html')));
app.use(express.static(path.join(here, '../dashboard/dist')));

const server = app.listen(port, host, () =>
  console.log(`findmydeck server on ${host}:${port} (public: ${baseUrl})`));

for (const sig of ['SIGTERM', 'SIGINT']) {
  process.on(sig, () => {
    server.close(() => db.end().then(() => process.exit(0)));
    setTimeout(() => process.exit(1), 10_000).unref();
  });
}
