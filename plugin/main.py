"""Find My Steam Deck — Decky plugin backend.

Loop: sleep per-mode interval → poll signed command → verify + apply →
scan/seal/upload (with disk retry queue). A monotonic-clock jump bigger
than the sleep means we were suspended — treat wake as a network-connect
event and report immediately (spec §3: wake+connect is the real heartbeat,
not a timer).

The backend never sees the password. Enrollment key material arrives from
the frontend (derive → discard) already reduced to public keys.
"""

import asyncio
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "py_modules"))

try:
    import decky  # type: ignore  # present on-Deck; absent in tests
    DATA_DIR = decky.DECKY_PLUGIN_SETTINGS_DIR
    log = decky.logger.info
except ImportError:
    decky = None
    DATA_DIR = os.path.expanduser("~/.local/share/findmydeck")
    log = print

# Never let an import failure kill the backend silently — the QAM panel
# polls get_status and must be able to SHOW what broke.
IMPORT_ERROR = None
try:
    import fmsd_client
    import fmsd_queue
    import fmsd_reporter
    import fmsd_state
except Exception as e:  # noqa: BLE001 — anything here must reach the UI
    IMPORT_ERROR = f"{type(e).__name__}: {e}"


class Plugin:
    async def _main(self):
        if IMPORT_ERROR:
            log(f"fmsd backend disabled: {IMPORT_ERROR}")
            return
        self.state = fmsd_state.DeviceState(os.path.join(DATA_DIR, "state.json"))
        self.queue = fmsd_queue.RetryQueue(os.path.join(DATA_DIR, "outbox"))
        self.loop_task = asyncio.get_event_loop().create_task(self._loop())

    async def _unload(self):
        if getattr(self, "loop_task", None):
            self.loop_task.cancel()

    async def _loop(self):
        # Lazy background heartbeat. Most responsiveness comes from event
        # triggers (check_now, called on QAM-open / game-exit / wake from the
        # frontend). Stolen mode still ticks tightly on its own.
        self._last_report = 0.0
        self._busy = asyncio.Lock()
        last_tick = time.monotonic()
        while True:
            await asyncio.sleep(fmsd_state.LOOP_HEARTBEAT[self.state.mode])
            now = time.monotonic()
            woke = (now - last_tick) > 120  # slept through: suspend/resume
            last_tick = now
            if not self.state.data["enrolled"]:
                continue
            try:
                await self.check_now("wake" if woke else "heartbeat", force_report=woke)
            except Exception as e:  # never let the loop die
                log(f"fmsd loop failed: {e}")

    async def check_now(self, reason: str = "event", force_report: bool = False):
        """Poll for a command and report if due/changed/forced. Called by the
        loop AND by the frontend on UI events. Serialized so overlapping
        triggers don't double-fire."""
        if not self.state.data["enrolled"]:
            return {"ok": False, "error": "not enrolled"}
        if getattr(self, "_busy", None) is None:
            self._busy = asyncio.Lock()
        async with self._busy:
            changed = await self._poll_command()
            await self._poll_ring()
            now = time.monotonic()
            last = getattr(self, "_last_report", 0.0)
            due = (now - last) >= fmsd_state.REPORT_INTERVAL[self.state.mode]
            if force_report or changed or due:
                await self._report()
                self._last_report = now
            log(f"fmsd check ({reason}): mode={self.state.mode} changed={changed} reported={force_report or changed or due}")
            return {"ok": True, "mode": self.state.mode, "changed": changed}

    async def _poll_command(self) -> bool:
        """Fetch + apply a pending command. Returns True if the mode changed."""
        api = fmsd_client.Api(self.state.data["server_url"])
        cmd = await asyncio.to_thread(
            api.get_command, self.state.data["device_id"], self.state.data["device_token"])
        if not cmd:
            return False
        before = self.state.mode
        applied, why = self.state.apply_command(cmd["payload"], cmd["sig"])
        log(f"fmsd command: {why} (mode={self.state.mode})")
        changed = applied and self.state.mode != before
        if changed:
            # Push to the frontend so the toast + full-screen fire even when
            # the QAM is closed (backend-driven, not poll-driven).
            await self._emit_mode()
        return changed

    async def _emit_mode(self):
        if decky is None:
            return
        try:
            await decky.emit("fmsd_mode", self.state.mode, self.state.data.get("command"))
        except Exception as e:  # noqa: BLE001
            log(f"fmsd emit failed: {e}")

    async def _poll_ring(self):
        """Check the owner's ring counter; if it advanced, ring (play sound)."""
        api = fmsd_client.Api(self.state.data["server_url"])
        ring = await asyncio.to_thread(
            api.get_ring, self.state.data["device_id"], self.state.data["device_token"])
        if ring > self.state.data.get("last_ring", 0):
            self.state.data["last_ring"] = ring
            self.state.save()
            log(f"fmsd ring -> {ring}")
            if decky is not None:
                try:
                    await decky.emit("fmsd_ring", ring)
                except Exception as e:  # noqa: BLE001
                    log(f"fmsd ring emit failed: {e}")

    async def _report(self):
        api = fmsd_client.Api(self.state.data["server_url"])
        result = await asyncio.to_thread(fmsd_reporter.report_once, self.state, api, self.queue)
        log(f"fmsd report: {result}")

    async def _tick(self):
        # Used by report_now(): poll then force a report.
        await self._poll_command()
        await self._report()

    # ---- methods callable from the React frontend ------------------------
    async def get_status(self):
        if IMPORT_ERROR:
            return {"enrolled": False, "backend_error": IMPORT_ERROR}
        return {**self.state.public_status(), "queued": len(self.queue)}

    async def enroll(self, server_url: str, pair_code: str, box_pk: str,
                     sign_pk: str, salt: str, kdf: dict, device_name: str):
        """Pubkeys only — the frontend derived and already discarded secrets."""
        if IMPORT_ERROR:
            return {"ok": False, "error": IMPORT_ERROR}
        try:
            api = fmsd_client.Api(server_url)
            res = await asyncio.to_thread(
                api.enroll, pair_code, box_pk, sign_pk, salt, kdf, device_name)
            self.state.enroll(server_url, res["device_id"], res["device_token"],
                              box_pk, sign_pk)
            return {"ok": True, "device_id": res["device_id"]}
        except Exception as e:  # noqa: BLE001 — surface DNS/TLS/anything in the UI
            log(f"fmsd enroll failed: {type(e).__name__}: {e}")
            return {"ok": False, "error": f"{type(e).__name__}: {e}"}

    async def report_now(self):
        if IMPORT_ERROR:
            return {"ok": False, "error": IMPORT_ERROR}
        if not self.state.data["enrolled"]:
            return {"ok": False, "error": "not enrolled"}
        try:
            await self._tick()
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": f"{type(e).__name__}: {e}"}
        return {"ok": True, **await self.get_status()}

    async def event_check(self, reason: str = "ui"):
        """Frontend calls this on QAM-open / game-exit / resume."""
        if IMPORT_ERROR:
            return {"ok": False, "error": IMPORT_ERROR}
        try:
            return await self.check_now(reason)
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": f"{type(e).__name__}: {e}"}

    # ---- on-Deck chat with the owner (lost mode) -------------------------
    async def get_messages(self):
        if IMPORT_ERROR or not self.state.data["enrolled"]:
            return {"ok": False, "messages": []}
        api = fmsd_client.Api(self.state.data["server_url"])
        msgs = await asyncio.to_thread(
            api.get_messages, self.state.data["device_id"], self.state.data["device_token"])
        return {"ok": True, "messages": msgs}

    async def send_message(self, body: str):
        if IMPORT_ERROR or not self.state.data["enrolled"]:
            return {"ok": False, "error": "not enrolled"}
        api = fmsd_client.Api(self.state.data["server_url"])
        ok = await asyncio.to_thread(
            api.send_message, self.state.data["device_id"], self.state.data["device_token"], body)
        return {"ok": ok}

    async def unenroll(self):
        self.state.data.update(fmsd_state.DEFAULTS)
        self.state.save()
        return {"ok": True}
