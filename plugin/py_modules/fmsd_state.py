"""Device state machine — spec §3.

Persists enrollment + mode + last_applied_counter to disk. apply_command is
the ONLY way mode changes: signature verified against enrolled sign_pk,
counter strictly monotonic. A compromised server relaying garbage cannot
move this state machine.
"""

from __future__ import annotations

import json
import os
import tempfile

import fmsd_crypto

MODES = ("normal", "lost")

# Seconds between report attempts per mode. Normal also reports on
# wake/network-connect and on UI events; these are the autonomous ceilings.
# 'lost' is the active tracking mode (was split into lost+stolen) — it scans
# aggressively, adds Bluetooth, and reports often.
REPORT_INTERVAL = {"normal": 3600, "lost": 90}
# Background loop heartbeat: how long it sleeps between autonomous checks.
# Normal stays lazy (battery); lost ticks tight so a lost Deck reports and
# picks up ring/command changes quickly even without the owner opening UI.
LOOP_HEARTBEAT = {"normal": 300, "lost": 60}

DEFAULTS = {
    "enrolled": False,
    "server_url": "",
    "device_id": "",
    "device_token": "",
    "box_pk": "",
    "sign_pk": "",
    "mode": "normal",
    "last_applied_counter": 0,
    "seq": 0,
    "last_report_ts": 0,       # unix ms of last DELIVERED report
    "last_report_ok": False,
    "last_ring": 0,            # highest ring_counter we've acted on
    "command": None,  # last applied command dict (message/contact for lost UI)
}


class DeviceState:
    def __init__(self, path: str):
        self.path = path
        self.data = dict(DEFAULTS)
        self._load()

    def _load(self) -> None:
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                stored = json.load(f)
            self.data.update({k: stored[k] for k in DEFAULTS if k in stored})
        except (OSError, ValueError):
            pass

    def save(self) -> None:
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(self.path) or ".")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(self.data, f)
        os.replace(tmp, self.path)  # atomic — counter persistence must not tear

    # -- enrollment -------------------------------------------------------
    def enroll(self, server_url: str, device_id: str, device_token: str,
               box_pk: str, sign_pk: str) -> None:
        self.data.update(
            enrolled=True, server_url=server_url.rstrip("/"), device_id=device_id,
            device_token=device_token, box_pk=box_pk, sign_pk=sign_pk,
            mode="normal", last_applied_counter=0, seq=0, command=None,
        )
        self.save()

    # -- the load-bearing check (§1.3): verify THEN parse, counter advances --
    def apply_command(self, payload: str, sig: str) -> tuple[bool, str]:
        if not self.data["enrolled"]:
            return False, "not enrolled"
        if not fmsd_crypto.verify_command(payload, sig, self.data["sign_pk"]):
            return False, "bad signature"
        try:
            cmd = json.loads(payload)
        except ValueError:
            return False, "payload not JSON"
        counter = cmd.get("counter")
        if not isinstance(counter, int) or counter <= self.data["last_applied_counter"]:
            return False, "replayed or stale counter"
        if cmd.get("mode") not in MODES:
            return False, "unknown mode"
        self.data["mode"] = cmd["mode"]
        self.data["last_applied_counter"] = counter
        self.data["command"] = cmd
        self.save()
        return True, "applied"

    def next_seq(self) -> int:
        self.data["seq"] += 1
        self.save()
        return self.data["seq"]

    @property
    def mode(self) -> str:
        return self.data["mode"]

    def mark_report(self, ts: int, ok: bool) -> None:
        if ok:
            self.data["last_report_ts"] = ts
        self.data["last_report_ok"] = ok
        self.save()

    def public_status(self) -> dict:
        """Status safe to show in the QAM UI (never the token)."""
        return {
            "enrolled": self.data["enrolled"],
            "server_url": self.data["server_url"],
            "device_id": self.data["device_id"],
            "mode": self.data["mode"],
            "seq": self.data["seq"],
            "counter": self.data["last_applied_counter"],
            "last_report_ts": self.data["last_report_ts"],
            "last_report_ok": self.data["last_report_ok"],
            "command": self.data["command"],
        }
