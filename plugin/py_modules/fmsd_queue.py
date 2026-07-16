"""On-device retry queue — spec §3.

A stolen Deck touching WiFi for 30 seconds is the report you can't afford
to lose: if upload fails, persist the (already sealed, therefore harmless)
blob to disk and retry oldest-first on every network-up.
"""

from __future__ import annotations

import json
import os
import time

MAX_QUEUED = 500  # cap disk usage; drop oldest beyond this


class RetryQueue:
    def __init__(self, dirpath: str):
        self.dir = dirpath
        os.makedirs(dirpath, exist_ok=True)
        self._n = 0

    def _files(self) -> list[str]:
        return sorted(f for f in os.listdir(self.dir) if f.endswith(".blob"))

    def enqueue(self, blob: str) -> None:
        self._n += 1
        name = f"{time.monotonic_ns():020d}-{self._n:06d}.blob"
        tmp = os.path.join(self.dir, name + ".tmp")
        with open(tmp, "w", encoding="ascii") as f:
            f.write(blob)
        os.replace(tmp, os.path.join(self.dir, name))
        files = self._files()
        for stale in files[: max(0, len(files) - MAX_QUEUED)]:
            os.unlink(os.path.join(self.dir, stale))

    def drain(self, post) -> tuple[int, int]:
        """Post oldest-first via `post(blob) -> bool`. Stops at first failure
        (no point hammering a dead link). Returns (sent, remaining)."""
        sent = 0
        files = self._files()
        for name in files:
            path = os.path.join(self.dir, name)
            try:
                with open(path, encoding="ascii") as f:
                    blob = f.read()
            except OSError:
                continue
            if not post(blob):
                break
            os.unlink(path)
            sent += 1
        return sent, len(self._files())

    def __len__(self) -> int:
        return len(self._files())
