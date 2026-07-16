"""WiFi + BT environment scan — spec §3 "scan quality".

Sends {bssid, rssi, ch, freq} per AP (RSSI-weighted solve needs signal
strength, not a bare BSSID list). BSSIDs are NEVER resolved to coordinates
here — the raw scan gets sealed and geolocation happens in the owner's
browser.
"""

from __future__ import annotations

import re
import subprocess


def _run(cmd: list[str], timeout: int = 25) -> str:
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False,
        ).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


def freq_to_channel(freq: int) -> int:
    if 2412 <= freq <= 2472:
        return (freq - 2407) // 5
    if freq == 2484:
        return 14
    if 5000 <= freq <= 5925:
        return (freq - 5000) // 5
    if 5955 <= freq <= 7115:  # 6 GHz
        return (freq - 5950) // 5
    return 0


def parse_iw_scan(text: str) -> list[dict]:
    """Parse `iw dev <if> scan` output into AP entries."""
    aps: list[dict] = []
    cur: dict | None = None
    for line in text.splitlines():
        m = re.match(r"^BSS ([0-9a-f:]{17})", line.strip(), re.I)
        if m:
            if cur:
                aps.append(cur)
            cur = {"bssid": m.group(1).lower(), "rssi": -100, "ch": 0, "freq": 0}
            continue
        if cur is None:
            continue
        m = re.search(r"signal:\s*(-?\d+(?:\.\d+)?)\s*dBm", line)
        if m:
            cur["rssi"] = int(float(m.group(1)))
            continue
        m = re.search(r"freq:\s*(\d+)", line)
        if m:
            cur["freq"] = int(m.group(1))
            cur["ch"] = freq_to_channel(cur["freq"])
    if cur:
        aps.append(cur)
    return aps


def parse_nmcli(text: str) -> list[dict]:
    """Parse `nmcli -t -f BSSID,SIGNAL,CHAN,FREQ dev wifi` (BSSID colons escaped)."""
    aps = []
    for line in text.splitlines():
        parts = line.replace(r"\:", "|").split(":")
        if len(parts) < 4:
            continue
        bssid = parts[0].replace("|", ":").lower()
        if not re.match(r"^[0-9a-f:]{17}$", bssid):
            continue
        try:
            signal = int(parts[1])            # nmcli SIGNAL is 0..100
            freq = int(re.sub(r"\D", "", parts[3]) or 0)
        except ValueError:
            continue
        aps.append({
            "bssid": bssid,
            "rssi": (signal // 2) - 100,      # rough %-to-dBm mapping
            "ch": int(parts[2]) if parts[2].isdigit() else freq_to_channel(freq),
            "freq": freq,
        })
    return aps


def wifi_scan(interface: str = "wlan0", active: bool = False, cap: int = 40) -> list[dict]:
    """Best AP list we can get. `active=True` (stolen mode) forces a rescan;
    passive uses the last cached results (battery-friendly, spec §3 normal)."""
    out = _run(["iw", "dev", interface, "scan"] + ([] if active else ["dump"]))
    aps = parse_iw_scan(out)
    if not aps:
        args = ["nmcli", "-t", "-f", "BSSID,SIGNAL,CHAN,FREQ", "dev", "wifi", "list"]
        if not active:
            args += ["--rescan", "no"]
        aps = parse_nmcli(_run(args))
    aps.sort(key=lambda a: a["rssi"], reverse=True)
    return aps[:cap]


def parse_bluetoothctl(text: str) -> list[dict]:
    devs = []
    for line in text.splitlines():
        m = re.match(r"^Device ([0-9A-F:]{17})", line.strip(), re.I)
        if m:
            devs.append({"mac": m.group(1).lower(), "rssi": 0})
    return devs


def bt_scan(window_s: int = 10) -> list[dict]:
    """Nearby BT devices (stolen mode only — thief's phone/earbuds/car recur
    across reports and turn blobs into a movement track for the owner)."""
    _run(["bluetoothctl", "--timeout", str(window_s), "scan", "on"], timeout=window_s + 5)
    return parse_bluetoothctl(_run(["bluetoothctl", "devices"]))


def battery_level() -> float:
    for supply in ("BAT0", "BAT1", "battery"):
        try:
            with open(f"/sys/class/power_supply/{supply}/capacity", encoding="ascii") as f:
                return int(f.read().strip()) / 100
        except (OSError, ValueError):
            continue
    return -1.0
