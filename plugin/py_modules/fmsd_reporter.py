"""Build + seal + deliver one report — spec §1.2 / §3."""

from __future__ import annotations

import time

import fmsd_crypto
import fmsd_scan


def build_report(state, active_scan: bool, with_bt: bool) -> dict:
    return {
        "v": 1,
        "seq": state.next_seq(),
        "ts": int(time.time() * 1000),
        "wifi": fmsd_scan.wifi_scan(active=active_scan),
        "bt": fmsd_scan.bt_scan() if with_bt else [],
        "ssid": fmsd_scan.connected_ssid(),
        "batt": fmsd_scan.battery_level(),
        "flag_ack": state.data["last_applied_counter"],
    }


def report_once(state, api, queue) -> dict:
    """Scan, seal to box_pk, try to post; on failure park the blob on disk.
    Then drain any backlog. Sealed blobs are safe at rest — the device
    cannot decrypt its own reports (ephemeral sender key)."""
    mode = state.mode
    # 'lost' is the active tracking mode: full active scan + Bluetooth trail.
    report = build_report(state, active_scan=(mode == "lost"), with_bt=(mode == "lost"))
    blob = fmsd_crypto.seal_report(report, state.data["box_pk"])

    post = lambda b: api.post_report(state.data["device_id"], state.data["device_token"], b)
    delivered = post(blob)
    if not delivered:
        queue.enqueue(blob)
    flushed, backlog = queue.drain(post) if delivered else (0, len(queue))
    state.mark_report(report["ts"], delivered)
    return {"delivered": delivered, "flushed_backlog": flushed, "queued": backlog,
            "aps": len(report["wifi"]), "bt": len(report["bt"]), "seq": report["seq"]}
