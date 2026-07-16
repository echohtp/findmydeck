"""Simulated Deck for the e2e test: drives the REAL plugin modules
(state/queue/client/reporter) against a live server. WiFi scan is canned —
everything else is production code paths.

Usage: e2e_device.py <statedir> <enroll|tick|status> [json-args-on-stdin]
"""

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "../crypto/py"))
sys.path.insert(0, os.path.join(HERE, "../plugin/py_modules"))

import fmsd_client
import fmsd_queue
import fmsd_reporter
import fmsd_scan
import fmsd_state

fmsd_scan.wifi_scan = lambda **kw: [
    {"bssid": "de:ad:be:ef:00:01", "rssi": -45, "ch": 6, "freq": 2437},
    {"bssid": "de:ad:be:ef:00:02", "rssi": -71, "ch": 44, "freq": 5220},
]
fmsd_scan.bt_scan = lambda **kw: [{"mac": "ca:fe:00:00:00:01", "rssi": 0}]
fmsd_scan.battery_level = lambda: 0.62


def main():
    statedir, cmd = sys.argv[1], sys.argv[2]
    state = fmsd_state.DeviceState(os.path.join(statedir, "state.json"))
    queue = fmsd_queue.RetryQueue(os.path.join(statedir, "outbox"))

    if cmd == "enroll":
        a = json.load(sys.stdin)
        api = fmsd_client.Api(a["server_url"])
        res = api.enroll(a["pair_code"], a["box_pk"], a["sign_pk"],
                         a["salt"], a["kdf"], "e2e Deck")
        state.enroll(a["server_url"], res["device_id"], res["device_token"],
                     a["box_pk"], a["sign_pk"])
        out = {"device_id": res["device_id"]}
    elif cmd == "tick":
        api = fmsd_client.Api(state.data["server_url"])
        cmd_row = api.get_command(state.data["device_id"], state.data["device_token"])
        applied = None
        if cmd_row:
            applied = state.apply_command(cmd_row["payload"], cmd_row["sig"])
        report = fmsd_reporter.report_once(state, api, queue)
        out = {"applied": applied, "report": report, "mode": state.mode}
    elif cmd == "status":
        out = state.public_status()
    else:
        raise SystemExit(f"unknown cmd {cmd}")
    json.dump(out, sys.stdout)


if __name__ == "__main__":
    main()
