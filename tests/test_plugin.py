"""Plugin backend unit tests: state machine, retry queue, scan parsers,
reporter. Run: <venv>/bin/python -m unittest tests.test_plugin -v (from repo root),
or via `npm test` which wires paths."""

import json
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
# crypto/py must win the name `fmsd_crypto` here: unit tests need the full
# PyNaCl implementation (derive/sign/open). The device-side ctypes module is
# loaded explicitly below as `ct` and interop-tested against it.
sys.path.insert(0, os.path.join(HERE, "../plugin/py_modules"))
sys.path.insert(0, os.path.join(HERE, "../crypto/py"))

import importlib.util

import fmsd_crypto

_spec = importlib.util.spec_from_file_location(
    "fmsd_crypto_ctypes", os.path.join(HERE, "../plugin/py_modules/fmsd_crypto.py"))
ct = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ct)
import fmsd_queue
import fmsd_reporter
import fmsd_scan
import fmsd_state

TEST_KDF = {"v": 1, "alg": "argon2id", "ops": 1, "mem": 8388608}

IW_SAMPLE = """\
BSS aa:bb:cc:dd:ee:01(on wlan0) -- associated
\tfreq: 2437
\tsignal: -41.00 dBm
\tSSID: HomeNet
BSS aa:bb:cc:dd:ee:02(on wlan0)
\tfreq: 5180
\tsignal: -67.00 dBm
\tSSID: Neighbor
BSS aa:bb:cc:dd:ee:03(on wlan0)
\tfreq: 2412
\tsignal: -80.00 dBm
"""

NMCLI_SAMPLE = "AA\\:BB\\:CC\\:DD\\:EE\\:10:84:6:2437 MHz\nAA\\:BB\\:CC\\:DD\\:EE\\:11:40:36:5180 MHz\n"


def make_keys():
    salt = fmsd_crypto.gen_salt()
    return fmsd_crypto.derive_keys("a long test password 42", salt, TEST_KDF)


class StateMachineTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.keys = make_keys()
        self.state = fmsd_state.DeviceState(os.path.join(self.dir, "state.json"))
        self.state.enroll("http://x", "dev1", "tok1", self.keys["box_pk"], self.keys["sign_pk"])

    def tearDown(self):
        shutil.rmtree(self.dir)

    def signed(self, mode, counter):
        return fmsd_crypto.sign_command(
            {"mode": mode, "counter": counter, "issued_at": 1, "message": "m", "contact": "c"},
            self.keys["sign_seed"])

    def test_valid_command_applies_and_persists(self):
        s = self.signed("lost", 1)
        ok, why = self.state.apply_command(s["payload"], s["sig"])
        self.assertTrue(ok, why)
        self.assertEqual(self.state.mode, "lost")
        reloaded = fmsd_state.DeviceState(self.state.path)
        self.assertEqual(reloaded.mode, "lost")
        self.assertEqual(reloaded.data["last_applied_counter"], 1)

    def test_bad_signature_rejected(self):
        s = self.signed("lost", 1)
        ok, why = self.state.apply_command(s["payload"].replace("lost", "normal"), s["sig"])
        self.assertFalse(ok)
        self.assertEqual(why, "bad signature")
        self.assertEqual(self.state.mode, "normal")

    def test_foreign_key_rejected(self):
        other = fmsd_crypto.derive_keys("attacker pw 9999", fmsd_crypto.gen_salt(), TEST_KDF)
        s = fmsd_crypto.sign_command(
            {"mode": "lost", "counter": 1, "issued_at": 1, "message": "", "contact": ""},
            other["sign_seed"])
        ok, why = self.state.apply_command(s["payload"], s["sig"])
        self.assertFalse(ok)
        self.assertEqual(why, "bad signature")

    def test_replay_rejected(self):
        s2 = self.signed("lost", 2)
        self.assertTrue(self.state.apply_command(s2["payload"], s2["sig"])[0])
        s_old = self.signed("normal", 2)   # same counter — replay
        ok, why = self.state.apply_command(s_old["payload"], s_old["sig"])
        self.assertFalse(ok)
        self.assertIn("counter", why)
        self.assertEqual(self.state.mode, "lost")
        s1 = self.signed("normal", 1)      # older counter
        self.assertFalse(self.state.apply_command(s1["payload"], s1["sig"])[0])

    def test_unknown_mode_rejected(self):
        s = self.signed("bricked", 3)
        ok, why = self.state.apply_command(s["payload"], s["sig"])
        self.assertFalse(ok)
        self.assertEqual(why, "unknown mode")


class QueueTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.q = fmsd_queue.RetryQueue(self.dir)

    def tearDown(self):
        shutil.rmtree(self.dir)

    def test_fifo_drain_stops_on_failure_then_resumes(self):
        for i in range(3):
            self.q.enqueue(f"blob{i}")
        calls = []
        def flaky(blob):
            calls.append(blob)
            return blob != "blob1"
        sent, remaining = self.q.drain(flaky)
        self.assertEqual(sent, 1)              # blob0 sent, stopped at blob1
        self.assertEqual(remaining, 2)
        self.assertEqual(calls, ["blob0", "blob1"])
        sent, remaining = self.q.drain(lambda b: True)
        self.assertEqual((sent, remaining), (2, 0))

    def test_cap_drops_oldest(self):
        old_cap = fmsd_queue.MAX_QUEUED
        fmsd_queue.MAX_QUEUED = 5
        try:
            for i in range(8):
                self.q.enqueue(f"b{i}")
            self.assertEqual(len(self.q), 5)
            got = []
            self.q.drain(lambda b: got.append(b) or True)
            self.assertEqual(got, ["b3", "b4", "b5", "b6", "b7"])
        finally:
            fmsd_queue.MAX_QUEUED = old_cap


class ScanParserTest(unittest.TestCase):
    def test_iw_parse(self):
        aps = fmsd_scan.parse_iw_scan(IW_SAMPLE)
        self.assertEqual(len(aps), 3)
        self.assertEqual(aps[0], {"bssid": "aa:bb:cc:dd:ee:01", "rssi": -41, "ch": 6, "freq": 2437})
        self.assertEqual(aps[1]["ch"], 36)

    def test_nmcli_parse(self):
        aps = fmsd_scan.parse_nmcli(NMCLI_SAMPLE)
        self.assertEqual(len(aps), 2)
        self.assertEqual(aps[0]["bssid"], "aa:bb:cc:dd:ee:10")
        self.assertEqual(aps[0]["ch"], 6)
        self.assertLess(aps[1]["rssi"], aps[0]["rssi"])

    def test_freq_to_channel(self):
        self.assertEqual(fmsd_scan.freq_to_channel(2412), 1)
        self.assertEqual(fmsd_scan.freq_to_channel(2484), 14)
        self.assertEqual(fmsd_scan.freq_to_channel(5745), 149)


class ReporterTest(unittest.TestCase):
    def test_report_seals_and_queues_on_failure(self):
        d = tempfile.mkdtemp()
        try:
            keys = make_keys()
            state = fmsd_state.DeviceState(os.path.join(d, "state.json"))
            state.enroll("http://x", "dev1", "tok1", keys["box_pk"], keys["sign_pk"])
            queue = fmsd_queue.RetryQueue(os.path.join(d, "outbox"))

            orig_scan, orig_bt, orig_batt = fmsd_scan.wifi_scan, fmsd_scan.bt_scan, fmsd_scan.battery_level
            fmsd_scan.wifi_scan = lambda **kw: [{"bssid": "aa:bb:cc:dd:ee:01", "rssi": -50, "ch": 1, "freq": 2412}]
            fmsd_scan.bt_scan = lambda **kw: [{"mac": "11:22:33:44:55:66", "rssi": 0}]
            fmsd_scan.battery_level = lambda: 0.5
            try:
                class DeadApi:
                    def post_report(self, *a):
                        return False
                res = fmsd_reporter.report_once(state, DeadApi(), queue)
                self.assertFalse(res["delivered"])
                self.assertEqual(res["queued"], 1)

                sent_blobs = []
                class LiveApi:
                    def post_report(self, _id, _tok, blob):
                        sent_blobs.append(blob)
                        return True
                state.data["mode"] = "lost"  # exercise bt path
                res = fmsd_reporter.report_once(state, LiveApi(), queue)
                self.assertTrue(res["delivered"])
                self.assertEqual(res["flushed_backlog"], 1)  # backlog drained after success
                self.assertEqual(res["queued"], 0)
                self.assertEqual(res["bt"], 1)

                # blobs decrypt only with box_sk; device kept none — use test sk
                plain = json.loads(fmsd_crypto.seal_open(sent_blobs[0], keys["box_sk"]))
                self.assertEqual(plain["v"], 1)
                self.assertEqual(plain["wifi"][0]["bssid"], "aa:bb:cc:dd:ee:01")
            finally:
                fmsd_scan.wifi_scan, fmsd_scan.bt_scan, fmsd_scan.battery_level = orig_scan, orig_bt, orig_batt
        finally:
            shutil.rmtree(d)


class CtypesInteropTest(unittest.TestCase):
    """Device ctypes implementation vs canonical PyNaCl implementation."""

    def test_ctypes_seal_opens_with_pynacl(self):
        keys = make_keys()
        report = {"v": 1, "seq": 9, "wifi": [{"bssid": "aa:bb:cc:dd:ee:ff", "rssi": -50}]}
        blob = ct.seal_report(report, keys["box_pk"])
        self.assertEqual(json.loads(fmsd_crypto.seal_open(blob, keys["box_sk"])), report)

    def test_ctypes_verifies_pynacl_signature(self):
        keys = make_keys()
        s = fmsd_crypto.sign_command(
            {"mode": "lost", "counter": 3, "issued_at": 1, "message": "", "contact": ""},
            keys["sign_seed"])
        self.assertTrue(ct.verify_command(s["payload"], s["sig"], keys["sign_pk"]))
        self.assertFalse(ct.verify_command(s["payload"] + " ", s["sig"], keys["sign_pk"]))
        self.assertFalse(ct.verify_command(s["payload"], s["sig"], keys["box_pk"]))
        self.assertFalse(ct.verify_command(s["payload"], "AAAA", keys["sign_pk"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
