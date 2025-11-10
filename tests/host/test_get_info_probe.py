import io
import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import ctap_get_info_probe as probe  # noqa: E402


class GetInfoProbeTests(unittest.TestCase):
    def test_exact_response_guard(self):
        probe.check_get_info_response(probe.EXPECTED_GET_INFO)
        changed = bytearray(probe.EXPECTED_GET_INFO)
        changed[-1] ^= 1
        with self.assertRaises(probe.GetInfoProbeError):
            probe.check_get_info_response(changed)

    def test_five_requests_malformed_and_recovery(self):
        calls = []

        def fake_exchange(unused_handle, cid, command, data, wait_ms):
            calls.append((cid, command, bytes(data), wait_ms))
            if command == probe.CTAPHID_INIT:
                return bytes(data) + bytes.fromhex("01020304020001000c")
            if data == probe.GET_INFO_REQUEST + b"\xff":
                return probe.INVALID_CBOR
            return probe.EXPECTED_GET_INFO

        output = io.StringIO()
        probe.run_smoke(None, 2000, output, fake_exchange)
        self.assertEqual(len(calls), 8)
        self.assertEqual(calls[0][0], probe.BROADCAST_CID)
        self.assertEqual(
            [call[2] for call in calls[1:]],
            [probe.GET_INFO_REQUEST] * 5
            + [probe.GET_INFO_REQUEST + b"\xff", probe.GET_INFO_REQUEST],
        )
        self.assertEqual(
            output.getvalue().splitlines(),
            [
                "PASS five canonical GetInfo responses",
                "PASS malformed GetInfo failed and the next request recovered",
            ],
        )


if __name__ == "__main__":
    unittest.main()
