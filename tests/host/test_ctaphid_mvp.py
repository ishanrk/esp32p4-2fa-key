import io
import pathlib
import re
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
COMPONENT = ROOT / "components" / "p4_ctaphid"

sys.path.insert(0, str(SCRIPTS))
import ctaphid_mvp_probe as mvp  # noqa: E402
import usb_common  # noqa: E402


class FakeHandle:
    def __init__(self):
        self.closed = False
        self.pending = []
        self.request = None
        self.completed = []

    def open_path(self, path):
        if path != b"p4key-mvp":
            raise OSError("wrong fake path")

    def get_report_descriptor(self):
        return usb_common.EXPECTED_REPORT_DESCRIPTOR

    def write(self, data):
        raw = bytes(data)
        if len(raw) != 65 or raw[0] != 0:
            return 0
        report = raw[1:]
        cid = int.from_bytes(report[0:4], "big")
        if report[4] & 0x80:
            declared_len = int.from_bytes(report[5:7], "big")
            self.request = {
                "cid": cid,
                "command": report[4],
                "len": declared_len,
                "data": bytearray(report[7:7 + min(declared_len, 57)]),
                "sequence": 0,
            }
        else:
            if self.request is None or cid != self.request["cid"]:
                return 0
            if report[4] != self.request["sequence"]:
                return 0
            take = min(59, self.request["len"] - len(self.request["data"]))
            self.request["data"].extend(report[5:5 + take])
            self.request["sequence"] += 1

        if len(self.request["data"]) == self.request["len"]:
            request = self.request
            self.request = None
            payload = bytes(request["data"])
            self.completed.append((request["cid"], request["command"], payload))
            if request["command"] == mvp.CTAPHID_INIT:
                response = (
                    payload + b"\x01\x02\x03\x04" + b"\x02\x00\x01\x00\x0c"
                )
            elif request["command"] == mvp.CTAPHID_PING:
                response = payload
            else:
                response = b"\x00\xa0"
            self.pending.extend(
                mvp.encode_reports(request["cid"], request["command"], response)
            )
        return len(raw)

    def read(self, length, timeout_ms):
        if length != 64 or timeout_ms < 1 or not self.pending:
            return []
        return list(self.pending.pop(0))

    def close(self):
        self.closed = True


class FakeHid:
    def __init__(self):
        self.handle = FakeHandle()

    def enumerate(self, vid, pid):
        return [{
            "path": b"p4key-mvp",
            "vendor_id": vid,
            "product_id": pid,
            "interface_number": 0,
            "usage_page": 0xF1D0,
            "usage": 0x01,
        }]

    def device(self):
        return self.handle


class CtaphidMvpTests(unittest.TestCase):
    def test_reports_are_64_bytes_with_57_and_59_byte_chunks(self):
        payload = bytes(range(117))
        reports = mvp.encode_reports(0x01020304, mvp.CTAPHID_PING, payload)
        self.assertEqual([len(report) for report in reports], [64, 64, 64])
        self.assertEqual(reports[0][7:64], payload[:57])
        self.assertEqual(reports[1][4], 0)
        self.assertEqual(reports[1][5:64], payload[57:116])
        self.assertEqual(reports[2][4], 1)
        self.assertEqual(reports[2][5], payload[116])
        self.assertEqual(reports[2][6:64], bytes(58))

    def test_minimal_init_ping_and_cbor_smoke(self):
        fake = FakeHid()
        output = io.StringIO()
        result = mvp.probe(
            0x303A, 0x4004, 2000, hid_module=fake, output=output
        )
        self.assertEqual(result, 0)
        self.assertTrue(fake.handle.closed)
        self.assertEqual(
            [command for unused_cid, command, unused_data in fake.handle.completed],
            [mvp.CTAPHID_INIT, mvp.CTAPHID_PING,
             mvp.CTAPHID_PING, mvp.CTAPHID_CBOR],
        )
        self.assertEqual(
            [cid for cid, unused_command, unused_data in fake.handle.completed],
            [mvp.BROADCAST_CID, 0x01020304, 0x01020304, 0x01020304],
        )
        self.assertEqual(len(fake.handle.completed[2][2]), 117)
        self.assertEqual(
            output.getvalue().splitlines(),
            [
                "PASS INIT allocated a valid channel and echoed the nonce",
                "PASS short PING echoed 9 bytes",
                "PASS multi frame PING echoed 117 bytes",
                "PASS CBOR GetInfo reached the application",
            ],
        )

    def test_no_heap_and_keepalive_stub_guards(self):
        sources = "\n".join(
            path.read_text(encoding="utf-8")
            for path in sorted(COMPONENT.glob("*.c"))
        )
        without_comments = re.sub(r"/\*.*?\*/|//[^\n]*", "", sources,
                                  flags=re.DOTALL)
        self.assertIsNone(re.search(
            r"\b(?:malloc|calloc|realloc|free|pvPortMalloc|vPortFree)\s*\(",
            without_comments,
        ))
        compact = re.sub(r"\s+", " ", without_comments)
        self.assertIn("status != CTAPHID_KEEPALIVE_PROCESSING", compact)
        self.assertIn("status != CTAPHID_KEEPALIVE_UP_NEEDED", compact)
        self.assertIn(
            "send_locked(cid, CTAPHID_KEEPALIVE, &status, 1,", compact
        )
        stub = (ROOT / "main" / "ctap_stub.c").read_text(encoding="utf-8")
        self.assertIn(
            "p4_ctap_dispatch(cid, s_request, request_len,", stub
        )
        self.assertIn(
            "hid_send_msg(cid, command, s_response, response_len);", stub
        )


if __name__ == "__main__":
    unittest.main()
