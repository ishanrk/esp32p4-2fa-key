import pathlib
import re
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
WIRE = ROOT / "components" / "p4_ctaphid" / "include" / "p4_ctaphid_wire.h"
NOTES = ROOT / "docs" / "CTAPHID_NOTES.txt"


class CtaphidConstantTests(unittest.TestCase):
    def test_wire_header_compiles_with_verified_values(self):
        source = r'''
#include "p4_ctaphid_wire.h"

_Static_assert(CTAPHID_PING == 0x81, "ping");
_Static_assert(CTAPHID_INIT == 0x86, "init");
_Static_assert(CTAPHID_CBOR == 0x90, "cbor");
_Static_assert(CTAPHID_CANCEL == 0x91, "cancel");
_Static_assert(CTAPHID_KEEPALIVE == 0xbb, "keepalive");
_Static_assert(CTAPHID_ERROR == 0xbf, "error");
_Static_assert(CTAPHID_ERR_INVALID_CMD == 0x01, "invalid cmd");
_Static_assert(CTAPHID_ERR_INVALID_PAR == 0x02, "invalid par");
_Static_assert(CTAPHID_ERR_INVALID_LEN == 0x03, "invalid len");
_Static_assert(CTAPHID_ERR_INVALID_SEQ == 0x04, "invalid seq");
_Static_assert(CTAPHID_ERR_MSG_TIMEOUT == 0x05, "timeout");
_Static_assert(CTAPHID_ERR_CHANNEL_BUSY == 0x06, "busy");
_Static_assert(CTAPHID_ERR_INVALID_CHANNEL == 0x0b, "channel");
_Static_assert(CTAPHID_ERR_OTHER == 0x7f, "other");
_Static_assert(CTAPHID_CAPABILITIES == 0x0c, "caps");
_Static_assert(CTAPHID_KEEPALIVE_PROCESSING == 1, "processing");
_Static_assert(CTAPHID_KEEPALIVE_UP_NEEDED == 2, "up");
_Static_assert(CTAP2_ERR_KEEPALIVE_CANCEL == 0x2d, "cancelled");

int main(void) { return 0; }
'''
        with tempfile.TemporaryDirectory() as tmp:
            output = pathlib.Path(tmp) / "ctaphid_constants"
            subprocess.run(
                [
                    "cc",
                    "-std=c11",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-I",
                    str(WIRE.parent),
                    "-x",
                    "c",
                    "-",
                    "-o",
                    str(output),
                ],
                input=source,
                text=True,
                check=True,
            )
            subprocess.run([str(output)], check=True)

    def test_notes_record_local_timeout_policy(self):
        text = NOTES.read_text(encoding="utf-8")
        self.assertIn("sets no numeric value", text)
        self.assertIn("selects 500 milliseconds", text)
        self.assertIn("project capability byte is therefore 0x0c", text)
        self.assertRegex(text, re.compile(r"normative maximum of 127"))


if __name__ == "__main__":
    unittest.main()
