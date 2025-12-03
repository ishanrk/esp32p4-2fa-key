import pathlib
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
COMPONENT = ROOT / "components" / "p4_ctap"


class CtapCoreTests(unittest.TestCase):
    def test_actual_minimal_cbor_and_dispatch_core(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = pathlib.Path(tmp) / "ctap_core_test"
            subprocess.run(
                [
                    "cc",
                    "-std=c11",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-I",
                    str(COMPONENT / "include"),
                    "-I",
                    str(ROOT / "components" / "p4_cred" / "include"),
                    str(ROOT / "tests" / "host" / "ctap_core_test.c"),
                    str(COMPONENT / "p4_cbor.c"),
                    str(COMPONENT / "p4_ctap.c"),
                    str(COMPONENT / "p4_get_info.c"),
                    str(ROOT / "components" / "p4_cred" / "p4_aaguid.c"),
                    "-o",
                    str(output),
                ],
                check=True,
            )
            result = subprocess.run(
                [str(output)],
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertEqual(
                result.stdout,
                "PASS minimal cbor and ctap core\n",
            )


if __name__ == "__main__":
    unittest.main()
