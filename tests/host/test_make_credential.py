import pathlib
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
CTAP = ROOT / "components" / "p4_ctap"
CRED = ROOT / "components" / "p4_cred"


class MakeCredentialTests(unittest.TestCase):
    def test_actual_make_credential_and_wrapped_credential_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = pathlib.Path(tmp) / "make_credential_test"
            subprocess.run(
                [
                    "cc",
                    "-std=c11",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-I",
                    str(ROOT / "tests" / "host"),
                    "-I",
                    str(CTAP / "include"),
                    "-I",
                    str(CTAP),
                    "-I",
                    str(CRED / "include"),
                    "-I",
                    str(CRED),
                    "-I",
                    str(ROOT / "components" / "p4_crypto" / "include"),
                    "-I",
                    str(ROOT / "components" / "p4_press" / "include"),
                    str(ROOT / "tests" / "host" / "make_credential_test.c"),
                    str(ROOT / "tests" / "host" / "make_cred_fakes.c"),
                    str(CTAP / "p4_cbor.c"),
                    str(CTAP / "p4_ctap.c"),
                    str(CTAP / "p4_get_info.c"),
                    str(CTAP / "p4_make_credential.c"),
                    str(CRED / "p4_cred.c"),
                    str(CRED / "p4_aaguid.c"),
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
                "PASS minimal make credential response and errors\n",
            )


if __name__ == "__main__":
    unittest.main()
