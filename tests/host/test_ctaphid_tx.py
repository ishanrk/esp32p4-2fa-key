import pathlib
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
COMPONENT = ROOT / "components" / "p4_ctaphid"


class CtaphidSendTests(unittest.TestCase):
    def test_actual_send_core(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = pathlib.Path(tmp) / "ctaphid_tx_test"
            subprocess.run(
                [
                    "cc",
                    "-std=c11",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-I",
                    str(COMPONENT),
                    "-I",
                    str(COMPONENT / "include"),
                    str(ROOT / "tests" / "host" / "ctaphid_tx_test.c"),
                    str(COMPONENT / "p4_ctaphid_tx.c"),
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
            self.assertEqual(result.stdout, "PASS ctaphid send frames\n")


if __name__ == "__main__":
    unittest.main()
