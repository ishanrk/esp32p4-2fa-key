import pathlib
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
COMPONENT = ROOT / "components" / "p4_ctaphid"


class CtaphidReceiveTests(unittest.TestCase):
    def test_actual_receive_core(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = pathlib.Path(tmp) / "ctaphid_rx_test"
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
                    str(ROOT / "tests" / "host" / "ctaphid_rx_test.c"),
                    str(COMPONENT / "p4_ctaphid_rx.c"),
                    str(COMPONENT / "p4_ctaphid_chan.c"),
                    str(COMPONENT / "p4_ctaphid_time.c"),
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
            self.assertEqual(result.stdout, "PASS ctaphid receive paths\n")


if __name__ == "__main__":
    unittest.main()
