import pathlib
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
COMPONENT = ROOT / "components" / "p4_press"


class PressTests(unittest.TestCase):
    def test_actual_fresh_press_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = pathlib.Path(tmp) / "press_test"
            subprocess.run(
                [
                    "cc",
                    "-std=c11",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-I",
                    str(ROOT / "tests" / "host" / "press_fakes"),
                    "-I",
                    str(COMPONENT / "include"),
                    "-I",
                    str(ROOT / "components" / "p4_ctaphid" / "include"),
                    str(ROOT / "tests" / "host" / "press_test.c"),
                    str(COMPONENT / "p4_press.c"),
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
            self.assertEqual(result.stdout, "PASS fresh button presence\n")


if __name__ == "__main__":
    unittest.main()
