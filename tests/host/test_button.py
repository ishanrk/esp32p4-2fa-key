import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]


class ButtonTests(unittest.TestCase):
    def test_button_helper(self):
        compiler = shutil.which("cc")
        self.assertIsNotNone(compiler, "host C compiler not found")

        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "button_test"
            compile_result = subprocess.run(
                [
                    compiler,
                    "-std=c11",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-I",
                    str(REPO / "components" / "p4_board" / "include"),
                    str(REPO / "components" / "p4_board" / "p4_button.c"),
                    str(REPO / "tests" / "host" / "button_test.c"),
                    "-o",
                    str(binary),
                ],
                capture_output=True,
                text=True,
                timeout=20,
            )
            self.assertEqual(
                compile_result.returncode,
                0,
                compile_result.stdout + compile_result.stderr,
            )

            run_result = subprocess.run(
                [str(binary)],
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(
                run_result.returncode,
                0,
                run_result.stdout + run_result.stderr,
            )
            self.assertIn("PASS button level conversion", run_result.stdout)


if __name__ == "__main__":
    unittest.main()
