import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
STATE_CHECK = REPO / "scripts" / "state_check.py"

PROJECT_STATE = """P4KEY PROJECT STATE

updated utc
2026 08 26 00 00 00

project
ESP32-P4 2FA Key

current stage
01 repository and board baseline

stage status
in progress fixture

repository path
/tmp/p4key-fixture

branch
main

upstream
origin/main

ESP IDF
6.0.2

target
esp32p4
"""

CHALLENGES = """P4KEY CHALLENGES AND ERRORS

append only

fixture has no entries
"""

DECISIONS = """P4KEY DECISIONS

append only

fixture has no entries
"""


class BaselineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "PROJECT_STATE.txt").write_text(
            PROJECT_STATE, encoding="utf-8"
        )
        (self.root / "CHALLENGES_AND_ERRORS.txt").write_text(
            CHALLENGES, encoding="utf-8"
        )
        (self.root / "DECISIONS.txt").write_text(
            DECISIONS, encoding="utf-8"
        )

    def tearDown(self):
        self.temp.cleanup()

    def run_state_check(self):
        return subprocess.run(
            [sys.executable, str(STATE_CHECK), "--root", str(self.root)],
            capture_output=True,
            text=True,
            timeout=10,
        )

    def test_button_helper(self):
        compiler = shutil.which("cc")
        self.assertIsNotNone(compiler, "host C compiler not found")

        binary = self.root / "button_test"
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

    def test_state_check_accepts_filled_templates(self):
        result = self.run_state_check()
        self.assertEqual(
            result.returncode,
            0,
            result.stdout + result.stderr,
        )
        self.assertIn("PASS continuity files", result.stdout)

    def test_state_check_rejects_missing_file(self):
        (self.root / "DECISIONS.txt").unlink()
        result = self.run_state_check()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "FAIL missing continuity file: DECISIONS.txt",
            result.stdout,
        )

    def test_state_check_rejects_likely_secret(self):
        path = self.root / "PROJECT_STATE.txt"
        with path.open("a", encoding="utf-8") as output:
            output.write(
                "\nprivate key: "
                "00112233445566778899aabbccddeeff\n"
            )

        result = self.run_state_check()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "FAIL likely secret material in PROJECT_STATE.txt",
            result.stdout,
        )


if __name__ == "__main__":
    unittest.main()
