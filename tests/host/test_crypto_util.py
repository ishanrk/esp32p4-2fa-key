import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]


class CryptoUtilTests(unittest.TestCase):
    def test_p256_scalar_and_der_helpers(self):
        compiler = shutil.which("cc")
        self.assertIsNotNone(compiler, "host C compiler not found")

        with tempfile.TemporaryDirectory() as temp:
            binary = Path(temp) / "p256_util_test"
            compile_result = subprocess.run(
                [
                    compiler,
                    "-std=c11",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-I",
                    str(REPO / "components" / "p4_crypto"),
                    str(
                        REPO
                        / "components"
                        / "p4_crypto"
                        / "p4_crypto_p256_util.c"
                    ),
                    str(REPO / "tests" / "host" / "p256_util_test.c"),
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
            self.assertIn(
                "PASS p256 scalar and strict DER helpers",
                run_result.stdout,
            )


if __name__ == "__main__":
    unittest.main()
