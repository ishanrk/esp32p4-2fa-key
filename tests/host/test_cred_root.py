import pathlib
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
COMPONENT = ROOT / "components" / "p4_cred"


class CredentialRootTests(unittest.TestCase):
    def test_actual_root_source_with_nvs_failures(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = pathlib.Path(tmp) / "cred_root_test"
            subprocess.run(
                [
                    "cc",
                    "-std=c11",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-I",
                    str(ROOT / "tests" / "host" / "root_fakes"),
                    "-I",
                    str(COMPONENT / "include"),
                    "-I",
                    str(COMPONENT),
                    "-I",
                    str(ROOT / "components" / "p4_crypto" / "include"),
                    str(ROOT / "tests" / "host" / "cred_root_test.c"),
                    str(COMPONENT / "p4_root.c"),
                    "-o",
                    str(output),
                ],
                check=True,
            )
            for scenario in (
                "missing",
                "existing",
                "short",
                "long",
                "read_error",
                "load_error",
                "init_error",
                "commit_error",
            ):
                result = subprocess.run(
                    [str(output), scenario],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(
                    result.stdout,
                    "PASS fail closed development credential root\n",
                )

    def test_no_erase_or_root_logging_path(self):
        source = (COMPONENT / "p4_root.c").read_text(encoding="utf-8")
        self.assertNotIn("nvs_flash_erase", source)
        self.assertNotIn("ESP_LOG_BUFFER", source)
        self.assertNotIn("printf", source)


if __name__ == "__main__":
    unittest.main()
