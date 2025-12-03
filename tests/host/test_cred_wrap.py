import pathlib
import re
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
COMPONENT = ROOT / "components" / "p4_cred"


class WrappedCredentialTests(unittest.TestCase):
    def test_actual_credential_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = pathlib.Path(tmp) / "cred_wrap_test"
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
                    str(COMPONENT),
                    "-I",
                    str(ROOT / "components" / "p4_crypto" / "include"),
                    str(ROOT / "tests" / "host" / "cred_wrap_test.c"),
                    str(COMPONENT / "p4_cred.c"),
                    str(COMPONENT / "p4_aaguid.c"),
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
                "PASS exact wrapped credential format and failures\n",
            )

    def test_credential_component_has_no_heap_or_logging(self):
        sources = "\n".join(
            path.read_text(encoding="utf-8")
            for path in sorted(COMPONENT.glob("*.c"))
        )
        without_comments = re.sub(
            r"/\*.*?\*/|//[^\n]*", "", sources, flags=re.DOTALL
        )
        self.assertIsNone(
            re.search(
                r"\b(?:malloc|calloc|realloc|free|pvPortMalloc|vPortFree)\s*\(",
                without_comments,
            )
        )
        self.assertNotIn("ESP_LOG_BUFFER", sources)
        self.assertNotIn("printf", sources)


if __name__ == "__main__":
    unittest.main()
