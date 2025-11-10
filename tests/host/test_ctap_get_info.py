import pathlib
import re
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
COMPONENT = ROOT / "components" / "p4_ctap"


class CtapGetInfoTests(unittest.TestCase):
    def test_actual_get_info_dispatch_and_cbor(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = pathlib.Path(tmp) / "ctap_get_info_test"
            subprocess.run(
                [
                    "cc",
                    "-std=c11",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-I",
                    str(COMPONENT / "include"),
                    str(ROOT / "tests" / "host" / "ctap_get_info_test.c"),
                    str(COMPONENT / "p4_cbor.c"),
                    str(COMPONENT / "p4_ctap.c"),
                    str(COMPONENT / "p4_get_info.c"),
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
                "PASS minimal authenticator get info\n",
            )

    def test_ctap_component_has_no_heap_calls(self):
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


if __name__ == "__main__":
    unittest.main()
