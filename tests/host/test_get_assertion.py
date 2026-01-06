import pathlib
import subprocess
import tempfile
import unittest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


ROOT = pathlib.Path(__file__).resolve().parents[2]
CTAP = ROOT / "components" / "p4_ctap"
CRED = ROOT / "components" / "p4_cred"
CLIENT_HASH = bytes(
    [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x08,
        0x19, 0x2A, 0x3B, 0x4C, 0x5D, 0x6E, 0x7F, 0x10,
        0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x07, 0x18,
        0x29, 0x3A, 0x4B, 0x5C, 0x6D, 0x7E, 0x0F, 0x20,
    ]
)


class GetAssertionTests(unittest.TestCase):
    def test_actual_get_assertion_and_wrapped_credential_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = pathlib.Path(tmp) / "get_assertion_test"
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
                    str(ROOT / "tests" / "host" / "get_assertion_test.c"),
                    str(ROOT / "tests" / "host" / "get_assertion_fakes.c"),
                    str(CTAP / "p4_cbor.c"),
                    str(CTAP / "p4_ctap.c"),
                    str(CTAP / "p4_get_info.c"),
                    str(CTAP / "p4_make_credential.c"),
                    str(CTAP / "p4_get_assertion.c"),
                    str(CRED / "p4_cred.c"),
                    str(CRED / "p4_aaguid.c"),
                    "-lcrypto",
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
            lines = result.stdout.splitlines()
            self.assertEqual(
                lines[-1],
                "PASS dispatcher make credential and get assertion",
            )
            evidence = dict(line.split(" ", 1) for line in lines[:-1])
            self.assertEqual(
                set(evidence),
                {"PUBLIC_X", "PUBLIC_Y", "AUTH_DATA", "SIGNATURE"},
            )

            x = bytes.fromhex(evidence["PUBLIC_X"])
            y = bytes.fromhex(evidence["PUBLIC_Y"])
            auth_data = bytes.fromhex(evidence["AUTH_DATA"])
            signature = bytes.fromhex(evidence["SIGNATURE"])
            self.assertEqual(len(x), 32)
            self.assertEqual(len(y), 32)
            self.assertEqual(len(auth_data), 37)

            public_key = ec.EllipticCurvePublicNumbers(
                int.from_bytes(x, "big"),
                int.from_bytes(y, "big"),
                ec.SECP256R1(),
            ).public_key()
            public_key.verify(
                signature,
                auth_data + CLIENT_HASH,
                ec.ECDSA(hashes.SHA256()),
            )

            changed_hash = bytes([CLIENT_HASH[0] ^ 0x80]) + CLIENT_HASH[1:]
            with self.assertRaises(InvalidSignature):
                public_key.verify(
                    signature,
                    auth_data + changed_hash,
                    ec.ECDSA(hashes.SHA256()),
                )


if __name__ == "__main__":
    unittest.main()
