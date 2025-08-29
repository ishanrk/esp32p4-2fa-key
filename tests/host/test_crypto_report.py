import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
REPORTER = REPO / "scripts" / "crypto_report.py"
ELF_SHA = "0123456789abcdef" * 4

# independent fixture lists keep reporter omissions visible
REQUIRED_CONFIG = (
    "CONFIG_ESP32P4_SELECTS_REV_LESS_V3",
    "CONFIG_MBEDTLS_SHA256_C",
    "CONFIG_MBEDTLS_HARDWARE_SHA",
    "CONFIG_MBEDTLS_AES_C",
    "CONFIG_MBEDTLS_GCM_C",
    "CONFIG_MBEDTLS_HARDWARE_AES",
    "CONFIG_MBEDTLS_HARDWARE_GCM",
    "CONFIG_MBEDTLS_ECP_C",
    "CONFIG_MBEDTLS_ECDH_C",
    "CONFIG_MBEDTLS_ECDSA_C",
    "CONFIG_MBEDTLS_ECP_DP_SECP256R1_ENABLED",
    "CONFIG_MBEDTLS_HARDWARE_ECC",
)

DISABLED_CONFIG = (
    "CONFIG_MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH",
    "CONFIG_MBEDTLS_AES_SOFT_FALLBACK",
    "CONFIG_MBEDTLS_GCM_SUPPORT_NON_AES_CIPHER",
    "CONFIG_MBEDTLS_ECC_OTHER_CURVES_SOFT_FALLBACK",
    "CONFIG_MBEDTLS_HARDWARE_ECDSA_SIGN",
    "CONFIG_MBEDTLS_HARDWARE_ECDSA_VERIFY",
)

REQUIRED_TESTS = (
    "rng_lengths",
    "rng_consecutive",
    "rng_nonce_smoke",
    "sha_empty",
    "sha_abc",
    "sha_block",
    "sha_multi",
    "sha_precondition",
    "gcm_empty",
    "gcm_plain",
    "gcm_multi",
    "gcm_aad",
    "gcm_tamper",
    "gcm_zero_open",
    "gcm_alias",
    "gcm_hw_one_shot",
    "p256_scalars",
    "p256_generate",
    "p256_sign",
    "p256_negative",
    "p256_der",
    "p256_repeat",
    "p256_siglen_alias",
)

REQUIRED_BENCHES = (
    ("sha256_32", 64),
    ("sha256_4096", 24),
    ("gcm_seal_64", 32),
    ("gcm_open_64", 32),
    ("gcm_seal_1024", 16),
    ("gcm_open_1024", 16),
    ("p256_keygen", 8),
    ("p256_sign", 16),
    ("p256_verify", 16),
)


def config_text(target=True, overrides=None):
    values = {name: "y" for name in REQUIRED_CONFIG}
    values.update({name: "n" for name in DISABLED_CONFIG})
    if target:
        values["CONFIG_P4KEY_CRYPTO_SELFTEST"] = "y"
        values["CONFIG_P4KEY_CRYPTO_BENCH"] = "y"
    if overrides:
        values.update(overrides)

    lines = []
    for name, value in values.items():
        if value == "n":
            lines.append(f"# {name} is not set")
        else:
            lines.append(f"{name}={value}")
    return "\n".join(lines) + "\n"


def log_lines():
    lines = [
        "I (30) boot: chip revision: v1.3",
        f"I (31) app_init: ELF file SHA256: {ELF_SHA[:9]}...",
        f"I (1) p4crypto: CRYPTO_SELFTEST START tests={len(REQUIRED_TESTS)}",
    ]
    for index, name in enumerate(REQUIRED_TESTS, start=1):
        lines.append(
            f"I ({index}) p4crypto: CRYPTO_TEST {name} PASS us={index}"
        )
    lines.extend(
        [
            f"I (30) p4crypto: CRYPTO_SELFTEST PASS tests={len(REQUIRED_TESTS)}",
            "I (31) p4crypto: CRYPTO_BENCHMARK START",
        ]
    )
    for index, (name, reps) in enumerate(REQUIRED_BENCHES, start=1):
        lines.append(
            "I (40) p4crypto: CRYPTO_BENCH "
            f"{name} PASS min_us={index} reps={reps}"
        )
    lines.append(
        f"I (50) p4crypto: CRYPTO_BENCHMARK PASS tests={len(REQUIRED_BENCHES)}"
    )
    return lines


class CryptoReportTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.config = self.root / "sdkconfig"
        self.log = self.root / "target.log"
        self.size = self.root / "size.txt"
        self.image = self.root / "p4key.bin"
        self.output = self.root / "report.txt"
        self.config.write_text(config_text(), encoding="utf-8")
        self.log.write_text("\n".join(log_lines()) + "\n", encoding="utf-8")
        self.size.write_text(
            "Total image size: 345,100 bytes (.bin may be padded larger)\n",
            encoding="utf-8",
        )
        image = bytearray(32 + 256)
        image[0] = 0xE9
        image[1] = 1
        image[28:32] = (256).to_bytes(4, "little")
        image[32:36] = (0xABCD5432).to_bytes(4, "little")
        image[176:208] = bytes.fromhex(ELF_SHA)
        self.image.write_bytes(image)

    def tearDown(self):
        self.temporary.cleanup()

    def run_report(self, include_log=True, include_size=True, include_image=True):
        command = [
            sys.executable,
            str(REPORTER),
            "--sdkconfig",
            str(self.config),
            "--output",
            str(self.output),
        ]
        if include_log:
            command.extend(["--log", str(self.log)])
        if include_size:
            command.extend(["--size", str(self.size)])
        if include_image:
            command.extend(["--image", str(self.image)])
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=10,
        )

    def test_valid_ansi_crlf_report_is_deterministic_and_whitelisted(self):
        lines = log_lines()
        lines.insert(1, "private key: 00112233445566778899aabbccddeeff")
        wrapped = [f"\x1b[32m{line}\x1b[0m" for line in lines]
        self.log.write_text("\r\n".join(wrapped) + "\r\n", encoding="utf-8")

        first = self.run_report()
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        report = self.output.read_text(encoding="utf-8")
        self.assertIn("report status\nPASS", report)
        self.assertIn("IDF total image size bytes 345100", report)
        self.assertIn("boot fingerprint matches app image PASS", report)
        self.assertIn("gcm_hw_one_shot PASS", report)
        self.assertIn("p256_siglen_alias PASS", report)
        self.assertNotIn("00112233445566778899aabbccddeeff", report)

        second = self.run_report()
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        self.assertEqual(report, self.output.read_text(encoding="utf-8"))

    def test_mismatched_or_malformed_app_image_fails(self):
        valid_image = self.image.read_bytes()
        valid_log = self.log.read_text(encoding="utf-8")
        image = bytearray(valid_image)
        image[176] ^= 0xFF
        self.image.write_bytes(image)
        result = self.run_report()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(
            "target boot fingerprint does not match app image",
            self.output.read_text(encoding="utf-8"),
        )

        self.image.write_bytes(valid_image)
        self.log.write_text(
            "\n".join(
                line
                for line in valid_log.splitlines()
                if "ELF file SHA256" not in line
            )
            + "\n",
            encoding="utf-8",
        )
        result = self.run_report()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(
            "target log lacks a boot ELF SHA256 fingerprint",
            self.output.read_text(encoding="utf-8"),
        )

        self.log.write_text(valid_log, encoding="utf-8")
        invalid_structures = (
            (0, 256),
            (17, 256),
            (1, 0),
            (1, 175),
            (1, 255),
            (1, 512),
        )
        for segment_count, segment_length in invalid_structures:
            with self.subTest(
                segment_count=segment_count,
                segment_length=segment_length,
            ):
                image = bytearray(valid_image)
                image[1] = segment_count
                image[28:32] = segment_length.to_bytes(4, "little")
                self.image.write_bytes(image)
                result = self.run_report()
                self.assertEqual(
                    result.returncode, 1, result.stdout + result.stderr
                )
                self.assertIn(
                    "supplied app image evidence is invalid",
                    self.output.read_text(encoding="utf-8"),
                )

        self.image.write_bytes(b"not an esp image")
        result = self.run_report()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(
            "supplied app image evidence is invalid",
            self.output.read_text(encoding="utf-8"),
        )

    def test_omitted_log_marks_target_unavailable(self):
        self.config.write_text(config_text(target=False), encoding="utf-8")
        result = self.run_report(include_log=False, include_size=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = self.output.read_text(encoding="utf-8")
        self.assertIn("report status\nTARGET DATA UNAVAILABLE", report)
        self.assertIn("required named tests 23 NOT ATTEMPTED", report)
        self.assertIn("required named benchmarks 9 NOT ATTEMPTED", report)
        self.assertNotIn("elapsed_us\n", report)

    def test_missing_required_test_fails(self):
        lines = [line for line in log_lines() if " sha_multi " not in line]
        self.log.write_text("\n".join(lines) + "\n", encoding="utf-8")
        result = self.run_report()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("report status\nFAIL", self.output.read_text(encoding="utf-8"))

    def test_explicit_test_failure_fails_without_copying_codes(self):
        text = "\n".join(log_lines()) + "\n"
        text = text.replace(
            "CRYPTO_TEST sha_abc PASS us=5",
            "CRYPTO_TEST sha_abc FAIL code=-132 detail=-133 us=5",
        )
        self.log.write_text(text, encoding="utf-8")
        result = self.run_report()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        report = self.output.read_text(encoding="utf-8")
        self.assertIn("supplied target evidence is invalid", report)
        self.assertNotIn("target data unavailable", report)
        self.assertNotIn("-132", report)
        self.assertNotIn("-133", report)

    def test_duplicate_session_or_name_fails(self):
        variants = []
        lines = log_lines()
        variants.append(lines + lines)
        variants.append(lines[:3] + [lines[2]] + lines[3:])
        for variant in variants:
            with self.subTest(records=len(variant)):
                self.log.write_text(
                    "\n".join(variant) + "\n", encoding="utf-8"
                )
                result = self.run_report()
                self.assertEqual(
                    result.returncode, 1, result.stdout + result.stderr
                )

    def test_wrong_test_order_or_summary_count_fails(self):
        lines = log_lines()
        lines[2], lines[3] = lines[3], lines[2]
        self.log.write_text("\n".join(lines) + "\n", encoding="utf-8")
        result = self.run_report()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

        text = "\n".join(log_lines()).replace(
            "CRYPTO_SELFTEST PASS tests=23",
            "CRYPTO_SELFTEST PASS tests=22",
        )
        self.log.write_text(text + "\n", encoding="utf-8")
        result = self.run_report()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    def test_missing_benchmark_or_wrong_repetitions_fails(self):
        lines = [line for line in log_lines() if " gcm_open_1024 " not in line]
        self.log.write_text("\n".join(lines) + "\n", encoding="utf-8")
        result = self.run_report()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

        text = "\n".join(log_lines()).replace(
            "p256_verify PASS min_us=9 reps=16",
            "p256_verify PASS min_us=9 reps=15",
        )
        self.log.write_text(text + "\n", encoding="utf-8")
        result = self.run_report()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    def test_bad_hardware_config_or_test_profile_fails(self):
        variants = [
            {"CONFIG_MBEDTLS_HARDWARE_ECDSA_SIGN": "y"},
            {"CONFIG_MBEDTLS_HARDWARE_GCM": "n"},
            {"CONFIG_P4KEY_CRYPTO_BENCH": "n"},
        ]
        for override in variants:
            with self.subTest(override=override):
                self.config.write_text(
                    config_text(overrides=override), encoding="utf-8"
                )
                result = self.run_report()
                self.assertEqual(
                    result.returncode, 1, result.stdout + result.stderr
                )

        self.config.write_text(
            config_text() + "CONFIG_MBEDTLS_HARDWARE_GCM=n\n",
            encoding="utf-8",
        )
        result = self.run_report()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(
            "sdkconfig contains duplicate symbol assignments",
            self.output.read_text(encoding="utf-8"),
        )

    def test_supplied_missing_log_is_an_input_error(self):
        self.log.unlink()
        result = self.run_report()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertFalse(self.output.exists())

    def test_malformed_or_conflicting_size_fails(self):
        variants = [
            "no total here\n",
            "Total image size: 1 bytes\nTotal image size: 2 bytes\n",
            "Total image size: 2 bytes\nTotal image size: 2 bytes\n",
            "Total image size: 1,2,3 bytes\n",
        ]
        for text in variants:
            with self.subTest(text=text):
                self.size.write_text(text, encoding="utf-8")
                result = self.run_report()
                self.assertEqual(
                    result.returncode, 1, result.stdout + result.stderr
                )
                self.assertIn(
                    "supplied IDF size evidence is invalid",
                    self.output.read_text(encoding="utf-8"),
                )


if __name__ == "__main__":
    unittest.main()
