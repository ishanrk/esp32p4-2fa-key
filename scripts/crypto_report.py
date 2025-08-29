#!/usr/bin/env python3

import argparse
import os
import re
import tempfile
from pathlib import Path

from check_crypto_config import DISABLED, REQUIRED


REPO = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT = REPO / "docs" / "generated" / "CRYPTO_REPORT.txt"

TESTS = (
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

BENCHES = (
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

ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
TEST_PASS_RE = re.compile(
    r"CRYPTO_TEST ([a-z0-9_]+) PASS us=([0-9]+)"
)
TEST_FAIL_RE = re.compile(
    r"CRYPTO_TEST ([a-z0-9_]+) FAIL "
    r"code=(-?[0-9]+) detail=(-?[0-9]+) us=([0-9]+)"
)
BENCH_PASS_RE = re.compile(
    r"CRYPTO_BENCH ([a-z0-9_]+) PASS "
    r"min_us=([0-9]+) reps=([0-9]+)"
)
BENCH_FAIL_RE = re.compile(
    r"CRYPTO_BENCH ([a-z0-9_]+) FAIL "
    r"code=(-?[0-9]+) detail=(-?[0-9]+) reps=([0-9]+)"
)
SIZE_RE = re.compile(
    r"Total image size: ([0-9]+|[0-9]{1,3}(?:,[0-9]{3})+) bytes"
)
REVISION_RE = re.compile(r"chip revision:\s*v([0-9]+(?:\.[0-9]+)*)")
ELF_RE = re.compile(
    r"ELF file SHA256:\s*([0-9a-fA-F]{8,64})(?:\.\.\.)?(?:\s|$)"
)

# idf app images place esp_app_desc_t at the start of segment zero
ESP_IMAGE_MAGIC = 0xE9
ESP_IMAGE_MAX_SEGMENTS = 16
APP_DESC_OFFSET = 24 + 8
APP_DESC_LENGTH = 256
APP_DESC_MAGIC = 0xABCD5432
APP_ELF_SHA_OFFSET = APP_DESC_OFFSET + 144
APP_ELF_SHA_LENGTH = 32


class InputError(Exception):
    pass


class EvidenceError(Exception):
    pass


def clean_text(text):
    return ANSI_RE.sub("", text).replace("\r", "")


def read_input(path, label):
    try:
        return path.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeError) as error:
        raise InputError(f"{label} could not be read") from error


def read_binary(path, label):
    try:
        return path.read_bytes()
    except OSError as error:
        raise InputError(f"{label} could not be read") from error


def display_path(path):
    if path is None:
        return "not supplied"
    try:
        return str(path.resolve().relative_to(REPO.resolve()))
    except ValueError:
        return str(path)


def parse_config(text):
    values = {}
    duplicates = set()

    for raw in text.splitlines():
        line = raw.strip()
        name = None
        value = None
        if line.startswith("# CONFIG_") and line.endswith(" is not set"):
            name = line[2:-11]
            value = "n"
        elif line.startswith("CONFIG_") and "=" in line:
            name, value = line.split("=", 1)

        if name is None:
            continue
        if name in values:
            duplicates.add(name)
            continue
        values[name] = value

    return values, duplicates


def validate_config(path, target_log_supplied):
    text = read_input(path, "sdkconfig")
    values, duplicates = parse_config(text)
    rows = []
    errors = []

    if duplicates:
        errors.append("sdkconfig contains duplicate symbol assignments")

    for name in REQUIRED:
        observed = values.get(name, "missing")
        status = "PASS" if observed == "y" else "FAIL"
        rows.append((name, "y", observed, status))
        if status == "FAIL":
            errors.append("a required hardware configuration is not enabled")

    for name in DISABLED:
        observed = values.get(name, "missing")
        status = "PASS" if observed == "n" else "FAIL"
        rows.append((name, "n", observed, status))
        if status == "FAIL":
            errors.append("a forbidden fallback or dedicated path is enabled")

    selftest = values.get("CONFIG_P4KEY_CRYPTO_SELFTEST", "n")
    bench = values.get("CONFIG_P4KEY_CRYPTO_BENCH", "n")
    if target_log_supplied and (selftest != "y" or bench != "y"):
        errors.append("target evidence requires both test profile flags")

    return {
        "rows": rows,
        "selftest": selftest,
        "bench": bench,
        "errors": sorted(set(errors)),
    }


def marker_payloads(text):
    payloads = []
    revisions = []
    elf_prefixes = []

    for raw in clean_text(text).splitlines():
        revision = REVISION_RE.search(raw)
        if revision is not None:
            revisions.append(revision.group(1))

        elf_prefix = ELF_RE.search(raw)
        if elf_prefix is not None:
            elf_prefixes.append(elf_prefix.group(1).lower())

        offset = raw.find("CRYPTO_")
        if offset >= 0:
            payloads.append(raw[offset:].strip())

    return payloads, revisions, elf_prefixes


def parse_target_log(text):
    payloads, revisions, elf_prefixes = marker_payloads(text)
    sequence = []
    test_records = []
    bench_records = []
    start_counts = []
    pass_counts = []
    bench_starts = 0
    bench_counts = []
    failures = []

    for payload in payloads:
        match = re.fullmatch(r"CRYPTO_SELFTEST START tests=([0-9]+)", payload)
        if match is not None:
            count = int(match.group(1))
            start_counts.append(count)
            sequence.append(("self_start", count))
            continue

        match = TEST_PASS_RE.fullmatch(payload)
        if match is not None:
            name = match.group(1)
            test_records.append((name, int(match.group(2)), "PASS"))
            sequence.append(("test", name, "PASS"))
            continue

        match = TEST_FAIL_RE.fullmatch(payload)
        if match is not None:
            name = match.group(1)
            test_records.append((name, int(match.group(4)), "FAIL"))
            sequence.append(("test", name, "FAIL"))
            failures.append("a target self test reported FAIL")
            continue

        match = re.fullmatch(r"CRYPTO_SELFTEST PASS tests=([0-9]+)", payload)
        if match is not None:
            count = int(match.group(1))
            pass_counts.append(count)
            sequence.append(("self_pass", count))
            continue

        if payload == "CRYPTO_BENCHMARK START":
            bench_starts += 1
            sequence.append(("bench_start",))
            continue

        match = BENCH_PASS_RE.fullmatch(payload)
        if match is not None:
            name = match.group(1)
            bench_records.append(
                (
                    name,
                    int(match.group(2)),
                    int(match.group(3)),
                    "PASS",
                )
            )
            sequence.append(("bench", name, "PASS"))
            continue

        match = BENCH_FAIL_RE.fullmatch(payload)
        if match is not None:
            name = match.group(1)
            bench_records.append((name, 0, int(match.group(4)), "FAIL"))
            sequence.append(("bench", name, "FAIL"))
            failures.append("a target benchmark reported FAIL")
            continue

        match = re.fullmatch(
            r"CRYPTO_BENCHMARK PASS tests=([0-9]+)", payload
        )
        if match is not None:
            count = int(match.group(1))
            bench_counts.append(count)
            sequence.append(("bench_pass", count))
            continue

        if "FAIL" in payload:
            failures.append("a target crypto summary reported FAIL")
            continue

        raise EvidenceError("target log contains a malformed crypto marker")

    expected_markers = 1 + len(TESTS) + 1 + 1 + len(BENCHES) + 1
    expected_sequence = [("self_start", len(TESTS))]
    expected_sequence.extend(("test", name, "PASS") for name in TESTS)
    expected_sequence.extend(
        [("self_pass", len(TESTS)), ("bench_start",)]
    )
    expected_sequence.extend(
        ("bench", name, "PASS") for name, repetitions in BENCHES
    )
    expected_sequence.append(("bench_pass", len(BENCHES)))
    if sequence != expected_sequence:
        failures.append("target crypto records are not one ordered session")
    if len(payloads) != expected_markers:
        failures.append("target log has missing duplicate or extra crypto records")
    if start_counts != [len(TESTS)] or pass_counts != [len(TESTS)]:
        failures.append("target self test summary count is invalid")
    if bench_starts != 1 or bench_counts != [len(BENCHES)]:
        failures.append("target benchmark summary count is invalid")

    names = tuple(record[0] for record in test_records)
    if names != TESTS:
        failures.append("target self test names or order are invalid")
    if any(record[2] != "PASS" for record in test_records):
        failures.append("not every target self test passed")

    bench_names = tuple(record[0] for record in bench_records)
    expected_bench_names = tuple(name for name, unused in BENCHES)
    if bench_names != expected_bench_names:
        failures.append("target benchmark names or order are invalid")
    if any(record[3] != "PASS" for record in bench_records):
        failures.append("not every target benchmark passed")
    if len(bench_records) == len(BENCHES):
        for record, expected in zip(bench_records, BENCHES):
            if record[2] != expected[1]:
                failures.append("a target benchmark repetition count is invalid")

    unique_revisions = sorted(set(revisions))
    if len(unique_revisions) > 1:
        failures.append("target log contains conflicting chip revisions")

    unique_elf_prefixes = sorted(set(elf_prefixes))
    if len(unique_elf_prefixes) > 1:
        failures.append("target log contains conflicting boot ELF fingerprints")

    if failures:
        raise EvidenceError("; ".join(sorted(set(failures))))

    return {
        "tests": test_records,
        "benches": bench_records,
        "revision": unique_revisions[0] if unique_revisions else "not recorded",
        "elf_prefix": (
            unique_elf_prefixes[0] if unique_elf_prefixes else None
        ),
    }


def parse_app_image(data):
    hash_end = APP_ELF_SHA_OFFSET + APP_ELF_SHA_LENGTH
    if len(data) < APP_DESC_OFFSET or data[0] != ESP_IMAGE_MAGIC:
        raise EvidenceError("app image lacks a valid ESP image header")

    segment_count = data[1]
    if segment_count < 1 or segment_count > ESP_IMAGE_MAX_SEGMENTS:
        raise EvidenceError("app image declares an invalid segment count")

    first_segment_length = int.from_bytes(data[28:32], "little")
    if first_segment_length < APP_DESC_LENGTH:
        raise EvidenceError(
            "app image first segment cannot contain the application descriptor"
        )
    if APP_DESC_OFFSET + first_segment_length > len(data):
        raise EvidenceError("app image first segment is truncated")

    descriptor_magic = int.from_bytes(
        data[APP_DESC_OFFSET:APP_DESC_OFFSET + 4], "little"
    )
    if descriptor_magic != APP_DESC_MAGIC:
        raise EvidenceError("app image lacks the expected application descriptor")

    elf_sha = data[APP_ELF_SHA_OFFSET:hash_end]
    if elf_sha in {bytes(APP_ELF_SHA_LENGTH), bytes([0xFF]) * APP_ELF_SHA_LENGTH}:
        raise EvidenceError("app image has an invalid ELF SHA256 descriptor")
    return elf_sha.hex()


def parse_size(text):
    matches = SIZE_RE.findall(clean_text(text))
    if len(matches) != 1:
        raise EvidenceError("size output lacks one unambiguous total image size")
    value = int(matches[0].replace(",", ""))
    if value <= 0:
        raise EvidenceError("size output total is not positive")
    return value


def report_lines(
    status,
    inputs,
    config,
    target,
    image_size,
    app_elf_sha,
    binding_status,
    errors,
):
    lines = [
        "P4KEY CRYPTO PROOF REPORT",
        "",
        "report status",
        status,
        "",
        "EVIDENCE INPUTS",
        "",
        f"sdkconfig {display_path(inputs['sdkconfig'])}",
        f"target log {display_path(inputs['log'])}",
        f"size output {display_path(inputs['size'])}",
        f"app image {display_path(inputs['image'])}",
        "source route proof docs/CRYPTO_PATHS.txt",
        "",
        "HARDWARE CONFIGURATION",
        "",
        "symbol expected observed status",
    ]

    for name, expected, observed, row_status in config["rows"]:
        lines.append(f"{name} {expected} {observed} {row_status}")

    lines.extend(
        [
            "",
            "dedicated eFuse ECDSA signer",
            (
                "disabled for per credential signing PASS"
                if all(
                    row[2] == "n"
                    for row in config["rows"]
                    if row[0]
                    in {
                        "CONFIG_MBEDTLS_HARDWARE_ECDSA_SIGN",
                        "CONFIG_MBEDTLS_HARDWARE_ECDSA_VERIFY",
                    }
                )
                else "dedicated path configuration FAIL"
            ),
            "",
            "TEST PROFILE",
            "",
            f"CONFIG_P4KEY_CRYPTO_SELFTEST {config['selftest']}",
            f"CONFIG_P4KEY_CRYPTO_BENCH {config['bench']}",
            "",
            "TARGET SELF TEST",
            "",
        ]
    )

    if target is None:
        if inputs["log"] is None:
            target_state = "target data unavailable"
            test_result = f"required named tests {len(TESTS)} NOT ATTEMPTED"
            bench_result = (
                f"required named benchmarks {len(BENCHES)} NOT ATTEMPTED"
            )
        else:
            target_state = "supplied target evidence is invalid"
            test_result = f"required named tests {len(TESTS)} FAIL"
            bench_result = f"required named benchmarks {len(BENCHES)} FAIL"
        lines.extend(
            [
                target_state,
                test_result,
                "",
                "TARGET BENCHMARK",
                "",
                target_state,
                bench_result,
            ]
        )
    else:
        lines.extend(
            [
                f"chip revision {target['revision']}",
                "name status elapsed_us",
            ]
        )
        for name, elapsed, record_status in target["tests"]:
            lines.append(f"{name} {record_status} {elapsed}")

        lines.extend(["", "TARGET BENCHMARK", "", "name status minimum_us repetitions"])
        for name, minimum, repetitions, record_status in target["benches"]:
            lines.append(
                f"{name} {record_status} {minimum} {repetitions}"
            )

    lines.extend(["", "APP IMAGE BINDING", ""])
    if target is None or target.get("elf_prefix") is None:
        lines.append("boot ELF SHA256 prefix unavailable")
    else:
        lines.append(f"boot ELF SHA256 prefix {target['elf_prefix']}")
    if app_elf_sha is None:
        if inputs["image"] is None:
            lines.append("app image ELF SHA256 unavailable")
        else:
            lines.append("supplied app image evidence is invalid")
    else:
        lines.append(f"app image ELF SHA256 {app_elf_sha}")
    lines.append(f"boot fingerprint matches app image {binding_status}")

    lines.extend(["", "IMAGE SIZE", ""])
    if image_size is None:
        if inputs["size"] is None:
            lines.append("IDF total image size unavailable")
        else:
            lines.append("supplied IDF size evidence is invalid")
    else:
        lines.append(f"IDF total image size bytes {image_size}")

    if errors:
        lines.extend(["", "VALIDATION ERRORS", ""])
        for error in errors:
            lines.append(error)

    lines.extend(
        [
            "",
            "PROOF LIMITS",
            "",
            "hardware route selection comes from the generated sdkconfig and pinned source paths in docs/CRYPTO_PATHS.txt",
            "timing is supporting target data only and does not select an implementation",
            "no constant time property is claimed from these measurements",
            "the random collision smoke sample does not prove entropy quality",
            "boot image binding is limited to the configured truncated ELF SHA256 prefix",
            "no RSA primitive or accelerator path is used by this ES256 only stage",
            "no raw key scalar nonce random plaintext ciphertext tag or signature value is copied into this report",
            "per credential private scalars remain software visible and the dedicated eFuse signer is not used",
            "",
        ]
    )
    return lines


def write_atomic(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            delete=False,
        ) as output:
            temporary = Path(output.name)
            output.write(text)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    except OSError as error:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
        raise InputError("report output could not be written") from error


def generate(arguments):
    config = validate_config(arguments.sdkconfig, arguments.log is not None)
    errors = list(config["errors"])
    target = None
    image_size = None
    app_elf_sha = None

    if arguments.log is not None:
        log_text = read_input(arguments.log, "target log")
        try:
            target = parse_target_log(log_text)
        except EvidenceError as error:
            errors.append(str(error))

    if arguments.size is not None:
        size_text = read_input(arguments.size, "size output")
        try:
            image_size = parse_size(size_text)
        except EvidenceError as error:
            errors.append(str(error))

    if arguments.image is not None:
        image_data = read_binary(arguments.image, "app image")
        try:
            app_elf_sha = parse_app_image(image_data)
        except EvidenceError as error:
            errors.append(str(error))

    binding_status = "NOT CHECKED"
    if arguments.log is not None and arguments.image is not None:
        if target is None or app_elf_sha is None:
            binding_status = "FAIL"
        elif target["elf_prefix"] is None:
            errors.append("target log lacks a boot ELF SHA256 fingerprint")
            binding_status = "FAIL"
        elif not app_elf_sha.startswith(target["elf_prefix"]):
            errors.append("target boot fingerprint does not match app image")
            binding_status = "FAIL"
        else:
            binding_status = "PASS"

    if errors:
        status = "FAIL"
    elif target is None:
        status = "TARGET DATA UNAVAILABLE"
    else:
        status = "PASS"

    inputs = {
        "sdkconfig": arguments.sdkconfig,
        "log": arguments.log,
        "size": arguments.size,
        "image": arguments.image,
    }
    lines = report_lines(
        status,
        inputs,
        config,
        target,
        image_size,
        app_elf_sha,
        binding_status,
        sorted(set(errors)),
    )
    write_atomic(arguments.output, "\n".join(lines))
    return status, bool(errors)


def main():
    parser = argparse.ArgumentParser(
        description="validate and write the P4Key crypto proof report"
    )
    parser.add_argument(
        "--sdkconfig",
        type=Path,
        default=REPO / "sdkconfig",
    )
    parser.add_argument("--log", type=Path)
    parser.add_argument("--size", type=Path)
    parser.add_argument("--image", type=Path)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    arguments = parser.parse_args()

    try:
        status, failed = generate(arguments)
    except InputError as error:
        print(f"FAIL {error}")
        return 2

    if failed:
        print(f"FAIL report written: {arguments.output}")
        return 1

    print(f"PASS report written: {arguments.output} status={status}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
