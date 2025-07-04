#!/usr/bin/env python3

import argparse
import re
import shutil
import subprocess
import sys


EXPECTED_IDF = (6, 0, 2)


def run_version(name, command):
    path = shutil.which(command[0])
    if path is None:
        print(f"FAIL {name}: {command[0]} not found")
        return None

    try:
        result = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            timeout=20,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        print(f"FAIL {name}: {error}")
        return None

    output = (result.stdout + result.stderr).strip()
    first = output.splitlines()[0] if output else "no version output"
    print(f"PASS {name}: {first}")
    return output


def parse_idf(output):
    match = re.search(r"ESP-IDF v?(\d+)\.(\d+)\.(\d+)", output)
    if match is None:
        return None
    return tuple(int(part) for part in match.groups())


def main():
    parser = argparse.ArgumentParser(
        description="check the pinned ESP32-P4 build environment"
    )
    parser.add_argument(
        "--allow-version-mismatch",
        action="store_true",
        help="report but do not fail on a different ESP-IDF version",
    )
    arguments = parser.parse_args()

    checks = (
        ("Python", [sys.executable, "--version"]),
        ("Git", ["git", "--version"]),
        ("CMake", ["cmake", "--version"]),
        ("Ninja", ["ninja", "--version"]),
        ("RISC-V compiler", ["riscv32-esp-elf-gcc", "--version"]),
    )

    failed = False
    idf_output = run_version("ESP-IDF", ["idf.py", "--version"])
    if idf_output is None:
        failed = True
    else:
        version = parse_idf(idf_output)
        if version != EXPECTED_IDF:
            text = ".".join(str(part) for part in version) if version else "unknown"
            print(f"FAIL ESP-IDF version: expected 6.0.2 got {text}")
            if not arguments.allow_version_mismatch:
                failed = True

    for name, command in checks:
        if run_version(name, command) is None:
            failed = True

    if failed:
        print("FIX run: . /home/ishan/esp-idf/export.sh")
        return 1

    print("PASS environment is ready for ESP32-P4")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
