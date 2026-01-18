#!/usr/bin/env bash

set -euo pipefail

repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_dir"

if ! command -v idf.py >/dev/null 2>&1; then
    echo "idf.py not found" >&2
    echo "run: . /path/to/esp-idf/export.sh" >&2
    exit 1
fi

python3 scripts/env_check.py

if [[ ! -f sdkconfig ]] ||
   ! grep -q '^CONFIG_IDF_TARGET="esp32p4"$' sdkconfig; then
    idf.py set-target esp32p4
fi

idf.py build
idf.py size
