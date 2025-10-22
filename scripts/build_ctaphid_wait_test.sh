#!/usr/bin/env bash

set -euo pipefail

repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_dir"

if ! command -v idf.py >/dev/null 2>&1; then
    echo "idf.py not found" >&2
    echo "run: . /home/ishan/esp-idf/export.sh" >&2
    exit 1
fi

build_dir="$repo_dir/build/ctaphid-wait-test"
test_config="$build_dir/sdkconfig"
defaults="$repo_dir/sdkconfig.defaults;$repo_dir/sdkconfig.ctaphid-wait-test.defaults"

python3 scripts/env_check.py
idf.py -B "$build_dir" \
    -D "SDKCONFIG=$test_config" \
    -D "SDKCONFIG_DEFAULTS=$defaults" \
    build
idf.py -B "$build_dir" \
    -D "SDKCONFIG=$test_config" \
    -D "SDKCONFIG_DEFAULTS=$defaults" \
    size
