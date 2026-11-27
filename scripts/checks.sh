#!/usr/bin/env bash
# Run the same static and documentation checks as CI.
# Bash 3.2 compatible (macOS default).
set -o pipefail
cd "$(dirname "$0")/.." || exit 1

status=0
make -s lint || status=1
make -s docs-check || status=1

if [ "$status" -eq 0 ]; then
  printf 'checks: PASS\n' >&2
else
  printf 'checks: FAIL\n' >&2
fi
exit "$status"
