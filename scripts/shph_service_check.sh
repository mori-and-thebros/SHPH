#!/usr/bin/env bash
# Read-only Linux service/readiness check. It never starts, stops, reloads, or
# otherwise mutates a service or network configuration.
set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
PYTHON="${PYTHON:-python3}"
CONFIG="${SHPH_CONFIG:-/etc/shph/host.toml}"
BINARY="${SHPH_BINARY:-/usr/local/bin/shph}"
UNIT="${SHPH_UNIT:-shph-host.service}"
LISTEN="${SHPH_LISTEN:-127.0.0.1:443}"

exec "$PYTHON" "$SCRIPT_DIR/shph_ops_check.py" \
  --binary "$BINARY" \
  --config "$CONFIG" \
  --unit "$UNIT" \
  --unit-file "/etc/systemd/system/$UNIT" \
  --listen "$LISTEN" \
  --strict \
  "$@"
