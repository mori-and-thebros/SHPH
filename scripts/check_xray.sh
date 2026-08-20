#!/usr/bin/env bash
set -euo pipefail

config_path="${SHPH_XRAY_CONFIG:-/usr/local/etc/xray/config.json}"
xray_path="${SHPH_XRAY_BIN:-/usr/local/bin/xray}"
socks_host="${SHPH_XRAY_SOCKS_HOST:-127.0.0.1}"
socks_port="${SHPH_XRAY_SOCKS_PORT:-10808}"

fail() {
    echo "[FAIL] $*" >&2
    exit 1
}

echo "SHPH Xray underlay check"
[[ -x "$xray_path" ]] || fail "Xray executable not found: $xray_path"
[[ -f "$config_path" ]] || fail "Xray configuration not found: $config_path"
command -v python3 >/dev/null 2>&1 || fail "python3 is required for the bounded SOCKS5 probe"

"$xray_path" run -test -config "$config_path" >/dev/null \
    || fail "Xray configuration test failed"
echo "[PASS] Xray configuration test"

python3 - "$config_path" "$socks_host" "$socks_port" <<'PY'
import json
import socket
import sys

config_path, socks_host, socks_port = sys.argv[1], sys.argv[2], int(sys.argv[3])
with open(config_path, "rb") as handle:
    config = json.load(handle)

inbounds = [
    item for item in config.get("inbounds", [])
    if item.get("protocol") == "socks"
    and str(item.get("listen", "0.0.0.0")) == socks_host
    and int(item.get("port", 0)) == socks_port
]
if not inbounds:
    raise SystemExit(f"[FAIL] no SOCKS inbound is configured on {socks_host}:{socks_port}")

if not any(
    item.get("protocol") == "vless"
    for item in config.get("inbounds", []) + config.get("outbounds", [])
):
    print("[WARN] no VLESS inbound or outbound found; the SOCKS listener may not reach SHPH")

with socket.create_connection((socks_host, socks_port), timeout=5) as connection:
    connection.sendall(b"\x05\x01\x00")
    response = connection.recv(2)
if response != b"\x05\x00":
    raise SystemExit("[FAIL] SOCKS5 listener did not accept the unauthenticated method")
print(f"[PASS] SOCKS5 listener responds on {socks_host}:{socks_port}")
print("Result: Xray is ready to carry an SHPH TCP underlay")
PY
