#!/usr/bin/env bash
# Validate the SHPH native-Linux, two-host TUN release gate.
#
# Run this exact script on two separate native Linux hosts or VMs. It refuses
# WSL and containers, and requires root or effective CAP_NET_ADMIN. First use
# --prepare-only on both hosts and exchange the printed public/signing keys.
# Then start the listener, followed by the connector. The connector's report
# contains the end-to-end RTT, jitter, goodput, local CPU/RSS, and reconnect
# measurements. This gate intentionally validates the stable authenticated TCP
# transport through the Linux AsyncTunDevice bridge; it does not claim
# standards-QUIC evidence.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

ROLE=""
PREPARE_ONLY=0
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
STATE_DIR=""
INTERFACE=""
LOCAL_TUN_CIDR=""
REMOTE_TUN_IP=""
LISTEN_HOST="0.0.0.0"
PEER_HOST=""
PEER_PORT="7231"
PEER_PUBLIC_KEY=""
PEER_SIGNING_PUBLIC_KEY=""
PING_COUNT="20"
SATURATION_SECONDS="30"
IPERF_PORT="5201"
LISTENER_RUNTIME_SECONDS="180"

usage() {
    cat <<'USAGE'
Usage:
  scripts/validate_linux_two_host.sh --role listener|connector [options]

Bootstrap on each native Linux host (run ID must be shared):
  sudo scripts/validate_linux_two_host.sh --role listener --run-id RUN --prepare-only
  sudo scripts/validate_linux_two_host.sh --role connector --run-id RUN --prepare-only

Exchange both printed public keys and signing public keys, then run:
  # Host A
  sudo scripts/validate_linux_two_host.sh --role listener --run-id RUN \
    --peer-host CONNECTOR_HOST --peer-public-key CONNECTOR_X25519_KEY \
    --peer-signing-public-key CONNECTOR_ED25519_KEY \
    --local-tun-cidr 10.250.0.1/30 --remote-tun-ip 10.250.0.2

  # Host B, after Host A reports it is listening
  sudo scripts/validate_linux_two_host.sh --role connector --run-id RUN \
    --peer-host LISTENER_HOST --peer-public-key LISTENER_X25519_KEY \
    --peer-signing-public-key LISTENER_ED25519_KEY \
    --local-tun-cidr 10.250.0.2/30 --remote-tun-ip 10.250.0.1

Options:
  --role ROLE                    listener or connector (required)
  --prepare-only                 create identity and print exchange values
  --run-id ID                    shared evidence/state identifier
  --state-dir PATH               identity/config directory (default: XDG state dir)
  --interface NAME               TUN name (default: shph-a or shph-b)
  --local-tun-cidr CIDR          local tunnel address, e.g. 10.250.0.1/30
  --remote-tun-ip IP             remote tunnel address used for ping/iperf3
  --listen-host HOST             listener bind host (default: 0.0.0.0)
  --peer-host HOST               remote transport host/IP (required to run)
  --peer-port PORT               remote transport port (default: 7231)
  --peer-public-key BASE64       remote X25519 public key (required to run)
  --peer-signing-public-key KEY  remote Ed25519 public key (required to run)
  --ping-count N                 ICMP RTT samples on connector (default: 20)
  --saturation-seconds N         iperf3 duration on connector (default: 30)
  --iperf-port PORT              iperf3 port (default: 5201)
  --listener-runtime-seconds N   listener hold time (default: 180)
  --help                         show this help
USAGE
}

fatal() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

require_positive_integer() {
    local label="$1"
    local value="$2"
    [[ "$value" =~ ^[1-9][0-9]*$ ]] || fatal "$label must be a positive integer"
}

require_port() {
    local label="$1"
    local value="$2"
    [[ "$value" =~ ^[1-9][0-9]*$ ]] && ((value <= 65535)) ||
        fatal "$label must be an integer from 1 through 65535"
}

while (($#)); do
    case "$1" in
        --role) ROLE="${2:?missing value for --role}"; shift 2 ;;
        --prepare-only) PREPARE_ONLY=1; shift ;;
        --run-id) RUN_ID="${2:?missing value for --run-id}"; shift 2 ;;
        --state-dir) STATE_DIR="${2:?missing value for --state-dir}"; shift 2 ;;
        --interface) INTERFACE="${2:?missing value for --interface}"; shift 2 ;;
        --local-tun-cidr) LOCAL_TUN_CIDR="${2:?missing value for --local-tun-cidr}"; shift 2 ;;
        --remote-tun-ip) REMOTE_TUN_IP="${2:?missing value for --remote-tun-ip}"; shift 2 ;;
        --listen-host) LISTEN_HOST="${2:?missing value for --listen-host}"; shift 2 ;;
        --peer-host) PEER_HOST="${2:?missing value for --peer-host}"; shift 2 ;;
        --peer-port) PEER_PORT="${2:?missing value for --peer-port}"; shift 2 ;;
        --peer-public-key) PEER_PUBLIC_KEY="${2:?missing value for --peer-public-key}"; shift 2 ;;
        --peer-signing-public-key) PEER_SIGNING_PUBLIC_KEY="${2:?missing value for --peer-signing-public-key}"; shift 2 ;;
        --ping-count) PING_COUNT="${2:?missing value for --ping-count}"; shift 2 ;;
        --saturation-seconds) SATURATION_SECONDS="${2:?missing value for --saturation-seconds}"; shift 2 ;;
        --iperf-port) IPERF_PORT="${2:?missing value for --iperf-port}"; shift 2 ;;
        --listener-runtime-seconds) LISTENER_RUNTIME_SECONDS="${2:?missing value for --listener-runtime-seconds}"; shift 2 ;;
        --help|-h) usage; exit 0 ;;
        *) fatal "unknown argument: $1" ;;
    esac
done

[[ "$ROLE" == "listener" || "$ROLE" == "connector" ]] ||
    fatal "--role must be listener or connector"
[[ "$RUN_ID" =~ ^[A-Za-z0-9._-]+$ ]] ||
    fatal "--run-id may contain only letters, digits, dot, underscore, and hyphen"
[[ "$RUN_ID" != "." && "$RUN_ID" != ".." ]] ||
    fatal "--run-id must not be . or .."
require_port "--peer-port" "$PEER_PORT"
require_port "--iperf-port" "$IPERF_PORT"
require_positive_integer "--ping-count" "$PING_COUNT"
require_positive_integer "--saturation-seconds" "$SATURATION_SECONDS"
require_positive_integer "--listener-runtime-seconds" "$LISTENER_RUNTIME_SECONDS"

if [[ -n "${WSL_DISTRO_NAME:-}" ]] ||
    grep -Eqi '(microsoft|wsl)' /proc/sys/kernel/osrelease /proc/version 2>/dev/null; then
    fatal "this is WSL/WSL2; native Linux two-host evidence must remain separate"
fi
[[ "$(uname -s)" == "Linux" ]] || fatal "this validator requires native Linux"
if [[ -f /.dockerenv || -f /run/.containerenv ]] ||
    (command -v systemd-detect-virt >/dev/null 2>&1 &&
        systemd-detect-virt --container --quiet) ||
    grep -Eqa '(docker|containerd|kubepods|libpod|podman|lxc)' \
        /proc/1/cgroup /proc/1/environ 2>/dev/null; then
    fatal "this is a containerized environment; native Linux two-host evidence must remain separate"
fi
[[ -c /dev/net/tun ]] || fatal "/dev/net/tun is unavailable"

if [[ "${EUID}" -ne 0 ]]; then
    command -v capsh >/dev/null 2>&1 ||
        fatal "run as root or install capsh and grant effective CAP_NET_ADMIN"
    capsh --has-p=cap_net_admin >/dev/null 2>&1 ||
        fatal "CAP_NET_ADMIN is not in this process's permitted capability set"
    capsh --has-e=cap_net_admin >/dev/null 2>&1 ||
        fatal "CAP_NET_ADMIN is not effective; run as root or grant it effectively"
fi

if [[ -f "$HOME/.cargo/env" ]]; then
    # shellcheck disable=SC1090
    source "$HOME/.cargo/env"
fi

for command in cargo ip ping iperf3 ss awk sed grep date stat timeout python3 getconf; do
    command -v "$command" >/dev/null 2>&1 || fatal "required command not found: $command"
done

BIN="$ROOT/target/release/shph"
if [[ -z "$STATE_DIR" ]]; then
    STATE_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/shph/two-host-validation/$RUN_ID/$ROLE"
fi
CONFIG="$STATE_DIR/config.toml"
KEYSTORE="$STATE_DIR/keystore.json"
LOG_DIR="$STATE_DIR/logs"
EVIDENCE_DIR="$ROOT/docs/evidence"
REPORT="$EVIDENCE_DIR/LINUX_TWO_HOST_VALIDATION_${RUN_ID}_${ROLE}.md"
INTERFACE="${INTERFACE:-$([[ "$ROLE" == "listener" ]] && printf 'shph-a' || printf 'shph-b')}"

if [[ "$STATE_DIR" == "$ROOT" || "$STATE_DIR" == "$ROOT/"* ]]; then
    fatal "--state-dir must be outside the repository because it contains private keystores"
fi

[[ "$INTERFACE" =~ ^[A-Za-z0-9_.-]{1,15}$ ]] ||
    fatal "--interface must be 1..15 ASCII letters, digits, dot, underscore, or hyphen"

SHPh_PID=""
IPERF_PID=""
SAMPLER_PID=""
ROUTE_INSTALLED=0

remove_validation_route() {
    if [[ "$ROUTE_INSTALLED" -eq 1 ]]; then
        ip route del "$REMOTE_TUN_IP/32" dev "$INTERFACE" 2>/dev/null || true
        ROUTE_INSTALLED=0
    fi
}

cleanup() {
    local status=$?
    set +e
    [[ -n "$SAMPLER_PID" ]] && kill "$SAMPLER_PID" 2>/dev/null
    [[ -n "$IPERF_PID" ]] && kill "$IPERF_PID" 2>/dev/null
    [[ -n "$SHPh_PID" ]] && kill -TERM "$SHPh_PID" 2>/dev/null
    [[ -n "$SHPh_PID" ]] && wait "$SHPh_PID" 2>/dev/null
    remove_validation_route
    exit "$status"
}
trap cleanup EXIT INT TERM

prepare_identity() {
    mkdir -p "$STATE_DIR" "$LOG_DIR"
    chmod 700 "$STATE_DIR"

    if [[ ! -f "$CONFIG" || ! -f "$KEYSTORE" ]]; then
        [[ ! -e "$CONFIG" && ! -e "$KEYSTORE" ]] ||
            fatal "only one of config/keystore exists in $STATE_DIR; refuse to replace identity"
        "$BIN" --config "$CONFIG" init --new
    fi
    chmod 600 "$CONFIG" "$KEYSTORE"
    require_private_file "$CONFIG"
    require_private_file "$KEYSTORE"

    printf '\nSHPH two-host bootstrap (%s)\n' "$ROLE"
    printf '  State directory: %s\n' "$STATE_DIR"
    printf '  Public key: %s\n' "$("$BIN" --config "$CONFIG" show-public-key)"
    printf '  Signing public key: %s\n' "$("$BIN" --config "$CONFIG" show-signing-public-key)"
}

wait_for_interface() {
    local deadline=$((SECONDS + 30))
    while ((SECONDS < deadline)); do
        ip link show dev "$INTERFACE" >/dev/null 2>&1 && return 0
        if [[ -n "$SHPh_PID" ]] && ! kill -0 "$SHPh_PID" 2>/dev/null; then
            tail -n 80 "$LOG_DIR/shph.log" >&2 || true
            fatal "SHPH exited before creating $INTERFACE"
        fi
        sleep 1
    done
    fatal "timed out waiting for native TUN interface $INTERFACE"
}

wait_for_handshake() {
    local deadline=$((SECONDS + 60))
    while ((SECONDS < deadline)); do
        grep -q 'SHPH handshake .* ok' "$LOG_DIR/shph.log" 2>/dev/null && return 0
        if [[ -n "$SHPh_PID" ]] && ! kill -0 "$SHPh_PID" 2>/dev/null; then
            tail -n 100 "$LOG_DIR/shph.log" >&2 || true
            fatal "SHPH exited before authenticated handshake completed"
        fi
        sleep 1
    done
    tail -n 100 "$LOG_DIR/shph.log" >&2 || true
    fatal "timed out waiting for authenticated secure-default handshake"
}

configure_tun_addressing() {
    ip link set dev "$INTERFACE" up
    ip address replace "$LOCAL_TUN_CIDR" dev "$INTERFACE"
    if [[ "$ROUTE_INSTALLED" -eq 0 ]]; then
        if ip -4 route show exact "$REMOTE_TUN_IP/32" | grep -q .; then
            fatal "a route already exists for $REMOTE_TUN_IP/32; refuse to overwrite host routing"
        fi
        ip route add "$REMOTE_TUN_IP/32" dev "$INTERFACE"
        ROUTE_INSTALLED=1
    fi
}

start_shph() {
    : >"$LOG_DIR/shph.log"
    env SHPH_TUN_NATIVE=1 "$BIN" up --config "$CONFIG" \
        --transport tcp --handshake-profile secure-default >"$LOG_DIR/shph.log" 2>&1 &
    SHPh_PID=$!
    wait_for_interface
    configure_tun_addressing
}

read_process_sample() {
    local pid="$1"
    local stat_line
    local stat_fields
    local ticks
    local rss_kib

    [[ -r "/proc/$pid/stat" && -r "/proc/$pid/status" ]] || return 1
    stat_line="$(<"/proc/$pid/stat")"
    stat_fields="${stat_line##*) }"
    read -r -a stat_fields <<<"$stat_fields"
    ((${#stat_fields[@]} >= 13)) || return 1
    ticks=$((stat_fields[11] + stat_fields[12]))
    rss_kib="$(awk '/^VmRSS:/ { print $2; found = 1; exit } END { if (!found) print 0 }' \
        "/proc/$pid/status")"
    printf '%s,%s,%s\n' "$(date +%s%N)" "$ticks" "$rss_kib"
}

start_resource_sampler() {
    local output="$1"
    local pid="$2"
    : >"$output"
    (
        while kill -0 "$pid" 2>/dev/null; do
            read_process_sample "$pid" >>"$output" || break
            sleep 1
        done
    ) &
    SAMPLER_PID=$!
}

resource_summary() {
    local samples="$1"
    local clock_ticks
    [[ -s "$samples" ]] || {
        printf 'unavailable'
        return
    }
    clock_ticks="$(getconf CLK_TCK)"
    [[ "$clock_ticks" =~ ^[1-9][0-9]*$ ]] || {
        printf 'unavailable'
        return
    }
    awk -F, -v clock_ticks="$clock_ticks" '
        BEGIN {
            intervals = 0
            cpu_sum = 0
            cpu_max = 0
            rss_max = 0
            previous_time = 0
            previous_ticks = 0
        }
        NF == 3 {
            time_ns = $1 + 0
            ticks = $2 + 0
            rss = $3 + 0
            if (rss > rss_max) rss_max = rss
            if (previous_time > 0 && time_ns > previous_time && ticks >= previous_ticks) {
                cpu = 100 * (ticks - previous_ticks) / clock_ticks / ((time_ns - previous_time) / 1000000000)
                intervals++
                cpu_sum += cpu
                if (cpu > cpu_max) cpu_max = cpu
            }
            previous_time = time_ns
            previous_ticks = ticks
        }
        END {
            if (intervals == 0) print "unavailable"
            else printf "intervals=%d;cpu_avg_one_core_percent=%.2f;cpu_peak_one_core_percent=%.2f;rss_peak_kib=%d", intervals, cpu_sum / intervals, cpu_max, rss_max
        }' "$samples"
}

wait_for_iperf_server() {
    local deadline=$((SECONDS + 15))
    while ((SECONDS < deadline)); do
        if [[ -n "$IPERF_PID" ]] && ! kill -0 "$IPERF_PID" 2>/dev/null; then
            cat "$LOG_DIR/iperf3-server.log" >&2 || true
            fatal "iperf3 server exited before it was ready"
        fi
        if ss -H -ltn "sport = :$IPERF_PORT" 2>/dev/null |
            grep -qE "[:.]$IPERF_PORT([[:space:]]|$)"; then
            return 0
        fi
        sleep 1
    done
    cat "$LOG_DIR/iperf3-server.log" >&2 || true
    fatal "timed out waiting for iperf3 server port $IPERF_PORT"
}

write_report() {
    local status="$1"
    local rtt="$2"
    local throughput="$3"
    local resources="$4"
    local reconnect="$5"
    mkdir -p "$EVIDENCE_DIR"
    cat >"$REPORT" <<EOF
# Native Linux Two-Host Validation

| Field | Value |
| --- | --- |
| Status | $status |
| Run ID | $RUN_ID |
| Role | $ROLE |
| Timestamp (UTC) | $(date -u +%Y-%m-%dT%H:%M:%SZ) |
| Platform | $(uname -srm) |
| Kernel | $(cat /proc/sys/kernel/osrelease) |
| Commit | $(git rev-parse HEAD) |
| Rust | $(rustc --version) |
| Transport | TCP native transport through Linux AsyncTunDevice bridge |
| Handshake profile | secure-default |
| Native TUN | SHPH_TUN_NATIVE=1 |
| TUN interface | $INTERFACE |
| Local TUN address | ${LOCAL_TUN_CIDR:-not-run} |
| Remote TUN address | ${REMOTE_TUN_IP:-not-run} |
| Transport endpoint | $([[ "$ROLE" == "listener" ]] && printf '%s:%s' "$LISTEN_HOST" "$PEER_PORT" || printf '%s:%s' "$PEER_HOST" "$PEER_PORT") |
| RTT and jitter | $rtt |
| iperf3 goodput | $throughput |
| Local SHPH resource samples | $resources |
| Controlled reconnect | $reconnect |

## Scope

This is native Linux two-host evidence. It is not WSL2, container, network
namespace, Windows, standards-QUIC, or local in-memory benchmark evidence.
The listener and connector were started with \`SHPH_TUN_NATIVE=1\` and
\`--transport tcp\`; TUN addresses and a host route for the remote tunnel IP
were installed by this script and removed on exit. CPU values are sampled from
the SHPH process's \`/proc/<pid>/stat\` tick deltas during saturation and are
reported as one-core percentages; RSS is that local process's peak VmRSS. Raw
logs and metric captures are stored under \`$STATE_DIR/logs\`.
EOF
}

require_private_file() {
    local path="$1"
    [[ -f "$path" ]] || fatal "expected private file is missing: $path"
    if [[ "$(stat -c '%a' "$path")" != "600" ]]; then
        fatal "private file must have mode 0600: $path"
    fi
}

printf 'Building locked release workspace on native Linux...\n'
cargo build --workspace --release --locked

prepare_identity
if ((PREPARE_ONLY)); then
    exit 0
fi

[[ -n "$LOCAL_TUN_CIDR" ]] || fatal "--local-tun-cidr is required"
[[ -n "$REMOTE_TUN_IP" ]] || fatal "--remote-tun-ip is required"
[[ -n "$PEER_HOST" ]] || fatal "--peer-host is required"
[[ -n "$PEER_PUBLIC_KEY" ]] || fatal "--peer-public-key is required"
[[ -n "$PEER_SIGNING_PUBLIC_KEY" ]] || fatal "--peer-signing-public-key is required"
[[ "$PEER_HOST" =~ ^[A-Za-z0-9.-]+$ ]] ||
    fatal "--peer-host must be an IPv4 address or DNS hostname without TOML-special characters"

python3 - "$LOCAL_TUN_CIDR" "$REMOTE_TUN_IP" <<'PY'
import ipaddress
import sys

try:
    local = ipaddress.ip_interface(sys.argv[1])
    remote = ipaddress.ip_address(sys.argv[2])
except ValueError as error:
    raise SystemExit(f"invalid tunnel address input: {error}")

if local.version != 4 or remote.version != 4:
    raise SystemExit("only IPv4 TUN addresses are supported by this validator")
if remote == local.ip:
    raise SystemExit("remote tunnel IP must differ from the local tunnel IP")
if remote not in local.network:
    raise SystemExit("remote tunnel IP must be inside the local tunnel network")
PY

ip -4 address show dev "$INTERFACE" >/dev/null 2>&1 &&
    fatal "interface $INTERFACE already exists; select a different --interface or clean up the prior run"

# Rebuild the prepared configuration on every run without replacing the
# keystore. Peer pinning remains in the keystore, and the config records the
# exact listener/connector role and reconnect policy used as evidence.
"$BIN" --config "$CONFIG" add-peer validation-peer "$PEER_HOST" "$PEER_PORT" \
    "$PEER_PUBLIC_KEY" --sign-pubkey "$PEER_SIGNING_PUBLIC_KEY" \
    >"$LOG_DIR/add-peer.log" 2>&1 || {
        grep -q 'already exists' "$LOG_DIR/add-peer.log" ||
            { cat "$LOG_DIR/add-peer.log" >&2; fatal "unable to pin peer identity"; }
    }

if [[ "$ROLE" == "listener" ]]; then
    SESSION_TOML="role = \"listen\"
bind = \"${LISTEN_HOST}:${PEER_PORT}\""
else
    SESSION_TOML="role = \"connect\"
peer = \"${PEER_HOST}:${PEER_PORT}\""
fi

cat >"$CONFIG" <<EOF
interface_name = "$INTERFACE"
local_endpoint = "${LISTEN_HOST}:${PEER_PORT}"

[[peers]]
alias = "validation-peer"
endpoint = "${PEER_HOST}:${PEER_PORT}"
pubkey = "$PEER_PUBLIC_KEY"
sign_pubkey = "$PEER_SIGNING_PUBLIC_KEY"

[session]
$SESSION_TOML
timeout_secs = 5
handshake_profile = "secure-default"

[session.reconnect]
enabled = true
max_attempts = 20
initial_delay_ms = 500
max_delay_ms = 2000
EOF
chmod 600 "$CONFIG"

if [[ "$ROLE" == "listener" ]]; then
    start_shph
    printf 'Listener native TUN ready: interface=%s address=%s\n' "$INTERFACE" "$LOCAL_TUN_CIDR"
    printf 'Awaiting connector at %s:%s for up to %ss.\n' "$LISTEN_HOST" "$PEER_PORT" "$LISTENER_RUNTIME_SECONDS"

    iperf3 -s -B "${LOCAL_TUN_CIDR%/*}" -p "$IPERF_PORT" \
        >"$LOG_DIR/iperf3-server.log" 2>&1 &
    IPERF_PID=$!
    wait_for_iperf_server
    start_resource_sampler "$LOG_DIR/resources.csv" "$SHPh_PID"

    wait_for_handshake
    sleep "$LISTENER_RUNTIME_SECONDS"
    write_report "listener-complete" "captured by connector" \
        "iperf3 server active on ${LOCAL_TUN_CIDR%/*}:$IPERF_PORT" \
        "$(resource_summary "$LOG_DIR/resources.csv")" \
        "controlled by connector"
    printf 'Listener report: %s\n' "$REPORT"
    exit 0
fi

start_shph
wait_for_handshake

PING_LOG="$LOG_DIR/ping.log"
if ! ping -I "$INTERFACE" -c "$PING_COUNT" -i 0.2 "$REMOTE_TUN_IP" >"$PING_LOG" 2>&1; then
    cat "$PING_LOG" >&2
    write_report "failed" "ping failed; see $PING_LOG" "not-run" "not-run" "not-run"
    fatal "TUN ping failed; no RTT/jitter or saturation claim is valid"
fi
RTT_SUMMARY="$(sed -n 's/.*= \([^ ]*\) ms/\1 ms/p' "$PING_LOG" | tail -n1)"
[[ -n "$RTT_SUMMARY" ]] || RTT_SUMMARY="ping completed; parser did not find summary"

RESOURCE_LOG="$LOG_DIR/resources.csv"
IPERF_LOG="$LOG_DIR/iperf3-client.json"
start_resource_sampler "$RESOURCE_LOG" "$SHPh_PID"
if ! iperf3 -c "$REMOTE_TUN_IP" -B "${LOCAL_TUN_CIDR%/*}" -p "$IPERF_PORT" \
    -t "$SATURATION_SECONDS" -J >"$IPERF_LOG" 2>&1; then
    cat "$IPERF_LOG" >&2
    write_report "failed" "$RTT_SUMMARY" "iperf3 failed; see $IPERF_LOG" \
        "$(resource_summary "$RESOURCE_LOG")" "not-run"
    fatal "iperf3 saturation through TUN failed"
fi
kill "$SAMPLER_PID" 2>/dev/null || true
wait "$SAMPLER_PID" 2>/dev/null || true
SAMPLER_PID=""

THROUGHPUT_SUMMARY="$(python3 - "$IPERF_LOG" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    data = json.load(source)
bits_per_second = data["end"]["sum_sent"]["bits_per_second"]
bytes_sent = data["end"]["sum_sent"]["bytes"]
seconds = data["end"]["sum_sent"]["seconds"]
print(
    f"sent_bytes={bytes_sent};duration_seconds={seconds:.3f};"
    f"goodput_mbps={bits_per_second / 1_000_000:.3f}"
)
PY
)"

RECONNECT_START_NS="$(date +%s%N)"
remove_validation_route
kill -TERM "$SHPh_PID"
wait "$SHPh_PID" 2>/dev/null || true
SHPh_PID=""
start_shph
wait_for_handshake
RECONNECT_END_NS="$(date +%s%N)"
RECONNECT_MS="$(((RECONNECT_END_NS - RECONNECT_START_NS) / 1000000))"

if ! ping -I "$INTERFACE" -c 3 -i 0.2 "$REMOTE_TUN_IP" >"$LOG_DIR/ping-after-reconnect.log" 2>&1; then
    cat "$LOG_DIR/ping-after-reconnect.log" >&2
    write_report "failed" "$RTT_SUMMARY" "$THROUGHPUT_SUMMARY" \
        "$(resource_summary "$RESOURCE_LOG")" "recovery_ms=$RECONNECT_MS;post-reconnect ping failed"
    fatal "post-reconnect TUN ping failed"
fi

write_report "connector-complete" "$RTT_SUMMARY" "$THROUGHPUT_SUMMARY" \
    "$(resource_summary "$RESOURCE_LOG")" \
    "controlled local connector termination;recovery_ms=$RECONNECT_MS;post_reconnect_ping=pass"
printf 'Connector report: %s\n' "$REPORT"
