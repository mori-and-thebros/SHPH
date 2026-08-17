#!/usr/bin/env bash
# scripts/demo.sh — reproducible SHPH demo + failure-mode walk-through.
#
# Runs entirely on loopback; no privileges or real TUN needed. Demonstrates the
# authenticated, encrypted one-shot tunnel and two fail-closed failure modes.
#
# Usage:
#   scripts/demo.sh              # run all demos (default)
#   scripts/demo.sh happy        # only the successful encrypted transfer
#   scripts/demo.sh bad-cidr     # only the invalid-CIDR rejection
#   scripts/demo.sh unreachable  # only the unreachable-peer reconnect/backoff
#
# Requires: a built `shph` binary. The script builds it if missing.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
BIN="$ROOT/target/debug/shph"
DEMO_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/shph-demo.XXXXXX")"

cleanup() {
  rm -rf -- "$DEMO_ROOT"
}
trap cleanup EXIT INT TERM

build_if_needed() {
  if [ ! -x "$BIN" ]; then
    echo ">> building shph (cargo build -p shph-cli)"
    cargo build -p shph-cli
  fi
}

fresh_dir() { mkdir -p -- "$1"; }

demo_happy() {
  echo "================ DEMO 1: encrypted one-shot tunnel (happy path) ================"
  local a="$DEMO_ROOT/a" b="$DEMO_ROOT/b"
  fresh_dir "$a"; fresh_dir "$b"
  "$BIN" --config "$a/config.toml" init --new >/dev/null
  "$BIN" --config "$b/config.toml" init --new >/dev/null
  local a_key b_key a_sign_key b_sign_key
  a_key="$("$BIN" --config "$a/config.toml" show-public-key)"
  b_key="$("$BIN" --config "$b/config.toml" show-public-key)"
  a_sign_key="$("$BIN" --config "$a/config.toml" show-signing-public-key)"
  b_sign_key="$("$BIN" --config "$b/config.toml" show-signing-public-key)"
  "$BIN" --config "$a/config.toml" add-peer b 127.0.0.1 7251 "$b_key" \
    --sign-pubkey "$b_sign_key" >/dev/null
  "$BIN" --config "$b/config.toml" add-peer a 127.0.0.1 7251 "$a_key" \
    --sign-pubkey "$a_sign_key" >/dev/null
  printf '[session]\nrole = "listen"\nbind = "127.0.0.1:7251"\ntimeout_secs = 4\nstartup_payload = "expect"\n' >> "$a/config.toml"
  printf '[session]\nrole = "connect"\npeer = "127.0.0.1:7251"\ntimeout_secs = 4\nstartup_payload = "demo-payload"\n' >> "$b/config.toml"
  "$BIN" --config "$a/config.toml" up > "$a.out" 2>&1 &
  local pid=$!
  sleep 0.4
  if ! "$BIN" --config "$b/config.toml" up > "$b.out" 2>&1; then
    cat "$b.out"
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    return 1
  fi
  if ! wait "$pid"; then
    cat "$a.out"
    return 1
  fi
  if ! grep -Eq "Payload: demo-payload|handshake recv-once ok" "$a.out"; then
    cat "$a.out"
    return 1
  fi
  if ! grep -Eq "Sent bytes:|handshake send-once ok" "$b.out"; then
    cat "$b.out"
    return 1
  fi
  echo "-- listener received:"; grep -E "Payload:|handshake recv-once ok" "$a.out"
  echo "-- connector sent:";    grep -E "Sent bytes:|handshake send-once ok" "$b.out"
  echo ">> EXPECT: listener prints 'Payload: demo-payload' (decrypted), connector prints 'Sent bytes: 12'."
  echo
}

demo_bad_cidr() {
  echo "================ DEMO 2: invalid CIDR rejected (fail-closed) ================"
  local d="$DEMO_ROOT/cidr"; fresh_dir "$d"
  "$BIN" --config "$d/config.toml" init --new >/dev/null
  printf '[control_plane]\napply_routes = true\nroute_cidrs = ["10.99.0.0/40"]\ndry_run = false\n' >> "$d/config.toml"
  set +e
  "$BIN" --config "$d/config.toml" up > "$d.out" 2>&1
  local rc=$?
  set -e
  echo "-- exit code: $rc"
  if [ "$rc" -eq 0 ] || ! grep -Eq "CIDR prefix out of range|Error:" "$d.out"; then
    cat "$d.out"
    return 1
  fi
  grep -E "CIDR prefix out of range|Error:" "$d.out"
  echo ">> EXPECT: non-zero exit and 'CIDR prefix out of range' (preflight atomicity, nothing applied)."
  echo
}

demo_unreachable() {
  echo "================ DEMO 3: unreachable peer (reconnect + backoff, fail-closed) ================"
  local d="$DEMO_ROOT/unreachable"; fresh_dir "$d"
  "$BIN" --config "$d/config.toml" init --new >/dev/null
  printf '[session]\nrole = "connect"\npeer = "127.0.0.1:1"\ntimeout_secs = 1\n[session.reconnect]\nenabled = true\nmax_attempts = 2\ninitial_delay_ms = 1\nmax_delay_ms = 2\n' >> "$d/config.toml"
  set +e
  "$BIN" --config "$d/config.toml" up > "$d.out" 2>&1
  local rc=$?
  set -e
  echo "-- exit code: $rc"
  if [ "$rc" -eq 0 ] || ! grep -Eq "Reconnect: attempt 1/2|Session mode: connect" "$d.out"; then
    cat "$d.out"
    return 1
  fi
  grep -E "Reconnect: attempt 1/2|Session mode: connect" "$d.out"
  echo ">> EXPECT: non-zero exit and 'Reconnect: attempt 1/2 failed' (bounded retries, then fail)."
  echo
}

build_if_needed
case "${1:-all}" in
  happy)      demo_happy ;;
  bad-cidr)   demo_bad_cidr ;;
  unreachable) demo_unreachable ;;
  all)        demo_happy; demo_bad_cidr; demo_unreachable ;;
  *) echo "unknown demo: $1 (try: happy | bad-cidr | unreachable | all)" >&2; exit 1 ;;
esac
echo ">> demo complete."
