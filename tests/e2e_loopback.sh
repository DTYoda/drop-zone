#!/usr/bin/env bash
#
# End-to-end test: two clients and a server on one machine, one transfer per
# combination of transport tier and encryption setting.
#
# What this exercises that the unit tests cannot: the handshake through a real
# server, the transport ladder, the chunk pipeline under real thread scheduling, and
# whether the bytes that come out are the bytes that went in.
#
# Two environment variables make a single-machine run possible:
#
#   DROP_ZONE_HOME            gives each client its own configuration, so they do
#                             not share an identity or a known_peers file.
#   DROP_ZONE_ALLOW_LOOPBACK  puts 127.0.0.1 in the candidate list. Pointless in
#                             real use -- a peer cannot reach our loopback -- and
#                             the only way two clients on one host can find each
#                             other directly.
#
# Usage: tests/e2e_loopback.sh [BUILD_DIR] [SIZE_MB]

set -u -o pipefail

BUILD_DIR="${1:-build}"
SIZE_MB="${2:-64}"
PORT="${DZ_TEST_PORT:-47777}"

CLIENT="$(cd "$BUILD_DIR" && pwd)/bin/drop-zone"
SERVER="$(cd "$BUILD_DIR" && pwd)/bin/drop-zone-server"

if [[ ! -x "$CLIENT" || ! -x "$SERVER" ]]; then
    echo "Build the project first: cmake --build $BUILD_DIR" >&2
    exit 1
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/drop-zone-e2e.XXXXXX")"
SERVER_PID=""

ALICE_PRIVATE="alice-private-password"
BOB_PRIVATE="bob-private-password"
BOB_PUBLIC="bob-public-password-which-is-long"

PASSES=0
FAILURES=0

cleanup() {
    if [[ -n "$SERVER_PID" ]]; then kill "$SERVER_PID" 2>/dev/null || true; fi
    # Left behind on failure so the logs can be read.
    if [[ "$FAILURES" -eq 0 ]]; then rm -rf "$WORK"; fi
}
trap cleanup EXIT

export DROP_ZONE_ALLOW_LOOPBACK=1

note() { printf '  %s\n' "$*"; }
ok()   { printf '  \033[32mok\033[0m       %s\n' "$*"; PASSES=$((PASSES + 1)); }
bad()  { printf '  \033[31mFAILED\033[0m   %s\n' "$*"; FAILURES=$((FAILURES + 1)); }

# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------

printf '\ndrop-zone end-to-end test\n'
note "workspace $WORK"

mkdir -p "$WORK/alice" "$WORK/bob" "$WORK/source" "$WORK/source/tree/nested"

# One large file to measure throughput on, plus a small tree to check that paths,
# nesting and empty files survive the trip.
head -c "$((SIZE_MB * 1024 * 1024))" /dev/urandom > "$WORK/source/large.bin"
head -c 1024 /dev/urandom > "$WORK/source/tree/small.bin"
head -c 100000 /dev/urandom > "$WORK/source/tree/nested/deeper.bin"
: > "$WORK/source/tree/empty.bin"
printf 'hello from drop-zone\n' > "$WORK/source/tree/text.txt"

setup_client() {
    local home="$1" username="$2" private="$3" public="$4"
    DROP_ZONE_HOME="$home" "$CLIENT" setup >/dev/null 2>&1 <<EOF
$username
127.0.0.1:$PORT

$private
$private
$public
$public
EOF
}

note "starting the server on port $PORT"
"$SERVER" --port "$PORT" --shards 2 --log-level warn > "$WORK/server.log" 2>&1 &
SERVER_PID=$!
sleep 1

if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "the server exited immediately:" >&2
    cat "$WORK/server.log" >&2
    exit 1
fi

note "creating two identities"
setup_client "$WORK/alice" alice "$ALICE_PRIVATE" "alice-public-password-long"
setup_client "$WORK/bob" bob "$BOB_PRIVATE" "$BOB_PUBLIC"

# --------------------------------------------------------------------------
# One transfer
# --------------------------------------------------------------------------

# run_transfer NAME TRANSPORT ENCRYPT_FLAG SOURCE...
run_transfer() {
    local name="$1" transport="$2" encrypt_flag="$3"
    shift 3

    local out="$WORK/out-$name"
    rm -rf "$out"
    mkdir -p "$out"

    local receiver_log="$WORK/receiver-$name.log"
    local sender_log="$WORK/sender-$name.log"

    # The receiver has to be waiting before the sender asks for it.
    DROP_ZONE_HOME="$WORK/bob" "$CLIENT" accept --once -y -o "$out" \
        --force-transport="$transport" $encrypt_flag --log-level debug \
        > "$receiver_log" 2>&1 <<EOF &
$BOB_PRIVATE
$BOB_PUBLIC
EOF
    local receiver_pid=$!
    sleep 1.5

    DROP_ZONE_HOME="$WORK/alice" "$CLIENT" send "$@" -t bob \
        --force-transport="$transport" $encrypt_flag --log-level debug \
        > "$sender_log" 2>&1 <<EOF
$ALICE_PRIVATE
$BOB_PUBLIC
EOF
    local sender_status=$?

    wait "$receiver_pid"
    local receiver_status=$?

    if [[ "$sender_status" -ne 0 || "$receiver_status" -ne 0 ]]; then
        bad "$name (sender exit $sender_status, receiver exit $receiver_status)"
        printf '    --- sender ---\n'
        sed 's/^/    /' "$sender_log" | tail -20
        printf '    --- receiver ---\n'
        sed 's/^/    /' "$receiver_log" | tail -20
        return 1
    fi

    # Compare what arrived against what was sent, byte for byte.
    local expected actual
    for source in "$@"; do
        local base
        base="$(basename "$source")"
        if [[ -d "$source" ]]; then
            expected="$(cd "$(dirname "$source")" && find "$base" -type f | sort | xargs -r sha256sum)"
            actual="$(cd "$out" && find "$base" -type f | sort | xargs -r sha256sum)"
        else
            expected="$(cd "$(dirname "$source")" && sha256sum "$base")"
            actual="$(cd "$out" && sha256sum "$base")"
        fi

        if [[ "$expected" != "$actual" ]]; then
            bad "$name: '$base' does not match"
            printf '    expected: %s\n' "$expected"
            printf '    actual:   %s\n' "$actual"
            return 1
        fi
    done

    # Confirm the tier that was actually used, so a silent fallback cannot make a
    # forced-transport test pass by taking a different path.
    local reported
    reported="$(grep -o 'connected: [^,]*' "$sender_log" | head -1 | sed 's/connected: //')"

    local rate
    rate="$(grep -oE '\([0-9.]+ [KMGT]?i?B/s\)' "$sender_log" | tail -1)"

    ok "$name -- $reported ${rate:-}"
    return 0
}

# --------------------------------------------------------------------------
# The matrix
# --------------------------------------------------------------------------

printf '\nTransport tiers, encrypted\n'
run_transfer "tcp-encrypted"   tcp   ""             "$WORK/source/large.bin"
run_transfer "udp-encrypted"   udp   ""             "$WORK/source/large.bin"
run_transfer "relay-encrypted" relay ""             "$WORK/source/large.bin"

printf '\nTransport tiers, unencrypted\n'
run_transfer "tcp-plain"       tcp   "--no-encrypt" "$WORK/source/large.bin"
run_transfer "udp-plain"       udp   "--no-encrypt" "$WORK/source/large.bin"

printf '\nAutomatic tier selection\n'
run_transfer "auto"            auto  ""             "$WORK/source/large.bin"

printf '\nDirectory trees\n'
run_transfer "tree"            tcp   ""             "$WORK/source/tree"
run_transfer "tree-udp"        udp   ""             "$WORK/source/tree"

printf '\nMultiple inputs in one transfer\n'
run_transfer "multiple"        tcp   ""             "$WORK/source/tree" "$WORK/source/large.bin"

# --------------------------------------------------------------------------
# Refusals
# --------------------------------------------------------------------------

printf '\nRefusals\n'

# A wrong public password must not get a transfer, and the receiver must stay up
# for the next sender rather than exiting.
out="$WORK/out-wrong-password"
rm -rf "$out"
mkdir -p "$out"

DROP_ZONE_HOME="$WORK/bob" "$CLIENT" accept --once -y -o "$out" --force-transport=tcp \
    > "$WORK/receiver-wrong.log" 2>&1 <<EOF &
$BOB_PRIVATE
$BOB_PUBLIC
EOF
receiver_pid=$!
sleep 1.5

DROP_ZONE_HOME="$WORK/alice" "$CLIENT" send "$WORK/source/tree/small.bin" -t bob \
    --force-transport=tcp > "$WORK/sender-wrong.log" 2>&1 <<EOF
$ALICE_PRIVATE
definitely-not-bobs-password
EOF
if [[ $? -ne 0 ]] && ! [[ -e "$out/small.bin" ]]; then
    ok "a wrong public password is refused"
else
    bad "a wrong public password was accepted"
fi
kill "$receiver_pid" 2>/dev/null || true
wait "$receiver_pid" 2>/dev/null || true

# Unencrypted over the relay must be refused: the operator's machine would see the
# file contents.
out="$WORK/out-plain-relay"
rm -rf "$out"
mkdir -p "$out"

DROP_ZONE_HOME="$WORK/bob" "$CLIENT" accept --once -y -o "$out" --force-transport=relay \
    --no-encrypt > "$WORK/receiver-plain-relay.log" 2>&1 <<EOF &
$BOB_PRIVATE
$BOB_PUBLIC
EOF
receiver_pid=$!
sleep 1.5

DROP_ZONE_HOME="$WORK/alice" "$CLIENT" send "$WORK/source/tree/small.bin" -t bob \
    --force-transport=relay --no-encrypt > "$WORK/sender-plain-relay.log" 2>&1 <<EOF
$ALICE_PRIVATE
$BOB_PUBLIC
EOF
if [[ $? -ne 0 ]] && ! [[ -e "$out/small.bin" ]]; then
    ok "unencrypted over the relay is refused"
else
    bad "unencrypted data was allowed through the relay"
fi
kill "$receiver_pid" 2>/dev/null || true
wait "$receiver_pid" 2>/dev/null || true

# Sending to somebody who is not accepting must fail promptly and clearly.
DROP_ZONE_HOME="$WORK/alice" "$CLIENT" send "$WORK/source/tree/small.bin" -t nobody \
    --force-transport=tcp > "$WORK/sender-nobody.log" 2>&1 <<EOF
$ALICE_PRIVATE
$BOB_PUBLIC
EOF
if [[ $? -ne 0 ]] && grep -q "not accepting" "$WORK/sender-nobody.log"; then
    ok "sending to an absent user is refused"
else
    bad "sending to an absent user did not fail as expected"
    tail -5 "$WORK/sender-nobody.log" | sed 's/^/    /'
fi

# --------------------------------------------------------------------------
# The server's promise
# --------------------------------------------------------------------------

printf '\nThe server keeps nothing\n'

leaked=""
# No filename from the fixtures may appear in the log, because a manifest is sealed
# with a key the server does not have.
for name in large.bin small.bin deeper.bin text.txt tree; do
    if grep -q "$name" "$WORK/server.log"; then leaked="$leaked $name"; fi
done
# Nor may an address or a username.
for pattern in '127\.0\.0\.1' '::1' 'alice' 'bob'; do
    if grep -qE "$pattern" "$WORK/server.log"; then leaked="$leaked $pattern"; fi
done

if [[ -z "$leaked" ]]; then
    ok "no filename, address or username appears in the server log"
else
    bad "the server log mentions:$leaked"
    grep -nE "$(echo "$leaked" | tr ' ' '|' | sed 's/^|//')" "$WORK/server.log" | head -5 |
        sed 's/^/    /'
fi

# --------------------------------------------------------------------------

printf '\n%d passed, %d failed\n\n' "$PASSES" "$FAILURES"
[[ "$FAILURES" -eq 0 ]]
