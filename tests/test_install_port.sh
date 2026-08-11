#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR=$(cd "$(dirname "$0")/.." && pwd)
TEST_ROOT=$(mktemp -d)
HOLDER_PID=""
trap '[[ -z "$HOLDER_PID" ]] || kill "$HOLDER_PID" 2>/dev/null || true; rm -rf "$TEST_ROOT"' EXIT
mkdir -p "$TEST_ROOT/bin"
cat >"$TEST_ROOT/bin/systemctl" <<'SH'
#!/usr/bin/env bash
if [[ ${1:-} == is-active ]]; then [[ ${TEST_ACTIVE:-0} == 1 ]]; exit; fi
exit 0
SH
chmod +x "$TEST_ROOT/bin/systemctl"
for command in nmap ip ping systemd-run avahi-resolve-address nmblookup; do
    ln -s /bin/true "$TEST_ROOT/bin/$command"
done
cat >"$TEST_ROOT/bin/hostname" <<'SH'
#!/usr/bin/env bash
echo 127.0.0.1
SH
chmod +x "$TEST_ROOT/bin/hostname"

python3 - "$TEST_ROOT/occupied-port" <<'PY' &
import pathlib, socket, sys, time
sock = socket.socket()
sock.bind(("0.0.0.0", 0))
pathlib.Path(sys.argv[1]).write_text(str(sock.getsockname()[1]))
sock.listen()
time.sleep(30)
PY
HOLDER_PID=$!
for _ in $(seq 1 30); do [[ -s "$TEST_ROOT/occupied-port" ]] && break; sleep .1; done
OCCUPIED=$(<"$TEST_ROOT/occupied-port")

run_installer() {
    PATH="$TEST_ROOT/bin:$PATH" \
    TEST_ACTIVE="$1" \
    LANSCAN_START_PORT="$OCCUPIED" \
    LANSCAN_APP_DIR="$TEST_ROOT/app" \
    LANSCAN_DATA_DIR="$TEST_ROOT/data" \
    LANSCAN_SYSTEMD_DIR="$TEST_ROOT/systemd" \
    LANSCAN_ALLOW_NON_SYSTEMD=1 \
    bash "$PROJECT_DIR/install.sh" >/dev/null
}

cd "$TEST_ROOT"
run_installer 0
FIRST_PORT=$(<"$TEST_ROOT/data/port")
[[ "$FIRST_PORT" != "$OCCUPIED" ]]

run_installer 1
SECOND_PORT=$(<"$TEST_ROOT/data/port")
[[ "$SECOND_PORT" == "$FIRST_PORT" ]]
grep -q -- "--port $FIRST_PORT" "$TEST_ROOT/systemd/lan-scanner.service"
echo "installer port persistence tests: OK ($FIRST_PORT retained)"
