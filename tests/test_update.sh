#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR=$(cd "$(dirname "$0")/.." && pwd)
TEST_ROOT=$(mktemp -d)
trap 'rm -rf "$TEST_ROOT"' EXIT

mkdir -p "$TEST_ROOT/release/lan-scanner-main"
cp -a "$PROJECT_DIR/scanner.py" "$PROJECT_DIR/update.sh" "$PROJECT_DIR/install.sh" "$PROJECT_DIR/dependencies.sh" "$PROJECT_DIR/VERSION" "$PROJECT_DIR/static" "$TEST_ROOT/release/lan-scanner-main/"
tar -czf "$TEST_ROOT/release.tar.gz" -C "$TEST_ROOT/release" lan-scanner-main

make_fake_commands() {
    local bin_dir=$1
    mkdir -p "$bin_dir"
    cat >"$bin_dir/curl" <<'SH'
#!/usr/bin/env bash
set -e
destination=""
while (($#)); do
    if [[ $1 == -o ]]; then destination=$2; shift 2; continue; fi
    shift
done
if [[ -n "$destination" ]]; then cp "$TEST_ARCHIVE" "$destination"; fi
SH
    cat >"$bin_dir/systemctl" <<'SH'
#!/usr/bin/env bash
if [[ ${TEST_FAIL_RESTART:-0} == 1 && ${1:-} == restart ]]; then exit 1; fi
exit 0
SH
    chmod +x "$bin_dir/curl" "$bin_dir/systemctl"
    for command in nmap ip ping systemd-run avahi-resolve-address nmblookup; do ln -s /bin/true "$bin_dir/$command"; done
}

run_case() {
    local name=$1 fail_restart=$2
    local root="$TEST_ROOT/$name" app="$TEST_ROOT/$name/app" data="$TEST_ROOT/$name/data" bin="$TEST_ROOT/$name/bin"
    mkdir -p "$app/static" "$data"
    echo old-version >"$app/VERSION"
    echo 8765 >"$data/port"
    make_fake_commands "$bin"
    if [[ $fail_restart == 0 ]]; then
        PATH="$bin:$PATH" TEST_ARCHIVE="$TEST_ROOT/release.tar.gz" LANSCAN_ALLOW_NON_SYSTEMD=1 LANSCAN_APP_DIR="$app" LANSCAN_DATA_DIR="$data" bash "$PROJECT_DIR/update.sh"
        [[ $(<"$app/VERSION") == 20260811-7 ]]
        [[ $(<"$data/port") == 8765 ]]
        [[ ! -e "$app.previous" ]]
        grep -q '"status":"success"' "$data/update-status.json"
    else
        if PATH="$bin:$PATH" TEST_ARCHIVE="$TEST_ROOT/release.tar.gz" TEST_FAIL_RESTART=1 LANSCAN_ALLOW_NON_SYSTEMD=1 LANSCAN_APP_DIR="$app" LANSCAN_DATA_DIR="$data" bash "$PROJECT_DIR/update.sh"; then
            echo "Expected the simulated update to fail" >&2
            exit 1
        fi
        [[ $(<"$app/VERSION") == old-version ]]
        [[ $(<"$data/port") == 8765 ]]
        grep -q '"status":"failed"' "$data/update-status.json"
    fi
}

run_case success 0
run_case rollback 1
echo "transactional updater tests: OK"
