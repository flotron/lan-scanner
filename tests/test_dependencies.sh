#!/usr/bin/env bash
set -euo pipefail
PROJECT_DIR=$(cd "$(dirname "$0")/.." && pwd)
source "$PROJECT_DIR/dependencies.sh"
[[ $(package_for apt nmap) == nmap ]]
[[ $(package_for apt ip) == iproute2 ]]
[[ $(package_for apt avahi-resolve-address) == "avahi-utils avahi-daemon" ]]
[[ $(package_for dnf nmblookup) == samba-client ]]
[[ $(package_for pacman python3) == python ]]
echo "dependency mapping tests: OK"
