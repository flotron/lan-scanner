#!/usr/bin/env bash

required_commands=(python3 nmap ip ping curl tar systemctl systemd-run)
optional_commands=(avahi-resolve-address nmblookup)

package_for() {
    local manager=$1 command=$2
    case "$manager:$command" in
        apt:python3) echo python3 ;; apt:nmap) echo nmap ;; apt:ip) echo iproute2 ;;
        apt:ping) echo iputils-ping ;; apt:curl) echo curl ;; apt:tar) echo tar ;;
        apt:systemctl|apt:systemd-run) echo systemd ;; apt:avahi-resolve-address) echo "avahi-utils avahi-daemon" ;;
        apt:nmblookup) echo samba-common-bin ;;
        dnf:python3) echo python3 ;; dnf:nmap) echo nmap ;; dnf:ip) echo iproute ;;
        dnf:ping) echo iputils ;; dnf:curl) echo curl ;; dnf:tar) echo tar ;;
        dnf:systemctl|dnf:systemd-run) echo systemd ;; dnf:avahi-resolve-address) echo "avahi-tools avahi" ;;
        dnf:nmblookup) echo samba-client ;;
        pacman:python3) echo python ;; pacman:nmap) echo nmap ;; pacman:ip) echo iproute2 ;;
        pacman:ping) echo iputils ;; pacman:curl) echo curl ;; pacman:tar) echo tar ;;
        pacman:systemctl|pacman:systemd-run) echo systemd ;; pacman:avahi-resolve-address) echo avahi ;;
        pacman:nmblookup) echo samba ;;
    esac
}

missing_packages() {
    local manager=$1; shift
    local command package seen=" "
    for command in "$@"; do
        command -v "$command" >/dev/null 2>&1 && continue
        for package in $(package_for "$manager" "$command"); do
            [[ "$seen" != *" $package "* ]] || continue
            printf '%s\n' "$package"
            seen+="$package "
        done
    done
}

install_package_group() {
    local manager=$1 required=$2; shift 2
    local packages=("$@")
    ((${#packages[@]})) || return 0
    case "$manager" in
        apt) DEBIAN_FRONTEND=noninteractive apt-get install -y "${packages[@]}" ;;
        dnf) dnf install -y "${packages[@]}" ;;
        pacman) pacman -Sy --noconfirm "${packages[@]}" ;;
        *) return 1 ;;
    esac || {
        [[ "$required" == 0 ]] && { echo "Warning: optional discovery tools could not be installed: ${packages[*]}" >&2; return 0; }
        return 1
    }
}

ensure_dependencies() {
    local manager=""
    if command -v apt-get >/dev/null; then manager=apt
    elif command -v dnf >/dev/null; then manager=dnf
    elif command -v pacman >/dev/null; then manager=pacman
    fi

    local required_packages=() optional_packages=()
    [[ -n "$manager" ]] && mapfile -t required_packages < <(missing_packages "$manager" "${required_commands[@]}")
    [[ -n "$manager" ]] && mapfile -t optional_packages < <(missing_packages "$manager" "${optional_commands[@]}")
    if ((${#required_packages[@]} || ${#optional_packages[@]})) && [[ "$manager" == apt ]]; then
        apt-get update || echo "Warning: apt update failed because of an external repository; trying with the available package indexes." >&2
    fi
    install_package_group "$manager" 1 "${required_packages[@]}"
    install_package_group "$manager" 0 "${optional_packages[@]}"

    local missing_required=() command
    for command in "${required_commands[@]}"; do command -v "$command" >/dev/null 2>&1 || missing_required+=("$command"); done
    ((${#missing_required[@]} == 0)) || { echo "Missing required commands: ${missing_required[*]}" >&2; return 1; }
    if [[ ${LANSCAN_ALLOW_NON_SYSTEMD:-0} != 1 && ! -d /run/systemd/system ]]; then
        echo "LAN Scanner requires Linux running systemd." >&2
        return 1
    fi
    if command -v avahi-resolve-address >/dev/null 2>&1; then
        systemctl enable --now avahi-daemon.service >/dev/null 2>&1 || echo "Warning: Avahi is installed but its daemon could not be started." >&2
    fi

    local missing_optional=()
    for command in "${optional_commands[@]}"; do command -v "$command" >/dev/null 2>&1 || missing_optional+=("$command"); done
    ((${#missing_optional[@]} == 0)) || echo "Warning: optional host-name discovery is limited; missing: ${missing_optional[*]}" >&2
}
