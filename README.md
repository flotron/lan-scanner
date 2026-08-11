# LAN Scanner

A Linux web application for authorized local-network discovery. It lists online hosts with hostname, IPv4, MAC address and manufacturer, and opens a detailed top-1000 TCP port/service scan for each host.

The full subnet stays visible: offline addresses are dimmed and retain the last hostname, MAC address, manufacturer, and last-seen time. While the page is open, a lightweight presence scan runs about every 15 seconds for a /24 network. Larger ranges automatically use 30- or 60-second intervals, and monitoring stops when no browser is watching. A known online client must fail three consecutive checks before it is marked offline, preventing transient packet loss or Wi-Fi power saving from making solid clients flicker.

The device table can be sorted by status, last-known name, IP address, MAC address, or manufacturer. Its status filter can show all clients, online clients only, or offline addresses only.

## Immediate watch

Select the `WATCH` checkbox beside the few addresses you are working on. They are grouped in one panel and pinged concurrently once per second, independently from normal network discovery. Every target shows its immediate state, latency, check time, and the last 18 replies. A single missed reply is shown immediately in this panel; the conservative three-check rule continues to apply only to the general device list. Selections are kept in the browser and the endpoint is capped at 32 addresses to prevent accidental load.

Host identification tries reverse DNS, mDNS/Bonjour, NetBIOS, and SNMP. SNMP uses the read-only `public` community by default and is especially useful for printers; it can be changed with the `LANSCAN_SNMP_COMMUNITY` environment variable. Unknown online hosts are retried at most once per hour, so enhanced identification does not burden continuous presence monitoring.

## Install

```bash
chmod +x install.sh uninstall.sh
sudo ./install.sh
```

The installer checks TCP ports starting at `8765`, chooses the first free one, installs a hardened systemd service, starts it, and prints the final URL. To start searching at another port:

```bash
sudo LANSCAN_START_PORT=8080 ./install.sh
```

Supported package managers: apt, dnf, and pacman. Requirements are Python 3, nmap, iproute2, and iputils-ping. Vendor lookup uses nmap's local MAC-prefix database, so it works without sending device data to an external service.

The installer skips package-manager updates when all requirements are already installed. A broken unrelated APT repository therefore cannot block an otherwise ready system.

## Notes

- The default range is taken from the first active, globally addressed network interface.
- A different CIDR may be entered; discovery is capped at 4096 addresses (/20) to prevent accidental oversized scans.
- MAC addresses are normally available only for devices on the same Layer-2 network/VLAN.
- OS detection and some service details depend on device response and scanner privileges.
- Scan only networks you own or are authorized to inspect.

## Service controls

```bash
sudo systemctl status lan-scanner
sudo systemctl restart lan-scanner
sudo journalctl -u lan-scanner -f
```

## Install or update from GitHub

After the public repository is available, a new machine can install the current version with:

```bash
curl -fsSL https://raw.githubusercontent.com/flotron/lan-scanner/main/install-online.sh | sudo bash
```

An installed machine updates from the same repository with:

```bash
sudo /opt/lan-scanner/update.sh
```

You can also use the `UPDATE` button in the web interface. For security, it asks for the update PIN shown by the installer. Retrieve it later with `sudo cat /var/lib/lan-scanner/update-token`. The updater downloads into a temporary directory, invokes the normal installer and reloads the interface after the service restarts. Device history in `/var/lib/lan-scanner` is preserved.
