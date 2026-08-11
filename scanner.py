#!/usr/bin/env python3
"""LAN Scanner: small Linux LAN discovery web service."""
from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import threading
import time
import urllib.parse
import xml.etree.ElementTree as ET
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

BASE = Path(__file__).resolve().parent
STATIC = BASE / "static"
DATA_DIR = Path(os.getenv("LANSCAN_DATA_DIR", str(BASE / "data")))
HISTORY_FILE = DATA_DIR / "devices.json"
VERSION_FILE = BASE / "VERSION"
UPDATE_SCRIPT = BASE / "update.sh"
UPDATE_STATUS_FILE = DATA_DIR / "update-status.json"
OFFLINE_CONFIRMATIONS = max(2, int(os.getenv("LANSCAN_OFFLINE_CONFIRMATIONS", "3")))
OUI_FILES = (Path("/usr/share/nmap/nmap-mac-prefixes"), Path("/usr/share/ieee-data/oui.txt"))
state = {"running": False, "progress": 0, "subnet": "", "devices": [], "error": None, "started": None, "finished": None, "last_presence": None, "monitor_interval": 15}
lock = threading.Lock()
viewer_seen = 0.0


def current_version() -> str:
    try:
        return VERSION_FILE.read_text().strip()
    except OSError:
        return "unknown"


def write_update_status(payload: dict) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    temporary = UPDATE_STATUS_FILE.with_suffix(".tmp")
    temporary.write_text(json.dumps(payload, separators=(",", ":")))
    temporary.replace(UPDATE_STATUS_FILE)


def update_status() -> dict:
    try:
        value = json.loads(UPDATE_STATUS_FILE.read_text())
        return value if isinstance(value, dict) else {"status": "idle"}
    except (OSError, json.JSONDecodeError):
        return {"status": "idle", "version": current_version()}


def schedule_update(request_id: str = "") -> dict:
    if not UPDATE_SCRIPT.is_file():
        raise ValueError("Update script is not installed.")
    if shutil.which("systemd-run") is None:
        raise ValueError("systemd-run is required for web updates.")
    update_id = request_id if re.fullmatch(r"\d{13,16}", request_id) else str(int(time.time() * 1000))
    unit = f"lan-scanner-update-{update_id}"
    payload = {"id": update_id, "status": "scheduled", "message": "Update scheduled.", "version": current_version(), "updated_at": int(time.time())}
    write_update_status(payload)
    completed = subprocess.run(
        ["systemd-run", "--no-block", f"--unit={unit}", "--collect", "--property=Type=oneshot", f"--setenv=LANSCAN_UPDATE_ID={update_id}", str(UPDATE_SCRIPT)],
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )
    if completed.returncode:
        message = (completed.stderr or completed.stdout).strip()
        write_update_status({**payload, "status": "failed", "message": message or "Could not schedule the update."})
        raise ValueError(message or "Could not schedule the update.")
    return {"started": True, "id": update_id, "version": current_version()}


def local_update_request(address: str, origin: str, host: str) -> bool:
    try:
        client = ipaddress.ip_address(address)
    except ValueError:
        return False
    local_overlay = client.version == 4 and client in ipaddress.ip_network("100.64.0.0/10")
    if not (client.is_private or client.is_loopback or local_overlay):
        return False
    if origin:
        return urllib.parse.urlparse(origin).netloc == host
    return True


def run(command: list[str], timeout: int = 30) -> str:
    return subprocess.run(command, text=True, capture_output=True, timeout=timeout, check=False).stdout


def interfaces() -> list[dict]:
    try:
        raw = json.loads(run(["ip", "-j", "-4", "addr", "show"], 5) or "[]")
    except (json.JSONDecodeError, OSError, subprocess.TimeoutExpired):
        return []
    result = []
    for item in raw:
        if item.get("ifname") == "lo" or item.get("operstate") == "DOWN":
            continue
        for addr in item.get("addr_info", []):
            if addr.get("family") != "inet" or addr.get("scope") != "global":
                continue
            iface = ipaddress.ip_interface(f"{addr['local']}/{addr['prefixlen']}")
            result.append({"name": item["ifname"], "address": addr["local"], "subnet": str(iface.network), "mac": item.get("address", "")})
    return result


def oui_database() -> dict[str, str]:
    vendors: dict[str, str] = {}
    for path in OUI_FILES:
        if not path.exists():
            continue
        try:
            for line in path.read_text(errors="ignore").splitlines():
                match = re.match(r"^([0-9A-Fa-f]{6})\s+(.+)$", line)
                if match:
                    vendors[match.group(1).upper()] = match.group(2).strip()
                    continue
                match = re.match(r"^([0-9A-Fa-f]{2})[-:]([0-9A-Fa-f]{2})[-:]([0-9A-Fa-f]{2})\s+\(hex\)\s+(.+)$", line)
                if match:
                    vendors[(match.group(1) + match.group(2) + match.group(3)).upper()] = match.group(4).strip()
            if vendors:
                break
        except OSError:
            pass
    return vendors


VENDORS = oui_database()


def vendor_for(mac: str) -> str:
    return VENDORS.get(re.sub(r"[^0-9A-Fa-f]", "", mac)[:6].upper(), "Unknown") if mac else "Unknown"


def reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, TimeoutError):
        return ""


def optional_command_name(command: list[str], pattern: str) -> str:
    if not shutil.which(command[0]):
        return ""
    try:
        output = run(command, 3)
        match = re.search(pattern, output, re.MULTILINE | re.IGNORECASE)
        return match.group(1).rstrip(".") if match else ""
    except (OSError, subprocess.TimeoutExpired):
        return ""


def ber_length(size: int) -> bytes:
    if size < 128:
        return bytes([size])
    raw = size.to_bytes((size.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def ber(tag: int, payload: bytes) -> bytes:
    return bytes([tag]) + ber_length(len(payload)) + payload


def ber_integer(value: int) -> bytes:
    raw = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return ber(0x02, raw)


def oid_bytes(oid: str) -> bytes:
    parts = [int(part) for part in oid.split(".")]
    encoded = bytearray([parts[0] * 40 + parts[1]])
    for value in parts[2:]:
        groups = [value & 0x7F]
        value >>= 7
        while value:
            groups.append(0x80 | (value & 0x7F))
            value >>= 7
        encoded.extend(reversed(groups))
    return bytes(encoded)


def read_ber_length(data: bytes, offset: int) -> tuple[int, int]:
    first = data[offset]
    offset += 1
    if not first & 0x80:
        return first, offset
    count = first & 0x7F
    return int.from_bytes(data[offset:offset + count], "big"), offset + count


def snmp_identity(ip: str) -> str:
    """Read SNMPv2 sysName/sysDescr using a tiny dependency-free request."""
    community = os.getenv("LANSCAN_SNMP_COMMUNITY", "public").encode()
    oids = ("1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.1.1.0")
    varbinds = b"".join(ber(0x30, ber(0x06, oid_bytes(oid)) + ber(0x05, b"")) for oid in oids)
    pdu = ber(0xA0, ber_integer(int(time.time() * 1000) & 0x7FFFFFFF) + ber_integer(0) + ber_integer(0) + ber(0x30, varbinds))
    packet = ber(0x30, ber_integer(1) + ber(0x04, community) + pdu)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(1.0)
            sock.sendto(packet, (ip, 161))
            data = sock.recvfrom(8192)[0]
    except (OSError, TimeoutError):
        return ""
    values = []
    for oid in oids:
        marker = ber(0x06, oid_bytes(oid))
        offset = data.find(marker)
        if offset < 0:
            values.append("")
            continue
        offset += len(marker)
        try:
            tag = data[offset]
            size, start = read_ber_length(data, offset + 1)
            raw = data[start:start + size] if tag in (0x04, 0x44) else b""
            text = re.sub(r"[\x00-\x1f]+", " ", raw.decode(errors="ignore")).strip()
            values.append(text)
        except (IndexError, ValueError):
            values.append("")
    name, description = values
    if name and name.lower() not in {"unknown", "none", "localhost"}:
        return name[:120]
    return description[:120]


def identify_host(ip: str) -> dict:
    """Try low-cost naming protocols in order of usefulness."""
    name = reverse_dns(ip)
    source = "DNS" if name else ""
    if not name:
        name = optional_command_name(["avahi-resolve-address", "-4", ip], rf"^{re.escape(ip)}\s+([^\s]+)")
        source = "mDNS" if name else ""
    if not name:
        name = optional_command_name(["nmblookup", "-A", ip], r"^\s*([^\s<]+)\s+<00>\s+-")
        source = "NetBIOS" if name else ""
    if not name:
        name = snmp_identity(ip)
        source = "SNMP" if name else ""
    return {"name": name, "name_source": source, "name_probe_at": int(time.time())}


def load_history() -> dict[str, dict]:
    try:
        value = json.loads(HISTORY_FILE.read_text())
        return value if isinstance(value, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def save_history(history: dict[str, dict]) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    temporary = HISTORY_FILE.with_suffix(".tmp")
    temporary.write_text(json.dumps(history, separators=(",", ":")))
    temporary.replace(HISTORY_FILE)


def merged_device_list(subnet: str, online: list[dict]) -> list[dict]:
    """Retain known clients and require repeated misses before marking offline."""
    network = ipaddress.ip_network(subnet)
    history = load_history()
    current = {device["ip"]: device for device in online}
    now = int(time.time())
    result = []
    for address in network.hosts():
        ip = str(address)
        saved = history.get(ip, {})
        previous = saved if saved.get("subnet") == subnet else {}
        if ip in current:
            device = {**previous, **current[ip], "subnet": subnet, "status": "online", "last_seen": now, "missed_checks": 0}
            history[ip] = device
        else:
            missed = int(previous.get("missed_checks", 0)) + 1
            still_online = previous.get("status") == "online" and missed < OFFLINE_CONFIRMATIONS
            device = {"status": "online" if still_online else "offline", "name": previous.get("name", ""), "ip": ip,
                      "mac": previous.get("mac", ""), "manufacturer": previous.get("manufacturer", "Unknown"),
                      "last_seen": previous.get("last_seen"), "subnet": subnet, "missed_checks": missed}
            if previous:
                history[ip] = device
        result.append(device)
    save_history(history)
    return result


def parse_discovery(xml: str) -> list[dict]:
    devices = []
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return devices
    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue
        addresses = {a.get("addrtype"): a.get("addr", "") for a in host.findall("address")}
        ip = addresses.get("ipv4", "")
        mac = addresses.get("mac", "")
        hostnode = host.find("hostnames/hostname")
        devices.append({"status": "online", "name": hostnode.get("name", "") if hostnode is not None else "", "ip": ip, "mac": mac, "manufacturer": vendor_for(mac), "last_seen": int(time.time())})
    return devices


def scan_network(subnet: str) -> None:
    with lock:
        state.update(running=True, progress=8, subnet=subnet, devices=[], error=None, started=int(time.time()), finished=None)
    try:
        network = ipaddress.ip_network(subnet, strict=False)
        if network.version != 4 or network.num_addresses > 4096:
            raise ValueError("For safety, the maximum scan range is /20 (4096 addresses).")
        with lock:
            state["progress"] = 18
        xml = run(["nmap", "-sn", "-PR", "-oX", "-", str(network)], max(45, min(300, network.num_addresses // 4)))
        devices = parse_discovery(xml)
        with lock:
            state["progress"] = 82
        unnamed = [d for d in devices if not d["name"]]
        with concurrent.futures.ThreadPoolExecutor(max_workers=24) as pool:
            identities = list(pool.map(lambda d: identify_host(d["ip"]), unnamed))
        for device, identity in zip(unnamed, identities):
            device.update(identity)
        devices = merged_device_list(subnet, devices)
        with lock:
            state.update(devices=devices, progress=100, running=False, finished=int(time.time()), last_presence=int(time.time()))
    except Exception as exc:
        with lock:
            state.update(running=False, error=str(exc), progress=0, finished=int(time.time()))


def presence_scan() -> None:
    """Cheap discovery used only while at least one browser is active."""
    with lock:
        subnet = state["subnet"]
        busy = state["running"]
        old_devices = list(state.get("devices", []))
    if not subnet or busy:
        return
    try:
        network = ipaddress.ip_network(subnet)
        xml = run([
            "nmap", "-sn", "-PR", "-PE", "-PP",
            "-PS22,80,443,445,3389", "-PA80,443",
            "--max-retries", "2", "--initial-rtt-timeout", "500ms",
            "--max-rtt-timeout", "2s", "-oX", "-", subnet,
        ], max(45, min(180, network.num_addresses // 3)))
        online = parse_discovery(xml)
        old_by_ip = {item["ip"]: item for item in old_devices}
        identify = []
        for device in online:
            old = old_by_ip.get(device["ip"], {})
            if not device["name"]:
                device["name"] = old.get("name", "")
                device["name_source"] = old.get("name_source", "")
                device["name_probe_at"] = old.get("name_probe_at")
                if not device["name"] and time.time() - (old.get("name_probe_at") or 0) >= 3600:
                    identify.append(device)
            if not device["mac"]:
                device["mac"] = old.get("mac", "")
                device["manufacturer"] = old.get("manufacturer", "Unknown")
        if identify:
            with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
                identities = list(pool.map(lambda d: identify_host(d["ip"]), identify))
            for device, identity in zip(identify, identities):
                device.update(identity)
        devices = merged_device_list(subnet, online)
        with lock:
            if state["subnet"] == subnet:
                state.update(devices=devices, last_presence=int(time.time()))
    except Exception:
        pass


def presence_monitor() -> None:
    while True:
        time.sleep(5)
        with lock:
            active = time.time() - viewer_seen < 25
            last = state.get("last_presence") or 0
            subnet = state.get("subnet")
        addresses = ipaddress.ip_network(subnet).num_addresses if subnet else 0
        interval = 15 if addresses <= 256 else 30 if addresses <= 1024 else 60
        with lock:
            state["monitor_interval"] = interval
        if active and time.time() - last >= interval:
            presence_scan()


def ping_host(ip: str) -> dict:
    """One immediate, non-debounced ping for the explicitly watched panel."""
    started = time.monotonic()
    try:
        completed = subprocess.run(
            ["ping", "-n", "-c", "1", "-W", "1", ip],
            text=True, capture_output=True, timeout=2, check=False,
        )
        match = re.search(r"time[=<]([0-9.]+)\s*ms", completed.stdout)
        latency = float(match.group(1)) if match else None
        return {"ip": ip, "online": completed.returncode == 0, "latency_ms": latency,
                "checked_at": int(time.time() * 1000), "duration_ms": round((time.monotonic() - started) * 1000)}
    except (OSError, subprocess.TimeoutExpired):
        return {"ip": ip, "online": False, "latency_ms": None,
                "checked_at": int(time.time() * 1000), "duration_ms": round((time.monotonic() - started) * 1000)}


def watch_ips(values) -> list[dict]:
    if not isinstance(values, list) or not values:
        return []
    if len(values) > 32:
        raise ValueError("Immediate watch supports up to 32 selected IP addresses.")
    with lock:
        subnet = state.get("subnet")
    if not subnet:
        raise ValueError("Run a network scan before starting immediate watch.")
    network = ipaddress.ip_network(subnet)
    ips = []
    for value in values:
        address = ipaddress.ip_address(str(value))
        if address.version != 4 or address not in network or address in (network.network_address, network.broadcast_address):
            raise ValueError(f"{address} is outside the active scan range.")
        ip = str(address)
        if ip not in ips:
            ips.append(ip)
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(16, len(ips))) as pool:
        return list(pool.map(ping_host, ips))


def detail_scan(ip: str) -> dict:
    address = ipaddress.ip_address(ip)
    if address.version != 4 or not any(address in ipaddress.ip_network(i["subnet"]) for i in interfaces()):
        raise ValueError("The address must belong to a local subnet.")
    xml = run(["nmap", "-sT", "-sV", "--version-light", "-O", "--osscan-limit", "--top-ports", "1000", "-oX", "-", ip], 180)
    root = ET.fromstring(xml)
    host = root.find("host")
    if host is None:
        return {"ip": ip, "ports": [], "os": [], "latency": None}
    ports = []
    for port in host.findall("ports/port"):
        st = port.find("state")
        svc = port.find("service")
        if st is not None and st.get("state") == "open":
            ports.append({"port": int(port.get("portid", 0)), "protocol": port.get("protocol", "tcp"), "service": svc.get("name", "unknown") if svc is not None else "unknown", "product": " ".join(filter(None, [svc.get("product", "") if svc is not None else "", svc.get("version", "") if svc is not None else ""]))})
    os_matches = [{"name": x.get("name", ""), "accuracy": int(x.get("accuracy", 0))} for x in host.findall("os/osmatch")[:3]]
    times = host.find("times")
    return {"ip": ip, "ports": ports, "os": os_matches, "latency": float(times.get("srtt", 0)) / 1000 if times is not None else None}


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(STATIC), **kwargs)

    def log_message(self, fmt, *args):
        pass

    def send_json(self, payload, status=200):
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        try:
            if parsed.path == "/api/interfaces":
                found = interfaces()
                return self.send_json({"interfaces": found, "default": found[0]["subnet"] if found else ""})
            if parsed.path == "/api/scan":
                with lock:
                    return self.send_json(dict(state))
            if parsed.path == "/api/heartbeat":
                global viewer_seen
                with lock:
                    viewer_seen = time.time()
                return self.send_json({"ok": True})
            if parsed.path == "/api/version":
                return self.send_json({"version": current_version()})
            if parsed.path == "/api/update":
                return self.send_json(update_status())
            if parsed.path == "/api/details":
                ip = urllib.parse.parse_qs(parsed.query).get("ip", [""])[0]
                return self.send_json(detail_scan(ip))
        except (ValueError, OSError, subprocess.TimeoutExpired, ET.ParseError) as exc:
            return self.send_json({"error": str(exc)}, 400)
        return super().do_GET()

    def do_POST(self):
        if self.path not in ("/api/scan", "/api/watch", "/api/update"):
            return self.send_json({"error": "Not found"}, 404)
        try:
            if self.path == "/api/update":
                if not local_update_request(self.client_address[0], self.headers.get("Origin", ""), self.headers.get("Host", "")):
                    return self.send_json({"error": "Web updates are restricted to this local network."}, 403)
                return self.send_json(schedule_update(self.headers.get("X-Update-Id", "")), 202)
            size = min(int(self.headers.get("Content-Length", "0")), 8192)
            body = json.loads(self.rfile.read(size) or b"{}")
            if self.path == "/api/watch":
                return self.send_json({"results": watch_ips(body.get("ips"))})
            subnet = str(ipaddress.ip_network(body.get("subnet", ""), strict=False))
            with lock:
                if state["running"]:
                    return self.send_json({"error": "A scan is already running."}, 409)
            threading.Thread(target=scan_network, args=(subnet,), daemon=True).start()
            return self.send_json({"started": True, "subnet": subnet}, 202)
        except (ValueError, json.JSONDecodeError) as exc:
            return self.send_json({"error": f"Invalid subnet: {exc}"}, 400)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default=os.getenv("LANSCAN_HOST", "0.0.0.0"))
    parser.add_argument("--port", type=int, default=int(os.getenv("LANSCAN_PORT", "8765")))
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    threading.Thread(target=presence_monitor, daemon=True).start()
    print(f"LAN Scanner listening on http://{args.host}:{args.port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
