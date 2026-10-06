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
import sys
import threading
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from preferences import UserPreferences, watch_addresses

BASE = Path(__file__).resolve().parent
STATIC = BASE / "static"
DATA_DIR = Path(os.getenv("LANSCAN_DATA_DIR", str(BASE / "data")))
HISTORY_FILE = DATA_DIR / "devices.json"
user_preferences = UserPreferences(DATA_DIR / "preferences.json")
VERSION_FILE = BASE / "VERSION"
UPDATE_SCRIPT = BASE / "update.sh"
UPDATE_STATUS_FILE = DATA_DIR / "update-status.json"
OFFLINE_CONFIRMATIONS = max(2, int(os.getenv("LANSCAN_OFFLINE_CONFIRMATIONS", "3")))
OUI_FILES = (Path("/usr/share/nmap/nmap-mac-prefixes"), Path("/usr/share/ieee-data/oui.txt"))
REQUIRED_COMMANDS = ("python3", "nmap", "ip", "ping", "curl", "tar", "systemctl", "systemd-run")
OPTIONAL_COMMANDS = ("avahi-resolve-address", "nmblookup")
state = {"running": False, "progress": 0, "subnet": "", "devices": [], "error": None, "started": None, "finished": None, "last_presence": None, "monitor_interval": 15, "stopping": False, "cancelled": False, "monitor_paused": False, "message": "READY", "diagnostic": "", "warning": "", "scanned": 0}
lock = threading.Lock()
viewer_seen = 0.0
version_cache = {"latest_version": "", "checked_at": 0.0, "error": ""}
version_lock = threading.Lock()


class ScanCancelled(Exception):
    pass


class ScanJob:
    def __init__(self, subnet: str, background: bool = False):
        self.subnet = subnet
        self.background = background
        self.cancel = threading.Event()
        self.unverified = []
        self.diagnostics = []
        self.scanned = 0


active_job = None


def validated_network(subnet: str):
    network = ipaddress.ip_network(subnet, strict=False)
    if network.version != 4 or not 20 <= network.prefixlen <= 30:
        raise ValueError("Use an IPv4 range from /20 to /30 (up to 4094 hosts).")
    return network


def check_cancel(cancel):
    if cancel is not None and cancel.is_set():
        raise ScanCancelled()


def current_version() -> str:
    try:
        return VERSION_FILE.read_text().strip()
    except OSError:
        return "unknown"


def dependency_info() -> dict:
    missing_required = [command for command in REQUIRED_COMMANDS if shutil.which(command) is None]
    missing_optional = [command for command in OPTIONAL_COMMANDS if shutil.which(command) is None]
    return {"missing_dependencies": missing_required, "missing_optional_dependencies": missing_optional}


def version_info(force: bool = False) -> dict:
    current = current_version()
    with version_lock:
        if not force and time.time() - version_cache["checked_at"] < 300:
            latest = version_cache["latest_version"]
            return {"current_version": current, "latest_version": latest, "update_available": latest != current if latest else None, "check_error": version_cache["error"], **dependency_info()}
    latest = ""
    error = ""
    try:
        request = urllib.request.Request(
            "https://raw.githubusercontent.com/flotron/lan-scanner/main/VERSION",
            headers={"User-Agent": "LAN-Scanner-Update-Check"},
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            candidate = response.read(128).decode().strip()
        if not re.fullmatch(r"[0-9A-Za-z._-]{1,64}", candidate):
            raise ValueError("GitHub returned an invalid version.")
        latest = candidate
    except Exception as exc:
        error = str(exc)
    with version_lock:
        version_cache.update(latest_version=latest, checked_at=time.time(), error=error)
    return {"current_version": current, "latest_version": latest, "update_available": latest != current if latest else None, "check_error": error, **dependency_info()}


def write_update_status(payload: dict) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    temporary = UPDATE_STATUS_FILE.with_suffix(".tmp")
    temporary.write_text(json.dumps(payload, separators=(",", ":")))
    temporary.replace(UPDATE_STATUS_FILE)


def update_status() -> dict:
    try:
        value = json.loads(UPDATE_STATUS_FILE.read_text())
        status = value if isinstance(value, dict) else {"status": "idle"}
    except (OSError, json.JSONDecodeError):
        status = {"status": "idle"}
    return {**status, **version_info()}


def schedule_update(request_id: str = "") -> dict:
    if not UPDATE_SCRIPT.is_file():
        raise ValueError("Update script is not installed.")
    if shutil.which("systemd-run") is None:
        raise ValueError("systemd-run is required for web updates.")
    update_id = request_id if re.fullmatch(r"\d{13,16}", request_id) else str(int(time.time() * 1000))
    versions = version_info(force=True)
    missing_tools = versions["missing_dependencies"] + versions["missing_optional_dependencies"]
    if versions["update_available"] is False and not missing_tools:
        payload = {"id": update_id, "status": "up_to_date", "message": "LAN Scanner is already up to date.", "version": current_version(), "updated_at": int(time.time()), **versions}
        write_update_status(payload)
        return {"started": False, "up_to_date": True, **payload}
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


def run(command: list[str], timeout: float = 30, cancel=None) -> str:
    """Poll child processes so STOP terminates and reaps the actual scan."""
    check_cancel(cancel)
    if cancel is None:
        return subprocess.run(command, text=True, capture_output=True, timeout=timeout, check=False).stdout
    process = subprocess.Popen(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    deadline = time.monotonic() + timeout
    try:
        while True:
            check_cancel(cancel)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(command, timeout)
            try:
                output, error = process.communicate(timeout=min(.15, remaining))
                if process.returncode:
                    raise OSError(error.strip() or f"{command[0]} exited with status {process.returncode}")
                return output
            except subprocess.TimeoutExpired:
                continue
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.communicate(timeout=.5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()


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


def reverse_dns(ip: str, cancel=None) -> str:
    # libc DNS lookups cannot be interrupted in a Python thread. Isolate the
    # lookup in a short-lived child with a deadline and the scan's stop signal.
    try:
        return run([sys.executable, "-c", "import socket,sys; print(socket.gethostbyaddr(sys.argv[1])[0])", ip],
                   2, cancel).strip()
    except (OSError, subprocess.TimeoutExpired):
        return ""


def optional_command_name(command: list[str], pattern: str, cancel=None) -> str:
    check_cancel(cancel)
    if not shutil.which(command[0]):
        return ""
    try:
        output = run(command, 2, cancel)
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


def identify_host(ip: str, cancel=None) -> dict:
    """Try low-cost naming protocols in order of usefulness."""
    check_cancel(cancel)
    name = reverse_dns(ip, cancel)
    source = "DNS" if name else ""
    if not name:
        name = optional_command_name(["avahi-resolve-address", "-4", ip], rf"^{re.escape(ip)}\s+([^\s]+)", cancel)
        source = "mDNS" if name else ""
    if not name:
        name = optional_command_name(["nmblookup", "-A", ip], r"^\s*([^\s<]+)\s+<00>\s+-", cancel)
        source = "NetBIOS" if name else ""
    if not name:
        check_cancel(cancel)
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


def merged_device_list(subnet: str, online: list[dict], unverified=()) -> list[dict]:
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
        elif any(address in skipped for skipped in unverified):
            # An unfinished probe says nothing about reachability. Do not age
            # history or call these devices offline after a timeout.
            device = {**previous, "ip": ip, "status": "unknown", "subnet": subnet,
                      "name": previous.get("name", ""), "mac": previous.get("mac", ""),
                      "manufacturer": previous.get("manufacturer", "Unknown"),
                      "last_seen": previous.get("last_seen")}
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


def start_scan(subnet: str) -> str:
    """Validate and reserve atomically before starting the worker."""
    global active_job
    subnet = str(validated_network(subnet))
    with lock:
        if active_job is not None and not active_job.background:
            raise ValueError("A scan is already running. Stop it before changing range.")
        if active_job is not None:
            active_job.cancel.set()
        job = ScanJob(subnet)
        active_job = job
        state.update(running=True, stopping=False, cancelled=False, monitor_paused=False,
                     progress=0, subnet=subnet, devices=[], error=None, started=int(time.time()),
                     finished=None, last_presence=None, message="DISCOVERING HOSTS", diagnostic="", warning="", scanned=0)
    threading.Thread(target=scan_network, args=(subnet, job), daemon=True).start()
    return subnet


def stop_scan() -> dict:
    with lock:
        state["monitor_paused"] = True
        if active_job is not None:
            active_job.cancel.set()
            state.update(stopping=True, message="STOPPING SCAN…")
            return {"stopping": True}
        state.update(running=False, stopping=False, cancelled=True, message="SCAN STOPPED")
        return {"stopping": False}


def discover_chunks(network, job):
    """Retry slow /26 blocks as /28s; keep all other results usable."""
    chunks = list(network.subnets(new_prefix=26)) if network.prefixlen < 26 else [network]
    found = {}
    total = network.num_addresses - 2
    processed = 0

    def update(message):
        with lock:
            if active_job is job and not job.background:
                state.update(progress=round(processed * 80 / total), scanned=job.scanned,
                             devices=list(found.values()), message=message)

    def probe(chunk, retry=False):
        nonlocal processed
        check_cancel(job.cancel)
        update(f"SCANNING {chunk}" + (" — SMALLER RETRY" if retry else ""))
        command = ["nmap", "-sn", "-n", "-PE", "-PP", "-PS22,80,443,445,3389", "-PA80,443",
                   "--max-retries", "1", "--initial-rtt-timeout", "300ms", "--max-rtt-timeout", "1s",
                   "--host-timeout", "5s", "-oX", "-", str(chunk)]
        # Nmap's host timeout is not a deadline for the entire discovery batch.
        # Sparse or filtered segments can legitimately take longer than 25s.
        timeout = 30 if retry else 90
        try:
            xml = run(command, timeout, job.cancel)
        except subprocess.TimeoutExpired:
            job.diagnostics.append(f"Nmap discovery timed out after {timeout}s in {chunk}.")
            if chunk.prefixlen < 28:
                for smaller in chunk.subnets(new_prefix=28):
                    probe(smaller, retry=True)
                return
            job.unverified.append(chunk)
            usable = sum(address not in (network.network_address, network.broadcast_address) for address in chunk)
            processed += usable
            update(f"TIMEOUT IN {chunk} — CONTINUING")
            return
        for device in parse_discovery(xml):
            address = ipaddress.ip_address(device["ip"])
            if address in network and address not in (network.network_address, network.broadcast_address):
                found[device["ip"]] = device
        usable = sum(address not in (network.network_address, network.broadcast_address) for address in chunk)
        processed += usable
        job.scanned += usable
        update(f"CHECKED {job.scanned}/{total} ADDRESSES — {len(found)} ONLINE")

    for chunk in chunks:
        probe(chunk)
    return list(found.values())


def enrich_names(devices, job, seconds=12):
    """Names are optional; unavailable DNS must never block discovery."""
    unnamed = [device for device in devices if not device.get("name")]
    if not unnamed:
        return
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=12)
    pending = {pool.submit(identify_host, device["ip"], job.cancel): device for device in unnamed}
    deadline = time.monotonic() + seconds
    try:
        while pending:
            check_cancel(job.cancel)
            if time.monotonic() >= deadline:
                break
            done, _ = concurrent.futures.wait(pending, timeout=.15,
                                              return_when=concurrent.futures.FIRST_COMPLETED)
            for future in done:
                device = pending.pop(future)
                device.update(future.result())
    finally:
        for future in pending:
            future.cancel()
        # Each running lookup has its own short timeout; never wait for all
        # remaining names before allowing the next subnet scan.
        pool.shutdown(wait=False, cancel_futures=True)


def scan_network(subnet: str, job: ScanJob) -> None:
    global active_job
    try:
        devices = discover_chunks(validated_network(subnet), job)
        check_cancel(job.cancel)
        with lock:
            if active_job is job and not job.background:
                state.update(progress=85, message="RESOLVING NAMES (MAX 12s)")
        if job.background:
            previous = load_history()
            for device in devices:
                old = previous.get(device["ip"], {})
                if old.get("subnet") == subnet and not device.get("name"):
                    device["name"] = old.get("name", "")
                    device["name_source"] = old.get("name_source", "")
        enrich_names(devices, job)
        check_cancel(job.cancel)
        with lock:
            if active_job is job:
                devices = merged_device_list(subnet, devices, job.unverified)
                missing = sum(device["status"] == "unknown" for device in devices)
                warning = f"{missing} ADDRESSES NOT VERIFIED (TIMEOUT). OTHER RESULTS ARE AVAILABLE." if missing else ""
                state.update(devices=devices, progress=100, finished=int(time.time()),
                             last_presence=int(time.time()), scanned=job.scanned,
                             diagnostic="\n".join(job.diagnostics), warning=warning,
                             monitor_paused=bool(missing),
                             message="SCAN PARTIAL — SOME BLOCKS TIMED OUT" if missing else "SCAN COMPLETE")
    except ScanCancelled:
        with lock:
            if active_job is job:
                state.update(cancelled=True, message="SCAN STOPPED", finished=int(time.time()))
    except Exception as exc:
        with lock:
            if active_job is job:
                state.update(error="Scan could not finish. Results already found are retained; check technical details.",
                             diagnostic=str(exc), monitor_paused=True, message="SCAN FAILED — RETRY", finished=int(time.time()))
    finally:
        with lock:
            if active_job is job:
                active_job = None
                state.update(running=False, stopping=False)


def presence_scan() -> None:
    """Share scan ownership; a manual request supersedes background work."""
    global active_job
    with lock:
        subnet = state["subnet"]
        if not subnet or active_job is not None or state["monitor_paused"]:
            return
        job = ScanJob(subnet, background=True)
        active_job = job
    scan_network(subnet, job)


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
    if values == []:
        return []
    ips = watch_addresses(values)
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(16, len(ips))) as pool:
        return list(pool.map(ping_host, ips))


def detail_scan(ip: str) -> dict:
    address = ipaddress.ip_address(ip)
    with lock:
        subnet = state.get("subnet")
    if address.version != 4 or not subnet or address not in validated_network(subnet):
        raise ValueError("The address must belong to the selected scan range.")
    xml = run(["nmap", "-n", "-Pn", "-sT", "-sV", "--version-light", "-O", "--osscan-limit", "--top-ports", "1000", "-oX", "-", ip], 180)
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

    def end_headers(self):
        if not urllib.parse.urlparse(self.path).path.startswith("/api/"):
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")
        super().end_headers()

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
            if parsed.path == "/api/preferences":
                return self.send_json(user_preferences.read())
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
        if self.path not in ("/api/scan", "/api/scan/stop", "/api/watch", "/api/update", "/api/preferences"):
            return self.send_json({"error": "Not found"}, 404)
        try:
            if self.path == "/api/update":
                if not local_update_request(self.client_address[0], self.headers.get("Origin", ""), self.headers.get("Host", "")):
                    return self.send_json({"error": "Web updates are restricted to this local network."}, 403)
                return self.send_json(schedule_update(self.headers.get("X-Update-Id", "")), 202)
            size = min(int(self.headers.get("Content-Length", "0")), 8192)
            body = json.loads(self.rfile.read(size) or b"{}")
            if not isinstance(body, dict):
                raise ValueError("Expected a JSON object.")
            if self.path == "/api/preferences":
                return self.send_json(user_preferences.update(body))
            if self.path == "/api/scan/stop":
                return self.send_json(stop_scan())
            if self.path == "/api/watch":
                return self.send_json({"results": watch_ips(body.get("ips"))})
            subnet = start_scan(body.get("subnet", ""))
            return self.send_json({"started": True, "subnet": subnet}, 202)
        except (ValueError, OSError) as exc:
            return self.send_json({"error": str(exc)}, 400)


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
