import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location("scanner", Path(__file__).parents[1] / "scanner.py")
scanner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scanner)


def test_parse_discovery_and_vendor(monkeypatch):
    monkeypatch.setattr(scanner, "VENDORS", {"AABBCC": "Example Devices"})
    xml = """<nmaprun><host><status state="up"/><address addr="192.168.1.2" addrtype="ipv4"/><address addr="AA:BB:CC:11:22:33" addrtype="mac"/><hostnames><hostname name="neo.local"/></hostnames></host></nmaprun>"""
    devices = scanner.parse_discovery(xml)
    assert devices[0]["ip"] == "192.168.1.2"
    assert devices[0]["name"] == "neo.local"
    assert devices[0]["manufacturer"] == "Example Devices"


def test_invalid_xml_is_empty():
    assert scanner.parse_discovery("not xml") == []


def test_immediate_watch_validates_and_pings_selected_ips(monkeypatch):
    scanner.state["subnet"] = "192.168.44.0/24"
    monkeypatch.setattr(scanner, "ping_host", lambda ip: {"ip": ip, "online": True, "latency_ms": 1.2})
    result = scanner.watch_ips(["192.168.44.10", "192.168.44.11"])
    assert [item["ip"] for item in result] == ["192.168.44.10", "192.168.44.11"]


def test_immediate_watch_rejects_outside_subnet():
    scanner.state["subnet"] = "192.168.44.0/24"
    try:
        scanner.watch_ips(["192.168.45.10"])
    except ValueError:
        pass
    else:
        raise AssertionError("outside address must be rejected")
