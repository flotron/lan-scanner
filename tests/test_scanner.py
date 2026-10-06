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


def test_saved_watch_works_without_scan_and_across_subnets(monkeypatch):
    monkeypatch.setitem(scanner.state, "subnet", "")
    monkeypatch.setattr(scanner, "ping_host", lambda ip: {"ip": ip, "online": True})
    assert [x["ip"] for x in scanner.watch_ips(["192.168.0.2", "192.168.13.8"])] == ["192.168.0.2", "192.168.13.8"]


def test_update_is_rejected_when_versions_match(monkeypatch, tmp_path):
    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

        def read(self, _size):
            return b"20260811-6\n"

    version_file = tmp_path / "VERSION"
    version_file.write_text("20260811-6\n")
    monkeypatch.setattr(scanner, "VERSION_FILE", version_file)
    monkeypatch.setattr(scanner, "UPDATE_STATUS_FILE", tmp_path / "status.json")
    monkeypatch.setattr(scanner, "DATA_DIR", tmp_path)
    monkeypatch.setattr(scanner, "UPDATE_SCRIPT", Path(__file__).parents[1] / "update.sh")
    monkeypatch.setattr(scanner.shutil, "which", lambda _name: "/usr/bin/systemd-run")
    monkeypatch.setattr(scanner.urllib.request, "urlopen", lambda *_args, **_kwargs: Response())
    monkeypatch.setattr(scanner.subprocess, "run", lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("systemd-run must not execute")))
    scanner.version_cache.update(latest_version="", checked_at=0, error="")

    result = scanner.schedule_update("1723400000000")

    assert result["started"] is False
    assert result["up_to_date"] is True


def test_table_headers_and_cells_use_the_same_order():
    root = Path(__file__).parents[1]
    html = (root / "static/index.html").read_text()
    app = (root / "static/app.js").read_text()
    assert html.index("STATUS") < html.index("IP ADDRESS") < html.index("MAC ADDRESS") < html.index("NAME / LAST CLIENT")

    start = app.index("return `<tr data-ip=")
    row = app[start:app.index("}).join('')", start)]
    status = row.index("${on?'ONLINE':")
    ip = row.index("${esc(d.ip)}", status)
    mac = row.index("${esc(d.mac||'Not recorded')}", ip)
    name = row.index("${esc(d.name||", ip)
    assert status < ip < mac < name


def test_slash23_has_510_addresses_including_internal_endpoints(monkeypatch, tmp_path):
    monkeypatch.setattr(scanner, "DATA_DIR", tmp_path)
    monkeypatch.setattr(scanner, "HISTORY_FILE", tmp_path / 'devices.json')
    devices = scanner.merged_device_list("192.168.0.0/23", [])
    ips = [d['ip'] for d in devices]
    assert len(ips) == 510
    assert ips[0] == '192.168.0.1' and ips[-1] == '192.168.1.254'
    assert '192.168.0.255' in ips and '192.168.1.0' in ips


def test_invalid_range_does_not_poison_active_subnet(monkeypatch):
    import pytest
    monkeypatch.setattr(scanner, 'state', dict(scanner.state, subnet='192.168.0.0/23', running=False))
    monkeypatch.setattr(scanner, 'active_job', None)
    for subnet in ['192.168.0.0/16', '::/64', 'broken', '192.168.0.1/32']:
        with pytest.raises(ValueError):
            scanner.start_scan(subnet)
        assert scanner.state['subnet'] == '192.168.0.0/23'
        assert not scanner.state['running']


def test_stop_terminates_the_real_child_process(monkeypatch):
    import threading
    import time
    import pytest
    actual_popen = scanner.subprocess.Popen
    children = []
    def record(*args, **kwargs):
        child = actual_popen(*args, **kwargs)
        children.append(child)
        return child
    monkeypatch.setattr(scanner.subprocess, 'Popen', record)
    cancel = threading.Event()
    timer = threading.Timer(.15, cancel.set)
    timer.start()
    started = time.monotonic()
    try:
        with pytest.raises(scanner.ScanCancelled):
            scanner.run([scanner.sys.executable, '-c', 'import time; time.sleep(60)'], 30, cancel)
        assert time.monotonic() - started < 2
        assert children[0].poll() is not None
    finally:
        timer.join()


def test_routed_detail_uses_selected_range(monkeypatch):
    monkeypatch.setattr(scanner, 'state', dict(scanner.state, subnet='192.168.0.0/23'))
    commands = []
    monkeypatch.setattr(scanner, 'run', lambda command, *args: commands.append(command) or '<nmaprun/>')
    assert scanner.detail_scan('192.168.1.20')['ports'] == []
    assert '-Pn' in commands[0]


def test_superseded_scan_cannot_overwrite_new_scan(monkeypatch):
    old = scanner.ScanJob('192.168.0.0/23', background=True)
    new = scanner.ScanJob('192.168.100.0/24')
    monkeypatch.setattr(scanner, 'active_job', new)
    monkeypatch.setattr(scanner, 'state', dict(scanner.state, subnet=new.subnet, running=True, devices=[]))
    monkeypatch.setattr(scanner, 'discover_chunks', lambda *args: [])
    monkeypatch.setattr(scanner, 'enrich_names', lambda *args: None)
    monkeypatch.setattr(scanner, 'merged_device_list', lambda *args: (_ for _ in ()).throw(AssertionError('stale write')))
    scanner.scan_network(old.subnet, old)
    assert scanner.active_job is new
    assert scanner.state['subnet'] == new.subnet
    assert scanner.state['running']


def test_http_stop_then_scan_different_subnet(monkeypatch, tmp_path):
    import threading
    import time
    import json
    import urllib.request
    monkeypatch.setattr(scanner, 'DATA_DIR', tmp_path)
    monkeypatch.setattr(scanner, 'HISTORY_FILE', tmp_path / 'devices.json')
    monkeypatch.setattr(scanner, 'active_job', None)
    monkeypatch.setattr(scanner, 'state', dict(scanner.state, running=False, devices=[], subnet='', monitor_paused=False))
    entered = threading.Event()
    commands = []
    def fake_run(command, timeout=30, cancel=None):
        commands.append(command)
        if command[-1].startswith('192.168.0.'):
            entered.set()
            while not cancel.wait(.01):
                pass
            scanner.check_cancel(cancel)
        return '<nmaprun/>'
    monkeypatch.setattr(scanner, 'run', fake_run)
    server = scanner.ThreadingHTTPServer(('127.0.0.1', 0), scanner.Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f'http://127.0.0.1:{server.server_port}'
    def post(path, body=None):
        request = urllib.request.Request(base + path, data=json.dumps(body or {}).encode(), headers={'Content-Type':'application/json'})
        with urllib.request.urlopen(request, timeout=2) as response:
            return json.load(response)
    def await_idle():
        deadline = time.monotonic() + 3
        while scanner.state['running'] or scanner.state['stopping']:
            assert time.monotonic() < deadline
            time.sleep(.01)
    try:
        assert post('/api/scan', {'subnet':'192.168.0.0/23'})['started']
        assert entered.wait(1)
        assert post('/api/scan/stop')['stopping']
        await_idle()
        assert scanner.state['cancelled'] and scanner.state['monitor_paused']
        # A stopped scan must not restart itself via background monitoring.
        scanner.presence_scan()
        assert scanner.active_job is None
        assert post('/api/scan', {'subnet':'192.168.100.0/24'})['started']
        await_idle()
        assert scanner.state['subnet'] == '192.168.100.0/24'
        assert scanner.state['progress'] == 100
        assert len(scanner.state['devices']) == 254
        assert not scanner.state['monitor_paused']
        assert all('-n' in command and '-PS22,80,443,445,3389' in command for command in commands)
    finally:
        scanner.stop_scan()
        server.shutdown()
        server.server_close()
        thread.join(2)


def test_slow_block_retries_smaller_ranges_and_completes(monkeypatch):
    job = scanner.ScanJob('192.168.0.0/23')
    monkeypatch.setattr(scanner, 'active_job', job)
    monkeypatch.setattr(scanner, 'state', dict(scanner.state))
    commands = []
    def fake_run(command, timeout, cancel):
        chunk = command[-1]
        commands.append((chunk, timeout))
        if chunk == '192.168.1.0/26':
            assert timeout == 90
            raise scanner.subprocess.TimeoutExpired(command, timeout)
        ip = str(scanner.ipaddress.ip_network(chunk).network_address + 1)
        return f'<nmaprun><host><status state="up"/><address addr="{ip}" addrtype="ipv4"/></host></nmaprun>'
    monkeypatch.setattr(scanner, 'run', fake_run)
    result = scanner.discover_chunks(scanner.validated_network(job.subnet), job)
    assert job.scanned == 510
    assert not job.unverified
    assert ('192.168.1.0/28', 30) in commands
    assert any(d['ip'] == '192.168.0.1' for d in result)
    assert any(d['ip'] == '192.168.1.193' for d in result)


def test_persistent_timeout_keeps_history_and_marks_unknown(monkeypatch, tmp_path):
    job = scanner.ScanJob('192.168.0.0/23')
    monkeypatch.setattr(scanner, 'active_job', job)
    monkeypatch.setattr(scanner, 'state', dict(scanner.state, running=True))
    monkeypatch.setattr(scanner, 'DATA_DIR', tmp_path)
    monkeypatch.setattr(scanner, 'HISTORY_FILE', tmp_path / 'devices.json')
    old = {'ip':'192.168.1.5','subnet':job.subnet,'name':'Known server','status':'online','missed_checks':0,'last_seen':123}
    scanner.save_history({'192.168.1.5':old})
    def fake_run(command, timeout, cancel):
        if command[-1] in ('192.168.1.0/26', '192.168.1.0/28'):
            raise scanner.subprocess.TimeoutExpired(command, timeout)
        return '<nmaprun/>'
    monkeypatch.setattr(scanner, 'run', fake_run)
    scanner.scan_network(job.subnet, job)
    by_ip = {d['ip']:d for d in scanner.state['devices']}
    assert by_ip['192.168.1.5']['status'] == 'unknown'
    assert by_ip['192.168.1.5']['name'] == 'Known server'
    assert by_ip['192.168.1.5']['last_seen'] == 123
    assert scanner.load_history()['192.168.1.5'] == old
    assert by_ip['192.168.1.20']['status'] == 'offline'
    assert scanner.state['scanned'] == 494
    assert '16 ADDRESSES NOT VERIFIED' in scanner.state['warning']
    assert not scanner.state['running']
    assert scanner.state['monitor_paused']


def test_stop_during_timeout_retry_still_cancels(monkeypatch):
    import pytest
    job = scanner.ScanJob('192.168.0.0/23')
    def fake_run(command, timeout, cancel):
        cancel.set()
        raise scanner.subprocess.TimeoutExpired(command, timeout)
    monkeypatch.setattr(scanner, 'run', fake_run)
    with pytest.raises(scanner.ScanCancelled):
        scanner.discover_chunks(scanner.validated_network(job.subnet), job)
