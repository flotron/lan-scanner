"""Persistent user labels and reusable ping selections, independent of scan history."""
import ipaddress
import json
import re
import threading
from pathlib import Path


def mac_key(value):
    value = str(value).strip().upper().replace('-', ':')
    if not re.fullmatch(r'(?:[0-9A-F]{2}:){5}[0-9A-F]{2}', value):
        raise ValueError('A verified MAC address is required to name a device.')
    if value == '00:00:00:00:00:00' or int(value[:2], 16) & 1:
        raise ValueError('A unicast device MAC address is required.')
    return value


def watch_addresses(values):
    if not isinstance(values, list) or not 1 <= len(values) <= 32:
        raise ValueError('Select between 1 and 32 IPv4 addresses.')
    addresses = []
    for value in values:
        address = ipaddress.ip_address(str(value))
        if address.version != 4 or address.is_multicast or address.is_unspecified or str(address) == '255.255.255.255':
            raise ValueError('Use individual IPv4 device addresses.')
        if str(address) not in addresses:
            addresses.append(str(address))
    return addresses


def label(value, allow_empty=False):
    if not isinstance(value, str):
        raise ValueError('The name must be text.')
    value = value.strip()
    if len(value) > 64 or (not value and not allow_empty) or any(ord(c) < 32 for c in value):
        raise ValueError('Use a name of 1–64 characters without control characters.')
    return value


class UserPreferences:
    def __init__(self, path):
        self.path = Path(path)
        self.lock = threading.Lock()

    def _read(self):
        try:
            data = json.loads(self.path.read_text())
            if isinstance(data, dict) and isinstance(data.get('aliases'), dict) and isinstance(data.get('groups'), dict):
                return data
        except FileNotFoundError:
            pass
        return {'aliases': {}, 'groups': {}}

    def read(self):
        with self.lock:
            return self._read()

    def update(self, body):
        with self.lock:
            data = self._read()
            kind = body.get('kind')
            if kind == 'alias':
                key = mac_key(body.get('mac', ''))
                name = label(body.get('name', ''), allow_empty=True)
                if name:
                    data['aliases'][key] = name
                else:
                    data['aliases'].pop(key, None)
            elif kind == 'group':
                name = label(body.get('name', ''))
                if body.get('delete') is True:
                    data['groups'].pop(name, None)
                else:
                    ips = watch_addresses(body.get('ips'))
                    if name not in data['groups'] and len(data['groups']) >= 32:
                        raise ValueError('Up to 32 ping groups can be saved. Delete one first.')
                    data['groups'][name] = ips
            else:
                raise ValueError('Unknown preference type.')
            self.path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self.path.with_suffix('.tmp')
            temporary.write_text(json.dumps(data, ensure_ascii=False), encoding='utf-8')
            temporary.replace(self.path)
            return data
