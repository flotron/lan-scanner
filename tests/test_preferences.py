import pytest
from preferences import UserPreferences, mac_key, watch_addresses


def test_groups_survive_restart_and_replace_independently(tmp_path):
    path = tmp_path / 'preferences.json'
    store = UserPreferences(path)
    store.update({'kind': 'group', 'name': 'Servers', 'ips': ['192.168.0.2', '192.168.13.8']})
    store.update({'kind': 'group', 'name': 'Printers', 'ips': ['192.168.1.4']})
    store = UserPreferences(path)
    assert store.read()['groups']['Servers'] == ['192.168.0.2', '192.168.13.8']
    store.update({'kind': 'group', 'name': 'Servers', 'ips': ['192.168.0.5']})
    store.update({'kind': 'group', 'name': 'Printers', 'delete': True})
    assert UserPreferences(path).read()['groups'] == {'Servers': ['192.168.0.5']}


def test_alias_follows_mac_not_reused_ip(tmp_path):
    store = UserPreferences(tmp_path / 'preferences.json')
    store.update({'kind': 'alias', 'mac': 'aa-bb-cc-11-22-33', 'name': 'Impresora recepción'})
    aliases = UserPreferences(store.path).read()['aliases']
    changed_ip = {'ip': '192.168.0.20', 'mac': 'AA:BB:CC:11:22:33'}
    reused_ip = {'ip': '192.168.0.2', 'mac': 'AA:BB:CC:44:55:66'}
    assert aliases[mac_key(changed_ip['mac'])] == 'Impresora recepción'
    assert aliases.get(mac_key(reused_ip['mac'])) is None
    store.update({'kind': 'alias', 'mac': changed_ip['mac'], 'name': ''})
    assert not store.read()['aliases']


@pytest.mark.parametrize('mac', ['Unavailable (routed)', '', '00:00:00:00:00:00', 'FF:FF:FF:FF:FF:FF'])
def test_alias_rejects_missing_or_fake_identity(tmp_path, mac):
    with pytest.raises(ValueError):
        UserPreferences(tmp_path / 'preferences.json').update({'kind': 'alias', 'mac': mac, 'name': 'Router'})


@pytest.mark.parametrize('ips', [[], ['192.168.0.1;id'], ['::1'], ['224.0.0.1'], ['0.0.0.0'], ['192.168.0.1'] * 33])
def test_group_rejects_invalid_targets(ips):
    with pytest.raises(ValueError):
        watch_addresses(ips)


def test_invalid_edit_does_not_destroy_saved_group(tmp_path):
    store = UserPreferences(tmp_path / 'preferences.json')
    store.update({'kind': 'group', 'name': 'A', 'ips': ['192.168.0.2']})
    with pytest.raises(ValueError):
        store.update({'kind': 'group', 'name': 'A', 'ips': ['bad-ip']})
    assert store.read()['groups']['A'] == ['192.168.0.2']
