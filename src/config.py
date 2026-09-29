"""Configuration: JSON file, environment variables, command line.

Precedence is command line > environment > file > default, so a systemd unit
can keep the port and interface in flags while the API key stays in the file.
"""
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

DEFAULTS = {
    'api_host': '0.0.0.0',          # reachable from a browser by the server IP;
                                    # use 127.0.0.1 when nginx sets X-Real-IP
    'api_port': 8351,
    'api_key': '',                  # empty: only the query's own IP can be looked up
    'interface': '',                # empty: the interface of the default route
    'max_ips': 50000,
    'per_ip': 3,
    'expire_seconds': 0,            # 0: never expire entries, only evict the oldest
    'bpf': True,                    # filter SYNs in the kernel (needs CAP_NET_RAW)
    'ignore_local_ips': True,       # never fingerprint this host's own connections
    'ignore_private_ips': False,    # skip RFC1918/ULA sources as well
    'database': 'database/os_fingerprints.json',
    'log_dir': 'log',
    'verbose': False,
    'quiet': False,
}

ENV_PREFIX = 'POF_'


def _from_env():
    values = {}
    for name in DEFAULTS:
        raw = os.environ.get(ENV_PREFIX + name.upper())
        if raw is None:
            continue
        default = DEFAULTS[name]
        if isinstance(default, bool):
            values[name] = raw.strip().lower() in ('1', 'true', 'yes', 'on')
        elif isinstance(default, int):
            values[name] = int(raw)
        else:
            values[name] = raw
    return values


def load(path=None, overrides=None):
    """Merge defaults, the JSON file, the environment and `overrides`."""
    config = dict(DEFAULTS)
    source = None
    if path:
        source = Path(path)
    elif (ROOT / 'config.json').exists():
        source = ROOT / 'config.json'
    if source and source.exists():
        with open(source, encoding='utf-8') as handle:
            file_config = json.load(handle)
        unknown = [key for key in file_config if key not in DEFAULTS]
        if unknown:
            raise ValueError('{}: unknown config keys {}'.format(source, unknown))
        config.update(file_config)
    config['loaded_from'] = str(source) if source else None
    config.update(_from_env())
    for key, value in (overrides or {}).items():
        if value is not None:
            config[key] = value
    _verify(config)
    return config


def _verify(config):
    config['api_port'] = int(config['api_port'])
    if not 1 <= config['api_port'] <= 65535:
        raise ValueError('api_port out of range: {}'.format(config['api_port']))
    config['max_ips'] = max(1, int(config['max_ips']))
    config['per_ip'] = max(1, int(config['per_ip']))
    config['expire_seconds'] = max(0, int(config['expire_seconds']))
    config['interface'] = (config.get('interface') or '').strip()
    config['api_key'] = str(config.get('api_key') or '')
    config['database'] = str(config.get('database') or '')
