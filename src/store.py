"""In-memory fingerprints, one small ring per source IP.

The oldest IP is evicted when the table is full, and only the newest `per_ip`
SYNs of an IP are kept. A SYN is a few hundred bytes of dict, so the defaults
(50000 IPs x 3 fingerprints) stay well under 100 MB.
"""
import threading
import time
from collections import OrderedDict

DEFAULT_MAX_IPS = 50000
DEFAULT_PER_IP = 3


class Store:
    def __init__(self, max_ips=DEFAULT_MAX_IPS, per_ip=DEFAULT_PER_IP):
        self.max_ips = max(1, int(max_ips))
        self.per_ip = max(1, int(per_ip))
        self._lock = threading.Lock()
        self._entries = OrderedDict()      # ip -> {'fingerprints': [...], 'count': n}
        self.seen = 0                      # SYNs stored since start

    def put(self, ip, fingerprint):
        """Record one SYN; returns the entry."""
        now = time.time()
        fingerprint = dict(fingerprint)
        fingerprint.setdefault('last_seen', now)
        with self._lock:
            entry = self._entries.get(ip)
            if entry is None:
                entry = {'ip': ip, 'first_seen': fingerprint.get('ts') or now,
                         'last_seen': now, 'count': 0, 'fingerprints': []}
                self._entries[ip] = entry
                while len(self._entries) > self.max_ips:
                    self._entries.popitem(last=False)
            else:
                self._entries.move_to_end(ip)
            entry['last_seen'] = now
            entry['count'] += 1
            entry['fingerprints'].append(fingerprint)
            del entry['fingerprints'][:-self.per_ip]
            self.seen += 1
            return entry

    def get(self, ip):
        """The entry for `ip`, or None. The newest SYN is the last one."""
        with self._lock:
            entry = self._entries.get(ip)
            if entry is None:
                return None
            return {'ip': entry['ip'], 'first_seen': entry['first_seen'],
                    'last_seen': entry['last_seen'], 'count': entry['count'],
                    'fingerprints': list(entry['fingerprints'])}

    def latest(self, ip):
        entry = self.get(ip)
        return entry['fingerprints'][-1] if entry else None

    def snapshot(self, limit=None):
        """All entries with only their newest SYN, oldest first."""
        with self._lock:
            items = list(self._entries.items())
        if limit:
            items = items[-limit:]
        result = []
        for _ip, entry in items:
            result.append({'ip': entry['ip'], 'first_seen': entry['first_seen'],
                           'last_seen': entry['last_seen'], 'count': entry['count'],
                           'fingerprint': entry['fingerprints'][-1]})
        return result

    def cleanup(self, max_age):
        """Drop IPs that have not been seen for `max_age` seconds."""
        if not max_age:
            return 0
        cutoff = time.time() - max_age
        removed = 0
        with self._lock:
            for ip in [ip for ip, entry in self._entries.items() if entry['last_seen'] < cutoff]:
                del self._entries[ip]
                removed += 1
        return removed

    def stats(self):
        with self._lock:
            ips = len(self._entries)
            samples = sum(entry['count'] for entry in self._entries.values())
        return {'ips': ips, 'fingerprints_seen': self.seen, 'fingerprints_kept': samples,
                'max_ips': self.max_ips, 'per_ip': self.per_ip}

    def __len__(self):
        with self._lock:
            return len(self._entries)
