"""OS fingerprint database and scoring.

A fingerprint is scored field by field against a database of known SYN
profiles. Instead of walking every database entry per request, the database is
compiled into a set of index maps at load time:

    index[field][value][os] += weight * n

so scoring one SYN costs one dict lookup per field (plus arithmetic per
operating system), independent of how large the database is. The result per OS
is the *weighted average* similarity over the sessions behind the entries: a
profile seen a million times outweighs a one-off from a laptop.

Field set and weights (max 20.5):

    tcp_options       4.0  (2.5 when only the option order matches)
    tcp_data_offset   2.5
    ip_total_length   2.5
    ip_ttl_initial    2.0
    tcp_window_size   2.0
    tcp_window_scaling 2.0
    tcp_mss           1.5
    ip_id_zero        1.5
    tcp_timestamp     1.0
    tcp_timestamp_echo 1.0
    ip_tos            0.25
    tcp_flags         0.25

`confidence` is the share of the total score the winner holds, and
`coverage` is the share of the theoretically reachable score the SYN got
against the database - low coverage means the SYN is unlike anything known.
"""
import json
import re
import threading
from collections import OrderedDict
from pathlib import Path

import log
import packet
import tcp_opts

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DATABASE = ROOT / 'database' / 'os_fingerprints.json'

DB_FORMAT = 'pof-db/1'

# Scored field -> weight. `tcp_options` is handled by the ordered fallback.
WEIGHTS = OrderedDict((
    ('tcp_data_offset', 2.5),
    ('ip_total_length', 2.5),
    ('ip_ttl_initial', 2.0),
    ('tcp_window_size', 2.0),
    ('tcp_window_scaling', 2.0),
    ('tcp_mss', 1.5),
    ('ip_id_zero', 1.5),
    ('tcp_timestamp', 1.0),
    ('tcp_timestamp_echo', 1.0),
    ('ip_tos', 0.25),
    ('tcp_flags', 0.25),
))
OPTIONS_WEIGHT = 4.0
OPTIONS_ORDERED_WEIGHT = 2.5
MAX_SCORE = round(sum(WEIGHTS.values()) + OPTIONS_WEIGHT, 2)

OS_GROUPS = {'iOS': 'apple', 'Mac OS': 'apple', 'macOS': 'apple',
             'Linux': 'linux', 'Android': 'linux', 'Windows': 'windows'}

# The OS a User-Agent claims. Order matters: iOS before Mac OS because iPhone
# UAs also say "like Mac OS X".
_UA_PATTERNS = (
    (re.compile(r'iPhone|iPad|iPod'), 'iOS'),
    (re.compile(r'Android'), 'Android'),
    (re.compile(r'HarmonyOS|CrOS|Chromebook'), 'Linux'),
    (re.compile(r'Windows'), 'Windows'),
    (re.compile(r'Mac OS X|Macintosh'), 'Mac OS'),
    (re.compile(r'Linux|X11|Ubuntu|Fedora|Debian|BSD'), 'Linux'),
)


def ua_os(user_agent):
    """The OS class a User-Agent advertises, or None."""
    if not user_agent:
        return None
    for pattern, name in _UA_PATTERNS:
        if pattern.search(user_agent):
            return name
    return None


def features(fingerprint):
    """The normalized, comparable view of one SYN."""
    ttl = fingerprint.get('ip_ttl_initial')
    if ttl is None:
        ttl = packet.initial_ttl(fingerprint.get('ip_ttl'))
    options = fingerprint.get('tcp_options') or ''
    timestamp = fingerprint.get('tcp_timestamp')
    echo = fingerprint.get('tcp_timestamp_echo')
    values = {
        'tcp_options': options or None,
        'tcp_options_ordered': tcp_opts.ordered(options) if options else None,
        'tcp_data_offset': fingerprint.get('tcp_data_offset'),
        'ip_total_length': fingerprint.get('ip_total_length'),
        'ip_ttl_initial': ttl,
        'tcp_window_size': fingerprint.get('tcp_window_size'),
        'tcp_window_scaling': fingerprint.get('tcp_window_scaling'),
        'tcp_mss': fingerprint.get('tcp_mss'),
        'ip_id_zero': fingerprint.get('ip_id_zero'),
        'tcp_timestamp': None if timestamp is None else (1 if timestamp else 0),
        'tcp_timestamp_echo': None if echo is None else (1 if echo else 0),
        'ip_tos': fingerprint.get('ip_tos'),
        'tcp_flags': fingerprint.get('tcp_flags'),
    }
    return values


def signature(values):
    """Stable one line description of a normalized fingerprint.

    Two SYNs with the same signature are indistinguishable to this tool, so it
    is what the API returns as `signature` and what repeated classifications
    are cached by.
    """
    return '{}|{}|{}|{}|{}|{}|{}|{}|{}|{}'.format(
        values.get('tcp_options') or '',
        values.get('tcp_window_size'),
        values.get('tcp_window_scaling'),
        values.get('tcp_mss'),
        values.get('ip_ttl_initial'),
        values.get('tcp_data_offset'),
        values.get('ip_total_length'),
        values.get('tcp_flags'),
        values.get('ip_id_zero'),
        values.get('ip_tos'),
    )


def _bump(mapping, key, name, points):
    bucket = mapping.setdefault(key, {})
    bucket[name] = bucket.get(name, 0) + points


class Database:
    """Compiled SYN fingerprint database with per-OS weighted scoring."""

    def __init__(self, path=DEFAULT_DATABASE, cache_size=2048):
        self.path = Path(path) if path else None
        self.entries = []
        self.by_os = {}           # os -> number of entries
        self.sessions = {}        # os -> sessions behind those entries
        self.os_names = []
        self.cache_size = cache_size
        self._index = {}          # field -> value -> os -> weighted sum
        self._ordered = {}        # ordered option string -> os -> weighted sum
        self._exact_options = {}  # option string -> os -> weighted sum
        self._cache = OrderedDict()
        self._lock = threading.Lock()

    # -- loading -------------------------------------------------------------
    def load(self, path=None):
        source = Path(path) if path else self.path
        if source is None or not source.exists():
            log.log('no fingerprint database at {}'.format(source), 'database',
                    level='WARNING')
            log.log('hint: build it from your own pcaps (tools/build_db.py) or '
                    'convert a foreign table (tools/import_db.py)', 'database',
                    level='WARNING')
            self.entries = []
        else:
            with open(source, encoding='utf-8') as handle:
                document = json.load(handle)
            entries = document.get('entries') if isinstance(document, dict) else document
            if not isinstance(entries, list):
                raise ValueError('{}: expected a list of entries'.format(source))
            self.entries = entries
            self.path = source
        self._compile()
        return self

    def _compile(self):
        by_os, sessions = {}, {}
        index, ordered, exact = {}, {}, {}
        for entry in self.entries:
            name = entry.get('os')
            if not name:
                continue
            weight = int(entry.get('n', 1) or 1)
            by_os[name] = by_os.get(name, 0) + 1
            sessions[name] = sessions.get(name, 0) + weight
            option_string = entry.get('tcp_options') or ''
            order_string = entry.get('tcp_options_ordered') or tcp_opts.ordered(option_string)
            # Raw session counts: the weights are applied in score() so that
            # the exact match bonus and the order-only bonus cannot overlap.
            _bump(exact, option_string, name, weight)
            _bump(ordered, order_string, name, weight)
            for field, field_weight in WEIGHTS.items():
                value = entry.get(field)
                if value is None:
                    continue
                _bump(index.setdefault(field, {}), value, name, field_weight * weight)
        self.by_os, self.sessions = by_os, sessions
        self.os_names = sorted(sessions)
        self._index, self._ordered, self._exact_options = index, ordered, exact
        with self._lock:
            self._cache.clear()
        if self.entries:
            log.log('loaded {} fingerprints / {} sessions for {} from {}'.format(
                len(self.entries), sum(sessions.values()),
                ', '.join('{}={}'.format(name, by_os[name]) for name in self.os_names),
                self.path), 'database')
        return self

    @property
    def loaded(self):
        return bool(self.entries)

    # -- scoring -------------------------------------------------------------
    def score(self, values, exclude=None):
        """`({os: average similarity}, reachable score)` for one fingerprint.

        Fields the SYN never carried (`None`) are skipped rather than counted
        as misses, so an unusual or truncated SYN is not punished for them.

        `exclude` is a database entry to score as if it were absent. Only the
        operating system of that entry can have collected points from it, so
        subtracting that share is enough - this is what the leave-one-out self
        test of `tools/check_db.py` measures a table with.
        """
        totals = dict.fromkeys(self.os_names, 0.0)
        if not self.os_names:
            return totals, 0.0
        reachable = 0.0
        for field, field_weight in WEIGHTS.items():
            value = values.get(field)
            if value is None:
                continue
            reachable += field_weight
            for name, points in (self._index.get(field, {}).get(value) or {}).items():
                totals[name] += points
        option_string = values.get('tcp_options')
        if option_string:
            reachable += OPTIONS_WEIGHT
            exact = self._exact_options.get(option_string) or {}
            near = self._ordered.get(values.get('tcp_options_ordered')) or {}
            for name in self.os_names:
                exact_sessions = exact.get(name, 0)
                # Sessions sharing the option *order* but not the values still
                # say a lot, so they earn a smaller bonus on top.
                ordered_sessions = max(0, near.get(name, 0) - exact_sessions)
                totals[name] += (OPTIONS_WEIGHT * exact_sessions
                                 + OPTIONS_ORDERED_WEIGHT * ordered_sessions)
        scores = {}
        sessions = dict(self.sessions)
        if exclude is not None:
            self._subtract(totals, sessions, values, option_string, exclude)
        for name in self.os_names:
            scores[name] = round(max(0.0, totals[name]) / (sessions.get(name) or 1), 2)
        return scores, round(min(reachable, MAX_SCORE), 2)

    def _subtract(self, totals, sessions, values, option_string, entry):
        """Remove one entry's contribution from the totals (leave-one-out)."""
        name = entry.get('os')
        weight = int(entry.get('n', 1) or 1)
        if name not in totals or weight <= 0:
            return
        for field, field_weight in WEIGHTS.items():
            value = entry.get(field)
            if value is not None and value == values.get(field):
                totals[name] -= field_weight * weight
        if option_string:
            excluded_options = entry.get('tcp_options') or ''
            if excluded_options == option_string:
                totals[name] -= OPTIONS_WEIGHT * weight
            elif tcp_opts.ordered(excluded_options) == values.get('tcp_options_ordered'):
                totals[name] -= OPTIONS_ORDERED_WEIGHT * weight
        sessions[name] = max(0, sessions.get(name, 0) - weight)

    def classify(self, fingerprint, exclude=None):
        """Classify one raw fingerprint dict; repeated shapes come from cache.

        With `exclude` the fingerprint is scored as if that entry were not in
        the table (see `score`). Such a query answers differently every time the
        table changes, so it is never cached.
        """
        values = features(fingerprint)
        if exclude is None:
            key = signature(values)
            with self._lock:
                cached = self._cache.get(key)
                if cached is not None:
                    self._cache.move_to_end(key)
                    result = dict(cached)
                    result['cached'] = True
                    return result
        result = self._classify_values(values, exclude)
        if exclude is None:
            with self._lock:
                self._cache[key] = {k: v for k, v in result.items() if k != 'cached'}
                while len(self._cache) > self.cache_size:
                    self._cache.popitem(last=False)
        return result

    def _classify_values(self, values, exclude=None):
        """Answer one normalized fingerprint: no points for anybody, no answer."""
        scores, reachable = self.score(values, exclude)
        base = {'os': None, 'os_group': None, 'score': 0.0, 'scores': {}, 'margin': 0.0,
                'confidence': 0.0, 'coverage': 0.0, 'possible_score': reachable,
                'signature': signature(values), 'max_score': MAX_SCORE,
                'guess_source': 'none'}
        ranked = sorted(scores.items(), key=lambda item: (-item[1], item[0]))
        if not ranked or ranked[0][1] <= 0:
            # Not one field of this SYN is like anything in the table, so the
            # first name in it would be a wild guess rather than a guess.
            return base
        best_name, best = ranked[0]
        second = ranked[1][1] if len(ranked) > 1 else 0.0
        total = sum(scores.values())
        base.update({
            'os': best_name,
            'os_group': OS_GROUPS.get(best_name, best_name.lower()),
            'score': round(best, 2),
            'scores': scores,
            'confidence': round(best / total, 4) if total else 0.0,
            'coverage': round(best / reachable, 4) if reachable else 0.0,
            'margin': round(best - second, 2),
            'guess_source': 'database',
        })
        return base


def load(path=None, cache_size=2048):
    return Database(path=path or DEFAULT_DATABASE, cache_size=cache_size).load()
