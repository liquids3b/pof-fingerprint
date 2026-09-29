"""Check a fingerprint table: is it in this format, is it sound, does it work?

    python tools/check_db.py                                     # the shipped table
    python tools/check_db.py --database database/mydb.json

The report answers three questions:

  1. what is it   - this project's `pof-db/1` format, a bare list, or a foreign
                    table (p0f.fp, zardaxt newCleaned.json), in which case the
                    exact tools/import_db.py command that converts it is shown;
  2. is it sound  - unknown fields, option blocks that cannot be on the wire,
                    entries whose own numbers contradict each other, duplicates,
                    impossible values (a TTL that is not a bucket, and so on);
  3. does it work - every entry is classified with itself removed from the table
                    (leave-one-out): accuracy per OS, the confusions that remain
                    and the mean coverage. A table that cannot recognise its own
                    profiles will not recognise live traffic either, and the
                    usual reason is a foreign dialect that was never converted.

Exit code: 0 - no problems, 1 - problems found, 2 - the file could not be read.
"""
import argparse
import json
import sys
from collections import Counter
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
ROOT = TOOLS.parent
for directory in (ROOT / 'src', TOOLS):
    sys.path.insert(0, str(directory))

import build_db   # noqa: E402  (the field list and the entry identity)
import database   # noqa: E402
import log        # noqa: E402
import tcp_opts   # noqa: E402

# Fields an entry may carry: the scored ones, plus the bookkeeping around them.
ALLOWED = set(build_db.SCORED_FIELDS) | {'os', 'n', 'tcp_options_ordered', 'source', 'note'}

# Bytes an option takes on the wire, keyed by the token name without its value.
# `sack` and names like `opt253` have a length the name does not imply, so an
# entry using them is not checked against its own data offset.
OPTION_SIZES = {'eol': 1, 'nop': 1, 'mss': 4, 'ws': 3, 'sackok': 2, 'ts': 10,
                'echo': 6, 'echoreply': 6,
                'partial-order-conn': 3, 'partial-order-svc': 3}

# A TTL is stored bucketed (`packet.initial_ttl`), so anything else is dead.
CHOICES = {'ip_ttl_initial': (32, 64, 128, 255)}
RANGES = {'tcp_data_offset': (5, 15), 'ip_total_length': (40, 65535),
          'tcp_window_size': (0, 65535), 'tcp_window_scaling': (0, 14),
          'tcp_mss': (0, 65535), 'ip_id_zero': (0, 1), 'tcp_timestamp': (0, 1),
          'tcp_timestamp_echo': (0, 1), 'ip_tos': (0, 255), 'tcp_flags': (0, 511)}

# Fields of a zardaxt table; their presence means the file was never converted.
ZARDAXT_FIELDS = ('tcp_off', 'ip_ttl', 'ip_id', 'tcp_timestamp_echo_reply')


def parse_args(argv=None):
    parser = argparse.ArgumentParser(prog='check_db.py', description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--database', default=str(database.DEFAULT_DATABASE),
                        metavar='FILE.json', help='table to check (default: the shipped one)')
    return parser.parse_args(argv)


def option_size(option_string):
    """Bytes of a canonical option string, or None if a token implies none."""
    total = 0
    for token in (option_string or '').split(','):
        token = token.strip()
        if not token:
            continue
        width = OPTION_SIZES.get(token.rstrip('0123456789'))
        if width is None:
            return None
        total += width
    return total


def entries_of(document):
    """The list of entries in a database document, whatever wraps it."""
    return document.get('entries') if isinstance(document, dict) else document


def dialect_of(entries, text=''):
    """The foreign format this file is written in, or None if it is ours."""
    for entry in entries or []:
        if isinstance(entry, dict) and any(field in entry for field in ZARDAXT_FIELDS):
            return 'zardaxt'
    if 'sig =' in text or '[tcp:request]' in text:
        return 'p0f'
    return None


def convert_hint(dialect, path):
    """The import command that turns this file into a table we can serve."""
    return 'python tools/import_db.py --source {} --file {} --out {}.pof.json'.format(
        dialect, path, Path(path).with_suffix(''))


def check_entries(entries):
    """`(problems, coverage)`: what is wrong, and which fields entries carry."""
    problems, coverage = [], Counter()
    for number, entry in enumerate(entries, 1):
        if not isinstance(entry, dict):
            problems.append('entry {}: not an object'.format(number))
            continue
        for field, value in entry.items():
            if field not in ALLOWED:
                problems.append('entry {}: unknown field "{}"'.format(number, field))
            elif value is not None and field in build_db.SCORED_FIELDS:
                coverage[field] += 1
        name = entry.get('os')
        if not isinstance(name, str) or not name.strip():
            problems.append('entry {}: no os name'.format(number))
        weight = entry.get('n', 1)
        if isinstance(weight, bool) or not isinstance(weight, int) or weight < 1:
            problems.append('entry {}: n must be a positive integer, got {!r}'.format(
                number, weight))
        for field, choices in CHOICES.items():
            value = entry.get(field)
            if value is not None and value not in choices:
                problems.append('entry {}: {} = {!r} is not a TTL bucket {}'.format(
                    number, field, value, list(choices)))
        for field, (low, high) in RANGES.items():
            value = entry.get(field)
            if value is None:
                continue
            if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
                problems.append('entry {}: {} = {!r} is outside {}..{}'.format(
                    number, field, value, low, high))
        option_string = entry.get('tcp_options')
        if not option_string:
            continue
        ordered = entry.get('tcp_options_ordered')
        if ordered is not None and ordered != tcp_opts.ordered(option_string):
            problems.append('entry {}: tcp_options_ordered {!r} does not match {!r}'.format(
                number, ordered, tcp_opts.ordered(option_string)))
        size = option_size(option_string)
        if size is None:      # `sack`, `opt253`, ...: the name implies no length
            continue
        if size % 4:
            problems.append('entry {}: {} bytes of options cannot be on the wire'.format(
                number, size))
            continue
        offset = entry.get('tcp_data_offset')
        if offset is not None and offset != 5 + size // 4:
            problems.append('entry {}: tcp_data_offset {} != {} implied by {!r}'.format(
                number, offset, 5 + size // 4, option_string))
        length = entry.get('ip_total_length')
        if length is not None and length != 40 + size:
            problems.append('entry {}: ip_total_length {} != {} implied by {!r}'.format(
                number, length, 40 + size, option_string))
    return problems, coverage


def duplicates(entries):
    """Groups of entries carrying the same profile: their weights belong together."""
    groups = {}
    for number, entry in enumerate(entries, 1):
        if isinstance(entry, dict):
            groups.setdefault(build_db.entry_key(entry), []).append(number)
    return [numbers for numbers in groups.values() if len(numbers) > 1]


def group_of(name):
    """The OS family an entry name belongs to (`database.OS_GROUPS`)."""
    return database.OS_GROUPS.get(name, (name or '').lower())


def self_test(db):
    """Classify every entry with itself excluded; `(per OS, confusions, coverage)`.

    Per OS the tuple is `(exact hits, entries, hits in the same OS group)`: an
    Android SYN answered with Linux (or a Mac OS one answered with iOS) is not
    the failure a Windows answer would be.
    """
    per_os, confusions, coverage = {}, Counter(), []
    for entry in db.entries:
        if not isinstance(entry, dict) or not entry.get('os'):
            continue
        result = db.classify(entry, exclude=entry)
        name, got = entry['os'], result['os']
        hits, total, same_group = per_os.get(name, (0, 0, 0))
        per_os[name] = (hits + (1 if got == name else 0), total + 1,
                        same_group + (1 if group_of(name) == group_of(got) else 0))
        if got != name:
            confusions[(name, got or 'unknown')] += 1
        coverage.append(result['coverage'])
    mean = sum(coverage) / len(coverage) if coverage else 0.0
    return per_os, confusions, mean


def report(path):
    """Print the report for one file; returns the exit code."""
    text = Path(path).read_text(encoding='utf-8', errors='replace')
    try:
        document = json.loads(text)
    except ValueError as err:
        print('file    : {}'.format(path))
        print('format  : not JSON ({})'.format(err))
        dialect = dialect_of(None, text)
        if dialect:
            print('this looks like a {} source file, convert it first:'.format(dialect))
            print('  ' + convert_hint(dialect, path))
            return 1
        return 2
    if isinstance(document, dict):
        entries, declared = entries_of(document) or [], document.get('format') or 'bare list'
    else:
        entries, declared = document or [], 'bare list'
    if not isinstance(entries, list):
        print('file    : {}'.format(path))
        print('format  : this document holds no list of entries')
        return 2

    dialect = dialect_of(entries, text)
    db = database.Database(path).load()
    problems, coverage = ([], Counter()) if dialect else check_entries(entries)
    per_os, confusions, mean_coverage = self_test(db)

    print('file    : {}'.format(path))
    print('format  : {}'.format(declared))
    print('entries : {}, sessions: {}'.format(len(entries), sum(db.sessions.values())))
    if dialect:
        print('dialect : {} table - these are not this project\'s field names, so a run'.format(
            dialect))
        print('          of the service would load every entry and match almost none.')
        print('convert it first, then point --database / config.json at the result:')
        print('  ' + convert_hint(dialect, path))
    print('{:<14}{:>8}{:>12}{:>12}'.format('os', 'entries', 'sessions', 'self test'))
    for name in db.os_names:
        hits, total, _same = per_os.get(name, (0, 0, 0))
        self_cell = '{}/{}'.format(hits, total) if total else '-'
        print('{:<14}{:>8}{:>12}{:>12}'.format(name, db.by_os.get(name, 0),
                                               db.sessions.get(name, 0), self_cell))
    hits = sum(item[0] for item in per_os.values())
    total = sum(item[1] for item in per_os.values())
    group_hits = sum(item[2] for item in per_os.values())
    percent = 100.0 * hits / total if total else 0.0
    print('{:<14}{:>8}{:>12}{:>12}'.format('total', len(entries), '',
                                           '{}/{} ({:.1f}%)'.format(hits, total, percent)))
    if not dialect:
        carried = ['{} {}/{}'.format(field, coverage.get(field, 0), len(entries))
                   for field in build_db.SCORED_FIELDS]
        print('fields  : ' + '  '.join(carried[:6]))
        print('          ' + '  '.join(carried[6:]))
    print('self test: leave-one-out, {}/{} stay in the same OS group, mean coverage {:.2f}'.format(
        group_hits, total, mean_coverage))
    for (expected, got), count in confusions.most_common(5):
        print('   {} -> {} x{}'.format(expected, got, count))
    if dialect:
        return 1
    for numbers in duplicates(entries):
        problems.append('entries {} hold the same profile, they should be one entry'.format(
            ', '.join(str(number) for number in numbers)))
    if problems:
        print('problems ({}):'.format(len(problems)))
        for line in problems[:40]:
            print('  ' + line)
        if len(problems) > 40:
            print('  ... and {} more'.format(len(problems) - 40))
        return 1
    print('problems: none')
    return 0


def main(argv=None):
    args = parse_args(argv)
    log.setup(quiet=True)          # the report is the output, not the startup log
    try:
        return report(args.database)
    except OSError as err:
        print('check_db: cannot read {}: {}'.format(args.database, err), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
