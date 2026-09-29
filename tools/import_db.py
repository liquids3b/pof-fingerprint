"""Import a foreign SYN fingerprint table into the pof-fingerprint format.

Both supported sources are read from a file *you* provide - nothing foreign is
shipped with this project:

  p0f      the `[tcp:request]` section of p0f 3.x's p0f.fp by Michal Zalewski,
           distributed under the GNU LGPL. It is the only public table with
           Apple (macOS / iOS) entries, which is what makes the Apple profiles
           in the shipped database/ possible. Every imported entry keeps a
           `source` field saying where it came from.

  zardaxt  `database/newCleaned.json` of https://github.com/NikolaiT/zardaxt.
           That repository is proprietary ("Unauthorized copying of the source
           code in this repository, via any medium, is strictly prohibited"),
           so its table is deliberately not part of this project - point
           `--file` at your own checkout and the data stays on your machine.

    # Apple profiles of p0f, merged into the shipped table
    python tools/import_db.py --source p0f --file p0f.fp --os apple \
           --out database/os_fingerprints.json --merge

    # your own zardaxt checkout, dropping profiles seen only once
    python tools/import_db.py --source zardaxt --file ../zardaxt/database/newCleaned.json \
           --min-weight 3 --out database/os_fingerprints.json --merge

    # a separate table for --database
    python tools/import_db.py --source p0f --file p0f.fp --out database/p0f.json

Weights: p0f records no traffic counts, so every imported profile gets --weight
sessions (default 1, "one documented profile"). zardaxt records how many
sessions a profile stands for and that count is kept, capped by --max-weight so
that one profile cannot swamp the table.
"""
import argparse
import json
import re
import sys
from collections import Counter, OrderedDict
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
ROOT = TOOLS.parent
for directory in (ROOT / 'src', TOOLS):
    sys.path.insert(0, str(directory))

import build_db   # noqa: E402  shares the writer and the merge rules
import database   # noqa: E402
import packet     # noqa: E402
import tcp_opts   # noqa: E402

# p0f option names -> (our token, bytes on the wire). `eol+n` is handled apart.
P0F_OPTIONS = {'mss': ('mss', 4), 'nop': ('nop', 1), 'ws': ('ws', 3),
               'sok': ('sackok', 2), 'ts': ('ts', 10)}
P0F_OS = {'Windows': 'Windows', 'Linux': 'Linux', 'Android': 'Android', 'iOS': 'iOS',
          'Mac OS X': 'Mac OS', 'MacOS X': 'Mac OS', 'macOS': 'Mac OS',
          'Mac OS': 'Mac OS', 'Darwin': 'Mac OS',
          'FreeBSD': 'BSD', 'OpenBSD': 'BSD', 'NetBSD': 'BSD', 'DragonFly': 'BSD'}
P0F_SOURCE = 'p0f.fp (Michal Zalewski, GNU LGPL)'

# zardaxt option letters -> (our token, bytes on the wire, None = length varies).
# `U<kind>`, zardaxt's spelling for an option it cannot name, is handled apart.
ZARDAXT_OPTIONS = {'M': ('mss', 4), 'N': ('nop', 1), 'W': ('ws', 3), 'S': ('sackok', 2),
                   'T': ('ts', 10), 'E': ('eol', 1), 'K': ('sack', None),
                   'J': ('echo', 6), 'F': ('echoreply', 6),
                   'P': ('partial-order-conn', 3), 'R': ('partial-order-svc', 3)}
ZARDAXT_OS = {'iOS': 'iOS', 'iPadOS': 'iOS', 'Windows': 'Windows', 'Linux': 'Linux',
              'Android': 'Android', 'Mac OS': 'Mac OS', 'Mac OS X': 'Mac OS',
              'macOS': 'Mac OS', 'FreeBSD': 'BSD', 'OpenBSD': 'BSD', 'NetBSD': 'BSD'}
ZARDAXT_SOURCE = 'zardaxt database/newCleaned.json (imported from a local checkout)'

# --os aliases, so `--os apple` means both Apple names.
OS_ALIASES = {'apple': ('ios', 'mac os'), 'mac': ('mac os',), 'macos': ('mac os',),
              'osx': ('mac os',), 'win': ('windows',), 'windows': ('windows',),
              'linux': ('linux',), 'android': ('android',), 'bsd': ('bsd',)}


def parse_args(argv=None):
    parser = argparse.ArgumentParser(prog='import_db.py', description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--source', choices=('p0f', 'zardaxt'), required=True,
                        help='format of --file')
    parser.add_argument('--file', required=True, metavar='FILE',
                        help='p0f.fp or newCleaned.json from your own download/clone')
    parser.add_argument('--out', metavar='FILE.json', help='write the table here')
    parser.add_argument('--merge', action='store_true',
                        help='merge into an existing --out instead of replacing it')
    parser.add_argument('--os', action='append', default=[], metavar='NAME',
                        help='keep this OS only (repeatable, accepts "apple")')
    parser.add_argument('--weight', type=int, default=1,
                        help='sessions per imported p0f profile (default 1)')
    parser.add_argument('--min-weight', type=int, default=1,
                        help='drop imported profiles lighter than this (default 1)')
    parser.add_argument('--max-weight', type=int, default=50,
                        help='cap on the sessions of one imported profile (default 50)')
    parser.add_argument('--generic', action='store_true',
                        help='p0f: also import the broad last-resort ("g:") rules')
    parser.add_argument('--origin', help='origin note written into the output')
    return parser.parse_args(argv)


# -- p0f ---------------------------------------------------------------------
def parse_label(value):
    """`s:unix:Mac OS X:10.x` -> the four parts of a p0f label line."""
    parts = (value.split(':', 3) + ['', '', '', ''])[:4]
    return {'type': parts[0].strip().lower(), 'class': parts[1].strip().lower(),
            'name': parts[2].strip(), 'flavor': parts[3].strip()}


def p0f_os(label):
    """The OS name a p0f label maps to, or None for families we cannot name."""
    if 'Android' in label['name'] or 'Android' in label['flavor']:
        return 'Android'
    return P0F_OS.get(label['name'])


def option_tokens(layout):
    """`[(token, bytes), ...]` for a p0f olayout, or None when unscoreable.

    `sack` and `?n` carry a length this decoder cannot predict from the
    signature alone, so any rule using them is skipped instead of guessed at.
    """
    tokens = []
    for name in layout.split(','):
        name = name.strip()
        if not name:
            continue
        if name.startswith('eol'):
            padding = name[3:].lstrip('+')
            tokens += [('eol', 1)] * (1 + int(padding) if padding.isdigit() else 1)
        elif name in P0F_OPTIONS:
            tokens.append(P0F_OPTIONS[name])
        else:
            return None
    return tokens or None


def window_value(expression, mss):
    """p0f expresses the window as a number, `mss*N`, `mtu*N` or `%N`."""
    expression = (expression or '').strip()
    if expression.isdigit():
        return int(expression)
    if mss and expression.startswith('mss*') and expression[4:].isdigit():
        return mss * int(expression[4:])
    return None


def ttl_value(expression):
    """`64`, `120+8` and `nnn+?` all start with the initial TTL of the sender."""
    head = re.match(r'\d+', (expression or '').strip())
    return packet.initial_ttl(int(head.group())) if head else None


def p0f_entry(label, spec, weight):
    """One `sig = ...` line of `[tcp:request]` as a database entry, or None.

    The layout is `ver:ittl:olen:mss:wsize,scale:olayout:quirks:pclass`; see
    section 5 of the p0f documentation. Fields p0f does not describe (the ToS
    byte, for instance) are left out of the entry, and the scorer skips them
    instead of counting them as a mismatch.
    """
    fields = spec.split(':')
    if len(fields) != 8:
        return None
    version, ittl, olen, mss_field, window_field, layout, quirks, _payload = fields
    if version.strip() not in ('4', '*'):
        return None        # an IPv6 signature says nothing about IPv4 id/flags
    name = p0f_os(label)
    if name is None:
        return None
    mss = int(mss_field) if mss_field.strip().isdigit() else None
    window, scale = (window_field.strip().split(',') + ['*'])[:2]
    scale_value = int(scale) if scale.isdigit() else None
    tokens = option_tokens(layout)
    if tokens is None:
        return None
    size = sum(part[1] for part in tokens)
    if size % 4:
        return None        # cannot be a real SYN header
    # A wildcard MSS or window scale stays a bare token: the profile can still
    # earn the option *order* bonus, but it will never be an exact match.
    pieces = []
    for token, _bytes in tokens:
        if token == 'mss' and mss is not None:
            pieces.append('mss{}'.format(mss))
        elif token == 'ws' and scale_value is not None:
            pieces.append('ws{}'.format(scale_value))
        else:
            pieces.append(token)
    option_string = ','.join(pieces)
    quirks = [quirk.strip() for quirk in quirks.split(',')]
    if 'id-' in quirks:
        ip_id_zero = 1     # "DF not set but IPID is zero"
    elif 'id+' in quirks:
        ip_id_zero = 0     # "DF set but IPID non-zero"
    else:
        ip_id_zero = None
    has_timestamp = 'ts' in [token for token, _bytes in tokens]
    entry = OrderedDict()
    entry['os'] = name
    entry['n'] = max(1, weight)
    entry['tcp_options'] = option_string
    entry['tcp_options_ordered'] = tcp_opts.ordered(option_string)
    entry['tcp_data_offset'] = 5 + size // 4
    entry['ip_total_length'] = 20 + (int(olen) if olen.strip().isdigit() else 0) + 20 + size
    entry['ip_ttl_initial'] = ttl_value(ittl)
    entry['tcp_window_size'] = window_value(window, mss)
    entry['tcp_window_scaling'] = scale_value
    entry['tcp_mss'] = mss
    entry['ip_id_zero'] = ip_id_zero
    entry['tcp_timestamp'] = 1 if has_timestamp else None
    entry['tcp_timestamp_echo'] = 0 if has_timestamp else None
    entry['ip_tos'] = None
    entry['tcp_flags'] = 2
    entry['source'] = P0F_SOURCE
    entry['note'] = 'p0f {}: {}'.format(label['name'], label['flavor'] or '-')
    return entry


def p0f_entries(text, weight=1, generic=False):
    """`(entries, skipped)` for the `[tcp:request]` section of a p0f.fp file."""
    entries, skipped = [], Counter()
    label, section = None, None
    for raw in text.splitlines():
        line = raw.split(';', 1)[0].strip()
        if not line:
            continue
        if line.startswith('['):
            section = line.strip('[]').strip().lower()
            continue
        if section != 'tcp:request' or '=' not in line:
            continue
        key, value = line.split('=', 1)
        key, value = key.strip().lower(), value.strip()
        if key == 'label':
            label = parse_label(value)
        elif key == 'sig' and label is not None:
            if label['type'] == 'g' and not generic:
                skipped['generic rule'] += 1
                continue
            if p0f_os(label) is None:
                skipped['unnamed OS family'] += 1
                continue
            entry = p0f_entry(label, value, weight)
            if entry is None:
                skipped['unsupported signature'] += 1
            else:
                entries.append(entry)
    return entries, skipped


# -- zardaxt -----------------------------------------------------------------
def option_block_size(tcp_off, ip_total_length):
    """Bytes of TCP options implied by the lengths zardaxt recorded, or None.

    `tcp_off` is the TCP data offset in 32 bit words, so the option block is
    `(tcp_off - 5) * 4` bytes; `ip_total_length` says the same, the IPv4 and TCP
    headers being 40 bytes for a SYN without IP options.
    """
    if isinstance(tcp_off, int) and tcp_off >= 5:
        return (tcp_off - 5) * 4
    if isinstance(ip_total_length, int) and ip_total_length >= 40:
        return ip_total_length - 40
    return None


def zardaxt_option_string(options, tcp_off=None, ip_total_length=None):
    """`M1360,N,W6,N,N,T,S,E,E,` -> `(canonical string, bytes)`, or None.

    `M<n>`, `W<n>` and the single letters become this project's tokens, so the
    entry matches what the live decoder produces. Options whose length zardaxt
    does not record (`K`, and `U<kind>` for the ones it cannot name) get the
    room the recorded data offset leaves; a table whose letters and lengths
    disagree is skipped instead of guessed at.
    """
    pieces, sizes = [], []
    for part in options.split(','):
        part = part.strip()
        if not part:
            continue
        if part[0] == 'U':                       # an option zardaxt cannot name
            kind = part[1:]
            if not kind.isdigit():
                return None
            pieces.append(tcp_opts.KIND_NAMES.get(int(kind), 'opt{}'.format(int(kind))))
            sizes.append(None)
            continue
        known = ZARDAXT_OPTIONS.get(part[0])
        if known is None:
            return None
        token, width = known
        value = part[1:]
        if token in ('mss', 'ws'):
            if not value.isdigit():
                return None
            pieces.append(token + value)
        elif value:
            return None
        else:
            pieces.append(token)
        sizes.append(width)
    if not pieces:
        return None
    named = sum(width for width in sizes if width is not None)
    unnamed = sum(1 for width in sizes if width is None)
    recorded = option_block_size(tcp_off, ip_total_length)
    if unnamed:
        if recorded is None or recorded <= named:
            return None
        rest = recorded - named
        if rest % unnamed or rest // unnamed < 2:
            return None
        sizes = [rest // unnamed if width is None else width for width in sizes]
    elif recorded not in (None, named):
        return None                              # letters and lengths disagree
    return ','.join(pieces), sum(sizes)


def zardaxt_entries(records, min_weight=1, max_weight=50):
    """`(entries, skipped)` for the list in a zardaxt `newCleaned.json`.

    Every header field the file lists is carried over; the option string is
    re-rendered in this project's vocabulary (`M1360` -> `mss1360`, `U34` ->
    `fastopen`) and the total length / data offset are recomputed, so an
    imported entry always agrees with the decoder used on live traffic.
    """
    entries, skipped = [], Counter()
    for record in records:
        if not isinstance(record, dict):
            skipped['not an object'] += 1
            continue
        name = ZARDAXT_OS.get(str(record.get('os') or '').strip())
        if name is None:
            skipped['unknown OS name'] += 1
            continue
        parsed = zardaxt_option_string(str(record.get('tcp_options') or ''),
                                       record.get('tcp_off'), record.get('ip_total_length'))
        if parsed is None:
            skipped['unsupported options'] += 1
            continue
        option_string, size = parsed
        if size % 4:
            skipped['impossible option length'] += 1
            continue
        weight = int(record.get('n') or 1)
        if weight < min_weight:
            skipped['too few sessions'] += 1
            continue
        weight = max(1, min(weight, max_weight))
        has_timestamp = any(part.strip().startswith('T') for part in
                            str(record.get('tcp_options') or '').split(','))
        entry = OrderedDict()
        entry['os'] = name
        entry['n'] = weight
        entry['tcp_options'] = option_string
        entry['tcp_options_ordered'] = tcp_opts.ordered(option_string)
        entry['tcp_data_offset'] = 5 + size // 4
        entry['ip_total_length'] = 40 + size
        entry['ip_ttl_initial'] = (packet.initial_ttl(int(record['ip_ttl']))
                                   if str(record.get('ip_ttl') or '').isdigit() else None)
        entry['tcp_window_size'] = record.get('tcp_window_size')
        entry['tcp_window_scaling'] = record.get('tcp_window_scaling')
        entry['tcp_mss'] = record.get('tcp_mss')
        entry['ip_id_zero'] = None if 'ip_id' not in record else (1 if not record['ip_id'] else 0)
        entry['tcp_timestamp'] = 1 if has_timestamp else None
        entry['tcp_timestamp_echo'] = 0 if has_timestamp else None
        entry['ip_tos'] = record.get('ip_tos')
        entry['tcp_flags'] = record.get('tcp_flags') or 2
        entry['source'] = ZARDAXT_SOURCE
        entry['note'] = '{} session(s) in the imported table'.format(record.get('n') or 1)
        entries.append(entry)
    return entries, skipped


# -- shared ------------------------------------------------------------------
def wanted_os(names):
    """Expand `--os` arguments into the set of OS names that stay in the table."""
    wanted = set()
    for name in names:
        wanted.update(OS_ALIASES.get(name.strip().lower(), (name.strip().lower(),)))
    return wanted


def deduplicate(entries):
    """Sum the weights of identical profiles: `(entries, merged count)`."""
    unique = OrderedDict()
    for entry in entries:
        key = build_db.entry_key(entry)
        if key in unique:
            unique[key]['n'] += entry['n']
        else:
            unique[key] = entry
    return list(unique.values()), len(entries) - len(unique)


def print_entries(entries):
    """One line per entry; unknown values (`None`) are shown as a dash."""
    def show(value):
        return '-' if value is None else value
    for entry in sorted(entries, key=lambda item: (item['os'], -item['n'])):
        print('{:>7}  {:<10} ttl={} len={} win={} ws={} mss={} opts={}'.format(
            entry['n'], entry['os'], show(entry['ip_ttl_initial']),
            show(entry['ip_total_length']), show(entry['tcp_window_size']),
            show(entry['tcp_window_scaling']), show(entry['tcp_mss']),
            entry['tcp_options']))


def main(argv=None):
    args = parse_args(argv)
    try:
        text = Path(args.file).read_text(encoding='utf-8', errors='replace')
    except OSError as err:
        print('import_db: cannot read {}: {}'.format(args.file, err), file=sys.stderr)
        return 2

    if args.source == 'p0f':
        entries, skipped = p0f_entries(text, weight=args.weight, generic=args.generic)
    else:
        try:
            document = json.loads(text)
        except ValueError as err:
            print('import_db: {} is not JSON: {}'.format(args.file, err), file=sys.stderr)
            return 2
        records = document if isinstance(document, list) else document.get('entries', [])
        entries, skipped = zardaxt_entries(records, args.min_weight, args.max_weight)

    wanted = wanted_os(args.os)
    if wanted:
        entries = [entry for entry in entries if entry['os'].lower() in wanted]
    entries, duplicates = deduplicate(entries)
    if not entries:
        print('import_db: nothing importable in {} ({})'.format(
            args.file, dict(skipped) or 'no client SYN signatures found'))
        return 1

    print_entries(entries)
    for reason, count in sorted(skipped.items()):
        print('skipped {}: {}'.format(reason, count))
    if duplicates:
        print('merged {} identical profile(s)'.format(duplicates))
    print('{} entries, {} sessions: {}'.format(
        len(entries), sum(entry['n'] for entry in entries),
        ', '.join('{}={}'.format(name, count) for name, count in
                  sorted(Counter(entry['os'] for entry in entries).items()))))

    if not args.out:
        print(json.dumps({'format': database.DB_FORMAT, 'entries': entries}, indent=2))
        return 0
    if args.merge and Path(args.out).exists():
        existing = build_db.load_entries(args.out)
        # sum_weights=False: a second run of the same import adds nothing and
        # leaves the weights of the profiles it already wrote untouched.
        merged, added = build_db.merge(existing, {build_db.entry_key(entry): entry
                                                 for entry in entries},
                                       sum_weights=False)
        entries = merged
        print('merged into {}: {} profiles, {} new'.format(args.out, len(entries), added))
    origin = args.origin or (
        'own hand written profiles plus entries imported by tools/import_db.py from {}; '
        'no proprietary fingerprint table is redistributed here'.format(
            P0F_SOURCE if args.source == 'p0f' else ZARDAXT_SOURCE))
    build_db.save_entries(args.out, entries, origin=origin)
    print('wrote {} entries to {}'.format(len(entries), args.out))
    return 0


if __name__ == '__main__':
    sys.exit(main())
