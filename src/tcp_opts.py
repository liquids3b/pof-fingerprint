"""TCP option decoding and the canonical option string.

A SYN carries at most 40 bytes of TCP options. Their content, their order and
their total length (which shows up in the TCP data offset and the IP total
length) are among the strongest OS hints a passive observer can get.

Options are rendered as a comma separated list of lowercase tokens, so a
Windows 10 SYN looks like::

    mss1460,nop,ws8,nop,nop,sackok
    -> ordered: mnwnns

The `ordered` string is the first letter of every token; two SYNs with the
same ordered string use the same options in the same order but with different
values (segment sizes, window scale), which is still a strong hint.
"""
import struct

# IANA TCP option kinds we know by name.
KIND_NAMES = {
    0: 'eol',
    1: 'nop',
    2: 'mss',
    3: 'ws',
    4: 'sackok',
    5: 'sack',
    6: 'echo',
    7: 'echoreply',
    8: 'ts',
    9: 'partial-order-conn',
    10: 'partial-order-svc',
    11: 'cc',
    12: 'ccnew',
    13: 'ccecho',
    14: 'altsum',
    15: 'altsumdata',
    19: 'md5',
    28: 'usertimeout',
    29: 'tcp-ao',
    30: 'mptcp',
    34: 'fastopen',
}

EOL = 0
NOP = 1
MSS = 2
WSCALE = 3
SACKOK = 4
TIMESTAMP = 8


def decode(raw):
    """Decode option bytes into `(option_string, parsed)`.

    `parsed` carries the values the scoring cares about: `mss`,
    `window_scaling`, `timestamp`, `timestamp_echo`, `sackok`, `length`.
    Malformed options stop the walk instead of raising; a hostile SYN must
    never be able to crash the capture loop.
    """
    raw = bytes(raw or b'')
    tokens = []
    parsed = {
        'mss': None,
        'window_scaling': None,
        'timestamp': None,
        'timestamp_echo': None,
        'sackok': False,
        'length': len(raw),
    }

    index = 0
    while index < len(raw):
        kind = raw[index]
        if kind == EOL:
            # Trailing padding becomes one `eol` token per zero byte, which is
            # what the wire actually shows (Apple pads with two zero bytes).
            tokens.append('eol')
            index += 1
            continue
        if kind == NOP:
            tokens.append('nop')
            index += 1
            continue
        if index + 1 >= len(raw):
            break
        size = raw[index + 1]
        if size < 2 or index + size > len(raw):
            # A truncated or nonsensical option: keep what we have.
            break
        value = raw[index + 2:index + size]
        name = KIND_NAMES.get(kind, 'opt{}'.format(kind))
        if kind == MSS and len(value) >= 2:
            parsed['mss'] = struct.unpack('!H', value[:2])[0]
            tokens.append('mss{}'.format(parsed['mss']))
        elif kind == WSCALE and len(value) >= 1:
            parsed['window_scaling'] = value[0]
            tokens.append('ws{}'.format(parsed['window_scaling']))
        elif kind == TIMESTAMP and len(value) >= 8:
            parsed['timestamp'] = struct.unpack('!I', value[:4])[0]
            parsed['timestamp_echo'] = struct.unpack('!I', value[4:8])[0]
            tokens.append('ts')
        elif kind == SACKOK:
            parsed['sackok'] = True
            tokens.append(name)
        else:
            tokens.append(name)
        index += size

    return ','.join(tokens), parsed


def ordered(option_string):
    """First letter of every token: `mss1460,nop,ws8` -> `mnw`."""
    return ''.join(token[0] for token in option_string.split(',') if token)


def describe(raw):
    """Same as decode(), but only the human readable string."""
    return decode(raw)[0]
