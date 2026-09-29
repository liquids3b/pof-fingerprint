"""Self test for pof-fingerprint: no network, no root, no dependencies.

Builds SYN packets in memory, wraps them in a pcap file and replays that file
through exactly the code path the live service uses (decode -> store ->
classify), so `python tests/test_pof.py` validates the whole pipeline on any
platform, including Windows.

Run:  python tests/test_pof.py        (or: python -m unittest discover tests)
"""
import contextlib
import http.client
import io
import ipaddress
import json
import os
import struct
import sys
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'src'))
sys.path.insert(0, str(ROOT / 'tools'))

import api          # noqa: E402
import bpf          # noqa: E402
import check_db     # noqa: E402  (tools/check_db.py, the table validator)
import config as config_mod   # noqa: E402
import database     # noqa: E402
import import_db    # noqa: E402  (tools/import_db.py, the table converter)
import log          # noqa: E402
import packet       # noqa: E402
import pcap         # noqa: E402
import pof          # noqa: E402
import store as store_mod     # noqa: E402
import tcp_opts     # noqa: E402

CLIENT = '203.0.113.7'
SERVER = '198.51.100.10'


def syn(source, destination, window, options, ttl=64, ident=0, tos=0, flags=0x02,
        ports=(40000, 443), mss=None, window_scaling=None, timestamp=None):
    """Hand build one Ethernet/IPv4/TCP SYN frame.

    `options` is the raw TCP option bytes; the IP total length and the TCP data
    offset follow from it, exactly like a real sender would compute them.
    """
    def padding():
        while len(options) % 4:
            options.append(0)

    padding()
    tcp_header = struct.pack('!HHIIHHHH', ports[0], ports[1], 1234, 0,
                             ((20 + len(options)) // 4 << 12) | flags,
                             window, 0, 0) + bytes(options)
    total_length = 20 + len(tcp_header)
    ip_header = struct.pack('!BBHHHBBH', 0x45, tos, total_length, ident, 0x4000,
                            ttl, 6, 0) + _pack_ip(source) + _pack_ip(destination)
    ethernet = b'\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00'
    return ethernet + ip_header + tcp_header


def _pack_ip(address):
    return bytes(int(part) for part in address.split('.'))


def opt(*parts):
    """Build option bytes from `(kind, value)` pairs."""
    blob = bytearray()
    for kind, value in parts:
        if kind in (0, 1):
            blob.append(kind)
        else:
            blob += struct.pack('!BB', kind, len(value) + 2) + value
    return blob


def mss(value=1460):
    return (2, struct.pack('!H', value))


def wscale(value):
    return (3, bytes([value]))


def timestamp(value):
    return (8, struct.pack('!II', value, 0))


# Option blobs of the three stacks under test.
WINDOWS_OPTIONS = opt(mss(1460), (1, None), wscale(8), (1, None), (1, None), (4, b''))
LINUX_OPTIONS = opt(mss(1460), (4, b''), timestamp(0x11223344), (1, None), wscale(7))
ANDROID_OPTIONS = opt(mss(1460), (4, b''), timestamp(0x11223344), (1, None), wscale(8))


def windows_syn(**kwargs):
    kwargs.setdefault('window', 65535)
    kwargs.setdefault('ttl', 128)
    return syn(CLIENT, SERVER, options=bytearray(WINDOWS_OPTIONS), **kwargs)


def linux_syn(window=29200, **kwargs):
    kwargs.setdefault('ttl', 64)
    return syn(CLIENT, SERVER, window=window, options=bytearray(LINUX_OPTIONS), **kwargs)


# Apple (iOS / macOS): 24 byte option block, two EOL padding bytes and no SACK,
# classic for a Mac or an iPhone.
APPLE_OPTIONS = opt(mss(1360), (1, None), wscale(6), (1, None), (1, None),
                    timestamp(0x11223344), (4, b''), (0, None), (0, None))


def apple_syn(**kwargs):
    kwargs.setdefault('window', 65535)
    kwargs.setdefault('ttl', 64)
    return syn(CLIENT, SERVER, options=bytearray(APPLE_OPTIONS), **kwargs)


def run_bpf(program, frame):
    """A tiny interpreter for the instruction set `bpf.py` emits.

    Enough to prove the filter accepts SYNs and rejects everything else without
    needing root: same semantics as the kernel implementation for these
    instructions (big endian loads, unsigned 32 bit accumulator).
    """
    instructions = program.assemble()
    accumulator = 0
    index_register = 0
    pc = 0
    while pc < len(instructions):
        code, jt, jf, k = instructions[pc]
        if code == 0x28:                       # BPF_LD | BPF_H | BPF_ABS
            accumulator = struct.unpack('!H', frame[k:k + 2])[0]
        elif code == 0x30:                     # BPF_LD | BPF_B | BPF_ABS
            accumulator = frame[k]
        elif code == 0xB1:                     # BPF_LDX | BPF_B | BPF_MSH
            index_register = (frame[k] & 0x0F) * 4
        elif code == 0x50:                     # BPF_LD | BPF_B | BPF_IND
            accumulator = frame[index_register + k]
        elif code == 0x54:                     # BPF_ALU | BPF_AND | BPF_IMM
            accumulator &= k
        elif code == 0x15:                     # BPF_JMP | BPF_JEQ | BPF_IMM
            pc += jt if accumulator == k else jf
        elif code == 0x06:                     # BPF_RET | BPF_IMM
            return k
        else:
            raise AssertionError('unexpected opcode {:#x}'.format(code))
        pc += 1
    raise AssertionError('filter ran off the end without returning')


def ipv6_syn(source='2001:db8::1', destination='2001:db8::2', flags=0x02, next_header=6):
    """Ethernet + IPv6 + TCP SYN with the same Linux option blob."""
    options = bytearray(LINUX_OPTIONS)
    while len(options) % 4:
        options.append(0)
    tcp_header = struct.pack('!HHIIHHHH', 40000, 443, 7, 0,
                             ((20 + len(options)) // 4 << 12) | flags, 29200, 0, 0) + bytes(options)
    ipv6_header = struct.pack('!IHBB', 6 << 28, len(tcp_header), next_header, 64) \
        + ipaddress.IPv6Address(source).packed + ipaddress.IPv6Address(destination).packed
    ethernet = b'\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x86\xdd'
    return ethernet + ipv6_header + tcp_header


def udp_frame():
    """Ethernet + IPv4 + UDP: the filter must drop this."""
    payload = struct.pack('!HHHH', 5353, 5353, 8, 0)
    ip_header = struct.pack('!BBHHHBBH', 0x45, 0, 20 + len(payload), 1, 0, 64, 17, 0) \
        + _pack_ip(CLIENT) + _pack_ip(SERVER)
    ethernet = b'\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00'
    return ethernet + ip_header + payload


def run_cli(argv):
    """Run pof.main() with stdout captured, so the test log stays readable."""
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        code = pof.main(argv)
    return code, buffer.getvalue()


class TestOptionDecoding(unittest.TestCase):
    def test_windows_option_block(self):
        text, parsed = tcp_opts.decode(WINDOWS_OPTIONS)
        self.assertEqual(text, 'mss1460,nop,ws8,nop,nop,sackok')
        self.assertEqual(tcp_opts.ordered(text), 'mnwnns')
        self.assertEqual(parsed['mss'], 1460)
        self.assertEqual(parsed['window_scaling'], 8)
        self.assertIsNone(parsed['timestamp'])
        self.assertTrue(parsed['sackok'])
        self.assertEqual(parsed['length'], 12)

    def test_linux_option_block(self):
        text, parsed = tcp_opts.decode(LINUX_OPTIONS)
        self.assertEqual(text, 'mss1460,sackok,ts,nop,ws7')
        self.assertEqual(tcp_opts.ordered(text), 'mstnw')
        self.assertEqual(parsed['window_scaling'], 7)
        self.assertEqual(parsed['timestamp_echo'], 0)
        self.assertEqual(parsed['length'], 20)

    def test_empty_and_truncated_options(self):
        self.assertEqual(tcp_opts.decode(b''), ('', {
            'mss': None, 'window_scaling': None, 'timestamp': None,
            'timestamp_echo': None, 'sackok': False, 'length': 0}))
        # kind=2 (mss) with a bogus length byte: the walk stops, nothing raises.
        text, parsed = tcp_opts.decode(bytes([2, 99, 1, 1]))
        self.assertEqual(text, '')
        self.assertIsNone(parsed['mss'])

    def test_eol_padding_is_visible(self):
        text, _parsed = tcp_opts.decode(bytes([1, 0, 0]))
        self.assertEqual(text, 'nop,eol,eol')


class TestPacketParsing(unittest.TestCase):
    def test_windows_syn_fields(self):
        fingerprint = packet.decode_frame(windows_syn(), 1.5)
        self.assertEqual(fingerprint['ip_src'], CLIENT)
        self.assertEqual(fingerprint['ip_dst'], SERVER)
        self.assertEqual(fingerprint['ip_total_length'], 52)
        self.assertEqual(fingerprint['tcp_data_offset'], 8)
        self.assertEqual(fingerprint['tcp_window_size'], 65535)
        self.assertEqual(fingerprint['ip_ttl'], 128)
        self.assertEqual(fingerprint['ip_ttl_initial'], 128)
        self.assertEqual(fingerprint['ip_id_zero'], 1)
        self.assertEqual(fingerprint['tcp_options'], 'mss1460,nop,ws8,nop,nop,sackok')

    def test_linux_syn_is_a_client_syn(self):
        fingerprint = packet.decode_frame(linux_syn(), 2.0)
        self.assertTrue(packet.is_client_syn(fingerprint))
        self.assertEqual(fingerprint['ip_total_length'], 60)
        self.assertEqual(fingerprint['tcp_timestamp_echo'], 0)

    def test_syn_ack_is_not_a_client_syn(self):
        frame = linux_syn(flags=0x12)
        fingerprint = packet.decode_frame(frame, 3.0)
        self.assertFalse(packet.is_client_syn(fingerprint))

    def test_ipv6_syn(self):
        fingerprint = packet.decode_frame(ipv6_syn(), 4.0)
        self.assertEqual(fingerprint['ip_version'], 6)
        self.assertEqual(fingerprint['ip_src'], '2001:db8::1')
        self.assertEqual(fingerprint['ip_ttl'], 64)
        self.assertIsNone(fingerprint['ip_id_zero'])
        self.assertTrue(packet.is_client_syn(fingerprint))

    def test_ipv4_mapped_addresses_are_normalized(self):
        self.assertEqual(packet.normalize_ip('::ffff:203.0.113.7'), '203.0.113.7')
        self.assertEqual(packet.normalize_ip('2001:db8::1'), '2001:db8::1')
        self.assertIsNone(packet.normalize_ip(None))

    def test_garbage_is_rejected(self):
        for frame in (b'', b'\x00' * 20, b'\xff' * 60, udp_frame(), ipv6_syn(next_header=17)):
            self.assertIsNone(packet.decode_frame(frame, 5.0), 'accepted: {!r}'.format(frame[:20]))

    def test_ttl_buckets(self):
        self.assertEqual(packet.initial_ttl(63), 64)
        self.assertEqual(packet.initial_ttl(1), 32)
        self.assertEqual(packet.initial_ttl(64), 64)
        self.assertEqual(packet.initial_ttl(100), 128)
        self.assertEqual(packet.initial_ttl(200), 255)
        self.assertIsNone(packet.initial_ttl(None))


class TestBpfFilter(unittest.TestCase):
    """The SYN filter is checked with the interpreter in run_bpf()."""

    ACCEPT = bpf.ACCEPT
    DROP = bpf.DROP

    def test_program_shape(self):
        program = bpf.syn_only_program().assemble()
        self.assertGreaterEqual(len(program), 10)
        codes = [instruction[0] for instruction in program]
        self.assertIn(0xB1, codes, 'the IPv4 header length is never loaded into X')
        self.assertEqual(codes.count(0x06), 2, 'expected exactly one accept and one drop')
        # First instructions encode "ethertype == IPv4 -> ipv4".
        self.assertEqual(program[0], (0x28, 0, 0, 12))
        self.assertEqual(program[1], (0x15, program[1][1], program[1][2], 0x0800))
        self.assertLessEqual(program[1][1], 255)

    def test_serialization_matches_struct_sock_filter(self):
        blob = bpf.syn_only_program().ser()
        self.assertEqual(len(blob), 8 * len(bpf.syn_only_program().assemble()))
        self.assertEqual(blob[:8], struct.pack('HBBI', 0x28, 0, 0, 12))

    def test_tcp_flags_are_loaded_at_the_right_offset(self):
        # BPF_MSH yields the IPv4 header length only, so the indirect load has
        # to add the link layer header itself: 14 + 13 = 27.
        program = bpf.syn_only_program().assemble()
        indirect = [instruction for instruction in program if instruction[0] == 0x50]
        self.assertEqual(len(indirect), 1)
        self.assertEqual(indirect[0][3], bpf.ETH_HEADER + bpf.TCP_FLAGS_OFFSET)

    def test_accepts_client_syns(self):
        program = bpf.syn_only_program()
        self.assertEqual(run_bpf(program, linux_syn()), self.ACCEPT)
        self.assertEqual(run_bpf(program, windows_syn(ttl=128)), self.ACCEPT)
        self.assertEqual(run_bpf(program, ipv6_syn()), self.ACCEPT)
        # A SYN with an IPv4 header option block still has to be found.
        self.assertEqual(run_bpf(program, linux_syn(tos=0x10)), self.ACCEPT)

    def test_rejects_everything_else(self):
        program = bpf.syn_only_program()
        self.assertEqual(run_bpf(program, linux_syn(flags=0x12)), self.DROP)   # SYN|ACK
        self.assertEqual(run_bpf(program, linux_syn(flags=0x10)), self.DROP)   # ACK
        self.assertEqual(run_bpf(program, linux_syn(flags=0x04)), self.DROP)   # RST
        self.assertEqual(run_bpf(program, udp_frame()), self.DROP)
        self.assertEqual(run_bpf(program, ipv6_syn(next_header=17)), self.DROP)
        self.assertEqual(run_bpf(program, b'\xff' * 60), self.DROP)

    def test_ecn_syn_is_accepted(self):
        # ECE|CWR|SYN is still a connection attempt and must be fingerprinted.
        self.assertEqual(run_bpf(bpf.syn_only_program(),
                                 linux_syn(flags=0xC2, tos=2)), self.ACCEPT)


DB_PATH = ROOT / 'database' / 'os_fingerprints.json'


class TestScoring(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.db = database.Database(DB_PATH).load()

    def classify(self, frame):
        return self.db.classify(packet.decode_frame(frame, 1.0))

    def test_database_is_sane(self):
        self.assertTrue(self.db.loaded)
        self.assertEqual(database.MAX_SCORE, 20.5)
        option_sizes = {'mss': 4, 'ws': 3, 'nop': 1, 'eol': 1, 'sackok': 2, 'ts': 10}
        for entry in self.db.entries:
            self.assertIn(entry['os'], self.db.os_names)
            self.assertGreaterEqual(entry.get('n', 1), 1)
            # The option block size must explain the data offset and the IP
            # total length, otherwise the table contradicts itself.
            size = sum(option_sizes[token.rstrip('0123456789')]
                       for token in entry['tcp_options'].split(','))
            self.assertEqual(size % 4, 0, entry['tcp_options'])
            self.assertEqual(entry['tcp_data_offset'], 5 + size // 4, entry['tcp_options'])
            self.assertEqual(entry['ip_total_length'], 20 + 20 + size, entry['tcp_options'])
            self.assertEqual(entry.get('tcp_options_ordered')
                             or tcp_opts.ordered(entry['tcp_options']),
                             tcp_opts.ordered(entry['tcp_options']))

    def test_windows_client(self):
        result = self.classify(windows_syn())
        self.assertEqual(result['os'], 'Windows')
        self.assertEqual(result['os_group'], 'windows')
        self.assertEqual(result['possible_score'], 18.5)  # no timestamp options
        self.assertGreater(result['coverage'], 0.8)
        self.assertGreater(result['margin'], 5)
        self.assertEqual(result['guess_source'], 'database')

    def test_linux_client(self):
        result = self.classify(linux_syn())
        self.assertEqual(result['os'], 'Linux')
        self.assertEqual(result['possible_score'], 20.5)
        self.assertGreater(result['coverage'], 0.8)

    def test_android_client(self):
        result = self.classify(syn(CLIENT, SERVER, 65535, bytearray(ANDROID_OPTIONS)))
        self.assertEqual(result['os'], 'Android')
        self.assertGreater(result['coverage'], 0.8)
        # Linux shares the layout, so it must still score lower.
        self.assertLess(result['scores']['Linux'], result['scores']['Android'])

    def test_apple_client(self):
        result = self.classify(apple_syn())
        # Which Apple name wins depends on the window scale in the SYN, so the
        # stable answer is the group; both names are Apple.
        self.assertEqual(result['os_group'], 'apple')
        self.assertIn(result['os'], ('iOS', 'Mac OS'))
        self.assertGreater(result['coverage'], 0.6)
        self.assertEqual(result['signature'].split('|')[0],
                         'mss1360,nop,ws6,nop,nop,ts,sackok,eol,eol')

    def test_imported_apple_profiles_do_not_outscore_the_other_stacks(self):
        # Apple is covered by a handful of nearly identical profiles and an OS
        # score is the *average* over its sessions, which makes a small, tight
        # group score high. It must still lose on Linux and Windows traffic.
        for frame, expected in ((linux_syn(), 'Linux'), (windows_syn(), 'Windows')):
            result = self.classify(frame)
            self.assertEqual(result['os'], expected)
            for name in ('iOS', 'Mac OS'):
                self.assertLess(result['scores'].get(name, 0.0), result['score'], name)

    def test_unusual_window_lowers_coverage(self):
        result = self.classify(linux_syn(window=4000))
        self.assertLess(result['coverage'], 0.95)
        self.assertEqual(result['os'], 'Linux')

    def test_ecn_client(self):
        result = self.classify(linux_syn(window=64240, flags=0xC2, tos=2))
        self.assertEqual(result['os'], 'Linux')
        self.assertGreater(result['coverage'], 0.85)
        # The ToS byte alone cannot outweigh the shared option layout.
        self.assertLess(result['scores']['Android'], result['scores']['Linux'])

    def test_ttl_is_bucketed_so_hops_do_not_matter(self):
        far_away = self.classify(linux_syn(ttl=52))     # 12 hops from a TTL 64 host
        near = self.classify(linux_syn(ttl=64))
        self.assertEqual(far_away['os'], near['os'])
        self.assertEqual(far_away['scores']['Linux'], near['scores']['Linux'])

    def test_repeated_classification_uses_the_cache(self):
        first = self.classify(linux_syn(window=33333))
        second = self.classify(linux_syn(window=33333))
        self.assertNotIn('cached', first)
        self.assertTrue(second['cached'])
        self.assertEqual(first['scores'], second['scores'])

    def test_empty_database_returns_no_guess(self):
        empty = database.Database(path=None)
        result = empty.classify(packet.decode_frame(linux_syn(), 1.0))
        self.assertIsNone(result['os'])
        self.assertEqual(result['guess_source'], 'none')
        self.assertEqual(result['confidence'], 0.0)

    @staticmethod
    def entry_for(frame, name, count=1, **changes):
        """The table entry for one SYN, as tools/build_db.py would write it."""
        values = database.features(packet.decode_frame(frame, 1.0))
        values.update(changes)
        entry = {'os': name, 'n': count}
        entry.update(values)
        return entry

    def table(self, entries):
        """Load a one-off table from a temporary file, like a local table."""
        directory = tempfile.mkdtemp(prefix='pof-table-')
        path = os.path.join(directory, 'table.json')
        with open(path, 'w', encoding='utf-8') as handle:
            json.dump({'format': database.DB_FORMAT, 'entries': entries}, handle)
        self.addCleanup(os.rmdir, directory)      # run after the unlink below
        self.addCleanup(os.unlink, path)
        return database.Database(path).load()

    def test_a_table_that_explains_nothing_is_not_a_guess(self):
        # Not the TTL, the window, the flags, the MSS or the options of this SYN
        # are like the one profile in the table, so there is nothing to award.
        db = self.table([self.entry_for(windows_syn(), 'Windows', tcp_mss=1360)])
        result = db.classify(packet.decode_frame(
            linux_syn(window=1234, ttl=32, tos=7, ident=5, flags=0x12), 1.0))
        self.assertIsNone(result['os'])
        self.assertEqual(result['score'], 0.0)
        self.assertEqual(result['guess_source'], 'none')
        # 20.5 points were reachable, the table just earned none of them.
        self.assertEqual(result['possible_score'], database.MAX_SCORE)

    def test_leave_one_out_takes_the_evidence_back_out(self):
        # This is what the self test of tools/check_db.py does: score an entry as
        # if it were not in the table.
        # The Windows profile is unlike the SYN scored below in every single
        # field, so once the Linux entry is gone the table explains nothing.
        windows = self.entry_for(windows_syn(), 'Windows', tcp_mss=1360,
                                 ip_tos=8, tcp_flags=0x12, ip_id_zero=0)
        db = self.table([self.entry_for(linux_syn(), 'Linux'), windows])
        frame = packet.decode_frame(linux_syn(), 1.0)
        plain = db.classify(frame)
        self.assertEqual(plain['os'], 'Linux')
        self.assertGreater(plain['score'], 0.0)
        without = db.classify(frame, exclude=db.entries[0])
        self.assertIsNone(without['os'])                 # no Linux profile is left
        self.assertEqual(without['score'], 0.0)
        self.assertEqual(without['confidence'], 0.0)
        self.assertEqual(without['guess_source'], 'none')
        # Such a query answers differently every time the table changes, so it
        # must never be served from the cache - while the plain one is.
        self.assertNotIn('cached', without)
        self.assertTrue(db.classify(frame)['cached'])

    def test_leave_one_out_moves_only_the_excluded_operating_system(self):
        db = self.table([self.entry_for(linux_syn(), 'Linux'),
                         self.entry_for(linux_syn(window=4000), 'Linux'),
                         self.entry_for(windows_syn(), 'Windows')])
        frame = packet.decode_frame(linux_syn(), 1.0)
        plain = db.classify(frame)
        without = db.classify(frame, exclude=db.entries[0])
        self.assertEqual(without['os'], 'Linux')      # the second profile still fits
        self.assertLess(without['scores']['Linux'], plain['scores']['Linux'])
        self.assertEqual(without['scores']['Windows'], plain['scores']['Windows'])
        self.assertEqual(without['possible_score'], plain['possible_score'])

    def test_user_agent_mapping(self):
        self.assertEqual(database.ua_os('Mozilla/5.0 (Windows NT 10.0; Win64) Firefox'),
                         'Windows')
        self.assertEqual(database.ua_os('Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 ...)'),
                         'iOS')
        self.assertIsNone(database.ua_os(None))
        self.assertIsNone(database.ua_os('curl/8.4.0'))


# A slice of p0f.fp and a slice of zardaxt's newCleaned.json, written from the
# published format documentation of both projects. They stand in for the real
# files so the converter is covered without shipping anybody else's data.
P0F_SAMPLE = """
classes = win,unix,other

[mtu]
label = Ethernet or modem
sig   = 1500

[tcp:request]
label = g:unix:Mac OS X:
sig   = *:64:0:*:65535,*:mss,nop,ws,nop,nop,ts,sok,eol+1:df,id+:0

label = s:unix:Mac OS X:10.x
sig   = *:64:0:*:65535,1:mss,nop,ws,nop,nop,ts,sok,eol+1:df,id+:0

label = s:unix:iOS:iPhone or iPad
sig   = *:64:0:*:65535,2:mss,nop,ws,nop,nop,ts,sok,eol+1:df,id+:0

label = s:unix:Linux:3.11 and newer
sig   = *:64:0:*:mss*20,10:mss,sok,ts,nop,ws:df,id+:0

label = s:win:Windows:7 or 8
sig   = *:128:0:*:8192,8:mss,nop,ws,nop,nop,sok:df,id+:0

label = s:other:Cisco:router
sig   = *:255:0:*:4128,0:mss,nop,ws,nop,nop,sok:df,id-:0
"""

ZARDAXT_SAMPLE = [
    {'tcp_options': 'M1360,N,W6,N,N,T,S,E,E,', 'tcp_options_ordered': 'MNWNNTSEE',
     'ip_total_length': 64, 'tcp_off': 11, 'tcp_window_scaling': 6,
     'tcp_window_size': 65535, 'ip_ttl': 64, 'ip_id': 0, 'tcp_timestamp': 1,
     'tcp_timestamp_echo_reply': 0, 'tcp_mss': 1360, 'tcp_flags': 2, 'ip_tos': 0,
     'os': 'iOS', 'n': 6},
    {'tcp_options': 'M1460,N,W8,N,N,S,', 'tcp_options_ordered': 'MNWNNS',
     'ip_total_length': 52, 'tcp_off': 8, 'tcp_window_scaling': 8,
     'tcp_window_size': 65535, 'ip_ttl': 128, 'ip_id': 1, 'tcp_timestamp': 0,
     'tcp_timestamp_echo_reply': 0, 'tcp_mss': 1460, 'tcp_flags': 2, 'ip_tos': 0,
     'os': 'Windows', 'n': 1},
    {'tcp_options': 'M1412,S,T,N,W8,', 'tcp_options_ordered': 'MSTNW',
     'ip_total_length': 60, 'tcp_off': 10, 'tcp_window_scaling': 8,
     'tcp_window_size': 65535, 'ip_ttl': 64, 'ip_id': 1, 'tcp_timestamp': 1,
     'tcp_timestamp_echo_reply': 0, 'tcp_mss': 1412, 'tcp_flags': 2, 'ip_tos': 0,
     'os': 'Linux', 'n': 4},
]


# zardaxt spells the options it has no name for as `U<kind>` and records no
# length for those (as for `K`, SACK), so the data offset next to them has to
# settle the size. The last two records contradict themselves and must be
# skipped rather than guessed at.
ZARDAXT_ODD = [
    {'tcp_options': 'M1460,N,U34,E,', 'tcp_off': 7, 'ip_total_length': 48,
     'tcp_window_size': 65535, 'ip_ttl': 64, 'ip_id': 1, 'tcp_mss': 1460,
     'tcp_flags': 2, 'ip_tos': 0, 'os': 'Linux', 'n': 3},
    {'tcp_options': 'M1460,N,S,K,E,E,E,', 'tcp_off': 10, 'ip_total_length': 60,
     'tcp_window_size': 65535, 'ip_ttl': 64, 'ip_id': 0, 'tcp_mss': 1460,
     'tcp_flags': 2, 'ip_tos': 0, 'os': 'Windows', 'n': 2},
    {'tcp_options': 'M1460,U253,E,E,', 'tcp_off': 11, 'ip_total_length': 64,
     'tcp_window_size': 65535, 'ip_ttl': 64, 'ip_id': 0, 'tcp_mss': 1460,
     'tcp_flags': 2, 'ip_tos': 0, 'os': 'Linux', 'n': 1},
    {'tcp_options': 'M1460,N,W8,N,N,S,', 'tcp_off': 12, 'ip_total_length': 68,
     'tcp_window_size': 65535, 'ip_ttl': 128, 'ip_id': 0, 'tcp_mss': 1460,
     'tcp_flags': 2, 'ip_tos': 0, 'os': 'Windows', 'n': 9},
    {'tcp_options': 'M1460,Q,E,', 'tcp_off': 8, 'ip_total_length': 52,
     'tcp_window_size': 65535, 'ip_ttl': 64, 'ip_id': 0, 'tcp_mss': 1460,
     'tcp_flags': 2, 'ip_tos': 0, 'os': 'Linux', 'n': 5},
]


def run_import(argv):
    """Run tools/import_db.py in process, with both streams captured."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = import_db.main(argv)
    return code, out.getvalue()


class TestImporter(unittest.TestCase):
    """tools/import_db.py converts a foreign table into this format."""

    def setUp(self):
        self.directory = tempfile.mkdtemp(prefix='pof-import-')
        self.p0f = self.write('p0f.fp', P0F_SAMPLE)
        self.zardaxt = self.write('newCleaned.json', json.dumps(ZARDAXT_SAMPLE))

    def tearDown(self):
        for name in os.listdir(self.directory):
            os.unlink(os.path.join(self.directory, name))
        os.rmdir(self.directory)

    def path(self, name):
        return os.path.join(self.directory, name)

    def write(self, name, text):
        with open(self.path(name), 'w', encoding='utf-8') as handle:
            handle.write(text)
        return self.path(name)

    def entries_of(self, path):
        with open(path, encoding='utf-8') as handle:
            document = json.load(handle)
        self.assertEqual(document['format'], database.DB_FORMAT)
        return document['entries']

    def by_os(self, path):
        return {entry['os']: entry for entry in self.entries_of(path)}

    def test_p0f_profiles(self):
        out = self.path('p0f.json')
        code, text = run_import(['--source', 'p0f', '--file', self.p0f, '--out', out])
        self.assertEqual(code, 0)
        entries = self.by_os(out)
        # Apple comes in; the Cisco router is a family this tool cannot name and
        # the generic "g:" catch-all is skipped unless --generic is passed.
        self.assertEqual(sorted(entries), ['Linux', 'Mac OS', 'Windows', 'iOS'])
        self.assertIn('generic rule: 1', text)
        self.assertIn('unnamed OS family: 1', text)
        apple = entries['Mac OS']
        self.assertEqual(apple['tcp_options'], 'mss,nop,ws1,nop,nop,ts,sackok,eol,eol')
        self.assertEqual(apple['tcp_options_ordered'], 'mnwnntsee')
        self.assertEqual(apple['tcp_data_offset'], 11)     # a 24 byte option block
        self.assertEqual(apple['ip_total_length'], 64)
        self.assertEqual(apple['tcp_window_size'], 65535)
        self.assertIsNone(apple['tcp_mss'])                # p0f says "mss*": unknown
        self.assertEqual(apple['ip_id_zero'], 0)           # "df,id+": IPID non-zero
        self.assertEqual(apple['tcp_timestamp'], 1)
        self.assertEqual(apple['source'], import_db.P0F_SOURCE)
        # That Linux rule derives its window from the MSS, which is a wildcard,
        # so the entry says "unknown" instead of inventing a number.
        self.assertIsNone(entries['Linux']['tcp_window_size'])
        # --os apple keeps both Apple names and nothing else.
        filtered = self.path('apple.json')
        code, _text = run_import(['--source', 'p0f', '--file', self.p0f, '--os', 'apple',
                                  '--out', filtered])
        self.assertEqual(code, 0)
        self.assertEqual(sorted(self.by_os(filtered)), ['Mac OS', 'iOS'])

    def test_zardaxt_profiles(self):
        out = self.path('zardaxt.json')
        code, _text = run_import(['--source', 'zardaxt', '--file', self.zardaxt,
                                  '--out', out])
        self.assertEqual(code, 0)
        entries = {(entry['os'], entry['n']): entry for entry in self.entries_of(out)}
        self.assertEqual(sorted(entries), [('Linux', 4), ('Windows', 1), ('iOS', 6)])
        apple = entries[('iOS', 6)]
        self.assertEqual(apple['tcp_options'], 'mss1360,nop,ws6,nop,nop,ts,sackok,eol,eol')
        self.assertEqual(apple['tcp_options_ordered'], 'mnwnntsee')
        self.assertEqual(apple['tcp_data_offset'], 11)
        self.assertEqual(apple['ip_total_length'], 64)
        self.assertEqual(apple['tcp_mss'], 1360)
        self.assertEqual(apple['tcp_window_scaling'], 6)
        self.assertEqual(apple['ip_id_zero'], 1)           # "ip_id": 0 means zero
        self.assertEqual(apple['ip_tos'], 0)
        self.assertEqual(apple['source'], import_db.ZARDAXT_SOURCE)
        # --min-weight drops the one-off profiles a real table is full of.
        thinned = self.path('min.json')
        code, _text = run_import(['--source', 'zardaxt', '--file', self.zardaxt,
                                  '--min-weight', '2', '--out', thinned])
        self.assertEqual(code, 0)
        self.assertEqual(sorted(entry['n'] for entry in self.entries_of(thinned)), [4, 6])

    def test_zardaxt_options_beyond_the_common_letters(self):
        out = self.path('odd.json')
        source = self.write('odd-source.json', json.dumps(ZARDAXT_ODD))
        code, text = run_import(['--source', 'zardaxt', '--file', source, '--out', out])
        self.assertEqual(code, 0)
        entries = {entry['tcp_options']: entry for entry in self.entries_of(out)}
        # `U34` is TCP Fast Open and `K` is SACK: both are named, and both take
        # the room the recorded data offset leaves next to the known options.
        self.assertEqual(sorted(entries), ['mss1460,nop,fastopen,eol',
                                           'mss1460,nop,sackok,sack,eol,eol,eol',
                                           'mss1460,opt253,eol,eol'])
        fastopen = entries['mss1460,nop,fastopen,eol']
        self.assertEqual(fastopen['tcp_data_offset'], 7)      # a 2 byte cookie
        self.assertEqual(fastopen['ip_total_length'], 48)
        self.assertEqual(fastopen['tcp_options_ordered'], tcp_opts.ordered(
            'mss1460,nop,fastopen,eol'))
        self.assertEqual(fastopen['n'], 3)
        self.assertEqual(entries['mss1460,nop,sackok,sack,eol,eol,eol']['ip_total_length'], 60)
        # An option there is no name for keeps its IANA kind: `U253` -> opt253.
        self.assertEqual(entries['mss1460,opt253,eol,eol']['tcp_data_offset'], 11)
        # The two records whose letters and lengths disagree are reported, not
        # stored as a profile nobody could ever send.
        self.assertIn('unsupported options: 2', text)

    def test_imported_table_classifies(self):
        apple_only = self.path('apple-only.json')
        run_import(['--source', 'zardaxt', '--file', self.zardaxt, '--os', 'apple',
                    '--out', apple_only])
        db = database.Database(apple_only).load()
        result = db.classify(packet.decode_frame(apple_syn(), 1.0))
        self.assertEqual(result['os'], 'iOS')              # the only profile left
        self.assertEqual(result['os_group'], 'apple')
        # An exact match: every reachable field is explained by the entry.
        self.assertEqual(result['score'], result['possible_score'])
        self.assertEqual(result['coverage'], 1.0)

        p0f_only = self.path('p0f.json')
        run_import(['--source', 'p0f', '--file', self.p0f, '--out', p0f_only])
        db = database.Database(p0f_only).load()
        self.assertEqual(db.classify(packet.decode_frame(apple_syn(), 1.0))['os_group'],
                         'apple')
        self.assertEqual(db.classify(packet.decode_frame(windows_syn(), 1.0))['os'],
                         'Windows')

    def test_merge_keeps_the_existing_profiles_and_is_idempotent(self):
        out = self.path('merged.json')
        with open(DB_PATH, encoding='utf-8') as handle:
            shipped = json.load(handle)
        with open(out, 'w', encoding='utf-8') as handle:
            json.dump(shipped, handle)
        code, text = run_import(['--source', 'p0f', '--file', self.p0f,
                                 '--out', out, '--merge'])
        self.assertEqual(code, 0)
        self.assertIn('new', text)
        entries = self.entries_of(out)
        self.assertGreater(len(entries), len(shipped['entries']))
        self.assertIn('Android', [entry['os'] for entry in entries])   # nothing lost
        weights = sorted((entry['os'], entry['n']) for entry in entries)
        code, text = run_import(['--source', 'p0f', '--file', self.p0f,
                                 '--out', out, '--merge'])
        self.assertEqual(code, 0)
        self.assertIn('0 new', text)
        entries = self.entries_of(out)
        self.assertEqual(len(entries), len(weights))
        # A repeated import must not inflate the weight of what it already wrote.
        self.assertEqual(sorted((entry['os'], entry['n']) for entry in entries), weights)

    def test_bad_input_is_reported(self):
        code, _text = run_import(['--source', 'p0f', '--file', self.path('nope.fp')])
        self.assertEqual(code, 2)                          # missing file, no traceback
        broken = self.write('broken.json', '{not json')
        code, _text = run_import(['--source', 'zardaxt', '--file', broken])
        self.assertEqual(code, 2)
        empty = self.write('empty.fp', '[mtu]\nlabel = Ethernet\nsig = 1500\n')
        code, _text = run_import(['--source', 'p0f', '--file', empty])
        self.assertEqual(code, 1)                          # nothing importable


class TestCheckDatabase(unittest.TestCase):
    """tools/check_db.py tells a usable table from a broken or foreign one."""

    def setUp(self):
        self.log_state = dict(log._config)          # check_db.main() quiets the log
        self.directory = tempfile.mkdtemp(prefix='pof-check-')
        self.errors = ''

    def tearDown(self):
        log._config.update(self.log_state)
        for name in os.listdir(self.directory):
            os.unlink(os.path.join(self.directory, name))
        os.rmdir(self.directory)

    def write(self, name, document):
        """Write `document` as JSON, or verbatim when it is already text."""
        path = os.path.join(self.directory, name)
        with open(path, 'w', encoding='utf-8') as handle:
            if isinstance(document, str):
                handle.write(document)
            else:
                json.dump(document, handle)
        return path

    def run_check(self, *argv):
        """Run tools/check_db.py in process, with both streams captured."""
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = check_db.main(list(argv))
        self.errors = err.getvalue()
        return code, out.getvalue()

    def test_shipped_table_is_clean(self):
        code, text = self.run_check('--database', str(DB_PATH))
        self.assertEqual(code, 0)
        self.assertIn('format  : pof-db/1', text)
        self.assertIn('problems: none', text)
        # The self test classifies every entry with itself removed, so it can
        # only be right about the entries this table actually carries.
        self.assertIn('self test: leave-one-out', text)
        for name in ('Windows', 'Linux', 'Android', 'BSD'):
            self.assertIn(name, text)

    def test_problems_are_reported(self):
        profile = {'os': 'Windows', 'n': 1, 'tcp_options': 'mss1460,nop,ws8,nop,nop,sackok',
                   'tcp_data_offset': 8, 'ip_total_length': 52, 'ip_ttl_initial': 128,
                   'tcp_window_size': 65535}
        path = self.write('broken.json', {'format': database.DB_FORMAT, 'entries': [
            {'os': 'Linux', 'n': 2, 'tcp_options': 'mss,nop',      # 5 bytes: impossible
             'tcp_data_offset': 6, 'ip_total_length': 45, 'ip_ttl_initial': 63, 'osp': 1},
            profile, dict(profile),                                 # the same profile twice
            # A sound 12 byte option block (data offset 8, total length 52), but
            # the lengths written next to it are not the ones it implies.
            {'os': 'BSD', 'n': 1, 'tcp_options': 'mss1460,nop,ws8,nop,nop,sackok',
             'tcp_data_offset': 9, 'ip_total_length': 60, 'ip_ttl_initial': 64,
             'tcp_window_size': 65535, 'tcp_timestamp': 2},        # 0/1 only
        ]})
        code, text = self.run_check('--database', path)
        self.assertEqual(code, 1)
        self.assertIn('unknown field "osp"', text)
        self.assertIn('5 bytes of options cannot be on the wire', text)
        self.assertIn('is not a TTL bucket', text)
        self.assertIn('tcp_data_offset 9 != 8', text)
        self.assertIn('ip_total_length 60 != 52', text)
        self.assertIn('tcp_timestamp = 2 is outside 0..1', text)
        self.assertIn('hold the same profile', text)

    def test_a_foreign_dialect_comes_back_with_the_conversion_command(self):
        path = self.write('foreign.json', ZARDAXT_SAMPLE)
        code, text = self.run_check('--database', path)
        self.assertEqual(code, 1)
        self.assertIn('dialect : zardaxt table', text)
        # The report has to name the exact command, with the exact output path.
        self.assertIn('--source zardaxt --file {}'.format(path), text)
        self.assertIn('.pof.json', text)

    def test_a_missing_file_is_not_a_traceback(self):
        code, _text = self.run_check('--database', os.path.join(self.directory, 'nope.json'))
        self.assertEqual(code, 2)
        self.assertIn('check_db: cannot read', self.errors)

    def test_a_source_file_that_is_not_json_is_recognized(self):
        path = self.write('p0f.fp', '[tcp:request]\nlabel = s:unix:Linux:3.x\n'
                                    'sig = *:64:0:*:mss*20,10:mss,sok,ts,nop,ws:df,id+:0\n')
        code, text = self.run_check('--database', path)
        self.assertEqual(code, 1)
        self.assertIn('p0f source file', text)
        self.assertIn('--source p0f', text)


class TestStore(unittest.TestCase):
    def test_eviction_and_ring(self):
        store = store_mod.Store(max_ips=2, per_ip=2)
        for index, ip in enumerate(('10.0.0.1', '10.0.0.2', '10.0.0.3')):
            store.put(ip, {'ip_src': ip, 'ts': index})
        self.assertEqual(len(store), 2)
        self.assertIsNone(store.get('10.0.0.1'))
        self.assertIsNotNone(store.get('10.0.0.3'))

    def test_per_ip_ring_keeps_count(self):
        store = store_mod.Store(max_ips=10, per_ip=2)
        for index in range(5):
            entry = store.put('10.0.0.9', {'ip_src': '10.0.0.9', 'ts': index})
        self.assertEqual(entry['count'], 5)
        self.assertEqual(len(store.get('10.0.0.9')['fingerprints']), 2)
        self.assertEqual(store.latest('10.0.0.9')['ts'], 4)

    def test_snapshot_limit(self):
        store = store_mod.Store(max_ips=10, per_ip=1)
        for index in range(4):
            store.put('10.0.0.{}'.format(index), {'ip_src': 'x', 'ts': index})
        self.assertEqual(len(store.snapshot()), 4)
        self.assertEqual(len(store.snapshot(limit=2)), 2)

    def test_cleanup_by_age(self):
        store = store_mod.Store(max_ips=10, per_ip=1)
        store.put('10.0.0.1', {'ip_src': 'x'})
        store.put('10.0.0.2', {'ip_src': 'y'})
        store._entries['10.0.0.1']['last_seen'] -= 600
        self.assertEqual(store.cleanup(300), 1)
        self.assertIsNone(store.get('10.0.0.1'))
        self.assertIsNotNone(store.get('10.0.0.2'))
        self.assertEqual(store.cleanup(0), 0)


class TestPcapReplay(unittest.TestCase):
    """The offline path is the same decoder the live capture uses."""

    def setUp(self):
        self.db = database.Database(DB_PATH).load()
        self.directory = tempfile.mkdtemp(prefix='pof-test-')

    def tearDown(self):
        for name in os.listdir(self.directory):
            os.unlink(os.path.join(self.directory, name))
        os.rmdir(self.directory)

    def path(self, name):
        return os.path.join(self.directory, name)

    def test_read_mixed_capture(self):
        records = [(1.0, windows_syn()), (2.0, linux_syn()), (3.0, linux_syn(flags=0x12)),
                   (4.0, udp_frame()), (5.0, ipv6_syn())]
        pcap.write(self.path('mixed.pcap'), records)
        rows = pof.read_pcap(self.path('mixed.pcap'), self.db, quiet=True)
        self.assertEqual([row[0] for row in rows], [CLIENT, CLIENT, '2001:db8::1'])
        self.assertEqual([row[2]['os'] for row in rows], ['Windows', 'Linux', 'Linux'])

    def test_linktype_raw_is_wrapped_back_into_ethernet(self):
        raw_records = [(1.0, windows_syn()[14:]), (2.0, linux_syn()[14:])]
        pcap.write(self.path('raw.pcap'), raw_records, linktype=pcap.LINKTYPE_RAW)
        rows = pof.read_pcap(self.path('raw.pcap'), self.db, quiet=True)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0][2]['os'], 'Windows')

    def test_broken_file_does_not_explode(self):
        with open(self.path('bad.pcap'), 'wb') as handle:
            handle.write(b'not a pcap at all')
        with self.assertRaises(pcap.PcapError):
            list(pcap.frames(self.path('bad.pcap')))
        # A header without records yields nothing instead of raising.
        pcap.write(self.path('empty.pcap'), [])
        self.assertEqual(pof.read_pcap(self.path('empty.pcap'), self.db, quiet=True), [])

    def test_cli_read_mode(self):
        pcap.write(self.path('cli.pcap'), [(1.0, linux_syn())])
        # --database is explicit here: the tests always check the shipped table,
        # never whatever table the local config.json happens to point at.
        code, text = run_cli(['--read', self.path('cli.pcap'), '--quiet', '--log-dir', '',
                              '--database', str(DB_PATH)])
        self.assertEqual(code, 0)
        self.assertIn('Linux', text)
        code, text = run_cli(['--read', self.path('cli.pcap'), '--quiet', '--log-dir', '',
                              '--database', str(DB_PATH), '--json'])
        self.assertEqual(code, 0)
        document = json.loads(text)
        self.assertEqual(document[0]['os'], 'Linux')
        self.assertEqual(document[0]['ip'], CLIENT)
        self.assertGreater(document[0]['scores']['Linux'], document[0]['scores']['Android'])
        self.assertEqual(document[0]['possible_score'], 20.5)
        self.assertEqual(document[0]['fingerprint']['tcp_window_size'], 29200)

    def test_cli_list_database_and_config(self):
        code, text = run_cli(['--list-database', '--database', str(DB_PATH), '--log-dir', ''])
        self.assertEqual(code, 0)
        self.assertIn('Windows', text)
        self.assertIn('Android', text)
        code, text = run_cli(['--print-config', '--log-dir', '',
                              '--port', '1234', '--api-key', 'abc'])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(text)['api_port'], 1234)
        self.assertEqual(json.loads(text)['api_key'], 'abc')
        code, _text = run_cli(['--list-database', '--database', str(DB_PATH), '--log-dir', ''])
        self.assertEqual(code, 0)

    def test_cli_survives_a_missing_database_and_a_missing_capture(self):
        pcap.write(self.path('cli2.pcap'), [(1.0, linux_syn())])
        # Нет таблицы отпечатков: разбор всё равно работает, баллов просто нет
        # (перед JSON в stdout попадает предупреждение в лог, поэтому смотрим текст).
        code, text = run_cli(['--read', self.path('cli2.pcap'), '--quiet', '--log-dir', '',
                              '--database', self.path('nope.json'), '--json'])
        self.assertEqual(code, 0)
        self.assertIn('"os": null', text)
        self.assertIn('"score": 0.0', text)
        # Нет файла дампа: аккуратная ошибка вместо трейсбека.
        code, _text = run_cli(['--read', self.path('nope.pcap'), '--quiet', '--log-dir', ''])
        self.assertEqual(code, 2)


class TestApi(unittest.TestCase):
    """Starts a real HTTP server on a free localhost port."""

    def setUp(self):
        self.db = database.Database(DB_PATH).load()
        self.store = store_mod.Store(max_ips=10, per_ip=2)
        self.store.put(CLIENT, packet.decode_frame(windows_syn(), 1.0))
        self.config = dict(config_mod.DEFAULTS)
        self.config.update({'api_host': '127.0.0.1', 'api_port': 0, 'api_key': '',
                            'database': str(DB_PATH)})
        self.server = api.make_server(self.store, self.db, self.config)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       kwargs={'poll_interval': 0.05}, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def get(self, path, headers=None, method='GET', parse=True):
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=5)
        connection.request(method, path, headers=headers or {})
        response = connection.getresponse()
        body = response.read().decode('utf-8')
        connection.close()
        if not parse:       # the HTML viewer is not JSON
            return response, body
        return response, json.loads(body) if body else {}

    def test_own_ip_via_x_real_ip(self):
        response, body = self.get('/fingerprint', {'X-Real-IP': CLIENT})
        self.assertEqual(response.status, 200)
        self.assertEqual(body['ip'], CLIENT)
        self.assertEqual(body['os'], 'Windows')
        self.assertEqual(response.getheader('Access-Control-Allow-Origin'), '*')
        self.assertEqual(body['fingerprint']['tcp_window_size'], 65535)
        self.assertEqual(body['fingerprint']['tcp_options'],
                         'mss1460,nop,ws8,nop,nop,sackok')

    def test_slim_detail_mode(self):
        response, body = self.get('/fingerprint?detail=0', {'X-Real-IP': CLIENT})
        self.assertEqual(response.status, 200)
        self.assertEqual(set(body), set(api.SLIM_FIELDS))
        self.assertNotIn('fingerprint', body)

    def test_root_serves_the_html_viewer(self):
        response, body = self.get('/', {'X-Real-IP': CLIENT}, parse=False)
        self.assertEqual(response.status, 200)
        self.assertIn('text/html', response.getheader('Content-Type'))
        # The page is a viewer only: it fetches the JSON endpoint itself.
        self.assertIn('/fingerprint', body)
        response, payload = self.get('/fingerprint', {'X-Real-IP': CLIENT})
        self.assertEqual(response.status, 200)
        self.assertEqual(payload['os'], 'Windows')

    def test_unknown_ip(self):
        response, body = self.get('/fingerprint', {'X-Real-IP': '198.51.100.99'})
        self.assertEqual(response.status, 404)
        self.assertFalse(body['found'])
        self.assertIn('no SYN captured', body['message'])

    def test_invalid_ip(self):
        response, body = self.get('/fingerprint?ip=not-an-ip')
        self.assertEqual(response.status, 400)
        self.assertEqual(body['error'], 'not an IP address')

    def test_user_agent_comparison(self):
        _response, body = self.get('/fingerprint', {
            'X-Real-IP': CLIENT,
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126'})
        self.assertEqual(body['user_agent_os'], 'Windows')
        self.assertFalse(body['os_mismatch'])
        _response, body = self.get('/fingerprint', {
            'X-Real-IP': CLIENT,
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) Chrome/126'})
        self.assertEqual(body['user_agent_os'], 'Linux')
        self.assertTrue(body['os_mismatch'])

    def test_health_needs_no_key(self):
        response, body = self.get('/health')
        self.assertEqual(response.status, 200)
        self.assertEqual(body['status'], 'ok')
        self.assertTrue(body['database_loaded'])

    def test_head_request(self):
        response, _body = self.get('/health', method='HEAD')
        self.assertEqual(response.status, 200)
        self.assertEqual(response.getheader('Access-Control-Allow-Origin'), '*')

    def test_unknown_path(self):
        response, body = self.get('/nope')
        self.assertEqual(response.status, 404)
        self.assertIn('/fingerprint', body['paths'])


class TestApiWithKey(TestApi):
    """Same routes, but the bulk endpoints now need ?key=."""

    def setUp(self):
        super().setUp()
        self.config['api_key'] = 's3cret'

    def test_bulk_endpoints_need_the_key(self):
        for path in ('/fingerprints', '/stats', '/database'):
            response, _body = self.get(path)
            self.assertEqual(response.status, 403, path)
        response, body = self.get('/fingerprints?key=s3cret')
        self.assertEqual(response.status, 200)
        self.assertEqual(body['count'], 1)
        response, body = self.get('/stats?key=s3cret')
        self.assertEqual(response.status, 200)
        self.assertIn('ips', body)
        response, body = self.get('/database?key=s3cret')
        self.assertEqual(response.status, 200)
        self.assertEqual(body['entries'], len(self.db.entries))

    def test_lookup_of_another_ip_needs_the_key(self):
        response, body = self.get('/fingerprint?ip={}&key=s3cret'.format(CLIENT))
        self.assertEqual(response.status, 200)
        self.assertEqual(body['os'], 'Windows')
        response, _body = self.get('/fingerprint?ip={}'.format(CLIENT))
        self.assertEqual(response.status, 404)   # answered about 127.0.0.1 instead

    def test_invalid_ip(self):
        response, body = self.get('/fingerprint?ip=not-an-ip&key=s3cret')
        self.assertEqual(response.status, 400)
        self.assertEqual(body['error'], 'not an IP address')


class TestStartupUrls(unittest.TestCase):
    """What the service prints at startup, and what it warns about.

    `bind_urls` replaces a wildcard bind with the addresses of this host, so the
    log never says "http://0.0.0.0:8351"; a non-loopback bind also gets a
    warning, because the API key only covers the bulk endpoints.
    """

    @contextlib.contextmanager
    def local_addresses(self, addresses):
        original = api.netutil.local_ips
        api.netutil.local_ips = lambda interface=None: set(addresses)
        try:
            yield
        finally:
            api.netutil.local_ips = original

    @contextlib.contextmanager
    def logged_lines(self):
        lines = []
        original = log.log
        log.log = lambda message, module='pof', level='INFO': lines.append((message, level))
        try:
            yield lines
        finally:
            log.log = original

    def test_a_specific_address_is_kept_as_it_is(self):
        config = {'api_host': '127.0.0.1', 'api_port': 8351}
        self.assertEqual(api.bind_urls(config), ['http://127.0.0.1:8351'])

    def test_wildcard_bind_becomes_the_addresses_of_this_host(self):
        config = {'api_host': '0.0.0.0', 'api_port': 8351}
        with self.local_addresses({'127.0.0.1', '10.0.0.5', '2001:db8::1'}):
            self.assertEqual(api.bind_urls(config), ['http://10.0.0.5:8351'])

    def test_startup_warns_when_the_api_is_reachable_from_the_network(self):
        config = {'api_host': '0.0.0.0', 'api_port': 8351, 'api_key': 'k'}
        with self.local_addresses({'192.0.2.5'}), self.logged_lines() as lines:
            api.log_startup(config)
        self.assertEqual(lines[0], ('API on http://192.0.2.5:8351 (key set)', 'INFO'))
        self.assertIn('reachable from the network', lines[1][0])
        self.assertEqual(lines[1][1], 'WARNING')

    def test_startup_is_quiet_on_loopback(self):
        config = {'api_host': '127.0.0.1', 'api_port': 8351, 'api_key': ''}
        with self.logged_lines() as lines:
            api.log_startup(config)
        self.assertEqual(lines, [('API on http://127.0.0.1:8351 (key not set)', 'INFO')])


class TestConfig(unittest.TestCase):
    def test_defaults_match_the_shipped_config_file(self):
        with open(ROOT / 'config.json', encoding='utf-8') as handle:
            shipped = json.load(handle)
        self.assertEqual(set(shipped), set(config_mod.DEFAULTS))

    def test_the_configured_database_loads(self):
        """Whatever config.json points at must be a table this format can read.

        The file is local (a converted proprietary table lives outside the
        repository), so a missing one is not an error - but a present one that
        does not load is exactly the mistake worth catching.
        """
        with open(ROOT / 'config.json', encoding='utf-8') as handle:
            path = ROOT / json.load(handle)['database']
        self.assertTrue(str(path).endswith('.json'), path)
        if not path.exists():
            self.skipTest('{} is a local table and is not there'.format(path))
        db = database.Database(path).load()
        self.assertTrue(db.loaded, path)
        self.assertTrue(db.os_names, path)

    def test_precedence(self):
        base = config_mod.load(overrides={'log_dir': ''})
        self.assertEqual(base['api_port'], 8351)
        os.environ['POF_API_PORT'] = '9999'
        try:
            self.assertEqual(config_mod.load(overrides={'log_dir': ''})['api_port'], 9999)
            config = config_mod.load(overrides={'api_port': 1234, 'log_dir': ''})
            self.assertEqual(config['api_port'], 1234)
        finally:
            del os.environ['POF_API_PORT']

    def test_bad_values_are_rejected(self):
        for port in (0, 70000):
            with self.assertRaises(ValueError):
                config_mod.load(overrides={'api_port': port})

    def test_unknown_key_in_a_config_file_is_reported(self):
        directory = tempfile.mkdtemp(prefix='pof-config-')
        path = os.path.join(directory, 'config.json')
        with open(path, 'w', encoding='utf-8') as handle:
            json.dump({'api_port': 8351, 'nope': 1}, handle)
        try:
            with self.assertRaises(ValueError):
                config_mod.load(path)
        finally:
            os.unlink(path)
            os.rmdir(directory)


if __name__ == '__main__':
    unittest.main(verbosity=2)
