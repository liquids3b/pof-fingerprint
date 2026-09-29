"""Minimal libpcap file reader for offline analysis.

Supported: the four classic magic numbers (microsecond and nanosecond
timestamps, both endiannesses) and the standard 16 byte per packet record
header. Enough to replay a `tcpdump -w` capture through the same decoder and
scorer that the live capture uses, which is also how this tool is tested.
"""
import struct

MAGIC_US = 0xA1B2C3D4
MAGIC_NS = 0xA1B23C4D
MAGIC_US_SWAPPED = 0xD4C3B2A1
MAGIC_NS_SWAPPED = 0x4D3CB2A1

LINKTYPE_ETHERNET = 1
LINKTYPE_LINUX_SLL = 113
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL2 = 276


class PcapError(Exception):
    pass


def _reader(handle):
    header = handle.read(24)
    if len(header) < 24:
        raise PcapError('file is shorter than a pcap header')
    magic = struct.unpack('<I', header[:4])[0]
    if magic in (MAGIC_US, MAGIC_NS):
        endian, divisor = '<', (1_000_000 if magic == MAGIC_US else 1_000_000_000)
    elif magic in (MAGIC_US_SWAPPED, MAGIC_NS_SWAPPED):
        endian, divisor = '>', (1_000_000 if magic == MAGIC_US_SWAPPED else 1_000_000_000)
    else:
        raise PcapError('unknown pcap magic {:#x}'.format(magic))
    linktype = struct.unpack(endian + 'I', header[20:24])[0]
    return endian, divisor, linktype


def frames(path):
    """Yield `(timestamp, linktype, bytes)` for every record in the file."""
    with open(path, 'rb') as handle:
        endian, divisor, linktype = _reader(handle)
        while True:
            record = handle.read(16)
            if len(record) < 16:
                return
            seconds, fraction, captured, _original = struct.unpack(endian + 'IIII', record)
            data = handle.read(captured)
            if len(data) < captured:
                return
            yield seconds + fraction / divisor, linktype, data


def link_offset(linktype):
    """Bytes of link layer header in front of the IP header, or None."""
    if linktype == LINKTYPE_ETHERNET:
        return 14
    if linktype == LINKTYPE_LINUX_SLL:
        return 16
    if linktype == LINKTYPE_LINUX_SLL2:
        return 20
    if linktype == LINKTYPE_RAW:
        return 0
    return None


def write(path, records, linktype=LINKTYPE_ETHERNET):
    """Write `(timestamp, frame)` pairs - used by the tests and fixtures."""
    with open(path, 'wb') as handle:
        handle.write(struct.pack('<IHHiIII', MAGIC_US, 2, 4, 0, 0, 65535, linktype))
        for timestamp, frame in records:
            seconds = int(timestamp)
            fraction = int(round((timestamp - seconds) * 1_000_000))
            handle.write(struct.pack('<IIII', seconds, fraction, len(frame), len(frame)))
            handle.write(bytes(frame))


def to_ethernet(data, linktype):
    """Wrap a captured record in a synthetic Ethernet header.

    The decoder always reads from an Ethernet header; rewriting the link layer
    here means a `tcpdump -w` file with LINKTYPE_RAW or SLL replays through
    exactly the same code path as a live capture.
    """
    offset = link_offset(linktype)
    if offset is None:
        return None
    payload = data[offset:]
    if not payload:
        return None
    version = payload[0] >> 4
    if version == 4:
        ethertype = 0x0800
    elif version == 6:
        ethertype = 0x86DD
    else:
        return None
    return b'\x00' * 12 + struct.pack('!H', ethertype) + payload
