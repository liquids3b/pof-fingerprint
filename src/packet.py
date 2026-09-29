"""Minimal Ethernet / IPv4 / IPv6 / TCP decoder.

Only the header fields that carry OS entropy are extracted, which is why this
is a few dozen lines of struct work instead of a full packet library. Every
read is bounds checked: a truncated or malformed frame returns None.
"""
import socket
import struct

import tcp_opts

ETH_IPV4 = 0x0800
ETH_IPV6 = 0x86DD
ETH_VLAN = 0x8100
ETH_QINQ = 0x88A8

IPPROTO_TCP = 6

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20
TCP_ECE = 0x40
TCP_CWR = 0x80


def initial_ttl(ttl):
    """Bucket a hop-decremented TTL into the value the sender likely started with.

    64 covers Unix, Apple and most embedded stacks, 128 Windows, 255 network
    gear and some BSDs. Routers decrement TTL, so the observed value is
    `initial - hops`; bucketing undoes that.
    """
    if ttl is None:
        return None
    if ttl <= 32:
        return 32
    if ttl <= 64:
        return 64
    if ttl <= 128:
        return 128
    return 255


def _ipv4(payload, link_len):
    if len(payload) < 20:
        return None
    version_ihl, tos = payload[0], payload[1]
    if version_ihl >> 4 != 4:
        return None
    header_len = (version_ihl & 0x0F) * 4
    if header_len < 20 or len(payload) < header_len:
        return None
    total_length, ident, flags_frag = struct.unpack('!HHH', payload[2:8])
    ttl, proto, checksum = payload[8], payload[9], struct.unpack('!H', payload[10:12])[0]
    if proto != IPPROTO_TCP:
        return None
    return {
        'ip_version': 4,
        'ip_header_length': header_len,
        'ip_tos': tos,
        'ip_total_length': total_length,
        'ip_id': ident,
        'ip_id_zero': 1 if ident == 0 else 0,
        'ip_df': 1 if flags_frag & 0x4000 else 0,
        'ip_mf': 1 if flags_frag & 0x2000 else 0,
        'ip_frag_offset': flags_frag & 0x1FFF,
        'ip_ttl': ttl,
        'ip_checksum': checksum,
        'ip_src': socket.inet_ntop(socket.AF_INET, payload[12:16]),
        'ip_dst': socket.inet_ntop(socket.AF_INET, payload[16:20]),
        'ip_traffic_class': None,
        'ip_flow_label': None,
        'ip_next_header': None,
        '_ip_payload': payload[header_len:],
        '_link_len': link_len + header_len,
    }


def _ipv6(payload, link_len):
    if len(payload) < 40:
        return None
    first, payload_len, next_header, hop_limit = struct.unpack('!IHBB', payload[:8])
    if first >> 28 != 6:
        return None
    if next_header != IPPROTO_TCP:
        # Extension headers are rare on a SYN and deliberately not chased here.
        return None
    return {
        'ip_version': 6,
        'ip_header_length': 40,
        'ip_tos': None,
        'ip_total_length': payload_len + 40,
        'ip_id': None,
        'ip_id_zero': None,
        'ip_df': None,
        'ip_mf': None,
        'ip_frag_offset': None,
        'ip_ttl': hop_limit,
        'ip_checksum': None,
        'ip_src': socket.inet_ntop(socket.AF_INET6, payload[8:24]),
        'ip_dst': socket.inet_ntop(socket.AF_INET6, payload[24:40]),
        'ip_traffic_class': (first >> 20) & 0xFF,
        'ip_flow_label': first & 0xFFFFF,
        'ip_next_header': next_header,
        '_ip_payload': payload[40:],
        '_link_len': link_len + 40,
    }


def _tcp(ip, timestamp, frame_len):
    payload = ip.pop('_ip_payload')
    link_len = ip.pop('_link_len')
    if len(payload) < 20:
        return None
    sport, dport, seq, ack = struct.unpack('!HHII', payload[:12])
    offset_flags, window, checksum, urgent = struct.unpack('!HHHH', payload[12:20])
    data_offset = (offset_flags >> 12) & 0x0F
    flags = offset_flags & 0x01FF
    header_len = data_offset * 4
    if header_len < 20 or len(payload) < header_len:
        return None
    option_string, options = tcp_opts.decode(payload[20:header_len])
    ip.update({
        'ts': timestamp,
        'frame_len': frame_len,
        'tcp_src_port': sport,
        'tcp_dst_port': dport,
        'tcp_seq': seq,
        'tcp_ack': ack,
        'tcp_data_offset': data_offset,
        'tcp_header_length': header_len,
        'tcp_flags': flags,
        'tcp_window_size': window,
        'tcp_checksum': checksum,
        'tcp_urgent': urgent,
        'tcp_options': option_string,
        'tcp_options_ordered': tcp_opts.ordered(option_string),
        'tcp_mss': options['mss'],
        'tcp_window_scaling': options['window_scaling'],
        'tcp_timestamp': options['timestamp'],
        'tcp_timestamp_echo': options['timestamp_echo'],
        'tcp_options_length': options['length'],
        'ip_ttl_initial': initial_ttl(ip['ip_ttl']),
        'header_len': link_len + header_len,
    })
    return ip


def decode_frame(frame, timestamp):
    """Decode one captured frame into a fingerprint dict, or None.

    The frame is expected to start with an Ethernet header (what AF_PACKET
    hands back on a NIC). Single and double VLAN tags are handled because both
    show up in the wild on VPS links.
    """
    frame = bytes(frame)
    if len(frame) < 34:
        return None
    ethertype = struct.unpack('!H', frame[12:14])[0]
    offset = 14

    if ethertype in (ETH_QINQ, ETH_VLAN):
        inner = struct.unpack('!H', frame[16:18])[0]
        if ethertype == ETH_QINQ and inner == ETH_VLAN:  # stacked 802.1ad + 802.1q
            ethertype = struct.unpack('!H', frame[20:22])[0]
            offset = 22
        else:
            ethertype = inner
            offset = 18

    payload = frame[offset:]
    if ethertype == ETH_IPV4:
        ip = _ipv4(payload, offset)
    elif ethertype == ETH_IPV6:
        ip = _ipv6(payload, offset)
    else:
        return None
    if ip is None:
        return None
    return _tcp(ip, timestamp, len(frame))


def is_client_syn(fingerprint):
    """True for a bare SYN (no ACK), i.e. the first packet of a connection."""
    flags = fingerprint.get('tcp_flags') or 0
    return bool(flags & TCP_SYN) and not flags & TCP_ACK


def normalize_ip(address):
    """Map IPv4-mapped IPv6 addresses (`::ffff:1.2.3.4`) to plain IPv4."""
    if not address:
        return address
    if address.startswith('::ffff:') and '.' in address:
        return address[7:]
    return address
