"""Live SYN capture over a raw AF_PACKET socket.

This is the part that replaces libpcap: `socket.AF_PACKET` plus the classic BPF
filter in `bpf.py` gives the same "only the first packet of every connection"
view with no C extension to build, and it feeds the parser straight from the
kernel ring buffer.
"""
import select
import socket
import time

import bpf
import log
import netutil
import packet

MAX_FRAME = 2048  # a SYN is < 100 bytes; a larger read would only waste copies
IDLE_TIMEOUT = 1.0
ETH_P_ALL = 3     # every protocol, both directions


class Capture:
    def __init__(self, store, config):
        self.store = store
        self.config = config
        self.interface = config['interface'] or netutil.default_interface()
        self.local_ips = netutil.local_ips(self.interface) if config['ignore_local_ips'] else set()
        self.socket = None
        self.frames = 0
        self.stored = 0
        self.filtered_bpf = False
        self.finished = False

    def open(self):
        if not hasattr(socket, 'AF_PACKET'):
            raise RuntimeError('AF_PACKET is Linux only; use --read FILE.pcap elsewhere')
        if not self.interface:
            raise RuntimeError('no capture interface found, set "interface" in the config')
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        sock.bind((self.interface, 0))
        sock.setblocking(False)
        if self.config['bpf']:
            try:
                instructions = bpf.attach(sock, bpf.syn_only_program())
                self.filtered_bpf = True
                log.log('attached SYN filter ({} BPF instructions) to {}'.format(
                    instructions, self.interface), 'capture')
            except OSError as err:
                log.log('cannot attach BPF filter ({}); filtering in Python instead'.format(err),
                        'capture', level='WARNING')
        self.socket = sock
        log.log('capturing on {} (local addresses: {})'.format(
            self.interface, ', '.join(sorted(self.local_ips)) or '-'), 'capture')
        return self

    def handle_frame(self, frame, timestamp):
        """Decode one frame and store it when it is a client SYN. Returns the IP."""
        self.frames += 1
        fingerprint = packet.decode_frame(frame, timestamp)
        if fingerprint is None or not packet.is_client_syn(fingerprint):
            return None
        source = packet.normalize_ip(fingerprint['ip_src'])
        if netutil.is_local(source, self.local_ips):
            return None
        if netutil.is_ignorable(source, private=self.config['ignore_private_ips']):
            return None
        fingerprint['ip_src'] = source
        fingerprint['ip_dst'] = packet.normalize_ip(fingerprint['ip_dst'])
        self.store.put(source, fingerprint)
        self.stored += 1
        return source

    def run(self, on_fingerprint=None, should_stop=None):
        """Capture until `should_stop()` returns True (or the socket dies)."""
        if self.socket is None:
            self.open()
        last_cleanup = time.time()
        log.log('capture loop started', 'capture')
        while True:
            if should_stop and should_stop():
                break
            try:
                ready = select.select([self.socket], [], [], IDLE_TIMEOUT)[0]
            except (OSError, ValueError):  # interrupted, or the socket was closed
                break
            if ready:
                self._drain(on_fingerprint)
            if self.config['expire_seconds'] and time.time() - last_cleanup > 60:
                removed = self.store.cleanup(self.config['expire_seconds'])
                if removed:
                    log.log('expired {} IPs'.format(removed), 'capture')
                last_cleanup = time.time()
        self.finished = True
        log.log('capture loop stopped after {} frames / {} SYN'.format(
            self.frames, self.stored), 'capture')

    def _drain(self, on_fingerprint):
        """Read everything the kernel has queued; recv() raises when it is empty."""
        while True:
            try:
                frame = self.socket.recv(MAX_FRAME)
            except (BlockingIOError, InterruptedError):
                return
            except OSError as err:
                log.log('recv failed: {}'.format(err), 'capture', level='ERROR')
                return
            source = self.handle_frame(frame, time.time())
            if source and on_fingerprint:
                on_fingerprint(source)

    def close(self):
        if self.socket is not None:
            try:
                self.socket.close()
            except OSError:
                pass
            self.socket = None
