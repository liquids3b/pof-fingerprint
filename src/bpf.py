"""Classic BPF: a small assembler and the SYN-only capture filter.

A raw AF_PACKET socket without a filter copies every packet on the link into
Python, which is the fastest way to burn CPU. Attaching a classic BPF program
moves the decision into the kernel: it only ever wakes this process for TCP
SYNs addressed *to* us, and the SYN|ACK our own stack answers with is rejected
because the ACK bit is set.

`struct sock_filter` is 8 bytes: u16 code, u8 jt, u8 jf, u32 k.
"""
import ctypes
import os
import struct
from ctypes.util import find_library

SOL_SOCKET = 1
SO_ATTACH_FILTER = 26

# Instruction classes (bpf_common.h).
BPF_LD, BPF_LDX, BPF_ST, BPF_STX = 0x00, 0x01, 0x02, 0x03
BPF_ALU, BPF_JMP, BPF_RET, BPF_MISC = 0x04, 0x05, 0x06, 0x07
# Widths and addressing modes.
BPF_W, BPF_H, BPF_B = 0x00, 0x08, 0x10
BPF_IMM, BPF_ABS, BPF_IND, BPF_MSH = 0x00, 0x20, 0x40, 0xA0
# ALU and jump operators.
BPF_AND = 0x50
BPF_JA, BPF_JEQ, BPF_JSET = 0x00, 0x10, 0x40

ACCEPT = 0xFFFF
DROP = 0

ETH_IPV4 = 0x0800
ETH_IPV6 = 0x86DD
ETH_HEADER = 14
IPPROTO_TCP = 6
TCP_FLAGS_OFFSET = 13
IPV6_HEADER = 40
SYN_AND_ACK = 0x12
SYN_ONLY = 0x02


class Program:
    """Assembles an instruction list; labels resolve at `assemble()` time."""

    def __init__(self):
        self.instructions = []
        self._labels = {}
        self._jumps = []

    def label(self, name):
        self._labels[name] = len(self.instructions)

    def _emit(self, code, k=0, jt=0, jf=0):
        self.instructions.append([code, jt, jf, k])
        return len(self.instructions) - 1

    def ld_b(self, offset):
        """A = P[offset] (one byte)."""
        return self._emit(BPF_LD | BPF_B | BPF_ABS, offset)

    def ld_h(self, offset):
        """A = P[offset] (half word, network order)."""
        return self._emit(BPF_LD | BPF_H | BPF_ABS, offset)

    def ld_ip_header_length(self, offset):
        """X = 4 * (P[offset] & 0x0f): the IPv4 header length in bytes."""
        return self._emit(BPF_LDX | BPF_B | BPF_MSH, offset)

    def ld_indirect_byte(self, offset):
        """A = P[X + offset]."""
        return self._emit(BPF_LD | BPF_B | BPF_IND, offset)

    def alu_and(self, value):
        return self._emit(BPF_ALU | BPF_AND | BPF_IMM, value)

    def jeq(self, value, true_label=None, false_label=None):
        index = self._emit(BPF_JMP | BPF_JEQ | BPF_IMM, value)
        self._jumps.append((index, true_label, false_label))
        return index

    def ret(self, verdict):
        return self._emit(BPF_RET | BPF_IMM, verdict)

    def assemble(self):
        """Resolve labels and return `[(code, jt, jf, k), ...]`."""
        for index, true_label, false_label in self._jumps:
            for slot, target in ((1, true_label), (2, false_label)):
                if target is None:
                    continue
                if target not in self._labels:
                    raise ValueError('unknown label {!r}'.format(target))
                offset = self._labels[target] - index - 1
                if offset < 0 or offset > 255:
                    raise ValueError('jump to {!r} is out of range'.format(target))
                self.instructions[index][slot] = offset
        if not self.instructions:
            raise ValueError('empty program')
        return [tuple(item) for item in self.instructions]

    def ser(self):
        """Serialize to the byte layout `struct sock_filter` expects."""
        blob = bytearray()
        for code, jt, jf, k in self.assemble():
            blob += struct.pack('HBBI', code, jt, jf, k)
        return bytes(blob)


def syn_only_program():
    """Accept IPv4/IPv6 TCP segments that have SYN set and ACK clear."""
    program = Program()
    program.ld_h(12)                                   # ethertype
    program.jeq(ETH_IPV4, 'ipv4', 'ethernet_check')
    program.label('ethernet_check')
    program.jeq(ETH_IPV6, 'ipv6', 'drop')

    program.label('ipv4')
    program.ld_b(ETH_HEADER + 9)                       # IPv4 protocol field
    program.jeq(IPPROTO_TCP, 'ipv4_flags', 'drop')
    program.label('ipv4_flags')
    # BPF_MSH leaves X holding the IPv4 header length only, so the indirect
    # load has to add the 14 bytes of the Ethernet header itself.
    program.ld_ip_header_length(ETH_HEADER)
    program.ld_indirect_byte(ETH_HEADER + TCP_FLAGS_OFFSET)   # A = TCP flags
    program.alu_and(SYN_AND_ACK)
    program.jeq(SYN_ONLY, 'accept', 'drop')

    program.label('ipv6')
    program.ld_b(ETH_HEADER + 6)                       # IPv6 next header
    program.jeq(IPPROTO_TCP, 'ipv6_flags', 'drop')
    program.label('ipv6_flags')
    program.ld_b(ETH_HEADER + IPV6_HEADER + TCP_FLAGS_OFFSET)
    program.alu_and(SYN_AND_ACK)
    program.jeq(SYN_ONLY, 'accept', 'drop')

    program.label('accept')
    program.ret(ACCEPT)
    program.label('drop')
    program.ret(DROP)
    return program


class _SockFilter(ctypes.Structure):
    _fields_ = [('code', ctypes.c_ushort), ('jt', ctypes.c_ubyte),
                ('jf', ctypes.c_ubyte), ('k', ctypes.c_uint32)]


class _SockFprog(ctypes.Structure):
    _fields_ = [('len', ctypes.c_ushort), ('filter', ctypes.POINTER(_SockFilter))]


_libc = None
_attached = {}


def _load_libc():
    global _libc
    if _libc is None:
        _libc = ctypes.CDLL(find_library('c') or 'libc.so.6', use_errno=True)
    return _libc


def attach(sock, program):
    """Attach `program` to `sock`; returns the instruction count.

    Raises OSError when the kernel refuses the filter (for example when the
    process lacks CAP_NET_RAW), so the caller can fall back to filtering in
    Python instead of dying.
    """
    instructions = program.assemble()
    array = (_SockFilter * len(instructions))()
    for index, (code, jt, jf, k) in enumerate(instructions):
        array[index] = _SockFilter(code, jt, jf, k)
    fprog = _SockFprog(len(instructions), array)
    result = _load_libc().setsockopt(sock.fileno(), SOL_SOCKET, SO_ATTACH_FILTER,
                                     ctypes.byref(fprog), ctypes.sizeof(fprog))
    if result != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    # The kernel copies the program, but the ctypes buffers are kept alive
    # anyway so later kernel behaviour cannot surprise us.
    _attached[sock.fileno()] = (array, fprog)
    return len(instructions)
