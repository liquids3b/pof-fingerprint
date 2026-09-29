"""Network helpers with no third party dependencies.

`local_ips()` is what keeps this host's own outbound connections (health
checks, package updates, the operator's ssh session) out of the fingerprint
table, and `default_interface()` replaces netifaces by reading the routing
table directly.
"""
import ipaddress
import socket
import struct

try:  # AF_PACKET, ioctl and /proc exist on Linux; the offline tools also run on Windows
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None

SIOCGIFADDR = 0x8915
LOOPBACK_PREFIX = '127.'


def default_interface():
    """The interface the default IPv4 route uses, from /proc/net/route."""
    try:
        with open('/proc/net/route', encoding='ascii') as handle:
            lines = handle.readlines()[1:]
    except OSError:
        return None
    for line in lines:
        fields = line.split()
        if len(fields) < 4:
            continue
        if fields[1] == '00000000' and fields[7] == '00000000':  # dst and mask 0.0.0.0
            return fields[0]
    # No default route (or an IPv6 only host): take the first non-loopback NIC.
    for _index, name in socket.if_nameindex():
        if name != 'lo':
            return name
    return None


def _ipv4_of_interface(name):
    if fcntl is None:
        return None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except OSError:
        return None
    try:
        request = struct.pack('256s', name.encode('ascii')[:15])
        return socket.inet_ntoa(fcntl.ioctl(sock.fileno(), SIOCGIFADDR, request)[20:24])
    except OSError:
        return None
    finally:
        sock.close()


def _ipv6_addresses():
    """Every local IPv6 address, from /proc/net/if_inet6."""
    addresses = set()
    try:
        with open('/proc/net/if_inet6', encoding='ascii') as handle:
            for line in handle:
                raw = line.split()[0]
                if len(raw) == 32:
                    addresses.add(str(ipaddress.IPv6Address(int(raw, 16))))
    except (OSError, ValueError):
        pass
    return addresses


def local_ips(interface=None):
    """Addresses this host owns: its own SYNs must not be fingerprinted."""
    found = {'127.0.0.1', '::1', '0.0.0.0', '::'}
    try:
        names = socket.if_nameindex()
    except OSError:
        names = []
    for _index, name in names:
        if interface and name != interface:
            continue
        address = _ipv4_of_interface(name)
        if address:
            found.add(address)
    try:
        _host, _aliases, addresses = socket.gethostbyname_ex(socket.gethostname())
        found.update(addresses)
    except (OSError, socket.gaierror):
        pass
    found.update(_ipv6_addresses())
    return {address.split('%')[0] for address in found}


def is_local(address, addresses):
    return address in addresses


def is_ignorable(address, private=False):
    """Loopback, link local, multicast, broadcast, unspecified - and RFC1918."""
    if not address:
        return True
    address = address.split('%')[0]
    if address.startswith(LOOPBACK_PREFIX):
        return True
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return True
    if parsed.is_loopback or parsed.is_multicast or parsed.is_unspecified:
        return True
    if parsed.version == 6 and parsed.is_link_local:
        return True
    if parsed.version == 4 and parsed.is_link_local:
        return True
    if private and parsed.is_private:
        return True
    return False
