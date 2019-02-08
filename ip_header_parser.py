from parser import *

class IPHeaderParser(PacketParser):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def parse_header(self, data):
        (version, header_length, ttl, proto, src, target, data) = self._ipv4_packet(data)
        print('IPv4 Packet:')
        print('Version: {}, Header length: {}, TTL: {}'.format(version, header_length, ttl))
        print('Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))

        if proto == 6:  # TCP
            self.next_parsers['tcp_parser'].parse_header(data)
        elif proto == 17:  # UDP
            self.next_parsers['udp_parser'].parse_header(data)

    def _ipv4_packet(self, data):
        version_header_length = data[0]
        version = version_header_length >> 4
        header_length = (version_header_length & 15) * 4
        ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
        return version, header_length, ttl, proto, self._ipv4(src), self._ipv4(target), data[header_length:]

    # Return properly formatted IPV4 address
    def _ipv4(self, addr):
        return '.'.join(map(str, addr))