from parser import *

class EthernetParser(PacketParser):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def parse_header(self, raw_data):
        dest_mac, src_mac, eth_proto, data = self._ethernet_frame(raw_data)

        print('\nEthernet frame:')
        print('Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))

        if eth_proto == 8:
            self.next_parsers['ipv4_parser'].parse_header(data)
        else:
            print('Parser of {} is not defined'.format(eth_proto))

    def _ethernet_frame(self, data):
        dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
        return self._get_mac_addr(dest_mac), self._get_mac_addr(src_mac), socket.htons(proto), data[14:]

    def _get_mac_addr(self, bytes_addr):
        bytes_str = map('{:02x}'.format, bytes_addr)
        return ':'.join(bytes_str).upper()
