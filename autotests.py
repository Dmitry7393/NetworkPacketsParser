import unittest

from ethernet_frame_parser import EthernetParser
from ip_header_parser import  IPHeaderParser
from tcp_header_parser import TCPHeaderParser
from udp_header_parser import UDPHeaderParser

tcp_parser = TCPHeaderParser()
udp_parser = UDPHeaderParser()
ip_parser = IPHeaderParser(tcp_parser=tcp_parser, udp_parser=udp_parser)

ethernet_parser = EthernetParser(ipv4_parser=ip_parser)

class TestPacketParser(unittest.TestCase):

    def test1(self):
        raw_data = b'\xc0\x4a\x00\x57\x00\xee\x6c\x71\xd9\x61\xf1\xa1\x08\x00\x45\x00'
        ethernet_parser.parse_header(raw_data)


if __name__ == '__main__':
    unittest.main()