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
        raw_data = b'\x6c\x71\xd9\x61\xf1\xa1\xc0\x4a\x00\x57\x00\xee\x08\x00\x45\x00\x00\x34\xd5\x74\x40\x00\x39\x06\xa3\x56\x97\x65\x70\x85\xc0\xa8\x00\x66\x01\xbb\x86\x2c\xa8\x7e\x90\xd2\xc8\x58\x1a\x83\x80\x10\x00\x3f\x95\xef\x00\x00\x01\x01\x08\x0a\xe7\x84\x79\xa2\xac\x4c\x66\x0d'
        ethernet_parser.parse_header(raw_data)

        dest_mac, src_mac, eth_proto = ethernet_parser.get_parsed_data()
        self.assertEqual(dest_mac, '6C:71:D9:61:F1:A1')
        self.assertEqual(src_mac, 'C0:4A:00:57:00:EE')
        self.assertEqual(eth_proto, 8)





if __name__ == '__main__':
    unittest.main()