import unittest

from ethernet_parser import EthernetParser
from ip_header_parser import  IPHeaderParser
from tcp_header_parser import TCPHeaderParser
from udp_header_parser import UDPHeaderParser
from xml_reader import XMLReader

tcp_parser = TCPHeaderParser()
udp_parser = UDPHeaderParser()
ip_parser = IPHeaderParser(tcp_parser=tcp_parser, udp_parser=udp_parser)

ethernet_parser = EthernetParser(ipv4_parser=ip_parser)


class TestPacketParser(unittest.TestCase):

    def test1(self):
        raw_data = b'\x6c\x71\xd9\x61\xf1\xa1\xc0\x4a\x00\x57\x00\xee\x08\x00\x45\x00\x00\x34\xd5\x74\x40\x00\x39\x06\xa3\x56\x97\x65\x70\x85\xc0\xa8\x00\x66\x01\xbb\x86\x2c\xa8\x7e\x90\xd2\xc8\x58\x1a\x83\x80\x10\x00\x3f\x95\xef\x00\x00\x01\x01\x08\x0a\xe7\x84\x79\xa2\xac\x4c\x66\x0d'
        ethernet_parser.parse_header(raw_data)

        xml_reader = XMLReader('sniffed_data2.xml')
        dest, src, proto = xml_reader.get_ethernet_frame_header()

        self.assertEqual(dest, '6C:71:D9:61:F1:A1')
        self.assertEqual(src, 'C0:4A:00:57:00:EE')
        self.assertEqual(proto, '8')

        version, header_length, ttl, protocol, source, target = xml_reader.get_ip_header()
        self.assertEqual(version, '4')
        self.assertEqual(header_length, '20')
        self.assertEqual(ttl, '57')
        self.assertEqual(protocol, '6')
        self.assertEqual(source, '151.101.112.133')
        self.assertEqual(target, '192.168.0.102')

        source_port, destination_port, sequence, acknowledgement, data = xml_reader.get_tcp_header()
        self.assertEqual(source_port, '443')
        self.assertEqual(destination_port, '34348')
        self.assertEqual(sequence, '2826866898')
        self.assertEqual(acknowledgement, '3361217155')
    #    self.assertEqual(data, b'\x01\xbb\x86,\xa8~\x90\xd2\xc8X\x1a\x83\x80\x10\x00?\x95\xef\x00\x00\x01\x01\x08\n\xe7\x84y\xa2\xacLf\r')

    def test2(self):
        print('test2')
        #raw_data = b'\x01\x00^\x7f\xff\xfa\xc0J\x00W\x00\xee\x08\x00E\x00\x01d\x00\x00@\x00\x04\x11\xc4\xe5\xc0\xa8\x00\x01\xef\xff\xff\xfa\x80\x01\x07l\x01P\x0e\xf5NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nCACHE-CONTROL: max-age=100\r\nLOCATION: http://192.168.0.1:1900/igd.xml\r\nNT: urn:schemas-wifialliance-org:device:WFADevice:1\r\nNTS: ssdp:alive\r\nSERVER: ipos/7.0 UPnP/1.0 TL-WR840N/1.0\r\nUSN: uuid:565aa949-67c1-4c0e-aa8f-f349e6f59311::urn:schemas-wifialliance-org:device:WFADevice:1\r\n\r\n'
        #ethernet_parser.parse_header(raw_data)


if __name__ == '__main__':
    unittest.main()