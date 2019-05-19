import unittest
from ethernet_parser import EthernetParser
from ip_header_parser import  IPHeaderParser
from tcp_header_parser import TCPHeaderParser
from udp_header_parser import UDPHeaderParser
from xml_reader import XMLReader
from xml_writer import XMLWriter

tcp_parser = TCPHeaderParser()
udp_parser = UDPHeaderParser()
ip_parser = IPHeaderParser(tcp_parser=tcp_parser, udp_parser=udp_parser)

ethernet_parser = EthernetParser(ipv4_parser=ip_parser)


class TestPacketParser(unittest.TestCase):

    def testTCPParserWithoutData(self):
        raw_data = b'\x6c\x71\xd9\x61\xf1\xa1\xc0\x4a\x00\x57\x00\xee\x08\x00\x45\x00\x00\x34\xd5\x74\x40\x00\x39\x06\xa3\x56\x97\x65\x70\x85\xc0\xa8\x00\x66\x01\xbb\x86\x2c\xa8\x7e\x90\xd2\xc8\x58\x1a\x83\x80\x10\x00\x3f\x95\xef\x00\x00\x01\x01\x08\x0a\xe7\x84\x79\xa2\xac\x4c\x66\x0d'
        xml_writer = XMLWriter.getXMLWriter()
        xml_writer.setPath('testTCPParserWithoutData.xml')
        ethernet_parser.parse_header(raw_data)

        xml_reader = XMLReader('testTCPParserWithoutData.xml')
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

    def testTCPParserWithData(self):
        print('testTCPParserWithData')
        raw_data = b'lq\xd9a\xf1\xa1\xc0J\x00W\x00\xee\x08\x00E\x00\x004\xb0\xd8@\x00V\x06\x00\xcc\x9d\xf0\x14#\xc0\xa8\x00d\x01\xbb\x80\xcc\xe9\x88\xd9\x84\xc3\x13@^\x80\x10\x00rV\xdc\x00\x00\x01\x01\x08\nWn\xaf1\xec6pq'
        xml_writer = XMLWriter.getXMLWriter()
        xml_writer.setPath('testTCPParserWithData.xml')
        ethernet_parser.parse_header(raw_data)

        xml_reader = XMLReader('testTCPParserWithData.xml')
        dest, src, proto = xml_reader.get_ethernet_frame_header()

        self.assertEqual(dest, '6C:71:D9:61:F1:A1')
        self.assertEqual(src, 'C0:4A:00:57:00:EE')
        self.assertEqual(proto, '8')

        version, header_length, ttl, protocol, source, target = xml_reader.get_ip_header()
        self.assertEqual(version, '4')
        self.assertEqual(header_length, '20')
        self.assertEqual(ttl, '86')
        self.assertEqual(protocol, '6')
        self.assertEqual(source, '157.240.20.35')
        self.assertEqual(target, '192.168.0.100')

        source_port, destination_port, sequence, acknowledgement, data = xml_reader.get_tcp_header()
        self.assertEqual(source_port, '443')
        self.assertEqual(destination_port, '32972')
        self.assertEqual(sequence, '3918059908')
        self.assertEqual(acknowledgement, '3272818782')

        print('============= data in tests = ', data)
        #self.assertEqual(data, b'\x01\xbb\x80\xcc\xe9\x88\xd9\x84\xc3\x13@^\x80\x10\x00rV\xdc\x00\x00\x01\x01\x08\nWn\xaf1\xec6pq')

    def testParseUDPWithoutData(self):
        pass

    def testParsingUDPWithData(self):
        pass

if __name__ == '__main__':
    unittest.main()