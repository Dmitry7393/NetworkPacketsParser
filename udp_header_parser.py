from parser import *

class UDPHeaderParser(PacketParser):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def parse_header(self, data):
        src_port, dest_port, length = struct.unpack('! H H 2x H', data[:8])

        print('UDP Segment: ')
        print('Source port: {}, Destination Port: {}, Length: {}'.format(src_port, dest_port, length))