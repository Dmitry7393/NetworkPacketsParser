from xml.dom import minidom

class XMLWriter:
    def __init__(self):
        self.doc = minidom.Document()
        self.root = self.doc.createElement('data')
        self.doc.appendChild(self.root)

    def save_ethernet_frame_header(self, *args):
        eth_elem = self.doc.createElement('ethernet_frame')
        self.root.appendChild(eth_elem)

        fields = ['Destination', 'Source', 'Protocol']
        i = 0
        for field in args:
            item = self.doc.createElement(fields[i])
            text = self.doc.createTextNode('{}'.format(field))
            item.appendChild(text)
            eth_elem.appendChild(item)
            i += 1

    def save_ip_header(self, *args):
        ipv4_elem = self.doc.createElement('ipv4_header')
        self.root.appendChild(ipv4_elem)

        fields = ['Version', 'TTL', 'Protocol', 'Source', 'Target']
        i = 0
        for field in args:
            item = self.doc.createElement(fields[i])
            text = self.doc.createTextNode('{}'.format(field))
            item.appendChild(text)
            ipv4_elem.appendChild(item)
            i += 1

    def save_tcp_header(self, *args):
        tcp_elem = self.doc.createElement('tcp_header')
        self.root.appendChild(tcp_elem)

        fields = ['SourcePort', 'DestinationPort', 'Sequence', 'Acknowledgement']
        i = 0
        for field in args:
            item = self.doc.createElement(fields[i])
            text = self.doc.createTextNode('{}'.format(field))
            item.appendChild(text)
            tcp_elem.appendChild(item)
            i += 1

    def save_udp_header(self, *args):
        udp_elem = self.doc.createElement('udp_header')
        self.root.appendChild(udp_elem)

        fields = ['SourcePort', 'DestinationPort', 'Length']
        i = 0
        for field in args:
            item = self.doc.createElement(fields[i])
            text = self.doc.createTextNode('{}'.format(field))
            item.appendChild(text)
            udp_elem.appendChild(item)
            i += 1

    def save_to_xml_file(self):
        xml_str = self.doc.toprettyxml(indent="  ")
        with open("sniffed_data.xml", "w") as f:
            f.write(xml_str)


a = XMLWriter()
a.save_ethernet_frame_header('192.168.10.102', '34.342.23.45', 8)
a.save_ip_header('454', 45, '6', '23232323232', '454545454545')
a.save_tcp_header('111111111111', '333333333333', 23324, 324)
a.save_to_xml_file()