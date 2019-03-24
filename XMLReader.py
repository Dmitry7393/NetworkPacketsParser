from xml.dom import minidom

class XMLReader:
    def __init__(self):
        self.doc = minidom.Document()
        root = self.doc.createElement('data')
        self.doc.appendChild(root)

    def get_ethernet_frame_header(self):
        mydoc = minidom.parse('sniffed_data.xml')
        dest = mydoc.getElementsByTagName("Destination")[0]
        print(dest.firstChild.data)

        src = mydoc.getElementsByTagName("Source")[0]
        print(src.firstChild.data)

        proto = mydoc.getElementsByTagName("Protocol")[0]
        print(proto.firstChild.data)
        return (dest, src, proto)

