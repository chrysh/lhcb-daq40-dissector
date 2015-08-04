import socket
import array
import random
import struct

ip = "127.0.0.1"
port_meta = 1234
port_data = 1235


class DataGen:

    def __init__(self):
        self.ID0 = random.randint(1, 10)          # 64 bit
        self.event_base_addr = 0xAAAAAAAA       # 64 bit
        self.num_events = random.randint(1, 3)    # 8? bit
        self.data_size = []                     # 16 bit each
        self.data_size.extend([random.randint(1, 10)
                              for _ in range(self.num_events)])
        self.ev_type = 2                        # 8 bit

    def generate_data_bufs(self):
        # FIXME: should data be send as big or little endian?
        metadata = struct.pack("QQB",
                               self.ID0,               # 64 bit
                               self.event_base_addr,   # 64 bit
                               self.num_events)        # 8? bit
        i = 0
        data = ""
        data_pkts = []
        for sz in self.data_size:
            metadata += struct.pack(">H", sz)

            data += struct.pack("QBH",
                                self.ID0 + i,    # 64 bit
                                self.ev_type,   # 8 bit
                                sz)             # 16 bit
            # event payload
            while (sz > 0):
                payload_size = random.randint(1, sz)
                data += struct.pack(">H", payload_size)   # 16 bit
                data += 'B'*payload_size
                sz -= payload_size
            i += 1
            data_pkts.append(data)
        return (metadata, data_pkts)


def send_pkt_lo(port, data):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect((ip, port))
    s.send(data)
    s.close()


if __name__ == '__main__':
    dGen = DataGen()
    (metadata, data_pkts) = dGen.generate_data_bufs()
    print(["dGen: ", vars(dGen)])
    print(["metadata: ", metadata])
    print(["data_pkts: ", data_pkts])
    send_pkt_lo(port_meta, metadata)
    for pkt in data_pkts:
        send_pkt_lo(port_data, pkt)
