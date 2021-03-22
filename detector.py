import sys
from os import remove

from scapy.layers.inet import IP, Ether, TCP
from scapy.utils import PcapReader

import collections


#
# class DetectPortScanning:
#     def __init__(self, fname):
#         self.sent = collections.Counter()
#         self.received = collections.Counter()
#         self.ratio = 3
#         self.fname = fname
#
#     def count(self):
#         """Counts sent and received packets"""
#         for pkt in PcapReader(sys.argv[1]):  # Using generator to avoid loading 350MB file into mem at once
#             if pkt.haslayer(Ether) and pkt.haslayer(IP) and pkt.haslayer(TCP):
#                 if (pkt[TCP].flags == 'S'):  # SYN - Sent packet
#                     ip = pkt[IP].src
#                     self.sent.update(ip)
#
#                 elif (pkt[TCP].flags == 'SA'):  # SYN-ACK - Sent packet acknowledgement
#                     ip = pkt[IP].dst
#                     self.received.update(ip)

def main():
    sent = collections.Counter()
    received = collections.Counter()
    ratio = 3
    for pkt in PcapReader(sys.argv[1]):  # Using generator to avoid loading 350MB file into mem at once
        if pkt.haslayer(Ether) and pkt.haslayer(IP) and pkt.haslayer(TCP):
            if pkt[TCP].flags == 'S':  # SYN - Sent packet
                ip = pkt[IP].src
                sent[ip] += 1

            elif pkt[TCP].flags == 'SA':  # SYN-ACK - Sent packet acknowledgement
                ip = pkt[IP].dst
                received[ip] += 1

    for ip in sent.keys():
        if sent[ip] > received[ip] * ratio:
            print(ip)


if __name__ == '__main__':
    main()
