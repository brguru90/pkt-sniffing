import socket
import sys


ETH_P_ALL = 3
ETH_P_IP = 0x800 
# Create a TCP/IP socket
sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,socket.htons(ETH_P_ALL))

# Bind the socket to the port
server_address = ('wlp2s0', 0)
print (server_address, 'starting up ')
sock.bind(server_address)

# Listen for incoming connections
# sock.listen(1)

while True:
    print(repr(sock.recv(4096).decode("iso-8859-1")))