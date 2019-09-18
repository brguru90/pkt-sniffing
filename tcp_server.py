import socket
import sys
from struct import *

# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM )

# Bind the socket to the port
server_address = ('localhost', 8888)
print (server_address, 'starting up ')
sock.bind(server_address)
sock.listen(1)
connection, client_address = sock.accept()
print(connection)

while True:
    # print(repr(sock.recvfrom(8888)))
    packet = connection.recv(8888)
    packet = packet[0]
    ip_header = packet[0:20]
    iph = unpack('!BBHHHBBH4s4s' , ip_header)
    version_ihl = iph[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF
    iph_length = ihl * 4
    # print(iph)
    tcp_header = packet[iph_length:iph_length+20]
    tcph = unpack('!HHLLBBHHH' , tcp_header)
    doff_reserved = tcph[4]
    tcph_length = doff_reserved >> 4
    # print("TCP HEADER: \n"+str(tcph))
    source_port = tcph[0]
    dest_port = tcph[1]
    sequence = tcph[2]
    acknowledgement = tcph[3]
    doff_reserved = tcph[4]
    tcph_length = doff_reserved >> 4
    print('Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length))
    h_size = iph_length + tcph_length * 4
    data_size = len(packet) - h_size
    data = packet[h_size:]
    print("DATA :\n"+str(data.decode("iso-8859-1")))
# Listen for incoming connections
# sock.listen(1)

# while True:
#     # Wait for a connection
#     print ( 'waiting for a connection')
#     connection, client_address = sock.accept()
    
#     try:
#         print ('connection from', client_address)
#         while True:
#             data = connection.recv(1024).decode()
#             print(data)
#     finally:
#         # Clean up the connection
#         connection.close()