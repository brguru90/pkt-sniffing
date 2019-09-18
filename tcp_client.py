import socket
import sys


# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect the socket to the port where the server is listening
server_address = ('192.168.0.56', 8888)
print ('connecting ')
sock.connect(server_address)
flag=True
while True:
    amount_received = 0
    amount_expected = len(message)
    
    while amount_received < amount_expected:
        data = sock.recv(1024)
        amount_received += len(data)
        print (data.decode())
        if data.decode()=="e":
            print ('closing socket')
            sock.close()
            exit()
    
