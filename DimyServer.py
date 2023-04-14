import socket
import hashlib
import re
from Crypto.Protocol.SecretSharing import Shamir

UDP_IP = "0.0.0.0"
UDP_PORT = 9999

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Create a UDP socket
sock.bind((UDP_IP, UDP_PORT))  # Bind the socket to the specified IP and port

print("Listening for UDP packets on {}:{}".format(UDP_IP, UDP_PORT))
hash_list = []
current_flag = 0
while True:
    data, addr = sock.recvfrom(1024)  # Receive up to 1024 bytes from the client
    print(data)
