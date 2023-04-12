import socket
import hashlib
import re
from Crypto.Protocol.SecretSharing import Shamir

UDP_IP = "0.0.0.0"
UDP_PORT = 9999

public_key = b"""
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1Oi1vEfh9qdKQ2oPRIdy0Yb98I5F
a3e5ao5Z5z5jRvVVX9C5Ev4dd4y4PVtJtnwR1DpafA5rLlb07oZPQvJ7ZA==
-----END PUBLIC KEY-----
"""

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Create a UDP socket
sock.bind((UDP_IP, UDP_PORT))  # Bind the socket to the specified IP and port

print("Listening for UDP packets on {}:{}".format(UDP_IP, UDP_PORT))
hash_list = []
current_flag = 0
while True:
    data, addr = sock.recvfrom(1024)  # Receive up to 1024 bytes from the client
    flag = int(chr(int(str(data[0]))))
    data = (int(chr(int(str(data[1])))), data[2:])
    # data[1]=""
    # data[-2]=""
    print(data)
    if flag > current_flag:
        hash_list = [data]
        current_flag = flag
    elif flag == current_flag:
        hash_list.append(data)
    #hash_list.append(data)
    if len(hash_list) == 3:
        #reconstruct()

        # hash_list = str(hash_list)
        # print(hash_list)
        # print(hash_list)
        # hash_list = re.sub("\"([0-9]", "([0-9]", hash_list)
        #hash_list = re.sub("\"", "", hash_list,flags=1)
        # hash_list = hash_list.replace('"([0-9]', '([0-9]')
        # hash_list = hash_list.replace('b\'', '')
        # hash_list = hash_list.replace('\'', '')
        print(hash_list)
        combined_id = Shamir.combine(hash_list)
        print(f"Combined = {combined_id}")