import socket
import hashlib


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

while True:
    data, addr = sock.recvfrom(1024)  # Receive up to 1024 bytes from the client
    print(data.decode())
