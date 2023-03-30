import sys
import secrets
import time
import socket
import Crypto.Protocol.SecretSharing as Shamir

def generate_ephid():
    return secrets.token_hex(32)

def gernerate_shares(ephid, n, k):
    return Shamir.split(k,n,ephid)

k = 3
n = 5



while True:
    BROADCAST_IP = "0.0.0.0"
    UDP_PORT = 5000
    listeningADDR = (BROADCAST_IP, UDP_PORT)

    ephid = generate_ephid()
    print("Ephemeral ID: " + ephid)
    time.sleep(1)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Create a UDP socket
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)  # Enable broadcasting
    sock.bind(listeningADDR)

    sock.sendto(ephid, (listeningADDR))
    sock.close()
    time.sleep(3)

