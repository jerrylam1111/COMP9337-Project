import sys
import secrets
import time
import socket
import random
from Crypto.Protocol.SecretSharing import Shamir
from Crypto.Random import get_random_bytes

def generate_ephid():
    return get_random_bytes(16)

def generate_shares(ephid, n, k):
    shares = Shamir.split(k,n,ephid)
    return shares

while True:
    BROADCAST_IP = "0.0.0.0"
    UDP_PORT = 9999
    listeningADDR = (BROADCAST_IP, UDP_PORT)

    ephid = generate_ephid()
    print("Ephemeral ID: " + str(ephid))
    time.sleep(1)

    k = 3
    n = 5
    shares = generate_shares(ephid, n, k)
    randomNo = random.random()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Create a UDP socket
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)  # Enable broadcasting
    #sock.bind(listeningADDR)
    shares_value = str()

    for share in shares:
        shares_value += str(share) + " "
    
    if randomNo < 0.5:
        print(randomNo)
        sock.sendto(shares_value.encode(), (listeningADDR))
        sock.close()

    time.sleep(3)