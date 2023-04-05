import sys
import secrets
import time
import socket
import random
import hashlib
from Crypto.Protocol.SecretSharing import Shamir
from Crypto.Random import get_random_bytes

public_key = b"""
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1Oi1vEfh9qdKQ2oPRIdy0Yb98I5F
a3e5ao5Z5z5jRvVVX9C5Ev4dd4y4PVtJtnwR1DpafA5rLlb07oZPQvJ7ZA==
-----END PUBLIC KEY-----
"""

def generate_ephid(public_key):
    hash_object = hashlib.sha256(public_key)
    ephid = hash_object.digest().hex()
    return ephid[:16]

def generate_shares(ephid, k, n):
    shares = Shamir.split(k,n,ephid.encode())
    return shares

def hash_message_md5(message):
    # Create an MD5 hash object
    md5_hasher = hashlib.md5()
    # Encode the message as bytes and update the hash object with the message
    md5_hasher.update(message.encode('utf-8'))
    # Return the hexadecimal representation of the hashed message
    return md5_hasher.hexdigest()

while True:
    BROADCAST_IP = "0.0.0.0"
    UDP_PORT = 9999
    listeningADDR = (BROADCAST_IP, UDP_PORT)

    ephid = generate_ephid(public_key)
    print(ephid)
    time.sleep(15)

    k = 3
    n = 5
    shares = generate_shares(ephid, n, k)
    print(shares)
    randomNo = random.random()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Create a UDP socket
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)  # Enable broadcasting
    #sock.bind(listeningADDR)  
    shares_value = str()
    hashed = hash_message_md5(str(shares_value))

    for share in shares:
        shares_value += str(share) + " "
    
    if randomNo < 0.5:
        sock.sendto(shares_value.encode(), (listeningADDR))
        sock.sendto(hashed.encode(), (listeningADDR))
        sock.close()

    time.sleep(3)