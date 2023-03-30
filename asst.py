import sys
import secrets
import time
import socket
import Crypto.Protocol.SecretSharing as Shamir

def generate_ephid():
    return secrets.token_hex(32)

def gernerate_shares(ephid, n, k):
    return Shamir.split(k,n,ephid)

while True:
    ephid = generate_ephid()
    print("Ephemeral ID: " + ephid)

    time.sleep(15)