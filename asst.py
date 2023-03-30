import sys
import secrets
import time


def generate_ephid():
    return secrets.token_hex(32)

while True:
    ephid = generate_ephid()
    print("Ephemeral ID: " + ephid)

    time.sleep(15)