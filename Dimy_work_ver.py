import sys
import secrets
import time
import socket
import random
import hashlib
import subrosa
import threading

#randomly gen EphID 1 time at each node

def generate_ephid():
    ephid = ''.join(random.choices("0123456789abcdef", k=32))
    return ephid


def generate_shares(ephid, k, n):
    shares = subrosa.split_secret(ephid.encode(), k, n)
    return shares


def send_broadcast():
    flag = 0
    time.sleep(1)
    while True:
        BROADCAST_IP = "0.0.0.0"
        UDP_PORT = 9999
        listeningADDR = (BROADCAST_IP, UDP_PORT)

        ephid = generate_ephid()
        k = 3
        n = 5
        shares = generate_shares(ephid, k, n)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        for i in shares:
            randomNo = random.random()
            if randomNo < 0.5:
                sock.sendto(str(flag).encode() + bytes(i), (listeningADDR))
            time.sleep(3)
        flag += 1
        

def split_secret(secret, k=3, n=5):
    shares = subrosa.split_secret(secret, k, n)
    return shares


def recover_secret(shares):
    recovered_message = subrosa.recover_secret(shares)
    return recovered_message


def receive_broadcast(node_name):
    UDP_IP = "0.0.0.0"
    UDP_PORT = 9999
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((UDP_IP, UDP_PORT))

    print("Node {} is listening for UDP packets on {}:{}".format(node_name, UDP_IP, UDP_PORT))

    shares_list = []
    current_flag = -1
    
    while True:
        data, addr = sock.recvfrom(1024)
        share = subrosa.Share.from_bytes(data[1:])
        flag = int(data[0])
        shares_list.append(share)
        
        if len(shares_list) >= 3 and flag > current_flag:
            try:
                ephid_bytes = recover_secret(shares_list[:3])
                ephid = ephid_bytes.decode()
                print("Node {} recovered ephID: {}".format(node_name, ephid))
            except ValueError:
                pass
            shares_list = shares_list[-3:]
            current_flag = flag


if __name__ == '__main__':
    node_names = ['A', 'B', 'C']
    threads = []
    for i in range(3):
        node_name = node_names[i]
        send_thread = threading.Thread(target=send_broadcast)
        receive_thread = threading.Thread(target=receive_broadcast, args=(node_name,))
        threads.append(send_thread)
        threads.append(receive_thread)
        
    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()