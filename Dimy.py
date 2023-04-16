import sys
import secrets
import time
import socket
import random
import hashlib
#from Crypto.Protocol.SecretSharing import Shamir
import subrosa
from Crypto.Random import get_random_bytes
import threading


def generate_ephid():
    ephid = ''.join(random.choices("0123456789abcdef", k=32))
    return ephid

def generate_shares(ephid, k, n):
    shares = subrosa.split_secret(ephid.encode(), k, n)
    print(shares)
    return shares

def send_broadcast():
    flag = 0
    time.sleep(1)
    while True:
        
        BROADCAST_IP = "0.0.0.0"
        UDP_PORT = 9999
        listeningADDR = (BROADCAST_IP, UDP_PORT)

        ephid = generate_ephid()
        #print(f"ID={ephid}")

        #for i in range(5):
        k = 3
        n = 5
        shares = generate_shares(ephid, k, n)
        #print(shares)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Create a UDP socket
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)  # Enable broadcasting
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        #sock.sendto(hashed.encode(), (listeningADDR))
        for i in shares:
            randomNo = random.random()
            if randomNo < 0.5:
                #print(i)
                sock.sendto(str(flag).encode() + str(i).encode(), (listeningADDR))
            time.sleep(3)
        flag += 1
        
def split_secret(secret, k=3, n=5):
    shares = subrosa.split_secret(secret, k, n)
    return shares

def recover_secret(shares):
    recovered_message = subrosa.recover_secret(shares)
    return recovered_message


def receive_broadcast():
    UDP_IP = "0.0.0.0"
    UDP_PORT = 9999
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Create a UDP socket
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((UDP_IP, UDP_PORT))  # Bind the socket to the specified IP and port

    print("Listening for UDP packets on {}:{}".format(UDP_IP, UDP_PORT))

    shares_list = []
    current_flag = -1
    
    while True:
        data, addr = sock.recvfrom(1024)  # Receive up to 1024 bytes from the client
        
        flag = int(data[0])
        share = subrosa.Share.from_bytes(data[1:])
        
        if flag != current_flag:
            current_flag = flag
            shares_list = []
            
        shares_list.append(share)
        
        if len(shares_list) == 3:
            try:
                message_bytes = recover_secret(shares_list)
                message = message_bytes.decode()
                print("Recovered message: {}".format(message))
            except ValueError as e:
                print("Error recovering message: {}".format(str(e)))

                
# def receive_broadcast():

#     UDP_IP = "0.0.0.0"
#     UDP_PORT = 9999
#     sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Create a UDP socket
#     sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
#     sock.bind((UDP_IP, UDP_PORT))  # Bind the socket to the specified IP and port

#     print("Listening for UDP packets on {}:{}".format(UDP_IP, UDP_PORT))
#     hash_list = []
#     current_flag = 0
    
#     while True:
#         data, addr = sock.recvfrom(1024)  # Receive up to 1024 bytes from the client
        
#         flag = int(data[0])
#         data = data.decode()[1:]


#         if flag > current_flag:
#             hash_list = [data]
#             current_flag = flag
#         elif flag == current_flag:
#             hash_list.append(data)


#         if len(hash_list) == 3:
#             #finish here
#             combined_id = subrosa.recover_secret(selected)
#             print(f"Combined = {combined_id}")
            

send_thread = threading.Thread(target=send_broadcast)
receive_thread = threading.Thread(target=receive_broadcast)

send_thread.start()
receive_thread.start()

send_thread.join()
receive_thread.join()