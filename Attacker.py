from binascii import hexlify
from secrets import token_bytes, randbits
from random import random, randint
import sys
import time
import socket
import threading
import hashlib
import os.path
import numpy as np
from collections import defaultdict
from binascii import unhexlify
from datetime import datetime
from Crypto.PublicKey import ECC
from pycryptodome.lib.Crypto.Protocol.SecretSharing import Shamir
from BloomFilter import BloomFilter

np.set_printoptions(threshold=6)
def catch(msg):
    print("Exception caught: " + msg)
    if peerSoc:
        peerSoc.close()
    if clientSoc:
        clientSoc.close()
    sys.exit(1)

if len(sys.argv) != 3:
    print("Usage: python3 client.py server_IP server_port")
    sys.exit(1)

cycle_time = 15
COVID_chance = 200000
COVID_rng = randint(1, COVID_chance)
k_out_of_n_k = 3
k_out_of_n_n = 5
bloom_k = 3
bloom_m = int(8 * 100e3)
drop_prob = 0.5
sha_digest_len = 24
bc_port = 5500
bc_addr = ("255.255.255.255", bc_port)
shares_dict = defaultdict(list)
sent_data = None
my_eph_id = None
my_private_key = None
common_point_dir = '.'
common_point_name = 'common_point.pem'
common_point_path = os.path.join(common_point_dir, common_point_name)
public_key_dir = 'public_keys'
attack_flag = 0
attacked_list = []

if not os.path.exists(public_key_dir):
    print("Creating public keys dir...")
    os.mkdir(public_key_dir)

if not os.path.isfile(common_point_path):
    elliptic_curve = ECC.generate(curve='ed25519')
    with open('common_point.pem', 'wt') as f:
        f.write(elliptic_curve.export_key(format='PEM'))
else:
    with open('common_point.pem', 'rt') as f:
        elliptic_curve = ECC.import_key(f.read())

point_g = elliptic_curve.pointQ
broadcast_timer = None
DBF_bloom_counter = 0
DBF_bloom = BloomFilter(bloom_m, bloom_k)
DBF_bloom_list = list()
QBF_bloom = BloomFilter(bloom_m, bloom_k)
QBF_bloom_list = list()
QBF_bloom_counter = 0
CBF_bloom = None
timeout = 15
server_IP = sys.argv[1]
server_port = int(sys.argv[2])
ser_addr = (server_IP, server_port)
clientSoc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
clientSoc.settimeout(timeout)
try:
    clientSoc.connect(ser_addr)
except TimeoutError:
    catch("Connection timed out")
except ConnectionRefusedError:
    catch("Connection refused by server")
except socket.error as e:
    catch(str(e))

def task_1_gen_id():
    #return token_bytes(32)
    return randbits(256)

def task_2_prepare_n_chunks(my_eph_id):
    shares = Shamir.split(k_out_of_n_k, k_out_of_n_n, my_eph_id)
    for idx, share in shares:
        print("Index #%d: %s" % (idx, hexlify(share[:6])))
    return shares    

def task_3_broadcast(shares, my_eph_id_hash_no):
    global sent_data
    global broadcast_timer
    for share in shares:
        sent_index = share[0].to_bytes(1, byteorder='big')
        sent_data = share[1]
        rng = random()
        if rng >= drop_prob:
            peerSoc.sendto(my_eph_id_hash_no.encode() + sent_index + sent_data, bc_addr)
        while time.time() - broadcast_timer < cycle_time / 5:
            pass
        broadcast_timer = time.time()
    
def task_4_reconstruct(serial, shares_dict):
    print()
    print(f"{serial} has {k_out_of_n_k} shares! reconstructing...")
    key = Shamir.combine(shares_dict[serial])
    print(f"The original my_eph_id is {str(hexlify(key)[:6])}")
    print()
    return key

def task_4_verify(origin_eph_id, serial):
    origin_eph_id_hash = hashlib.sha256(origin_eph_id)
    origin_eph_id_hash_no = origin_eph_id_hash.hexdigest()[:sha_digest_len]
    if origin_eph_id_hash_no == serial:
        print("ephID verified with hash, match with advertisement")
        return True
    else:
        print("ephID verification failed! discarding...")
        return False

def task_5_diffie_hellman(serial):
    public_key_file = str(serial.decode()) + '.pem'
    public_key_path = os.path.join(public_key_dir, public_key_file)
    with open(public_key_path, 'rb') as f:
        public_key_x = f.read(32)
        public_key_y = f.read(32)
    public_curve = ECC.construct(curve='ed25519', point_x=int.from_bytes(public_key_x, "big"), point_y=int.from_bytes(public_key_y, "big"))
    public_point = public_curve.pointQ
    encounter_id = (my_private_key * public_point).x
    print(f"Encounter_id is {hex(encounter_id)[2:2+6]}")
    return encounter_id

def task_6_encode_encid(enc_id):
    global DBF_bloom
    global DBF_bloom_counter
    print("Bloom filter before: ", end = "")
    print(np.array(DBF_bloom.seek()))
    DBF_bloom.add(enc_id.to_bytes(32, 'big'))
    enc_id = None
    print("Bloom filter after: ", end = "")
    print(np.array(DBF_bloom.seek()))
    return enc_id

def task_7_store_DBF():
    global DBF_bloom
    global DBF_bloom_list
    global DBF_bloom_counter
    global QBF_bloom_counter
    if DBF_bloom_counter == 6:
        if len(DBF_bloom_list) == 6:
            DBF_bloom_list.pop(0)
        DBF_bloom_list.append(DBF_bloom)
        DBF_bloom = BloomFilter(bloom_m, bloom_k)
        DBF_bloom_counter = 0
        QBF_bloom_counter += 1
        print()
        print("DBF bloom list: ", end='')
        print(DBF_bloom_list)

def upload_bloom_filter(bloom_filter_bit_array):
    clientSoc.sendall(bloom_filter_bit_array)

def task_8_gen_QBF():
    global DBF_bloom
    global DBF_bloom_list
    global QBF_bloom
    global QBF_bloom_list
    global QBF_bloom_counter
    
    if QBF_bloom_counter == 6:
        for temp_DBF_bloom in DBF_bloom_list:
            QBF_bloom_bit_array = QBF_bloom.bit_array | temp_DBF_bloom.bit_array
            QBF_bloom.set(QBF_bloom_bit_array)
        print("Updated QBF Bloom: ", end='')
        print(np.array(QBF_bloom.seek()))
        QBF_bloom_list.append(QBF_bloom)
        QBF_bloom = BloomFilter(bloom_m, bloom_k)
        QBF_bloom_counter = 0
        clientSoc.sendall('Q'.encode())
        upload_bloom_filter(QBF_bloom_bit_array)
        print()
        print(clientSoc.recv(1024).decode())

        
def gen_CBF():
    global DBF_bloom_list
    global CBF_bloom
    CBF_bloom = BloomFilter(bloom_m, bloom_k)
    for temp_DBF_bloom in DBF_bloom_list:
        CBF_bloom_bit_array = CBF_bloom.bit_array | temp_DBF_bloom.bit_array
        CBF_bloom.set(CBF_bloom_bit_array)
    print("Updated CBF Bloom: ", end='')
    print(np.array(CBF_bloom.seek()))
    clientSoc.sendall('C'.encode())
    upload_bloom_filter(CBF_bloom_bit_array)
    print()
    print(clientSoc.recv(1024).decode())

def recv():
    global DBF_bloom
    global DBF_bloom_list
    global QBF_bloom
    global attack_flag
    global sent_data
    while True:
        data, addr = peerSoc.recvfrom(1024)
        serial = data[:sha_digest_len]
        index = data[sha_digest_len:sha_digest_len + 1]
        index = int.from_bytes(index, "big")
        data = data[sha_digest_len + 1:]
        if data != sent_data and not attack_flag:
            shares_dict[serial].append((index, data))
            print()
            print("Received share " + str(index))
            print("hash: " + str(serial.decode()))
            print("data: " + str(hexlify(data)[:6]))
            if len(shares_dict[serial]) == k_out_of_n_k:
                origin_eph_id = task_4_reconstruct(serial, shares_dict)
                verify_success = task_4_verify(origin_eph_id, serial.decode())
                if not verify_success:
                    continue
                if not my_private_key:
                    continue
                enc_id = task_5_diffie_hellman(serial)
                enc_id = task_6_encode_encid(enc_id)

        if attack_flag and serial not in attacked_list:
            bogus_data = b'\xf0\x01' * 16
            sent_data = bogus_data
            bogus_eph_id_hash_no = serial
            bogus_index = 6
            print(f"sent forged share {bogus_index}: {bogus_data[:6]} targeting {bogus_eph_id_hash_no}\n")
            bogus_index = bogus_index.to_bytes(1, byteorder='big')
            peerSoc.sendto(bogus_eph_id_hash_no + bogus_index + bogus_data, bc_addr)
            attacked_list.append(serial)

            


def send():
    global my_private_key
    global my_eph_id
    global broadcast_timer
    global DBF_bloom
    global DBF_bloom_list
    global DBF_bloom_counter
    global QBF_bloom
    global QBF_bloom_counter
    global CBF_bloom
    have_COVID = False
    while True:
        while datetime.now().second % cycle_time  != 0:
            pass
    
        if not broadcast_timer:
            broadcast_timer = time.time()
        my_private_key = task_1_gen_id()
        public_key = (my_private_key * point_g)
        my_eph_id = public_key.x.to_bytes(32, "big")
        print()
        print(f"my_eph_id is {hex(public_key.x)[2:2+6]}")
        shares = task_2_prepare_n_chunks(my_eph_id)
        my_eph_id_hash = hashlib.sha256(my_eph_id)
        my_eph_id_hash_no = my_eph_id_hash.hexdigest()[:sha_digest_len]
        print(f"Hash(eph_id) = {my_eph_id_hash_no}")
        public_key_name = my_eph_id_hash_no + '.pem'
        public_key_path = os.path.join(public_key_dir, public_key_name)
        with open(public_key_path, 'wb') as f:
            f.write(b''.join((public_key.x.to_bytes(32, "big"), public_key.y.to_bytes(32, "big"))))
        task_3_broadcast(shares, my_eph_id_hash_no)
        
        DBF_bloom_counter += 1

        task_7_store_DBF()
        if (randint(1, COVID_chance) != COVID_rng and not have_COVID) or not DBF_bloom_list:
            task_8_gen_QBF()
        elif not have_COVID:
                gen_CBF()
                have_COVID = True
        elif QBF_bloom_counter == 6 and have_COVID:
            print("QBF not generated.")
            QBF_bloom_counter = 0
        if os.path.isfile(public_key_path):
            os.remove(public_key_path)

try:
    peerSoc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    peerSoc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    peerSoc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    peerSoc.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    peerSoc.bind(("", bc_port))
    myHostName = socket.gethostname()
    myIP = socket.gethostbyname(myHostName)
    print(f"The client address is {myIP}")
except socket.error as e:
    catch(str(e))

print("Initialising...")
sim_start = time.time()
t1 = threading.Thread(target=recv)
t2 = threading.Thread(target=send)
t1.start()
t2.start()
while time.time() - sim_start < 11 * 60:
    pass
print("Task 11")
print("Attack started...\n")
attack_flag = 1
