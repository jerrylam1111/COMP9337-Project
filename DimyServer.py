import sys
import socket
import threading
import time
import numpy as np
from bitarray import bitarray
from BloomFilter import BloomFilter

def catch(msg):
    print("Exception caught: " + msg)
    if serverSoc:
        serverSoc.close()
    sys.exit(1)

if len(sys.argv) != 2:
    print("Usage: python3 server.py server_port")
    sys.exit(0)


eng_dict = {1: "1st", 2: "2nd", 3: "3rd"}
server_port = int(sys.argv[1])
buffer_size = 1000
bloom_m = int(8 * 100e3)
bloom_k = 3
CBF_bloom_list = list()

class ClientThread(threading.Thread):
    def __init__(self, conn, addr):
        threading.Thread.__init__(self)
        self.kill_received = False
        self.conn = conn
        self.addr = addr
        self.i = 0
        self.bloom_data = bitarray()
        self.BF = BloomFilter(bloom_m, bloom_k)

    def run(self):
        print(f"New connection from {self.addr}")
        while True:
            temp = bitarray()
            if self.i == 0:
                mode = self.conn.recv(1)
                time.sleep(0.01)
                mode = mode.decode()
                self.bloom_data = bitarray()
                recv_bitarray = bitarray()
            temp.frombytes(self.conn.recv(buffer_size))
            time.sleep(0.01)
            recv_bitarray = temp
            if recv_bitarray:
                self.i += 1
                self.bloom_data += recv_bitarray
                if self.i == 100:
                    self.i = 0
                    self.BF.set(self.bloom_data)

                    if mode and mode == 'C':
                        print("Task 9")
                        CBF_bloom_list.append(self.BF)
                        if len(CBF_bloom_list) in eng_dict:
                            word = eng_dict[len(CBF_bloom_list)]
                        else:
                            word = str(len(CBF_bloom_list)) + "th"
                        confirm_msg = f"\nUpload success! You are the {word} person to catch COVID"
                        self.conn.sendall(confirm_msg.encode())
                        print(f"CBF received from {self.addr}")
                        time.sleep(0.01)
                    elif mode and mode == 'Q':
                        print("Task 10")
                        print(f"QBF received from {self.addr}")
                        if not CBF_bloom_list:
                            self.conn.sendall("Your QBF does not match any CBF in the database".encode())
                        else:
                            temp_bitarray = bitarray(bloom_m)
                            matched = False
                            for temp_BF in CBF_bloom_list:
                                temp_bitarray = temp_BF.bit_array & self.BF.bit_array
                                if temp_bitarray.count(1) > 0:
                                    self.conn.sendall(f"Your QBF has a {temp_bitarray.count(1)}-bit match with another CBF in the database\nMatching bits: {str(np.array((temp_bitarray.search(bitarray('1')))))}".encode())
                                    matched = True
                            if not matched:
                                self.conn.sendall("Your QBF does not match any CBF in the database".encode())

                    elif mode:
                        print(f"{mode}")

                    self.bloom_data = bitarray()
                    self.i = 0

try:
    serverPort = int(sys.argv[1])
except ValueError:
    catch(f"Invalid server_port: {sys.argv[1]}")
try:
    serverSoc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if serverSoc is None:
        catch("Could not open socket")
    myHostName = socket.gethostname()
    myIP = socket.gethostbyname(myHostName)
    print(f"The server IP address is {myIP}")
except socket.error as e:
    print(str(e))

serverSoc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
serverSoc.setsockopt(socket.SOL_SOCKET, socket.SO_USEPORT, 1)

try:
    serverSoc.bind((myIP, server_port))
except OSError as e:
    catch(f"Port {server_port} is already in use")

threads = []

while True:
    try:
        serverSoc.listen(5)
        conn, addr = serverSoc.accept()
    except socket.error as e:
        serverSoc.close()
        catch(str(e))
    except KeyboardInterrupt as e:
        for t in threads:
            t.kill_received = True
        if serverSoc:
            serverSoc.close()
        sys.exit(e)

    newThread = ClientThread(conn, addr)
    newThread.daemon = True
    newThread.start()
    threads.append(newThread)

    #share = serverSoc.recv(buffer_size)
    #print(share.decode("latin-1"))
    #except socket.error as e:
    #   print(str(e))

