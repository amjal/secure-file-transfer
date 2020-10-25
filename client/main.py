from cryptography.fernet import Fernet
import socket
import csv
import cipher_module
import network_module
import random
import time

name2address_table_file = open('name2address.csv', 'r')
reader = csv.reader(name2address_table_file)
# convert it from csv to list
name2address_table = list(reader)
name2address_table_file.close()

name2key_table_file = open('name2key.csv', 'r')
reader = csv.reader(name2key_table_file)
# convert it from csv to list
name2key_table = list(reader)
name2key_table_file.close()

# ------------------------------------------------------------------
# Get the name of the process that wants to connect
process = input()
# Default for remote address is 127.0.0.1
remote_addr = '127.0.0.1'
public_key = 0
private_key = 0
# Find the process name and it's corresponding address, public key and our private key in the table
for i in range(0, len(name2address_table)):
    if name2address_table[i][0] == process:
        remote_addr = name2address_table[i][1]
    if name2key_table[i][0] == process:
        public_key = name2key_table[i][1]
        private_key = name2key_table[i][2]

# Now we have everything we need to make a connection
n = network_module.Network(remote_addr)
# Send the username so server can find the right physical key
n.tobesent_messages.put(process.encode('UTF-8'))
n.send(False)

# Get address of the file to send
data_file_address = input()
data_file = open(data_file_address, 'rb')
# read the contents of the file into the RAM as a string
data = data_file.read()
data_file.close()

# Exchange secret for initial session key
pr = random.randint(1, 20)
pub = int(pow(11, pr)) % 218
n.tobesent_messages.put(str(pub).encode('UTF-8'))
n.send(False)
n.receive()
other_pub = int(n.received_messages.get().decode('UTF-8'))
shared_secret = int(pow(other_pub, pr)) % 218
c = cipher_module.Cipher(data, 128, str(shared_secret).encode('UTF-8'))

# when cbc is called for the first time, because last generation time is set to 0,
# a new session key is immediately generated
c.cbc()
n.tobesent_messages = c.ciphered_blocks
while not n.tobesent_messages.empty():
    n.send(True)
