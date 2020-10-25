import socket
import time
import decipher_module
import csv
import random


server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_socket.bind(('', 4096))
server_socket.listen(3)
connection, peerAddress = server_socket.accept()
connection.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

name = connection.recv(1024)
name = name.decode('UTF-8')
name = name[0:-1]

# Exchange secret for initial session key
other_pub = connection.recv(1024)
other_pub = other_pub.decode('UTF-8')
other_pub = int(other_pub[0:-1])
pr = random.randint(1, 20)
pub = int(pow(11, pr)) % 218
connection.send(str(pub).encode('UTF-8'))
shared_secret = int(pow(other_pub, pr)) % 218

name2key_file = open('name2key.csv', 'r')
reader = csv.reader(name2key_file)
table = list(reader)
username_row = 0

pub_key = 0
pr_key = 0
for i in range(0, len(table)):
    if table[i][0] == name:
        DH_pub_key = table[i][1]
        pr_key = table[i][2]
        username_row = i
        break
c = decipher_module.Decipher(str(shared_secret).encode('UTF-8'))
name2key_file.close()


while True:
    message = connection.recv(1024)
    received_buffer = bytearray(message)
    received_blocks = received_buffer.split(b'*')
    for b in received_blocks:
        if b != b'':
            c.ciphered_blocks.put(bytes(b))
            if c.cbc_decipher():
                connection.send('ACK'.encode('UTF-8'))
            else:
                connection.send('NACK'.encode('UTF-8'))
    if not message:
        print("connection closed")
        break

file = open('received_file', 'wb')
while not c.plain_blocks.empty():
    file.write(c.plain_blocks.get())
file.close()

