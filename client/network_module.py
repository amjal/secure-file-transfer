import socket
import queue
import time


class Network:
    tobesent_messages = queue.Queue()
    received_messages = queue.Queue()

    def __init__(self, remote_addr):
        self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connection.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.connection.connect((remote_addr, 4096))

    def send(self, ack_required):
        if not self.tobesent_messages.empty():
            message = self.tobesent_messages.get()
            # turn message into bytearray and append * to it so destination can separate blocks
            temp_bytearray = bytearray(message)
            temp_bytearray.append(ord('*'))
            self.connection.send(bytes(temp_bytearray))
            while ack_required and (not self.get_ack()):
                self.connection.send(bytes(temp_bytearray))

    def get_ack(self):
        ack_message = self.connection.recv(1024)
        ack_message = ack_message.decode('UTF-8')
        if ack_message == 'ACK':
            return True
        else:
            return False

    def receive(self):
        message = self.connection.recv(1024)
        self.received_messages.put(message)
