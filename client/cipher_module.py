import time
import queue
from cryptography.fernet import Fernet
import string
import random
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import hashlib


class Cipher:
    letters = string.ascii_letters
    # Session keys are put here also
    ciphered_blocks = queue.Queue()

    def __init__(self, data, block_size, shared_secret):
        random.seed(time.time())
        self.sha = hashlib.sha256()
        # last generation time is set to 0 which means -inf. because the initial session key is physical key and
        # is only valid for the first transaction of real session keys
        self.last_generation_time = 0
        self.block_size = block_size
        self.data_size = len(data)
        self.data = data
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=bytes(1),
            iterations=100000,
            backend=default_backend()
        )
        initial_session_key = base64.urlsafe_b64encode(kdf.derive(bytes(shared_secret)))
        self.current_session_key = initial_session_key
        self.IV = 0

    # cipher the data given, using cipher block-chaining
    def cbc(self):
        # slice data into some blocks
        plain_blocks = [self.data[i: i + self.block_size] for i in range(0, self.data_size, self.block_size)]
        # IV is the initial value but also gets updated and is always one side of xor
        self.IV = self.generate_IV()
        for block_index in range(len(plain_blocks)):
            if time.time() - self.last_generation_time > 60:
                self.generate_session_key()
            plain_blocks[block_index] = Cipher.bxor(plain_blocks[block_index], self.IV)
            plain_blocks[block_index] = bytes(self.append_hmac(bytearray(plain_blocks[block_index])))
            f = Fernet(self.current_session_key)
            cipher_block = f.encrypt(plain_blocks[block_index])
            self.ciphered_blocks.put(cipher_block)
            self.IV = cipher_block

    def append_hmac(self, message):
        # insert block digest after '...'
        self.sha.update(message)
        message.append(ord('.'))
        message.append(ord('.'))
        message.append(ord('.'))
        message.extend(bytearray(self.sha.digest()))
        return message

    def generate_session_key(self):
        new_key = Fernet.generate_key()
        key_message = bytearray(new_key)
        # '***' is signature for key-containing messages
        key_message = bytearray(Cipher.bxor(key_message, self.IV))
        key_message[0:0] = b'***'
        key_message = self.append_hmac(key_message)
        f = Fernet(self.current_session_key)
        m = f.encrypt(bytes(key_message))
        self.ciphered_blocks.put(m)
        self.current_session_key = new_key
        self.last_generation_time = time.time()

    # generates, packets and puts IV into sending ciphered blocks queue
    def generate_IV(self):
        f = Fernet(self.current_session_key)
        IV = ''.join(random.choice(self.letters) for i in range(self.block_size))
        IV = IV.encode('UTF-8')
        IV_message = bytearray(IV)
        # '**' is signature for IV-containing messages
        IV_message[0:0] = b'**'
        IV_message = self.append_hmac(IV_message)
        # Note that IV is not xored with anything when ciphered
        m = f.encrypt(bytes(IV_message))
        self.ciphered_blocks.put(m)
        return IV

    @staticmethod
    def bxor(b1, b2):
        parts = []
        for b1, b2 in zip(b1, b2):
            parts.append(bytes([b1 ^ b2]))
        return b''.join(parts)