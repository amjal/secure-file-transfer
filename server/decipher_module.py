import queue
from cryptography.fernet import Fernet
import base64
import hashlib
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class Decipher:
    ciphered_blocks = queue.Queue()
    plain_blocks = queue.Queue()

    def __init__(self, shared_secret):
        self.sha = hashlib.sha256()
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

    def cbc_decipher(self):
        while not self.ciphered_blocks.empty():
            ciphered_block = self.ciphered_blocks.get()
            f = Fernet(self.current_session_key)
            middle_plain = f.decrypt(ciphered_block)
            middle_plain = bytearray(middle_plain).split(b'...')
            middle_plain_digest = middle_plain[1]
            middle_plain = bytes(middle_plain[0])
            if not self.check_hmac(bytearray(middle_plain), middle_plain_digest):
                return False
            if middle_plain[0:3] == b'***':
                self.current_session_key = Decipher.bxor(self.IV, middle_plain[3:len(middle_plain)])
            elif middle_plain[0:2] == b'**':
                self.IV = middle_plain[2:len(middle_plain)]
            else:
                self.plain_blocks.put(Decipher.bxor(self.IV, middle_plain))
                self.IV = ciphered_block
        return True

    def check_hmac(self, middle_plain, given_digest):
        self.sha.update(middle_plain)
        if self.sha.digest() == bytes(given_digest):
            return True
        else:
            return False


    @staticmethod
    def bxor(b1, b2):
        parts = []
        for b1, b2 in zip(b1, b2):
            parts.append(bytes([b1 ^ b2]))
        return b''.join(parts)
