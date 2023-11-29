from Crypto.Hash import SHA256
import math
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util import strxor
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.strxor import strxor
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import json, time, ast
import random

class Encryption():
    
    def hash_256(self,message):
        sha_256 = SHA256.new(message).digest()
        return sha_256


    def encrypt(self,message: bytes, Key: bytes, IV: bytes):
        batch_size = 32
        msg_len = len(message)
        n_batches = math.ceil(msg_len/batch_size)
        print(f"{n_batches=}")
        encrypted_blocks = []
        b = self.hash_256(Key + IV)
        encrypted_block = None

        for batch_number in range(n_batches):
            batch_start  = batch_number * batch_size
            batch_end = batch_start + batch_size
            msg_block = message[batch_start:batch_end]
            print(f"Batch size {len(msg_block)=}")

            if len(msg_block) % 32 != 0:
                msg_block = pad(msg_block, 32)

            encrypted_block = strxor(msg_block, b)
            encrypted_blocks.append(encrypted_block)
            b = self.hash_256(Key + encrypted_block)


        return encrypted_blocks