import json
import math
from typing import List
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util import strxor
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.strxor import strxor as xordata
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


class Decryption:
    def hash_256(self, message):
        sha_256 = SHA256.new(message).digest()
        return sha_256

    def decrypt(self, encrypted_message: bytes, Key: bytes, IV: bytes):
        b = self.hash_256(Key + IV)
        print(f"Length of encrypted message {len(encrypted_message)}")

        batch_size = 32
        msg_len = len(encrypted_message)
        n_batches = math.ceil(msg_len / batch_size)
        # print(f"{n_batches=}")
        b = self.hash_256(Key + IV)
        concatenated_decrypted_message = b""

        for batch_number in range(n_batches):
            batch_start = batch_number * batch_size
            batch_end = batch_start + batch_size
            enc_block = encrypted_message[batch_start:batch_end]
            # print(f"Batch size {len(msg_block)=}")
            decrypted_block = xordata(b, enc_block)
            concatenated_decrypted_message += decrypted_block
            b = self.hash_256(Key + enc_block)

        unpaded_dmsg = concatenated_decrypted_message
        print(
            f"************* decrypted message {concatenated_decrypted_message}, {len(concatenated_decrypted_message)=}, { (len(unpaded_dmsg) % 32)} ***************"
        )
        try:
            unpaded_dmsg = unpad(concatenated_decrypted_message, 32)
        except:
            pass

        decrypted_message = unpaded_dmsg.decode()
        decrypted_json = json.loads(decrypted_message)
        if type(decrypted_json) == str:
            decrypted_json = json.loads(decrypted_json)

        return decrypted_json
