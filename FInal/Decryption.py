import json
import math
from typing import List
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util import strxor
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.strxor import strxor
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

class Decryption():

    def hash_256(self,message):
        sha_256 = SHA256.new(message).digest()
        return sha_256

    def decrypt(self, encrypted_blocks: List[bytes], Key: bytes, IV: bytes):
        b = self.hash_256(Key + IV)
        decrypted_blocks = []
        for enc_block in encrypted_blocks:
            print("b length {} enc_block length {}".format(len(b),len(enc_block)))
            decrypted_block = strxor(b, enc_block)
            decrypted_blocks.append(decrypted_block)
            b = self.hash_256(Key + enc_block)

        concatenated_decrypted_message = b""
        for dmsg in decrypted_blocks:
            concatenated_decrypted_message += dmsg
        unpaded_dmsg = unpad(concatenated_decrypted_message, 32)

        decrypted_message = unpaded_dmsg.decode()
        # print(f"{decrypted_message=}")
        decrypted_json = dict(json.loads(decrypted_message))


        return decrypted_json