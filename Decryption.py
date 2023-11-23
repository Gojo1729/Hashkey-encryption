import hashlib
import math
from textwrap import wrap

class Decryption():

    @staticmethod
    def hash_to_bytes(hash_hex):
        return bytes.fromhex(hash_hex)

    @staticmethod
    def xor_hashes(hash1, bytes2):
        bytes1 = Decryption.hash_to_bytes(hash1)
        xor_result = bytes(a ^ b for a, b in zip(bytes2, bytes1))

        return xor_result

    def Plain_Text(IV, Key, C):
        a = Key + IV
        b = hashlib.sha256()
        b.update(a)
        Hash_b= b.hexdigest()
        print("Hash_b initially: ", Hash_b)
        
        Plains = []

        for i in C:
            print("Chunk: ",i)
            P= Decryption.xor_hashes(Hash_b, i)
            concat = Key + P
            B = hashlib.sha256()
            B.update(concat)
            Hash_b= B.hexdigest()
            print("Hash_b After: ", Hash_b)
            Plains.append(P)

        return Plains
