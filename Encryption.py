import hashlib
import math

class Encryption():

    @staticmethod
    def hash_to_bytes(hash_hex):
        return bytes.fromhex(hash_hex)

    @staticmethod
    def xor_hashes(bytes1, hash2):
        bytes2 = Encryption.hash_to_bytes(hash2)

        # Perform XOR operation
        xor_result = bytes(a ^ b for a, b in zip(bytes1, bytes2))

        return xor_result

    def Cipher_Text(IV, Key, P):
        a = Key + IV
        b = hashlib.sha256()
        b.update(a)
        Hash_b= b.hexdigest()
        Cipher= []

        for i in range(math.ceil(len(P)/32)):
            print(P[31*i:31*(i+1)])
            C= Encryption.xor_hashes(P[31*i:31*(i+1)], Hash_b)
            print("C: ",C)
            concat = Key + C
            B = hashlib.sha256()
            B.update(concat)
            Hash_b= B.hexdigest()
            Cipher.append(C) 

        print("Cipher chunks array: ", Cipher)
        return Cipher






