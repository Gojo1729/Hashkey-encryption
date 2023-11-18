import hashlib
from textwrap import wrap

class Decryption():

    @staticmethod
    def hash_to_bytes(hash_hex):
        return bytes.fromhex(hash_hex)

    @staticmethod
    def xor_hashes(hash1, bytes2):
        # Convert the hex strings to byte arrays
        e= Decryption()
        bytes1 = e.hash_to_bytes(hash1)
        # bytes2 = e.hash_to_bytes(hash2)

        # Perform XOR operation
        xor_result = bytes(a ^ b for a, b in zip(bytes1, bytes2))

        return xor_result

    def Plain_Text(IV, Key, C):
        # IVC1M = b'4832500747'
        # KC1B = b'4103583911'
        a = Key + IV
        b = hashlib.sha256()
        b.update(a)
        Hash_b= b.hexdigest()

        print("Hash of b: ", Hash_b)

        # chunks = wrap(str(C), width = 32)
        # print(chunks)

        # c = hashlib.sha256()
        # c.update(C)
        # Hash_C= b.hexdigest()
        
        Plains = b''

        for c in C:
            P= Decryption.xor_hashes(Hash_b, bytes(c,'ascii'))
            print("Hash for chunk ",c +" is ",Hash_b)
            a= Key + P
            b = hashlib.sha256()
            b.update(a)
            Hash_b= b.hexdigest()
            Plains = Plains + P 

        return Plains.hex()
