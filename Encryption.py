import hashlib
from textwrap import wrap

# def int_to_bytes(number):
#     # The method .to_bytes requires the length in bytes.
#     # The number of bytes needed can be calculated by dividing the bit length by 8.
#     # The bit length of 0 is 0, so we use max to ensure at least one byte.
#     byte_length = max(1, (number.bit_length() + 7) // 8)
#     return number.to_bytes(byte_length, byteorder='big')

# IVC1M = 4832500747
# KC1B = 4103583911

# a= int_to_bytes(IVC1M) + int_to_bytes(KC1B)
# print(a)
# b1 = hashlib.sha256()
# b1.update(a)

# print(b1.hexdigest())


class Encryption():

    @staticmethod
    def hash_to_bytes(hash_hex):
        return bytes.fromhex(hash_hex)

    @staticmethod
    def xor_hashes(bytes1, hash2):
        # Convert the hex strings to byte arrays
        e= Encryption()
        # bytes1 = e.hash_to_bytes(hash1)
        bytes2 = e.hash_to_bytes(hash2)

        # Perform XOR operation
        xor_result = bytes(a ^ b for a, b in zip(bytes1, bytes2))

        return xor_result

    def Cipher_Text(IV, Key, P):
        # IVC1M = b'4832500747'
        # KC1B = b'4103583911'
        a = Key + IV
        b = hashlib.sha256()
        b.update(a)
        Hash_b= b.hexdigest()

        print("Hash of b: ", Hash_b)

        chunks = wrap(P, width = 32)

        # p = hashlib.sha256()
        # p.update(P)
        # Hash_P = p.hexdigest()
        # print(Hash_P)
        Cipher= b''

        for i in chunks:
            
            C= Encryption.xor_hashes(bytes(i,'ascii'), Hash_b)
            print("Hash for chunk ",i +" is ",C)
            a= Key + C
            b = hashlib.sha256()
            b.update(a)
            Hash_b= b.hexdigest()
            Cipher = Cipher + C 
            print("updated Cipher ", Cipher.hex())

        return Cipher






