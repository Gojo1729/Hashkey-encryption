from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5

def decrypt_data(encrypted_data, private_key_path):
    # Load the private key
    with open(private_key_path, 'rb') as key_file:
        private_key = RSA.import_key(key_file.read())

    # Create a cipher object using the private key
    cipher = PKCS1_OAEP.new(private_key)

    # Decrypt the data
    decrypted_data = cipher.decrypt(encrypted_data).decode('utf-8')

    return decrypted_data


def verify(data,signature,public_key_path):
    try:
        digest =  SHA256.new()
        digest.update(data)
        with open(public_key_path, 'rb') as key_file:
            public_key = RSA.import_key(key_file.read())
        signer = PKCS1_v1_5.new(public_key)
        flag = signer.verify(digest,signature)
        print("The signature is valid.")
        flag= "V"
    except (ValueError, TypeError):
        flag = "NV"
        print("The signature is not valid, Message Tampered")

    return flag


