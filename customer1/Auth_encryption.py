from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256


def rsa_encrypt_data(data, public_key_path):
    # Load the public key
    with open(public_key_path, "rb") as key_file:
        public_key = RSA.import_key(key_file.read())

    # Create a cipher object using the public key
    cipher = PKCS1_OAEP.new(public_key)

    # Encrypt the data
    encrypted_data = cipher.encrypt(data.encode("latin1"))

    return encrypted_data


def signing(data, private_key_path):
    digest = SHA256.new()
    digest.update(data)
    with open(private_key_path, "rb") as key_file:
        private_key = RSA.import_key(key_file.read())
    signer = PKCS1_v1_5.new(private_key)
    signature = signer.sign(digest)
    return signature.hex()
