from KeyedHash.encryption import Encryption
from KeyedHash.decryption import Decryption
import json

enc = Encryption()
decryption = Decryption()


def validate_hash(decrypted_message, state, mode):
    Key, _ = state.session_key, state.iv
    # get the hash included in the decrypted message and confirm the hash with the decrypted message
    decrypted_msg_hash = decrypted_message["HASH"]
    decrypted_message["HASH"] = ""
    if mode != "RSA":
        calculated_hash = enc.hash_256(decrypted_message + Key)
    else:
        calculated_hash = enc.hash_256(decrypted_message)
    print(f"{decrypted_msg_hash=}, {calculated_hash=}")
    return decrypted_msg_hash == calculated_hash


def decrypt_data(encrypted_message, state):
    Key, IV = state.session_key, state.iv
    decrypted_msg = decryption.decrypt(encrypted_message, Key, IV)
    return decrypted_msg


def encrypt_payload(payload, state):
    """
    For hash part, get the hash of the message without hash field, then reinsert
    the hash key and value and then encrypt it
    """
    Key, IV = state.session_key, state.iv
    encoded_MESS_CB = json.dumps(payload).encode("latin1")
    # calculate the hash of the message without the hash included
    encoded_msg_hash = enc.hash_256(encoded_MESS_CB + Key)
    payload["HASH"] = encoded_msg_hash
    # encrypt the message along with hash
    encoded_MESS_CB = json.dumps(payload).encode("latin1")
    enc_data = enc.encrypt(encoded_MESS_CB, Key, IV)
    return enc_data
