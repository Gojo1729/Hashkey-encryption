from KeyedHash.encryption import Encryption
from KeyedHash.decryption import Decryption
import json


def decrypt_data(encrypted_message, state):
    decryption = Decryption()
    Key, IV = state.session_key, state.iv
    decrypted_msg = decryption.decrypt(encrypted_message, Key, IV)
    return decrypted_msg


def get_encrypted_payload(payload, state):
    enc = Encryption()
    Key, IV = state.session_key, state.iv
    encoded_MESS_CB = json.dumps(payload).encode()
    enc_data = enc.encrypt(encoded_MESS_CB, Key, IV)
    HASH_MESS_CM = enc.hash_256(encoded_MESS_CB + Key)
    return enc_data, HASH_MESS_CM
