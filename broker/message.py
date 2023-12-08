from KeyedHash.decryption import Decryption
from KeyedHash.encryption import Encryption
import json


def decrypt_data(enc_payload, customer_state):
    decryption = Decryption()
    Key, IV = customer_state.session_key, customer_state.iv
    customer_msg_decrypted = decryption.decrypt(enc_payload, Key, IV)
    return customer_msg_decrypted


def get_encrypted_payload_to_merchant(payload, state):
    enc = Encryption()
    Key, IV = state.session_key, state.iv
    encoded_MESS_CB = json.dumps(payload).encode()
    enc_data = enc.encrypt(encoded_MESS_CB, Key, IV)
    print(f"Type of {type(enc_data)}")
    HASH_MESS_CM = enc.hash_256(encoded_MESS_CB + Key)
    return enc_data, HASH_MESS_CM
