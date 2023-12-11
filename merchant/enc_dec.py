from KeyedHash.encryption import Encryption
from KeyedHash.decryption import Decryption
import json

enc = Encryption()
decryption = Decryption()


def validate_rsa_hash(decrypted_message, provided_hash):
    calculated_hash = enc.hash_256(decrypted_message.encode("latin1"))
    return calculated_hash == provided_hash


def validate_hash(decrypted_message, msg_hash, state):
    Key, _ = state.session_key, state.iv
    # get the hash included in the decrypted message and confirm the hash with the decrypted message
    decrypted_msg_hash = msg_hash
    calculated_hash = enc.hash_256(json.dumps(decrypted_message).encode("latin1") + Key)
    print(f"Calculated hash {calculated_hash}")
    return calculated_hash == decrypted_msg_hash


def decrypt_data(encrypted_message, state):
    Key, IV = state.session_key, state.iv
    decrypted_msg = decryption.decrypt(encrypted_message, Key, IV)
    return decrypted_msg


def encrypt_payload(payload, state):
    Key, IV = state.session_key, state.iv
    encoded_MESS_CB = json.dumps(payload).encode("latin1")
    enc_data = enc.encrypt(encoded_MESS_CB, Key, IV)
    return enc_data
