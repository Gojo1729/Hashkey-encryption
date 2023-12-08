from KeyedHash.encryption import Encryption
import json


def get_encrypted_payload_to_broker(broker_payload, broker_state):
    enc = Encryption()
    Key, IV = broker_state.broker_session_key, broker_state.broker_iv
    encoded_MESS_CB = json.dumps(broker_payload).encode()
    enc_data = enc.encrypt(encoded_MESS_CB, Key, IV)
    HASH_MESS_CM = enc.hash_256(encoded_MESS_CB + Key)
    return enc_data, HASH_MESS_CM
