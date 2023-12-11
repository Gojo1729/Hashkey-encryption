from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from DH import DiffieHellman
from Auth_decryption import rsa_decrypt_data, verify
from Auth_encryption import rsa_encrypt_data
from datetime import datetime
import json
import httpx
import pandas as pd
import asyncio
import enc_dec
import hashlib
from typing import Tuple, Dict


# broker_public_key = "../bro_pub.pem"
# broker_private_key = "../bro_pri.pem"
# customer1_public_key = "../cus_pub.pem"
# merchant_public_key = "../mer_pub.pem"

broker_public_key = "../OLD KEYS/broker_public_key.pem"
broker_private_key = "../OLD KEYS/broker_private_key.pem"
stars = "*" * 10
Broker = DiffieHellman()
MSG_KEY = "MSG"
HASH_KEY = "HASH"
ENCODING_TYPE = "latin1"


class CustomerData(BaseModel):
    enc_data: bytes


class Customer1State:
    def __init__(self) -> None:
        self.user_id = "C1"
        self.salt = "Net_sec_1"
        self.password = (
            "4f59554b34b1d0fe8832e8fab4b638f51a770f879bf232a36100f316aa56b2c0"
        )
        self.user_id = "C1"
        self.host = "http://127.0.0.1:8001"
        self.msg_api = f"{self.host}/message_customer_1"
        self.auth_api = f"{self.host}/auth_customer_1"
        self.state = None
        self.auth_done = False
        self.random_id = "6514161"
        # assume DH is done
        self.iv = b"4832500747"
        self.session_key = b"4103583911"
        self.public_key = "../OLD KEYS/customer1_public_key.pem"
        self.request_id = "10129120"
        self.entity = "Customer"
        self.Money = "2000"
        self.DHKE_api = f"{self.host}/DHKE_customer_1"
        (
            self.dh_private_key,
            self.dh_public_key,
            self.dh_prime,
        ) = Broker.generate_keypair(10000000019)
        self.dh_shared_key = None


class Customer2State:
    def __init__(self) -> None:
        self.user_id = "C2"
        self.salt = "Net_sec_2"
        self.password = (
            "c5ffcdf4de1aa33a92a65c60cd74d38a88a399c6f3324a7d601d1ff00bb56b12"
        )
        self.host = "http://127.0.0.1:8004"
        self.msg_api = f"{self.host}/message_customer_2"
        self.auth_api = f"{self.host}/auth_customer_2"
        self.DHKE_api = f"{self.host}/DHKE_customer_2"
        self.state = None
        self.auth_done = False
        self.random_id = "1001991"
        # assume DH is done
        self.iv = b"4832500747"
        self.session_key = b"4103583911"
        self.public_key = "../OLD KEYS/customer2_public_key.pem"
        self.request_id = "10129121"
        self.entity = "Customer"
        (
            self.dh_private_key,
            self.dh_public_key,
            self.dh_prime,
        ) = Broker.generate_keypair(10000000033)
        self.dh_shared_key = None


class MerchantState:
    def __init__(self) -> None:
        self.user_id = "M1"
        self.host = "http://127.0.0.1:8003"
        self.msg_api = f"{self.host}/message_merchant"
        self.auth_api = f"{self.host}/auth_merchant"
        self.state = None
        self.auth_done = False
        self.iv = b"6042302273"
        self.session_key = b"7289135233"
        self.public_key = "../OLD KEYS/merchant_public_key.pem"
        self.request_id = "10129122"
        self.entity = "Merchant"
        self.Money = "20000"
        self.DHKE_api = f"{self.host}/DHKE_merchant"
        (
            self.dh_private_key,
            self.dh_public_key,
            self.dh_prime,
        ) = Broker.generate_keypair(10000000007)
        self.dh_shared_key = None


class Hashcheck:
    def hash_password(self, salt, plain_text):
        combined_text = salt + plain_text
        hashed_text = hashlib.sha256(combined_text.encode()).hexdigest()
        return hashed_text


# Create an instance of the FastAPI class
app = FastAPI()
templates = Jinja2Templates(directory="templates")
customer_1_state: Customer1State = Customer1State()
customer_2_state: Customer2State = Customer2State()
customers_state: dict = {"C1": customer_1_state, "C2": customer_2_state}
hashcheck = Hashcheck()

merchant_state = MerchantState()

AUTH_MSG = "auth"
DHKE_MSG = "dhke"
KEYED_MSG = "kh"


def unpack_message(json_message: dict) -> Tuple[bytes, bytes]:
    enc_message = json_message[MSG_KEY].encode(ENCODING_TYPE)
    message_hash = json_message[HASH_KEY].encode(ENCODING_TYPE)
    return enc_message, message_hash


def pack_message(enc_bytes: bytes, message_hash: bytes) -> Dict[str, str]:
    return {
        MSG_KEY: enc_bytes.decode(ENCODING_TYPE),
        HASH_KEY: message_hash.decode(ENCODING_TYPE),
    }


# region message
def send_message(state, encrypted_data, message_type):
    async def send_request():
        async with httpx.AsyncClient() as client:
            if message_type == AUTH_MSG:
                response = await client.post(state.auth_api, json=encrypted_data)
                print(
                    f"{response=}, {response.status_code=}, {type(response.status_code)=}, {type(response.text)=}"
                )
                if state.entity == "Customer":
                    if response.status_code == 200:
                        print(f"{response.json()}")
                        if response.json() == state.request_id:
                            print(
                                f"Mutual authentication with {state.user_id} successfull"
                            )
                            state.auth_done = True
                        else:
                            print(
                                f"Mutual authentication with {state.user_id} {response.text} un-successfull"
                            )
                            state.auth_done = False
                    else:
                        state.auth_done = False
                elif state.entity == "Merchant":
                    if response.status_code == 200:
                        print(
                            f"BROKER: Successfully send auth message sent to merchant"
                        )
                    else:
                        print("Error in sending auth message to merchant")

                return "BROKER: MESSAGE SENT"
            elif message_type == DHKE_MSG:
                response = await client.post(state.DHKE_api, content=encrypted_data)
                print(
                    f"{response=}, {response.status_code=}, {type(response.status_code)=}, {type(response.text)=}"
                )

            elif message_type == KEYED_MSG:
                response = await client.post(state.msg_api, json=encrypted_data)
                # print(
                #     f"{response=}, {response.status_code=}, {type(response.status_code)=}, {type(response.text)=}"
                # )
                return "BROKER: ERROR IN SENDING MESSAGE"

    asyncio.create_task(send_request())


# endregion


def validate_credentials(user_id, passwd):
    print(f"Validating: User ID = {user_id}, Password = {passwd}")
    valid_user = customers_state.get(user_id)
    if user_id == customer_1_state.user_id:
        hash_pass = hashcheck.hash_password(customer_1_state.salt, passwd)
        print(hash_pass)
        if customer_1_state.password == hash_pass:
            return valid_user
        else:
            return None
    elif user_id == customer_2_state.user_id:
        hash_pass = hashcheck.hash_password(customer_2_state.salt, passwd)
        if customer_2_state.password == hash_pass:
            print("valid")
            return valid_user
        else:
            return None

    return valid_user if valid_user is not None else None


def BROKER_CUSTOMER(login_creds):
    user_id = login_creds.get("USER_ID")
    password = login_creds.get("PASSWORD")
    MESSAGE = f"Hi {user_id} , Login Unsuccessful, Invalid Credentials"
    valid_user = validate_credentials(user_id, password)
    if valid_user is None:
        print("Invalid credentials")
        return {"message": MESSAGE}

    timestamp = str(datetime.now())
    auth_payload = {
        "TYPE": "MUTUAL_AUTHENTICATION",
        "ENTITY": "Broker",
        "REQUEST_ID": valid_user.request_id,
        "RESPONSE_ID": login_creds.get("REQUEST_ID"),
        "TIMESTAMP": timestamp,
    }
    payload_hash = enc_dec.enc.hash_256(json.dumps(auth_payload).encode("latin1"))
    payload = json.dumps(auth_payload)
    encrypted_data = rsa_encrypt_data(payload, valid_user.public_key)
    message_wrapper = {
        "MSG": encrypted_data.decode("latin1"),
        "HASH": payload_hash.decode("latin1"),
    }
    send_message(valid_user, message_wrapper, AUTH_MSG)


def auth_merchant():
    timestamp = str(datetime.now())

    # Create payload
    auth_payload = {
        "TYPE": "MUTUAL_AUTHENTICATION",
        "ENTITY": "Broker",
        "TIMESTAMP": timestamp,
        "PAYLOAD": {"REQUEST_ID": merchant_state.request_id},
    }

    # Convert payload to JSON format
    payload_hash = enc_dec.enc.hash_256(json.dumps(auth_payload).encode("latin1"))
    payload = json.dumps(auth_payload)
    encrypted_data = rsa_encrypt_data(payload, merchant_state.public_key)
    print(f"Encrypted message to merchant {encrypted_data}\n --- hash {payload_hash}")
    message_wrapper = {
        "MSG": encrypted_data.decode("latin1"),
        "HASH": payload_hash.decode("latin1"),
    }
    send_message(merchant_state, message_wrapper, AUTH_MSG)
    print("Authentication response sent to Merchant.")


def customer_to_merchant(customer_decrypted_message):
    random_customer_id: str = customers_state[
        customer_decrypted_message["USERID"]
    ].random_id
    customer_decrypted_message["USERID"] = random_customer_id
    customer_decrypted_message["ENTITY"] = "Broker"
    customer_decrypted_message["TIMESTAMP"] = str(datetime.now())
    print(
        f"payload to merchant {customer_decrypted_message}, type {type(customer_decrypted_message)}"
    )
    merchant_payload_hash = enc_dec.enc.keyed_hash(
        json.dumps(customer_decrypted_message).encode("latin1"), merchant_state
    )
    encrypted_payload_to_merchant = enc_dec.encrypt_payload(
        customer_decrypted_message, merchant_state
    )
    print(
        f"Encrypted message sent to merchant {encrypted_payload_to_merchant} \n \n *** Hash is {merchant_payload_hash}"
    )
    packed_encrypted_message = pack_message(
        encrypted_payload_to_merchant, merchant_payload_hash
    )
    send_message(merchant_state, packed_encrypted_message, KEYED_MSG)


# Define a simple endpoint
@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


# region DH generation
def BROKER_CUSTOMER1_DHKE():  # THIS IS FOR SENDING THE KEY TO CUSTOMER1
    timestamp = str(datetime.now())
    payload = {
        "TYPE": "DHKE",
        "DH_PUBLIC_KEY": customer_1_state.dh_public_key,
        "TS": timestamp,
    }

    payload = json.dumps(payload)
    print("Message Sent : ", payload)
    print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
    send_message(customer_1_state, payload, DHKE_MSG)


def BROKER_MERCHANT_DHKE():  # THIS IS FOR SENDING THE KEY TO MERCHANT
    timestamp = str(datetime.now())
    payload = {
        "TYPE": "DHKE",
        "DH_PUBLIC_KEY": merchant_state.dh_public_key,
        "TS": timestamp,
    }

    payload = json.dumps(payload)
    print("Message Sent : ", payload)
    print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
    send_message(merchant_state, payload, DHKE_MSG)


def BROKER_CUSTOMER2_DHKE():  # THIS IS FOR SENDING THE KEY TO CUSTOMER2
    timestamp = str(datetime.now())
    payload = {
        "TYPE": "DHKE",
        "UID": "",
        "DH_PUBLIC_KEY": customer_2_state.dh_public_key,
        "TS": timestamp,
    }

    payload = json.dumps(payload)
    print("Message Sent : ", payload)
    print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
    send_message(customer_2_state, payload, DHKE_MSG)


# endregion


# customer 1 sending DH keys to merchant through broker
@app.post("/DHKE_Customer1_broker")
async def DHKE_Customer1_broker(data: Request):
    receieved_data = await data.body()
    receieved_data = receieved_data.decode("utf-8")
    receieved_data = json.loads(receieved_data)
    print("payload :", receieved_data)

    if "DHKE" == receieved_data["TYPE"]:  # THIS IS WHEN CUSTOMER1 SENDS HIS KEY
        public_key_C1B = receieved_data["DH_PUBLIC_KEY"]
        print("Diffe_hellman : public key of customer1 recieved")
        customer_1_state.dh_shared_key = Broker.calculate_shared_secret(
            public_key_C1B, customer_1_state.dh_private_key, customer_1_state.dh_prime
        )
        print(f"Customer 1 DH session key {customer_1_state.dh_shared_key}")

    elif (
        "DHKE WITH MERCHANT" == receieved_data["TYPE"]
    ):  # THIS IS WHEN CUSTOMER1 WANTS TO SEND HIS KEY TO MERCHANT
        print("Diffe_hellman : Recieved from Customer forwarding to Merchant")
        receieved_data["USERID"] = customer_1_state.random_id
        payload = json.dumps(receieved_data)
        print("Message Sent : ", payload)
        print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
        send_message(merchant_state, payload, DHKE_MSG)


# region DH apis


@app.post("/DHKE_Customer2_broker")
async def DHKE_Customer2_broker(data: Request):
    receieved_data = await data.body()
    receieved_data = receieved_data.decode("utf-8")
    receieved_data = json.loads(receieved_data)
    print("payload :", receieved_data)

    if "DHKE" == receieved_data["TYPE"]:  # THIS IS WHEN CUSTOMER2 SENDS H   IS KEY
        public_key_C2B = receieved_data["DH_PUBLIC_KEY"]
        print("Diffe_hellman : public key of customer2 recieved")
        customer_2_state.dh_shared_key = Broker.calculate_shared_secret(
            public_key_C2B, customer_2_state.dh_private_key, customer_2_state.dh_prime
        )
        print(f"Customer 2 DH session key {customer_2_state.dh_shared_key}")

    elif (
        "DHKE WITH MERCHANT" == receieved_data["TYPE"]
    ):  # THIS IS WHEN CUSTOMER1 WANTS TO SEND HIS KEY TO MERCHANT
        print("Diffe_hellman : Recieved from Customer forwarding to Merchant")
        receieved_data["USERID"] = customer_2_state.random_id
        payload = json.dumps(receieved_data)
        print("Message Sent : ", payload)
        print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
        send_message(merchant_state, payload, DHKE_MSG)


@app.post("/DHKE_Merchant_broker")
async def DHKE_Merchant_broker(data: Request):
    receieved_data = await data.body()
    receieved_data = receieved_data.decode("utf-8")
    receieved_data = json.loads(receieved_data)
    print("payload :", receieved_data)

    if "DHKE" == receieved_data["TYPE"]:
        public_key_MB = receieved_data["DH_PUBLIC_KEY"]
        print("Diffe_hellman : public key of Merchant recieved")
        merchant_state.dh_shared_key = Broker.calculate_shared_secret(
            public_key_MB, merchant_state.dh_private_key, merchant_state.dh_prime
        )
        print(f"Merchant - Broker DH session key {merchant_state.dh_shared_key}")

    elif (
        "DHKE WITH Customer" == receieved_data["TYPE"]
    ):  # THIS SEND TO CUSTOMER 1 OR 2 DEPENDING ON RID AND DEL RID BEFORE SENDING IT
        print(f"USERID {receieved_data}")
        for customer_state in customers_state.values():
            if customer_state.random_id == receieved_data["USERID"]:
                payload = json.dumps(receieved_data)
                print("Message Sent : ", payload)
                print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
                send_message(customer_state, payload, DHKE_MSG)
                print(
                    f"Diffe_hellman : Recieved from Merchant forwarding to Customer {customer_state.user_id}"
                )
        del receieved_data["USERID"]


# endregion


@app.post("/handleinput")
async def handle_input(action_number: int = Form(...)):
    # send auth request to merchant
    if action_number == 1:
        auth_merchant()
        return {"message": "Sending auth request to merchant"}

    # sending DH keys to customer1
    elif action_number == 2:
        if customer_1_state.auth_done:
            BROKER_CUSTOMER1_DHKE()
            return {"message": "Sending DH keys to Customer1"}
        else:
            return {
                "message": "Customer1 not authorized yet, please authorize and then send DH keys"
            }

    # sending DH keys to customer2
    elif action_number == 3:
        if customer_2_state.auth_done:
            BROKER_CUSTOMER2_DHKE()
            return {"message": "Sending request to Customer2"}
        else:
            return {
                "message": "Customer2 not authorized yet, please authorize and then send DH keys"
            }
    # sending DH keys to merchant
    elif action_number == 4:
        if merchant_state.auth_done:
            BROKER_MERCHANT_DHKE()
            return {"message": "Sending DH key to merchant"}
        else:
            return {"message": "Merchant not authorized"}


# used by other stakeholders to authenticate mutually with broker
@app.post("/auth_broker")
async def auth_broker(data: Request):
    receieved_data = await data.json()
    encrypted_message, message_hash = unpack_message(receieved_data)
    print(f"original message {receieved_data}")
    print(f"Encrypted payload : {encrypted_message}\n ---- message hash {message_hash}")

    Decrypted_MESS = rsa_decrypt_data(encrypted_message, broker_private_key)
    is_hash_validated = enc_dec.validate_rsa_hash(Decrypted_MESS, message_hash)
    print(f"Hash validated for customer ? {is_hash_validated=}")

    Decrypted_MESS = json.loads(Decrypted_MESS)
    formatted_data = json.dumps(Decrypted_MESS, indent=2)
    entity = Decrypted_MESS["ENTITY"]
    print(f"Received from {entity}:\n {formatted_data}")

    return_msg = ""
    if "MUTUAL_AUTHENTICATION" == Decrypted_MESS["TYPE"]:
        entity = Decrypted_MESS["ENTITY"]
        print(entity)
        if entity == "Merchant":
            print("Authentication payload received from Merchant.")
            if Decrypted_MESS["PAYLOAD"]["RESPONSE_ID"] == merchant_state.request_id:
                print("MUTUAL AUTHENTICATION DONE WITH MERCHANT")
                merchant_state.auth_done = True
                return_msg = Decrypted_MESS["PAYLOAD"]["REQUEST_ID"]
                return return_msg
            else:
                merchant_state.auth_done = False

        elif entity == "Customer":
            login_cred = Decrypted_MESS["PAYLOAD"]["LOGINCRED"]
            print(login_cred)
            print("Authentication payload received from Customer.")
            return_msg = BROKER_CUSTOMER(login_cred)

            return "BROKER: AUTH REQUEST RECEIVED"
    else:
        print("Received payload does not contain any information to forward.")
        return ""


def get_valid_customer(id, from_entity):
    valid_customer = None
    for customer in customers_state.values():
        if from_entity == "MERCHANT":
            if customer.random_id == id:
                valid_customer = customer
        elif from_entity == "CUSTOMER":
            if customer.user_id == id:
                valid_customer = customer

    return valid_customer


# receving msg from merchant
@app.post("/message_merchant_broker")
async def message_merchant_broker(data: Request):
    # use keyed hash
    receieved_data = await data.json()
    encrypted_message, message_hash = unpack_message(receieved_data)
    print(f"Encrypted payload in bytes from merchant {encrypted_message} \n {stars}")
    merchant_msg_decrypted = enc_dec.decrypt_data(encrypted_message, merchant_state)
    msg_hash = enc_dec.validate_hash(
        merchant_msg_decrypted, message_hash, merchant_state
    )
    print(f"Hash of message from merchant validated {msg_hash}")

    msg_type = merchant_msg_decrypted["TYPE"]
    cust_rid = merchant_msg_decrypted["USERID"]
    valid_customer = get_valid_customer(cust_rid, "MERCHANT")

    if valid_customer is None:
        return "INVALID_MESSAGE"

    print(
        f"Decrypted data from merchant {merchant_msg_decrypted}, {type(merchant_msg_decrypted)=}"
    )  # create a new payload to merchant
    customer_payload = None
    timestamp = str(datetime.now())
    if "CUSTOMER_AUTHENTICATION" == msg_type:
        print("Payload received from Merchant")
        print(f"Modified payload forwarded to customer")
        # encrypt payload to customer
        customer_payload = {
            "TYPE": "MERCHANT_AUTHENTICATION",
            "ENTITY": "BROKER",
            "PAYLOAD": merchant_msg_decrypted["PAYLOAD"],
            "TIMESTAMP": timestamp,
        }
        # customer_hash = enc_dec.enc.keyed_hash(
        #     json.dumps(customer_payload).encode("latin1"), valid_customer
        # )

    elif "TO_CUSTOMER" == msg_type:
        # get the payload, append his message to customer and send it
        customer_payload = {
            "TYPE": "FROM_MERCHANT",
            "ENTITY": "BROKER",
            "TIMESTAMP": str(datetime.now()),
            "PAYLOAD": merchant_msg_decrypted["PAYLOAD"],
        }
        customer_hash = enc_dec.enc.keyed_hash(
            json.dumps(customer_payload).encode("latin1"), valid_customer
        )
        # enc_payload = enc_dec.encrypt_payload(customer_payload, valid_customer)
        # encrypted_packed_message = pack_message(enc_payload, customer_hash)
        # send_message(valid_customer, encrypted_packed_message, KEYED_MSG)

    elif "PURCHASE_CONSENT" == msg_type:
        # get the payload, append his message to customer and send it
        customer_payload = {
            "TYPE": "PURCHASE_CONSENT",
            "ENTITY": "BROKER",
            "AMOUNT": merchant_msg_decrypted["AMOUNT"],
            "TIMESTAMP": str(datetime.now()),
            "PAYLOAD": merchant_msg_decrypted["PAYLOAD"],
        }
        # customer_hash = enc_dec.enc.keyed_hash(
        #     json.dumps(customer_payload).encode("latin1"), valid_customer
        # )
        # enc_payload = enc_dec.encrypt_payload(customer_payload, valid_customer)
        # encrypted_packed_message = pack_message(enc_payload, customer_hash)
        # send_message(valid_customer, encrypted_packed_message, KEYED_MSG)

    customer_hash = enc_dec.enc.keyed_hash(
        json.dumps(customer_payload).encode("latin1"), valid_customer
    )
    enc_payload = enc_dec.encrypt_payload(customer_payload, valid_customer)
    encrypted_packed_message = pack_message(enc_payload, customer_hash)
    send_message(valid_customer, encrypted_packed_message, KEYED_MSG)

    return "MESSAGE SENT TO CUSTOMER"


# receiving msg from customer1
@app.post("/message_customer_1_broker")
async def message_customer_1_broker(data: Request):
    # use keyed hash
    receieved_data = await data.json()
    encrypted_msg, message_hash = unpack_message(receieved_data)
    print(f"Encrypted payload in bytes from customer1 {encrypted_msg} \n {stars}")
    customer_msg_decrypted = enc_dec.decrypt_data(encrypted_msg, customer_1_state)
    print(f"Decrypted data {customer_msg_decrypted} \n {stars}")
    msg_hash = enc_dec.validate_hash(
        customer_msg_decrypted, message_hash, customer_1_state
    )
    print(f"Hash of message from customer validated {msg_hash}")
    msg_type = customer_msg_decrypted["TYPE"]

    # decrypt, verify the hash, take action
    print("Payload received from Customer")
    # create a new payload to merchant
    if "MERCHANT_AUTHENTICATION" == msg_type:
        customer_to_merchant(customer_msg_decrypted)

    elif "TO_MERCHANT" == msg_type:
        """
        1. check if the user exists using UID and get the custoemr state
        2. check if he is authorized.
        3. if already authorized forward message to merch.
        4. else reply to customer that msg is invalid, authorize first
        """
        customer_msg_decrypted["TYPE"] = "FROM_CUSTOMER"
        customer_to_merchant(customer_msg_decrypted)
    elif "PAYMENT_CONSENT" == msg_type:
        if customer_msg_decrypted["AMOUNT"] <= int(customer_1_state.Money):
            # get the payload, append his message to customer and send it
            broker_to_merchant(customer_msg_decrypted)
        else:
            return "**********Insufficient Funds! Payment Aborted**********"


def broker_to_merchant(customer_decrypted_message):
    random_customer_id: str = customers_state[
        customer_decrypted_message["USERID"]
    ].random_id
    customer_decrypted_message["USERID"] = random_customer_id
    customer_decrypted_message["TYPE"] = "PAYMENT_DONE"
    customer_decrypted_message["ENTITY"] = "Broker"
    customer_decrypted_message["MESSAGE"] = "Payment Done --  Funds Transferred"
    customer_decrypted_message["TIMESTAMP"] = str(datetime.now())
    payload = json.dumps(customer_decrypted_message)
    print(
        f"payload to merchant {customer_decrypted_message}, type {type(customer_decrypted_message)}"
    )
    merchant_payload_hash = enc_dec.enc.keyed_hash(
        json.dumps(customer_decrypted_message).encode("latin1"), merchant_state
    )

    encrypted_payload_to_merchant = enc_dec.encrypt_payload(payload, merchant_state)
    print(
        f"Encrypted message sent to merchant {encrypted_payload_to_merchant} \n \n *** Hash is {merchant_payload_hash}"
    )
    packed_encrypted_message = pack_message(
        encrypted_payload_to_merchant, merchant_payload_hash
    )
    send_message(merchant_state, packed_encrypted_message, KEYED_MSG)


# receiving msg from customer1
@app.post("/message_customer_2_broker")
async def message_customer_2_broker(data: Request):
    # use keyed hash
    receieved_data = await data.json()
    encrypted_message, message_hash = unpack_message(receieved_data)
    # print("Encrypted payload :", receieved_data)
    customer_msg_decrypted = enc_dec.decrypt_data(encrypted_message, customer_2_state)
    msg_hash = enc_dec.validate_hash(
        customer_msg_decrypted, message_hash, customer_2_state
    )
    print(f"Hash of message from merchant validated {msg_hash}")
    print(f"Decrypted data {customer_msg_decrypted}")
    # create a new payload to merchant
    if "MERCHANT_AUTHENTICATION" == customer_msg_decrypted["TYPE"]:
        customer_to_merchant(customer_msg_decrypted)
