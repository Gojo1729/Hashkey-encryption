from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from Auth_decryption import rsa_decrypt_data, verify
from Auth_encryption import rsa_encrypt_data
from datetime import datetime
import json
import httpx
import pandas as pd
import asyncio
import enc_dec


# broker_public_key = "../bro_pub.pem"
# broker_private_key = "../bro_pri.pem"
# customer1_public_key = "../cus_pub.pem"
# merchant_public_key = "../mer_pub.pem"

broker_public_key = "../OLD KEYS/broker_public_key.pem"
broker_private_key = "../OLD KEYS/broker_private_key.pem"
stars = "*" * 10


class CustomerData(BaseModel):
    enc_data: bytes


class Customer1State:
    def __init__(self) -> None:
        self.user_id = "C1"
        self.password = "pass1"
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


class Customer2State:
    def __init__(self) -> None:
        self.user_id = "C2"
        self.password = "pass2"
        self.host = "http://127.0.0.1:8004"
        self.msg_api = f"{self.host}/message_customer_2"
        self.auth_api = f"{self.host}/auth_customer_2"
        self.state = None
        self.auth_done = False
        self.random_id = "1001991"
        # assume DH is done
        self.iv = b"4832500747"
        self.session_key = b"4103583911"
        self.public_key = "../OLD KEYS/customer2_public_key.pem"
        self.request_id = "10129121"
        self.entity = "Customer"


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


# Create an instance of the FastAPI class
app = FastAPI()
templates = Jinja2Templates(directory="templates")
customer_1_state = Customer1State()
customer_2_state = Customer2State()
customers_state = {"C1": customer_1_state, "C2": customer_2_state}
merchant_state = MerchantState()


# region message
def send_message(state, encrypted_data, auth=False):
    async def send_request():
        async with httpx.AsyncClient() as client:
            if auth:
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
                            state.auth = True
                        else:
                            print(
                                f"Mutual authentication with {state.user_id} {response.text} un-successfull"
                            )
                            state.auth = False
                    else:
                        state.auth = False
                elif state.entity == "Merchant":
                    if response.status_code == 200:
                        print(
                            f"BROKER: Successfully send auth message sent to merchant"
                        )
                    else:
                        print("Error in sending auth message to merchant")

                return "BROKER: MESSAGE SENT"
            else:
                response = await client.post(state.msg_api, content=encrypted_data)
                # print(
                #     f"{response=}, {response.status_code=}, {type(response.status_code)=}, {type(response.text)=}"
                # )
                return "BROKER: ERROR IN SENDING MESSAGE"

    asyncio.create_task(send_request())


# endregion


def validate_credentials(user_id, passwd):
    print(f"Validating: User ID = {user_id}, Password = {passwd}")
    valid_user = customers_state.get(user_id)
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
    send_message(valid_user, message_wrapper, auth=True)


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
    send_message(merchant_state, message_wrapper, auth=True)
    print("Authentication response sent to Merchant.")


def customer_to_merchant(customer_decrypted_message):
    random_customer_id: str = customers_state[
        customer_decrypted_message["USERID"]
    ].random_id
    customer_decrypted_message["USERID"] = random_customer_id
    customer_decrypted_message["ENTITY"] = "Broker"
    customer_decrypted_message["TIMESTAMP"] = str(datetime.now())
    customer_decrypted_message["HASH"] = ""
    print(
        f"payload to merchant {customer_decrypted_message}, type {type(customer_decrypted_message)}"
    )
    merchant_payload_hash = enc_dec.enc.keyed_hash(
        json.dumps(customer_decrypted_message).encode("latin1"), merchant_state
    )
    customer_decrypted_message["HASH"] = merchant_payload_hash.decode("latin1")
    encrypted_payload_to_merchant = enc_dec.encrypt_payload(
        customer_decrypted_message, merchant_state
    )
    print(
        f"Encrypted message sent to merchant {encrypted_payload_to_merchant} \n \n *** Hash is {merchant_payload_hash}"
    )
    send_message(merchant_state, encrypted_payload_to_merchant)


# Define a simple endpoint
@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/handleinput")
async def handle_input(action_number: int = Form(...)):
    # send auth request to broker
    if action_number == 1:
        pass
    # send auth request to merchant
    elif action_number == 2:
        pass
    # send auth request to merchant
    elif action_number == 3:
        auth_merchant()
        return {"message": "Sending auth request to merchant"}

    # buy product


# used by other stakeholders to authenticate mutually with broker
@app.post("/auth_broker")
async def auth_broker(data: Request):
    receieved_data = await data.json()
    encrypted_message = receieved_data["MSG"].encode("latin1")
    message_hash = receieved_data["HASH"].encode("latin1")
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


# def get_enc_payload_to_customer(merchant_payload, customer_payload, customer_state):
#     merchant_enc_payload, merchant_hash = enc_dec.encrypt_data(
#         merchant_payload, customer_state
#     )
#     customer_payload["PAYLOAD"] = merchant_enc_payload.decode("latin1")
#     broker_enc_payload, broker_hash = enc_dec.encrypt_data(customer_payload, broker_state)

#     return broker_enc_payload


# receving msg from merchant
@app.post("/message_merchant_broker")
async def message_merchant_broker(data: Request):
    # use keyed hash
    receieved_data = await data.body()
    print(f"Encrypted payload in bytes from merchant {receieved_data} \n {stars}")
    merchant_msg_decrypted = enc_dec.decrypt_data(receieved_data, merchant_state)
    msg_hash = enc_dec.validate_hash(merchant_msg_decrypted, merchant_state)
    print(f"Hash of message from merchant validated {msg_hash}")

    msg_type = merchant_msg_decrypted["TYPE"]
    cust_rid = merchant_msg_decrypted["USERID"]
    valid_customer = get_valid_customer(cust_rid, "MERCHANT")
    if valid_customer is None:
        return "INVALID_MESSAGE"

    print(
        f"Decrypted data from merchant {merchant_msg_decrypted}, {type(merchant_msg_decrypted)=}"
    )  # create a new payload to merchant
    timestamp = str(datetime.now())
    if "CUSTOMER_AUTHENTICATION" == msg_type:
        print("Payload received from Merchant")
        print(f"Modified payload forwarded to customer")
        # encrypt payload to customer
        customer_payload = {
            "TYPE": "MERCHANT_AUTHENTICATION",
            "ENTITY": "BROKER",
            "PAYLOAD": merchant_msg_decrypted["PAYLOAD"],
            "HASH": "",
            "TIMESTAMP": timestamp,
        }
        customer_hash = enc_dec.enc.keyed_hash(
            json.dumps(customer_payload).encode("latin1"), valid_customer
        )
        customer_payload["HASH"] = customer_hash.decode("latin1")
        enc_payload = enc_dec.encrypt_payload(customer_payload, valid_customer)
        send_message(valid_customer, enc_payload, auth=False)

    elif "TO_CUSTOMER" == msg_type:
        # get the payload, append his message to customer and send it
        customer_payload = {
            "TYPE": "FROM_MERCHANT",
            "ENTITY": "BROKER",
            "HASH": "",
            "TIMESTAMP": str(datetime.now()),
            "PAYLOAD": merchant_msg_decrypted["PAYLOAD"],
        }
        customer_hash = enc_dec.enc.keyed_hash(
            json.dumps(customer_payload).encode("latin1"), valid_customer
        )
        customer_payload["HASH"] = customer_hash.decode("latin1")
        enc_payload = enc_dec.encrypt_payload(customer_payload, valid_customer)
        send_message(valid_customer, enc_payload, auth=False)
    return "MESSAGE SENT TO CUSTOMER"


# receiving msg from customer1
@app.post("/message_customer_1_broker")
async def message_customer_1_broker(data: Request):
    # use keyed hash
    receieved_data = await data.body()
    print(f"Encrypted payload in bytes from customer1 {receieved_data} \n {stars}")
    customer_msg_decrypted = enc_dec.decrypt_data(receieved_data, customer_1_state)
    print(f"Decrypted data {customer_msg_decrypted} \n {stars}")
    msg_hash = enc_dec.validate_hash(customer_msg_decrypted, customer_1_state)
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


# receiving msg from customer1
@app.post("/message_customer_2_broker")
async def message_customer_2_broker(data: Request):
    # use keyed hash
    receieved_data = await data.body()
    # print("Encrypted payload :", receieved_data)
    customer_msg_decrypted = enc_dec.decrypt_data(receieved_data, customer_2_state)
    msg_hash = enc_dec.validate_hash(customer_msg_decrypted, customer_2_state)
    print(f"Hash of message from merchant validated {msg_hash}")
    print(f"Decrypted data {customer_msg_decrypted}, {type(customer_msg_decrypted)=}")
    # create a new payload to merchant
    if "MERCHANT_AUTHENTICATION" == customer_msg_decrypted["TYPE"]:
        customer_to_merchant(customer_msg_decrypted)
