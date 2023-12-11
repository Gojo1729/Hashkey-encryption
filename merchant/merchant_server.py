import asyncio
from fastapi import Depends, FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from Auth_decryption import rsa_decrypt_data
from Auth_encryption import rsa_encrypt_data
from datetime import datetime
import json
import httpx
import enc_dec
from DH import DiffieHellman
from typing import Dict, Tuple
from random import randint
import pandas as pd

# broker_public_key = "../bro_pub.pem"
# merchant_private_key = "../mer_pri.pem"
# merchant_public_key = "../mer_pub.pem"


broker_public_key = "../OLD KEYS/broker_public_key.pem"
merchant_public_key = "../OLD KEYS/merchant_public_key.pem"
merchant_private_key = "../OLD KEYS/merchant_private_key.pem"
stars = "*" * 10
Merchant = DiffieHellman()
AUTH_MSG = "auth"
DHKE_MSG = "dhke"
KEYED_MSG = "kh"
MSG_KEY = "MSG"
HASH_KEY = "HASH"
ENCODING_TYPE = "latin1"


class CustomerInput(BaseModel):
    action_number: int
    enc_data: bytes


class BrokerState:
    def __init__(self) -> None:
        self.state = None
        self.auth_done = False
        self.host = f"http://127.0.0.1:8002"
        self.auth_api = f"{self.host}/auth_broker"
        self.msg_api = f"{self.host}/message_merchant_broker"
        # assume DH is done
        self.iv = b"6042302273"
        self.session_key = b"7289135233"
        self.request_id = "129311"
        (
            self.dh_private_key,
            self.dh_public_key,
            self.dh_prime,
        ) = Merchant.generate_keypair(10000000007)
        self.DHKE_api = f"{self.host}/DHKE_Merchant_broker"
        self.dh_session_key = None


class CustomerState:
    def __init__(self, rid, state, auth_done) -> None:
        self.random_id = rid
        self.state = state
        self.auth_done = auth_done
        # assume DH is done
        self.iv = b"6042302272"
        self.session_key = b"7289135232"
        (
            self.dh_private_key,
            self.dh_public_key,
            self.dh_prime,
        ) = Merchant.generate_keypair(10000000061)
        self.dh_session_key = None
        self.prods = {}
        self.payment = 0
        self.Inventory = {
            1: {"PID": 1, "Quantity": 5, "Name": "Watch", "Price": "$300"},
            2: {"PID": 2, "Quantity": 4, "Name": "IPAD", "Price": "$300"},
            3: {"PID": 3, "Quantity": 4, "Name": "MAC", "Price": "$300"},
            4: {"PID": 4, "Quantity": 2, "Name": "AIRTAG", "Price": "$300"},
            5: {"PID": 5, "Quantity": 1, "Name": "AIRPODS", "Price": "$300"},
            6: {"PID": 6, "Quantity": 0, "Name": "Apple TV", "Price": "$300"},
        }


# Create an instance of the FastAPI class
app = FastAPI()
broker_state = BrokerState()
# rid, customer state mapping
customers: Dict[str, CustomerState] = {}
templates = Jinja2Templates(directory="templates")


# Define a simple endpoint
@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


def unpack_message(json_message: dict) -> Tuple[bytes, bytes]:
    enc_message = json_message[MSG_KEY].encode(ENCODING_TYPE)
    message_hash = json_message[HASH_KEY].encode(ENCODING_TYPE)
    return enc_message, message_hash


def pack_message(enc_bytes: bytes, message_hash: bytes) -> Dict[str, str]:
    return {
        MSG_KEY: enc_bytes.decode(ENCODING_TYPE),
        HASH_KEY: message_hash.decode(ENCODING_TYPE),
    }


def auth_broker(encrypted_data):
    async def send_request():
        async with httpx.AsyncClient() as client:
            response = await client.post(broker_state.auth_api, json=encrypted_data)

            print("Response Status Code:", response.status_code)
            print("Response Content:", response.text)

            if response.status_code == 200:
                if response.json() == broker_state.request_id:
                    broker_state.auth_done = True
                    print(f"Mutual authentication with broker successfull")
                else:
                    broker_state.auth_done = False
            else:
                broker_state.auth_done = False
                raise HTTPException(
                    status_code=response.status_code,
                    detail="Failed to send JSON request",
                )

    asyncio.create_task(send_request())


def message_broker(encrypted_data):
    async def send_request():
        async with httpx.AsyncClient() as client:
            response = await client.post(broker_state.msg_api, json=encrypted_data)

            print("Response Status Code:", response.status_code)
            print("Response Content:", response.text)

            if response.status_code == 200:
                return {"message": "JSON request sent successfully"}
            else:
                raise HTTPException(
                    status_code=response.status_code,
                    detail="Failed to send JSON request",
                )

    asyncio.create_task(send_request())


def Send_Msg_MB(broker_dec_msg):
    choice = input("'A' for authentication with broker ").upper()

    if choice == "A":
        timestamp = str(datetime.now())
        # Create payload
        payload = {
            "TYPE": "MUTUAL_AUTHENTICATION",
            "ENTITY": "Merchant",
            "TIMESTAMP": timestamp,
            "PAYLOAD": {
                "REQUEST_ID": broker_state.request_id,
                "RESPONSE_ID": broker_dec_msg.get("PAYLOAD").get("REQUEST_ID"),
            },
        }

        payload_hash = enc_dec.enc.hash_256(json.dumps(payload).encode("latin1"))
        payload = json.dumps(payload)
        encrypted_data = rsa_encrypt_data(payload, broker_public_key)
        message_wrapper = {
            "MSG": encrypted_data.decode("latin1"),
            "HASH": payload_hash.decode("latin1"),
        }
        auth_broker(message_wrapper)
        print("Message Sent (Encrypted Format): ", message_wrapper)


@app.post("/handleinput")
async def handle_input(action_number: int = Form(...)):
    print(f"Sending request to broker {action_number}")

    # Add products
    if action_number == 1:
        pass


# region dh api
def DHKE_broker(encrypted_data):
    async def send_request():
        async with httpx.AsyncClient() as client:
            response = await client.post(broker_state.DHKE_api, content=encrypted_data)

            print("Response Status Code:", response.status_code)
            print("Response Content:", response.text)

            if response.status_code == 200:
                return {"message": "JSON request sent successfully"}
            else:
                raise HTTPException(
                    status_code=response.status_code,
                    detail="Failed to send JSON request",
                )

    asyncio.create_task(send_request())


@app.post("/DHKE_merchant")
async def DHKE_merchant(data: Request):
    # use keyed hash
    received_data = await data.body()
    received_data = received_data.decode("utf-8")
    received_data = json.loads(received_data)
    if "DHKE" == received_data["TYPE"]:
        public_key_BM = received_data["DH_PUBLIC_KEY"]
        print("Diffe_hellman : public key of Broker recieved")
        print("received payload:", received_data)
        broker_state.dh_session_key = Merchant.calculate_shared_secret(
            public_key_BM, broker_state.dh_private_key, broker_state.dh_prime
        )
        print(f"Merchant - Broker DH session key {broker_state.dh_session_key}")
        Merchant_Broker_DHKE()

    elif "DHKE WITH MERCHANT" == received_data["TYPE"]:
        RID = received_data["USERID"]
        customer_state = customers[RID]
        public_key_CM = received_data["DH_PUBLIC_KEY"]
        print("Diffe_hellman : public key of customer1 recieved:")
        customer_state.dh_session_key = Merchant.calculate_shared_secret(
            public_key_CM, customer_state.dh_private_key, customer_state.dh_prime
        )
        print(
            f"Merchant - Customer {RID} DH session key {customer_state.dh_session_key}"
        )
        Merchant_Customer_DHKE(customer_state)


# endregion


# region dh key gen


def Merchant_Broker_DHKE():
    timestamp = str(datetime.now())
    payload = {
        "TYPE": "DHKE",
        "DH_PUBLIC_KEY": broker_state.dh_public_key,
        "TS": timestamp,
    }

    payload = json.dumps(payload)
    print("Message Sent : ", payload)
    print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
    DHKE_broker(payload)


def Merchant_Customer_DHKE(customer_state: CustomerState):
    timestamp = str(datetime.now())
    payload = {
        "TYPE": "DHKE WITH Customer",
        "USERID": customer_state.random_id,
        "DH_PUBLIC_KEY": customer_state.dh_public_key,
        "TS": timestamp,
    }

    payload = json.dumps(payload)
    print("Message Sent : ", payload)
    print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
    DHKE_broker(payload)


# def Merchant_Customer2_DHKE():
#     timestamp = str(datetime.now())
#     payload = {
#         "TYPE": "DHKE WITH Customer",
#         "RID": CustomerRID2,
#         "DH_PUBLIC_KEY": public_key_MC2,
#         "TS": timestamp,
#     }

#     payload = json.dumps(payload)
#     print("Message Sent : ", payload)
#     print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
#     DHKE_broker(payload)


# endregion


def get_enc_payload_to_customer(customer_payload, broker_payload, customer_state):
    print(f"{stars}")
    print("Encrypting customer payload")
    customer_payload_hash = enc_dec.enc.keyed_hash(
        json.dumps(customer_payload).encode("latin1"), customer_state
    )
    customer_enc_payload = enc_dec.encrypt_payload(
        customer_payload,
        customer_state,
    )
    customer_packed_messagee = pack_message(customer_enc_payload, customer_payload_hash)

    print(f"Customer enc payload {customer_packed_messagee}")
    broker_payload["PAYLOAD"] = customer_packed_messagee
    broker_hash = enc_dec.enc.keyed_hash(
        json.dumps(broker_payload).encode("latin1"), broker_state
    )
    broker_enc_payload = enc_dec.encrypt_payload(broker_payload, broker_state)
    broker_packed_message = pack_message(broker_enc_payload, broker_hash)
    return broker_packed_message


def handle_message(customer_payload, rid):
    msg_type = customer_payload["TYPE"]
    if msg_type == "MERCHANT_AUTHENTICATION":
        if customer_payload["ENTITY"] == "Customer":
            timestamp = str(datetime.now())
            # message customer through broker
            broker_payload = {
                "TYPE": "CUSTOMER_AUTHENTICATION",
                "ENTITY": "Merchant",
                "USERID": f"{rid}",
                "TIMESTAMP": timestamp,
                "PAYLOAD": {
                    "ENTITY": "Merchant",
                    "RESPONSE_ID": customer_payload.get("REQUEST_ID"),
                },
            }
            broker_hash = enc_dec.enc.keyed_hash(
                json.dumps(broker_payload).encode("latin1"), broker_state
            )
            encrypt_broker_payload = enc_dec.encrypt_payload(
                broker_payload, broker_state
            )
            packed_encrypted_message = pack_message(encrypt_broker_payload, broker_hash)

            if not False:
                customers[rid] = CustomerState(rid, "state", True)
            else:
                return_msg = "INVALID, CUSTOMER ALREADY AUTHENTICATED"
                print(f"{return_msg}")
                return return_msg
            message_broker(packed_encrypted_message)

    elif msg_type == "VIEW_PRODUCTS":
        cust: CustomerState = customers.get(rid)
        customer_payload = {
            "TIMESTAMP": str(datetime.now()),
            "PRODUCTS": cust.Inventory,
        }
        broker_payload = {
            "TYPE": "TO_CUSTOMER",
            "ENTITY": "Merchant",
            "USERID": f"{rid}",
            "TIMESTAMP": str(datetime.now()),
            "PAYLOAD": "",
        }
        # handle rid
        cust: CustomerState = customers.get(rid)
        if cust is None:
            print("MERCHANT: PLEASE AUTH BEFORE YOU VIEW PRODUCTS")
        else:
            print(f"Customer {cust.iv}, {cust.session_key}")
            enc_payload = get_enc_payload_to_customer(
                customer_payload, broker_payload, cust
            )
            message_broker(enc_payload)

    elif msg_type == "BUY_PRODUCTS":
        Products = customer_payload["PRODUCTS"]
        cust: CustomerState = customers.get(rid)
        prods = cust.prods = {}
        Not_Available = {}
        for i in Products:
            for k in cust.Inventory.values():
                if int(i) == k["PID"]:
                    if int(Products[i]) <= k["Quantity"]:
                        prods["PRODUCT" + i] = {
                            "PID": int(i),
                            "Name": k["Name"],
                            "Quantity": Products[i],
                            "Price": k["Price"],
                        }
                        cust.payment = cust.payment + int(Products[i]) * int(
                            k["Price"][1:]
                        )
                    else:
                        prods["PRODUCT" + i] = {
                            "PID": int(i),
                            "Name": k["Name"],
                            "Quantity": Products[i],
                        }
                        Not_Available[k["PID"]] = k["Quantity"]
        if Not_Available != {}:
            p = "All Items are not available, You requested for following number of items"
            customer_payload = {
                "TIMESTAMP": str(datetime.now()),
                "MESSAGE": p,
                "PRODUCTS": prods,
                "HASH": "",
            }
            broker_payload = {
                "TYPE": "TO_CUSTOMER",
                "ENTITY": "Merchant",
                "USERID": f"{rid}",
                "TIMESTAMP": str(datetime.now()),
                "HASH": "",
                "PAYLOAD": "",
            }
            cust.prods = {}
            cust = customers.get(rid)
            if cust is None:
                print("MERCHANT: PLEASE AUTH BEFORE YOU VIEW PRODUCTS")
            else:
                print(f"Customer {cust.iv}, {cust.session_key}")
                enc_payload = get_enc_payload_to_customer(
                    customer_payload, broker_payload, cust
                )
                message_broker(enc_payload)
        else:
            customer_payload = {
                "TIMESTAMP": str(datetime.now()),
                "PRODUCTS": prods,
                "HASH": "",
            }
            broker_payload = {
                "TYPE": "PURCHASE_CONSENT",
                "ENTITY": "Merchant",
                "AMOUNT": cust.payment,
                "USERID": f"{rid}",
                "TIMESTAMP": str(datetime.now()),
                "HASH": "",
                "PAYLOAD": "",
            }
            cust = customers.get(rid)
            if cust is None:
                print("MERCHANT: PLEASE AUTH BEFORE YOU VIEW PRODUCTS")
            else:
                print(f"Customer {cust.iv}, {cust.session_key}")
                enc_payload = get_enc_payload_to_customer(
                    customer_payload, broker_payload, cust
                )
                message_broker(enc_payload)
    elif msg_type == "Payment--Done":
        cust = customers.get(rid)
        prods = cust.prods
        PRODUCTS = {}
        for j, i in zip(prods.keys(), prods.values()):
            PRODUCTS[j] = {
                "PID": i["PID"],
                "Name": i["Name"],
                "State": "Purchased",
            }
            cust.Inventory[i["PID"]]["Quantity"] = cust.Inventory[i["PID"]][
                "Quantity"
            ] - int(cust.prods["PRODUCT" + str(i["PID"])]["Quantity"])
        broker_payload = {
            "TYPE": "TO_CUSTOMER",
            "ENTITY": "Merchant",
            "USERID": f"{rid}",
            "TIMESTAMP": str(datetime.now()),
            "HASH": "",
            "PAYLOAD": "",
        }
        customer_payload = {
            "TIMESTAMP": str(datetime.now()),
            "PRODUCTS": PRODUCTS,
            "HASH": "",
        }
        # handle rid
        cust = customers.get(rid)
        if cust is None:
            print("MERCHANT: PLEASE AUTH BEFORE YOU VIEW PRODUCTS")
        else:
            print(f"Customer {cust.iv}, {cust.session_key}")
            enc_payload = get_enc_payload_to_customer(
                customer_payload, broker_payload, cust
            )
            message_broker(enc_payload)
            print("Updated Inventory after the purchase: \n")
            print(pd.DataFrame(cust.Inventory.values()))


def take_action_for_customer(payload, rid, enc_type):
    enc_payload = payload["PAYLOAD"]
    encrypted_message, message_hash = unpack_message(enc_payload)
    print(f"Encrypted payload from customer {enc_payload}")
    # decrypt using rsa
    if enc_type == "rsa":
        decypted_customer_msg = rsa_decrypt_data(
            encrypted_message, merchant_private_key
        )
        decrypted_customer_msg_json = json.loads(decypted_customer_msg)
        is_hash_validated = enc_dec.validate_rsa_hash(
            decypted_customer_msg, message_hash
        )
        print(
            f"Customer data decrypted {decrypted_customer_msg_json}, {rid=}, {is_hash_validated=}"
        )
        return handle_message(decrypted_customer_msg_json, rid)

    elif enc_type == "keyedhash":
        customer_state = customers.get(rid)
        if customer_state is None:
            print("MERCHANT: AUTH FIRST")
        else:
            decrypted_customer_msg_json = enc_dec.decrypt_data(
                encrypted_message, customer_state
            )
            is_customer_hash_valid = enc_dec.validate_hash(
                decrypted_customer_msg_json, message_hash, customer_state
            )
            print(
                f"Customer data decrypted {decrypted_customer_msg_json}, \n customer hash validated -> {is_customer_hash_valid}"
            )
            return handle_message(decrypted_customer_msg_json, rid)


# recieving message from broker
@app.post("/message_merchant")
async def message_merchant(data: Request):
    receieved_data = await data.json()
    encrypted_message, message_hash = unpack_message(receieved_data)
    print(f"Encrypted payload in bytes from broker {encrypted_message} \n {stars}")
    broker_msg_decrypted = enc_dec.decrypt_data(encrypted_message, broker_state)
    print(f"Decrypted data {broker_msg_decrypted} \n {stars}")
    msg_hash = enc_dec.validate_hash(broker_msg_decrypted, message_hash, broker_state)
    print(f"Hash of message from broker validated {msg_hash} \n{stars}")

    msg_type = broker_msg_decrypted["TYPE"]
    cust_id = broker_msg_decrypted["USERID"]
    if "MERCHANT_AUTHENTICATION" == msg_type:
        print("Payload received from Customer")
        return take_action_for_customer(broker_msg_decrypted, cust_id, "rsa")

    elif "FROM_CUSTOMER" == msg_type:
        # get the rid, get the customer, decrypt the message
        if True:
            return take_action_for_customer(broker_msg_decrypted, cust_id, "keyedhash")
    elif "PAYMENT_DONE" == msg_type:
        # get the rid, get the customer, decrypt the message
        if True:
            # update the inventory
            return handle_message({"TYPE": "Payment--Done"}, cust_id)


@app.post("/auth_merchant")
async def auth_merchant(data: Request):
    received_data = await data.json()
    encrypted_message, message_hash = unpack_message(received_data)
    print(f"original message {received_data}")
    print(f"Encrypted payload : {encrypted_message}\n ---- message hash {message_hash}")

    Decrypted_MESS = rsa_decrypt_data(encrypted_message, merchant_private_key)
    is_hash_validated = enc_dec.validate_rsa_hash(Decrypted_MESS, message_hash)
    print(f"Hash validated for customer ? {is_hash_validated=}")

    Decrypted_MESS = json.loads(Decrypted_MESS)
    formatted_data = json.dumps(Decrypted_MESS, indent=2)
    print(f"Received from Broker:\n {formatted_data}")

    if "MUTUAL_AUTHENTICATION" == Decrypted_MESS["TYPE"]:
        entity = Decrypted_MESS["ENTITY"]
        print(entity)
        if entity == "Broker":
            print("Authentication payload received from Broker.")
            Send_Msg_MB(Decrypted_MESS)

    # Perform any additional processing or return a response as needed
    # return {"message": "Data received successfully"}
