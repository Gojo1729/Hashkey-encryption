import asyncio
from fastapi import Depends, FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from Auth_decryption import decrypt_data
from Auth_encryption import encrypt_data
from datetime import datetime
import json
import httpx
import enc_dec

# broker_public_key = "../bro_pub.pem"
# merchant_private_key = "../mer_pri.pem"
# merchant_public_key = "../mer_pub.pem"


broker_public_key = "../OLD KEYS/broker_public_key.pem"
merchant_public_key = "../OLD KEYS/merchant_public_key.pem"
merchant_private_key = "../OLD KEYS/merchant_private_key.pem"


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


class CustomerState:
    def __init__(self, rid, state, auth_done) -> None:
        self.random_id = rid
        self.state = state
        self.auth_done = auth_done
        # assume DH is done
        self.iv = b"6042302272"
        self.session_key = b"7289135232"


# Create an instance of the FastAPI class
app = FastAPI()
broker_state = BrokerState()
# rid, customer state mapping
customers: dict[str, CustomerState] = {}
templates = Jinja2Templates(directory="templates")


# Define a simple endpoint
@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


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
            response = await client.post(broker_state.msg_api, content=encrypted_data)

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
        encrypted_data = encrypt_data(payload, broker_public_key)
        message_wrapper = {
            "MSG": encrypted_data.decode("latin1"),
            "HASH": payload_hash.decode("latin1"),
        }
        auth_broker(message_wrapper)
        print("Message Sent (Encrypted Format): ", message_wrapper)


@app.post("/handleinput")
async def handle_input(action_number: int = Form(...)):
    print(f"Sending request to broker {action_number}")

    # send auth request to broker
    if action_number == 1:
        pass
    # send auth request to merchant
    elif action_number == 2:
        return {"message": "Sending request to merchant"}
    # view products
    elif action_number == 3:
        pass

    # buy product
    elif action_number == 4:
        pass


def get_enc_payload_to_customer(customer_payload, broker_payload, customer_state):
    customer_enc_payload = enc_dec.encrypt_payload(
        customer_payload,
        customer_state,
    )
    c_e = customer_enc_payload.decode("latin1")
    print(f"Customer enc payload {customer_enc_payload}")
    broker_payload["PAYLOAD"] = c_e
    broker_enc_payload = enc_dec.encrypt_payload(broker_payload, broker_state)

    return broker_enc_payload


def handle_message(payload, rid):
    msg_type = payload["TYPE"]
    if msg_type == "MERCHANT_AUTHENTICATION":
        if payload["ENTITY"] == "Customer":
            timestamp = str(datetime.now())
            # message customer through broker
            broker_payload = {
                "TYPE": "CUSTOMER_AUTHENTICATION",
                "ENTITY": "Merchant",
                "RID": f"{rid}",
                "PAYLOAD": {
                    "ENTITY": "Merchant",
                    "RESPONSE_ID": payload.get("REQUEST_ID"),
                },
            }
            encrypt_broker_payload = enc_dec.encrypt_payload(
                broker_payload, broker_state
            )
            if not False:
                customers[rid] = CustomerState(rid, "state", True)
            else:
                return_msg = "INVALID, CUSTOMER ALREADY AUTHENTICATED"
                print(f"{return_msg}")
                return return_msg
            message_broker(encrypt_broker_payload)

    elif msg_type == "VIEW_PRODUCTS":
        customer_payload = {
            "TIMESTAMP": str(datetime.now()),
            "PRODUCTS": {
                "PROD1": {"PID": 1, "NAME": "WATCH"},
                "PROD2": {"PID": 1, "NAME": "WATCH"},
            },
            "HASH": "",
        }
        broker_payload = {
            "TYPE": "TO_CUSTOMER",
            "ENTITY": "Merchant",
            "RID": f"{rid}",
            "TIMESTAMP": str(datetime.now()),
            "HASH": "",
            "PAYLOAD": "",
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

    elif msg_type == "BUY_PRODUCTS":
        pass


def take_action_for_customer(payload, rid, enc_type):
    enc_payload = payload["PAYLOAD"].encode("latin1")
    print(f"encpayload {enc_payload}, {type(enc_payload)=}")
    # decrypt using rsa
    if enc_type == "rsa":
        decypted_customer_msg = decrypt_data(enc_payload, merchant_private_key)
        decrypted_customer_msg_json = json.loads(decypted_customer_msg)
        print(f"Customer data decrypted {decrypted_customer_msg_json}, {rid=}")
        return handle_message(decrypted_customer_msg_json, rid)

    elif enc_type == "keyedhash":
        customer = customers.get(rid)
        if customer is None:
            print("MERCHANT: AUTH FIRST")
        else:
            decrypted_customer_msg_json = enc_dec.decrypt_data(enc_payload, customer)
            print(f"Customer data decrypted {decrypted_customer_msg_json}")
            return handle_message(decrypted_customer_msg_json, rid)


# use keyed hash
@app.post("/message_merchant")
async def message_merchant(data: Request):
    receieved_data = await data.body()

    # print("Encrypted payload :", receieved_data)
    broker_msg_decrypted = enc_dec.decrypt_data(receieved_data, broker_state)
    print(
        f"Decrypted data from broker {type(broker_msg_decrypted)} {broker_msg_decrypted}"
    )
    msg_type = broker_msg_decrypted["TYPE"]
    cust_id = broker_msg_decrypted["USERID"]
    if "MERCHANT_AUTHENTICATION" == msg_type:
        print("Payload received from Customer")
        return take_action_for_customer(broker_msg_decrypted, cust_id, "rsa")

    elif "FROM_CUSTOMER" == msg_type:
        # get the rid, get the customer, decrypt the message
        if True:
            return take_action_for_customer(broker_msg_decrypted, cust_id, "keyedhash")


@app.post("/auth_merchant")
async def auth_merchant(data: Request):
    received_data = await data.json()
    encrypted_message = received_data["MSG"].encode("latin1")
    message_hash = received_data["HASH"].encode("latin1")
    print("Encrypted payload:", received_data)

    Decrypted_MESS = decrypt_data(encrypted_message, merchant_private_key)
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
