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
import message

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


# Create an instance of the FastAPI class
app = FastAPI()
broker_state = BrokerState()
templates = Jinja2Templates(directory="templates")


# Define a simple endpoint
@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


def auth_broker(encrypted_data):
    async def send_request():
        async with httpx.AsyncClient() as client:
            response = await client.post(broker_state.auth_api, content=encrypted_data)

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


def Send_Msg_MB():
    choice = input("'A' for authentication with broker ").upper()

    if choice == "A":
        timestamp = str(datetime.now())
        # Create payload
        payload = {
            "TYPE": "MUTUAL_AUTHENTICATION",
            "ENTITY": "Merchant",
            "PAYLOAD": {
                "MESSAGE": "Hi Broker",
                "FLAG": "VALIDATED",
                "TS": timestamp,
            },
        }

        # Convert payload to JSON format
        # json_auth_payload = json.dumps(auth_payload)

        # sign=signing(payload,self.merchant_private_key)
        payload = json.dumps(payload)
        encrypted_data = encrypt_data(payload, broker_public_key)
        auth_broker(encrypted_data)
        print("Message Sent (Encrypted Format): ", encrypted_data)


def Send_Msg_MC(RID):
    choice = input("'B' for sending message to broker").upper()

    if choice == "b":
        # Get the current timestamp
        timestamp = str(datetime.now())

        broker_payload = {
            "TYPE": "CUSTOMER_AUTHENTICATION",
            "ENTITY": "Merchant",
            "PAYLOAD": {
                "ENTITY": "Merchant",
                "Customer_Message": {
                    "MESSAGE": "Hi Customer",
                    "RID": f"{RID}",
                    "TS": timestamp,
                },
            },
        }

        # Convert payload to JSON format
        # sign=signing(payload,self.merchant_private_key)
        encrypted_data = encrypt_data(json.dumps(broker_payload), broker_public_key)
        auth_broker(encrypted_data)
        print(encrypted_data)


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


def handle_message(msg, rid):
    payload = msg["PAYLOAD"]
    if payload["TYPE"] == "MERCHANT_AUTHENTICATION":
        if payload["ENTITY"] == "Customer":
            timestamp = str(datetime.now())
            # message customer through broker
            broker_payload = {
                "TYPE": "CUSTOMER_AUTHENTICATION",
                "ENTITY": "Merchant",
                "RID": f"{rid}",
                "PAYLOAD": {
                    "ENTITY": "Merchant",
                    "MESSAGE": {
                        "MESSAGE": "Hi Customer, from merchant",
                        "TS": timestamp,
                        "Signature": "",
                    },
                },
            }
            encrypt_broker_payload, msg_hash = message.get_encrypted_payload(
                broker_payload, broker_state
            )
            message_broker(encrypt_broker_payload)


def CUSTOMER_MERCHANT(payload):
    enc_payload = payload["PAYLOAD"].encode("latin")
    print(f"{type(enc_payload)=}")
    # decrypt using rsa
    decypted_customer_msg = decrypt_data(enc_payload, merchant_private_key)
    decrypted_customer_msg_json = json.loads(decypted_customer_msg)
    print(f"Customer data decrypted {decrypted_customer_msg_json}")
    handle_message(decrypted_customer_msg_json, payload["USERID"])


@app.post("/message_merchant")
async def message_merchant(data: Request):
    # use keyed hash
    receieved_data = await data.body()
    # print("Encrypted payload :", receieved_data)
    broker_msg_decrypted = message.decrypt_data(receieved_data, broker_state)
    print(f"Decrypted data {type(broker_msg_decrypted)} {broker_msg_decrypted}")
    if "MERCHANT_AUTHENTICATION" == broker_msg_decrypted["TYPE"]:
        print("Payload received from Customer")
        CUSTOMER_MERCHANT(broker_msg_decrypted)
        print(f"Modified payload forwarded to Merchant")


@app.post("/auth_merchant")
async def auth_merchant(data: Request):
    received_data = await data.body()
    print("Encrypted payload:", received_data)

    Decrypted_MESS = decrypt_data(received_data, merchant_private_key)
    Decrypted_MESS = json.loads(Decrypted_MESS)
    formatted_data = json.dumps(Decrypted_MESS, indent=2)
    print(f"Received from Broker:\n {formatted_data}")

    if "MUTUAL_AUTHENTICATION" == Decrypted_MESS["TYPE"]:
        entity = Decrypted_MESS["ENTITY"]
        print(entity)
        if entity == "Broker":
            print("Authentication payload received from Broker.")
            Send_Msg_MB()

    elif "MERCHANT_AUTHENTICATION" == Decrypted_MESS["TYPE"]:
        entity = Decrypted_MESS["ENTITY"]
        RID = Decrypted_MESS["RID"]
        print(entity)
        if entity == "MERCHANT":
            print("Authentication payload received from Merchant.")
            Send_Msg_MC(RID)

    # Perform any additional processing or return a response as needed
    # return {"message": "Data received successfully"}
