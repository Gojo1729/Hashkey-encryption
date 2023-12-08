import asyncio
from fastapi import Depends, FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from Auth_decryption import decrypt_data
from Auth_encryption import rsa_encrypt_data
from datetime import datetime
import json
import httpx
import enc_dec
import time

# broker_public_key = "../bro_pub.pem"
# customer1_private_key = "../cus1_pri.pem"
# customer1_public_key = "../cus1_pub.pem"
# merchant_public_key = "../mer_pub.pem"

broker_public_key = "../OLD KEYS/broker_public_key.pem"
merchant_public_key = "../OLD KEYS/merchant_public_key.pem"
customer1_public_key = "../OLD KEYS/customer1_public_key.pem"
customer1_private_key = "../OLD KEYS/customer1_private_key.pem"

BROKER_API = f"http://127.0.0.1:8002"
BROKER_AUTH_API = f"{BROKER_API}/auth_broker"
BROKER_MSG_API = f"{BROKER_API}/message_customer_1_broker"


class CustomerInput(BaseModel):
    action_number: int
    enc_data: bytes


class BrokerState:
    def __init__(self) -> None:
        self.state = None
        self.auth_done = False
        # assume DH is done
        self.iv = b"4832500747"
        self.session_key = b"4103583911"


class MerchantState:
    def __init__(self) -> None:
        self.state = None
        self.auth_done = False
        self.iv = b"6042302272"
        self.session_key = b"7289135232"


global_userid = "C1"
global_password = ""

# region broker messages

# Create an instance of the FastAPI class
app = FastAPI()
broker_state = BrokerState()
merchant_state = MerchantState()
templates = Jinja2Templates(directory="templates")


def auth_broker(encrypted_data):
    # use rsa keys for auth
    async def send_request():
        async with httpx.AsyncClient() as client:
            response = await client.post(BROKER_AUTH_API, content=encrypted_data)

            print("Response Status Code:", response.status_code)
            print("Response Content:", response.text)

            if response.status_code == 200:
                return {"message": "Auth request sent to broker"}

            else:
                raise HTTPException(
                    status_code=response.status_code,
                    detail="Failed to send JSON request",
                )

    asyncio.create_task(send_request())


def message_broker(encrypted_data):
    # use keyed hash for sending messages after encryption
    async def send_message():
        async with httpx.AsyncClient() as client:
            response = await client.post(BROKER_MSG_API, content=encrypted_data)

            print("Response Status Code:", response.status_code)
            print("Response Content:", response.text)

            if response.status_code == 200:
                return {"message": "Sent data to broker"}
            else:
                raise HTTPException(
                    status_code=response.status_code,
                    detail="Failed to send data to broker request",
                )

    asyncio.create_task(send_message())


def get_enc_payload_to_merchant(merchant_payload, broker_payload):
    print("Encrypting merchant payload")
    merchant_enc_payload, merchant_hash = enc_dec.get_encrypted_payload(
        merchant_payload, merchant_state
    )
    broker_payload["PAYLOAD"] = merchant_enc_payload.decode("latin1")
    # broker_payload["PAYLOAD"]["HASH"] = merchant_hash

    broker_enc_payload, broker_hash = enc_dec.get_encrypted_payload(
        broker_payload, broker_state
    )

    return broker_enc_payload


def send_message(action):
    action = action.upper()
    if action == "VIEW_PRODUCTS":
        merchant_payload = {
            "TYPE": action,
            "TIMESTAMP": str(datetime.now()),
            "HASH": "",
        }
        broker_payload = {
            "USERID": global_userid,
            "HASH": "",
            "TYPE": "TO_MERCHANT",
            "TIMESTAMP": str(datetime.now()),
            "PAYLOAD": "",
        }
        enc_payload = get_enc_payload_to_merchant(merchant_payload, broker_payload)
        message_broker(enc_payload)


# endregion


# region encrypt
@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


def auth_payload_for_broker():
    global_userid = input("Enter your USER_ID: ")
    global_password = input("Enter your password: ")

    # Get the current timestamp
    timestamp = str(datetime.now())
    # PAYLOAD
    payload = {
        "TYPE": "MUTUAL_AUTHENTICATION",
        "ENTITY": "Customer",
        "PAYLOAD": {
            "MESSAGE": "Hi Broker",
            "LOGINCRED": {
                "UID": "Customer_1",
                "USER_ID": global_userid,
                "PASSWORD": global_password,
            },
            "TS": timestamp,
        },
    }

    # sign=signing(payload,self.customer1_private_key)
    payload = json.dumps(payload)
    encrypted_data = rsa_encrypt_data(payload, broker_public_key)
    print("Message Sent (Encrypted Format): ", encrypted_data)
    print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
    auth_broker(encrypted_data)


async def auth_payload_to_merchant():
    # customer to merchant auth
    """
    1. Encrypt customer payload to merchant using merchant's public key
    2. Then encrypt the whole thing using Customer 1 and broker session key using keyed hash
    """

    timestamp = str(datetime.now())

    # #PAYLOAD
    Merchant_Payload = {
        "ENTITY": "Customer",
        "MESSAGE": "Hi Merchant ********",
        "TYPE": "MERCHANT_AUTHENTICATION",
    }

    Merchant_Payload_JSON = json.dumps(Merchant_Payload)
    Merchant_Encrypted_Payload: bytes = rsa_encrypt_data(
        Merchant_Payload_JSON, merchant_public_key
    )
    print(f"Merchant payload {str(Merchant_Encrypted_Payload)}")
    broker_payload = {
        "TYPE": "MERCHANT_AUTHENTICATION",
        "ENTITY": "Customer",
        "USERID": global_userid,
        "PAYLOAD": Merchant_Encrypted_Payload.decode("latin1"),
        "TS": timestamp,
    }

    # # sign=signing(payload,self.customer1_private_key)
    # broker_payload = json.dumps(broker_payload)
    encrypted_data, signature = enc_dec.get_encrypted_payload(
        broker_payload, broker_state
    )
    # print("Message Sent (Encrypted Format): ", encrypted_data)
    print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
    message_broker(encrypted_data)


# endregion


# region APIs
@app.post("/handleinput")
async def handle_input(action_number: int = Form(...)):
    print(f"Sending message to broker {action_number}")

    # send auth request to broker
    if action_number == 1:
        timestamp = str(datetime.now())
        # PAYLOAD
        auth_payload_for_broker()

    # send auth request to merchant through broker
    elif action_number == 2:
        await auth_payload_to_merchant()

        return {"message": "Sending request to merchant"}

    # view products
    elif action_number == 3:
        print(f"sending view prod request to merchant through broker")
        send_message("VIEW_PRODUCTS")

    # buy product
    elif action_number == 4:
        pass


@app.post("/auth_customer_1")
async def handle_customer_input(data: Request):
    receieved_data = await data.body()
    print("Encrypted payload :", receieved_data)
    Decrypted_MESS = decrypt_data(receieved_data, customer1_private_key)

    Decrypted_MESS = json.loads(Decrypted_MESS)
    formatted_data = json.dumps(Decrypted_MESS, indent=2)
    print(f"Received from Broker:\n {formatted_data}")

    if "MUTUAL_AUTHENTICATION" == Decrypted_MESS["TYPE"]:
        entity = Decrypted_MESS["ENTITY"]
        if entity == "Broker":
            payload = Decrypted_MESS["PAYLOAD"]
            if payload["FLAG"] == "VALIDATED":
                print("Mutual authentication with broker successfull")
                broker_state.auth_done = True
                # return templates.TemplateResponse("index.html", {"request": data})
                return "VALIDATED"
            else:
                broker_state.auth_done = False


# receiving msg from broker
@app.post("/message_customer_1")
async def message_customer_1(data: Request):
    # use keyed hash
    receieved_data = await data.body()
    # print("Encrypted payload :", receieved_data)
    broker_msg_decrypted = enc_dec.decrypt_data(receieved_data, broker_state)
    # print(f"Decrypted data {broker_msg_decrypted}")
    # create a new payload to merchant
    if "MERCHANT_AUTHENTICATION" == broker_msg_decrypted["TYPE"]:
        print(f"Payload received from broker {broker_msg_decrypted}")
        # print(f"Modified payload forwarded to Merchant")

    elif "FROM_MERCHANT" == broker_msg_decrypted["TYPE"]:
        merchant_payload = broker_msg_decrypted["PAYLOAD"].encode("latin1")
        print(f"Merchant keys {merchant_state.iv}, {merchant_state.session_key}")
        print(f"Payload received from merchant {merchant_payload}")
        merchant_msg_decrypted = enc_dec.decrypt_data(merchant_payload, merchant_state)
        print(f"Merchant data decrypted {merchant_msg_decrypted['PRODUCTS']}")
        return "VALID"


# endregion
