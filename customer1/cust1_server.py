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
import message


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
        self.merchant_iv = b"6042302273"
        self.merchant_session_key = b"7289135233"


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
                return {"message": "JSON request sent successfully"}
            else:
                raise HTTPException(
                    status_code=response.status_code,
                    detail="Failed to send JSON request",
                )

    task = asyncio.create_task(send_request())


def message_broker(encrypted_data):
    # use keyed hash for sending messages after encryption
    async def send_message():
        async with httpx.AsyncClient() as client:
            response = await client.post(BROKER_MSG_API, content=encrypted_data)

            print("Response Status Code:", response.status_code)
            print("Response Content:", response.text)

            if response.status_code == 200:
                return {"message": "JSON request sent successfully"}
            else:
                raise HTTPException(
                    status_code=response.status_code,
                    detail="Failed to send JSON request",
                )

    asyncio.create_task(send_message())


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
        "PAYLOAD": {
            "ENTITY": "Customer",
            "MESSAGE": "Hi Merchant ********",
            "TYPE": "MERCHANT_AUTHENTICATION",
        }
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
    encrypted_data, signature = message.get_encrypted_payload(
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
        pass

    # buy product
    elif action_number == 4:
        pass


@app.post("/auth_customer1")
async def handle_customer_input(data: Request):
    receieved_data = await data.body()
    print("Encrypted payload :", receieved_data)
    Decrypted_MESS = decrypt_data(receieved_data, customer1_private_key)

    Decrypted_MESS = json.loads(Decrypted_MESS)
    formatted_data = json.dumps(Decrypted_MESS, indent=2)
    print(f"Received from Customer:\n {formatted_data}")
    print(f"Received data from customer {receieved_data}")

    if "MUTUAL_AUTHENTICATION" == Decrypted_MESS["TYPE"]:
        entity = Decrypted_MESS["ENTITY"]

        if entity == "Broker":
            print("Authentication payload received from Broker.")
            print("MUTUAL AUTHENTICATION DONE WITH MERCHANT")

    elif "FORWARD_TO_CUSTOMER_FOR_AUTHENTICATION" in Decrypted_MESS:
        sender_info = Decrypted_MESS["FORWARD_TO_CUSTOMER_FOR_AUTHENTICATION"][
            "SENDER_INFO"
        ]
        entity = sender_info.get["MERCHANT"]

        if entity == "MERCHANT":
            print("Authentication payload received from Broker.")
            print("Authentication done with Merchant")

    # Perform any additional processing or return a response as needed
    return {"message": "Data received successfully"}


# receiving msg from customer1
@app.post("/message_customer_1")
async def message_customer_1(data: Request):
    # use keyed hash
    receieved_data = await data.body()
    # print("Encrypted payload :", receieved_data)
    customer_msg_decrypted = message.decrypt_data(receieved_data, broker_state)
    print(f"Decrypted data {customer_msg_decrypted}")
    # create a new payload to merchant
    if "MERCHANT_AUTHENTICATION" == customer_msg_decrypted["TYPE"]:
        print("Payload received from broker")
        # print(f"Modified payload forwarded to Merchant")


# endregion
