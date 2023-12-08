from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from Auth_decryption import decrypt_data
from Auth_encryption import encrypt_data
from datetime import datetime
import json
import httpx
import pandas as pd
import asyncio
import message


# broker_public_key = "../bro_pub.pem"
# broker_private_key = "../bro_pri.pem"
# customer1_public_key = "../cus_pub.pem"
# merchant_public_key = "../mer_pub.pem"

broker_public_key = "../OLD KEYS/broker_public_key.pem"
broker_private_key = "../OLD KEYS/broker_private_key.pem"


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


class MerchantState:
    def __init__(self) -> None:
        self.host = "http://127.0.0.1:8003"
        self.msg_api = f"{self.host}/message_merchant"
        self.auth_api = f"{self.host}/auth_merchant"
        self.state = None
        self.auth_done = False
        self.iv = b"6042302273"
        self.session_key = b"7289135233"
        self.public_key = "../OLD KEYS/merchant_public_key.pem"


# Create an instance of the FastAPI class
app = FastAPI()
templates = Jinja2Templates(directory="templates")
customer1_state = Customer1State()
customer2_state = Customer2State()
customers_state = {"C1": customer1_state, "C2": customer2_state}
merchant_state = MerchantState()


# region send message
def handle_response(response):
    print("Response Status Code:", response.status_code)
    print("Response Content:", response.text)

    if response.status_code == 200:
        print("Auth response sent successfully")
    else:
        raise HTTPException(
            status_code=response.status_code, detail="Failed to send JSON request"
        )


def send_message(state, encrypted_data, auth=False):
    async def send_request():
        async with httpx.AsyncClient() as client:
            if auth:
                response = await client.post(state.auth_api, content=encrypted_data)
                handle_response(response)
            else:
                response = await client.post(state.msg_api, content=encrypted_data)
                handle_response(response)

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

    choice = input("Press A to send authentication request with customer").upper()
    if choice == "A":
        MESSAGE = f"Hi {user_id} , Login Successful"
        timestamp = str(datetime.now())
        auth_payload = {
            "TYPE": "MUTUAL_AUTHENTICATION",
            "ENTITY": "Broker",
            "PAYLOAD": {
                "MESSAGE": MESSAGE,
                "FLAG": "VALIDATED",
                "TS": timestamp,
            },
        }
        payload = json.dumps(auth_payload)
        encrypted_data = encrypt_data(payload, valid_user.public_key)
        # sign=signing(payload,self.broker_private_key)
        send_message(valid_user, encrypted_data, auth=True)


def BROKER_MERCHANT():
    timestamp = str(datetime.now())

    # Create payload
    auth_payload = {
        "TYPE": "MUTUAL_AUTHENTICATION",
        "ENTITY": "Broker",
        "PAYLOAD": {"MESSAGE": "HI MERCHANT", "FLAG": "VALIDATE", "TS": timestamp},
    }

    # Convert payload to JSON format
    payload = json.dumps(auth_payload)
    encrypted_data = encrypt_data(payload, merchant_state.public_key)
    # sign = signing(payload,self.broker_private_key)
    send_message(merchant_state, encrypted_data, auth=True)
    print("Authentication response sent to Merchant.")


def CUSTOMER_MERCHANT(Decrypted_MESS):
    random_customer_id: str = customers_state[Decrypted_MESS["USERID"]].random_id
    Decrypted_MESS["USERID"] = random_customer_id
    Decrypted_MESS["ENTITY"] = "Broker"
    Decrypted_MESS["SIGNATURE"] = ""
    print(f"payload to merchant {Decrypted_MESS}, type {type(Decrypted_MESS)}")
    payload = json.dumps(Decrypted_MESS)
    (
        encrypted_payload_to_merchant,
        merchant_hash,
    ) = message.encrypt_data(payload, merchant_state)
    # encrypted_data = encrypt_data(payload, merchant_public_key)
    # sign=signing(payload,self.broker_private_key)
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
    # view products
    elif action_number == 3:
        BROKER_MERCHANT()
        return {"message": "Sending request to merchant"}

    # buy product


# used by other stakeholders to authenticate mutually with broker
@app.post("/auth_broker")
async def auth_broker(data: Request):
    receieved_data = await data.body()
    print("Encrypted payload :", receieved_data)
    Decrypted_MESS = decrypt_data(receieved_data, broker_private_key)

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
            if Decrypted_MESS["PAYLOAD"]["FLAG"] == "VALIDATED":
                print("MUTUAL AUTHENTICATION DONE WITH MERCHANT")
                merchant_state.auth_done = True
                return_msg = {
                    "message": "Hi Merchant, you and broker are mutually authenticated"
                }

        elif entity == "Customer":
            login_cred = Decrypted_MESS["PAYLOAD"]["LOGINCRED"]
            print(login_cred)
            print("Authentication payload received from Customer.")
            return_msg = BROKER_CUSTOMER(login_cred)

    else:
        print("Received payload does not contain any information to forward.")

    return return_msg


# receving msg from merchant
@app.post("/message_merchant_broker")
async def message_merchant_broker(data: Request):
    # use keyed hash
    receieved_data = await data.body()
    # print("Encrypted payload :", receieved_data)
    merchant_msg_decrypted = message.decrypt_data(receieved_data, merchant_state)
    print(f"Decrypted data {merchant_msg_decrypted}, {type(merchant_msg_decrypted)=}")
    # create a new payload to merchant
    if "CUSTOMER_AUTHENTICATION" == merchant_msg_decrypted["TYPE"]:
        rid = merchant_msg_decrypted["RID"]
        for customer in customers_state.values():
            if customer.random_id == rid:
                timestamp = str(datetime.now())
                print("Payload received from Merchant")
                print(f"Modified payload forwarded to customer")
                # encrypt payload to customer
                customer_payload = {
                    "TYPE": "MERCHANT_AUTHENTICATION",
                    "ENTITY": "BROKER",
                    "PAYLOAD": {
                        "ENTITY": "Merchant",
                        "Customer_Message": {
                            "MESSAGE": "Hi Customer, merchant is successfully authenticated",
                            "TS": timestamp,
                            "Signature": "",
                        },
                    },
                }
                enc_payload, msg_hash = message.encrypt_data(customer_payload, customer)
                send_message(customer, enc_payload, auth=False)


# receiving msg from customer1
@app.post("/message_customer_1_broker")
async def message_customer_1_broker(data: Request):
    # use keyed hash
    receieved_data = await data.body()
    # print("Encrypted payload :", receieved_data)
    customer_msg_decrypted = message.decrypt_data(receieved_data, customer1_state)
    print(f"Decrypted data {customer_msg_decrypted}, {type(customer_msg_decrypted)=}")
    # create a new payload to merchant
    if "MERCHANT_AUTHENTICATION" == customer_msg_decrypted["TYPE"]:
        print("Payload received from Customer")
        CUSTOMER_MERCHANT(customer_msg_decrypted)
        print(f"Modified payload forwarded to Merchant")


# receiving msg from customer1
@app.post("/message_customer_2_broker")
async def message_customer_2_broker(data: Request):
    # use keyed hash
    receieved_data = await data.body()
    # print("Encrypted payload :", receieved_data)
    customer_msg_decrypted = message.decrypt_data(receieved_data, customer1_state)
    print(f"Decrypted data {customer_msg_decrypted}, {type(customer_msg_decrypted)=}")
    # create a new payload to merchant
    if "MERCHANT_AUTHENTICATION" == customer_msg_decrypted["TYPE"]:
        print("Payload received from Customer")
        CUSTOMER_MERCHANT(customer_msg_decrypted)
        print(f"Modified payload forwarded to Merchant")
