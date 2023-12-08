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
merchant_public_key = "../OLD KEYS/merchant_public_key.pem"
customer1_public_key = "../OLD KEYS/customer1_public_key.pem"
customer2_public_key = "../OLD KEYS/customer2_public_key.pem"


customer_id_mapping = {"C1": "6514161"}
key_list = list(customer_id_mapping.keys())
val_list = list(customer_id_mapping.values())

login_data = pd.read_excel("../broker.xlsx", sheet_name="LOGIN")


class CustomerData(BaseModel):
    enc_data: bytes


class Customer1State:
    def __init__(self) -> None:
        self.host = "http://127.0.0.1:8001"
        self.msg_api = f"{self.host}/message_customer_1"
        self.auth_api = f"{self.host}/auth_customer_1"
        self.state = None
        self.auth_done = False
        # assume DH is done
        self.iv = b"4832500747"
        self.session_key = b"4103583911"


class Customer2State:
    def __init__(self) -> None:
        self.host = "http://127.0.0.1:8004"
        self.msg_api = f"{self.host}/message_customer_2"
        self.auth_api = f"{self.host}/auth_customer_2"
        self.state = None
        self.auth_done = False
        # assume DH is done
        self.iv = b"4832500747"
        self.session_key = b"4103583911"


class MerchantState:
    def __init__(self) -> None:
        self.host = "http://127.0.0.1:8003"
        self.msg_api = f"{self.host}/message_merchant"
        self.auth_api = f"{self.host}/auth_merchant"
        self.state = None
        self.auth_done = False
        self.iv = b"6042302273"
        self.session_key = b"7289135233"


# Create an instance of the FastAPI class
app = FastAPI()
templates = Jinja2Templates(directory="templates")
customer1_state = Customer1State()
customer2_state = Customer2State()
merchant_state = MerchantState()


def handle_response(response):
    print("Response Status Code:", response.status_code)
    print("Response Content:", response.text)

    if response.status_code == 200:
        return {"message": "JSON request sent successfully"}
    else:
        raise HTTPException(
            status_code=response.status_code, detail="Failed to send JSON request"
        )


def auth_stakeholders(entity, encrypted_data):
    async def send_request():
        if entity == "Merchant":
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    merchant_state.auth_api, content=encrypted_data
                )
                handle_response(response)
        elif entity == "Customer1":
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    customer1_state.auth_api, content=encrypted_data
                )
                handle_response(response)
                print("TEST")
                print(encrypted_data)
        elif entity == "Customer2":
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    customer2_state.auth_api, content=encrypted_data
                )
                handle_response(response)
        else:
            print("INVALID ENTITY")

    asyncio.create_task(send_request())


def send_message_to_merchant(encrypted_data):
    # use keyed hash for sending messages after encryption
    async def send_message():
        async with httpx.AsyncClient() as client:
            response = await client.post(merchant_state.msg_api, content=encrypted_data)

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


def validate_credentials(user_id, passwd):
    print(f"Validating: User ID = {user_id}, Password = {passwd}")

    # Check if user_id exists in the 'USER ID' column
    if user_id in login_data["USER ID"].values:
        user_row = login_data[login_data["USER ID"] == user_id]
        print(f"Found user row: {user_row}")

        # Check if the provided password matches the stored password
        if passwd == user_row["PASSWORD"].values[0]:
            print("Credentials are valid.")
            return True

    # If user_id doesn't exist or passwords don't match, return False
    return False


def BROKER_CUSTOMER(login_creds):
    user_id = login_creds.get("USER_ID")
    password = login_creds.get("PASSWORD")
    MESSAGE = "Hi {user_id} , Login Unsuccessful, Invalid Credentials"
    if validate_credentials(user_id, password):
        choice = input("'A' for authentication with Customer ").upper()
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
            encrypted_data = encrypt_data(payload, customer1_public_key)
            # sign=signing(payload,self.broker_private_key)
            print("Return MSG start")
            auth_stakeholders("Customer1", encrypted_data)
    else:
        print("Invalid credentials")
        return {"message": "Invalid credentials"}


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
    encrypted_data = encrypt_data(payload, merchant_public_key)
    # sign = signing(payload,self.broker_private_key)
    auth_stakeholders("Merchant", encrypted_data)
    print("Authentication response sent to Merchant.")


def CUSTOMER_MERCHANT(Decrypted_MESS):
    random_customer_id: str = str(customer_id_mapping[Decrypted_MESS["USERID"]])
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
    send_message_to_merchant(encrypted_payload_to_merchant)


def MERCHANT_CUSTOMER(Decrypted_MESS):
    authentication_data = Decrypted_MESS["CUSTOMER_AUTHENTICATION"]
    if "SENDER_INFO" in authentication_data:
        sender_info = authentication_data["SENDER_INFO"]
        if "ID" in sender_info:
            del sender_info["ID"]
            if "ID" == "CUS1":
                user = "c1"
                sender_info["USER_ID"] = user
                Type = "customer1"
            elif "ID" == "CUS2":
                user = "c2"
                sender_info["USER_ID"] = user
                Type = "customer2"

                payload = json.dumps(Decrypted_MESS)
                encrypted_data = encrypt_data(payload, customer1_public_key)
                # signature=signing(payload,self.broker_private_key)
                auth_stakeholders("Customer1", encrypted_data)


# Define a simple endpoint
@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/handleinput")
async def handle_input(action_number: int = Form(...)):
    print(f"Sending request to broker {action_number}")

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


@app.post("/auth_broker")
async def auth_broker(data: Request):
    receieved_data = await data.body()
    print("Encrypted payload :", receieved_data)
    Decrypted_MESS = decrypt_data(receieved_data, broker_private_key)

    Decrypted_MESS = json.loads(Decrypted_MESS)
    formatted_data = json.dumps(Decrypted_MESS, indent=2)
    print(f"Received from Customer:\n {formatted_data}")
    print(f"Received data from customer {receieved_data}")
    return_msg = ""
    if "MUTUAL_AUTHENTICATION" == Decrypted_MESS["TYPE"]:
        entity = Decrypted_MESS["ENTITY"]
        print(entity)
        if entity == "Merchant":
            print("Authentication payload received from Merchant.")
            if Decrypted_MESS["PAYLOAD"]["FLAG"] == "VALIDATED":
                print("MUTUAL AUTHENTICATION DONE WITH MERCHANT")
        else:
            login_cred = Decrypted_MESS["PAYLOAD"]["LOGINCRED"]
            print(login_cred)
            print("Authentication payload received from Customer.")
            return_msg = BROKER_CUSTOMER(login_cred)

    elif "MERCHANT_AUTHENTICATION_RESPONSE" == Decrypted_MESS:
        print("Customer--Merchant Authentication Response Received")
        return_msg = MERCHANT_CUSTOMER(Decrypted_MESS)
        print(f"Modified payload forwarded to Customer")

    else:
        print("Received payload does not contain any information to forward.")

    return return_msg


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


# receiving msg from customer2
@app.post("/message_customer_2_broker")
async def message_customer_2_broker(data: Request):
    # use keyed hash
    receieved_data = await data.body()
    # print("Encrypted payload :", receieved_data)
    customer_msg_decrypted = message.decrypt_data(receieved_data, customer2_state)
    print(f"Decrypted data {customer_msg_decrypted}, {type(customer_msg_decrypted)=}")
    # create a new payload to merchant
    if "CUSTOMER_AUTHENTICATION" == customer_msg_decrypted["TYPE"]:
        print("Payload received from Customer")
        # CUSTOMER_MERCHANT(customer_msg_decrypted)
        print(f"Modified payload forwarded to Merchant")


def message_customer_1(encrypted_data, state):
    async def send_message():
        async with httpx.AsyncClient() as client:
            response = await client.post(state.msg_api, content=encrypted_data)

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
        if key_list[val_list.index(rid)] == "C1":
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
                        "MESSAGE": "Hi Customer, from merchant",
                        "TS": timestamp,
                        "Signature": "",
                    },
                },
            }
            enc_payload, msg_hash = message.encrypt_data(
                customer_payload, customer1_state
            )
            message_customer_1(enc_payload, customer1_state)
