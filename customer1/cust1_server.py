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
import time
import pandas as pd
from DH import DiffieHellman
from typing import Tuple, Dict
import logging


class CustomFormatter(logging.Formatter):
    grey = "\x1b[38;20m"
    yellow = "\x1b[33;20m"
    red = "\x1b[31;20m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"
    blue = "\x1b[34m"
    white = "\x1b[97m"
    green = "\x1b[32m"
    bold_green = "\x1b[1m\x1b[32m"
    format = "%(message)s"  # type: ignore

    FORMATS = {
        logging.DEBUG: grey + format + reset,  # type: ignore
        logging.INFO: bold_green + format + reset,  # type: ignore
        logging.WARNING: yellow + format + reset,  # type: ignore
        logging.ERROR: blue + format + reset,  # type: ignore
        logging.CRITICAL: bold_red + format + reset,  # type: ignore
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)


# create logger with 'spam_application'
logger = logging.getLogger("My_app")
logger.setLevel(logging.DEBUG)

# create console handler with a higher log level
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)

ch.setFormatter(CustomFormatter())

logger.addHandler(ch)


# broker_public_key = "../bro_pub.pem"
# customer1_private_key = "../cus1_pri.pem"
# customer1_public_key = "../cus1_pub.pem"
# merchant_public_key = "../mer_pub.pem"

broker_public_key = "../OLD KEYS/broker_public_key.pem"
merchant_public_key = "../OLD KEYS/merchant_public_key.pem"
customer_1_public_key = "../OLD KEYS/customer1_public_key.pem"
customer_1_private_key = "../OLD KEYS/customer1_private_key.pem"

BROKER_API = f"http://127.0.0.1:8002"
BROKER_AUTH_API = f"{BROKER_API}/auth_broker"
BROKER_MSG_API = f"{BROKER_API}/message_customer_1_broker"
BROKER_DHKEC1_API = f"{BROKER_API}/DHKE_Customer1_broker"
# as we don't have access to the DH keys before authentication, we will use this key for generating hash

Customer1 = DiffieHellman()


class CustomerInput(BaseModel):
    action_number: int
    enc_data: bytes


class BrokerState:
    def __init__(self) -> None:
        self.state = None
        self.auth_done = False
        # assume DH is done
        # self.iv = b"4832500747"
        # self.session_key = b"4103583911"
        self.session_key, self.iv = None, None
        self.request_id = "10129120"
        (
            self.dh_private_key,
            self.dh_public_key,
            self.dh_prime,
        ) = Customer1.generate_keypair(10000000019)
        self.dh_shared_key = None


class MerchantState:
    def __init__(self) -> None:
        self.state = None
        self.auth_done = False
        # self.iv = b"6042302272"
        # self.session_key = b"7289135232"
        self.session_key, self.iv = None, None
        self.request_id = "129129"
        (
            self.dh_private_key,
            self.dh_public_key,
            self.dh_prime,
        ) = Customer1.generate_keypair(10000000061)
        self.dh_shared_key = None


global_userid = "C1"
AUTH_MSG = "auth"
DHKE_MSG = "dhke"
KEYED_MSG = "kh"
MSG_KEY = "MSG"
HASH_KEY = "HASH"
ENCODING_TYPE = "latin1"

# Create an instance of the FastAPI class
app = FastAPI()
broker_state = BrokerState()
merchant_state = MerchantState()
templates = Jinja2Templates(directory="templates")


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
    # use rsa keys for auth
    async def send_request():
        async with httpx.AsyncClient() as client:
            # response = await client.post(BROKER_AUTH_API, content=encrypted_data)
            response = await client.post(BROKER_AUTH_API, json=encrypted_data)

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


# to send a message to broker
def message_broker(encrypted_data):
    # use keyed hash for sending messages after encryption
    async def send_message():
        async with httpx.AsyncClient() as client:
            response = await client.post(BROKER_MSG_API, json=encrypted_data)

            logger.warning(f"Response Status Code: {response.status_code}")
            logger.warning(f"Response Content: {response.text}")

            if response.status_code == 200:
                return {"message": "Sent data to broker"}
            else:
                raise HTTPException(
                    status_code=response.status_code,
                    detail="Failed to send data to broker request",
                )

    asyncio.create_task(send_message())


# region DH apis


def DHKE_Customer1_broker(encrypted_data):
    # use keyed hash for sending messages after encryption
    async def send_message():
        async with httpx.AsyncClient() as client:
            response = await client.post(BROKER_DHKEC1_API, content=encrypted_data)

            print("Response Status Code:", response.status_code)
            print("Response Content:", response.text)

            if response.status_code == 200:
                return {"message": "JSON request sent successfully"}
            else:
                raise HTTPException(
                    status_code=response.status_code,
                    detail="Failed to send JSON request",
                )

    asyncio.create_task(send_message())  # type: ignore


# for receiving DHKE request from broker
@app.post("/DHKE_customer_1")
async def DHKE_customer_1(data: Request):
    if broker_state.auth_done:
        # use keyed hash
        receieved_data = await data.body()
        print("\n\n")
        print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
        print("PAYLOAD1:", receieved_data)
        receieved_data = receieved_data.decode("utf-8")
        print("PAYLOAD2:", receieved_data)
        receieved_data = json.loads(receieved_data)
        logger.info(f"Payload Received {receieved_data}")

        if "DHKE" == receieved_data["TYPE"]:
            public_key_BC1 = receieved_data["DH_PUBLIC_KEY"]
            print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
            print("Diffe_hellman : public key of broker recieved")
            broker_state.dh_shared_key = Customer1.calculate_shared_secret(
                public_key_BC1, broker_state.dh_private_key, broker_state.dh_prime
            )

            broker_state.session_key = str(broker_state.dh_shared_key).encode()  # type: ignore
            broker_state.iv = str(broker_state.dh_shared_key)[::-1].encode()  # type: ignore
            logger.critical(
                f"Calculated Customer 1 - Broker DH session key {broker_state.dh_shared_key}"
            )
            print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
            Customer_Broker_DHKE()

        elif "DHKE WITH Customer" == receieved_data["TYPE"]:
            public_key_MC1 = receieved_data["DH_PUBLIC_KEY"]
            print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
            print("Diffe_hellman : public key of merchant recieved")
            merchant_state.dh_shared_key = Customer1.calculate_shared_secret(
                public_key_MC1, merchant_state.dh_private_key, merchant_state.dh_prime
            )
            merchant_state.session_key = str(merchant_state.dh_shared_key).encode()  # type: ignore
            merchant_state.iv = str(merchant_state.dh_shared_key)[::-1].encode()  # type: ignore
            logger.critical(
                f"Customer 1 - Merchant DH session key {merchant_state.dh_shared_key}"
            )
    else:
        return {"message": "CUSTOMER1: You are not authorized, please authorize first"}


# end region


# region DH gen


def Customer_Broker_DHKE():
    timestamp = str(datetime.now())
    payload = {
        "TYPE": "DHKE",
        "DH_PUBLIC_KEY": broker_state.dh_public_key,
        "TS": timestamp,
    }
    print("Sending DH_PUBLIC_KEY to Broker")
    print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
    payload = json.dumps(payload)
    logger.critical(f"Payload Sent :")
    logger.critical(f"{payload}")
    print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
    DHKE_Customer1_broker(payload)


def Customer_Merchant_DHKE():
    timestamp = str(datetime.now())
    payload = {
        "TYPE": "DHKE WITH MERCHANT",
        "DH_PUBLIC_KEY": merchant_state.dh_public_key,
        "TS": timestamp,
    }
    print("Sending DH_PUBLIC_KEY to Merchant")
    payload = json.dumps(payload)
    logger.critical(f"Payload Sent :")
    logger.critical(payload)
    print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
    DHKE_Customer1_broker(payload)


# endregion

"""
keyed hash 
"""


def get_enc_payload_to_merchant(merchant_payload, broker_payload):
    print("Encrypting merchant payload")
    merchant_payload_hash = enc_dec.enc.keyed_hash(
        json.dumps(merchant_payload).encode("latin1"), merchant_state
    )
    merchant_enc_payload = enc_dec.encrypt_payload(merchant_payload, merchant_state)
    merchant_packed_message = pack_message(merchant_enc_payload, merchant_payload_hash)

    broker_payload["PAYLOAD"] = merchant_packed_message
    broker_hash = enc_dec.enc.keyed_hash(
        json.dumps(broker_payload).encode("latin1"), broker_state
    )
    broker_enc_payload = enc_dec.encrypt_payload(broker_payload, broker_state)
    broker_packed_message = pack_message(broker_enc_payload, broker_hash)

    return broker_packed_message


def get_enc_payload_to_broker(broker_payload):
    print("Encrypting merchant payload")
    broker_hash = enc_dec.enc.keyed_hash(
        json.dumps(broker_payload).encode("latin1"), broker_state
    )
    broker_enc_payload = enc_dec.encrypt_payload(broker_payload, broker_state)
    broker_packed_message = pack_message(broker_enc_payload, broker_hash)
    return broker_packed_message


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
        print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
        logger.info(f"Encrypted Payload prepared for merchant: ")
        logger.critical(enc_payload)
        logger.info(f"Payload Sent to Broker")
        print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
        message_broker(enc_payload)
    elif action == "BUY_PRODUCTS":
        Items = {}
        print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
        n = int(input("Enter the number of type of products you want to purchase ?"))
        for _ in range(0, n):
            print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
            j = int(input("Enter the product ID"))
            Items[j] = input("Enter the Number of items you want to purchase")

        print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")

        merchant_payload = {
            "TYPE": action,
            "PRODUCTS": Items,
            "TIMESTAMP": str(datetime.now()),
            "HASH": "",
        }
        broker_payload = {
            "USERID": global_userid,
            "TYPE": "TO_MERCHANT",
            "TIMESTAMP": str(datetime.now()),
            "PAYLOAD": "",
        }
        enc_payload = get_enc_payload_to_merchant(merchant_payload, broker_payload)
        print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
        logger.info(f"Encrypted Payload prepared for merchant: ")
        logger.critical(enc_payload)
        logger.info(f"Payload Sent to Broker")
        print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
        message_broker(enc_payload)
    elif action[0:7] == "PAYMENT":
        print("Entered the loop")
        broker_payload = {
            "USERID": global_userid,
            "AMOUNT": int(action[7:]),
            "TYPE": "PAYMENT_CONSENT",
            "MESSAGE": "Proceed with the Payment",
            "TIMESTAMP": str(datetime.now()),
        }
        enc_payload = get_enc_payload_to_broker(broker_payload)
        print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
        logger.info(f"Encrypted Payload prepared for Broker: ")
        logger.critical(enc_payload)
        logger.info(f"Payload Sent to Broker")
        print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
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
        "TIMESTAMP": timestamp,
        "PAYLOAD": {
            "LOGINCRED": {
                "REQUEST_ID": broker_state.request_id,
                "USER_ID": global_userid,
                "PASSWORD": global_password,
            },
        },
    }

    payload_hash = enc_dec.enc.hash_256(json.dumps(payload).encode("latin1"))
    payload = json.dumps(payload)
    encrypted_data = rsa_encrypt_data(payload, broker_public_key)
    print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
    logger.critical(f"Encrypted message to broker {encrypted_data}")
    logger.error(f" --- HASH {payload_hash}---")
    print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
    message_wrapper = {
        "MSG": encrypted_data.decode("latin1"),
        "HASH": payload_hash.decode("latin1"),
    }
    auth_broker(message_wrapper)


async def auth_payload_to_merchant():
    # customer to merchant auth
    """
    1. Encrypt customer payload to merchant using merchant's public key
    2. Then encrypt the whole thing using Customer 1 and broker session key using keyed hash
    """
    timestamp = str(datetime.now())

    # #PAYLOAD
    merchant_payload = {
        "ENTITY": "Customer",
        "TYPE": "MERCHANT_AUTHENTICATION",
        "REQUEST_ID": merchant_state.request_id,
    }

    merchant_payload_hash = enc_dec.enc.hash_256(
        json.dumps(merchant_payload).encode("latin1")
    )
    merchant_payload_string = json.dumps(merchant_payload)
    merchant_encrypted_payload: bytes = rsa_encrypt_data(
        merchant_payload_string, merchant_public_key
    )
    logger.warning(f"Merchant payload prepared {str(merchant_encrypted_payload)}")
    logger.error(f"Merchant payload Hash is --- {str(merchant_payload_hash)} ---")
    broker_payload = {
        "TYPE": "MERCHANT_AUTHENTICATION",
        "ENTITY": "Customer",
        "USERID": global_userid,
        "PAYLOAD": {
            "MSG": merchant_encrypted_payload.decode("latin1"),
            "HASH": merchant_payload_hash.decode("latin1"),
        },
        "TIMESTAMP": timestamp,
    }

    broker_payload_hash = enc_dec.enc.keyed_hash(
        json.dumps(broker_payload).encode("latin1"), broker_state
    )
    encrypted_data = enc_dec.encrypt_payload(broker_payload, broker_state)
    print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
    logger.critical(f"Encrypted message sent to broker {encrypted_data}")
    logger.error(f"--- Hash of the Broker payload {broker_payload_hash} ---")
    print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
    message_wrapper = {
        "MSG": encrypted_data.decode("latin1"),
        "HASH": broker_payload_hash.decode("latin1"),
    }
    message_broker(message_wrapper)


# endregion


def isBrokerAuthorized():
    return broker_state.auth_done


def isMerchantAuthorized():
    return merchant_state.auth_done


# region APIs
@app.post("/handleinput")
async def handle_input(action_number: int = Form(...)):
    print("\n\n")
    print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")

    # send auth request to broker
    if action_number == 1:
        timestamp = str(datetime.now())
        # PAYLOAD
        auth_payload_for_broker()
        return {"message": "AUTH_REQUEST_BROKER"}

    # send auth request to merchant through broker
    elif action_number == 2:
        if isBrokerAuthorized():
            await auth_payload_to_merchant()
            return {"message": "AUTH_REQUEST_MERCHANT"}
        else:
            return {"message": "BROKER_NOT_AUTHORIZED to send auth request to merchant"}

    # sending dh key request to merchant
    elif action_number == 3:
        if isBrokerAuthorized() and isMerchantAuthorized():
            Customer_Merchant_DHKE()
            return {"message": "Sending DH key request to merchant"}
        else:
            return {"message": "Broker/Merchant not authorized"}

    # view products
    elif action_number == 4:
        if (
            isBrokerAuthorized()
            and isMerchantAuthorized()
            and (merchant_state.session_key is not None)
        ):
            print(f"sending view prod request to merchant through broker")
            send_message("VIEW_PRODUCTS")
            return {"message": "MESSAGE_MERCHANT"}
        else:
            return {"message": "Broker or Merchant not authorized"}

    # buy product from merchant
    elif action_number == 5:
        if (
            isBrokerAuthorized()
            and isMerchantAuthorized()
            and (merchant_state.session_key is not None)
        ):
            print(f"sending Buy Products Request to Merchant through broker")
            send_message("BUY_PRODUCTS")
            return {"message": "MESSAGE_MERCHANT"}
        else:
            return {"message": "Broker or Merchant not authorized"}


# authorizing request from broker
@app.post("/auth_customer_1")
async def auth_customer_1(data: Request):
    receieved_data = await data.json()
    encrypted_message, message_hash = unpack_message(receieved_data)
    print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
    logger.critical(f"Received Encrypted payload : {encrypted_message}")
    logger.error(f"----message hash {message_hash}----")

    Decrypted_MESS = rsa_decrypt_data(encrypted_message, customer_1_private_key)
    is_hash_validated = enc_dec.validate_rsa_hash(Decrypted_MESS, message_hash)
    logger.warning(f"hash validated for broker ? ")
    logger.info({is_hash_validated})
    print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")

    Decrypted_MESS = json.loads(Decrypted_MESS)
    formatted_data = json.dumps(Decrypted_MESS, indent=2)
    print(f"Decrypted Payload Received from Broker:")
    logger.info(f"\n{formatted_data}")
    print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")

    if "MUTUAL_AUTHENTICATION" == Decrypted_MESS["TYPE"]:
        entity = Decrypted_MESS["ENTITY"]
        if entity == "Broker":
            if Decrypted_MESS.get("RESPONSE_ID") == broker_state.request_id:
                logger.info("Mutual authentication with broker successfull")
                broker_state.auth_done = True
                print(f"broker request id {Decrypted_MESS.get('REQUEST_ID')}")
                return Decrypted_MESS.get("REQUEST_ID")
            else:
                broker_state.auth_done = False


# receiving msg from broker
@app.post("/message_customer_1")
async def message_customer_1(data: Request):
    # use keyed hash
    receieved_data = await data.json()
    encrypted_message, message_hash = unpack_message(receieved_data)
    # print("Encrypted payload :", receieved_data)
    broker_msg_decrypted = enc_dec.decrypt_data(encrypted_message, broker_state)
    is_hash_validated = enc_dec.validate_hash(
        broker_msg_decrypted, message_hash, broker_state
    )
    logger.info(f"Hash of message from broker validated {is_hash_validated}")

    if "MERCHANT_AUTHENTICATION" == broker_msg_decrypted["TYPE"]:
        print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
        logger.info(f"Payload received from broker")
        logger.critical(broker_msg_decrypted)
        if broker_msg_decrypted["PAYLOAD"]["RESPONSE_ID"] == merchant_state.request_id:
            merchant_state.auth_done = True
            print(f"MERCHANT AUTHENTICATED")
            print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
        else:
            merchant_state.auth_done = False
            print(f"MERCHANT NOT AUTHENTICATED")

    # viewing products
    elif "FROM_MERCHANT" == broker_msg_decrypted["TYPE"]:
        merchant_payload = broker_msg_decrypted["PAYLOAD"]
        encrypted_message, message_hash = unpack_message(merchant_payload)
        logger.critical(
            f"Merchant keys {merchant_state.iv}, {merchant_state.session_key}"
        )
        print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
        logger.info(f"Payload received from merchant")
        logger.critical({encrypted_message})
        merchant_msg_decrypted = enc_dec.decrypt_data(encrypted_message, merchant_state)

        is_hash_validated = enc_dec.validate_hash(
            merchant_msg_decrypted, message_hash, merchant_state
        )
        try:
            print(merchant_msg_decrypted["MESSAGE"])
        except KeyError as ke:
            pass
        p = pd.DataFrame(merchant_msg_decrypted["PRODUCTS"].values())
        print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
        logger.info(
            f"Merchant data decrypted | Merchant hash validated -> {is_hash_validated} \n {p},"
        )
        print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
        return "VALID"

    elif "PURCHASE_CONSENT" == broker_msg_decrypted["TYPE"]:
        merchant_payload = broker_msg_decrypted["PAYLOAD"]
        encrypted_message, message_hash = unpack_message(merchant_payload)
        merchant_msg_decrypted = enc_dec.decrypt_data(encrypted_message, merchant_state)
        logger.info(pd.DataFrame(merchant_msg_decrypted["PRODUCTS"]))
        print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
        c = input(
            "Merchant Requested Payment Request of amount ${} for the purchase of the items shown above  Yes/No".format(
                broker_msg_decrypted["AMOUNT"]
            )
        )
        print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
        is_hash_validated = enc_dec.validate_hash(
            merchant_msg_decrypted, message_hash, merchant_state
        )
        print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
        logger.info(f"Merchant data decrypted {merchant_msg_decrypted['PRODUCTS']}")
        logger.error(f"merchant hash validated -> {is_hash_validated}")
        print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
        if c == "Yes":
            send_message("PAYMENT" + str(broker_msg_decrypted["AMOUNT"]))
        else:
            print("Payment Aborted")
        return "VALID"


# endregion
