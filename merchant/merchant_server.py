import asyncio
import logging
from fastapi import Depends, FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from Auth_decryption import rsa_decrypt_data
from Auth_encryption import rsa_encrypt_data
from datetime import datetime
import json
import httpx
import enc_dec
from DH import DiffieHellman
from typing import Dict, Tuple
import random
import pandas as pd
import starlette.status as status


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


class ProductInfo(BaseModel):
    prod_id: int
    quantity: int
    price_per_item: float
    name: str


class MyState:
    def __init__(self):
        self.inventory = {}
        self.display_form = []


class BrokerState:
    def __init__(self) -> None:
        self.state = None
        self.auth_done = False
        self.host = f"http://127.0.0.1:8002"
        self.auth_api = f"{self.host}/auth_broker"
        self.msg_api = f"{self.host}/message_merchant_broker"
        # assume DH is done
        # self.iv = b"6042302273"
        # self.session_key = b"7289135233"
        self.session_key, self.iv = None, None
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
        # self.iv = b"6042302272"
        # self.session_key = b"7289135232"
        self.session_key, self.iv = None, None
        (
            self.dh_private_key,
            self.dh_public_key,
            self.dh_prime,
        ) = Merchant.generate_keypair(10000000061)
        self.dh_session_key = None
        self.prods = {}
        self.payment = 0


# Create an instance of the FastAPI class
app = FastAPI()
broker_state = BrokerState()
mystate = MyState()
# rid, customer state mapping
customers: Dict[str, CustomerState] = {}
templates = Jinja2Templates(directory="templates")


# Define a simple endpoint
@app.get("/", response_class=HTMLResponse, name="index")
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/inventory", response_class=HTMLResponse)
async def display_inventory(request: Request):
    return templates.TemplateResponse(
        "display_inventory.html",
        {"request": request, "products_info": mystate.display_form},
    )


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
                    logger.info(f"Mutual authentication with broker successfull")
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
        print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
        logger.critical(f"Encrypted Auth payload to Broker: {encrypted_data}")
        print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
        auth_broker(message_wrapper)
        print("Message Sent to Broker")
        print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")


# Add product
@app.post("/add_new_product")
async def handle_input(
    request: Request,
    prod_id: int = Form(...),
    name: str = Form(...),
    quantity: int = Form(...),
    price_per_item: float = Form(...),
):
    redirect_url = request.url_for("index")
    new_product = ProductInfo(
        prod_id=prod_id, name=name, quantity=quantity, price_per_item=price_per_item
    )
    # product = ProductInfo(prod_id, quantity, price_per_item, name)
    print(f"Product inventory  before {mystate.inventory}")
    print(f"Adding new product {new_product}")
    existing_product = mystate.inventory.get(new_product.prod_id)
    if existing_product is None:
        mystate.inventory[prod_id] = new_product.model_dump()
    else:
        mystate.inventory[existing_product["prod_id"]] = new_product.model_dump()

    mystate.display_form = list(mystate.inventory.values())
    print(f"Product inventory after {mystate.inventory}")
    return RedirectResponse(redirect_url, status_code=status.HTTP_303_SEE_OTHER)


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
        print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
        logger.critical("Diffe_hellman : public key of Broker recieved")
        logger.info("payload :")
        logger.info(f"{received_data}")
        broker_state.dh_session_key = Merchant.calculate_shared_secret(
            public_key_BM, broker_state.dh_private_key, broker_state.dh_prime
        )

        broker_state.iv = str(broker_state.dh_session_key)[::-1].encode()  # type: ignore
        broker_state.session_key = str(broker_state.dh_session_key).encode()  # type: ignore
        logger.critical(
            f"Calculated Merchant - Broker DH session key {broker_state.dh_session_key}"
        )
        print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
        Merchant_Broker_DHKE()

    elif "DHKE WITH MERCHANT" == received_data["TYPE"]:
        RID = received_data["USERID"]
        customer_state = customers[RID]
        public_key_CM = received_data["DH_PUBLIC_KEY"]
        print("\n\n")
        print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
        logger.critical("Diffe_hellman : public key of Customer recieved")
        logger.info("payload :")
        logger.info(f"{received_data}")
        customer_state.dh_session_key = Merchant.calculate_shared_secret(
            public_key_CM, customer_state.dh_private_key, customer_state.dh_prime
        )
        customer_state.iv = str(customer_state.dh_session_key)[::-1].encode()  # type: ignore
        customer_state.session_key = str(customer_state.dh_session_key).encode()  # type: ignore
        logger.critical(
            f"Calculated Merchant - Customer {RID} DH session key {customer_state.dh_session_key}"
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
    print("Sending DH_PUBLIC_KEY to Broker: ")
    logger.critical(payload)
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
    print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
    print("Sending DH_PUBLICKEY to customer")
    payload = json.dumps(payload)
    logger.critical(f"Message Sent : {payload}")
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
    print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
    logger.info("Encrypting customer payload")
    customer_payload_hash = enc_dec.enc.keyed_hash(
        json.dumps(customer_payload).encode("latin1"), customer_state
    )
    customer_enc_payload = enc_dec.encrypt_payload(
        customer_payload,
        customer_state,
    )
    customer_packed_messagee = pack_message(customer_enc_payload, customer_payload_hash)

    logger.critical(customer_packed_messagee)
    logger.error(customer_payload_hash)
    print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
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
            print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
            logger.info("Customer Authenticated!! sending info to Broker")
            logger.critical({encrypt_broker_payload})
            print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
            if not False:
                customers[rid] = CustomerState(rid, "state", True)
            else:
                return_msg = "INVALID, CUSTOMER ALREADY AUTHENTICATED"
                print(f"{return_msg}")
                return return_msg
            message_broker(packed_encrypted_message)

    elif msg_type == "VIEW_PRODUCTS":
        cust: CustomerState = customers.get(rid)  # type: ignore
        customer_payload = {
            "TIMESTAMP": str(datetime.now()),
            "PRODUCTS": mystate.inventory,
        }
        broker_payload = {
            "TYPE": "TO_CUSTOMER",
            "ENTITY": "Merchant",
            "USERID": f"{rid}",
            "TIMESTAMP": str(datetime.now()),
            "PAYLOAD": "",
        }
        # handle rid
        cust: CustomerState = customers.get(rid)  # type: ignore
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
        cust: CustomerState = customers.get(rid)  # type: ignore
        prods = cust.prods = {}
        cust.payment = 0
        Not_Available = {}
        for customer_product in Products:
            for k in mystate.inventory.values():
                if int(customer_product) == k["prod_id"]:
                    if int(Products[customer_product]) <= k["quantity"]:
                        prods["PRODUCT" + customer_product] = {
                            "PID": int(customer_product),
                            "Name": k["name"],
                            "Quantity": Products[customer_product],
                            "Price": k["price_per_item"],
                        }
                        cust.payment = cust.payment + int(
                            Products[customer_product]
                        ) * int(k["price_per_item"])
                    else:
                        prods["PRODUCT" + customer_product] = {
                            "PID": int(customer_product),
                            "Name": k["name"],
                            "Quantity": Products[customer_product],
                        }
                        Not_Available[k["pID"]] = k["quantity"]
        if Not_Available != {}:
            p = "All Items are not available, You requested for following number of items"
            customer_payload = {
                "TIMESTAMP": str(datetime.now()),
                "MESSAGE": p,
                "PRODUCTS": prods,
            }
            broker_payload = {
                "TYPE": "TO_CUSTOMER",
                "ENTITY": "Merchant",
                "USERID": f"{rid}",
                "TIMESTAMP": str(datetime.now()),
                "PAYLOAD": "",
            }
            cust.prods = {}
            cust = customers.get(rid)  # type: ignore
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
            }
            broker_payload = {
                "TYPE": "PURCHASE_CONSENT",
                "ENTITY": "Merchant",
                "AMOUNT": cust.payment,
                "USERID": f"{rid}",
                "TIMESTAMP": str(datetime.now()),
                "PAYLOAD": "",
            }
            cust = customers.get(rid)  # type: ignore
            if cust is None:
                print("MERCHANT: PLEASE AUTH BEFORE YOU VIEW PRODUCTS")
            else:
                print(f"Customer {cust.iv}, {cust.session_key}")
                enc_payload = get_enc_payload_to_customer(
                    customer_payload, broker_payload, cust
                )
                message_broker(enc_payload)
    elif msg_type == "Payment--Done":
        cust = customers.get(rid)  # type: ignore
        prods = cust.prods
        PRODUCTS = {}
        for j, customer_product in zip(prods.keys(), prods.values()):
            PRODUCTS[j] = {
                "PID": customer_product["PID"],
                "Name": customer_product["Name"],
                "State": "Purchased",
            }
            mystate.inventory[customer_product["PID"]]["quantity"] = mystate.inventory[
                customer_product["PID"]
            ]["quantity"] - int(
                cust.prods["PRODUCT" + str(customer_product["PID"])]["Quantity"]
            )
        broker_payload = {
            "TYPE": "TO_CUSTOMER",
            "ENTITY": "Merchant",
            "USERID": f"{rid}",
            "TIMESTAMP": str(datetime.now()),
            "PAYLOAD": "",
        }
        customer_payload = {
            "TIMESTAMP": str(datetime.now()),
            "PRODUCTS": PRODUCTS,
            "RANDOM_BYTES": (random.randint(0, 1000) * b"x").decode(ENCODING_TYPE),
        }
        # handle rid
        cust = customers.get(rid)  # type: ignore
        if cust is None:
            print("MERCHANT: PLEASE AUTH BEFORE YOU VIEW PRODUCTS")
        else:
            print(f"Customer {cust.iv}, {cust.session_key}")
            enc_payload = get_enc_payload_to_customer(
                customer_payload, broker_payload, cust
            )
            message_broker(enc_payload)
            print("Updated Inventory after the purchase: \n")
            print(pd.DataFrame(mystate.inventory.values()))


def take_action_for_customer(payload, rid, enc_type):
    enc_payload = payload["PAYLOAD"]
    encrypted_message, message_hash = unpack_message(enc_payload)
    logger.info(f"Encrypted payload from customer")
    logger.critical({encrypted_message})
    # decrypt using rsa
    if enc_type == "rsa":
        decypted_customer_msg = rsa_decrypt_data(
            encrypted_message, merchant_private_key
        )
        decrypted_customer_msg_json = json.loads(decypted_customer_msg)
        is_hash_validated = enc_dec.validate_rsa_hash(
            decypted_customer_msg, message_hash
        )
        logger.info(
            f"Customer data decrypted {decrypted_customer_msg_json}, {rid=}, {is_hash_validated=}"
        )
        return handle_message(decrypted_customer_msg_json, rid)

    elif enc_type == "keyedhash":
        customer_state = customers.get(rid)
        if customer_state is None:
            logger.critical("MERCHANT: AUTH FIRST")
        else:
            decrypted_customer_msg_json = enc_dec.decrypt_data(
                encrypted_message, customer_state
            )
            is_customer_hash_valid = enc_dec.validate_hash(
                decrypted_customer_msg_json, message_hash, customer_state
            )
            logger.info(f"Customer data decrypted {decrypted_customer_msg_json}")
            logger.error(f"customer hash validated -> {is_customer_hash_valid}")
            print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
            return handle_message(decrypted_customer_msg_json, rid)


# recieving message from broker
@app.post("/message_merchant")
async def message_merchant(data: Request):
    receieved_data = await data.json()
    encrypted_message, message_hash = unpack_message(receieved_data)
    print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
    logger.info(f"Encrypted payload from broker")
    logger.critical({encrypted_message})
    broker_msg_decrypted = enc_dec.decrypt_data(encrypted_message, broker_state)
    # print(f"Decrypted data {broker_msg_decrypted} \n {stars}")
    msg_hash = enc_dec.validate_hash(broker_msg_decrypted, message_hash, broker_state)
    logger.error(f"Merchant Payload Hash is ---{message_hash}")
    logger.info(f"Hash of message from broker validated {msg_hash} \n{stars}")
    print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
    msg_type = broker_msg_decrypted["TYPE"]
    cust_id = broker_msg_decrypted["USERID"]
    if "MERCHANT_AUTHENTICATION" == msg_type:
        print("Customer Requested for Authentication")
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
    print("Authentication Request Received.")
    print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
    logger.critical(f"Encrypted payload : {encrypted_message}")
    logger.debug(f"---- message hash {message_hash}")
    Decrypted_MESS = rsa_decrypt_data(encrypted_message, merchant_private_key)
    is_hash_validated = enc_dec.validate_rsa_hash(Decrypted_MESS, message_hash)
    logger.info(f"Hash validated for customer ? ")
    logger.info({is_hash_validated})
    print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
    Decrypted_MESS = json.loads(Decrypted_MESS)
    formatted_data = json.dumps(Decrypted_MESS, indent=2)
    logger.info(f"Received from Broker:\n {formatted_data}")

    if "MUTUAL_AUTHENTICATION" == Decrypted_MESS["TYPE"]:
        entity = Decrypted_MESS["ENTITY"]
        if entity == "Broker":
            print("Authentication payload received from Broker.")
            Send_Msg_MB(Decrypted_MESS)

    # Perform any additional processing or return a response as needed
    # return {"message": "Data received successfully"}
