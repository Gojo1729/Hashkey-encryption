from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from DH import DiffieHellman
from Auth_decryption import decrypt_data
from Auth_encryption import encrypt_data
from datetime import datetime
import json
import httpx
import pandas as pd
import asyncio
import message
import hashlib

# broker_public_key = "../bro_pub.pem"
# broker_private_key = "../bro_pri.pem"
# customer1_public_key = "../cus_pub.pem"
# merchant_public_key = "../mer_pub.pem"

broker_public_key = "../OLD KEYS/broker_public_key.pem"
broker_private_key = "../OLD KEYS/broker_private_key.pem"
Broker = DiffieHellman()
private_key_BM, public_key_BM, prime_BM = Broker.generate_keypair(10000000007)
private_key_BC1, public_key_BC1, prime_BC1 = Broker.generate_keypair(10000000019)
private_key_BC2, public_key_BC2, prime_BC2 = Broker.generate_keypair(10000000033)
print("private key_BM:", private_key_BM, "public_key_BM:", public_key_BM, "prime_BM:", prime_BM)
print("private key_BC1:", private_key_BC1, "public_key_BC1:", public_key_BC1, "prime_BC1:", prime_BC1)
print("private key_BC2:", private_key_BC2, "public_key_BC2:", public_key_BC2, "prime_BC2:", prime_BC2)


class CustomerData(BaseModel):
    enc_data: bytes


class Customer1State:
    def __init__(self) -> None:
        self.user_id = "C1"
        self.salt = "Net_sec_1"
        self.password = "4f59554b34b1d0fe8832e8fab4b638f51a770f879bf232a36100f316aa56b2c0"
        self.host = "http://127.0.0.1:8001"
        self.msg_api = f"{self.host}/message_customer_1"
        self.auth_api = f"{self.host}/auth_customer_1"
        self.DHKE_api = f"{self.host}/DHKE_customer_1"
        self.state = None
        self.auth_done = False
        self.random_id = "6514161"
        # assume DH is done
        self.iv = b"4832500747"
        self.session_key = b"4103583911"
        self.public_key = "../OLD KEYS/customer1_public_key.pem"
        #self.session_key = Shared_secret.shared_secret_BC1
    


class Customer2State:
    def __init__(self) -> None:
        self.user_id = "C2"
        self.salt = "Net_sec_2"
        self.password = "c5ffcdf4de1aa33a92a65c60cd74d38a88a399c6f3324a7d601d1ff00bb56b12"
        self.host = "http://127.0.0.1:8004"
        self.msg_api = f"{self.host}/message_customer_2"
        self.auth_api = f"{self.host}/auth_customer_2"
        self.DHKE_api = ""
        self.state = None
        self.auth_done = False
        self.random_id = "1001991"
        # assume DH is done
        self.iv = b"4832500747"
        self.session_key = b"4103583911"
        self.public_key = "../OLD KEYS/customer2_public_key.pem"


class MerchantState:
    def __init__(self) -> None:
        self.user_id = "M1"
        self.host = "http://127.0.0.1:8003"
        self.msg_api = f"{self.host}/message_merchant"
        self.auth_api = f"{self.host}/auth_merchant"
        self.DHKE_api = f"{self.host}/DHKE_merchant"
        self.state = None
        self.auth_done = False
        self.iv = b"6042302273"
        self.session_key = b"7289135233"
        self.public_key = "../OLD KEYS/merchant_public_key.pem"


class Hashcheck:

    def hash_password(self,salt,plain_text):
        combined_text = salt + plain_text
        hashed_text = hashlib.sha256(combined_text.encode()).hexdigest()
        return hashed_text


# Create an instance of the FastAPI class
app = FastAPI()
templates = Jinja2Templates(directory="templates")
customer1_state = Customer1State()
customer2_state = Customer2State()
customers_state = {"C1": customer1_state, "C2": customer2_state}
merchant_state = MerchantState()
hashcheck = Hashcheck()

# region message
def send_message(state, encrypted_data,Type):
    async def send_request():
        async with httpx.AsyncClient() as client:
            # if Type== "auth:
            #     response = await client.post(state.auth_api, content=encrypted_data)
            #     print(
            #         f"{response=}, {response.status_code=}, {type(response.status_code)=}, {type(response.text)=}"
            #     )
            #     if (response.status_code == 200) and (response.text == '"VALIDATED"'):
            #         print(f"Mutual authentication with {state.user_id} successfull")
            #         state.auth = True   
            #     else:
                    # state.auth = False
            if Type == "DHKE":
                response = await client.post(state.DHKE_api, content=encrypted_data)
                print(
                    f"{response=}, {response.status_code=}, {type(response.status_code)=}, {type(response.text)=}"
                )
            
            else:
                response = await client.post(state.msg_api, content=encrypted_data)

    asyncio.create_task(send_request())


# endregion


def validate_credentials(user_id, passwd):
    print(f"Validating: User ID = {user_id}, Password = {passwd}")
    valid_user = customers_state.get(user_id)    
    if user_id == customer1_state.user_id:
        hash_pass = hashcheck.hash_password(customer1_state.salt,passwd)
        print(hash_pass)
        if customer1_state.password == hash_pass:
            return valid_user
        else : 
            return None
    elif user_id == customer2_state.user_id:
        hash_pass = hashcheck.hash_password(customer2_state.salt,passwd)
        if customer2_state.password == hash_pass:
            print("valid")
            return valid_user 
        else : 
            return None 
            
    return valid_user if valid_user is not None else None


def BROKER_CUSTOMER(login_creds):
    user_id = login_creds.get("USER_ID")
    password = login_creds.get("PASSWORD")
    MESSAGE = f"Hi {user_id} , Login Unsuccessful, Invalid Credentials"
    valid_user = validate_credentials(user_id, password)
    if valid_user is None:
        print("Invalid credentials")
        return {"message": MESSAGE}

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




def BROKER_CUSTOMER1_DHKE(): #THIS IS FOR SENDING THE KEY TO CUSTOMER1
    timestamp = str(datetime.now())
    payload = {
        "TYPE" : "DHKE",
        "DH_PUBLIC_KEY" : public_key_BC1,
        "TS" : timestamp
    }    

    payload = json.dumps(payload)
    print("Message Sent : ", payload)
    print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
    send_message(customer1_state, payload,"DHKE")



def Shared_secret(entity,other_entity_public_key): #THIS IS TO CALCULATE SHARED SECRET 
 
    if entity == "Customer1": 
        shared_secret_BC1 = Broker.calculate_shared_secret(other_entity_public_key,private_key_BC1,prime_BC1)
        print("Customer1_Broker_Secret key :",shared_secret_BC1)
        return shared_secret_BC1
    elif entity == "Customer2":
        shared_secret_BC2 = Broker.calculate_shared_secret(other_entity_public_key,private_key_BC2,prime_BC2)
        print("Customer2_Broker_Secret key :",shared_secret_BC2)
        return shared_secret_BC2
    elif entity == "Broker":
        shared_secret_BM = Broker.calculate_shared_secret(other_entity_public_key,private_key_BM,prime_BM)
        print("Broker_Merchant_Secret key :",shared_secret_BM)
        return shared_secret_BM



def BROKER_CUSTOMER2_DHKE(): #THIS IS FOR SENDING THE KEY TO CUSTOMER2
    timestamp = str(datetime.now())
    payload = {
        "TYPE" : "DHKE",
        "UID" : "",
        "DH_PUBLIC_KEY" : public_key_BC2,
        "TS" : timestamp
    }    

    payload = json.dumps(payload)
    print("Message Sent : ", payload)
    print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
    send_message(customer2_state, payload,"DHKE" )


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

def BROKER_MERCHANT_DHKE(): #THIS IS FOR SENDING THE KEY TO MERCHANT
    timestamp = str(datetime.now())
    payload = {
        "TYPE" : "DHKE",
        "DH_PUBLIC_KEY" : public_key_BM,
        "TS" : timestamp
    }    

    payload = json.dumps(payload)
    print("Message Sent : ", payload)
    print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
    send_message(merchant_state, payload,"DHKE")


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
   
    elif action_number == 4:
        BROKER_CUSTOMER1_DHKE()
        return {"message" : "Sending request to Customer1"}
    # view products
    elif action_number == 5:
        BROKER_MERCHANT_DHKE()
        return {"message": "Sending request to merchant"}
    elif action_number == 6:
        BROKER_CUSTOMER2_DHKE()
        return {"message": "Sending request to Customer2"}

    # buy product


@app.post("/DHKE_Customer1_broker")
async def DHKE_Customer1_broker(data: Request):
       
        receieved_data = await data.body()
        receieved_data = receieved_data.decode('utf-8')  
        receieved_data = json.loads(receieved_data) 
        print("payload :", receieved_data)

        if "DHKE" == receieved_data["TYPE"]:  # THIS IS WHEN CUSTOMER1 SENDS HIS KEY 
            public_key_C1B = receieved_data["DH_PUBLIC_KEY"]
            print("Diffe_hellman : public key of customer1 recieved")
            Shared_secret("Customer1",public_key_C1B)
           

        elif "DHKE WITH MERCHANT" == receieved_data["TYPE"]: #THIS IS WHEN CUSTOMER1 WANTS TO SEND HIS KEY TO MERCHANT 
            print("Diffe_hellman : Recieved from Customer forwarding to Merchant")
            receieved_data["RID"] = customer1_state.random_id
            payload = json.dumps(receieved_data)
            print("Message Sent : ", payload)
            print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
            send_message(merchant_state, payload,"DHKE")
            

  



@app.post("/DHKE_Customer2_broker")
async def DHKE_Customer2_broker(data: Request):
       
        receieved_data = await data.body()
        receieved_data = receieved_data.decode('utf-8') 
        receieved_data = json.loads(receieved_data)  
        print("payload :", receieved_data)

        if "DHKE" == receieved_data["TYPE"]: # THIS IS WHEN CUSTOMER2 SENDS H   IS KEY 
            public_key_C2B = receieved_data["DH_PUBLIC_KEY"]
            print("Diffe_hellman : public key of customer2 recieved")
            Shared_secret("Customer2",public_key_C2B)
            

        elif "DHKE WITH MERCHANT" == receieved_data["TYPE"]: #THIS IS WHEN CUSTOMER1 WANTS TO SEND HIS KEY TO MERCHANT
            print("Diffe_hellman : Recieved from Customer forwarding to Merchant")
            receieved_data["RID"] = customer2_state.random_id
            payload = json.dumps(receieved_data)
            print("Message Sent : ", payload)
            print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
            send_message(merchant_state, payload,"DHKE")
           



@app.post("/DHKE_Merchant_broker")
async def DHKE_Merchant_broker(data: Request):
       
        receieved_data = await data.body()
        receieved_data = receieved_data.decode('utf-8') 
        receieved_data = json.loads(receieved_data)  
        print("payload :", receieved_data)

        if "DHKE" == receieved_data["TYPE"]:
            public_key_MB = receieved_data["DH_PUBLIC_KEY"]
            print("Diffe_hellman : public key of Merchant recieved")
            Shared_secret("Broker",public_key_MB)

            
        elif "DHKE WITH Customer" == receieved_data["TYPE"]:  #THIS SEND TO CUSTOMER 1 OR 2 DEPENDING ON RID AND DEL RID BEFORE SENDING IT 
            if receieved_data["RID"] == "6514161":
                del receieved_data["RID"]
                payload = json.dumps(receieved_data)
                print("Message Sent : ", payload)
                print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
                send_message(customer1_state, payload,"DHKE")
                print("Diffe_hellman : Recieved from Merchant forwarding to Customer1")
            
            elif receieved_data["RID"] == "1001991" :
                del receieved_data["RID"]
                payload = json.dumps(receieved_data)
                print("Message Sent : ", payload)
                print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
                send_message(customer2_state,payload,"DHKE")
                print("Diffe_hellman : Recieved from Customer forwarding to Merchant")
            




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
                BROKER_MERCHANT_DHKE()

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
    print("Encrypted payload :", receieved_data)
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
    print("Encrypted payload :", receieved_data)
    customer_msg_decrypted = message.decrypt_data(receieved_data, customer1_state)
    print(f"Decrypted data {customer_msg_decrypted}, {type(customer_msg_decrypted)=}")
    # create a new payload to merchant
    if "MERCHANT_AUTHENTICATION" == customer_msg_decrypted["TYPE"]:
        print("Payload received from Customer")
        CUSTOMER_MERCHANT(customer_msg_decrypted)
        print(f"Modified payload forwarded to Merchant")


    
    

    

