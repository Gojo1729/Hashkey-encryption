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

# broker_public_key = "../bro_pub.pem"
# broker_private_key = "../bro_pri.pem"
# customer1_public_key = "../cus_pub.pem"
# merchant_public_key = "../mer_pub.pem"

broker_public_key = "../OLD KEYS/broker_public_key.pem"
broker_private_key = "../OLD KEYS/broker_private_key.pem"
merchant_public_key = "../OLD KEYS/merchant_public_key.pem"
customer1_public_key = "../OLD KEYS/customer1_public_key.pem"
customer2_public_key = "../OLD KEYS/customer2_public_key.pem"



auth_dict = {"C1": 6514161}
key_list = list(auth_dict.keys())
val_list = list(auth_dict.values())

login_data = pd.read_excel('../broker.xlsx', sheet_name='LOGIN')

class CustomerData(BaseModel):
    enc_data: bytes


# Create an instance of the FastAPI class
app = FastAPI()
templates = Jinja2Templates(directory="templates")

import asyncio

def start_client(entity, encrypted_data):
    async def send_request():
        if entity == "Merchant":
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"http://127.0.0.1:8003/authmer", content=encrypted_data
                )
        elif entity == "Customer1":
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"http://127.0.0.1:8001/authbro", content=encrypted_data
                )
                print("TEST")
                print(encrypted_data)
        elif entity == "Customer2":
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"http://127.0.0.1:8004/handleclient", content=encrypted_data
                )
        else:
            print("INVALID ENTITY")

        print("Response Status Code:", response.status_code)
        print("Response Content:", response.text)

        if response.status_code == 200:
            return {"message": "JSON request sent successfully"}
        else:
            raise HTTPException(
                status_code=response.status_code, detail="Failed to send JSON request"
            )

    asyncio.create_task(send_request())




def validate_credentials(user_id, passwd):
        print(f"Validating: User ID = {user_id}, Password = {passwd}")

        # Check if user_id exists in the 'USER ID' column
        if user_id in login_data['USER ID'].values:
            user_row = login_data[login_data['USER ID'] == user_id]
            print(f"Found user row: {user_row}")

            # Check if the provided password matches the stored password
            if passwd == user_row['PASSWORD'].values[0]:
                print("Credentials are valid.")
                return True

        # If user_id doesn't exist or passwords don't match, return False
        print("Invalid credentials.")
        return False




def BROKER_CUSTOMER(login_creds):
            
            user_id = login_creds.get("USER_ID")
            password = login_creds.get("PASSWORD")
            MESSAGE = "Hi {user_id} , Login Unsuccessful, Invalid Credentials"
            if validate_credentials(user_id, password):
                choice = input("'A' for authentication with Customer ").upper()
                if choice == 'A':
                    MESSAGE = "Hi {user_id} , Login Successful"
            timestamp = str(datetime.now())
            auth_payload = {
                    
            "TYPE": "MUTUAL_AUTHENTICATION",
            "ENTITY": "Broker",
            "PAYLOAD": {
                "MESSAGE": MESSAGE,
                "FLAG": "VALIDATED",
                "TS": timestamp,
             #   "SIGNATURE" : sign
            }
            }         
            payload = json.dumps(auth_payload)
            encrypted_data= encrypt_data(payload, customer1_public_key)
            #sign=signing(payload,self.broker_private_key)
            print("Return MSG start")
            start_client("Customer1", encrypted_data)
            




def BROKER_MERCHANT():
            
            timestamp = str(datetime.now())
            
            # Create payload
            auth_payload = {                 
            "TYPE": "MUTUAL_AUTHENTICATION",
            "ENTITY": "Broker",
            "PAYLOAD": {
                "MESSAGE": "HI MERCHANT",
                "FLAG": "VALIDATE",
                "TS": timestamp,
             #   "SIGNATURE" : sign
            }
            }         
          
            # Convert payload to JSON format
            payload = json.dumps(auth_payload)
            encrypted_data= encrypt_data(payload, merchant_public_key)
            #sign = signing(payload,self.broker_private_key)
            start_client("Merchant",encrypted_data)
            print("Authentication response sent to Merchant.")
            start_client("Merchant", encrypted_data)





def CUSTOMER_MERCHANT(Decrypted_MESS):

        position = val_list.index(Decrypted_MESS["USERID"])
        del Decrypted_MESS["USERID"]
        Decrypted_MESS["ID"] = auth_dict[position]       
        Decrypted_MESS["entity"] = "Broker"
        #Decrypted_MESS["SIGNATURE"] = sign       
        payload = json.dumps(Decrypted_MESS)
        encrypted_data= encrypt_data(payload, merchant_public_key)
        #sign=signing(payload,self.broker_private_key)
        start_client("Merchant",encrypted_data)





def MERCHANT_CUSTOMER(Decrypted_MESS):
        authentication_data = Decrypted_MESS["CUSTOMER_AUTHENTICATION"]
        if "SENDER_INFO" in authentication_data:
            sender_info = authentication_data["SENDER_INFO"]
            if "ID" in sender_info:
                del sender_info["ID"]
                if "ID" == "CUS1" :
                    user = "c1"
                    sender_info["USER_ID"] = user
                    Type = "customer1"
                elif "ID" == "CUS2" :
                    user = "c2"
                    sender_info["USER_ID"] = user
                    Type = "customer2"
                                    
                        
                    payload = json.dumps(Decrypted_MESS)
                    encrypted_data= encrypt_data(payload, customer1_public_key)
                    #signature=signing(payload,self.broker_private_key)
                    start_client("Customer1", encrypted_data)
                    



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
    




@app.post("/authcustomer")
async def handle_input(data: Request):
    receieved_data = await data.body()
    print("Encrypted payload :",receieved_data)
    Decrypted_MESS = decrypt_data(receieved_data,broker_private_key)
            
        
    Decrypted_MESS = json.loads(Decrypted_MESS)
    formatted_data = json.dumps(Decrypted_MESS, indent=2)
    print(f"Received from Customer:\n {formatted_data}")
    print(f"Received data from customer {receieved_data}")



    if "MUTUAL_AUTHENTICATION" == Decrypted_MESS["TYPE"]:
        entity = Decrypted_MESS["ENTITY"]
        print(entity)
        if entity=="Merchant":
            print("Authentication payload received from Merchant.")
            if Decrypted_MESS["PAYLOAD"]["FLAG"] == "VALIDATED":
                print("MUTUAL AUTHENTICATION DONE WITH MERCHANT")
        else:
            login_cred = Decrypted_MESS['PAYLOAD']["LOGINCRED"]
            print(login_cred)
            print("Authentication payload received from Customer.")                        
            BROKER_CUSTOMER(login_cred)
            print(f"Authentication response sent to Customer.")                         
        

    elif "MERCHANT_AUTHENTICATION" ==  Decrypted_MESS["TYPE"]:
            print("Payload received from Customer")
            CUSTOMER_MERCHANT(Decrypted_MESS)
            print(f"Modified payload forwarded to Merchant")


    elif "MERCHANT_AUTHENTICATION_RESPONSE" == Decrypted_MESS:
            print("Customer--Merchant Authentication Response Received")
            MERCHANT_CUSTOMER(Decrypted_MESS)                        
            print(f"Modified payload forwarded to Customer")


    else:
            print("Received payload does not contain any information to forward.")


# # Define an endpoint with a path parameter
# @app.get("/items/{item_id}")
# def read_item(item_id: int, query_param: str = None):
#     return {"item_id": item_id, "query_param": query_param}


# Run the server with uvicorn
# Use the command: uvicorn filename:app --reload
# For example, if your file is named "main.py", use: uvicorn main:app --reload
