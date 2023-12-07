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



# broker_public_key = "../bro_pub.pem"
# customer1_private_key = "../cus1_pri.pem"
# customer1_public_key = "../cus1_pub.pem"
# merchant_public_key = "../mer_pub.pem"

broker_public_key = "../OLD KEYS/broker_public_key.pem"
merchant_public_key = "../OLD KEYS/merchant_public_key.pem"
customer1_public_key = "../OLD KEYS/customer1_public_key.pem"
customer1_private_key = "../OLD KEYS/customer1_private_key.pem"


global_userid = ""
global_password = ""


class CustomerInput(BaseModel):
    action_number: int
    enc_data: bytes


def start_client(encrypted_data):
    async def send_request():
       async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"http://127.0.0.1:8002/authcustomer", content=encrypted_data
                )

                print("Response Status Code:", response.status_code)
                print("Response Content:", response.text)

                if response.status_code == 200:
                    return {"message": "JSON request sent successfully"}
                else:
                    raise HTTPException(
                        status_code=response.status_code, detail="Failed to send JSON request"
                    )
                
    asyncio.create_task(send_request())
   


# Create an instance of the FastAPI class
app = FastAPI()
templates = Jinja2Templates(directory="templates")


# Define a simple endpoint
@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})



def Send_Msg_CB():
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
                        "PASSWORD": global_password
                        },
                    "TS": timestamp,
                    #"SIGNATURE":sign
                }
            }

        #sign=signing(payload,self.customer1_private_key)
        payload = json.dumps(payload)
        encrypted_data = encrypt_data(payload,broker_public_key)
        print("Message Sent (Encrypted Format): ",encrypted_data)
        print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
        start_client(encrypted_data)



def Send_Msg_CM():
            
        # choice_1 = input("'M' for authentication with merchant: ").upper()
        # print(choice_1)
        # if choice_1 == 'M':
            timestamp = str(datetime.now())

            # #PAYLOAD
            # Merchant_Payload = { "PAYLOAD": {
            # "ENTITY": "Customer",     
            # "MESSAGE": "Hi Merchant"
            # }
            # }
            #payload = json.dumps(payload).encode()
            #sign=signing(payload,self.customer1_private_key)
            
            Merchant_payload = "5a7fba98236e4c1b0d9a8cbb2ef48b7c7b490a40537bea70f95aa126c858153b8e1f48c4426e24e2c51e04f6cb58c57bf130c4310f56e9a8fc48e2a410d4f91b6a384329b336ed13e7b2c810c5c2e1db36a48bf18a2b807a9c17a567d68f5b3ca4d15c146f2c15ab1fc61858f8943e47b56a0e3e5866b3ce74c74b5e64d9973e"

            # Merchant_Payload_JSON = json.dumps(Merchant_Payload)
            # Merchant_Encrypted_Payload = encrypt_data(Merchant_Payload_JSON,merchant_public_key)
            payload = {  
            "TYPE": "MERCHANT_AUTHENTICATION",
            "ENTITY": "Customer",
            "USERID": global_userid,
            "PAYLOAD": str(Merchant_payload),
            "TS": timestamp,
            #"SIGNATURE":sign
            }

            #sign=signing(payload,self.customer1_private_key)
            payload = json.dumps(payload)
            encrypted_data = encrypt_data(payload,broker_public_key)
            print("Message Sent (Encrypted Format): ",encrypted_data)
            print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
            start_client(encrypted_data)


@app.post("/handleinput")
   
async def handle_input(action_number: int = Form(...)):
    print(f"Sending request to broker {action_number}")    
    

    # send auth request to broker
    if action_number == 1:
        timestamp = str(datetime.now())
        # PAYLOAD
        Send_Msg_CB()


    # send auth request to merchant
    elif action_number == 2:
        Send_Msg_CM()

        return {"message": "Sending request to merchant"}
    # view products
    elif action_number == 3:
        pass

    # buy product
    elif action_number == 4:
        pass


@app.post("/authbro")
async def handle_customer_input(data: Request ):
    receieved_data = await data.body()
    print("Encrypted payload :",receieved_data)
    Decrypted_MESS = decrypt_data(receieved_data,customer1_private_key)
            
        
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
            sender_info = Decrypted_MESS["FORWARD_TO_CUSTOMER_FOR_AUTHENTICATION"]["SENDER_INFO"]
            entity = sender_info.get["MERCHANT"]

            if entity == "MERCHANT": 
                    print("Authentication payload received from Broker.")
                    print("Authentication done with Merchant")
    
    # Perform any additional processing or return a response as needed
    return {"message": "Data received successfully"}


# Run the server with uvicorn
# Use the command: uvicorn filename:app --reload
# For example, if your file is named "main.py", use: uvicorn main:app --reload
