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
# merchant_private_key = "../mer_pri.pem"
# merchant_public_key = "../mer_pub.pem"


broker_public_key = "../OLD KEYS/broker_public_key.pem"
merchant_public_key = "../OLD KEYS/merchant_public_key.pem"
merchant_private_key = "../OLD KEYS/merchant_private_key.pem"




class CustomerInput(BaseModel):
    action_number: int
    enc_data: bytes


   


# Create an instance of the FastAPI class
app = FastAPI()
templates = Jinja2Templates(directory="templates")


# Define a simple endpoint
@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})



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



def Send_Msg_MB():
            
        choice = input("'A' for authentication with broker ").upper()
        
        if choice == 'A':
            timestamp = str(datetime.now())
            # Create payload
            payload = {
                "TYPE": "MUTUAL_AUTHENTICATION",
                "ENTITY": "Merchant",
                "PAYLOAD": {
                    "MESSAGE": "Hi Broker",
                    "FLAG": "VALIDATED",
                    "TS": timestamp,
                    #"SIGNATURE" : sign
                }
                }
                
            # Convert payload to JSON format
            #json_auth_payload = json.dumps(auth_payload)


            #sign=signing(payload,self.merchant_private_key)
            payload = json.dumps(payload)
            encrypted_data = encrypt_data(payload, broker_public_key)
            start_client(encrypted_data)           
            print("Message Sent (Encrypted Format): ",encrypted_data)
            


def Send_Msg_MC(RID):
            
        choice = input("'B' for authentication with customer ").upper()
            
        if choice == 'b':
                # Get the current timestamp
            timestamp = str(datetime.now())

            Customer_Payload = { "PAYLOAD": {
            "ENTITY": "Merchant",     
            "MESSAGE": "Hi Merchant",
            #"SIGNATURE": sign1
            }
            }
            payload = json.dumps(payload).encode()
            #sign1=signing(payload,self.merchant_private_key)
            Customer_Encrypted_Payload = encrypt_data(payload,merchant_public_key)
            payload = {  
            "TYPE": "MERCHANT_AUTHENTICATION",
            "ENTITY": "Merchant",
            "RID": RID,
            "PAYLOAD": str(Customer_Encrypted_Payload),
            "TS": timestamp,
            #"SIGNATURE" : sign
            }

                # Convert payload to JSON format
            #sign=signing(payload,self.merchant_private_key)
            encrypted_data = encrypt_data(json.dumps(payload), broker_public_key)
            start_client(encrypted_data)
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


@app.post("/authmer")
async def handle_customer_input(data: Request):
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
    return {"message": "Data received successfully"}

