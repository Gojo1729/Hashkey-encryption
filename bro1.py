import socket
import json
import threading
from datetime import datetime
from threading import Thread
from encryption import encrypt_data
from encryption import signing
from decryption import decrypt_data
from decryption import verify 
import pandas as pd



class BrokerServer:
    def __init__(self):
        # Initialize your variables here
        self.broker_public_key = "broker_public_key.pem"
        self.broker_private_key = "broker_private_key.pem"
        self.merchant_public_key = "merchant_public_key.pem"
        self.customer1_public_key = "customer1_public_key.pem"
        self.customer2_public_key = "customer2_public_key.pem"

        self.auth_dict = {"C1": 6514161}
        self.key_list = list(self.auth_dict.keys())
        self.val_list = list(self.auth_dict.values())

        self.login_data = pd.read_excel('broker.xlsx', sheet_name='LOGIN')



    def validate_credentials(self,user_id, passwd):
        print(f"Validating: User ID = {user_id}, Password = {passwd}")

        # Check if user_id exists in the 'USER ID' column
        if user_id in self.login_data['USER ID'].values:
            user_row = self.login_data[self.login_data['USER ID'] == user_id]
            print(f"Found user row: {user_row}")

            # Check if the provided password matches the stored password
            if passwd == user_row['PASSWORD'].values[0]:
                print("Credentials are valid.")
                return True

        # If user_id doesn't exist or passwords don't match, return False
        print("Invalid credentials.")
        return False


    def start_client(self,Type,MSG):
            # Create a TCP/IP socket
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # Connect the socket to the server's address and port
            if (Type=="Merchant"):
                server_address = ('127.0.0.1', 10001) # Replace 'server_ip_address' with the server's IP
                client_socket.connect(server_address)
            elif (Type=="Customer1"):
                server_address = ('127.0.0.1', 10002) # Replace 'server_ip_address' with the server's IP
                client_socket.connect(server_address)               
           
            
            try:
                client_socket.sendall(MSG)
                client_socket.send(b'STOP')
                print("PAYLOAD SENT")

            finally:
                # Close the socket to clean up
                client_socket.close()
                self.start_server()
                
                
    def handle_client(self,connection):
            try:
                data=b""
                while True:
                    chunk = connection.recv(32)
                    if chunk.endswith(b'STOP'):
                        s="C" 
                        print("Received")
                        break
                    elif chunk.endswith(b'STOM'):
                        s="M"
                        break
                    else:
                        data += chunk
        
                Cipher = data
                self.Recieve_Msg(s,Cipher)       
            finally:
                connection.close()          
        


        
    def BROKER_MERCHANT(self):
            
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
            encrypted_data= encrypt_data(payload, self.merchant_public_key)
            #sign = signing(payload,self.broker_private_key)
            self.start_client("Merchant",encrypted_data)
            print("Authentication response sent to Merchant.")


        
        
    def BROKER_CUSTOMER(self,login_creds):
            
            user_id = login_creds.get("USER_ID")
            password = login_creds.get("PASSWORD")
            MESSAGE = "Hi {user_id} , Login Unsuccessful, Invalid Credentials"
            if self.validate_credentials(user_id, password):
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
            encrypted_data= encrypt_data(payload, self.customer1_public_key)
            #sign=signing(payload,self.broker_private_key)
            print("Return MSG start")
            self.start_client("Customer1",encrypted_data)




    def CUSTOMER_MERCHANT(self,Decrypted_MESS):

        position = self.val_list.index(Decrypted_MESS["USERID"])
        del Decrypted_MESS["USERID"]
        Decrypted_MESS["ID"] = self.auth_dict[position]       
        Decrypted_MESS["entity"] = "Broker"
        #Decrypted_MESS["SIGNATURE"] = sign       
        payload = json.dumps(Decrypted_MESS)
        encrypted_data= encrypt_data(payload, self.merchant_public_key)
        #sign=signing(payload,self.broker_private_key)
        self.start_client("Merchant",encrypted_data)
                

    def MERCHANT_CUSTOMER(self,Decrypted_MESS_MC):
        authentication_data = Decrypted_MESS_MC["FORWARD_TO_CUSTOMER_FOR_AUTHENTICATION"]
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
                                    
                        
                    payload = json.dumps(Decrypted_MESS_MC)
                    encrypted_data= encrypt_data(payload, self.customer1_public_key)
                    #signature=signing(payload,self.broker_private_key)
                    self.start_client("Customer1",encrypted_data)
                    

            
            
            
    def Recieve_Msg(self, s:str, Message):
                    Received_Message = Message
                    print("Encrypted payload :",Received_Message)
                    if s=="M":
                        Decrypted_MESS = decrypt_data(Received_Message,self.broker_private_key)
                    else:
                        Decrypted_MESS = decrypt_data(Received_Message,self.broker_private_key)
                        
                    
                    Decrypted_MESS = json.loads(Decrypted_MESS)
                    formatted_data = json.dumps(Decrypted_MESS, indent=2)
                    print(f"Received from Customer:\n {formatted_data}")

                    
                       # signature = Decrypted_MESS["SIGNATURE"]
                        #Verification = verify(Decrypted_MESS,signature,self.broker_public_key)
                        #if Verification == "NV":
                            #print("Message Verification is failed ....")
                            
                        #else:               


                    if "MUTUAL_AUTHENTICATION" == Decrypted_MESS["TYPE"]:
                        entity = Decrypted_MESS["ENTITY"]
                        print(entity)
                        if entity=="Merchant":
                            print("Authentication payload received from Merchant.")
                            if Decrypted_MESS["PAYLOAD"]["FLAG"] == "VALIDATED":
                                print("MUTUAL AUTHENTICATION DONE WITH MERCHANT")
                        else:
                            login_cred = Decrypted_MESS['PAYLOAD']["LOGINCRED"]
                            print("Authentication payload received from Customer.")                        
                            self.BROKER_CUSTOMER(login_cred)
                            print(f"Authentication response sent to Customer.")                         
                        
            
                    elif "MERCHANT_AUTHENTICATION" ==  Decrypted_MESS["TYPE"]:
                        print("Payload received from Customer")
                        self.CUSTOMER_MERCHANT(Decrypted_MESS)
                        print(f"Modified payload forwarded to Merchant")


                    elif "MERCHANT_AUTHENTICATION_RESPONSE" == Decrypted_MESS:
                        print("Customer--Merchant Authentication Response Received")
                        self.MERCHANT_CUSTOMER(Decrypted_MESS)                        
                        print(f"Modified payload forwarded to Customer")
                
        
                    else:
                        print("Received payload does not contain any information to forward.")




    def start_server(self):
        # Create a TCP/IP socket
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Bind the socket to the address and port
            server_address = ('0.0.0.0', 10000) # 0.0.0.0 binds to all available interfaces
            server_socket.bind(server_address)

            # Listen for incoming connections
            server_socket.listen(6)

            print("<------Waiting for the Incoming request from Customer/Merchant----->")

            try:
                print("<------Broker Processed the Transaction----->")

                while True:
                    connection, client_address = server_socket.accept()
                    print(f"Accepted connection from {client_address}")
                    client_handler = threading.Thread(target=self.handle_client, args=(connection,))
                    client_handler.start()     
            finally:
                print("Done")
                server_socket.close() 
         
    def main(self):
            choice = input("'A' for authentication with Merchant ").upper()

            if choice == 'A':
                self.BROKER_MERCHANT()
                print("Broker socket listening on port 8080...")
            else:
                print("Invalid choice.")

if __name__ == "__main__":
    broker_server = BrokerServer()
    broker_server.main()
    
    
