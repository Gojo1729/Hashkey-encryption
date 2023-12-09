import socket
import json
from datetime import datetime
import threading
from encryption import encrypt_data
from encryption import signing
from decryption import decrypt_data
from decryption import verify
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization


class CustomerServer:
    def __init__(self):
            # Initialize your variables here
            self.broker_public_key = "broker_public_key.pem"
            self.customer1_private_key = "customer1_private_key.pem"
            self.customer1_public_key = "customer1_public_key.pem"
            self.merchant_public_key = "merchant_public_key.pem"
            self.USER_ID = input("Enter your USER_ID: ")
            self.password = input("Enter your password: ")

    def start_server(self):
        # Create a TCP/IP socket
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Bind the socket to the address and port
            server_address = ('0.0.0.0', 10002) # 0.0.0.0 binds to all available interfaces
            server_socket.bind(server_address)

            # Listen for incoming connections6
            server_socket.listen(10)

            print("<------Waiting for the Broker to process the request----->")

            try:
                print("<------Broker Processed the Transaction----->")

                while True:
                    connection, client_address = server_socket.accept()
                    print(f"Accepted connection from {client_address}")
                    client_handler = threading.Thread(target=self.handle_client, args=(connection,))
                    client_handler.start()     
            finally:
                print("Done")
                #server_socket.close()



    def handle_client(self,connection):
            try:
                data=b""
                while True:
                    chunk = connection.recv(32)
                    if chunk.endswith(b'STOP'): 
                        break
                    else:
                        data+=(chunk)
                
                Cipher = data
                self.Recieve_Msg(Cipher)       
            finally:
                connection.close()


    def start_client(self,MSG):
            # Create a TCP/IP socket
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # Connect the socket to the server's address and port
            server_address = ('127.0.0.1', 10000) # Replace 'server_ip_address' with the server's IP
            client_socket.connect(server_address)

            try:
                client_socket.sendall(MSG)
                client_socket.send(b'STOP')

            finally:
                # Close the socket to clean up
                client_socket.close()
                self.start_server()
                



    def Recieve_Msg(self, Message):
            
            Received_Message = Message
            Decrypted_MESS = decrypt_data(Received_Message,self.customer1_private_key)
            print("Encrypted payload:", Received_Message)
            Decrypted_MESS = json.loads(Decrypted_MESS)
            formatted_data = json.dumps(Decrypted_MESS, indent=2)
            print(f"Received from Customer:\n {formatted_data}")
            
            
            #signature = Decrypted_MESS["SIGNATURE"]
            #Verification = verify(Decrypted_MESS,signature,self.customer1_public_key)
            #if Verification == "NV":
             #   print("Message Verification is failed ....")
                            
            #else:  
            if "MUTUAL_AUTHENTICATION" == Decrypted_MESS["TYPE"]:
                entity = Decrypted_MESS["ENTITY"]

                if entity == "Broker":
                    print("Authentication payload received from Broker.")
                    print("MUTUAL AUTHENTICATION DONE WITH MERCHANT")
                    self.Send_Msg_CM()

            elif "FORWARD_TO_CUSTOMER_FOR_AUTHENTICATION" in Decrypted_MESS:
                sender_info = Decrypted_MESS["FORWARD_TO_CUSTOMER_FOR_AUTHENTICATION"]["SENDER_INFO"]
                entity = sender_info.get["MERCHANT"]

                if entity == "MERCHANT": 
                        print("Authentication payload received from Broker.")
                        print("Authentication done with Merchant")
                    


    def Send_Msg_CB(self,choice):

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
                        "USER_ID": self.USER_ID,
                        "PASSWORD": self.password
                        },
                    "TS": timestamp,
                    #"SIGNATURE":sign
                }
            }

        #sign=signing(payload,self.customer1_private_key)
        payload = json.dumps(payload)
        encrypted_data = encrypt_data(payload,self.broker_public_key)
        print("Message Sent (Encrypted Format): ",encrypted_data)
        print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
        self.start_client(encrypted_data)


    def Send_Msg_CM(self):
            
        choice_1 = input("'M' for authentication with merchant: ").upper()
        print(choice_1)
        if choice_1 == 'M':
            timestamp = str(datetime.now())

            #PAYLOAD
            Merchant_Payload = { "PAYLOAD": {
            "ENTITY": "Customer",     
            "MESSAGE": "Hi Merchant"
            }
            }
            #payload = json.dumps(payload).encode()
            #sign=signing(payload,self.customer1_private_key)
            Merchant_Encrypted_Payload = encrypt_data(Merchant_Payload,self.merchant_public_key)
            payload = {  
            "TYPE": "MERCHANT_AUTHENTICATION",
            "ENTITY": "Customer",
            "USERID": self.USER_ID,
            "PAYLOAD": str(Merchant_Encrypted_Payload),
            "TS": timestamp,
            #"SIGNATURE":sign
            }

            #sign=signing(payload,self.customer1_private_key)
            payload = json.dumps(payload).encode()
            encrypted_data = encrypt_data(payload,self.broker_public_key)
            print("Message Sent (Encrypted Format): ",encrypted_data)
            print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
            self.start_client(encrypted_data)

    
        


    def main (self):
    # Get user input to decide whether to connect to the broker or merchant
        choice = input("'B' for authentication with broker ").upper()

        if choice == 'B':
            self.Send_Msg_CB(choice)
            
        print("Merchant Authentication Needs to be done here")

        


if __name__ == "__main__":
    broker_server = CustomerServer()
    broker_server.main()    















    




    
    
