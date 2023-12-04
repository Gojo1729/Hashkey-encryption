import socket
import json
from datetime import datetime
import threading
from encryption import encrypt_data
from encryption import signing
from decryption import decrypt_data
from decryption import verify

class MerchantServer:
    def __init__(self):
            # Initialize your variables here
            self.broker_public_key = "broker_public_key.pem"
            self.merchant_public_key = "merchant_public_key.pem"
            self.merchant_private_key = "merchant_private_key.pem"
            


    def Recieve_Msg(self, Message):
            
            Received_Message = Message
            Decrypted_MESS = decrypt_data(Received_Message,self.merchant_private_key)
            print("Encrypted payload:", Received_Message)
            Decrypted_MESS = json.loads(Decrypted_MESS)
            formatted_data = json.dumps(Decrypted_MESS, indent=2)
            print(f"Received from Broker:\n {formatted_data}")
            
            #print("Decrypted payload:", Decrypted_MESS)
        
            #signature = Decrypted_MESS["SIGNATURE"]
            #Verification = verify(Decrypted_MESS,signature,self.merchant_private_key)
            #if Verification == "NV":
             #   print("Message Verification is failed ....")
                            
            #else:
                
            if "MUTUAL_AUTHENTICATION" == Decrypted_MESS["TYPE"]:
                                entity = Decrypted_MESS["ENTITY"]
                                print(entity)
                                if entity == "Broker":
                                    print("Authentication payload received from Broker.")
                                    self.Send_Msg_MB()


            elif "MERCHANT_AUTHENTICATION" == Decrypted_MESS["TYPE"]:
                                entity = Decrypted_MESS["ENTITY"]
                                RID = Decrypted_MESS["RID"]
                                print(entity)
                                if entity == "MERCHANT": 
                                    print("Authentication payload received from Merchant.")
                                    self.Send_Msg_MC(RID)


    def Send_Msg_MB(self):
            
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
            payload = encrypt_data(payload, self.broker_public_key)
            self.start_client(payload)           
            print("Message Sent (Encrypted Format): ",payload)
            


    def Send_Msg_MC(self,RID):
            
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
            Customer_Encrypted_Payload = encrypt_data(payload,self.merchant_public_key)
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
            payload = encrypt_data(json.dumps(payload), self.broker_public_key)
            print(payload)





    def start_client(self,MSG):
            # Create a TCP/IP socket
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # Connect the socket to the server's address and port

            server_address = ('127.0.0.1', 10000) # Replace 'server_ip_address' with the server's IP
            client_socket.connect(server_address)
            
            try:
                client_socket.sendall(MSG)
                client_socket.send(b'STOM')

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
                        break
                    else:
                        data+=chunk
                
                Cipher = data
                self.Recieve_Msg(Cipher)       
            finally:
                connection.close()


    def start_server(self):
        # Create a TCP/IP socket
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Bind the socket to the address and port
            server_address = ('0.0.0.0', 10001) # 0.0.0.0 binds to all available interfaces
            server_socket.bind(server_address)

            # Listen for incoming connections
            server_socket.listen(1)

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
                # server_socket.close()
                


    def main():
        merchant_server = MerchantServer()
        merchant_server.start_server()


if __name__ == "__main__":
    MerchantServer.main()



