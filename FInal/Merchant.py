import ast
import json
import socket
import threading
import time
from typing import List
from Encryption import Encryption
from Decryption import Decryption
from Broker import Broker


dict1 = {6514161: {"Key_CM":b'7289135233', "IV_CM":b'6042302273'}, 
             "CUST-2": {"Key_CM":b'1307885065', "IV_CM":b'9370883913'} }
Broker_M = {"Key_BM":b'3804386826', "IV_BM":b'7693280211'}

Products ={
        "Product1": {
            "PRODUCT ID": 1,
            "PRODUCT NAME": "Iphone",
            "PRICE PER EA": "$1000"
        },
        "Product2": {
            "PRODUCT ID": 2,
            "PRODUCT NAME": "MACBOOK PRO",
            "PRICE PER EA": "$1800"
        },
        "Product3": {
            "PRODUCT ID": 3,
            "PRODUCT NAME": "IWatch",
            "PRICE PER EA": "$500"
        }
        }

Availability ={
        "Product1": {
        "PRODUCT ID": 1,
        "Quantity": 50,
        "PRODUCT CODE": 16316314631436146341368
    },
    "Product2": {
        "PRODUCT ID": 2,
        "Quantity": 100,
        "PRODUCT CODE": 65148641634684341847876
    },
    "Product3": {
        "PRODUCT ID": 3,
        "Quantity": 150,
        "PRODUCT CODE": 84616841341614464164164
    }
    }

class Merchant():

    def __init__(self) -> None:
        self.enc= Encryption()
        self.dec = Decryption()

    def Merchant(self):
        self.Key_BM = Broker_M.get("Key_BM")
        self.IV_BM = Broker_M.get("IV_BM")

        self.start_server()

    def Recieve_Msg(self, Message: List):
        Received_Message_BM = Message

        Decrypted_MESS_BM = self.dec.decrypt(Received_Message_BM, self.Key_BM, self.IV_BM)

        HASH= Decrypted_MESS_BM.get('HASH')
        Decrypted_MESS_BM.update({'HASH': ""})

        print(Decrypted_MESS_BM.get("UID"))

        #Integrity validation
        if str(HASH) == str(self.dec.hash_256(json.dumps(Decrypted_MESS_BM).encode()+self.Key_BM)):
            print("BROKER Message Hash Validated, Message Integrity is maintained")
        else:
            print("Message Tampered")

        Payload = dict(Decrypted_MESS_BM.get('PAYLOAD'))

        if Decrypted_MESS_BM.get("ACTION")== "FROM CUSTOMER":
            print("Message Received from Customer ")
            bytes_list = ast.literal_eval(Payload.get("MESSAGE"))
            self.Key_CM = dict1.get(Decrypted_MESS_BM.get("UID")).get("Key_CM")
            self.IV_CM = dict1.get(Decrypted_MESS_BM.get("UID")).get("IV_CM")
            Decrypted_Payload = self.dec.decrypt(bytes_list, self.Key_CM, self.IV_CM)

            if Payload.get("HASH") == str(self.dec.hash_256(json.dumps(Decrypted_Payload).encode()+self.Key_CM)):
                print("Customer Message Hash Validated, Message Integrity is maintained")
                if Decrypted_Payload.get("ACTION") == "VIEW PRODUCTS":
                    print("CUSTOMER want to view the products sending the products list")
                    Encrypted_MESS_MB=self.CUSTOMER_BROKER("VIEW", Decrypted_MESS_BM)
                    self.start_client(Encrypted_MESS_MB)
                else:
                    print("CUSTOMER wants to purchase the product")
                    Encrypted_MESS_MB=self.CUSTOMER_BROKER("PURCHASE",Decrypted_MESS_BM)
                    self.start_client(Encrypted_MESS_MB)
            else:
                print("Message Tampered")



    def CUSTOMER_BROKER(self,Action,Decrypted_MESS_BM):
        MESS_MB = Decrypted_MESS_BM
        MESS_MB.update({"ACTION": "TO CUSTOMER"})
        MESS_MB.update({"TIMESTAMP": time.time()})


        if Action=="VIEW":
            MESSAGE = {            
                "ACTION": "PRODUCTS LIST",
                "PRODUCTS": Products,
                "TIMESTAMP": time.time()
                }
            HASH_MESS_MC = self.enc.hash_256(json.dumps(MESSAGE).encode()+self.Key_CM)
            PAYLOAD = {
                "PADDING_SIZE": "32",
                "MESSAGE": MESSAGE,
                "HASH": str(HASH_MESS_MC)
            }
        else:
            MESSAGE = {            
                "ACTION": "PRODUCT",
                "PRODUCT CODE": Decrypted_MESS_BM,
                "TIMESTAMP": time.time()
                }
            HASH_MESS_MC = self.enc.hash_256(json.dumps(MESSAGE).encode()+self.Key_CM)
            PAYLOAD = {
                "PADDING_SIZE": "32",
                "MESSAGE": MESSAGE,
                "HASH": str(HASH_MESS_MC)
            }
        encoded_Payload= json.dumps(PAYLOAD).encode()
        Encrypted_Payload = self.enc.encrypt(encoded_Payload, self.Key_CM, self.IV_CM)

        MESS_MB.update({"PAYLOAD": str(Encrypted_Payload)})
        HASH_MB = self.enc.hash_256(json.dumps(MESS_MB).encode()+self.Key_BM)
        MESS_MB.update({"HASH": str(HASH_MB)})
        print(MESS_MB.get("UID"))

        encoded_MESS_MB= json.dumps(MESS_MB).encode()
        Encrypted_MESS_MB = self.enc.encrypt(encoded_MESS_MB, self.Key_BM, self.IV_BM)
        return Encrypted_MESS_MB
    

    def start_client(self,MSG):
        # Create a TCP/IP socket
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Connect the socket to the server's address and port
        server_address = ('127.0.0.1', 10002) # Replace 'server_ip_address' with the server's IP
        client_socket.connect(server_address)

        try:
            for c in MSG:
                client_socket.sendall(c)
            client_socket.send(b'STOM')

        finally:
            # Close the socket to clean up
            client_socket.close()
            Merchant.start_server(self)
    
    def handle_client(self,connection):
        try:
            data=[]
            while True:
                chunk = connection.recv(32)
                if chunk.endswith(b'STOP'): 
                    break
                else:
                    data.append(chunk)
            
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

        print("<------Waiting for the Broker to send the request----->")

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

if __name__ == '__main__':
    Merchant().Merchant()