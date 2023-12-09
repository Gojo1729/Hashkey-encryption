import ast
import json
import socket
import threading
import time
from typing import List
from Encryption import Encryption
from Decryption import Decryption


UUID_dict = {"CUST-1": {"UUID":"7e3642ee-1fc4-4f65-a148-1f1f8ff106aa","Key_CM":b'7289135233', "IV_CM":b'6042302273', "Key_CB":b'4103583911', "IV_CB":b'4832500747'}, 
             "CUST-2": {"UUID":"993775cc-ea1f-412a-b472-bab3084c6239", "Key_CM":b'1307885065', "IV_CM":b'9370883913', "Key_CB":b'6613586306b', "IV_CB":b'3559682480'} }



class Customer():

    def __init__(self) -> None:
        self.enc= Encryption()
        self.dec = Decryption()


    def Customer(self,User: str):
        self.Key_CM = UUID_dict.get(User).get("Key_CM")
        self.IV_CM = UUID_dict.get(User).get("IV_CM")
        self.Key_CB = UUID_dict.get(User).get("Key_CB")
        self.IV_CB = UUID_dict.get(User).get("IV_CB")
        self.UUID = UUID_dict.get(User).get("UUID")

        Action = input("Hello {User}" + "Do you want to View the Products (V) or Buy the products (B) ?")
        if Action== "V":
            self.Send_Msg("VIEW PRODUCTS", self.Key_CM, self.IV_CM, self.Key_CB, self.IV_CB, self.UUID)
        else:
            self.Send_Msg("BUY PRODUCT", self.Key_CM, self.IV_CM, self.Key_CB, self.IV_CB, self.UUID)


    def ViewProducts(self,Key: bytes, IV:bytes):

        MESSAGE= {
        "ACTION": "VIEW PRODUCTS",
        "TIMESTAMP": time.time()
        }
        encoded_MESS_CM = json.dumps(MESSAGE).encode()
        payload = self.enc.encrypt(encoded_MESS_CM, Key, IV)
        HASH_MESS_CM = self.enc.hash_256(encoded_MESS_CM+  Key)
        return payload,HASH_MESS_CM 

    def BuyProduct(self,Key: bytes, IV:bytes):

        MESSAGE= {
        "ACTION": "BUY PRODUCT",
        "Product_ID": input("Enter the Product ID"),
        "TIMESTAMP": time.time()
        }
        encoded_MESS_CM = json.dumps(MESSAGE).encode()
        payload = self.enc.encrypt(encoded_MESS_CM,Key,IV)
        HASH_MESS_CM = self.enc.hash_256(encoded_MESS_CM+Key) 
        return payload,HASH_MESS_CM


    def Send_Msg(self,Action: str, Key_CM, IV_CM, Key_CB, IV_CB, UUID):

        if Action=="VIEW PRODUCTS":
            payload,HASH_MESS_CM=self.ViewProducts(Key_CM,IV_CM)
        else:
            payload,HASH_MESS_CM=self.BuyProduct(Key_CM,IV_CM)

        HASH_MESS_CB=""
        MESS_CB = {
        "UID": UUID,
        "HASH": "",
        "ACTION": "TO MERCHANT",
        "TIMESTAMP": time.time(),
        "PADDING": "32",
        "PAYLOAD": {
                    "PADDING_SIZE": "32",
                    "MESSAGE": str(payload),
                    "HASH": str(HASH_MESS_CM)
                    }
        }

        HASH_MESS_CB=self.enc.hash_256(json.dumps(MESS_CB).encode()+Key_CB)
        MESS_CB.update({'HASH': str(HASH_MESS_CB)})
        encoded_MESS_CB= json.dumps(MESS_CB).encode()
        Encrypted_MESS_CB = self.enc.encrypt(encoded_MESS_CB, Key_CB, IV_CB)
        print("Message Sent (Encrypted Format): ",Encrypted_MESS_CB)
        self.start_client(Encrypted_MESS_CB)

    def Recieve_Msg(self, Message: List):
        
        Received_Message_BC = Message
        Decrypted_MESS_BC = self.dec.decrypt(Received_Message_BC, self.Key_CB, self.IV_CB)

        # key_list = list(RandomID_dict.keys())
        # val_list = list(RandomID_dict.values())

        # position = val_list.index(MESS_BC.get("UID"))

        HASH= Decrypted_MESS_BC.get('HASH')
        Decrypted_MESS_BC.update({'HASH': ""})

        #Integrity validation
        if str(HASH) == str(self.enc.hash_256(json.dumps(Decrypted_MESS_BC).encode()+self.Key_CB)):
            print("Brokers Message Hash Validated, Message Integrity is maintained")
            if Decrypted_MESS_BC['ACTION']== "FROM MERCHANT":
                consent = input("Recieved Message From Merchant Want to view it ? Yes/No")
                if consent == "Yes":
                    bytes_list = ast.literal_eval(Decrypted_MESS_BC.get("PAYLOAD"))
                    Decrypted_Payload=self.dec.decrypt(bytes_list, self.Key_CM, self.IV_CM)
                    MESSAGE = dict(Decrypted_Payload.get("MESSAGE"))
                    if MESSAGE.get("ACTION") == "PRODUCTS LIST":
                        consent=input("Received Products List, Want to see ? Yes/No")
                        if consent=="Yes":
                            print(MESSAGE.get("PRODUCTS"))
                        else:
                            print("Denied")
            else:
                print("Denied")
        else:
            print("Message Tampered")
        

    def start_client(self,MSG):
        # Create a TCP/IP socket
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Connect the socket to the server's address and port
        server_address = ('127.0.0.1', 10002) # Replace 'server_ip_address' with the server's IP
        client_socket.connect(server_address)

        try:
            for c in MSG:
                client_socket.sendall(c)
            client_socket.send(b'STOP')

        finally:
            # Close the socket to clean up
            client_socket.close()
            self.start_server()

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

        # Bind the socket to the address and port
        server_address = ('0.0.0.0', 10000) # 0.0.0.0 binds to all available interfaces
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
            server_socket.close()

if __name__ == '__main__':
    Customer().Customer("CUST-1")
