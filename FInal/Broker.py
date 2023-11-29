import json
from random import random
import socket
import threading
import time
from typing import List
from Encryption import Encryption
from Decryption import Decryption


UUID_dict = {"CUST-1": {"UUID":"7e3642ee-1fc4-4f65-a148-1f1f8ff106aa","Key_BM":b'3804386826', "IV_BM":b'7693280211', "Key_CB":b'4103583911', "IV_CB":b'4832500747'}, 
             "CUST-2": {"UUID":"993775cc-ea1f-412a-b472-bab3084c6239", "Key_BM":b'3804386826', "IV_BM":b'7693280211', "Key_CB":b'6613586306b', "IV_CB":b'3559682480'} }


RandomID_dict = {"7e3642ee-1fc4-4f65-a148-1f1f8ff106aa" :6514161}


class Broker():

    def __init__(self) -> None:
        self.enc= Encryption()
        self.dec = Decryption()
    
    def Broker(self, User: str):
        self.Key_BM = UUID_dict.get(User).get("Key_BM")
        self.IV_BM = UUID_dict.get(User).get("IV_BM")
        self.Key_CB = UUID_dict.get(User).get("Key_CB")
        self.IV_CB = UUID_dict.get(User).get("IV_CB")
        self.UUID = UUID_dict.get(User).get("UUID")

        self.start_server()
   

    def BROER_MERCHANT(self,Decrypted_MESS_BM):
        MESS_BM = Decrypted_MESS_BM 
        
        if RandomID_dict[MESS_BM.get("UID")] is None:
            RandomID_dict[MESS_BM.get("UID")] = random.randint(1000,100000)

        MESS_BM.update({"UID": RandomID_dict[MESS_BM.get("UID")] })
        
        MESS_BM.update({"TIMESTAMP": time.time() })

        Decrypted_MESS_BM.update({'ACTION': "FROM CUSTOMER"})

        HASH_MESS_BM=self.enc.hash_256(json.dumps(MESS_BM).encode()+self.Key_BM)
        MESS_BM.update({'HASH': str(HASH_MESS_BM)})
        encoded_MESS_BM= json.dumps(MESS_BM).encode()
        return self.enc.encrypt(encoded_MESS_BM, self.Key_BM, self.IV_BM)
    
    def BROKER_CUSTOMER(self,Decrypted_MESS_CB):
        MESS_CB = Decrypted_MESS_CB 

        key_list = list(RandomID_dict.keys())
        val_list = list(RandomID_dict.values())

        position = val_list.index(MESS_CB.get("UID"))

        MESS_CB.update({"UID": RandomID_dict[key_list[position]] })
        
        MESS_CB.update({"TIMESTAMP": time.time() })

        Decrypted_MESS_CB.update({'ACTION': "FROM MERCHANT"})

        HASH_MESS_CB=self.enc.hash_256(json.dumps(MESS_CB).encode()+self.Key_CB)
        MESS_CB.update({'HASH': str(HASH_MESS_CB)})
        encoded_MESS_CB= json.dumps(MESS_CB).encode()
        return self.enc.encrypt(encoded_MESS_CB, self.Key_CB, self.IV_CB)


    def Recieve_Msg(self, s:str, Message: List):

        Received_Message = Message
        
        if s=="M":
            Decrypted_MESS = self.dec.decrypt(Received_Message, self.Key_BM, self.IV_BM)
        else:
            Decrypted_MESS = self.dec.decrypt(Received_Message, self.Key_CB, self.IV_CB)


        HASH= Decrypted_MESS.get('HASH')
        Decrypted_MESS.update({'HASH': ""})

        if Decrypted_MESS.get("ACTION")== "TO MERCHANT":
            print("<-----Message Received from the Customer----->")
        #Integrity validation
            if str(HASH) == str(self.enc.hash_256(json.dumps(Decrypted_MESS).encode()+self.Key_CB)):
                print("<-----Customer Hash Validated, Message Integrity is maintained..  Forwarding it to the Merchant.----->")
                Encrypted_MESS_BM=self.BROER_MERCHANT(Decrypted_MESS)
                self.start_client("Merchant",Encrypted_MESS_BM)
            else:
                print("<-----Message Tampered, cannot send Message----->")
        else:
            print("<-----Message Recieved from the Merchant----->")
            if str(HASH) == str(self.enc.hash_256(json.dumps(Decrypted_MESS).encode()+self.Key_BM)):
                print("<-----Merchant Hash Validated, Message Integrity is maintained..  Forwarding it to the Customer.----->")
                Encrypted_MESS_BC=self.BROKER_CUSTOMER(Decrypted_MESS)
                self.start_client("Customer",Encrypted_MESS_BC)
            else:
                print("<-----Message Tampered, cannot send Message----->")


    def start_client(self,Type,MSG):
        # Create a TCP/IP socket
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Connect the socket to the server's address and port
        if (Type=="Merchant"):
            server_address = ('127.0.0.1', 10001) # Replace 'server_ip_address' with the server's IP
            client_socket.connect(server_address)
        else:
            server_address = ('127.0.0.1', 10000) # Replace 'server_ip_address' with the server's IP
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
                    s="C" 
                    break
                elif chunk.endswith(b'STOM'):
                    s="M"
                    break
                else:
                    data.append(chunk)
            
            Cipher = data
            self.Recieve_Msg(s,Cipher)       
        finally:
            connection.close()
    
    
    def start_server(self):
    # Create a TCP/IP socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Bind the socket to the address and port
        server_address = ('0.0.0.0', 10002) # 0.0.0.0 binds to all available interfaces
        server_socket.bind(server_address)

        # Listen for incoming connections
        server_socket.listen(5)

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
                

if __name__ == '__main__':
    Broker().Broker("CUST-1")
