import socket
from Decryption import *

def start_server():
    # Create a TCP/IP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to the address and port
    server_address = ('127.0.0.1', 10000) # 0.0.0.0 binds to all available interfaces
    server_socket.bind(server_address)

    # Listen for incoming connections
    server_socket.listen(1)

    while True:
        # Wait for a connection
        print('waiting for a connection')
        connection, client_address = server_socket.accept()

        try:
            print('connection from', client_address)
            data= b''
            # Receive the data in small chunks and retransmit it
            while True:
                chunk = connection.recv(128)

                data+= chunk

                if not chunk:
                    connection.close()
                    break
            
            # print('received hash {!r}'.format(data))
            IV = b'4832500747'
            Key = b'4103583911'
            Cipher= data.hex()
            print("Cipher ", Cipher)
            Plain = Decryption.Plain_Text(IV, Key, Cipher)
            print(type(Plain))
            print("Plain Text: " ,Plain)
        
        finally:
            print("Done")

if __name__ == '__main__':
    start_server()
