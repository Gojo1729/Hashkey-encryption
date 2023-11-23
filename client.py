import socket
from Encryption import *

def start_client():
    # Create a TCP/IP socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect the socket to the server's address and port
    server_address = ('127.0.0.1', 10000) # Replace 'server_ip_address' with the server's IP
    client_socket.connect(server_address)

    try:
        # Send data
        IV = b'4832500747'
        Key = b'4103583911'
        Message= b"Firstly, the Customer sends Firstly, the Customer sends Firstl"
        Message_Chunks = Encryption.Cipher_Text(IV, Key, Message)
        for c in Message_Chunks:
            client_socket.sendall(c)

    finally:
        # Close the socket to clean up
        client_socket.close()

if __name__ == '__main__':
    start_client()




