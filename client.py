from Encryption import *
import socket

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
        Message= "Firstly, the Customer sends "
        print(Message)
        Hash_chunks = Encryption.Cipher_Text(IV, Key, Message)
        print(Hash_chunks)

        # print("Hash ready: ",Final_Hash)
        # print('sending {!r}'.format(Final_Hash))
        client_socket.sendall(Hash_chunks)

        # Look for the response
        # amount_received = 0
        # amount_expected = len(Final_Hash)
        
        # while amount_received < amount_expected:
        #     data = client_socket.recv(16)
        #     amount_received += len(data)
        #     print('received {!r}'.format(data.decode()))

    finally:
        # Close the socket to clean up
        client_socket.close()

if __name__ == '__main__':
    start_client()




