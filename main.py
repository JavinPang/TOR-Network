import socket
import base64
import json

from time import sleep
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.fernet import Fernet


webnode1Socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM);
CenterSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM);
 
print("\n---------------------TOR Network Demo---------------------\n")
host = "127.0.0.1"

CenterSocket.connect(("127.0.0.1",9103));
dataFromcenterserver = CenterSocket.recv(9999)
dataFromcenterserver = dataFromcenterserver.decode()
dataFromcenterserver = json.loads(dataFromcenterserver)
CenterSocket.close()
destination1 = int(f"{dataFromcenterserver['details']['port1']}")
destination2 = int(f"{dataFromcenterserver['details']['port2']}")
destination3 = int(f"{dataFromcenterserver['details']['port3']}")



L = 1
while (L == 1) :
    webnode1Socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM);
    webnode1Socket.connect((host,destination1));
    connected = True
    try:
        print("Enter a keyword: ")
        userinput = input()
        data = {
            'details': {
                'message': userinput,
                'destination2': destination2,
                'destination3': destination3
            }
        }
        print("Input: ", userinput)
        print(f'Data to be sent out: {data}')
        print()
    

        print("Encrypting message.....")
    
        for x in range(3):
            print(f'---------------------Encryption: {x}---------------------')
        

            with open(f'fernet_key_{x}.txt', 'rb') as fernet_key:
                key = fernet_key.read()
                f = Fernet(key)

                byted_data = json.dumps(data)
                byted_data = byted_data.encode()
                data['details']['message'] = f.encrypt(byted_data).decode()
                data['details']['destination2'] = destination2
                data['details']['destination3'] = destination3
                data['key'] = key

            with open(f'public_key_{x}.pem', 'rb') as public_key:
                encryptor = serialization.load_pem_public_key(
                    public_key.read(),
                    backend = default_backend()
                )

                data['key'] = encryptor.encrypt(
                    data['key'],
                    padding.OAEP(
                        mgf = padding.MGF1(algorithm = hashes.SHA256()),
                        algorithm = hashes.SHA256(),
                        label = None
                    )
                )
                data['key'] = base64.b64encode(data['key'])
                data['key'] = data['key'].decode()
            print(f"Encrypted Message is: {data['details']['message']}")
            print("Encrypted Message Sent out\n")


        encrypteddata = json.dumps(data).encode('utf-8')
        webnode1Socket.sendall(encrypteddata)
    except socket.error:
        connected = False
        webnode1Socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM);   
        print( "connection lost to webnode1... reconnecting" )  
        while not connected:  
            try:  
                webnode1Socket.connect((host,destination1));
                connected = True  
                print( "re-connection to webnode1 successful" )  
                webnode1Socket.sendall(encrypteddata)
                print(encrypteddata)
            except socket.error:  
                sleep( 2 ) 

