import socket
import base64
import json

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.fernet import Fernet

print("\n---------------------Center Server is online---------------------\n")


serverSocket1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM);

serverSocket2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM);

serverSocket3 = socket.socket(socket.AF_INET, socket.SOCK_STREAM);

mainsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM);


serverSocket3.bind(("127.0.0.1",9102));

serverSocket3.listen();

serverSocket2.bind(("127.0.0.1",9101));

serverSocket2.listen();

serverSocket1.bind(("127.0.0.1",9100));

serverSocket1.listen();

mainsocket.bind(("127.0.0.1",9103));

mainsocket.listen();
 
print("Center server is waiting for connection\n")
# Accept connections

while(True):


    (clientConnected3, clientAddress3) = serverSocket3.accept();
    print("Webnode3 Connected")

    (clientConnected2, clientAddress2) = serverSocket2.accept();
    print("Webnode2 Connected")

    (clientConnected1, clientAddress1) = serverSocket1.accept();
    print("Webnode1 Connected")
    
    (mainConnected, mainAddress) = mainsocket.accept();
    print("Main program Connected\n")
    

    dataFromClient3 = clientConnected3.recv(1024)
  
    dataFromClient2 = clientConnected2.recv(1024)

    dataFromClient1 = clientConnected1.recv(1024)

    data = {
        'details': {

            'port3': dataFromClient3.decode(),
            'port2': dataFromClient2.decode(),
            'port1': dataFromClient1.decode(),
        }
    }

    port = [dataFromClient1, dataFromClient2, dataFromClient3]
    for (x, number) in enumerate (port, start=1):

         print("Webnode",x," port number: ",number.decode())
         
    encrypteddata = json.dumps(data).encode('utf-8')
    mainConnected.sendall(encrypteddata);
    print("\nPort number sent to Main program")
    clientConnected3.close()
    clientConnected2.close()
    clientConnected1.close()
    mainConnected.close()
    print("\nTerminating Center Server......")
    exit()


    