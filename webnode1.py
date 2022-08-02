import base64
import json
import socket

from time import sleep  
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.fernet import Fernet


print("\n------------Webnode 1 is online------------\n")
print("Generating encryption key")

x = 2
private_key = rsa.generate_private_key(
    public_exponent = 65537,
    key_size = 2048,
    backend = default_backend()
)
public_key = private_key.public_key()

private_pem = private_key.private_bytes(
    encoding = serialization.Encoding.PEM,
    format = serialization.PrivateFormat.PKCS8,
    encryption_algorithm = serialization.NoEncryption()
)

public_pem = public_key.public_bytes(
    encoding = serialization.Encoding.PEM,
    format = serialization.PublicFormat.SubjectPublicKeyInfo
)

with open(f'fernet_key_{x}.txt', 'wb') as f:
    f.write(Fernet.generate_key())

with open(f'private_key_{x}.pem', 'wb') as f:
    f.write(private_pem)

with open(f'public_key_{x}.pem', 'wb') as f:
    f.write(public_pem)

print()

MainSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM);
webnode2Socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM);
CenterSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM);


host = "127.0.0.1"
port = 9090

CenterSocket.connect(("127.0.0.1",9100));
CenterSocket.sendall(str(port).encode());
CenterSocket.close()


L = 1
while (L == 1) :
    MainSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM);
    webnode2Socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM);
    MainSocket.bind(("127.0.0.1",9090));

    MainSocket.listen();
    
    print ("Webnode1 is awaiting for connection")	
    # Accept connections
    checkdestination2 = ""
    connected = True
    while(True):   
        (clientConnected, clientAddress) = MainSocket.accept();
        serverconnected = True
        try:
            print("Ready to receive encrypted message\n")
            data = clientConnected.recv(9999)
            data = data.decode()
            data = json.loads(data)
            print(f"Received Message : {data['details']['message']}\n")
            destination2 = int(f"{data['details']['destination2']}")
            try:
                if checkdestination2 == "":
                    webnode2Socket.connect((host,destination2));
                checkdestination2 = destination2
                
                print("Decrypting message.....\n")
                x = 2
                print(f'---------------------Decryption: {x}---------------------')

                with open(f'private_key_{x}.pem', 'rb') as private_key:
                    decryptor = serialization.load_pem_private_key(
                        private_key.read(), 
                        password = None,
                        backend = default_backend()
                )

                if type(data['key']) != bytes:
                    data['key'] = data['key'].encode()

                data['key'] = base64.b64decode(data['key'])
                data['key'] = decryptor.decrypt(
                    data['key'],
                    padding.OAEP(
                        mgf = padding.MGF1(algorithm = hashes.SHA256()),
                        algorithm = hashes.SHA256(),
                        label = None
                    )
                )

                f = Fernet(data['key'])

                byted_data = f.decrypt(data['details']['message'].encode())
                byted_data = byted_data.decode()
                data = json.loads(byted_data)

                print(f"Decrypted Message : {data['details']['message']}\n")

                encrypteddata = json.dumps(data).encode('utf-8')
                webnode2Socket.sendall(encrypteddata)
            except socket.error:
                connected = False
                webnode2Socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM);
                print( "connection lost to Webnode2... reconnecting" )  
                while not connected:   
                    try:  
                        webnode2Socket.connect((host,destination2)); 
                        connected = True  
                        print( "re-connection to Webnode2 successful" )  
                    except socket.error:  
                        sleep( 2 )  

        except socket.error:
            serverconnected = False
            MainSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM);
            print( "connection lost from client... reconnecting" )  
            while not serverconnected:  
                try:  
                    MainSocket.bind(("127.0.0.1",9090))
                    MainSocket.listen()
                    (clientConnected, clientAddress) = MainSocket.accept()
                    serverconnected = True
                    print( "re-connection from client successful" ) 
                    sleep( 2 ) 
                except socket.error:  
                    sleep( 2 )  


