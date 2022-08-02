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



print("\n------------Webnode 3 is online------------\n")
print("Generating encryption key")

x = 0
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


CenterSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM);
webnode2Socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM);

host = "127.0.0.1"
port = 9095

CenterSocket.connect(("127.0.0.1",9102));
CenterSocket.sendall(str(port).encode());
CenterSocket.close()


L = 1

webnode2Socket.bind((host,port));

webnode2Socket.listen();

# exit()

print ("Webnode3 is awaiting for connection")	
# Accept connections

while(True):

    (WebSocket2Connected, WebSocket2Address) = webnode2Socket.accept();
    connected = True
        # webnode2Socket.connect((host,9091));
    while (L == 1) :    
        try:
            print("Ready to receive encrypted message\n")
            data = WebSocket2Connected.recv(9999)
            data = data.decode()
            data = json.loads(data)
            print(f"Received Message : {data['details']['message']}\n")
            
        #   DECRYPTION
            print("Decrypting message.....\n")
            x = 0
            # for x in range(2, -1, -1):
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
        except socket.error:
            connected = False  
            webnode2Socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM);
            print( "connection lost from client... reconnecting" ) 
            while not connected:  
                try:  
                    webnode2Socket.bind((host,port));
                    webnode2Socket.listen();  
                    (WebSocket2Connected, WebSocket2Address) = webnode2Socket.accept(); 
                    connected = True 
                    print( "re-connection from client successful" )    
                except socket.error:  
                    sleep( 2 )  




    



    

   