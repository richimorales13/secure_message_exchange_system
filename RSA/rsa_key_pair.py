from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from os import path
def create_public_private_rsa_key_pair(password):
    backend = default_backend()
    #password = 'hello'
    #Generate privatekey/public key pair for RSA
    private_key = rsa.generate_private_key(public_exponent=65537,key_size=2048,backend=backend)
    #get the public key part
    public_key = private_key.public_key()
    #Encode the keys for serialization and saving
    #First the private key (which should be kept encrypted for security)
    pem_kr = private_key.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.PKCS8,encryption_algorithm=serialization.BestAvailableEncryption(password.encode()))
    #Now the public key
    pem_ku = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(path.join(path.abspath('.'),'keystore/kr.pem'),'wb') as w:
        w.write(pem_kr)
    with open(path.join(path.abspath('.'),'keystore/ku.pem'),'wb') as w2:
        w2.write(pem_ku) 


def load_private_key():
    pw = input('Enter password to load private key: ')
    with open(path.join(path.abspath('.'),'keystore/kr.pem'),'rb') as r:
        private_key = serialization.load_pem_private_key(data=r.read(),
            password=pw.encode(),backend=default_backend()
        )
        return private_key

def load_public_key():
    with open(path.join(path.abspath('.'),'keystore/ku.pem'),'rb') as r2:
        public_key = serialization.load_pem_public_key(
            data = r2.read(),
            backend=default_backend()
        )
        return public_key  
if __name__ == '__main__':
    pw = input('Enter password for public/private key generation: ')
    create_public_private_rsa_key_pair(pw)
    pass
