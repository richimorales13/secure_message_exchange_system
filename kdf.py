import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

def create_symmetric_key(password:bytes):
    backend = default_backend()
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=16,
        salt=salt,
        iterations=100000,
        backend=backend
    )
    key = kdf.derive(password)
    #print(f'Key = {key.hex()}')
    return key

def create_initialization_vector(ivval:bytes):
    backend = default_backend()
    salt = os.urandom(16)
    idf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=16,
        salt=salt,
        iterations=100000,
        backend=backend
    )
    iv = idf.derive(ivval)
    #print(f'iv = {iv.hex()}')
    return iv

if __name__ == '__main__':

    passwd = b'password'
    ivval= b'hello'

    key = create_symmetric_key(passwd)
    iv = create_initialization_vector(ivval)



    

