from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import kdf as k   

def create_cipher(key,iv,backend):
     cipher = Cipher(algorithm=algorithms.AES(key),
     mode=modes.CBC(iv),
     backend=backend
     )
     return cipher    


if __name__ =='__main__':
     password = input('Enter seed value as string:')
     ivval = input('Enter seed value for IV as string:')
     iv = k.create_initialization_vector(ivval.encode()) 
     key = k.create_symmetric_key(password.encode())
     backend = default_backend()

     cipher = create_cipher(key,iv,backend)
     cipher1 = create_cipher(key,iv,backend)
     encryptor = cipher.encryptor()
     encryptor1 = cipher1.encryptor()
     mydata = b'1234567812345678'
     print(f'Len of data = {len(mydata)}')
     print(f'Mydata in bytes = {mydata}')
     print(f'Mydata as hex = {mydata.hex()}')
     ciphertext = encryptor.update(mydata) + encryptor.finalize()
     print(f'Ciphertext as bytes = {ciphertext}')
     print(f'Ciphertext as hex = {ciphertext.hex()}')
 
     decryptor = cipher.decryptor()
     plaintext = decryptor.update(ciphertext) + decryptor.finalize()
     print(f'Plaintext as bytes = {plaintext}')
     print(f'Plaintext as hex = {plaintext.hex()}')
     
 
     ##Task 5.3 Effect of padding
     padder = padding.PKCS7(128).padder()
     mydata1 = b'1234567812345678'
     mydata_pad = padder.update(mydata1) + padder.finalize()
     print(f'After padding len of mydata = {len(mydata1)}')
     print(f'Data with padding as bytes = {mydata_pad}')
     print(f'Data with padding as hex = {mydata_pad.hex()}')
     cipher_text1= encryptor1.update(mydata_pad) + encryptor1.finalize()
     