from receiving_app import search_certificate
from verify_cert import load_certificate
from kdf import create_symmetric_key
from cipher import create_cipher
from kdf import create_initialization_vector
from cryptography.hazmat.backends import default_backend
from base64 import b64encode
from cryptography.hazmat.primitives import padding
from digital_sig import get_OAEP_padding,get_PSS_padding
import messagedigest as msgd
from RSA.rsa_key_pair import load_private_key
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives import hashes
from encodings.base64_codec import base64_encode
def read_file(filename):
    if filename:
        try:
             with open(filename,'r') as r: return r.read()
        except UnicodeDecodeError:
            try:
                 print('Cannot read file. File is not Unicode encoded. Convering to Unicode Assuming file is latin_1 encoded.')  
                 with open(filename,'rb') as r: d = r.read()
                 d = d.decode('latin_1')
                 d = d.encode()
                 d = d.decode()
                 return d
            except Exception as e:
                print(f'Received exception {e}')
                print('Cannot read file due to encoding. Change the encoding of the file and try again.')
                exit()     
               

if __name__ == '__main__':
    userid = input('Enter the userid to whom you want to send to: ')
    filepath = search_certificate(userid)
    message=''
    if filepath:
        print(f'Found certificate for {userid}')
        while True:
             user_choice = input('Press 0 to send file or 1 to write message:')
             if user_choice == '0':
                 filename=input('Enter filename to send: ')
                 message = read_file(filename)
                 break
             elif user_choice == '1':    
                  message = input('Enter the message to be sent: ')
                  break
             else:
                 print('Not a valid option...')     
        symkey_pw = input('Enter password for symmetric key: ')
        print("Creating symmetric key.")
        symmetric_key = create_symmetric_key(symkey_pw.encode())
        pad = padding.PKCS7(128).padder()
        print('Padding data.')
        datapad = pad.update(message.encode()) + pad.finalize()
        iv_pw = input('Enter password for iv: ')
        iv = create_initialization_vector(iv_pw.encode())
        cipher = create_cipher(symmetric_key,iv,default_backend())
        encryptor = cipher.encryptor()
        print("Encrypting message.")
        encrypted_message = encryptor.update(datapad) + encryptor.finalize()
        b64_message = base64_encode(encrypted_message)[0]
        print('Loading receivers certificate.')
        certifiate = load_certificate(filepath)
        print('Loading certificate public key.')
        publickey = certifiate.public_key()
        print('Encrypting symmetric key with public key.')
        encrypted_symkey = publickey.encrypt(symmetric_key,get_OAEP_padding())
        print('Encrypting IV with public key.')
        encrypted_iv = publickey.encrypt(iv,get_OAEP_padding())
        bytes_to_write = bytearray(b'-----BEGIN ID-----\n' + userid.encode()+b'\n'+
                                   b'-----END ID-----\n'+
                                   b'-----BEGIN MESSAGE-----\n'+
                                   b64_message +
                                   b'-----END MESSAGE-----\n' +
                                   b'-----BEGIN EKEY-----\n' +
                                   base64_encode(encrypted_symkey)[0]+
                                   b'-----END EKEY-----\n'+
                                   b'-----BEGIN EIV-----\n'+
                                   base64_encode(encrypted_iv)[0]+
                                   b'-----END EIV-----\n'
        )
        pkey = load_private_key()
        print('Creating message digest.')
        message_digest = msgd.message_digest(message=bytes_to_write)
        print('Signing digest with private key.')
        signature = pkey.sign(message_digest,padding=get_PSS_padding(),algorithm=utils.Prehashed(hashes.SHA256()))
        #print(f'sig = {signature}')
        bytes_to_write = bytes_to_write + b'-----BEGIN SIGNATURE-----\n' + base64_encode(signature)[0]+ b'-----END SIGNATURE-----\n'
        print('Writing to file.')
        with open('messagetosend.txt','wb') as w:
            w.write(bytes_to_write)
    else:
        print(f'{userid} certificate not found...')        





