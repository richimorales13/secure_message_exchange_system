from os import path
from verify_cert import load_certificate,verify_certificate
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from base64 import b64decode
from verify_sig import verify_signature
from RSA.rsa_key_pair import load_private_key
from cipher import create_cipher
from digital_sig import get_OAEP_padding

def search_certificate(userid:str):
    cert_name = userid.lower()+'_cert.pem'
    dir = path.join(path.abspath('.'),'keystore')
    filepath = path.join(dir,cert_name)
    print(f'Searching for file in filepath {filepath}')
    if path.isfile(filepath):
        return filepath
    else:
        return None    

def get_user_id_from_message(file:list[str]):
   while True:
        userid=''
        for line in file:
             if '-----BEGIN ID-----' in line:
                pass
             elif '-----END ID-----' in line:
                return userid.strip('\n')
             else:
                userid = userid + line
        break        


            
def get_EKEY(file:list[str]):
    i = iter(file)
    ekey = ''  
    for m in i:
        if '-----BEGIN EKEY-----' in m:
            ekey = i.__next__()
            for n in i:
                if '-----END EKEY-----' in n:
                    return ekey
                else:
                    ekey = ekey + n    


def get_message(file:list[str]):
    i = iter(file)  
    for m in i:
        if '-----BEGIN MESSAGE-----' in m:
            message = i.__next__()
            for n in i:
                if '-----END MESSAGE-----' in n:
                    return message
                else:
                    message = message + n

def get_signature(file:list[str]):
    i = iter(file)  
    sig = ''
    for m in i:
        if '-----BEGIN SIGNATURE-----' in m:
            #sig = sig + m
            sig = i.__next__()
            for n in i:
                if '-----END SIGNATURE-----' in n:
                    #sig = sig + n
                    return sig
                else:
                    sig = sig + n                        

def get_eiv(file:list[str]):
   i = iter(file)  
   for m in i:
       if '-----BEGIN EIV-----' in m:
           #eiv = eiv + m
           eiv = i.__next__()
           for n in i:
               if '-----END EIV-----' in n:
                   #eiv = eiv + n
                   return eiv
               else:
                   eiv = eiv + n                       
   
def grab_up_to_signature(file):
    data = ''
    with open(file,'r') as r:
        while True:
             line = r.readline()
             if '-----BEGIN SIGNATURE-----' in line:
                  break
             else:
                data = data + line   
    return data
    
                

if __name__ == '__main__':
    filename = input('Enter filename to load:')
    #filename = 'mess_to_richard_from_nigel.txt'
    if path.isfile(filename):
        with open(filename,'r') as r:
            file = r.readlines()
            print('Getting user id.')
            userid = get_user_id_from_message(file)
            if userid == None:
                print(f'Message was not properly formatted. Cannot get userid.')
                exit()
            print(f'Searching for {userid} certificate')
            cert_path = search_certificate(userid)
            #print(cert_path)
            print('Loading certificate.')
            certificate = load_certificate(cert_path)
            verify_certificate(certificate)
            print('Getting public key provided in certificate')
            ku = certificate.public_key()
            print('Getting encrypted message')
            message = get_message(file)
            #print(f'Message = #{message}#')
            print('Getting encrypted key')
            ekey = get_EKEY(file)
            #print(f'EKEY = #{ekey}#')
            print('Getting encrypted iv')
            eiv = get_eiv(file)
            #print(f'EIV = #{eiv}#')
            d = grab_up_to_signature(filename)
            #print(f"D = \n{d}")
            print('Creating digest.')
            myhash = hashes.SHA256()
            hasher = hashes.Hash(myhash,default_backend())
            hasher.update(d.encode())
            digest = hasher.finalize()
            #print(f'Digest = \n{digest}')
            print('Getting signature.')
            sig = get_signature(file)
            #print(f'Before decode, sig = \n{sig}')
            sig = b64decode(sig)
            print('Verifying signature.')
            if verify_signature(digest=digest,ku=ku,sig=sig):
                pkey = load_private_key()
                decrypted_ekey = pkey.decrypt(b64decode(ekey),padding=get_OAEP_padding())
                decrypted_iv = pkey.decrypt(b64decode(eiv),padding=get_OAEP_padding())
                AES_CIPHER = create_cipher(decrypted_ekey,decrypted_iv,default_backend())
                decryptor = AES_CIPHER.decryptor()
                decrypted_message = decryptor.update(b64decode(message)) + decryptor.finalize()
                print(f'------Decrypted message------\n{decrypted_message.decode()}')
            else:
                print('Signature is not valid and means the data has been modified...')

        




