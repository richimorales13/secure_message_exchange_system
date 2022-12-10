from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import utils
import cryptography.exceptions
import messagedigest as msgd
from RSA.rsa_key_pair import load_public_key
from digital_sig import get_PSS_padding
from base64 import b64decode

def load_signature(file):
    signature = bytearray()
    with open(file,'rb') as r:
        for line in r:
            if b'-----BEGIN SIGNATURE-----' in line or b'-----END SIGNATURE-----' in line:
                print("Found line to ignore")
            else:
                signature += bytearray(line.strip(b'\n'))
    return signature

def verify_signature(digest,ku,sig:bytes):
    try:
         ku.verify(
             signature=sig,
             data=digest,
             padding=get_PSS_padding(),
             algorithm=utils.Prehashed(hashes.SHA256())
         )
         print("Signature is valid with PSS padding")
         return True
    except cryptography.exceptions.InvalidSignature:
        print('Signature is invalid using PSS padding. Testing with PKCS1v15 padding')
        try:
            ku.verify(
                signature=sig,
                data=digest,
                padding=padding.PKCS1v15(),
                algorithm=utils.Prehashed(hashes.SHA256())
            )
            print("Signature is valid with PKCS1v15 padding")
        except cryptography.exceptions.InvalidSignature:
            print('Failed. Invalid signature...')    
            return False


if __name__ == '__main__':
    digest = msgd.message_digest('data.txt')
    ku = load_public_key()
    sig = load_signature('signature.sig')
    
    pad = get_PSS_padding()
    print(sig)
    print('----------------------------')
    decoded_sig = b64decode(sig)
    print(decoded_sig)
    print(verify_signature(digest,ku,decoded_sig))
    
    
