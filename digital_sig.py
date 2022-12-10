from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import utils
from encodings.base64_codec import base64_encode
import messagedigest as msgd
from RSA.rsa_key_pair import load_private_key as lpk

def get_PSS_padding():
    '''Padding used for signature'''
    pad = padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    )
    return pad

def get_OAEP_padding():
    '''Padding Used for encrypting key'''
    pad = padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
    return pad

if __name__ == '__main__':
    digest = msgd.message_digest('data.txt')
    kr = lpk()
    pad = get_PSS_padding()
    sig = kr.sign(
        data=digest,
        padding=pad,
        algorithm=utils.Prehashed(hashes.SHA256())
    )
    encoded_sig = base64_encode(sig)
    print(encoded_sig)

    with open('signature.sig','wb') as w:
        w.write('-----BEGIN SIGNATURE-----\n'.encode())
        w.write(base64_encode(sig)[0])
        w.write('-----END SIGNATURE-----\n'.encode())

    