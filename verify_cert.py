from cryptography import x509
from cryptography.hazmat.backends import default_backend
from os import path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from verify_sig import verify_signature


def load_certificate(path_to_file):
    with open(path_to_file,'rb') as r:
        certificate = x509.load_pem_x509_certificate(
            data=r.read(),
            backend = default_backend()
        )
        return certificate 

def verify_certificate(certificate):
        public_key = certificate.public_key()
        sig = certificate.signature
        data = certificate.tbs_certificate_bytes
        myhash = hashes.SHA256()
        hasher = hashes.Hash(myhash,default_backend())
        hasher.update(data)
        digest = hasher.finalize()
        pad = padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        )
        return verify_signature(ku=public_key,sig=sig,digest=digest)


if __name__ == '__main__':
        user = input('Enter name of user whose certificate you want to validate: ')
        user = user+'_cert.pem'
        certificate = load_certificate(path.join(path.abspath('.'),f'keystore/{user}'))
        verify_certificate(certificate)

        
