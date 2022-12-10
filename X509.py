from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.backends import default_backend
from RSA.rsa_key_pair import load_private_key,load_public_key
import datetime
from os import path

if __name__ == '__main__':
    print('Running X509.py file')
    kr = load_private_key()
    ku = load_public_key()
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME,u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME,u"Florida"),
        x509.NameAttribute(NameOID.LOCALITY_NAME,u"Coral Gables"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME,u"University of Miami"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME,u"ECE Dept"),
        x509.NameAttribute(NameOID.COMMON_NAME,u"Richard Morales"),
    ])
    issuer = subject
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer)
    builder = builder.not_valid_before(datetime.datetime.today())
    builder = builder.not_valid_after(datetime.datetime(2022,12,31))
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(ku)
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False,path_length=None),critical=True)

    certificate = builder.sign(
        private_key=kr,algorithm=hashes.SHA256(),backend=default_backend()
    )
    cert_name = 'Richard_cert.pem'
    with open(path.join(path.abspath('.'),'keystore',cert_name),'wb') as file:
        file.write(certificate.public_bytes(serialization.Encoding.PEM))    
