# secure_message_exchange_system

1) Run python script in RSA folder to generate a private/public key. A public/private key is required for sending/receiving applications to work.
2) You can add certificates by running X509.py. This will store the certificate in the keystore folder. You must adjust this code and fill in the ceritificate information yourself. Consult cryptography library for information on how to fill certificate.
3) Run receiving_app.py to decrypt a message from a file
4) Run sending_app.py to encrypt a file for sending or encrypt a provided message. Output is saved to messagetosend.txt.

Note: userid = firstname in lowercase. This is to match a certificate found in the keystore folder.
