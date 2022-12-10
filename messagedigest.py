from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

def message_digest(file=None,message=None):
    hasher = hashes.Hash(hashes.SHA256(),default_backend())
    if file:
         with open(file,'r') as r:
             for line in r:
                 hasher.update(line.encode())
             return hasher.finalize()
    else:
        #print('File not provided. Hashing message')     
        #print(f'Hashing the following data:{message}')         
        hasher.update(message)             
        return hasher.finalize()


if __name__ == '__main__':
    digest = message_digest('data.txt')
    print(digest)

