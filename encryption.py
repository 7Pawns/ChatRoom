
# RSA
import rsa, os

# AES
from cryptography.fernet import Fernet

"""
The encryption process:

Generate RSA keys for server and each client.

Then generate AES key for each client and send it encrypted with their public key
"""

def AESgenerate_key():
    return Fernet.generate_key()
    
def RSAgenerate_keys(fname):
    """
    Generate private and public keys and save them to PEM files
    """
    
    if not os.path.exists('keys'):
        os.mkdir('keys')
        
    publickey, privatekey = rsa.newkeys(1024)
    with open(f'keys/{fname}pu.pem', 'wb') as f:
        f.write(publickey.save_pkcs1('PEM'))
        
    with open(f'keys/{fname}pr.pem', 'wb') as f:
        f.write(privatekey.save_pkcs1('PEM'))
        

def load_keys(fname):
    """
    Load the keys from the pem files
    """
    
    with open(f'keys/{fname}pu.pem', 'rb') as f:
        publickey = rsa.PublicKey.load_pkcs1(f.read())
    
    with open(f'keys/{fname}pr.pem', 'rb') as f:
        privatekey = rsa.PrivateKey.load_pkcs1(f.read())
        
    return publickey, privatekey

def RSAencrypt(message, publickey):
    
    # print('chunk', message)
    # Only for jpegs
    if isinstance(message, bytes):
        return rsa.encrypt(message, publickey)
    
    return rsa.encrypt(message.encode(), publickey)

def RSAdecrypt(message, privatekey):
    
    message =  rsa.decrypt(message, privatekey)
    
    return message.decode()






