from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

import os

# sources
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/

# generate RSA private key (KPc: Customer’s private key)
private_key = rsa.generate_private_key(
    public_exponent = 65537, # (source) The public_exponent indicates what one mathematical property of the key generation will be. Unless you have a specific reason to do otherwise, you should always use 65537
    key_size = 2048 # Larger keys provide more security; currently 1024 and below are considered breakable while 2048 or 4096 are reasonable default key sizes for new keys. 
)


# get public key from private key
public_key = private_key.public_key()


# save keys
# folder for keys
os.makedirs('keys', exist_ok=True)

# private key
with open('keys/private_key.pem', 'wb') as f: # PEM format for storing keys
    f.write(
        private_key.private_bytes(
            encoding = serialization.Encoding.PEM,
            format = serialization.PrivateFormat.PKCS8, # standard format for storing private keys
            encryption_algorithm = serialization.BestAvailableEncryption(b'123') # encryption with simple passowrd (irl should use strong password and proper key management)
        )
    )

# public key
with open('keys/public_key.pem', 'wb') as f:
    f.write(
        public_key.public_bytes(
            encoding = serialization.Encoding.PEM,
            format = serialization.PublicFormat.SubjectPublicKeyInfo # standard format for storing public keys
        )
    )



print('RSA have been generated')