import hashlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization


# load publiv key
with open('keys/public_key.pem', 'rb') as f:
    public_key = serialization.load_pem_public_key(
        f.read()
    )

# load PI and OI from the messages file
with open('data/messages.txt', 'r') as f:
    lines = f.readlines()

# load signature
with open('signature.bin', 'rb') as f:
    signature = f.read()


#------------------------ MERCHANT -----------------------------
# show that merchant can verify the signature using only OI and the combined hash. (followed the diagram from geeks for geeks)
# get merchant data
with open('data/merchant_data.txt', 'r') as f:
    lines = f.readlines()

OI = lines[0].strip().split('=', 1)[1]

PIMD = bytes.fromhex(
    lines[1].strip().split('=', 1)[1]
)


# merchant hashes OI
OIMD = hashlib.sha256(
    OI.encode()
).digest()


# merchant reconsruct combined hash (POMD)
POMD = hashlib.sha256(
    PIMD + OIMD
).digest()


# merchant verifies signature
try: 
    public_key.verify(
        signature,
        POMD,
        padding.PSS(
            mgf = padding.MGF1(hashes.SHA256()),
            salt_length = padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # if success
    print('Merchant verification: Success')

# if not
except Exception:
    print('Merchant verification: Failed')



#------------------------ BANK -----------------------------
# show that the bank can verify the signature using only PI and the combined hash. (followed the diagram from geeks for geeks)
# get bank data
with open('data/bank_data.txt', 'r') as f:
    lines = f.readlines()


PI = lines[0].strip().split('=', 1)[1]

OMID = bytes.fromhex(
    lines[1].strip().split('=', 1)[1]
)


# bank hashes PI
PIMD = hashlib.sha256(
    PI.encode()
).digest()


# bank reconsruct combined hash (POMD)
POMD = hashlib.sha256(
    PIMD + OIMD
).digest()


# bank verifies signature
try: 
    public_key.verify(
        signature,
        POMD,
        padding.PSS(
            mgf = padding.MGF1(hashes.SHA256()),
            salt_length = padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # if success
    print('Bank verification: Success')

# if not
except Exception:
    print('Bank verification: Failed')