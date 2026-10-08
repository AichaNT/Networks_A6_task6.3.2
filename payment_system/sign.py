import hashlib
import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization


# creating the dual signature

# load PI and OI from the messages file
with open('data/messages.txt', 'r') as f:
    lines = f.readlines()

PI = lines[0].strip().split('=', 1)[1]
OI = lines[1].strip().split('=', 1)[1]


# load customer private key
with open('keys/private_key.pem', 'rb') as f:
    private_key = serialization.load_pem_private_key(
        f.read(),
        password = b'123'
    )


# hashing PI and OI (first step in the diagram) to get PIMD and OIMD 
# using sha256
PIMD = hashlib.sha256(
    PI.encode()
).digest()


OIMD = hashlib.sha256(
    OI.encode()
).digest()



# concatenate PIMD and OIMD (step 2 in diagram) to get POMD
POMD = hashlib.sha256(
    PIMD + OIMD
).digest()




# sign using private key
signature = private_key.sign( # params taken from (source)
    POMD,
    padding.PSS(
        mgf = padding.MGF1(hashes.SHA256()),
        salt_length = padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
        


# save signatue
with open('signature.bin', 'wb') as f:
    f.write(signature)



# saving data for use during verification
# save merchant data
with open('data/merchant_data.txt', 'w') as f:
    f.write(f"OI={OI}\n")
    f.write(f"PIMD={PIMD.hex()}\n")

# save bank data
with open('data/bank_data.txt', 'w') as f:
    f.write(f"PI={PI}\n")
    f.write(f"OIMD={OIMD.hex()}\n")



# display
print("PI:")
print(PI)

print("\nOI:")
print(OI)

print("\nPIMD:")
print(PIMD.hex())

print("\nOIMD:")
print(OIMD.hex())

print("\nPOMD:")
print(POMD.hex())

print("\nDual signature:")
print(base64.b64encode(signature).decode())