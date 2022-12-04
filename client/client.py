from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

print("Hello from client")

# References:

# Cryotography docs
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/

# Robert Heaton: Off-The-Record Messaging part 3
# https://robertheaton.com/otr3
# A high level overview of the Off-The-Record Messaging Protocol

# Generate a private key. Must be generated before each usage
def generate_private_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
def generate_public_key(private_key):
    return private_key.public_key()
    
def sign_message(private_key, message):
    return private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def validate_signature(peer_public_key, message, signature):
    try:
        # verify() will throw InvalidSignature exception if the signature is not valid
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except:
        return False
    
    

# Generate a shared key based on private key and the recieved public key
def generate_shared_key(private_key, peer_public_key):
    shared_key = private_key.exchange(peer_public_key)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=2048,
        salt=None,
        info=None,
    ).derive(shared_key)

def encrypt_message(shared_key, message):
    return shared_key.public_key().encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def decrypt_message(shared_key, message):
    return shared_key.decrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
# Steps:
# 1. tmp_private_key = generate_private_key()
# 2. tmp_public_key = generate_public_key(tmp_private_key)
# 3. signature = sign_message(private_key, tmp_public_key) << USES account private key
# 4. send(tmp_public_key) and send(signature)

# Once the peer has recieved the public_key and signature they will repeat steps 1-4

# 5. Recieve peer_public_key and signature
# 6. validate_signature(peer_public_key, signature)

# If signature is invalid then cancel the communication

# 7. generate_shared_key(private_key, peer_public_key)
