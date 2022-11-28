from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

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
        length=32,
        salt=None,
        info=b'handshake data',
    ).derive(shared_key)
    
# Steps:
# 1. generate_private_key()
# 2. generate_public_key(private_key)
# 3. sign_message(private_key, public_key)
# 4. send(public_key) and send(signature)
# 5. Recieve peer_public_key and signature
# 6. validate_signature(peer_public_key, signature)
