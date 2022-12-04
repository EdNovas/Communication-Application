from cryptography.hazmat.primitives import hashes, serialization, hmac
from cryptography.hazmat.primitives.asymmetric import rsa, dh, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidSignature
import os

print("Hello from client")

# References:

# Cryotography docs
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/dh/
# https://cryptography.io/en/latest/hazmat/primitives/mac/hmac/

# Robert Heaton: Off-The-Record Messaging part 3
# https://robertheaton.com/otr3
# A high level overview of the Off-The-Record Messaging Protocol

################################
## RSA CRYPTOGRAPHY FUNCTIONS ##
################################

# Generate a private key, used to register
def rsa_generate_private_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

# Generate a public key, passed to server when registering
def rsa_generate_public_key(private_key):
    return private_key.public_key()
    
def rsa_sign_message(private_key, message):
    return private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def rsa_validate_signature(public_key, message, signature):
    try:
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
    except InvalidSignature:
        return False
    
    
###########################################
## DIFFIE-HELLMAN CRYPTOGRAPHY FUNCTIONS ##
###########################################

parameters = dh.generate_parameters(generator=2, key_size=2048)

# Generate a private key for a single message
def dh_generate_private_key():
    return parameters.generate_private_key()

# Get public key from a private key
def dh_generate_public_key(private_key):
    return private_key.public_key()

# Get a byte array from a public key so that it can be signed
def dh_get_public_bytes(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

# Generate a shared key based on private key and the recieved public key
def dh_generate_shared_key(private_key, peer_public_key):
    shared_key = private_key.exchange(peer_public_key)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=16, #256 bits for AES 
        salt=None,
        info=None,
    ).derive(shared_key)

################################
## AES CRYPTOGRAPHY FUNCTIONS ##
################################

# Generate a 128 bit initialization vector
def generate_iv():
    return os.urandom(16)

# Encrypt a message with the shared key bytes
def aes_cbc_encrypt_message(shared_key, message, iv):
    encryptor = Cipher(algorithms.AES(shared_key), modes.CBC(iv)).encryptor()
    return encryptor.update(message) + encryptor.finalize()

# Decrypt a message with the shared key bytes
def aes_cbc_decrypt_message(shared_key, message, iv):
    decryptor = Cipher(algorithms.AES(shared_key), modes.CBC(iv)).decryptor()
    return decryptor.update(message) + decryptor.finalize()

# This funstion pads a message until its size is a multiple of 16
def pad_message(message):
    while len(message) % 16 != 0:
        message += b' '
    return message

#################################
## HMAC CRYPTOGRAPHY FUNCTIONS ##
#################################

def hmac_generate_signature(private_key, message):
    h = hmac.HMAC(private_key, hashes.SHA256())
    h.update(message)
    return h.finalize()

def hmac_verify_signature(private_key, signature, message):
    h = hmac.HMAC(private_key, hashes.SHA256())
    h.update(message)
    try:
        h.verify(signature)
        return True
    except InvalidSignature:
        return False



# The code below shows how will we can use these functions for Diffie-Hellman and message encryption and decryption

rsa_priv1 = rsa_generate_private_key()
rsa_pub1 = rsa_generate_public_key(rsa_priv1)
dh_priv1 = dh_generate_private_key()
dh_pub1 = dh_generate_public_key(dh_priv1)
signature1 = rsa_sign_message(rsa_priv1, dh_get_public_bytes(dh_pub1))

rsa_priv2 = rsa_generate_private_key()
rsa_pub2 = rsa_generate_public_key(rsa_priv2)
dh_priv2 = dh_generate_private_key()
dh_pub2 = dh_generate_public_key(dh_priv2)
signature2 = rsa_sign_message(rsa_priv2, dh_get_public_bytes(dh_pub2))

# Signature and dh_pub are sent to other client (rsa_pub should already be know to other client from server)

print("Client 1 validation: " + str(rsa_validate_signature(rsa_pub2, dh_get_public_bytes(dh_pub2), signature2)))
print("Client 2 validation: " + str(rsa_validate_signature(rsa_pub1, dh_get_public_bytes(dh_pub1), signature1)))

share1 = dh_generate_shared_key(dh_priv1, dh_pub2)
share2 = dh_generate_shared_key(dh_priv2, dh_pub1)

msg = pad_message(b"Test message 1")
iv = generate_iv()

msg_enc = aes_cbc_encrypt_message(share1, msg, iv)
hmac_sig = hmac_generate_signature(share1, msg_enc)

# msg_enc, iv and hmac_sig are sent to other client

print("HMAC validation: " + str(hmac_verify_signature(share2, hmac_sig, msg_enc)))
msg_dec = aes_cbc_decrypt_message(share2, msg_enc, iv)

print(msg_dec)
