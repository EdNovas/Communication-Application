from cryptography.hazmat.primitives import hashes, serialization, hmac
from cryptography.hazmat.primitives.asymmetric import rsa, dh, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidSignature
import os
import threading
import Socket


# References:

# Cryotography docs
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/dh/
# https://cryptography.io/en/latest/hazmat/primitives/mac/hmac/

# Robert Heaton: Off-The-Record Messaging part 3
# https://robertheaton.com/otr3
# A high level overview of the Off-The-Record Messaging Protocol

# Bek Brace: TCP-Chat-Room-Python
# https://github.com/BekBrace/TCP-Chat-Room-Python-



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
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

# Get public bytes, used to send the public key in a message
def rsa_get_public_bytes(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
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

# This function pads a message (bytes) until its size is a multiple of 16
def pad_message(message):
    while len(message) % 16 != 0:
        message += b' '
    return message

#################################
## HMAC CRYPTOGRAPHY FUNCTIONS ##
#################################

# This function gets a SHA256 hash, which is used as the key for HMAC key
def get_sha256_hash(input):
    return hases.SHA256.update(input).finalize()

def hmac_generate_signature(key, message):
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    return h.finalize()

def hmac_verify_signature(key, signature, message):
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    try:
        h.verify(signature)
        return True
    except InvalidSignature:
        return False


##################################
## MESSAGE FORMATTING FUNCTIONS ##
##################################

# Pad a string with spaces until it has 16 charcters
def pad_string(message):
    while len(message) % 16 != 0:
        message += ' '
    return message

# Get string in the following format: "r"[16 bytes username][rsa public key in PEM format]
def get_register_message(username, rsa_public_key):
    if len(username) > 16: raise Exception("Username must be max 16 characters")

    padded_username = pad_string(username)
    key_string = str(rsa_get_public_bytes(rsa_public_key))
    return "r" + "#" + padded_username + "#" + key_string

# Get string in the following format: "r"[16 bytes username]
def get_login_message1(username):
    if len(username) > 16: raise Exception("Username must be max 16 characters")
    
    padded_username = pad_string(username)
    return "l" + "#" + padded_username

# Get string in the following format: "s"[16 bytes username][rsa signature]
def get_login_message2(username, signature):
    if len(username) > 16: raise Exception("Username must be max 16 characters")
    
    padded_username = pad_string(username)
    signature_str = str(signature)
    return "s" + "#" + padded_username + "#" + signature_str

# Get string in the following format: "m"[16 bytes username][16 bytes rsa signature][DH public key] 
def get_message1(username, rsa_signature, dh_public_key):
    if len(username) > 16: raise Exception("Username must be max 16 characters")
    if len(rsa_signature) != 16: raise Exception("RSA signature must be of length 16")
    
    padded_username = pad_string(username)
    rsa_signature_str = str(rsa_signature)
    dh_public_key_str = str(dh_get_public_bytes(dh_public_key))
    return "m" + "#" + padded_username + "#" + rsa_signature_str + "#" + dh_public_key_str

# Get string in the following format: "b"[16 bytes rsa signature][16 bytes iv][DH public key] 
def get_message1_response(rsa_signature, dh_public_key):
    if len(rsa_signature) != 16: raise Exception("RSA signature must be of length 16")
    
    rsa_signature_str = str(rsa_signature)
    dh_public_key_str = str(dh_get_public_bytes(dh_public_key))
    return "b" + "#" + rsa_signature_str + "#" + dh_public_key_str

# Get string in the following format: "n"[16 bytes hmac signature][16 bytes iv][Encrypted message]
def get_message2(hmac, iv, message):
    if len(hmac) != 16: raise Exception("HMAC must be of length 16")
    if len(iv) != 16: raise Exception("IV must be of length 16")
    
    hmac_str = str(hmac)
    iv_str = str(iv)
    message_str = str(message)
    return "n" + "#" + padded_username + "#" + hmac_str + "#" + dh_public_key_str + "#" + message_str

def parse_message(message):
    command = message.split("#", 1)
    if (command[0] == "r"):
        message1 = command[1]
        data1 = message1.split("#", 1)
        padded_username_r = data1[0]
        key_string = data1[1]
    elif (command[0] == "l"):
        padded_username_l == command[1]
    elif (command[0] == "s"):
        message2 = command[1]
        data2 = message2.split("#", 1)
        padded_username_s = data2[0]
        signature_str = data2[1]
    elif (command[0] == "m"):
        message3 = command[1]
        data3 = message3.split("#", 2)
        padded_username_m = data3[0]
        rsa_signature_str_m = data3[1]
        dh_public_key_str = data3[2]
    elif (command[0] == "b"):
        message4 = command[1]
        data4 = message4.split("#", 1)
        rsa_signature_str_b = data4[0]
        dh_public_key_str_b = data4[1]
    elif (command[0] == "n"):
        message5 = command[1]
        data5 = message5.split("#", 3)
        padded_username_n = data5[0]
        hmac_str = data5[1]
        dh_public_key_str = data5[2]
        message_str = data5[3]
    else:
        print("not a valid message")
    # TODO

######################
## SOCKET FUNCTIONS ##
######################

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(('172.18.0.4', 59000))

def client_receive():
    while True:
        try:
            message = client.recv(1024).decode('utf-8')
            print(message)
            # TODO figure out what to do with the message
            if message == 'leave':
                break
        except:
            print('Error!')
            client.close()
            break


def client_send(message):
    client.sendall(message.encode('utf-8'))

##############
## COMMANDS ##
##############

def help_cmd():
    print("h (help) - Show this list of commands")
    print("r (register) - Register a new account")
    print("l (login) - Login to an existing account")
    print("m (message) - Message another user")
    print("v (view) - View message history with a user")
    print("d (delete) - Delete message history with a user")

def register_cmd():
    rsa_priv = rsa_generate_private_key()
    rsa_pub = rsa_generate_public_key(rsa_priv)

    print("Saving new private key file...")
    # TODO save rsa_priv to file

    username = ""
    while True:
        username = input("Please input a username: ")
        if len(username) > 0 and len(username) < 16:
            break
        print("Username must be between 1 and 16 characters")
    message = get_register_message(username, rsa_priv)
    client_send(message)

def login_cmd():
    # TODO

def message_cmd():
    # TODO

def view_cmd():
    # TODO

def delete_cmd():
    # TODO


# The code below shows how will we can use these functions for Diffie-Hellman and message encryption and decryption
"""
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
hmac_key1 = get_sha256_hash(share1)
hmac_sig = hmac_generate_signature(hmac_key1, msg_enc)

# msg_enc, iv and hmac_sig are sent to other client

hmac_key2 = get_sha256_hash(share2)
print("HMAC validation: " + str(hmac_verify_signature(hmac_key2, hmac_sig, msg_enc)))
msg_dec = aes_cbc_decrypt_message(share2, msg_enc, iv)

# Once client 2 has validated the HMAC they will send a success message to client 1 
# Since client 1 sent the message they must now release HMAC key for plausible denyability

# hmac_key1 sent to server to publisize


receive_thread = threading.Thread(target=client_receive)
receive_thread.start()

send_thread = threading.Thread(target=client_send)
send_thread.start()
print(msg_dec)
"""

##########
## MAIN ##
##########

if __name__ == "__main__":
    main()

def main():
    print("Welcome to encrypted messenger")
    print("Input h to see a list of available commands")
    while(True):
        cmd = input("> ")
        if (cmd == "h" or cmd == "help"):
            help_cmd()
        if (cmd == "r" or cmd == "register")
            register_cmd()
        if (cmd == "l" or cmd == "login"):
            help_cmd()
        if (cmd == "m" or cmd == "message")
            register_cmd()
        if (cmd == "v" or cmd == "view"):
            help_cmd()
        if (cmd == "d" or cmd == "delete")
            register_cmd()
