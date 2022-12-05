from cryptography.hazmat.primitives import hashes, serialization, hmac
from cryptography.hazmat.primitives.asymmetric import rsa, dh, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidSignature
import os
import threading
import socket


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

# Get private bytes, used to save the private key to a file
def rsa_get_private_bytes(private_key):
    return private_key.private_bytes(
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
    key_string = rsa_get_public_bytes(rsa_public_key).decode('utf-8')
    return "r" + padded_username + key_string

# Get string in the following format: "r"[16 bytes username]
def get_login_message1(username):
    if len(username) > 16: raise Exception("Username must be max 16 characters")
    
    padded_username = pad_string(username)
    return "l" + padded_username

# Get string in the following format: "s"[16 bytes username][rsa signature]
def get_login_message2(username, signature):
    if len(username) > 16: raise Exception("Username must be max 16 characters")
    
    padded_username = pad_string(username)
    signature_str = signature.decode('utf-8')
    return "s" + padded_username + signature_str

# Get string in the following format: "m"[16 bytes username][16 bytes rsa signature][DH public key] 
def get_message1(username, rsa_signature, dh_public_key):
    if len(username) > 16: raise Exception("Username must be max 16 characters")
    if len(rsa_signature) != 16: raise Exception("RSA signature must be of length 16")
    
    padded_username = pad_string(username)
    rsa_signature_str = rsa_signature.decode('utf-8')
    dh_public_key_str = dh_get_public_bytes(dh_public_key).decode('utf-8')
    return "m" + padded_username + rsa_signature_str + dh_public_key_str

# Get string in the following format: "b"[16 bytes rsa signature][16 bytes iv][DH public key] 
def get_message1_response(rsa_signature, dh_public_key):
    if len(rsa_signature) != 16: raise Exception("RSA signature must be of length 16")
    
    rsa_signature_str = rsa_signature.decode('utf-8')
    dh_public_key_str = dh_get_public_bytes(dh_public_key).decode('utf-8')
    return "b" + rsa_signature_str + dh_public_key_str

# Get string in the following format: "n"[16 bytes hmac signature][16 bytes iv][Encrypted message]
def get_message2(hmac, iv, message):
    if len(hmac) != 16: raise Exception("HMAC must be of length 16")
    if len(iv) != 16: raise Exception("IV must be of length 16")
    
    hmac_str = hmac.decode('utf-8')
    iv_str = iv.decode('utf-8')
    message_str = message.decode('utf-8')
    return "n" + padded_username + hmac_str + iv_str + message_str

def parse_message(message):
    if (message[0] == "l"):
        # Login part 1 response
        nonce = message[1:]
        if rsa_priv_global == None:
            print("Error. Log in response received but no RSA key found")
            print("Please try logging in again")
            return
        if username_global == "":
            print("Error. Log in response received but no username found")
            print("Please try logging in again")
            return

        signature = rsa_sign_message(rsa_priv_global, nonce.encode('utf-8'))
        message = get_login_message2(username_global, signature)
        client_send(message)
        loggedIn = True
    
    elif (message[0] == "e"):
        # Error message from server
        print_msg = message[1:]
        print(print_msg)

    elif (message[0] == "m"):
        # Message part 1 (another client is attempting to send a message to this client)
        padded_username_m = message[1:17]
        rsa_signature_str_m = message[17:33]
        dh_public_key_str = message[33:]

    elif (message[0] == "n"):
        # Message part 2
        padded_username_n = message[1:17]
        hmac_str = message[17:33]
        iv_str = message[33:49]
        message_str = message[49:]

    elif (message[0] == "b"):
        # Message part 1 response (another client responded to this clients message request)
        rsa_signature_str_b = message[1:17]
        dh_public_key_str_b = message[17:]
        
    else:
        print("not a valid message")
    # TODO

######################
## SOCKET FUNCTIONS ##
######################

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(('172.19.0.2', 59000))

def client_receive():
    while True:
        try:
            message = client.recv(1024).decode('utf-8')
            parse_message(message)
        except:
            print('Socket error')
            print('Shutting down...')
            client.close()
            exit()


def client_send(message):
    client.sendall(message.encode('utf-8'))

##############
## COMMANDS ##
##############

loggedIn = False
rsa_priv_global = None
dh_priv_global = None
username_global = ""

def help_cmd():
    print("h (help) - Show this list of commands")
    print("r (register) - Register a new account")
    print("l (login) - Login to an existing account")
    print("m (message) - Message another user")
    print("v (view) - View message history with a user")
    print("d (delete) - Delete message history with a user")
    print("u (logout) - Logout of account")
    print("q (quit) - Exit program safetly")

def register_cmd():
    loggedIn = False
    rsa_priv_global = rsa_generate_private_key()
    rsa_pub = rsa_generate_public_key(rsa_priv_global)

    username = ""
    while True:
        username = input("Please input a username: ")
        if len(username) > 0 and len(username) < 16:
            break
        print("Username must be between 1 and 16 characters")

    print("Saving new private key file...")
    file_name = username + ".pem"
    file_contents = rsa_get_private_bytes(rsa_priv).decode('utf-8')
    with open(file_name, 'w') as file:
        file.write(file_contents)
    print("Done. Please move the file to a secure location")

    message = get_register_message(username, rsa_priv)
    client_send(message)
    loggedIn = True

def login_cmd():
    loggedIn = False
    while True:
        username_global = input("Please input your existing username: ")
        if len(username_global) > 0 and len(username_global) < 16:
            break
        print("Username must be between 1 and 16 characters")
    message = get_login_message1(username_global)
    client_send(message)

def message_cmd():
    if loggedIn == False:
        print("You must log in first to send a messge")
        return
    if rsa_priv_global == None:
        print("Error. Logged in but no RSA key found")
        print("Please try logging in again")
        loggedIn = False
        return
    
    while True:
        msg_username = input("Who do you want to message, input his/her username: ")
        if len(msg_username) > 0 and len(msg_username) < 16:
            break
        print("Username must be between 1 and 16 characters")
    
    dh_priv_global = dh_generate_private_key()
    dh_pub = dh_generate_public_key(dh_priv_global)
    rsa_signature = rsa_sign_message(rsa_priv_global, dh_get_public_bytes(dh_pub))
    message = get_message1(msg_username, rsa_signature, dh_pub)
    client_send(message)


def view_cmd():
    # TODO
    return

def delete_cmd():
    # TODO
    return

def logout_cmd():
    client_send("u")
    loggedIn = False

def quit_cmd():
    client_send("q")
    exit()



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

def main():
    # Start a thread to accept any messages
    thread = threading.Thread(target=client_receive)
    thread.start()
    print("Welcome to encrypted messenger")
    print("Input h to see a list of available commands")
    while(True):
        cmd = input("> ")
        if (cmd == "h" or cmd == "help"):
            help_cmd()
        if (cmd == "r" or cmd == "register"):
            register_cmd()
        if (cmd == "l" or cmd == "login"):
            login_cmd()
        if (cmd == "m" or cmd == "message"):
            message_cmd()
        if (cmd == "v" or cmd == "view"):
            view_cmd()
        if (cmd == "d" or cmd == "delete"):
            delete_cmd()
        if (cmd == "u" or cmd == "logout"):
            logout_cmd()
        if (cmd == "q" or cmd == "quit"):
            quit_cmd()

if __name__ == "__main__":
    main()
