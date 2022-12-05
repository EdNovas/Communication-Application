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



# Import a private key that was read from a PEM file
def import_private_key(private_key_pem):
    return serialization.load_pem_private_key(private_key_pem, password=None)

# Import a public key that was read from a PEM file
def import_public_key(public_key_pem):
    return serialization.load_pem_public_key(private_key_pem, password=None)

################################
## RSA CRYPTOGRAPHY FUNCTIONS ##
################################

# Generate a private key, used to register
def rsa_generate_private_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

# Generate a public key from private key
def rsa_generate_public_key(private_key):
    return private_key.public_key()

# Get private bytes, used to save the private key to a file
def rsa_get_private_bytes(private_key):
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
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

###############################
## MESSAGE PARSING FUNCTIONS ##
###############################

# Pad a string with spaces until it has 16 charcters
def pad_string(message):
    while len(message) % 16 != 0:
        message += ' '
    return message

def parse_message(message):
    global rsa_priv_global
    global dh_priv_global
    global username_global
    global loggedIn
    global shared_key_global
    global msg_input_global

    code = message[0].decode('utf-8')
    if (code == "l"):
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

        signature = rsa_sign_message(rsa_priv_global, nonce)
        username_bytes = pad_string(username_global).encode('utf-8')

        # Get a byte array in the following format: b"s"[16 bytes username][rsa signature]
        message = b"s" + username_bytes + signature

        client_send(message)
        loggedIn = True
    
    elif (code == "e"):
        # Error message from server
        print_msg = message[1:].decode('utf-8')
        print(print_msg)

    elif (code == "m"):
        # Message part 1 (another client is attempting to send a message to this client)
        # Note: This message is changed by the server and is different than the one that was sent by the other client
        if loggedIn == False:
            print("Error. Message request received but not logged in")
            print("Please try logging in again")
            return
        if rsa_priv_global == None:
            print("Error. Message request received but no RSA key found")
            print("Please try logging in again")
            return

        padded_username = message[1:17].decode('utf-8')
        sender_rsa_signature = message[17:273]
        dh_public_key_len = int.from_bytes(message[273:275], 'little', signed=False)
        sender_dh_public_key_pem = message[275:275+dh_public_key_len].decode('utf-8')
        sender_rsa_pub_pem = message[275+dh_public_key_len:].decode('utf-8')

        sender_rsa_pub = import_public_key(sender_rsa_pub_pem)
        if rsa_validate_signature(sender_rsa_pub, sender_dh_public_key_pem, sender_rsa_signature) == False:
            print("Invalid RSA signature in received message")
            return
        
        # Create DH keys and sign DH public key
        dh_priv = dh_generate_private_key()
        dh_pub = dh_generate_public_key(dh_priv_global)
        peer_dh_public_key = import_public_key(sender_dh_public_key_pem)
        shared_key_global = dh_generate_shared_key(dh_priv, peer_dh_public_key)
        rsa_signature = rsa_sign_message(rsa_priv_global, dh_get_public_bytes(dh_pub))

        username_bytes = pad_string(username).encode('utf-8')
        dh_public_key_bytes = dh_get_public_bytes(dh_pub)

        # Get bytes array in the following format: b"b"[16 bytes username][256 bytes rsa signature][DH public key] 
        message = b"b" + username_bytes + rsa_signature + dh_public_key_bytes
        client_send(message)

    elif (code == "b"):
        # Message part 1 response (another client responded to this clients message request)
        # Note: This message is changed by the server and is different than the one that was sent by the other client
        if loggedIn == False:
            print("Error. Message response received but not logged in")
            print("Please try logging in again")
            return
        if len(msg_input_global) < 1:
            print("Error. Message reponse received but no stored message was found")
            return
        
        # Parse message
        padded_username = message[1:17].decode('utf-8')
        sender_rsa_signature = message[17:273]
        dh_public_key_len = int.from_bytes(message[273:275], 'little', signed=False)
        sender_dh_public_key_pem = message[275:275+dh_public_key_len].decode('utf-8')
        sender_rsa_pub_pem = message[275+dh_public_key_len:].decode('utf-8')

        sender_rsa_pub = import_public_key(sender_rsa_pub_pem)
        if rsa_validate_signature(sender_rsa_pub, sender_dh_public_key_pem, sender_rsa_signature) == False:
            print("Invalid RSA signature in received message response")
            return
        
        # Generate shared key
        peer_dh_public_key = import_public_key(sender_dh_public_key_pem)
        shared_key = dh_generate_shared_key(dh_priv_global, peer_dh_public_key)

        # Encrypt message and get HMAC
        iv = generate_iv()
        msg_enc = aes_cbc_encrypt_message(shared_key, msg_input_global, iv)
        hmac_key = get_sha256_hash(shared_key)
        hmac_sig = hmac_generate_signature(hmac_key, msg_enc)
    
        username_bytes = pad_string(username).encode('utf-8')

        # Get string in the following format: "n"[16 bytes username][16 bytes hmac signature][16 bytes iv][Encrypted message]   
        message = b"n" + username_bytes + hmac + iv + msg_enc
        client_send(message)

    elif (code == "n"):
        # Message part 2

        padded_username_n = message[1:17].decode('utf-8')
        hmac_sig = message[17:33]
        iv = message[33:49]
        msg_enc = message[49:]

        hmac_key = get_sha256_hash(shared_key_global)
        if hmac_verify_signature(hmac_key, hmac_sig, msg_enc) == False:
            print("Invalid HMAC in final received message")
            return

        msg_dec = aes_cbc_decrypt_message(shared_key_global, msg_enc, iv)

        print(msg_dec.decode('utf-8'))
        # TODO Store the message in encrypted form
        
    # else:
        # Invalid message recieved, it will be ignored
    

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
shared_key_global = None
username_global = ""
msg_input_global = ""

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
    global rsa_priv_global
    global loggedIn

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
    file_contents = rsa_get_private_bytes(rsa_priv_global).decode('utf-8')
    with open(file_name, 'w') as file:
        file.write(file_contents)
    print("Done. Please move the file to a secure location")

    username_bytes = pad_string(username).encode('utf-8')
    key_bytes = rsa_get_public_bytes(rsa_pub)

    # Get bytes array in the following format: b"r"[16 bytes username][rsa public key in PEM format]
    message = b"r" + username_bytes + key_bytes
    client_send(message)
    loggedIn = True

def login_cmd():
    global username_global
    global loggedIn

    loggedIn = False
    while True:
        username_global = input("Please input your existing username: ")
        if len(username_global) > 0 and len(username_global) < 16:
            break
        print("Username must be between 1 and 16 characters")
    
    username_bytes = pad_string(username_global).encode('utf-8')
    
    # Get string in the following format: "r"[16 bytes username]
    message = b"l" + username_bytes
    client_send(message)

def message_cmd():
    global loggedIn
    global rsa_priv_global
    global msg_input_global
    global dh_priv_global
    global rsa_priv_global

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
    
    msg_input_global = ""
    while True:
        msg_input_global = input("Please input a message to send: ")
        if len(msg_input_global) > 0:
            break
        print("You must send at least one character")
    
    dh_priv_global = dh_generate_private_key()
    dh_pub = dh_generate_public_key(dh_priv_global)
    rsa_signature = rsa_sign_message(rsa_priv_global, dh_get_public_bytes(dh_pub))

    username_bytes = pad_string(msg_sername).encode('utf-8')
    dh_public_key_bytes = dh_get_public_bytes(dh_pub)

    # Get byte array in the following format: b"m"[16 bytes username][256 bytes rsa signature][DH public key] 
    message = b"m" + username_bytes + rsa_signature + dh_public_key_bytes
    client_send(message)


def view_cmd():
    # TODO
    return

def delete_cmd():
    # TODO
    return

def logout_cmd():
    global loggedIn

    client_send("u")
    loggedIn = False

def quit_cmd():
    client_send("q")
    exit()


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
