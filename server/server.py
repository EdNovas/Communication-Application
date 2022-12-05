from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
import os
import csv
import threading
import socket

host = '0.0.0.0'
port = 59000
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((host, port))
print('Socket binded.')
server.listen()
print('Server is running and listening ...')
clients = []
clientInfo = [] # clientInfo is a tuple of format (username, isLoggedIn, nonce, returnAddress)



def handle_client(client):
    while True:
        try:
            message = client.recv(1024)
            if message == "q":
                remove_client(client)
                break
            elif message == "u":
                index = clients.index(client) 
                clientInfo[index] = (None, False, None, None)
                continue
            parse_message(client, message)
        except:
            remove_client(client)
            break

def remove_client():
    index = clients.index(client)
    clients.remove(client)
    client.close()
    clientInfo.pop(index)


def parse_message(client, message):
    index = clients.index(client)

    if (message[0] == "r"):
        # Register
        padded_username = message[1:17]
        key_string = message[17:]

        if register_account(padded_username, key_string) == False:
            client.sendall("eUsername is taken")
            return
        clientInfo[index][0] = padded_username
        clientInfo[index][1] = True

    elif (message[0] == "l"):
        # Login part 1
        padded_username = message[1:]
        public_key = read_account(padded_username)
        if public_key == None:
            client.sendall("eUsername not found")
            return
        
        nonce = os.urandom(16).decode('utf-8')
        client.sendall("l" + nonce)
        clientInfo[index][2] = nonce

    elif (message[0] == "s"):
        # Login part 2
        padded_username = message[1:17]
        signature_str = message[17:]

        nonce = clientInfo[index][2]
        if nonce == None:
            client.sendall("eMust send login part 1 first")
            return

        public_key_str = read_account(padded_username)
        if (public_key_str == None):
            client.sendall("eUsername not found")
            return
        
        public_key = serialization.load_pem_public_key(public_key_str.encode('utf-8'))
        signature = signature_str.encode('utf-8')

        if rsa_validate_signature(public_key, nonce, signature) == False:
            client.sendall("eInvalid signature")
            return

        clientInfo[index][0] = padded_username
        clientInfo[index][1] = True

    elif (message[0] == "m"):
        # Message part 1
        if clientInfo[index][1] == False:
            client.sendall("eYou must be logged in to send a message")
            return

        padded_username = message[1:17]

        receiver_index = [idx for idx, tup in enumerate(clientInfo) if tup[0] == padded_username]
        if len(receiver_index) < 1:
            client.sendall("eUser does not exist, or is not logged in")
            return
        
        clients[receiver_index[0]].sendall(message)
        clientInfo[receiver_index[0]][3] = clientInfo[index][0]

    elif (message[0] == "b"):
        # Message part 1 response
        original_sender = clientInfo[index][3]
        receiver_index = [idx for idx, tup in enumerate(clientInfo) if tup[0] == original_sender]
        if len(receiver_index) < 1:
            # No error message since this user did not initiate the request
            return
        
        clients[receiver_index[0]].sendall(message)

    elif (message[0] == "n"):
        # Message part 2
        padded_username = message[1:17]
        
        receiver_index = [idx for idx, tup in enumerate(clientInfo) if tup[0] == padded_username]
        if len(receiver_index) < 1:
            client.sendall("eUser does not exist, or is not logged in")
            return
            
        clients[receiver_index[0]].sendall(message)

# csv file name to store the accounts
account_list = "accounts.csv"

# initialize the CSV file with two columns: username and public_key
def initialize_csv():
    with open(account_list, 'w', encoding='UTF8', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["username", "public_key"])
    # print("Initialize the csv file successfully")

# load the new account into that csv file
# if the username already exists, return False, else, return True
def register_account(username, public_key):
    with open(account_list) as f:
        csv_reader = csv.reader(f)
        for row in csv_reader:
            if (row[0] == username):
                return False
    with open(account_list, 'a', encoding='UTF8', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([username,public_key])
    # print("Write " + username + " into the csv file successfully")
    return True

# return the public_key for that specific username
def read_account(username):
    with open(account_list) as f:
        csv_reader = csv.reader(f)
        for row in csv_reader:
            if (row[0] == username):
                return row[1]
        return None

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



def main():
    initialize_csv()
    while True:
        client, address = server.accept()
        conn_msg = 'Connection is established with' + str(address)
        print(conn_msg)

        clients.append(client)
        clientInfo.append((None, False, None, None))
        
        thread = threading.Thread(target=handle_client, args=(client,))
        thread.start()

if __name__ == "__main__":
    main()
