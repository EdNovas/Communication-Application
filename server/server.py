import os
import csv
import threading
import socket

host = '172.18.0.4'
port = 59000
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((host, port))
print('Socket binded.')
server.listen()
print('Server is running and listening ...')
clients = []
usernames = []
isLoggedIn = []



def handle_client(client):
    while True:
        try:
            message = client.recv(1024)
            parse_message(message)
            if message == "q":
                remove_client(client)
                break
        except:
            remove_client(client)
            break

def remove_client():
    index = clients.index(client)
    clients.remove(client)
    client.close()
    username = usernames[index]
    usernames.remove(alias)



def main():
    while True:
        client, address = server.accept()
        conn_msg = 'Connection is established with' + str(address)
        print(conn_msg)

        usernames.append("")
        clients.append(client)
        isLoggedIn.append(False)
        
        thread = threading.Thread(target=handle_client, args=(client,))
        thread.start()


if __name__ == "__main__":
    main()


def parse_message():
    # TODO copy from client.py and make required modifications


# print("Hello from server")

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


        

# Generate a 128 bit initialization vector  
def generate_iv():
    return os.urandom(16)
