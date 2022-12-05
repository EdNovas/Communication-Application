import os
import csv


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
