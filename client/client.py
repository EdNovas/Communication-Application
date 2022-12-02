# print("Hello from client")
import sys
import getpass

print("Hello, welcome to our communication application. ")

account_status = input("Do you have an account already?(y/n): ")

if (account_status == 'n' or account_status == 'N'):
    new_account = input("Please register your account name: ")
    new_password = getpass.getpass("Password: ")
    # store the account and password into server database
elif (account_status == 'y' or account_status == 'Y'):
    account = input("Your account name: ")
    password = getpass.getpass("Your Password: ")
    # deliver the account and password info to the server end, and verify the account and password
else:
    print("Sorry, that's not a valid answer. You should use y or n")
    exit(1)
