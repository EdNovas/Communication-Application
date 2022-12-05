
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
aliases = []


def broadcast(message):
    for client in clients:
        if message == 'leave':
            break
        else:
            client.sendall(message)



def handle_client(client):
    while True:
        try:
            message = client.recv(1024)
            broadcast(message)
            if message == 'leave':
                index = clients.index(client)
                clients.remove(client)
                client.close()
                alias = aliases[index]
                broadcast(f'{alias} has left the chat room!'.encode('utf-8'))
                aliases.remove(alias)
                break
        except:
            index = clients.index(client)
            clients.remove(client)
            client.close()
            alias = aliases[index]
            broadcast(f'{alias} has left the chat room!'.encode('utf-8'))
            aliases.remove(alias)
            break


def main():
    while True:
        client, address = server.accept()
        conn_msg = 'connection is established with' + str(address)
        print(conn_msg)

        client.sendall('alias?'.encode('utf-8'))
        alias = client.recv(1024)
        aliases.append(alias)
        clients.append(client)

        alias_msg = 'The alias of this client is' + str(alias)
        print(alias_msg)
        
        broadcast_msg = str(alias) + 'has connected to the server'
        broadcast(broadcast_msg.encode('utf-8'))
        
        client.sendall('you are now connected!'.encode('utf-8'))
        thread = threading.Thread(target=handle_client, args=(client,))
        thread.start()


if __name__ == "__main__":
    main()
