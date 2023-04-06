import socket, select, colorama, time, os, random, pickle, rsa, specialcommands, sys, threading
from scapy.all import *
from scapy.layers.inet import IP
from scapy.all import conf
from scapy.utils import hexdump
from scapy.all import get_if_list

conf.sniff_promisc = 0

from datetime import datetime
from cryptography.fernet import Fernet
import encryption

# * CONSTANTS
# Header length is used by the socket to receive correct amount of data
HEADER_LENGTH = 10
SERVERIP = "127.0.0.1"
PORT = 1234
ADMINPASS = 'opensesame'


def listen_for_discoveries(sock):
    """
    Listens for attempts to find the server
    """
    def packet_callback(packet):
        if packet.haslayer(Raw):
            if b"hello world" in packet[Raw].load:
                print("Found someone trying to connect...")
                sock.sendto(f'{SERVERIP}:{PORT}'.encode(), (packet[IP].src, packet[IP].sport))

        
    while True:
        sniff(count = 1, filter = "udp and dst 255.255.255.255", prn=packet_callback)
 
 
def exchange_keys(client_socket):
    """
    Receives the client's RSA public key
    
    Uses it to encrypt and send the AES symmetric key
    """
    
    # Currently only key. Becomes a cipher in exchange key
    symkey = encryption.AESgenerate_key()
    
    received_public = client_socket.recv(HEADER_LENGTH)
    
    if not len(received_public):
        return False
    
    received_length = int(received_public.decode('utf-8').strip())
    
    received_public = pickle.loads(client_socket.recv(received_length))
    
    
    symkey_sent = encryption.RSAencrypt(symkey, received_public)
    symkey_sent_header = f"{len(symkey_sent):<{HEADER_LENGTH}}".encode('utf-8')
    client_socket.send(symkey_sent_header + symkey_sent)
    
    symkey = Fernet(symkey)
    
    # A bit silly to send password when you accept every connection but why not
    encrypted_pass = symkey.encrypt(ADMINPASS.encode())
    encrypted_pass_header = f"{len(encrypted_pass):<{HEADER_LENGTH}}".encode('utf-8')
    client_socket.send(encrypted_pass_header + encrypted_pass)
    
    return symkey


def receive_message(client_socket):
    """
    Receives message header and data
    
    Not really used too much though, most of the time done manually
    """
    try:

        # Receive message expected length
        message_header = client_socket.recv(HEADER_LENGTH)
        

        # If we received no data, client gracefully closed a connection, for example using socket.close() or socket.shutdown(socket.SHUT_RDWR)
        if not len(message_header):
            return False

        # Convert header to int value
        message_length = int(message_header.decode())
        

        # Return an object of message header and message data
        return {'header': message_header, 'data': client_socket.recv(message_length)}

    # Ungraceful disconnection
    except Exception as e:
        print(e)
        return False


def initialize_socket():
    # UDP socket listening for discovery broadcasts
    discovery_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    discovery_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    discovery_socket.settimeout(1)
    
    
    # Create a socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((SERVERIP, PORT))

    # Start listening
    server_socket.listen()

    # List for select
    sockets_list = [server_socket]

    # Connected clients
    clients = {}
    
    # Clients public keys {clientsocket : publickey}
    symkeys = {}

    # Sockets that are yet to enter correct password
    incorrect_pass_sockets = []
    
    # Remove banner and display text
    os.system('cls')
    print(datetime.now())
    print(colorama.Fore.GREEN)
    print(f'=== Server listening on {SERVERIP}:{PORT} ====')
    
    # Start listening for connection thread       
    t1 = threading.Thread(target=listen_for_discoveries, args=(discovery_socket, ), daemon=True)
    t1.start()
    
    while True:

        read_sockets, write_sockets, exception_sockets = select.select(sockets_list, [], sockets_list)


        # Iterate over notified sockets
        for notified_socket in read_sockets:

            # If notified socket is a server socket - new connection, accept it
            if notified_socket == server_socket:

                # Accept new connection
                # That gives us new socket - client socket, connected to this given client only, it's unique for that client
                # The other returned object is ip/port set
                client_socket, client_address = server_socket.accept()

                symkeys[client_socket] = exchange_keys(client_socket)
                
                # Client should send his name right away, receive it
                user = receive_message(client_socket)
                
                # If False - client disconnected before he sent his name
                if user is False:
                    continue
                
                checkpass = receive_message(client_socket)
                
                # Add accepted socket to select.select() list
                sockets_list.append(client_socket)

                # Also save username and username header
                clients[client_socket] = user
                
                if symkeys[client_socket].decrypt(checkpass['data']).decode() != ADMINPASS:
                    print(f'$ Received wrong password from: {client_address}')
                    incorrect_pass_sockets.append(client_socket)
                    continue
                
                # Telling the client he is good to go
                confirmation = symkeys[client_socket].encrypt(b'Connect')
                confirmation_header = f"{len(confirmation):<{HEADER_LENGTH}}".encode()
                client_socket.send(confirmation_header + confirmation)

                print('$ Accepted new connection from {}:{}, username: {}'.format(*client_address, symkeys[client_socket].decrypt(user['data']).decode()))

            elif notified_socket in incorrect_pass_sockets:
                try:
                    # Receive password
                    receive_message(notified_socket)
                    
                    checkpass = receive_message(notified_socket)
                    
                    if symkeys[notified_socket].decrypt(checkpass['data']).decode() != ADMINPASS:
                        print(f'$ Received wrong password from: {client_address}')
                        continue
                    
                    incorrect_pass_sockets.remove(client_socket)
                    
                    # Telling the client he is good to go
                    confirmation = symkeys[client_socket].encrypt(b'Connect')
                    confirmation_header = f"{len(confirmation):<{HEADER_LENGTH}}".encode()
                    client_socket.send(confirmation_header + confirmation)

                    print('$ Accepted new connection from {}:{}, username: {}'.format(*client_address, symkeys[client_socket].decrypt(user['data']).decode()))
                
                except:
                    # Socket was closed 
                    # Remove from list for socket.socket()
                    sockets_list.remove(notified_socket)

                    # Remove from our list of users
                    del clients[notified_socket]
                    del symkeys[notified_socket]

                    continue
            # Else existing socket is sending a message
            else:

                # Receive message
                message = receive_message(notified_socket)
                
                # Ungraceful disconnection (probably program terminated)
                if message is False:
                    print(f'$ Closed connection from: {symkeys[notified_socket].decrypt(clients[notified_socket]["data"]).decode()}')

                    # Remove from list for socket.socket()
                    sockets_list.remove(notified_socket)

                    # Remove from our list of users
                    del clients[notified_socket]
                    del symkeys[notified_socket]

                    continue
                
                # Get user by notified socket, so we will know who sent the message
                user = clients[notified_socket]
                
                user_name = symkeys[notified_socket].decrypt(user["data"]).decode()
                message_text = symkeys[notified_socket].decrypt(message["data"]).decode()
                
                
                # Start checking for commands
                command = message_text.lstrip()
                
                # Server shutdown
                if command[:5] == '!quit':
                    
                    password = command[5:].lstrip()
                    if password != ADMINPASS:
                        print("Quit command received, but password was wrong")
                        
                        continue
                    
                    print(f'Disconnecting all clients and shutting down')
                    
                    # Iterate over connected clients and broadcast message
                    for client_socket in clients:

                        sent_username = symkeys[client_socket].encrypt(b'server')
                        sent_username_header = f"{len(sent_username):<{HEADER_LENGTH}}".encode()
                        sent_message = symkeys[client_socket].encrypt(b'Confirmed exit')
                        sent_message_header = f"{len(sent_message):<{HEADER_LENGTH}}".encode()
                        
                        client_socket.send(sent_username_header + sent_username + sent_message_header + sent_message)
                        
                    sys.exit()
                
                # Graceful disconnection (client asked to disconenct using !exit)
                if command == '!exit':
                    print(f'$ Client {user_name} disconnected gracefully')
                    
                    sent_username = symkeys[notified_socket].encrypt(b'server')
                    sent_username_header = f"{len(sent_username):<{HEADER_LENGTH}}".encode()
                    sent_message = symkeys[notified_socket].encrypt(b'Confirmed exit')
                    sent_message_header = f"{len(sent_message):<{HEADER_LENGTH}}".encode()
                    
                    notified_socket.send(sent_username_header + sent_username + sent_message_header + sent_message)
                    
                    notified_socket.close()
                    sockets_list.remove(notified_socket)
                    del clients[notified_socket]
                    del symkeys[notified_socket]
                    
                    continue
                
                # Echoes back echo variable
                if command[:5] == '!echo':
                    echo = command[5:].lstrip()
                    print(f'$ Echoing {echo} back to client {user_name}')
                    
                    sent_username = symkeys[notified_socket].encrypt(b'server')
                    sent_username_header = f"{len(sent_username):<{HEADER_LENGTH}}".encode()
                    sent_message = symkeys[notified_socket].encrypt(echo.encode())
                    sent_message_header = f"{len(sent_message):<{HEADER_LENGTH}}".encode()
                    
                    notified_socket.send(sent_username_header + sent_username + sent_message_header + sent_message)
                    
                    continue
                
                # Sends back random wiki page
                if command[:12] == '!enlightenme':
                    url = specialcommands.randomwiki()
                    pagename = url[30:]
                    print(f'Enlighening client {user_name} with information about {pagename}')
                    
                    sent_username = symkeys[notified_socket].encrypt(b'server')
                    sent_username_header = f"{len(sent_username):<{HEADER_LENGTH}}".encode()
                    sent_message = symkeys[notified_socket].encrypt(url.encode())
                    sent_message_header = f"{len(sent_message):<{HEADER_LENGTH}}".encode()
                    
                    notified_socket.send(sent_username_header + sent_username + sent_message_header + sent_message)
                    
                    continue
                
                # Execute shell commands on server
                if command[:6] == '!shell':
                    shell = specialcommands.shell(command[6:])
                    
                    # Unavailable command
                    if not shell:
                        print('Command failed')
                        sent_username = symkeys[notified_socket].encrypt(b'server')
                        sent_username_header = f"{len(sent_username):<{HEADER_LENGTH}}".encode()
                        sent_message = symkeys[notified_socket].encrypt(b'Forbidden command')
                        sent_message_header = f"{len(sent_message):<{HEADER_LENGTH}}".encode()
                        
                        notified_socket.send(sent_username_header + sent_username + sent_message_header + sent_message)
                        
                        continue
                    
                    print(f'Executing {shell} on server and returning to {user_name}')
                    
                    sent_username = symkeys[notified_socket].encrypt(b'server')
                    sent_username_header = f"{len(sent_username):<{HEADER_LENGTH}}".encode()
                    sent_message = symkeys[notified_socket].encrypt(shell.encode())
                    sent_message_header = f"{len(sent_message):<{HEADER_LENGTH}}".encode()
                    
                    notified_socket.send(sent_username_header + sent_username + sent_message_header + sent_message)
                    
                    continue
                
                
                # Sends encrypted image 
                if command[:5] == '!meow':
                    imagename = specialcommands.meow()
                    imagepath = f'cats/{imagename}'
                    
                    with open(imagepath, 'rb') as f:
                        imagebinary = f.read()
                        
                    encrypted_image = symkeys[notified_socket].encrypt(imagebinary)
                    
                    with open('temp.bin', 'wb') as f:
                        f.write(encrypted_image)
                    
                    imagesize = os.path.getsize('temp.bin')
                    os.remove('temp.bin')
                    
                    print(f'Sending a picture of a cute cat to {user_name} with size of {imagesize}')
                    
                    sent_username = symkeys[notified_socket].encrypt(b'server')
                    sent_username_header = f"{len(sent_username):<{HEADER_LENGTH}}".encode()
                    sent_message = symkeys[notified_socket].encrypt(f'{imagesize}&{imagename}'.encode())
                    sent_message_header = f"{len(sent_message):<{HEADER_LENGTH}}".encode()
                    
                    # Sending the image name and size first
                    notified_socket.send(sent_username_header + sent_username + sent_message_header + sent_message) 
                    
                    notified_socket.sendall(encrypted_image)
                    continue

            
                print(f'$ Received message from {user_name} : {message_text}')

                # Iterate over connected clients and broadcast message
                for client_socket in clients:

                    # Send user and message (both with their headers)
                    # We are reusing here message header sent by sender, and saved username header send by user when he connected
                    sent_username = symkeys[client_socket].encrypt(user_name.encode())
                    sent_username_header = f"{len(sent_username):<{HEADER_LENGTH}}".encode()
                    sent_message = symkeys[client_socket].encrypt(message_text.encode())
                    sent_message_header = f"{len(sent_message):<{HEADER_LENGTH}}".encode()
                    
                    client_socket.send(sent_username_header + sent_username + sent_message_header + sent_message)

        # It's not really necessary to have this, but will handle some socket exceptions just in case
        for notified_socket in exception_sockets:

            # Remove from list for socket.socket()
            sockets_list.remove(notified_socket)

            # Remove from our list of users
            del clients[notified_socket]


    
if __name__ == '__main__':
    # print banner
    with open('banner.txt', 'r', encoding='utf-8') as f:
        text = f.read()
        colors = list(vars(colorama.Fore).values())
        colored_chars = [random.choice(colors) + char for char in text]
        print(''.join(colored_chars))
        
    time.sleep(1)
    
    print(colorama.Fore.BLUE)
    initialize_socket()

