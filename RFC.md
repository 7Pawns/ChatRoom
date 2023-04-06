# ChatRoom RFC

*Status: Informational*

*Author: 7Pawns*

*Created: April 7, 2023*

## Table of Contents
- [Connection Process](#connection-process)
- [Key Exchanging](#key-exchanging)
- [Login](#login)
- [Chat](#chat)
- [Commands](#commands)

### Connection Process

A server is up when he has a TCP socket waiting for connections, and a sniffer which finds discovery messasges sent from clients.
The client first sets up a UDP socket, which sends discovery broadcasts throughout the LAN.
When the server finds the broadcast it sends back to the client its IP, port and password, allowing the client to connect.
The client then sets up a TCP socket and connects to the IP and port specified in the message.

### Key Exchanging

The client generates a pair of RSA keys, and sends the public key to the server.
The server generates a symmetric AES key, and when he receives the public key from the client he encrypts the symmetric key using the public key, and sends the output back to the client.
After both parties received the symmetric key the encrypted connection can begin.

### Login

The client uses his received password and sends it with a username to the server.
When the server receives the request to login he checks if the password matches the stored password. If it doesn't, he does not reply, and the client's socket will timeout.
If the password does match he will send a message back, confirming the login, which will then allow the client to login and join the chat room.

### Chat

In the chat the users can interact with each other using the built-in message box.
By sending a message, the users are essentially speaking with the server, which then distributes the content of the message to the appropriate individuals.
A plain message is sent back to everyone, and updated in the GUI, while commands only get sent to the executer, and obviously only popup on his screen.
Every message is encrypted on the sender side and decrypted on the receiver using the shared symmetric key.

### Commands

- `!echo <message>` - Receives a message as input, server returns the same message.
- `!enlightenme` - Receives no input, server returns a link to a wikipedia page, which automatically opens on the client machine.
- `!shell <command>` - Receives a shell command as input, the command then gets sent to the server, executed there, and the output gets sent back to the client.
- `!meow` - Receives no input, server returns a random image of a cat, if the folder is not tampered with. The image is fully encrypted and sent at this condition to the client just like every text message. The image is also displayed in the GUI.
- `!exit` - Receives no input, server send a request to disconnect client from the server and the chatroom.
- `!quit <password>` - Receives the admin password as input, which was received during the intial connection. The server first sends requests to disconnect to every client, and then shuts down itself.