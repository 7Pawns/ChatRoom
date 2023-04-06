# ChatRoom
Encrypted chat room with a client interface and several commands.
This is the first time I am experimenting with sockets, encryption and threading, so don't be too harsh :)
# Setup
* Run the following command to download all dependencies:
```console
python.exe -m pip install requirements.txt
```
* Run the quickstartup script that launches a server and 2 clients, if you are on one PC:
```console
./singlepcstartup.ps1
```
I don't know how licensing works, but I am pretty sure I can't provide you with the images I downloaded from the web, so:
* Place some JPEG files in the cats directory.<br>
* Place a GIF file in the UI folder, and name it waiting.gif.

# Features
## Rooms (GUI using PyQt)
### Waiting Room
From here the client initiates his connection to the server.
By clicking *START SERVER LOOKUP* the client initiates a UDP socket, and starts to broadcast discovery messages throughout the LAN.<br>
When the server sniffs the broadcast (using scapy) he will send a message back to the client with his __IP__, __Port__ and __password__ (just for fun, doesn't secure the server in any way), which will allow the client to connect to it. The connection is made using TCP sockets.<br>
By using threads we are able to continue allowing clients to interact with the server, while also listening for new connections.
We will know when we connected to the server when a popup containing the password will show up.
### Login Room
Here the client needs to enter his username and the password he received earlier.<br>
If the password matches the password stored on the server, he will be granted access.
### Chat Room
Here users can send messages to each other, or execute commands.
### Commands
* !echo <message> - Makes the server send the specified message back to the client.
* !enlightenme - Makes the server send a request to a Wikipedia page that redirects to a random page, returning the URL, and opening it on the client side.
* !shell <shell command> - Makes the server execute the specified command in shell.
* !meow - Makes the server transfer a cute image of a cat (or whatever was in the cats directory), and display it in the chatroom. Note that the image is saved at the receivedcats folder.
* !exit - Disconnects the client.
* !quit <password> - Disconnects every client, and shuts down the server.
### Chat Room Logic
The users will see every message they send to each other, __BUT__ only the user executing commands will be able to see their output.
## Encryption
The Chatroom uses two encryptions: __RSA__ and __AES__.<br>
### RSA
* First an __RSA key pair__ is generated at the client side.<br>
* Then, the __public key__ gets sent to the server.<br>
### AES
* The server generates an __AES key__, and encrypts it using the client's public key.<br>
* The encrypted __AES key__ is then sent to the client, which decrypts it using his private key.<br>
* Now the two sides can talk with each other with __encrypted data__.