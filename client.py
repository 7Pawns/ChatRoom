import socket, sys, pickle, webbrowser, re, os
from scapy.all import *
from cryptography.fernet import Fernet
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5 import uic
from PyQt5.QtCore import Qt, QObject, QThread, pyqtSignal
import encryption

# * CONSTANTS
HEADER_LENGTH = 10
IP = "127.0.0.1"
PORT = 12345

# Get RSA keys
encryption.RSAgenerate_keys('client')
MYPUBLICKEY, MYPRIVATEKEY = encryption.load_keys('client')

# AES key (assigned in exchange_keys)
symkey = None

# Find special messages
URLREGEX = re.compile(r"^https://en.wikipedia.org/wiki/")
JPGREGEX = re.compile(r"\.jpg$")

# Server admin password
adminpass = ''

class PassRecv(QDialog):
    """
    Informs the client what is the password
    """
    def __init__(self, client_socket):
        super(PassRecv, self).__init__()
        uic.loadUi('UI/passrecv.ui', self)
        
        self.password.setText(adminpass)
        self.password.setStyleSheet('QLabel { color : red; font-size: 14pt; font-family: Courier;}')
        
        self.client_socket = client_socket
        
        self.continuebutton.clicked.connect(self.switch_to_login)
        
        
    def switch_to_login(self):
        
        self.cams = Login(self.client_socket)
        self.cams.show()
        self.close() 
        
        
class Waiting(QMainWindow):
    """
    Waiting for server connection
    """
    def __init__(self):
        super(Waiting, self).__init__()
        uic.loadUi('UI/waitingroom.ui', self)
        
        self.movie = QMovie('UI/waiting.gif')
        self.loadinglabel.setMovie(self.movie)
        
        self.movie.start()
        
        self.start.clicked.connect(self.start_server_lookup)
        self.setWindowTitle('Waiting Room')
        
        self.client_socket = None
        self.waitingresponse.setHidden(True)
    
    def start_server_lookup(self):
        """
        Starts thread that will look for the server
        """
        self.waitingresponse.setHidden(False)
        self.thread = QThread()
        self.listener = Listener()
        self.listener.moveToThread(self.thread)
        self.listener.finished.connect(self.switch_to_passwordrecv)
        self.thread.started.connect(self.listener.serverlookup)
        
        self.thread.start()
        
    def switch_to_passwordrecv(self):
        
        self.thread.quit()
        self.cams = PassRecv(self.client_socket)
        self.cams.show()
        self.close()    
        
        
class Login(QMainWindow):
    def __init__(self, client_socket):
        """
        Login page after receiving connection with the server
        """
        self.client_socket = client_socket
        
        super(Login, self).__init__()
        uic.loadUi('UI/login.ui', self)
        
        # No tampering with window sizing :)
        self.setFixedSize(self.width(), self.height())
        
        # Applying some configurations
        self.errorfield.setHidden(True)
        
        self.setWindowTitle('Login Window')
        
        self.loginbutton.clicked.connect(self.wait_for_confirmation)
        self.actionClose.triggered.connect(self.terminate_everything)
        
        self.passline.setEchoMode(QLineEdit.Password)

        self.show()
            
    def wait_for_confirmation(self):
        """
        Starts thread that will wait for server confirmation of the login details
        """
        self.loginbutton.setEnabled(False)
        
        if self.userline.text() == '' or self.passline.text() == '':
            self.loginbutton.setEnabled(True)
            self.errorfield.setText('Please fill both fields')
            self.errorfield.setHidden(False)
            self.loginbutton.setEnabled(True)
            self.userline.setText('')
            self.passline.setText('')

            return
        
        app.setOverrideCursor(Qt.WaitCursor)
        self.errorfield.setText('Waiting for server confirmation...')
        self.errorfield.setHidden(False)
        
 
        self.thread = QThread()
        self.listener = Listener(self.client_socket)
        self.listener.moveToThread(self.thread)
        self.listener.finished.connect(self.handle_results)
        self.thread.started.connect(lambda: self.listener.logincheck(self.userline.text(), self.passline.text()))
        
        self.thread.start()

        
    def handle_results(self, option):
            
        if option == 2:
            # If we reached here it means we can now connect to the server
            app.restoreOverrideCursor()
            self.client_socket.setblocking(False)
            self.thread.quit()
            self.cams = Chat(self.userline.text(), self.client_socket) 
            self.cams.show()
            self.close()
            
        if option == 3:
            app.restoreOverrideCursor()
            self.thread.quit()
            self.loginbutton.setEnabled(True)
            self.errorfield.setText('Incorrect password')
            self.userline.setText('')
            self.passline.setText('')
            
            
    
    def terminate_everything(self):
        self.close()
        sys.exit()
        
    
            
class Listener(QObject):
    
    # Thread will only finish before gui if the server crashes
    progress = pyqtSignal(bytes)
    finished = pyqtSignal(int)
    
    def __init__(self, client_socket=None):
        super(Listener, self).__init__()
        self.client_socket = client_socket

    def serverlookup(self):
        """
        Find server
        """
        window.client_socket = initialize_socket()
        
        self.finished.emit(1)

    def logincheck(self, username, password):
        
        """
        Send login info and wait for confirmation from server
        """
        username = symkey.encrypt(username.encode())
        username_header = f"{len(username):<{HEADER_LENGTH}}"
        adminpass = symkey.encrypt(password.encode())
        adminpass_header = f"{len(adminpass):<{HEADER_LENGTH}}"
        
        self.client_socket.send(username_header.encode() + username + adminpass_header.encode() + adminpass)
        
        self.client_socket.setblocking(True)
        self.client_socket.settimeout(3)
        
        try:
            # After a couple of seconds of not receiving anything, a socket.timeout error will rise
            self.client_socket.recv(1024)
            self.finished.emit(2)
            
            return
            
        

        except socket.timeout:
            
            self.finished.emit(3)
            
            return
        
    
    def run(self):
        """
        Listen for messages from server
        """
        # We will raise a server might disconnected after 100 seconds
        # But we will leave it to the client to decide if to disconnect or stay
        self.client_socket.setblocking(True)
        self.client_socket.settimeout(100)
        
        while True:
            
            try:
                # Header tells us how many bytes to expect 
                username_header = self.client_socket.recv(HEADER_LENGTH)

                # Convert to int
                username_length = int(username_header.decode())

                # Receive and decode username
                username = symkey.decrypt(self.client_socket.recv(username_length)).decode()

                # Same thing as before
                message_header = self.client_socket.recv(HEADER_LENGTH)
                message_length = int(message_header.decode())
                got_message = symkey.decrypt(self.client_socket.recv(message_length)).decode()
                
                # Handle special commands / messages
                # Received after !exit or !quit and means disconnect now
                if got_message == 'Confirmed exit':
                    print('Disconnecting...')
                    self.client_socket.close()
                    self.finished.emit(1)
                
                # Wikipedia page
                elif URLREGEX.match(got_message):
                    webbrowser.open(got_message, new=2)

                # JPEG transfer
                elif JPGREGEX.findall(got_message):
                    
                    filesize, filename = got_message.split('&')
                            
                    # Create folder if it doesn't exists
                    if not os.path.exists('receivedcats'):
                        os.mkdir('receivedcats')
                        
                    with open(f'receivedcats/{filename}', "wb") as f:

                        f.write(symkey.decrypt(self.client_socket.recv(int(filesize))))
                        
                # Print message
                self.progress.emit(f'{username} > {got_message}'.encode())
                

            except socket.timeout:
                
                # Return a value through the thread
                self.progress.emit(f'socket timeout'.encode())

                # We just did not receive anything
                continue

            
            except Exception as e:
                # Any other exception - something happened, exit
                self.finished.emit(1)
    
    

    
class Chat(QMainWindow):
    
    
    def __init__(self, username, client_socket):
        super(Chat, self).__init__()
        uic.loadUi('UI/chatroom.ui', self)
        
        self.username = username
        self.client_socket = client_socket
        
        # Random color for each member of the chat
        self.possible_colors = ["QLabel { color : blue; font-size: 14pt; font-family: Courier;}", "QLabel { color : red; font-size: 14pt; font-family: Courier;}", "QLabel { color : green; font-size: 14pt; font-family: Courier;}", "QLabel { color : black; font-size: 14pt; font-family: Courier;}", "QLabel { color : purple; font-size: 14pt; font-family: Courier;}"]
        self.color_users = {}
        self.current_color = 0
        
        self.setWindowTitle('Chatroom')
        
        # No tampering with window sizing :)
        self.setFixedSize(self.width(), self.height())
        
        if len(self.username) > 8:
            self.usernamelabel.setText(self.username[:8] + '...') # To not go out of bounds
        else:
            self.usernamelabel.setText(self.username)
            
        self.send.clicked.connect(self.send_message)
        self.actionClose.triggered.connect(self.terminate_everything)
        
        
        # Scroll bar
        self.scroller = QScrollArea()             
        self.widget = QWidget()                 
        self.vbox = QVBoxLayout()       
        self.vbox.setAlignment(Qt.AlignTop | Qt.AlignLeft)
     

        self.widget.setLayout(self.vbox)

        #Scroll Area Properties
        self.scroller.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOn)
        self.scroller.setWidgetResizable(True)
        self.scroller.setWidget(self.widget)
        self.scroller.setFont(QFont('Arial', 14))
        
        self.chatlayout.addWidget(self.scroller)
        
        self.scroller.verticalScrollBar().rangeChanged.connect(self.scrollToBottom,)
        self.start_listening_thread()
        
        self.errormessage.setHidden(True)
        
        self.show()
        
    def start_listening_thread(self):
        """
        Thread that will always listen for information from server
        """
        self.thread = QThread()
        self.listener = Listener(client_socket=self.client_socket)
        self.listener.moveToThread(self.thread)
        self.thread.started.connect(self.listener.run)
        self.listener.progress.connect(self.print_message)
        self.listener.finished.connect(self.terminate_everything)
        
        self.thread.start()
        
    def terminate_everything(self):
        self.thread.quit()
        self.close()
        sys.exit()
    
    def print_message(self, message):
        
        # After not receiving a message for a while, which might hint on some problem
        if message.decode() == 'socket timeout':
            self.errormessage.setText('Socket timeout reached, disconnection Advised')
            self.errormessage.setHidden(False)
        
        # Handling received jpeg info
        elif JPGREGEX.findall(message.decode()):
            pic = QLabel(self)
            pic.setPixmap(QPixmap('receivedcats/' + message.decode().split('&')[1]).scaled(300, 300, Qt.KeepAspectRatio))
            
            self.vbox.addWidget(pic)
            
            return
        
        self.errormessage.setHidden(True)
        new_message = QLabel(message.decode())
        username = message.decode().split('>')[1]
        
        # Give color
        if username not in self.color_users:
            self.color_users[username] = self.possible_colors[self.current_color]
            self.current_color = (self.current_color + 1) % 5
            
        new_message.setStyleSheet(self.color_users[username])
        
        # Allow the shell and meow commands to display more
        if len(message.decode().splitlines()) == 0:
            new_message.setMaximumHeight(30)
        
        self.vbox.addWidget(new_message)
        
    
    def scrollToBottom (self, minVal=None, maxVal=None):
        """
        Make scroll bar always go to the bottom when message is received
        """
        self.scroller.verticalScrollBar().setValue(
            self.scroller.verticalScrollBar().maximum()
        )
    
    def send_message(self):
        """
        Sending messages to the server
        """
        message = self.message.text()
        
        self.message.setText('')
        
        # Encode message to bytes, prepare header and convert to bytes, like for username above, then send
        message_sent = symkey.encrypt(message.encode())
        message_header = f"{len(message_sent):<{HEADER_LENGTH}}".encode()
        self.client_socket.send(message_header + message_sent)
        
        
    

def find_server():
    """
    Setting up a socket that will broadcast discoveries throughout the LAN
    """
    
    while True:
        # Set up a UDP socket
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Enable broadcasting mode
        udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        
        # Every 1 second another broadcast will be sent
        udp_socket.settimeout(1)
        
        # Set the broadcast address and port
        broadcast_address = '255.255.255.255'  # Replace with the broadcast address of your network
        port = 4445  # Replace with the port number you want to use

        # Send the UDP message
        message = 'hello world'  # Replace with your message
        udp_socket.sendto(message.encode(), (broadcast_address, port))
        
        try:
            ip, port = udp_socket.recvfrom(1024)[0].decode().split(':')
            break
        
        except socket.timeout:
            print("Didn't get answer, broadcasting again...")
            
    udp_socket.close()
    return ip, int(port)
    

def initialize_socket():
    
    ipaddr, port = find_server()
    
    # Create a socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((ipaddr, port))
    client_socket.setblocking(True)

    exchange_keys(client_socket)
    
    return client_socket


def exchange_keys(client_socket):    
    
    global symkey
    global adminpass
    
    """
    Sends RSA public key to server and receives AES symmetric key
    """
    
    # Serialize the key allowing for quick load on the server side
    serialized = pickle.dumps(MYPUBLICKEY)
    serialized_header = f"{len(serialized):<{HEADER_LENGTH}}".encode('utf-8')
    client_socket.send(serialized_header + serialized)
    
    received_sym= client_socket.recv(HEADER_LENGTH)
    
    # In case nothing was returned
    if not len(received_sym):
        return False
    
    received_length = int(received_sym.decode('utf-8').strip())
    
    # Receive the AES key
    key = client_socket.recv(received_length)
    symkey = Fernet(encryption.RSAdecrypt(key, MYPRIVATEKEY))
    
    header = int(client_socket.recv(HEADER_LENGTH).decode())
    adminpass = symkey.decrypt(client_socket.recv(header)).decode()

    
    client_socket.setblocking(False)
    
    
if __name__ == '__main__':
    # PyQt initialization
    app = QApplication([])
    window = Waiting()
    window.show()
    
    app.exec_()
    