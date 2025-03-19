import socket
import threading
import sqlite3
from hashlib import sha256
from datetime import datetime


class Database:
    def initialize_database(self):
        conn = sqlite3.connect('app.db')
        c = conn.cursor()
        c.execute('CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password_hash TEXT)')
        conn.commit()
        conn.close()

    def register(self, username, password):
        password_hash = sha256(password.encode()).hexdigest()
        try:
            # establish connection with the database
            connection = sqlite3.connect('app.db')
            c = connection.cursor()

            # create a new user and store the hashed password
            c.execute('INSERT INTO users VALUES (?, ?)', (username, password_hash))

            connection.commit()
            connection.close()
            # succesful registration
            return True

        # this error occoures when we try to register an already existing user
        except sqlite3.IntegrityError:
            return False

    def login(self, username, password):
        # establish connection with the database
        connection = sqlite3.connect('app.db')
        c = connection.cursor()

        # hash the given password for comparison
        password_hash = sha256(password.encode()).hexdigest()

        # find the hashed password that belongs to the user
        c.execute('SELECT password_hash FROM users WHERE username=?', (username,))
        user_credentials = c.fetchone()
        connection.close()

        # only return true if the user is in the database, and the passwords hash matches
        return user_credentials and user_credentials[0] == password_hash


class Authenticate:
    # when server = Authenticate() is executed __init__() is automatically called to initialize
    # the variables that the server will use when the server.start() is executed
    def __init__(self, host='0.0.0.0', port=12345):
        self.host = host
        self.port = port
        self.db = Database()

        # limiting the number of connections to 3 with semaphore
        self.max_users = threading.Semaphore(3)

        # waiting queue:
        self.waiting_queue = []
        self.waiting_lock = threading.Lock()

    def authenticate(self, client_socket):
        if not self.max_users.acquire(blocking=False):
            with self.waiting_lock:
                self.waiting_queue.append(client_socket)
                position = len(self.waiting_queue)

            waiting_message = f"The server is full, you are {position}. in queue, please wait.\n"
            client_socket.send(waiting_message.encode())

            # this will wait until release() is called
            self.max_users.acquire()

            # release was called there is an empty space
            with self.waiting_lock:
                if client_socket in self.waiting_queue:
                    self.waiting_queue.remove(client_socket)

        # receive the authentication request:
        try:
            auth_message = client_socket.recv(1024).decode()
            request = auth_message.split()
            # request has 3 elements: "login" or "register", username, password

            if len(request) != 3:
                # if the register or login is pressed and the fields above are not filled out
                client_socket.send(b"Fields are not filled out!")
                client_socket.close()
                return

            # the flag is originally false, and if the login or registration is successful then change it
            authenticated = False

            if request[0] == "register":
                if self.db.register(request[1], request[2]):
                    client_socket.send(b"Successful registration!")
                    authenticated = True
                else:
                    client_socket.send(b"Username taken!")

            elif request[0] == "login":
                if self.db.login(request[1], request[2]):
                    client_socket.send(b"Successful login!")
                    authenticated = True
                else:
                    client_socket.send(b"Login has failed!")

            if authenticated:
                # Pass the semaphore to ChatServer
                ChatServer(self.db, self.max_users).client_connection(client_socket, request[1])
            else:
                client_socket.close()
                self.max_users.release()
        except Exception as e:
            print(f"Authentication error: {e}")
            client_socket.close()

    def start(self):
        self.db.initialize_database()
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((self.host, self.port))
        server.listen(5)
        print(f"Server started on port {self.port}")

        # the server always listenes for new connections, each user will have their own thread.
        while True:
            client, address = server.accept()
            print(f"Connection from {address}")
            threading.Thread(target=self.authenticate, args=[client]).start()


class ChatServer:
    def __init__(self, database, semaphore=None):
        self.db = database
        self.clients = []
        self.clients_lock = threading.Lock()
        self.max_users = semaphore

    def client_connection(self, client_socket, username):

        # add the new user to the list of current clients (observers) list
        with self.clients_lock:
            self.clients.append((username, client_socket))

        # send a message that the user has joined
        self.send_all("the server", f"{username} joined.")

        try:
            # keep the connection and listen for messages
            while True:
                message = client_socket.recv(1024).decode().strip()
                if not message:
                    break

                # Check for exit message
                if message == "EXIT":
                    break

                # when a message is received send it to the groupchat
                self.send_all(username, message)
        finally:
            # delete client from the list of current clients
            with self.clients_lock:
                self.clients = [(n, s) for n, s in self.clients if s != client_socket]

            # send a message that the user has left
            self.send_all("the server", f"{username} left.")

            # user has left so the semaphore can be released
            self.max_users.release()



    def send_all(self, senders_username, message):
        # Send message to everyone
        with self.clients_lock:
            for username, client_socket in self.clients:
                try:
                    sent_at = datetime.now().strftime("%H:%M:%S")
                    formatted_message = f"from: {senders_username}, at:{sent_at}: {message}\n"
                    client_socket.send(formatted_message.encode())  # encode it to send it securely
                except:
                    pass  # the client is probably disconnected



if __name__ == "__main__":
    server = Authenticate()
    server.start()
