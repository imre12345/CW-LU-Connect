# server.py
import socket
import threading
import sqlite3
from hashlib import sha256


class Database:
    def initialize_database(self):
        conn = sqlite3.connect('chat.db')
        c = conn.cursor()
        c.execute('CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password_hash TEXT)')
        conn.commit()
        conn.close()

    def register(self, username, password):
        password_hash = sha256(password.encode()).hexdigest()
        try:
            # establish connection with the database
            connection = sqlite3.connect('chat.db')
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
        connection = sqlite3.connect('chat.db')
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
    def __init__(self, host='0.0.0.0', port=12345):
        self.host = host
        self.port = port
        self.db = Database()

    def authenticate(self, client_socket):
        # Receive the entire authentication message
        try:
            auth_message = client_socket.recv(1024).decode()
            request = auth_message.split()

            # request has 3 elements: login or register, username, password
            if len(request) != 3:
                client_socket.send(b"Fields are not filled out!")
                return
            # if the register or login is pressed and the fields above are not filled out

            if request[0] == "register":
                if self.db.register(request[1], request[2]):
                    client_socket.send(b"Successful registration!")
                else:
                    client_socket.send(b"Username taken!")

            elif request[0] == "login":
                if self.db.login(request[1], request[2]):
                    client_socket.send(b"Successful login!")
                else:
                    client_socket.send(b"Login has failed!")
        finally:
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


if __name__ == "__main__":
    server = Authenticate()
    server.start()