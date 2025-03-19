# client.py
import tkinter as tk
from tkinter import messagebox
import socket


class UI:
    def __init__(self, root, client):
        self.root = root
        self.client = client
        self.setup_ui()

    def setup_ui(self):
        self.root.title("Chat Login")

        frame = tk.Frame(self.root)
        frame.pack()

        # the columns and rows:
        #           0           1
        #   0   username    usernames field
        #   1   password    passwords field
        # under that the login/register buttons
        tk.Label(frame, text="username:").grid(row=0, column=0, sticky="e")
        self.username_field = tk.Entry(frame, width=50)
        self.username_field.grid(row=0, column=1)

        tk.Label(frame, text="password:").grid(row=1, column=0, sticky="e")
        self.password_field = tk.Entry(frame, width=50)
        self.password_field.grid(row=1, column=1)

        button_frame = tk.Frame(frame, width=50)
        button_frame.grid(row=2, column=0, columnspan=2)

        login_button = tk.Button(button_frame, text="Login", command=self.client.login)
        login_button.pack()

        register_button = tk.Button(button_frame, text="Register", command=self.client.register)
        register_button.pack()


class ChatClient:
    def __init__(self, root):
        self.root = root
        self.ui = UI(root, self)

    def connect_to_server(self):
        # if the connection was succesful return the socket, if not return false
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(('localhost', 12345))
            return sock
        except Exception as e:
            messagebox.showerror("Connection error", str(e))
            return False

    def login(self):
        c_socket = self.connect_to_server()
        if not c_socket:
            return

        username = self.ui.username_field.get()
        password = self.ui.password_field.get()

        # Send all information in one message
        auth_message = f"login {username} {password}".encode()
        c_socket.send(auth_message)

        # Get result if login was succesful
        result = c_socket.recv(1024).decode()
        messagebox.showinfo("Result", result)
        c_socket.close()

    def register(self):
        c_socket = self.connect_to_server()
        if not c_socket:
            return

        username = self.ui.username_field.get()
        password = self.ui.password_field.get()

        # Send all information in one message
        auth_message = f"register {username} {password}".encode()
        c_socket.send(auth_message)

        # Get result if register was successful
        result = c_socket.recv(1024).decode()
        messagebox.showinfo("Result", result)
        c_socket.close()


if __name__ == "__main__":
    root = tk.Tk()
    client = ChatClient(root)
    root.mainloop()