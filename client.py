import tkinter as tk
from tkinter import messagebox, scrolledtext
import socket
import threading
import os

class UI:
    def __init__(self, root):
        self.root = root
        # these are the UI elements that will be needed to be accessed later
        self.username_field = None
        self.password_field = None
        self.message_field = None
        self.chat_area = None
        self.input_frame = None

    def authentication_ui(self, login, register):
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

        # the login and register buttons which initiate the login/register process
        login_button = tk.Button(button_frame, text="Login", command=login)
        login_button.pack()

        register_button = tk.Button(button_frame, text="Register", command=register)
        register_button.pack()

    def chat_ui(self, send, exit_app):
        # destroying the frames used for authentication to "hide them"
        for frame in self.root.winfo_children():
            frame.destroy()

        # the chats frame
        chat_frame = tk.Frame(self.root)
        chat_frame.pack(fill=tk.BOTH, expand=True)

        # this is where the chat is displayed
        self.chat_area = scrolledtext.ScrolledText(chat_frame, state=tk.DISABLED, wrap=tk.WORD)
        self.chat_area.pack(fill=tk.BOTH, expand=True)

        # message input
        self.input_frame = tk.Frame(chat_frame)
        self.input_frame.pack(fill=tk.X)

        self.message_field = tk.Entry(self.input_frame)
        self.message_field.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # trigger the message sending function
        send_button = tk.Button(self.input_frame, text="Send", command=send)
        send_button.pack(side=tk.RIGHT)

        # exit button
        exit_button = tk.Button(self.input_frame, text="Exit", command=exit_app, bg="red", fg="white")
        exit_button.pack(side=tk.RIGHT, padx=5)

    def show_message(self, message):
        self.chat_area.config(state=tk.NORMAL)
        self.chat_area.insert(tk.END, message)
        self.chat_area.see(tk.END)
        self.chat_area.config(state=tk.DISABLED)


class AuthenticateClient:
    def connect_to_server(self):
        # if the connection was succesful return the socket, if not return false
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(('localhost', 12345))
            return sock
        except Exception as exception:
            messagebox.showerror("Connection error", str(exception))
            return False

    def login(self, username, password):
        c_socket = self.connect_to_server()
        if not c_socket:
            return None, "Failed to connect to server"

        # Send all information in one message
        auth_message = f"login {username} {password}".encode()
        c_socket.send(auth_message)

        # Get result if login was succesful
        result = c_socket.recv(1024).decode()

        if "Successful" in result:
            # if the message sent contains Successful it means that the user has logged in
            return c_socket, result
        else:
            c_socket.close()
            return None, result

    def register(self, username, password):
        c_socket = self.connect_to_server()
        if not c_socket:
            return None, "Failed to connect to server"

        # send all information in one message
        auth_message = f"register {username} {password}".encode()
        c_socket.send(auth_message)

        # get result if register was successful
        result = c_socket.recv(1024).decode()

        if "Successful" in result:
            # if the message sent contains Successful it means that the user has registered
            return c_socket, result
        else:
            c_socket.close()
            return None, result


class ChatClient:
    def __init__(self, root):
        self.root = root
        self.ui = UI(root)
        self.auth_client = AuthenticateClient()
        self.socket = None
        self.username = None

        # initiate the authentication process
        self.ui.authentication_ui(self.handle_login, self.handle_register)

    # based on which button is pressed, either the register or the login related functions are called.
    def handle_login(self):
        username = self.ui.username_field.get()
        password = self.ui.password_field.get()

        # both registration and login has the same pattern:
        # get username and password, pass it to client authentication, and then process the result
        socket, result = self.auth_client.login(username, password)
        self.handle_auth_result(socket, result)

    def handle_register(self):
        username = self.ui.username_field.get()
        password = self.ui.password_field.get()

        socket, result = self.auth_client.register(username, password)
        self.handle_auth_result(socket, result)

    # process the result of login or register
    def handle_auth_result(self, socket, result):
        if socket:
            # authentication was successful
            self.ui.chat_ui(self.send_message, self.exit_chat)
            self.start_thread(socket)
        else:
            messagebox.showinfo("Result", result)


    def start_thread(self, socket):
        self.socket = socket

        # start a thread for receiving messages
        threading.Thread(target=self.receive_messages).start()

    def send_message(self):
        if not self.socket:
            return

        message = self.ui.message_field.get().strip()
        if message:
            try:
                # try to send the encoded message to the server.
                self.socket.send(message.encode())
                # reset the input field
                self.ui.message_field.delete(0, tk.END)
            except:
                messagebox.showerror("Error", "Failed to send message")
                self.socket.close()
                self.socket = None

    def receive_messages(self):
        # wait to receive messages from the server (Observer pattern)
        while self.socket:
            try:
                message = self.socket.recv(1024).decode()
                if not message:
                    break

                # show the message
                self.ui.show_message(message)
            except:
                break

        # at this point connection was lost
        if self.socket:
            messagebox.showerror("Error", "lost connection to the server")
            self.socket.close()
            self.socket = None

    def exit_chat(self):
        if self.socket:
            try:
                # inform the server
                self.socket.send("EXIT".encode())
                self.socket.close()  # before exiting the socket needs to be closed
            except:
                pass
        # exit the app
        os._exit(0)

if __name__ == "__main__":
    root = tk.Tk()
    client = ChatClient(root)
    root.mainloop()
