import tkinter as tk
from tkinter import messagebox, scrolledtext
import socket
import threading
import os
from tkinter import filedialog

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

    def chat_ui(self, send, exit_app, mute, send_file):
        # destroying the frames used for authentication to "hide them"
        for frame in self.root.winfo_children():
            frame.destroy()

        # the chats frame
        chat_frame = tk.Frame(self.root)
        chat_frame.pack(fill=tk.BOTH, expand=True)

        # this is where the chat is displayed
        self.chat_area = scrolledtext.ScrolledText(chat_frame, state=tk.DISABLED, wrap=tk.WORD)
        self.chat_area.pack(fill=tk.BOTH, expand=True, padx=10)

        # message input
        self.input_frame = tk.Frame(chat_frame)
        self.input_frame.pack(fill=tk.X, padx=10)

        self.message_field = tk.Entry(self.input_frame)
        self.message_field.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # trigger the message sending function
        send_button = tk.Button(self.input_frame, text="Send", command=send)
        send_button.pack(side=tk.RIGHT, padx=10)

        # exit button
        exit_button = tk.Button(self.input_frame, text="Exit", command=exit_app, bg="red", fg="white")
        exit_button.pack(side=tk.RIGHT, padx=10)

        # Add mute button
        self.mute_button = tk.Button(self.input_frame, text="🔊 Mute", command=mute)
        self.mute_button.pack(side=tk.RIGHT, padx=10)

        file_button = tk.Button(self.input_frame, text="Send file", command=send_file)
        file_button.pack(side=tk.RIGHT, padx=10)

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

        if "queue" in result:
            return c_socket, "wait:" + result
        elif "Successful" in result:
            # if the message sent contains Successful it means that the user has logged in
            return c_socket, result
        else:
            # Failed login
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

        if "queue" in result:
            return c_socket, "wait:" + result
        elif "Successful" in result:
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
        self.muted = False

        # initiate the authentication process
        self.ui.authentication_ui(self.handle_login, self.handle_register)


    def send_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Allowed Files", "*.pdf *.docx *.jpeg")])

        if not file_path:
            return  # the user canceled the file selecting

        try:
            # try to access the files name and data
            filename = os.path.basename(file_path)
            with open(file_path, 'rb') as f:
                file_data = f.read()

            # because of the formatting: file:filename:size
            #                               binary_data
            # my server implementation will know that it works with a file (not a message),
            # and it will also know how many bytes to read.
            header = f"file:{filename}:{len(file_data)}\n".encode()
            self.socket.sendall(header + file_data)
            self.ui.show_message(f"file sent: {filename}\n")

        except Exception as exception:
            messagebox.showerror("Error", f"file sending failed: {exception}")


    def mute_unmute(self):
        self.muted = not self.muted
        self.ui.mute_button.config(text="Unmute" if self.muted else "Mute")

    # based on which button is pressed, either the register or the login related functions are called.
    def handle_login(self):
        username = self.ui.username_field.get()
        password = self.ui.password_field.get()

        # both registration and login has the same pattern:
        # get username and password, pass it to client authentication, and then process the result
        socket, result = self.auth_client.login(username, password)
        self.handle_auth_result(socket, result, username)

    def handle_register(self):
        username = self.ui.username_field.get()
        password = self.ui.password_field.get()

        socket, result = self.auth_client.register(username, password)
        self.handle_auth_result(socket, result, username)

    # process the result of login or register
    def handle_auth_result(self, socket, result, username):
        if socket:
            if "queue" in result:
                messagebox.showinfo("Waiting", result)
                # start a thread that waits until a place becomes available
                threading.Thread(target=self.wait_in_que, args=[socket]).start()
            else:
                # authentication was successful
                self.username = username
                self.ui.chat_ui(self.send_message, self.exit_chat, self.mute_unmute, self.send_file)
                self.start_thread(socket)
        else:
            messagebox.showinfo("Result", result)

    def wait_in_que(self, socket):
        while True:
            try:
                message = socket.recv(1024).decode()
                if "Successful" in message:
                    # there is finally an empty space
                    # the UI should be set up before starting the message thread
                    self.root.after(0, self.ui.chat_ui, self.send_message, self.exit_chat, self.mute_unmute, self.send_file)
                    self.root.after(10, self.start_thread, socket)
                    break
            except:
                break

    def start_thread(self, socket):
        self.socket = socket

        # start a thread for receiving messages
        threading.Thread(target=self.receive).start()

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

    def receive(self):
        # wait to receive messages from the server (Observer pattern)

        # if the user does not have a directory, make one to save the file there
        os.makedirs(f"{self.username}_downloads", exist_ok=True)

        while self.socket:
            try:
                # receive data
                data = self.socket.recv(4096)
                if not data:
                    messagebox.showerror("Error", "Server closed the connection")
                    self.socket.close()
                    break

                # check if this is a file
                if data.startswith(b"file:"):
                    # parse file
                    header, file_data = data.split(b"\n", 1)
                    _, filename, size = header.decode().split(":", 2)
                    size = int(size)

                    # receive data until the whole file is received
                    received = len(file_data)
                    while received < size:
                        part = self.socket.recv(4096)
                        file_data += part
                        received += len(part)

                    # save the file in the users folder
                    with open(f"{self.username}_downloads/{filename}", "wb") as f:
                        f.write(file_data)

                    # get a message that the file is received
                    self.ui.show_message(f"File received: {filename}\n")

                    # notification sound
                    if not self.muted:
                        self.root.bell()
                else:
                    # it's a text massage
                    message = data.decode()

                    # show the message
                    self.ui.show_message(message)

                    # no notification for the own message of the user, and no notification when joining
                    if not self.muted and f"from: {self.username}" not in message.split(",") and all(
                            word not in message for word in ["joined.", "Successful"]):
                        self.root.bell()  # notification sound

            except Exception as exception:
                print(f"Error: {exception}")
                if self.socket:
                    self.socket.close()
                    self.socket = None
                break

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
