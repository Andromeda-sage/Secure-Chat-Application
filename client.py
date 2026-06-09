import os
import time
import uuid
import base64
import socket
import threading
import json

import customtkinter as ctk

from crypto_utils import (
    generate_rsa_keys,
    serialize_public_key,
    load_public_key,
    encrypt_message,
    decrypt_message,
    encrypt_aes_key,
    decrypt_aes_key,
    sign_message,
    verify_signature
)


HOST = "127.0.0.1"
PORT = 65432


# ==========================
# MAIN APP
# ==========================
class SecureChatApp(ctk.CTk):

    def __init__(self):
        super().__init__()

        self.title("🔐 Secure Student Messaging")
        self.geometry("1000x650")

        ctk.set_appearance_mode("dark")

        self.username = None
        self.private_key = None
        self.public_key = None

        self.client_socket = None

        self.users = {}
        self.selected_user = None
        self.seen_messages = set()

        self.build_login_ui()

    # ==========================
    # LOGIN UI
    # ==========================
    def build_login_ui(self):
        self.login_frame = ctk.CTkFrame(self)
        self.login_frame.pack(expand=True)

        ctk.CTkLabel(
            self.login_frame,
            text="🔐 Secure Messaging App",
            font=("Arial", 24, "bold")
        ).pack(pady=20)

        self.username_entry = ctk.CTkEntry(
            self.login_frame,
            width=250,
            placeholder_text="Username"
        )
        self.username_entry.pack(pady=10)


        self.password_entry = ctk.CTkEntry(
            self.login_frame,
            width=250,
            placeholder_text="Password",
            show="*"
        )
        self.password_entry.pack(pady=10)

        ctk.CTkButton(
            self.login_frame,
            text="Connect",
            command=self.connect_to_server
        ).pack(pady=10)

    # ==========================
    # CONNECT
    # ==========================
    def connect_to_server(self):

        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()

        if not username or not password:
            return

        self.username = username

        self.private_key, self.public_key = generate_rsa_keys()

        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((HOST, PORT))

        login_packet = {
            "type": "login",
            "username": self.username,
            "password": password,
            "public_key": serialize_public_key(self.public_key)
        }

        self.client_socket.sendall(
            (json.dumps(login_packet) + "\n").encode()
        )

        self.login_frame.destroy()
        self.build_chat_ui()

        threading.Thread(
            target=self.receive_messages,
            daemon=True
        ).start()

    # ==========================
    # CHAT UI
    # ==========================
    def build_chat_ui(self):

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.left_frame = ctk.CTkFrame(self)
        self.left_frame.grid(row=0, column=0, sticky="ns")

        ctk.CTkLabel(
            self.left_frame,
            text="Online Users",
            font=("Arial", 16, "bold")
        ).pack(pady=10)

        self.user_listbox = ctk.CTkScrollableFrame(self.left_frame, width=200)
        self.user_listbox.pack(fill="both", expand=True)

        self.right_frame = ctk.CTkFrame(self)
        self.right_frame.grid(row=0, column=1, sticky="nsew")

        self.chat_area = ctk.CTkScrollableFrame(self.right_frame)
        self.chat_area.pack(fill="both", expand=True, padx=10, pady=10)

        self.bottom_frame = ctk.CTkFrame(self.right_frame)
        self.bottom_frame.pack(fill="x", padx=10, pady=10)

        self.message_entry = ctk.CTkEntry(self.bottom_frame)
        self.message_entry.pack(side="left", fill="x", expand=True)

        ctk.CTkButton(
            self.bottom_frame,
            text="Send",
            command=self.send_message
        ).pack(side="right")

    # ==========================
    # SAFE UI UPDATES
    # ==========================
    def safe_call(self, func, *args):
        self.after(0, lambda: func(*args))

    # ==========================
    # UPDATE USERS
    # ==========================
    def update_user_list(self, users):
        self.users = users

        for w in self.user_listbox.winfo_children():
            w.destroy()

        for username in users:
            if username == self.username:
                continue

            ctk.CTkButton(
                self.user_listbox,
                text=username,
                command=lambda u=username: self.select_user(u)
            ).pack(fill="x", pady=3)

    def select_user(self, username):
        self.selected_user = username
        self.add_system_message(f"Chatting with {username}")

    # ==========================
    # MESSAGES UI
    # ==========================
    def add_message(self, text, sender="other"):
        color = "#1F6FEB" if sender == "me" else "#2b2b2b"

        frame = ctk.CTkFrame(self.chat_area, fg_color=color)
        frame.pack(anchor="e" if sender == "me" else "w", pady=5)

        ctk.CTkLabel(frame, text=text, wraplength=300).pack(padx=10, pady=5)

    def add_system_message(self, text):
        ctk.CTkLabel(
            self.chat_area,
            text=text,
            text_color="yellow"
        ).pack(pady=5)

    # ==========================
    # RECEIVE THREAD
    # ==========================
    def receive_messages(self):

        buffer = ""

        while True:
            try:
                data = self.client_socket.recv(65535)
                if not data:
                    break

                buffer += data.decode()

                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)

                    if not line.strip():
                        continue

                    packet = json.loads(line)

                    if packet["type"] == "users":
                        self.safe_call(self.update_user_list, packet["users"])

                    elif packet["type"] == "message":
                        self.handle_message(packet)

            except Exception as e:
                print("Receive error:", e)
                break

        self.safe_call(self.add_system_message, "Disconnected from server")

    # ==========================
    # SEND MESSAGE
    # ==========================
    def send_message(self):

        if not self.selected_user:
            self.add_system_message("Select a user first.")
            return

        message = self.message_entry.get().strip()
        if not message:
            return

        try:
            recipient = self.users[self.selected_user]

            recipient_public_key = load_public_key(recipient["public_key"])

            aes_key = os.urandom(32)

            nonce, ciphertext = encrypt_message(message, aes_key)

            encrypted_key = encrypt_aes_key(recipient_public_key, aes_key)

            signature = sign_message(self.private_key, message)

            packet = {
                "type": "message",
                "sender": self.username,
                "recipient": self.selected_user,

                "encrypted_key": base64.b64encode(encrypted_key).decode(),
                "nonce": base64.b64encode(nonce).decode(),
                "ciphertext": base64.b64encode(ciphertext).decode(),
                "signature": base64.b64encode(signature).decode(),

                "message_id": str(uuid.uuid4()),
                "timestamp": int(time.time())
            }

            self.client_socket.sendall((json.dumps(packet) + "\n").encode())

            self.add_message(f"You: {message}", "me")
            self.message_entry.delete(0, "end")

        except Exception as e:
            self.add_system_message(f"Send Error: {e}")

    # ==========================
    # HANDLE INCOMING MESSAGE
    # ==========================
    def handle_message(self, packet):

        try:
            msg_id = packet["message_id"]

            if msg_id in self.seen_messages:
                return

            self.seen_messages.add(msg_id)

            encrypted_key = base64.b64decode(packet["encrypted_key"])
            nonce = base64.b64decode(packet["nonce"])
            ciphertext = base64.b64decode(packet["ciphertext"])
            signature = base64.b64decode(packet["signature"])

            aes_key = decrypt_aes_key(self.private_key, encrypted_key)

            plaintext = decrypt_message(nonce, ciphertext, aes_key)

            sender = packet["sender"]

            if sender not in self.users:
                self.safe_call(self.add_system_message, "Unknown sender")
                return

            sender_public_key = load_public_key(
                self.users[sender]["public_key"]
            )

            if not verify_signature(sender_public_key, plaintext, signature):
                self.safe_call(
                    self.add_system_message,
                    f"WARNING: Invalid signature from {sender}"
                )
                return

            self.safe_call(
                self.add_message,
                f"{sender}: {plaintext}",
                "other"
            )

        except Exception as e:
            self.safe_call(self.add_system_message, f"Receive Error: {e}")


# ==========================
# RUN APP
# ==========================
if __name__ == "__main__":
    app = SecureChatApp()
    app.mainloop()