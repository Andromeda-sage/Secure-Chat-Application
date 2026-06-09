import socket
import threading
import json
import hashlib

HOST = "0.0.0.0"
PORT = 65432

clients = {}
lock = threading.Lock()

with open("users.json", "r") as f:
    USERS = json.load(f)

# ==========================
# SAFE JSON SEND
# ==========================
def send_json(sock, data):
    try:
        message = json.dumps(data) + "\n"
        sock.sendall(message.encode())
    except Exception:
        pass


# ==========================
# BROADCAST USERS
# ==========================
def broadcast_user_list():
    with lock:
        users = {
            username: {
                "public_key": info["public_key"]
            }
            for username, info in clients.items()
        }

        packet = {
            "type": "users",
            "users": users
        }

        for info in clients.values():
            send_json(info["socket"], packet)


# ==========================
# REMOVE CLIENT
# ==========================
def remove_client(username):
    with lock:
        if username in clients:
            del clients[username]

    print(f"[DISCONNECTED] {username}")
    broadcast_user_list()


# ==========================
# HANDLE CLIENT
# ==========================
def handle_client(client_socket):

    username = None
    buffer = ""

    try:
        # ==========================
        # LOGIN
        # ==========================
        while "\n" not in buffer:
            data = client_socket.recv(65535)
            if not data:
                return
            buffer += data.decode()

        line, buffer = buffer.split("\n", 1)

        login_data = json.loads(line)

        if login_data.get("type") != "login":
            return
    
        username = login_data["username"]
        password = login_data["password"]

        if username not in USERS:
            send_json(client_socket, {
                "type": "login_failed",
                "message": "Unknown user"
            })
            return

        # hash password
        password_hash = hashlib.sha256(
            password.encode()
        ).hexdigest()

        if password_hash != USERS[username]["password_hash"]:
            send_json(client_socket, {
                "type": "login_failed",
                "message": "Wrong password"
            })
            return        

        with lock:
            clients[username] = {
                "socket": client_socket,
                "public_key": login_data["public_key"]
            }

        send_json(client_socket, {
            "type": "login_success"
        })

        print(f"[CONNECTED] {username}")
        broadcast_user_list()

        # ==========================
        # MAIN LOOP
        # ==========================
        while True:
            data = client_socket.recv(65535)

            if not data:
                break

            buffer += data.decode()

            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)

                if not line.strip():
                    continue

                try:
                    packet = json.loads(line)
                except json.JSONDecodeError:
                    continue

                if packet.get("type") == "message":
                    recipient = packet.get("recipient")

                    with lock:
                        if recipient in clients:
                            send_json(
                                clients[recipient]["socket"],
                                packet
                            )

    except Exception as e:
        print(f"[ERROR] {e}")

    finally:
        if username:
            remove_client(username)

        try:
            client_socket.close()
        except:
            pass


# ==========================
# START SERVER
# ==========================
def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server.bind((HOST, PORT))
    server.listen()

    print("=" * 50)
    print("Secure Chat Server Started")
    print(f"Listening on {HOST}:{PORT}")
    print("=" * 50)

    while True:
        client_socket, address = server.accept()
        print(f"New connection from {address}")

        thread = threading.Thread(
            target=handle_client,
            args=(client_socket,),
            daemon=True
        )
        thread.start()


if __name__ == "__main__":
    start_server()