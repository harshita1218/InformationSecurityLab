import socket
import hashlib


def compute_hash(data):
    """Compute the SHA-256 hash of the given data."""
    return hashlib.sha256(data).hexdigest()


def start_server(host='127.0.0.1', port=65432):
    """Start the server to receive data and send back its hash."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        print(f"Server listening on {host}:{port}...")

        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr}")
            data = conn.recv(1024)  # Receive data from the client
            if data:
                print(f"Received data: {data.decode()}")
                data_hash = compute_hash(data)  # Compute hash of the received data
                print(f"Computed hash: {data_hash}")
                conn.sendall(data_hash.encode())  # Send back the computed hash


if __name__ == "__main__":
    start_server()
