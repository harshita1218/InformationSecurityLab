import socket
import hashlib


def compute_hash(data):
    """Compute the SHA-256 hash of the given data."""
    return hashlib.sha256(data).hexdigest()


def start_client(host='127.0.0.1', port=65432, message="Hello, Server!"):
    """Send data to the server and verify the hash received from the server."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        print(f"Sending data: {message}")
        s.sendall(message.encode())  # Send data to the server

        received_hash = s.recv(64)  # Receive the hash from the server
        received_hash = received_hash.decode()
        print(f"Received hash from server: {received_hash}")

        # Compute local hash
        local_hash = compute_hash(message.encode())
        print(f"Computed local hash: {local_hash}")

        # Verify the integrity of the received data
        if local_hash == received_hash:
            print("Data integrity verified. No tampering detected.")
        else:
            print("Data integrity compromised! Hashes do not match.")


if __name__ == "__main__":
    start_client()
