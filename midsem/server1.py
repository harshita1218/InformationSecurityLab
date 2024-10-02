import socket
import hashlib

def compute_hash(data):
    """Compute SHA-256 hash of the given data."""
    return hashlib.sha256(data.encode()).hexdigest()

def main():
    host = '127.0.0.1'  # Server address
    port = 65432        # Server port

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, port))
        server_socket.listen()
        print(f"Server listening on {host}:{port}")

        conn, addr = server_socket.accept()
        with conn:
            print(f"Connected by {addr}")

            # Receive the message in parts
            received_data = []
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                received_data.append(data.decode())

            # Reassemble the message
            full_message = ''.join(received_data)
            print(f"Reassembled message: {full_message}")

            # Compute the hash of the reassembled message
            message_hash = compute_hash(full_message)
            print(f"Computed hash: {message_hash}")

            # Send the hash back to the client
            conn.sendall(message_hash.encode())

if __name__ == "__main__":
    main()
