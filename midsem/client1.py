import socket
import hashlib

def compute_hash(data):
    """Compute SHA-256 hash of the given data."""
    return hashlib.sha256(data.encode()).hexdigest()

def main():
    host = '127.0.0.1'  # Server address
    port = 65432        # Server port

    message_parts = ["Hello, ", "this is ", "a message sent ", "in multiple parts!"]
    full_message = ''.join(message_parts)

    # Compute the hash of the original message
    original_hash = compute_hash(full_message)
    print(f"Original message: {full_message}")
    print(f"Original hash: {original_hash}")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((host, port))

        # Send the message in parts
        for part in message_parts:
            client_socket.sendall(part.encode())

        # Signal the end of message transmission
        client_socket.sendall(b'')  # Sending an empty byte string to indicate completion

        # Receive the hash from the server
        received_hash = client_socket.recv(1024).decode()
        print(f"Received hash from server: {received_hash}")

        # Verify the integrity of the message
        if received_hash == original_hash:
            print("Integrity check passed: The hashes match.")
        else:
            print("Integrity check failed: The hashes do not match.")

if __name__ == "__main__":
    main()
