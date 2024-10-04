import socket
import hashlib

# Function to compute the hash of the message
def compute_hash(message):
    return hashlib.sha256(message.encode()).hexdigest()

def main():
    # Create a TCP/IP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('localhost', 9999)
    server_socket.bind(server_address)

    # Listen for incoming connections
    server_socket.listen(1)
    print("Server is listening for incoming connections...")

    connection, client_address = server_socket.accept()
    try:
        print(f"Connection from {client_address}")

        # Receive message parts
        message_parts = []
        while True:
            data = connection.recv(1024)  # Buffer size is 1024 bytes
            if not data:
                break
            message_parts.append(data.decode())

        # Reassemble the message
        complete_message = ''.join(message_parts)
        print("Reassembled message:", complete_message)

        # Compute hash of the complete message
        message_hash = compute_hash(complete_message)
        print("Computed hash:", message_hash)

        # Send the hash back to the client
        connection.sendall(message_hash.encode())

    finally:
        connection.close()

if __name__ == "__main__":
    main()
