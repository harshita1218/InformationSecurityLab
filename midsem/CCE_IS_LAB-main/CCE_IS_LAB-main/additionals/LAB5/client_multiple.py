import socket
import hashlib

def main():
    # Create a TCP/IP socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('localhost', 9999)
    client_socket.connect(server_address)

    try:
        # Original message to be sent in parts
        original_message = "This is a message that will be sent in multiple parts."
        message_parts = [original_message[i:i+20] for i in range(0, len(original_message), 20)]

        # Send message parts to the server
        for part in message_parts:
            client_socket.sendall(part.encode())
            print(f"Sent part: {part}")

        # Close the connection to indicate the end of the message
        client_socket.shutdown(socket.SHUT_WR)

        # Wait for the hash from the server
        received_hash = client_socket.recv(1024).decode()
        print("Received hash from server:", received_hash)

        # Compute the hash of the original message
        computed_hash = hashlib.sha256(original_message.encode()).hexdigest()
        print("Computed hash of original message:", computed_hash)

        # Verify the integrity of the message
        if received_hash == computed_hash:
            print("Integrity verified: Hashes match.")
        else:
            print("Integrity verification failed: Hashes do not match.")

    finally:
        client_socket.close()

if __name__ == "__main__":
    main()
