import socket
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
import os


def generate_dh_parameters():
    # Generate Diffie-Hellman parameters
    parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
    return parameters


def dh_key_exchange_server(server_socket, parameters):
    # Generate private key for the server
    server_private_key = parameters.generate_private_key()

    # Exchange public keys with the client
    client_public_key_bytes = server_socket.recv(1024)
    client_public_key = serialization.load_pem_public_key(client_public_key_bytes, backend=default_backend())

    # Send server's public key to the client
    server_public_key_bytes = server_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    server_socket.sendall(server_public_key_bytes)

    # Derive shared secret
    shared_key = server_private_key.exchange(client_public_key)

    # Use HKDF to derive a symmetric key
    derived_key = HKDF(
        algorithm=SHA256(),
        length=32,
        salt=None,
        info=b'server key exchange',
        backend=default_backend()
    ).derive(shared_key)

    return derived_key


def server_program():
    parameters = generate_dh_parameters()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 65432))
    server_socket.listen(1)
    print("Server is listening for incoming connections...")

    conn, addr = server_socket.accept()
    print(f"Connected by {addr}")

    derived_key = dh_key_exchange_server(conn, parameters)
    print(f"Shared key derived: {derived_key.hex()}")

    # Close connection after exchange
    conn.close()


if __name__ == "__main__":
    server_program()
