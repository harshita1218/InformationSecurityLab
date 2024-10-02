import socket
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256


def dh_key_exchange_client(client_socket, parameters):
    # Generate private key for the client
    client_private_key = parameters.generate_private_key()

    # Send client's public key to the server
    client_public_key_bytes = client_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    client_socket.sendall(client_public_key_bytes)

    # Receive server's public key
    server_public_key_bytes = client_socket.recv(1024)
    server_public_key = serialization.load_pem_public_key(server_public_key_bytes, backend=default_backend())

    # Derive shared secret
    shared_key = client_private_key.exchange(server_public_key)

    # Use HKDF to derive a symmetric key
    derived_key = HKDF(
        algorithm=SHA256(),
        length=32,
        salt=None,
        info=b'client key exchange',
        backend=default_backend()
    ).derive(shared_key)

    return derived_key


def client_program():
    parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 65432))

    derived_key = dh_key_exchange_client(client_socket, parameters)
    print(f"Shared key derived: {derived_key.hex()}")

    # Close the connection after exchange
    client_socket.close()


if __name__ == "__main__":
    client_program()
