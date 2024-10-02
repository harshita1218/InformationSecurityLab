import os
import time
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib


def generate_keys():
    """Generate ECC keys using SECP256R1 curve."""
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key


def elgamal_encrypt(public_key, message):
    """Encrypt the message using ElGamal encryption."""
    # Generate ephemeral key
    ephemeral_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    ephemeral_pub_key = ephemeral_key.public_key()

    # Derive shared secret
    shared_secret = ephemeral_key.exchange(ec.ECDH(), public_key)
    shared_secret_hash = hashlib.sha256(shared_secret).digest()

    # Encrypt the message using AES
    aes_key = shared_secret_hash[:16]  # Use first 16 bytes as AES key
    cipher = AES.new(aes_key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))

    return ephemeral_pub_key, cipher.iv + ciphertext


def elgamal_decrypt(private_key, ephemeral_pub_key, ciphertext):
    """Decrypt the ciphertext using ElGamal decryption."""
    # Derive shared secret
    shared_secret = private_key.exchange(ec.ECDH(), ephemeral_pub_key)
    shared_secret_hash = hashlib.sha256(shared_secret).digest()

    # Decrypt the message using AES
    aes_key = shared_secret_hash[:16]
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted_message = unpad(cipher.decrypt(ct), AES.block_size).decode('utf-8')

    return decrypted_message


def main():
    # Generate ECC keys
    private_key, public_key = generate_keys()

    # Example patient data
    patient_data = [
        "Patient record 1: John Doe, Age: 30, Blood Type: O+",
        "Patient record 2: Jane Smith, Age: 45, Blood Type: A-",
        "Patient record 3: Alice Johnson, Age: 25, Blood Type: B+"
    ]

    # Measure performance for encryption and decryption
    for data in patient_data:
        print(f"\nEncrypting and decrypting data: {data}")

        # Measure encryption time
        start_time = time.time()
        ephemeral_pub_key, ciphertext = elgamal_encrypt(public_key, data)
        encryption_time = time.time() - start_time
        print(f"Encryption Time: {encryption_time:.4f} seconds")

        # Measure decryption time
        start_time = time.time()
        decrypted_message = elgamal_decrypt(private_key, ephemeral_pub_key, ciphertext)
        decryption_time = time.time() - start_time
        print(f"Decryption Time: {decryption_time:.4f} seconds")

        # Verify the decrypted message
        assert decrypted_message == data, "Decrypted message does not match the original."


if __name__ == "__main__":
    main()
