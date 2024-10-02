import os
import time
import rsa  # For RSA encryption
import secrets  # For random number generation
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES


def generate_rsa_keypair(bits=2048):
    """Generate RSA key pair."""
    return rsa.newkeys(bits)


def rsa_encrypt(public_key, message):
    """Encrypt a message using RSA public key."""
    # Generate a symmetric key for AES
    aes_key = secrets.token_bytes(16)  # 128-bit key for AES
    cipher = AES.new(aes_key, AES.MODE_CBC)

    # Encrypt the message using AES
    padded_message = pad(message.encode('utf-8'), AES.block_size)
    ciphertext = cipher.encrypt(padded_message)

    # Encrypt the AES key using RSA
    encrypted_aes_key = rsa.encrypt(aes_key, public_key)

    return encrypted_aes_key, cipher.iv + ciphertext  # Return AES key and IV + ciphertext


def rsa_decrypt(private_key, encrypted_aes_key, ciphertext):
    """Decrypt a message using RSA private key."""
    # Decrypt the AES key using RSA
    aes_key = rsa.decrypt(encrypted_aes_key, private_key)

    # Extract IV
    iv = ciphertext[:16]
    ct = ciphertext[16:]

    # Decrypt the message using AES
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted_message = unpad(cipher.decrypt(ct), AES.block_size).decode('utf-8')

    return decrypted_message


def generate_elgamal_keypair():
    """Generate ElGamal key pair using secp256r1."""
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key


def elgamal_encrypt(public_key, message):
    """Encrypt a message using ElGamal encryption."""
    ephemeral_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    ephemeral_pub_key = ephemeral_key.public_key()

    shared_secret = ephemeral_key.exchange(ec.ECDH(), public_key)
    aes_key = hashes.Hash(hashes.SHA256(), backend=default_backend())
    aes_key.update(shared_secret)
    aes_key = aes_key.finalize()[:16]  # Use the first 16 bytes for AES key

    cipher = AES.new(aes_key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))

    return ephemeral_pub_key, cipher.iv + ciphertext


def elgamal_decrypt(private_key, ephemeral_pub_key, ciphertext):
    """Decrypt a message using ElGamal decryption."""
    shared_secret = private_key.exchange(ec.ECDH(), ephemeral_pub_key)
    aes_key = hashes.Hash(hashes.SHA256(), backend=default_backend())
    aes_key.update(shared_secret)
    aes_key = aes_key.finalize()[:16]  # Use the first 16 bytes for AES key

    iv = ciphertext[:16]
    ct = ciphertext[16:]
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted_message = unpad(cipher.decrypt(ct), AES.block_size).decode('utf-8')

    return decrypted_message


def measure_performance(algorithm, message_size):
    message = os.urandom(message_size).decode(errors='ignore')  # Random binary data
    print(f"\nTesting with message size: {message_size} bytes")

    if algorithm == "RSA":
        # Measure RSA Key Generation Time
        start_time = time.time()
        private_key, public_key = generate_rsa_keypair()
        rsa_key_gen_time = time.time() - start_time
        print(f"RSA Key Generation Time: {rsa_key_gen_time:.4f} seconds")

        # Measure RSA Encryption Time
        start_time = time.time()
        encrypted_aes_key, encrypted_message = rsa_encrypt(public_key, message)
        rsa_encryption_time = time.time() - start_time
        print(f"RSA Encryption Time: {rsa_encryption_time:.4f} seconds")

        # Measure RSA Decryption Time
        start_time = time.time()
        decrypted_message = rsa_decrypt(private_key, encrypted_aes_key, encrypted_message)  # Use private key
        rsa_decryption_time = time.time() - start_time
        print(f"RSA Decryption Time: {rsa_decryption_time:.4f} seconds")

        assert decrypted_message == message, "Decrypted message does not match the original."

    elif algorithm == "ElGamal":
        # Measure ElGamal Key Generation Time
        start_time = time.time()
        private_key, public_key = generate_elgamal_keypair()
        elgamal_key_gen_time = time.time() - start_time
        print(f"ElGamal Key Generation Time: {elgamal_key_gen_time:.4f} seconds")

        # Measure ElGamal Encryption Time
        start_time = time.time()
        ephemeral_pub_key, encrypted_message = elgamal_encrypt(public_key, message)
        elgamal_encryption_time = time.time() - start_time
        print(f"ElGamal Encryption Time: {elgamal_encryption_time:.4f} seconds")

        # Measure ElGamal Decryption Time
        start_time = time.time()
        decrypted_message = elgamal_decrypt(private_key, ephemeral_pub_key, encrypted_message)
        elgamal_decryption_time = time.time() - start_time
        print(f"ElGamal Decryption Time: {elgamal_decryption_time:.4f} seconds")

        assert decrypted_message == message, "Decrypted message does not match the original."


def main():
    message_sizes = [1024, 10 * 1024]  # 1 KB and 10 KB
    for size in message_sizes:
        measure_performance("RSA", size)
        measure_performance("ElGamal", size)


if __name__ == "__main__":
    main()
