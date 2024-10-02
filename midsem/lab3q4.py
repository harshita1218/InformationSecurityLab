import os
import time
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


def generate_ecc_keypair():
    """Generate ECC key pair using SECP256r1."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key


def encrypt_file_aes(key, input_file):
    """Encrypt a file using AES."""
    with open(input_file, 'rb') as f:
        data = f.read()
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    return cipher.iv + ct_bytes  # Prepend IV to the ciphertext


def decrypt_file_aes(key, encrypted_data):
    """Decrypt a file using AES."""
    iv = encrypted_data[:16]  # Extract the IV
    ct = encrypted_data[16:]  # Extract the ciphertext
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(ct), AES.block_size)
    return decrypted_data


def main():
    # Generate ECC Key Pair
    ecc_private_key, ecc_public_key = generate_ecc_keypair()

    # Serialize ECC public key
    pem = ecc_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    print("ECC Public Key:")
    print(pem.decode())

    # Generate AES Key
    aes_key = get_random_bytes(32)  # 256-bit key
    print(f"AES Key: {aes_key.hex()}")

    # Create a test file
    test_file = "test_file.txt"
    with open(test_file, 'wb') as f:
        f.write(os.urandom(1 * 1024 * 1024))  # Write 1 MB of random data

    # Measure AES Encryption Time
    start_time = time.time()
    encrypted_data = encrypt_file_aes(aes_key, test_file)
    aes_encryption_time = time.time() - start_time
    print(f"AES Encryption Time: {aes_encryption_time:.4f} seconds")

    # Measure AES Decryption Time
    start_time = time.time()
    decrypted_data = decrypt_file_aes(aes_key, encrypted_data)
    aes_decryption_time = time.time() - start_time
    print(f"AES Decryption Time: {aes_decryption_time:.4f} seconds")

    # Clean up test file
    os.remove(test_file)


if __name__ == "__main__":
    main()
