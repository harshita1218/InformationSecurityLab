import os
from ecdsa import SigningKey, VerifyingKey, SECP256k1  # Change to SECP256k1
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


# Generate ECC key pair
def generate_ecc_keypair():
    """Generate ECC key pair using SECP256k1."""
    private_key = SigningKey.generate(curve=SECP256k1)
    public_key = private_key.get_verifying_key()
    return private_key, public_key


# Encrypt the message using ECC public key
def encrypt_message(public_key, message):
    """Encrypt a message using AES with a randomly generated AES key."""
    # Generate a random AES key
    aes_key = get_random_bytes(32)  # 256-bit AES key

    # Encrypt the message with AES
    cipher = AES.new(aes_key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))

    # Return the IV and ciphertext (AES) along with the AES key
    return cipher.iv + ct_bytes, aes_key


# Decrypt the message using ECC private key
def decrypt_message(private_key, encrypted_data, aes_key):
    """Decrypt the encrypted message using AES."""
    # Extract IV and ciphertext
    iv = encrypted_data[:16]
    ct = encrypted_data[16:]

    # Decrypt the message with AES
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(ct), AES.block_size)

    return decrypted_data.decode('utf-8')


# Main function to demonstrate encryption and decryption
if __name__ == "__main__":
    # Generate ECC key pair
    private_key, public_key = generate_ecc_keypair()

    # Message to encrypt
    message = "Secure Transactions"

    # Encrypt the message
    encrypted_message, aes_key = encrypt_message(public_key, message)
    print(f"Encrypted message (bytes): {encrypted_message}")

    # Decrypt the message
    decrypted_message = decrypt_message(private_key, encrypted_message, aes_key)
    print(f"Decrypted message: {decrypted_message}")
