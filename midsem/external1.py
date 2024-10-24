The image outlines the requirements for designing a secure Military Defense System using Elliptic Curve Cryptography (ECC). Below is a structured breakdown based on the content:

PC-1: Military Defense System Design
Goal:
To develop a secure system for handling classified communications and sensitive mission-critical data between two military bases or units. The system must ensure confidentiality, integrity, and security using:

Elliptic Curve Cryptography (ECC) for encryption
Digital signatures
Key management
Role Definitions:
Commander:

High clearance level
Access to Level 1 (highly classified) and Level 2 (less classified) data.
Can decrypt all classified data, including mission plans, personnel details, and national security information.
Field Officer:

Medium clearance level
Access to Level 2 (less classified) data, such as operational updates.
Cannot view or decrypt Level 1 data.
Data Encryption and Digital Signatures:
Level 1 Encryption:

Encrypt highly classified data (mission objectives, intelligence reports, troop locations) using Elliptic Curve Cryptography (ECC).
Only high-clearance users, such as Commanders, can decrypt this data.
Level 2 Encryption:

Encrypt less-classified data (e.g., operational orders, field updates) for users with medium clearance, like Field Officers.
Digital Signatures:

Field Officers must collect and digitally sign Level 2 data using the Elliptic Curve Digital Signature Algorithm (ECDSA) to ensure data authenticity and integrity.
The system must display real-time digital signature generation and verification to prevent tampering.
Key Management and Exchange:
Diffie-Hellman Key Exchange using ECC (ECDH):
Implement to enable secure communication between military bases or units.
Include the generation of public and private ECC keys for each military base or unit.


























from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os


# ECC Key generation
def generate_ecc_keys():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key


# Encrypt using ECC (Diffie-Hellman)
def encrypt_with_ecc(sender_private_key, recipient_public_key, message):
    # Generate shared secret using the sender's private key and recipient's public key
    shared_key = sender_private_key.exchange(ec.ECDH(), recipient_public_key)

    # Derive a symmetric key using HKDF (Hash-based Key Derivation Function)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_key)

    # Encrypt the message using AES-GCM
    aes_gcm_nonce = os.urandom(12)
    aes_cipher = Cipher(algorithms.AES(derived_key), modes.GCM(aes_gcm_nonce), backend=default_backend())
    encryptor = aes_cipher.encryptor()

    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    return aes_gcm_nonce, ciphertext, encryptor.tag


# Decrypt using ECC (Diffie-Hellman)
def decrypt_with_ecc(recipient_private_key, sender_public_key, aes_gcm_nonce, ciphertext, tag):
    # Generate shared secret using recipient's private key and sender's public key
    shared_key = recipient_private_key.exchange(ec.ECDH(), sender_public_key)

    # Derive a symmetric key using HKDF
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_key)

    # Decrypt the message using AES-GCM
    aes_cipher = Cipher(algorithms.AES(derived_key), modes.GCM(aes_gcm_nonce, tag), backend=default_backend())
    decryptor = aes_cipher.decryptor()

    decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted_message.decode()


# Example keys for Commander and Field Officer
commander_private_key, commander_public_key = generate_ecc_keys()
field_officer_private_key, field_officer_public_key = generate_ecc_keys()


# Menu-driven system
def main():
    while True:
        print("\n==== Secure Military Defense System ====")
        print("1. Log in as Commander (Encrypt)")
        print("2. Log in as Field Officer (Decrypt)")
        print("3. Exit")
        choice = input("Enter your choice: ")

        if choice == "1":
            print("\n==== Commander Mode ====")
            message = input("Enter the message to encrypt: ")
            aes_gcm_nonce, ciphertext, tag = encrypt_with_ecc(commander_private_key, field_officer_public_key, message)
            print(f"Encrypted message: {ciphertext}")
            print(f"Nonce: {aes_gcm_nonce}")
            print(f"Tag: {tag}")

        elif choice == "2":
            print("\n==== Field Officer Mode ====")
            aes_gcm_nonce = bytes.fromhex(input("Enter the Nonce (in hex): "))
            ciphertext = bytes.fromhex(input("Enter the Encrypted message (in hex): "))
            tag = bytes.fromhex(input("Enter the Tag (in hex): "))
            try:
                decrypted_message = decrypt_with_ecc(field_officer_private_key, commander_public_key, aes_gcm_nonce,
                                                     ciphertext, tag)
                print(f"Decrypted message: {decrypted_message}")
            except Exception as e:
                print(f"Decryption failed: {e}")

        elif choice == "3":
            print("Exiting the system.")
            break
        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()











