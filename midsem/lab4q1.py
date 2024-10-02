import os
import random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from hashlib import sha256


class SecureCorpSystem:
    def __init__(self, name, p, g):
        self.name = name
        self.private_key = RSA.generate(2048)
        self.public_key = self.private_key.publickey()
        self.shared_key = None  # Shared secret key for AES
        self.secret = random.randint(1, 100)  # Private value for DH
        self.p = p  # Prime modulus for DH
        self.g = g  # Generator for DH
        self.public_dh_key = pow(self.g, self.secret, self.p)  # DH public key

    def generate_shared_key(self, other_public_dh_key):
        """Generate a shared key using Diffie-Hellman."""
        shared_secret = pow(other_public_dh_key, self.secret, self.p)  # Calculate shared secret
        self.shared_key = sha256(str(shared_secret).encode()).digest()[:16]  # AES key (first 16 bytes)
        return self.public_dh_key  # Return own public DH key

    def encrypt_message(self, message):
        """Encrypt message using AES with the shared key."""
        if not self.shared_key:
            raise ValueError("Shared key not generated.")
        cipher = AES.new(self.shared_key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
        return cipher.iv + ct_bytes  # Return IV + ciphertext

    def decrypt_message(self, ciphertext):
        """Decrypt message using AES with the shared key."""
        if not self.shared_key:
            raise ValueError("Shared key not generated.")
        iv = ciphertext[:16]
        ct = ciphertext[16:]
        cipher = AES.new(self.shared_key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode()

    def sign_message(self, message):
        """Sign a message using RSA private key."""
        rsa_cipher = PKCS1_OAEP.new(self.private_key)
        return rsa_cipher.encrypt(message.encode())

    def verify_signature(self, signature):
        """Verify a signature using RSA public key."""
        rsa_cipher = PKCS1_OAEP.new(self.public_key)
        try:
            return rsa_cipher.decrypt(signature).decode()
        except Exception as e:
            return str(e)  # Return error if signature verification fails


# Example usage
def main():
    # Example prime and generator for DH
    p = 23  # Example small prime number
    g = 5  # Example generator

    finance_system = SecureCorpSystem("Finance", p, g)
    hr_system = SecureCorpSystem("HR", p, g)

    # Key generation and sharing
    finance_public_dh_key = finance_system.generate_shared_key(hr_system.public_dh_key)
    hr_public_dh_key = hr_system.generate_shared_key(finance_public_dh_key)

    print(f"Finance public DH key: {finance_public_dh_key}")
    print(f"HR public DH key: {hr_public_dh_key}")

    # Communication
    original_message = "Confidential Financial Report"
    encrypted_message = finance_system.encrypt_message(original_message)
    print(f"Encrypted Message: {encrypted_message}")

    decrypted_message = hr_system.decrypt_message(encrypted_message)
    print(f"Decrypted Message: {decrypted_message}")

    # Signing and verifying messages
    signed_message = finance_system.sign_message(original_message)
    print(f"Signed Message: {signed_message}")

    verified_message = hr_system.verify_signature(signed_message)
    print(f"Verified Message: {verified_message}")


if __name__ == "__main__":
    main()
