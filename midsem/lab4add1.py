from Crypto.Random import get_random_bytes
from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes
import time
import logging

# Configure logging
logging.basicConfig(filename='drm_audit.log', level=logging.INFO, format='%(asctime)s - %(message)s')

class DRMSystem:
    def __init__(self):
        self.key_size = 2048
        self.generate_master_key()

    def generate_master_key(self):
        logging.info("Generating ElGamal master key pair...")
        p = getPrime(self.key_size)
        g = 2  # Primitive root
        x = int.from_bytes(get_random_bytes(self.key_size // 8), byteorder='big') % (p - 1)  # Private key
        y = pow(g, x, p)  # Public key
        self.master_key_pair = {'p': p, 'g': g, 'x': x, 'y': y}
        logging.info("Master key pair generated successfully.")

    def encrypt_content(self, content):
        p = self.master_key_pair['p']
        g = self.master_key_pair['g']
        y = self.master_key_pair['y']

        # Convert content to integer
        content_int = bytes_to_long(content)

        # Generate random k
        k = int.from_bytes(get_random_bytes(self.key_size // 8), byteorder='big') % (p - 1)

        # ElGamal encryption
        c1 = pow(g, k, p)  # c1 = g^k mod p
        s = pow(y, k, p)   # s = y^k mod p
        c2 = (content_int * s) % p  # c2 = message * s mod p

        logging.info(f"Content encrypted successfully: c1 = {c1}, c2 = {c2}")
        return (c1, c2)

    def decrypt_content(self, ciphertext):
        p = self.master_key_pair['p']
        x = self.master_key_pair['x']

        c1, c2 = ciphertext

        # ElGamal decryption
        s = pow(c1, x, p)  # s = c1^x mod p
        s_inv = inverse(s, p)  # s^-1 mod p
        content_int = (c2 * s_inv) % p  # message = c2 * s^-1 mod p

        # Convert back to bytes
        content = long_to_bytes(content_int)

        logging.info("Content decrypted successfully.")
        return content

def main():
    # Initialize DRM system
    drm = DRMSystem()

    # Content to encrypt
    content = b"Sensitive digital content"

    # Encrypt the content
    ciphertext = drm.encrypt_content(content)

    # Decrypt the content
    decrypted_content = drm.decrypt_content(ciphertext)

    # Display the decrypted content
    print("Original content:", content.decode())
    print("Decrypted content:", decrypted_content.decode())

if __name__ == "__main__":
    main()
