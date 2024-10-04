from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import binascii

# Generate ECC keys
def generate_ecc_keys():
    key = ECC.generate(curve='P-256')  # Use P-256 curve
    private_key = key.export_key(format='PEM')
    public_key = key.public_key().export_key(format='PEM')
    return private_key, public_key

# Encrypt the message
def encrypt_message(message, public_key):
    # Generate a symmetric AES key
    aes_key = get_random_bytes(32)  # AES-256
    cipher_aes = AES.new(aes_key, AES.MODE_CBC)
    
    # Encrypt the message
    ciphertext = cipher_aes.encrypt(pad(message.encode('utf-8'), AES.block_size))
    
    # Export IV and ciphertext for transmission
    iv = cipher_aes.iv
    return aes_key, iv, ciphertext

# Decrypt the message
def decrypt_message(aes_key, iv, ciphertext):
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher_aes.decrypt(ciphertext), AES.block_size).decode('utf-8')
    return plaintext

# Main execution
if __name__ == "__main__":
    # Generate ECC keys
    private_key, public_key = generate_ecc_keys()
    
    # Message to encrypt
    message = "Secure Transactions"
    
    # Encrypt the message using the public key
    aes_key, iv, ciphertext = encrypt_message(message, public_key)
    print(f"Ciphertext (hex): {binascii.hexlify(ciphertext).decode('utf-8')}")
    
    # Decrypt the message using the AES key
    decrypted_message = decrypt_message(aes_key, iv, ciphertext)
    print(f"Decrypted message: {decrypted_message}")
