# Using AES-256, encrypt the message "Encryption Strength" with the key 
# "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789 ABCDEF". Then decrypt 
# the ciphertext to verify the original message. Encrypt the message "Secure Communication" using 
# DES in Cipher Block Chaining (CBC) mode with the key "A1B2C3D4" and an initialization vector (IV) of 
# "12345678". Provide the ciphertext and then decrypt it to retrieve the original message.


from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import binascii

# Define the message and key for AES-256
message = "Encryption Strength"
key = binascii.unhexlify("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")

# AES block size is 16 bytes
block_size = AES.block_size

# Encrypt the message using AES-256 in CBC mode
def aes_encrypt(message, key):
    iv = AES.block_size * b'\x00'  # Zero IV for simplicity
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(message.encode('utf-8'), block_size)
    ciphertext = cipher.encrypt(padded_message)
    return iv, ciphertext

# Decrypt the ciphertext
def aes_decrypt(iv, ciphertext, key):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_plaintext, block_size).decode('utf-8')
    return plaintext

# Perform encryption
iv, ciphertext = aes_encrypt(message, key)
print(f"AES-256 Ciphertext (hex): {binascii.hexlify(ciphertext).decode('utf-8')}")

# Perform decryption to verify the original message
decrypted_message = aes_decrypt(iv, ciphertext, key)
print(f"Decrypted message: {decrypted_message}")
