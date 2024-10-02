from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from binascii import hexlify

# Correct 24-byte (192-bit) key
key = bytes.fromhex('FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210')

# Plaintext message to encrypt
plaintext = "Top Secret Data"

# Function to pad the message (AES requires blocks of 16 bytes)
def pad_message(message):
    return pad(message.encode(), AES.block_size)

# Function to unpad the message
def unpad_message(padded_message):
    return unpad(padded_message, AES.block_size).decode()

# AES-192 encryption
cipher = AES.new(key, AES.MODE_ECB)

# Padding the plaintext to 16 bytes (128-bit block size)
padded_plaintext = pad_message(plaintext)

# Encrypt the message
ciphertext = cipher.encrypt(padded_plaintext)

# Decrypt the message to verify
decrypted_padded_plaintext = cipher.decrypt(ciphertext)
decrypted_message = unpad_message(decrypted_padded_plaintext)

# Output results
print(f"Ciphertext (hex): {hexlify(ciphertext).decode()}")
print(f"Decrypted Message: {decrypted_message}")
