from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from binascii import unhexlify

# Convert key to bytes (AES-128 uses a 16-byte key)
key = unhexlify("0123456789ABCDEF0123456789ABCDEF")

# Plaintext message to encrypt
plaintext = "Sensitive Information"

# Function to pad the plaintext to match the AES block size
def pad_message(message):
    return pad(message.encode(), AES.block_size)

# Function to unpad the decrypted message
def unpad_message(padded_message):
    return unpad(padded_message, AES.block_size).decode()

# Initialize AES cipher in ECB mode
cipher = AES.new(key, AES.MODE_ECB)

# Pad the plaintext and encrypt it
padded_plaintext = pad_message(plaintext)
ciphertext = cipher.encrypt(padded_plaintext)

# Decrypt the ciphertext to verify the original message
decrypted_padded_plaintext = cipher.decrypt(ciphertext)
decrypted_message = unpad_message(decrypted_padded_plaintext)

# Output results
print(f"Ciphertext (hex): {ciphertext.hex()}")
print(f"Decrypted Message: {decrypted_message}")
