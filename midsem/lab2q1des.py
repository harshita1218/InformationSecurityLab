from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

# Function to pad the data (DES requires data in blocks of 8 bytes)
def pad_message(message):
    return pad(message.encode(), DES.block_size)

# Function to unpad the data
def unpad_message(padded_message):
    return unpad(padded_message, DES.block_size).decode()

# Key and plaintext
key = b'A1B2C3D4'  # DES requires an 8-byte key
plaintext = "Confidential Data"

# Initialize DES cipher in ECB mode
cipher = DES.new(key, DES.MODE_ECB)

# Encrypt the message
padded_plaintext = pad_message(plaintext)
ciphertext = cipher.encrypt(padded_plaintext)

# Decrypt the ciphertext to verify the original message
decrypted_padded_plaintext = cipher.decrypt(ciphertext)
decrypted_message = unpad_message(decrypted_padded_plaintext)

# Output results
print(f"Ciphertext (hex): {ciphertext.hex()}")
print(f"Decrypted Message: {decrypted_message}")
