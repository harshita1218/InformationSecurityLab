from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# Generate a valid 24-byte key for Triple DES
# You can use `get_random_bytes` to generate a key that will pass the parity check
key = DES3.adjust_key_parity(get_random_bytes(24))

# Plaintext message to encrypt
plaintext = "Classified Text"

# Function to pad the message
def pad_message(message):
    return pad(message.encode(), DES3.block_size)

# Function to unpad the decrypted message
def unpad_message(padded_message):
    return unpad(padded_message, DES3.block_size).decode()

# Initialize Triple DES cipher in ECB mode
cipher = DES3.new(key, DES3.MODE_ECB)

# Pad the plaintext and encrypt it
padded_plaintext = pad_message(plaintext)
ciphertext = cipher.encrypt(padded_plaintext)

# Decrypt the ciphertext to verify the original message
decrypted_padded_plaintext = cipher.decrypt(ciphertext)
decrypted_message = unpad_message(decrypted_padded_plaintext)

# Output results
print(f"Ciphertext (hex): {ciphertext.hex()}")
print(f"Decrypted Message: {decrypted_message}")
