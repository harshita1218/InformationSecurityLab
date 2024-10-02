from Crypto.Cipher import AES
from Crypto.Util import Counter
import binascii

# Define the key (32 bytes for AES-256)
key = bytes.fromhex("0123456789ABCDEF0123456789ABCDEF")

# Define the nonce (should be 8 bytes)
nonce = bytes.fromhex("0000000000000000")  # 8 bytes for nonce

# Create a counter with the specified nonce
# AES requires a 16-byte (128-bit) block size
ctr = Counter.new(128, prefix=nonce)

# Message to encrypt
message = "Cryptography Lab Exercise"
message_bytes = message.encode()  # Convert message to bytes

# AES encryption in CTR mode
cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
ciphertext = cipher.encrypt(message_bytes)

# Print the ciphertext in hexadecimal format
print("Ciphertext (Hex):", binascii.hexlify(ciphertext).decode().upper())

# AES decryption in CTR mode (CTR mode is symmetric)
# We need to create a new counter for decryption
decrypt_ctr = Counter.new(128, prefix=nonce)  # Use the same nonce
decrypt_cipher = AES.new(key, AES.MODE_CTR, counter=decrypt_ctr)
decrypted = decrypt_cipher.decrypt(ciphertext)

# Print the decrypted plaintext
print("Decrypted Plaintext:", decrypted.decode())
