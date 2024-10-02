from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad, unpad
import binascii

# AES-256 Encryption and Decryption
aes_key = bytes.fromhex("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")
aes_message = "Encryption Strength"
aes_message_bytes = aes_message.encode()

# AES encryption
aes_cipher = AES.new(aes_key, AES.MODE_ECB)
aes_ciphertext = aes_cipher.encrypt(pad(aes_message_bytes, AES.block_size))

# AES decryption
aes_decrypted = unpad(aes_cipher.decrypt(aes_ciphertext), AES.block_size)

# Print AES results
print("AES-256 Ciphertext (Hex):", binascii.hexlify(aes_ciphertext).decode().upper())
print("AES-256 Decrypted Plaintext:", aes_decrypted.decode())

# DES Encryption and Decryption in CBC Mode
# DES key must be 8 bytes (64 bits)
des_key = bytes.fromhex("A1B2C3D4A1B2C3D4")  # 16 hex digits = 8 bytes
des_message = "Secure Communication"
des_message_bytes = des_message.encode()

# DES Initialization Vector - ensure it is 8 bytes long
iv = b'12345678'  # Explicitly set as an 8-byte byte string

# DES encryption in CBC mode
des_cipher = DES.new(des_key, DES.MODE_CBC, iv)
des_ciphertext = des_cipher.encrypt(pad(des_message_bytes, DES.block_size))

# DES decryption
des_decrypt_cipher = DES.new(des_key, DES.MODE_CBC, iv)
des_decrypted = unpad(des_decrypt_cipher.decrypt(des_ciphertext), DES.block_size)

# Print DES results
print("DES Ciphertext (Hex):", binascii.hexlify(des_ciphertext).decode().upper())
print("DES Decrypted Plaintext:", des_decrypted.decode())
