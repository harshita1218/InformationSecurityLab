import time
from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad
from binascii import unhexlify

# Message to be encrypted
message = "Performance Testing of Encryption Algorithms"


# Function to measure encryption and decryption time
def measure_time(cipher, plaintext, key_size, mode_name):
    # Padding the plaintext
    padded_message = pad(plaintext.encode(), cipher.block_size)

    # Encrypt
    start_time = time.time()
    ciphertext = cipher.encrypt(padded_message)
    encryption_time = time.time() - start_time

    # Decrypt
    start_time = time.time()
    decrypted_padded_message = cipher.decrypt(ciphertext)
    decrypted_message = unpad(decrypted_padded_message, cipher.block_size).decode()
    decryption_time = time.time() - start_time

    return encryption_time, decryption_time


# DES encryption setup
des_key = b'12345678'  # 8-byte key for DES
des_cipher = DES.new(des_key, DES.MODE_ECB)

# AES-256 encryption setup
aes_key = unhexlify("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")  # 32-byte key for AES-256
aes_cipher = AES.new(aes_key, AES.MODE_ECB)

# Measure DES times
des_encryption_time, des_decryption_time = measure_time(des_cipher, message, 8, "DES")

# Measure AES-256 times
aes_encryption_time, aes_decryption_time = measure_time(aes_cipher, message, 32, "AES-256")

# Output results
print(f"DES Encryption Time: {des_encryption_time:.6f} seconds")
print(f"DES Decryption Time: {des_decryption_time:.6f} seconds")
print(f"AES-256 Encryption Time: {aes_encryption_time:.6f} seconds")
print(f"AES-256 Decryption Time: {aes_decryption_time:.6f} seconds")
