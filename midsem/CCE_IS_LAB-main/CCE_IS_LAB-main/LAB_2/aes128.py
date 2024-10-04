# Encrypt the message "Sensitive Information" using AES-128 with the following key: 
# "0123456789ABCDEF0123456789ABCDEF". Then decrypt the ciphertext to verify the original 
# message

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import binascii

# Key and message
key = binascii.unhexlify("0123456789ABCDEF0123456789ABCDEF")
message = "Sensitive Information".encode()

# Generate a random IV
iv = get_random_bytes(AES.block_size)

# Create cipher object and encrypt
cipher = AES.new(key, AES.MODE_CBC, iv)
ciphertext = cipher.encrypt(pad(message, AES.block_size))

# Decrypt the ciphertext
decipher = AES.new(key, AES.MODE_CBC, iv)
decrypted_message = unpad(decipher.decrypt(ciphertext), AES.block_size)

print("Original message:", message.decode())
print("Ciphertext (hex):", binascii.hexlify(ciphertext).decode())
print("IV (hex):", binascii.hexlify(iv).decode())
print("Decrypted message:", decrypted_message.decode())
