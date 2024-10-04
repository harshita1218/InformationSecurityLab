# Encrypt the message "Confidential Data" using DES with the following key: "A1B2C3D4". Then 
# decrypt the ciphertext to verify the original message. 

from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import binascii

# Key must be 8 bytes long for DES
key = b"A1B2C3D4"

# The message to encrypt
message = "Confidential Data".encode()

# Create a DES cipher object in EAX mode
cipher = DES.new(key, DES.MODE_EAX)

# Encrypt the message
ciphertext, tag = cipher.encrypt_and_digest(message)

# Print the encrypted message in hexadecimal format
print("Encrypted message:", binascii.hexlify(ciphertext).decode())

# Decrypt the message
cipher_dec = DES.new(key, DES.MODE_EAX, nonce=cipher.nonce)
decrypted_message = cipher_dec.decrypt_and_verify(ciphertext, tag)

# Print the decrypted message
print("Decrypted message:", decrypted_message.decode())
