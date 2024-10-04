# Encrypt the message "Cryptography Lab Exercise" using AES in Counter (CTR) mode with the key 
# "0123456789ABCDEF0123456789ABCDEF" and a nonce of "0000000000000000". Provide the 
# ciphertext and then decrypt it to retrieve the original message. 

from Crypto.Cipher import AES
import binascii
from Crypto.Util import Counter

# Define the message and key for AES
message = "Cryptography Lab Exercise"
key = binascii.unhexlify("0123456789ABCDEF0123456789ABCDEF")

# Define the nonce (8 bytes)
nonce = b'00000000'

# Create a counter for CTR mode
ctr = Counter.new(64, prefix=nonce)

# Encrypt the message using AES in CTR mode
def aes_ctr_encrypt(message, key, ctr):
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    ciphertext = cipher.encrypt(message.encode('utf-8'))
    return ciphertext

# Decrypt the ciphertext
def aes_ctr_decrypt(ciphertext, key, ctr):
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    plaintext = cipher.decrypt(ciphertext).decode('utf-8')
    return plaintext

# Encrypt the message
ciphertext = aes_ctr_encrypt(message, key, ctr)
print(f"AES-CTR Ciphertext (hex): {binascii.hexlify(ciphertext).decode('utf-8')}")

# Reset the counter for decryption (since it's stateless, it must be reset)
ctr = Counter.new(64, prefix=nonce)

# Decrypt the message to verify
decrypted_message = aes_ctr_decrypt(ciphertext, key, ctr)
print(f"Decrypted message: {decrypted_message}")
