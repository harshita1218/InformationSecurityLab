# Using RSA, encrypt the message "Asymmetric Encryption" with the public key (n, e). Then decrypt the ciphertext with the private key (n, d) to verify the original message.

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
import binascii

# Generate RSA key pair
key = RSA.generate(2048)

# Extract public and private keys
public_key = key.publickey()
private_key = key

# Convert the keys to their components
n = key.n
e = key.e
d = key.d

#print(f"Public Key (n, e): ({n}, {e})")
#print(f"Private Key (n, d): ({n}, {d})")

# Define the message
message = "Asymmetric Encryption"

# Encryption with the public key
cipher_rsa = PKCS1_OAEP.new(public_key)
ciphertext = cipher_rsa.encrypt(message.encode())

print(f"Ciphertext (hex): {binascii.hexlify(ciphertext).decode('utf-8')}")

# Decryption with the private key
cipher_rsa = PKCS1_OAEP.new(private_key)
decrypted_message = cipher_rsa.decrypt(ciphertext)

print(f"Decrypted message: {decrypted_message.decode()}")

# Verify that the decrypted message matches the original message
assert decrypted_message.decode() == message
