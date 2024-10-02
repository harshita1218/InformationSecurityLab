from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes
import random
def elgamal_keygen(bits=256):
 p = getPrime(bits)  # Generate a large prime number p
 g = random.randint(2, p - 1)  # Choose a generator g
 x = random.randint(2, p - 2)  # Private key x
 h = pow(g, x, p)  # Compute public key component h = g^x mod p
 return p, g, h, x
def elgamal_encrypt(p, g, h, message):
 m = bytes_to_long(message.encode('utf-8'))  # Convert the message to an integer
 k = random.randint(2, p - 2)  # Choose a random integer k
 c1 = pow(g, k, p)  # Compute c1 = g^k mod p
 s = pow(h, k, p)  # Compute s = h^k mod p
 c2 = (m * s) % p  # Compute c2 = m * s mod p
 return c1, c2
def elgamal_decrypt(p, x, c1, c2):
 s = pow(c1, x, p)  # Compute the shared secret s = c1^x mod p
 s_inv = inverse(s, p)  # Compute the modular inverse of s
 m = (c2 * s_inv) % p  # Decrypt the message m = c2 * s_inv mod p
 return long_to_bytes(m).decode('utf-8')
# Key generation
p, g, h, x = elgamal_keygen(256)  # Generate keys with a 256-bit prime
# Original message
message = "Confidential Data"
# Encrypt the message
c1, c2 = elgamal_encrypt(p, g, h, message)
print("Ciphertext:", (c1, c2))
# Decrypt the message
decrypted_message = elgamal_decrypt(p, x, c1, c2)
print("Decrypted Message:", decrypted_message)