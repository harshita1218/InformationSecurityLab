from Crypto.Util.number import inverse, bytes_to_long, long_to_bytes
import random
from math import gcd  # Import the gcd function from the math module

# ElGamal parameters
p = 7919
g = 2
h = 6465
private_key = 2999

# Message to encrypt
message = "Asymmetric Algorithms"

# Convert message to numerical form
m = bytes_to_long(message.encode())

# Function to encrypt the message
def elgamal_encrypt(p, g, h, m):
    k = random.randint(1, p - 2)  # Random k such that 1 < k < p-1
    while gcd(k, p - 1) != 1:  # Ensure k is coprime to p-1
        k = random.randint(1, p - 2)

    c1 = pow(g, k, p)  # c1 = g^k mod p
    s = pow(h, k, p)   # s = h^k mod p
    c2 = (m * s) % p   # c2 = m * s mod p

    return (c1, c2)

# Function to decrypt the message
def elgamal_decrypt(c1, c2, private_key, p):
    s = pow(c1, private_key, p)  # s = c1^x mod p
    s_inv = inverse(s, p)         # s_inv = s^(-1) mod p
    m = (c2 * s_inv) % p          # m = c2 * s_inv mod p
    return m                       # Return numerical representation

# Encrypt the message
c1, c2 = elgamal_encrypt(p, g, h, m)
print(f"Ciphertext: (c1={c1}, c2={c2})")

# Decrypt the ciphertext
decrypted_value = elgamal_decrypt(c1, c2, private_key, p)

# Check if the decrypted value corresponds to a valid message
try:
    decrypted_message = long_to_bytes(decrypted_value)
    print(f"Decrypted message: {decrypted_message.decode('utf-8')}")
except UnicodeDecodeError:
    print("The decrypted message is not valid UTF-8 encoded text.")
