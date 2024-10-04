# With the ElGamal public key (p = 7919, g = 2, h = 6465) and the private key x = 2999, encrypt 
# the message "Asymmetric Algorithms". Decrypt the resulting ciphertext to verify the original 
# message 

#IDT THIS WORKS :( 


from Crypto.Util import number
from random import randint

# Given parameters for ElGamal
p = 7919  # A large prime number
g = 2     # Generator
h = 6465  # Public key (h = g^x mod p)
x = 2999  # Private key

# Function to convert a string to an integer
def message_to_int(message):
    return int.from_bytes(message.encode('utf-8'), 'big')

# Function to convert an integer back to a string
def int_to_message(integer):
    return integer.to_bytes((integer.bit_length() + 7) // 8, 'big').decode('utf-8')

# ElGamal encryption
def elgamal_encrypt(message, p, g, h):
    m = message_to_int(message)  # Convert the message to an integer
    k = randint(1, p - 2)        # Random integer k, 1 <= k <= p-2
    c1 = pow(g, k, p)            # c1 = g^k mod p
    c2 = (m * pow(h, k, p)) % p  # c2 = m * h^k mod p
    return (c1, c2)

# ElGamal decryption
def elgamal_decrypt(c1, c2, p, x):
    s = pow(c1, x, p)            # s = c1^x mod p
    s_inv = number.inverse(s, p)  # s_inv = modular inverse of s mod p
    m = (c2 * s_inv) % p          # m = c2 * s_inv mod p
    return int_to_message(m)

# Encrypt the message "Asymmetric Algorithms"
message = "Asymmetric Algorithms"
ciphertext = elgamal_encrypt(message, p, g, h)
print(f"Ciphertext: {ciphertext}")

# Decrypt the ciphertext to retrieve the original message
decrypted_message = elgamal_decrypt(ciphertext[0], ciphertext[1], p, x)
print(f"Decrypted message: {decrypted_message}")

