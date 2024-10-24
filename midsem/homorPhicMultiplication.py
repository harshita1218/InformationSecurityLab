from random import randint
from sympy import mod_inverse

# Key generation (simplified)
def generate_elgamal_keys():
    p = 101  # A small prime for simplicity (in practice, use a large prime)
    g = 2    # Generator (usually a small number coprime with p)
    x = randint(1, p - 1)  # Private key
    y = pow(g, x, p)  # Public key: y = g^x mod p
    return p, g, x, y

# Encryption
def elgamal_encrypt(p, g, y, m):
    k = randint(1, p - 1)  # Random number for each encryption
    c1 = pow(g, k, p)  # c1 = g^k mod p
    c2 = (m * pow(y, k, p)) % p  # c2 = m * y^k mod p
    return c1, c2

# Decryption
def elgamal_decrypt(p, x, c1, c2):
    s = pow(c1, x, p)  # s = c1^x mod p
    s_inv = mod_inverse(s, p)  # Modular inverse of s
    m = (c2 * s_inv) % p  # m = c2 / s mod p
    return m

# Homomorphic multiplication: Combine ciphertexts
def elgamal_homomorphic_multiply(p, c1_1, c2_1, c1_2, c2_2):
    c1_prod = (c1_1 * c1_2) % p  # Multiply c1 parts
    c2_prod = (c2_1 * c2_2) % p  # Multiply c2 parts
    return c1_prod, c2_prod

# Example usage
p, g, x, y = generate_elgamal_keys()

# Encrypt two messages
m1 = 10
m2 = 5
c1_1, c2_1 = elgamal_encrypt(p, g, y, m1)
c1_2, c2_2 = elgamal_encrypt(p, g, y, m2)

# Homomorphic multiplication of encrypted messages
c1_prod, c2_prod = elgamal_homomorphic_multiply(p, c1_1, c2_1, c1_2, c2_2)

# Decrypt the product ciphertext
m_prod = elgamal_decrypt(p, x, c1_prod, c2_prod)

print("Original product:", m1 * m2)
print("Decrypted product:", m_prod)
