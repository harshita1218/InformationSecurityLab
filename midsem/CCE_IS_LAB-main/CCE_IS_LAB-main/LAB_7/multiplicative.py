import random
import math

# Function to compute gcd
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

# Function to compute modular inverse
def modinv(a, m):
    g, x, _ = egcd(a, m)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    return x % m

# Extended Euclidean Algorithm
def egcd(a, b):
    if a == 0:
        return b, 0, 1
    g, y, x = egcd(b % a, a)
    return g, x - (b // a) * y, y

# Function to generate prime numbers (basic primality check)
def is_prime(n):
    if n < 2:
        return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False
    return True

def generate_prime_candidate(bit_length):
    # Generate random prime candidate
    p = random.getrandbits(bit_length)
    # Apply a mask to ensure it's odd and has the correct bit length
    p |= (1 << bit_length - 1) | 1
    return p

def generate_prime(bit_length):
    p = generate_prime_candidate(bit_length)
    while not is_prime(p):
        p = generate_prime_candidate(bit_length)
    return p

# RSA class for encryption, decryption, and homomorphic property
class RSA:
    def __init__(self, bit_length):
        self.p = generate_prime(bit_length)
        self.q = generate_prime(bit_length)
        self.n = self.p * self.q
        self.phi_n = (self.p - 1) * (self.q - 1)
        self.e = 65537  # Commonly used public exponent
        self.d = modinv(self.e, self.phi_n)

    # Encryption function: c = (m^e) mod n
    def encrypt(self, m):
        return pow(m, self.e, self.n)

    # Decryption function: m = (c^d) mod n
    def decrypt(self, c):
        return pow(c, self.d, self.n)

    # Multiplicative homomorphic property: c1 * c2 mod n = E(m1 * m2)
    def homomorphic_multiplication(self, c1, c2):
        return (c1 * c2) % self.n


# Example of RSA encryption and homomorphic multiplication
if __name__ == "__main__":
    # Initialize the RSA cryptosystem with 512-bit primes
    rsa = RSA(bit_length=512)

    # Encrypt two integers
    m1 = 7
    m2 = 3
    c1 = rsa.encrypt(m1)
    c2 = rsa.encrypt(m2)
    print(f"Ciphertext of {m1}: {c1}")
    print(f"Ciphertext of {m2}: {c2}")

    # Perform homomorphic multiplication on the encrypted values
    c_mult = rsa.homomorphic_multiplication(c1, c2)
    print(f"Ciphertext of multiplication (7 * 3): {c_mult}")

    # Decrypt the result
    decrypted_mult = rsa.decrypt(c_mult)
    print(f"Decrypted result of multiplication: {decrypted_mult}")
