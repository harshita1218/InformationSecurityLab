import random
import math


# Function to compute modular inverse using Extended Euclidean Algorithm
def modinv(a, m):
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise ValueError('Modular inverse does not exist')
    return x % m


# Extended Euclidean Algorithm
def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    g, y, x = extended_gcd(b % a, a)
    return g, x - (b // a) * y, y


# Generate large random prime numbers
def is_prime(n):
    if n < 2:
        return False
    for i in range(2, int(math.sqrt(n)) + 1):
        if n % i == 0:
            return False
    return True


def get_prime(bits):
    while True:
        prime = random.getrandbits(bits)
        if is_prime(prime):
            return prime


# RSA Key Generation
def generate_rsa_keypair(bits=512):
    p = get_prime(bits // 2)
    q = get_prime(bits // 2)
    n = p * q
    phi_n = (p - 1) * (q - 1)

    # Choose e such that 1 < e < phi_n and gcd(e, phi_n) = 1
    e = random.randint(2, phi_n - 1)
    while math.gcd(e, phi_n) != 1:
        e = random.randint(2, phi_n - 1)

    # Compute d such that d ≡ e^(-1) mod phi_n
    d = modinv(e, phi_n)

    # Public and private keys
    public_key = (n, e)
    private_key = (n, d)

    return public_key, private_key


# RSA Encryption
def rsa_encrypt(public_key, plaintext):
    n, e = public_key
    # Ciphertext: c = m^e mod n
    ciphertext = pow(plaintext, e, n)
    return ciphertext


# RSA Decryption
def rsa_decrypt(private_key, ciphertext):
    n, d = private_key
    # Plaintext: m = c^d mod n
    plaintext = pow(ciphertext, d, n)
    return plaintext


# Example of RSA Multiplicative Homomorphism
def rsa_multiplicative_homomorphism():
    # Step 1: Generate RSA key pair
    public_key, private_key = generate_rsa_keypair()

    # Step 2: Encrypt two integers
    m1 = 7
    m2 = 3
    c1 = rsa_encrypt(public_key, m1)
    c2 = rsa_encrypt(public_key, m2)

    print(f"Ciphertext 1 (encrypted 7): {c1}")
    print(f"Ciphertext 2 (encrypted 3): {c2}")

    # Step 3: Perform multiplicative homomorphism (c1 * c2) mod n
    n, _ = public_key
    c_product = (c1 * c2) % n
    print(f"Ciphertext of product (encrypted 7 * 3): {c_product}")

    # Step 4: Decrypt the result
    decrypted_product = rsa_decrypt(private_key, c_product)
    print(f"Decrypted product: {decrypted_product}")


# Run the example
if __name__ == "__main__":
    rsa_multiplicative_homomorphism()
