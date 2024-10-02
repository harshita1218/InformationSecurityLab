import random
import math

# Utility function to compute modular inverse
def modinv(a, m):
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise ValueError('Modular inverse does not exist')
    else:
        return x % m

# Utility function for extended GCD
def extended_gcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = extended_gcd(b % a, a)
        return (g, x - (b // a) * y, y)

# Utility function to compute lcm
def lcm(a, b):
    return abs(a * b) // math.gcd(a, b)

# Paillier key generation
def generate_paillier_keypair(bits=512):
    # Generate two large prime numbers p and q
    p = get_prime(bits // 2)
    q = get_prime(bits // 2)

    n = p * q
    n_sq = n * n
    lam = lcm(p-1, q-1)  # λ = lcm(p-1, q-1)

    # Generate g which is a random integer in Z*_n^2
    g = n + 1

    # Precompute mu = (L(g^λ mod n^2))^(-1) mod n
    def L(x): return (x - 1) // n
    mu = modinv(L(pow(g, lam, n_sq)), n)

    public_key = (n, g)
    private_key = (lam, mu)

    return public_key, private_key

# Random prime generator for key generation
def get_prime(bits):
    while True:
        prime = random.getrandbits(bits)
        if is_prime(prime):
            return prime

# Check primality using trial division
def is_prime(n):
    if n <= 1:
        return False
    for i in range(2, int(math.sqrt(n)) + 1):
        if n % i == 0:
            return False
    return True

# Paillier encryption
def encrypt(public_key, plaintext):
    n, g = public_key
    n_sq = n * n

    # Choose a random r in Z*_n
    r = random.randint(1, n-1)

    # Ciphertext: c = g^m * r^n mod n^2
    c = (pow(g, plaintext, n_sq) * pow(r, n, n_sq)) % n_sq
    return c

# Paillier decryption
def decrypt(private_key, public_key, ciphertext):
    lam, mu = private_key
    n, g = public_key
    n_sq = n * n

    # Compute L(c^λ mod n^2)
    def L(x): return (x - 1) // n
    x = pow(ciphertext, lam, n_sq)
    plain = (L(x) * mu) % n
    return plain

# Homomorphic addition on encrypted values
def homomorphic_addition(public_key, ciphertext1, ciphertext2):
    n, _ = public_key
    n_sq = n * n

    # Homomorphic addition: c3 = (c1 * c2) mod n^2
    result_ciphertext = (ciphertext1 * ciphertext2) % n_sq
    return result_ciphertext

# Example usage
if __name__ == "__main__":
    # Step 1: Generate Paillier key pair
    public_key, private_key = generate_paillier_keypair()

    # Step 2: Encrypt two integers
    m1 = 15
    m2 = 25
    c1 = encrypt(public_key, m1)
    c2 = encrypt(public_key, m2)

    print(f"Ciphertext 1 (encrypted 15): {c1}")
    print(f"Ciphertext 2 (encrypted 25): {c2}")

    # Step 3: Homomorphic addition on encrypted values
    c_sum = homomorphic_addition(public_key, c1, c2)
    print(f"Ciphertext of sum (encrypted 15 + 25): {c_sum}")

    # Step 4: Decrypt the result of the addition
    decrypted_sum = decrypt(private_key, public_key, c_sum)
    print(f"Decrypted sum: {decrypted_sum}")
