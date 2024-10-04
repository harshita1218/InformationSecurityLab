import random
import math

class Paillier:
    def __init__(self, bit_length):
        self.bit_length = bit_length
        self.p = self.generate_prime()
        self.q = self.generate_prime()
        self.n = self.p * self.q
        self.lambda_n = self.lcm(self.p - 1, self.q - 1)
        self.g = self.n + 1  # Often chosen in Paillier cryptosystem
        self.mu = self.modinv(self.l_function(pow(self.g, self.lambda_n, self.n**2)), self.n)
    
    # Generate a random prime number with bit_length
    def generate_prime(self):
        while True:
            prime_candidate = random.getrandbits(self.bit_length)
            if self.is_prime(prime_candidate):
                return prime_candidate

    # Simple primality test (Miller-Rabin could be used for stronger checking)
    def is_prime(self, n, k=40):  # Number of iterations
        if n <= 1:
            return False
        if n <= 3:
            return True
        if n % 2 == 0:
            return False

        # Find r and s such that n - 1 = 2^s * r
        r, s = n - 1, 0
        while r % 2 == 0:
            r //= 2
            s += 1

        for _ in range(k):
            a = random.randint(2, n - 2)
            x = pow(a, r, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(s - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True
    
    # Calculate least common multiple
    def lcm(self, a, b):
        return abs(a * b) // math.gcd(a, b)

    # Modular inverse
    def modinv(self, a, m):
        g, x, _ = self.egcd(a, m)
        if g != 1:
            raise Exception('Modular inverse does not exist')
        return x % m

    # Extended Euclidean algorithm
    def egcd(self, a, b):
        if a == 0:
            return b, 0, 1
        g, y, x = self.egcd(b % a, a)
        return g, x - (b // a) * y, y

    # L function for Paillier decryption
    def l_function(self, u):
        return (u - 1) // self.n

    # Encryption
    def encrypt(self, m):
        r = random.randint(1, self.n - 1)  # Random value r < n
        c = (pow(self.g, m, self.n**2) * pow(r, self.n, self.n**2)) % self.n**2
        return c

    # Decryption
    def decrypt(self, c):
        u = pow(c, self.lambda_n, self.n**2)
        l_of_u = self.l_function(u)
        m = (l_of_u * self.mu) % self.n
        return m
    
    # Homomorphic addition of two encrypted values
    def homomorphic_addition(self, c1, c2):
        return (c1 * c2) % self.n**2


# Example of Paillier encryption and homomorphic addition
if __name__ == "__main__":
    # Initialize the Paillier cryptosystem with 512-bit primes
    paillier = Paillier(bit_length=512)

    # Encrypt two integers
    m1 = 15
    m2 = 25
    c1 = paillier.encrypt(m1)
    c2 = paillier.encrypt(m2)
    print(f"Ciphertext of {m1}: {c1}")
    print(f"Ciphertext of {m2}: {c2}")

    # Perform homomorphic addition on the encrypted values
    c_add = paillier.homomorphic_addition(c1, c2)
    print(f"Ciphertext of addition (15 + 25): {c_add}")

    # Decrypt the result
    decrypted_add = paillier.decrypt(c_add)
    print(f"Decrypted result of addition: {decrypted_add}")
